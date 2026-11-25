// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! One-click quarantine of a compromised container.
//!
//! What an operator did by hand to contain a compromised container, as one
//! action, in the order that matters:
//!
//! 0. **Record the intent** before touching anything. The record is what
//!    [`reconcile`] isolates from, so state and firewall cannot diverge.
//! 1. **Cut the network** — before touching a process, so a C2 client
//!    cannot be told "they're onto us" and an exfiltration in flight
//!    stops. An nftables `netdev` table drops every packet the container
//!    sends (ingress on its host-side veth) and, where the kernel has the
//!    netdev egress hook (5.16+), every packet sent to it. The rule lives
//!    in the HOST's namespace: root inside an unprivileged container owns
//!    its own netns and could flush rules placed there; it cannot touch
//!    the host's.
//! 2. **Freeze, capture, kill** the processes the finding names (miners,
//!    binaries running from /tmp, processes carrying an injected loader).
//!    Each is SIGSTOPped first so nothing can react, its executable,
//!    command line, environment, maps and status are copied into an
//!    evidence directory with SHA-256s, then it is SIGKILLed. A process
//!    whose executable could NOT be captured is left frozen instead — a
//!    stopped process runs nothing, and the evidence stays in /proc. The
//!    container's init is never touched, and a PID is acted on only while
//!    it is provably the same process (cgroup + start time) in the same
//!    container.
//! 3. **Keep it quarantined** — a restarted container gets a new veth, so
//!    [`reconcile`] (every 3 s from main.rs) re-binds the drop to whatever
//!    device the container has now. The table is replaced atomically,
//!    never removed-then-added. A restarted quarantined container has
//!    network for up to one interval before the drop follows it.
//!
//! Every failure leans towards keeping the container isolated: an
//! unreadable state file, a /proc listing that fails, or an interface
//! lookup that times out leaves the current drop in place.
//!
//! Release removes the drop. Evidence is never deleted.
//!
//! ## Which host interfaces belong to the container
//!
//! iproute2 inside the container prints `eth0@if123`: 123 is the peer's
//! ifindex — but root in the container controls that number (a veth whose
//! peer sits in a child namespace prints whatever index that peer has),
//! so taken alone it could point at ANOTHER container's veth and make
//! quarantine cut off an innocent neighbour. A host interface is accepted
//! only when the kernel confirms the pairing from the host side:
//!
//! * it is a veth;
//! * its peer lives in the container's network namespace — the netns id
//!   the host reports for the veth's peer (`link-netnsid`) equals the id
//!   `RTM_GETNSID` returns for the container init's namespace;
//! * its peer is the container's interface — the host veth's `iflink` is
//!   that interface's ifindex.
//!
//! An interface that is not a veth (macvlan/ipvlan: its peer is the
//! host's physical NIC, and dropping there would cut the host off) is
//! never touched and makes the quarantine PARTIAL, which the result and
//! the inbox card say plainly.

use crate::predictive::intrusion::{procs, targets};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

const STATE_FILE: &str = "/etc/wolfstack/quarantine.json";
const LOCK_FILE: &str = "/etc/wolfstack/quarantine.lock";
const EVIDENCE_ROOT: &str = "/var/lib/wolfstack/quarantine";
const NFT_TABLE: &str = "wolfstack_quarantine";
/// Larger executables are not copied (and their process is left frozen).
const MAX_EXE_CAPTURE: u64 = 512 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSpec {
    /// Network isolation only.
    None,
    /// Processes executing from /tmp, /dev/shm or a memfd.
    Staging,
    /// Known crypto-miner processes.
    Miners,
    /// Processes whose environment carries a loader hook.
    EnvHooks,
    /// All of the above (command-line quarantine).
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KilledProc {
    pub pid: u32,
    pub cmdline: String,
    pub exe: String,
    pub sha256: Option<String>,
    pub killed: bool,
    /// Why a process was left frozen rather than killed, if it was.
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub target_key: String,
    pub label: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub actor: String,
    pub reason: String,
    pub evidence_dir: String,
    #[serde(default)]
    pub killed: Vec<KilledProc>,
    /// Human-readable state of the network isolation at quarantine time.
    #[serde(default)]
    pub network: String,
    /// Every network interface of the container was cut off.
    #[serde(default)]
    pub fully_isolated: bool,
}

/// What a quarantine did, for the caller to present.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub message: String,
    /// Set when the container is NOT fully cut off, or a process could not
    /// be stopped cleanly — must be shown to the operator, not toasted.
    pub warning: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    records: Vec<Record>,
}

/// In-process serialisation (quarantine / release / reconcile).
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Cross-process lock: the daemon and a `wolfstack --quarantine` from SSH
/// must not interleave their read-modify-write of the state file.
struct FileLock(#[allow(dead_code)] OwnedFd);

fn file_lock() -> Result<FileLock, String> {
    if let Some(dir) = std::path::Path::new(LOCK_FILE).parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {}", dir.display(), e))?;
    }
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).mode(0o600)
        .open(LOCK_FILE).map_err(|e| format!("open {}: {}", LOCK_FILE, e))?;
    let fd = OwnedFd::from(f);
    // SAFETY: flock on a descriptor we own; released when it closes.
    if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(format!("lock {}: {}", LOCK_FILE, std::io::Error::last_os_error()));
    }
    Ok(FileLock(fd))
}

/// Missing file = no quarantines. Any other failure is an ERROR: treating an
/// unreadable state file as empty would lift every quarantine.
fn load() -> Result<State, String> {
    match std::fs::read_to_string(STATE_FILE) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| format!("parse {}: {}", STATE_FILE, e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(format!("read {}: {}", STATE_FILE, e)),
    }
}

fn save(s: &State) -> Result<(), String> {
    if let Some(dir) = std::path::Path::new(STATE_FILE).parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {}", dir.display(), e))?;
    }
    let tmp = format!("{}.tmp", STATE_FILE);
    let mut f = std::fs::OpenOptions::new().create(true).write(true).truncate(true).mode(0o600)
        .open(&tmp).map_err(|e| format!("write {}: {}", tmp, e))?;
    use std::io::Write;
    f.write_all(serde_json::to_string_pretty(s).unwrap_or_default().as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("write {}: {}", tmp, e))?;
    std::fs::rename(&tmp, STATE_FILE).map_err(|e| format!("rename {}: {}", STATE_FILE, e))
}

/// Active quarantines on this node. An unreadable state file is logged and
/// reported as none (callers here only display); isolation is driven by
/// [`reconcile`], which never treats that case as "none".
pub fn records() -> Vec<Record> {
    match load() {
        Ok(s) => s.records,
        Err(e) => { tracing::error!("quarantine: {}", e); Vec::new() }
    }
}

// ─── Host-side interfaces of a container ───────────────────────────

/// One `ip -o link` line inside the container: (own ifindex, name, peer ifindex).
pub fn parse_peer_links(ip_o_link: &str) -> Vec<(u32, String, u32)> {
    ip_o_link.lines().filter_map(|l| {
        let mut parts = l.splitn(3, ": ");
        let idx: u32 = parts.next()?.trim().parse().ok()?;
        let name = parts.next()?.split(':').next()?;
        let (ifname, peer) = name.split_once("@if")?;
        Some((idx, ifname.to_string(), peer.parse().ok()?))
    }).collect()
}

fn host_iface_by_index(idx: u32) -> Option<String> {
    let rd = std::fs::read_dir("/sys/class/net").ok()?;
    // An interface vanishing mid-iteration (veth churn) is skipped, not fatal.
    rd.flatten().find_map(|e| {
        let i = std::fs::read_to_string(e.path().join("ifindex")).ok()?;
        (i.trim().parse::<u32>().ok() == Some(idx)).then(|| e.file_name().to_string_lossy().into_owned())
    })
}

/// (is veth, link-netnsid) from `ip -d -o link show dev X` (ip-link(8)
/// -details names the kind; `link-netnsid N` names the peer's namespace).
pub fn parse_link_details(out: &str) -> (bool, Option<i32>) {
    let words: Vec<&str> = out.split_whitespace().collect();
    let veth = words.contains(&"veth");
    let nsid = words.windows(2).find(|w| w[0] == "link-netnsid").and_then(|w| w[1].parse().ok());
    (veth, nsid)
}

fn link_details(iface: &str) -> (bool, Option<i32>) {
    crate::predictive::capped_exec::run_ok("ip", &["-d", "-o", "link", "show", "dev", iface],
        std::time::Duration::from_secs(5))
        .map(|o| parse_link_details(&o))
        .unwrap_or((false, None))
}

/// The netns id the host has for the network namespace of `pid`
/// (RTM_GETNSID with NETNSA_PID; linux/net_namespace.h + rtnetlink.h:
/// RTM_GETNSID = 90, reply RTM_NEWNSID = 88, NETNSA_NSID = 1,
/// NETNSA_PID = 2). None when unassigned or on any error.
pub fn netnsid_of_pid(pid: u32) -> Option<i32> {
    const RTM_NEWNSID: u16 = 88;
    const RTM_GETNSID: u16 = 90;
    const NETNSA_NSID: u16 = 1;
    const NETNSA_PID: u16 = 2;
    const NLMSG_HDRLEN: usize = 16;
    // SAFETY: plain socket creation; ownership taken immediately.
    let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
    if raw < 0 { return None; }
    // SAFETY: freshly created descriptor.
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };
    let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
    // SAFETY: valid timeval pointer and size.
    unsafe {
        libc::setsockopt(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32);
    }
    // nlmsghdr (len u32, type u16, flags u16, seq u32, pid u32) +
    // rtgenmsg (family u8, padded to 4) + nlattr (len u16, type u16) + u32.
    let total = NLMSG_HDRLEN + 4 + 8;
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&(total as u32).to_ne_bytes());
    buf.extend_from_slice(&RTM_GETNSID.to_ne_bytes());
    buf.extend_from_slice(&(libc::NLM_F_REQUEST as u16).to_ne_bytes());
    buf.extend_from_slice(&1u32.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(&[libc::AF_UNSPEC as u8, 0, 0, 0]);
    buf.extend_from_slice(&8u16.to_ne_bytes());
    buf.extend_from_slice(&NETNSA_PID.to_ne_bytes());
    buf.extend_from_slice(&pid.to_ne_bytes());
    // SAFETY: zeroed sockaddr_nl is valid; family set; buffers sized.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    let sent = unsafe {
        libc::sendto(sock.as_raw_fd(), buf.as_ptr() as *const libc::c_void, buf.len(), 0,
            &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32)
    };
    if sent != buf.len() as isize { return None; }
    let mut resp = vec![0u8; 4096];
    // SAFETY: resp is a valid writable buffer of the given length.
    let n = unsafe { libc::recv(sock.as_raw_fd(), resp.as_mut_ptr() as *mut libc::c_void, resp.len(), 0) };
    if n < (NLMSG_HDRLEN + 4) as isize { return None; }
    let resp = &resp[..n as usize];
    if u16::from_ne_bytes([resp[4], resp[5]]) != RTM_NEWNSID { return None; }
    let mut off = NLMSG_HDRLEN + 4;
    while off + 4 <= resp.len() {
        let alen = u16::from_ne_bytes([resp[off], resp[off + 1]]) as usize;
        let atype = u16::from_ne_bytes([resp[off + 2], resp[off + 3]]);
        if alen < 4 || off + alen > resp.len() { break; }
        if atype == NETNSA_NSID && alen >= 8 {
            let v = i32::from_ne_bytes([resp[off + 4], resp[off + 5], resp[off + 6], resp[off + 7]]);
            return (v >= 0).then_some(v);
        }
        off += (alen + 3) & !3;
    }
    None
}

/// Interface names nft is given: kernel names are ≤15 bytes; restrict to
/// the characters veth names use so nothing can break out of the quotes.
fn safe_ifname(s: &str) -> bool {
    !s.is_empty() && s.len() <= 15 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

#[derive(Debug, Default)]
pub struct Links {
    /// Verified host-side veths to drop on.
    pub veths: Vec<String>,
    /// Container interfaces that stay connected, with why.
    pub not_isolated: Vec<String>,
}

/// The container's host-side veths, verified from the host side (see the
/// module docs). Err only when the container's interfaces could not be
/// listed at all.
pub fn host_links(init_pid: u32) -> Result<Links, String> {
    let pid = init_pid.to_string();
    let out = crate::predictive::capped_exec::run_ok(
        "nsenter", &["-t", &pid, "-n", "ip", "-o", "link"], std::time::Duration::from_secs(5))
        .ok_or("could not list the container's interfaces (nsenter/ip failed)")?;
    let ct_nsid = netnsid_of_pid(init_pid);
    let mut links = Links::default();
    for (own_idx, ifname, peer) in parse_peer_links(&out) {
        let Some(host) = host_iface_by_index(peer) else {
            links.not_isolated.push(format!("{} (no host interface {})", ifname, peer));
            continue;
        };
        let (is_veth, peer_nsid) = link_details(&host);
        let iflink: Option<u32> = std::fs::read_to_string(format!("/sys/class/net/{}/iflink", host)).ok()
            .and_then(|s| s.trim().parse().ok());
        if !is_veth {
            links.not_isolated.push(format!("{} (peer {} is not a veth — dropping there would cut off the host)", ifname, host));
        } else if ct_nsid.is_none() || peer_nsid != ct_nsid || iflink != Some(own_idx) {
            links.not_isolated.push(format!("{} (host interface {} could not be proven to be its peer)", ifname, host));
        } else if !safe_ifname(&host) {
            links.not_isolated.push(format!("{} (host interface name {:?} not accepted)", ifname, host));
        } else {
            links.veths.push(host);
        }
    }
    if links.veths.is_empty() && links.not_isolated.is_empty() {
        links.not_isolated.push("no network link to the host (host networking?)".into());
    }
    Ok(links)
}

// ─── nftables ──────────────────────────────────────────────────────

/// The whole quarantine table for a device set. `table X` before
/// `delete table X` makes the delete safe when the table is absent; the
/// script is applied atomically by `nft -f`.
pub fn render_table(devices: &[String], egress: bool) -> String {
    let mut s = format!("table netdev {t}\ndelete table netdev {t}\n", t = NFT_TABLE);
    if devices.is_empty() { return s; }
    s.push_str(&format!("table netdev {} {{\n", NFT_TABLE));
    for (i, d) in devices.iter().enumerate() {
        s.push_str(&format!(
            "  chain in_{i} {{ type filter hook ingress device \"{d}\" priority -500; policy drop; }}\n"));
        if egress {
            s.push_str(&format!(
                "  chain out_{i} {{ type filter hook egress device \"{d}\" priority -500; policy drop; }}\n"));
        }
    }
    s.push_str("}\n");
    s
}

fn nft_apply(script: &str) -> Result<(), String> {
    let path = format!("/run/wolfstack-quarantine-{}.nft", std::process::id());
    std::fs::write(&path, script).map_err(|e| format!("write {}: {}", path, e))?;
    let r = crate::predictive::capped_exec::run("nft", &["-f", &path], std::time::Duration::from_secs(10), &[0]);
    let _ = std::fs::remove_file(&path);
    r.map(|_| ()).map_err(|e| format!("nft: {}", e))
}

/// Last device set written (and whether egress is covered), so nft is only
/// called on change. None = unknown (fresh process).
static APPLIED: std::sync::Mutex<Option<(Vec<String>, bool)>> = std::sync::Mutex::new(None);
/// Last verified devices per quarantined container — used when a lookup
/// fails, so a transient failure never lifts isolation.
static LAST_DEVICES: std::sync::LazyLock<std::sync::Mutex<HashMap<String, Vec<String>>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Write the table for `devices`. Tries with the egress hook first and
/// falls back to ingress-only on kernels without it. Returns whether
/// egress is covered.
fn apply_devices(mut devices: Vec<String>) -> Result<bool, String> {
    devices.retain(|d| safe_ifname(d));
    devices.sort();
    devices.dedup();
    let mut applied = APPLIED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((prev, eg)) = applied.as_ref()
        && *prev == devices { return Ok(*eg); }
    let egress = match nft_apply(&render_table(&devices, true)) {
        Ok(()) => true,
        Err(e_full) => {
            nft_apply(&render_table(&devices, false))
                .map_err(|e| format!("{} (and without the egress hook: {})", e_full, e))?;
            false
        }
    };
    *applied = Some((devices, egress));
    Ok(egress)
}

fn iface_exists(name: &str) -> bool {
    std::path::Path::new("/sys/class/net").join(name).exists()
}

/// Devices for every record, from the current container state. A running
/// container whose lookup fails keeps its last verified devices.
fn devices_for(recs: &[Record], all: &[targets::Target]) -> Vec<String> {
    let mut last = LAST_DEVICES.lock().unwrap_or_else(|e| e.into_inner());
    let mut devices = Vec::new();
    for r in recs {
        match all.iter().find(|t| t.key == r.target_key) {
            None => { last.remove(&r.target_key); } // stopped: its veth is gone with it
            Some(t) => match host_links(t.init_pid) {
                Ok(l) if !l.veths.is_empty() => {
                    last.insert(r.target_key.clone(), l.veths.clone());
                    devices.extend(l.veths);
                }
                _ => {
                    if let Some(prev) = last.get(&r.target_key) {
                        devices.extend(prev.iter().filter(|d| iface_exists(d)).cloned());
                    }
                }
            },
        }
    }
    devices
}

/// Re-bind every active quarantine to its container's current devices.
/// Called every 3 s. With nothing quarantined it is one file read and no
/// /proc walk.
pub fn reconcile() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(_fl) = file_lock() else { return };
    let recs = match load() {
        Ok(s) => s.records,
        Err(e) => {
            // Never "no quarantines" on a read error — keep what is applied.
            tracing::error!("quarantine: keeping current isolation, state unreadable: {}", e);
            return;
        }
    };
    if recs.is_empty() {
        // Remove the table once: when a fresh process does not know what a
        // previous one left behind, or after the last release.
        let need_clear = match APPLIED.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            None => true,
            Some((devs, _)) => !devs.is_empty(),
        };
        if need_clear && let Err(e) = apply_devices(Vec::new()) {
            tracing::error!("quarantine: could not remove the isolation table: {}", e);
        }
        return;
    }
    let Some(all) = targets::enumerate_checked() else {
        tracing::error!("quarantine: /proc unreadable; keeping current isolation");
        return;
    };
    if let Err(e) = apply_devices(devices_for(&recs, &all)) {
        tracing::error!("quarantine: could not apply isolation table: {}", e);
    }
}

// ─── Process capture + kill ────────────────────────────────────────

fn pids_for(t: &targets::Target, spec: KillSpec) -> Vec<u32> {
    let mut memfds = procs::MemfdVerifier::default();
    t.pids.iter().copied().filter(|&p| p != t.init_pid && !targets::is_zombie(p)).filter(|&p| {
        let exe = std::fs::read_link(format!("/proc/{}/exe", p)).ok()
            .map(|x| x.to_string_lossy().into_owned()).unwrap_or_default();
        let mut staging = || procs::staged_process(p, &exe, &mut memfds).is_some();
        let miner = || {
            let comm = std::fs::read_to_string(format!("/proc/{}/comm", p)).unwrap_or_default();
            crate::security::MINER_PROCS.contains(&comm.trim())
        };
        let hooked = || std::fs::read(format!("/proc/{}/environ", p)).ok()
            .is_some_and(|b| !crate::predictive::intrusion::hooks::hooks_in_environ(&b).is_empty());
        match spec {
            KillSpec::None => false,
            KillSpec::Staging => staging(),
            KillSpec::Miners => miner(),
            KillSpec::EnvHooks => hooked(),
            KillSpec::All => staging() || miner() || hooked(),
        }
    }).collect()
}

/// Key of the target a PID is in, from its cgroup.
fn target_key_of(pid: u32) -> Option<String> {
    let body = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;
    let (kind, id) = targets::classify_cgroup_file(&body, crate::containers::is_proxmox())?;
    Some(match kind {
        targets::TargetKind::Lxc => format!("lxc:{}", id),
        targets::TargetKind::Proxmox => format!("pve:{}", id),
        targets::TargetKind::Docker => format!("docker:{}", id),
        targets::TargetKind::Podman => format!("podman:{}", id),
        targets::TargetKind::Cri => format!("cri:{}", id),
        targets::TargetKind::Host => return None,
    })
}

/// Still the same process (start time) in the same container (cgroup)?
fn still_same(pid: u32, key: &str, started: Option<u64>) -> bool {
    started.is_some() && targets::start_time(pid) == started
        && target_key_of(pid).as_deref() == Some(key)
}

fn write_evidence(dir: &std::path::Path, name: &str, data: &[u8]) -> Result<String, String> {
    let p = dir.join(name);
    let mut f = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o400).open(&p)
        .map_err(|e| format!("{}: {}", p.display(), e))?;
    use std::io::Write;
    f.write_all(data).map_err(|e| format!("{}: {}", p.display(), e))?;
    Ok(crate::predictive::intrusion::sysfiles::sha256_hex(data))
}

/// Copy a process's executable into the evidence dir. Only from a
/// filesystem that cannot block (procs::exe_fs_safe), and only if it fits.
fn capture_exe(dir: &std::path::Path, pid: u32) -> Result<String, String> {
    use std::io::Read;
    if !procs::exe_fs_safe(pid) {
        return Err("executable is on a network/FUSE filesystem (or its filesystem is unknown) — not opened".into());
    }
    let f = std::fs::File::open(format!("/proc/{}/exe", pid)).map_err(|e| format!("open exe: {}", e))?;
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if len > MAX_EXE_CAPTURE {
        return Err(format!("executable is {} bytes, over the {} MiB capture limit", len, MAX_EXE_CAPTURE >> 20));
    }
    let mut buf = Vec::with_capacity(len as usize);
    f.take(MAX_EXE_CAPTURE).read_to_end(&mut buf).map_err(|e| format!("read exe: {}", e))?;
    write_evidence(dir, &format!("{}.exe", pid), &buf)
}

fn capture_and_kill(dir: &std::path::Path, key: &str, pids: &[u32]) -> Vec<KilledProc> {
    // Identify, then freeze all first: a supervisor among them can't
    // respawn the rest while we work.
    let live: Vec<(u32, Option<u64>)> = pids.iter().copied()
        .map(|p| (p, targets::start_time(p)))
        .filter(|(p, st)| still_same(*p, key, *st))
        .collect();
    for (p, _) in &live {
        // SAFETY: plain signal delivery to a PID verified above.
        unsafe { libc::kill(*p as i32, libc::SIGSTOP); }
    }
    let mut out = Vec::new();
    for (p, started) in &live {
        let cmdline = std::fs::read(format!("/proc/{}/cmdline", p)).unwrap_or_default();
        let exe = std::fs::read_link(format!("/proc/{}/exe", p)).ok()
            .map(|x| x.to_string_lossy().into_owned()).unwrap_or_default();
        for f in ["cmdline", "environ", "status", "maps"] {
            if let Ok(b) = std::fs::read(format!("/proc/{}/{}", p, f)) {
                let _ = write_evidence(dir, &format!("{}.{}", p, f), &b);
            }
        }
        let captured = capture_exe(dir, *p);
        let (killed, note, sha256) = match captured {
            Ok(sha) => {
                // Re-checked to close the window between freeze and kill.
                // SAFETY: as above.
                let k = still_same(*p, key, *started) && unsafe { libc::kill(*p as i32, libc::SIGKILL) } == 0;
                (k, if k { String::new() } else { "exited before it could be killed".into() }, Some(sha))
            }
            Err(why) => (false, format!("left FROZEN (SIGSTOP), not killed: {}", why), None),
        };
        out.push(KilledProc {
            pid: *p,
            cmdline: String::from_utf8_lossy(&cmdline).replace('\0', " ").trim().to_string(),
            exe, sha256, killed, note,
        });
    }
    out
}

/// A fresh evidence directory (never shared by two quarantines).
fn new_evidence_dir(target_key: &str) -> Result<std::path::PathBuf, String> {
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(EVIDENCE_ROOT)
        .map_err(|e| format!("create {}: {}", EVIDENCE_ROOT, e))?;
    let _ = std::fs::set_permissions(EVIDENCE_ROOT, std::fs::Permissions::from_mode(0o700));
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
    let safe_key: String = target_key.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    for n in 0..100 {
        let dir = std::path::PathBuf::from(EVIDENCE_ROOT)
            .join(if n == 0 { format!("{}-{}", stamp, safe_key) } else { format!("{}-{}-{}", stamp, safe_key, n) });
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("create evidence dir {}: {}", dir.display(), e)),
        }
    }
    Err("could not allocate an evidence directory".into())
}

// ─── Public actions ────────────────────────────────────────────────

/// Quarantine a running container.
pub fn quarantine(target_key: &str, spec: KillSpec, actor: &str, reason: &str) -> Result<Outcome, String> {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _fl = file_lock()?;
    if target_key == targets::HOST_KEY {
        return Err("the host itself cannot be quarantined — that would cut WolfStack off from it".into());
    }
    let all = targets::enumerate_checked().ok_or("/proc could not be listed — nothing was done")?;
    let t = all.iter().find(|t| t.key == target_key)
        .ok_or_else(|| format!("{} is not running on this node", target_key))?;
    let dir = new_evidence_dir(target_key)?;

    // 0. Persist the intent before touching anything (see module docs).
    let mut state = load().map_err(|e| format!("{} — nothing was done", e))?;
    let existed = state.records.iter().any(|r| r.target_key == target_key);
    if !existed {
        state.records.push(Record {
            target_key: target_key.into(),
            label: t.label.clone(),
            started_at: chrono::Utc::now(),
            actor: actor.into(),
            reason: reason.into(),
            evidence_dir: dir.display().to_string(),
            killed: Vec::new(),
            network: "being isolated".into(),
            fully_isolated: false,
        });
        save(&state).map_err(|e| format!("could not record the quarantine, nothing was done: {}", e))?;
    }

    // 1. Network.
    let links = match host_links(t.init_pid) {
        Ok(l) => l,
        Err(e) => Links { veths: Vec::new(), not_isolated: vec![e] },
    };
    if !links.veths.is_empty() {
        LAST_DEVICES.lock().unwrap_or_else(|e| e.into_inner()).insert(target_key.to_string(), links.veths.clone());
    }
    let devices = devices_for(&state.records, &all);
    let egress = match apply_devices(devices) {
        Ok(eg) => eg,
        Err(e) => {
            if !existed {
                state.records.retain(|r| r.target_key != target_key);
                let _ = save(&state);
            }
            return Err(format!("network isolation failed, nothing else was done: {}", e));
        }
    };
    let fully = !links.veths.is_empty() && links.not_isolated.is_empty();
    let mut network = if links.veths.is_empty() {
        "NOT isolated".to_string()
    } else if egress {
        format!("all traffic to and from {} dropped on the host", links.veths.join(", "))
    } else {
        format!("all traffic from {} dropped on the host (this kernel has no netdev egress hook: packets can still arrive but no reply can leave, so no TCP connection can form)", links.veths.join(", "))
    };
    if !links.not_isolated.is_empty() {
        network.push_str(&format!("; STILL CONNECTED: {}", links.not_isolated.join("; ")));
    }

    // 2. Freeze, capture, kill.
    let killed = capture_and_kill(&dir, target_key, &pids_for(t, spec));

    // 3. Complete the record.
    if let Some(rec) = state.records.iter_mut().find(|r| r.target_key == target_key) {
        rec.network = network.clone();
        rec.fully_isolated = fully;
        rec.killed.extend(killed.iter().cloned());
        let snapshot = Record { evidence_dir: dir.display().to_string(), ..rec.clone() };
        let _ = write_evidence(&dir, "quarantine.json", serde_json::to_string_pretty(&snapshot).unwrap_or_default().as_bytes());
    }
    if let Err(e) = save(&state) {
        tracing::error!("quarantine: {} is isolated but its record could not be updated: {}", target_key, e);
    }
    let stopped = killed.iter().filter(|k| k.killed).count();
    let frozen: Vec<&KilledProc> = killed.iter().filter(|k| !k.killed && k.note.starts_with("left FROZEN")).collect();
    tracing::warn!("SECURITY: {} ({}) quarantined by {} — {}; {} killed, {} left frozen; evidence {}",
        t.label, target_key, actor, network, stopped, frozen.len(), dir.display());

    let mut message = format!("{} quarantined. Network: {}.", t.label, network);
    if !killed.is_empty() {
        message.push_str(&format!(" Processes: {}.", killed.iter().map(|k| format!("PID {} {}", k.pid,
            if k.killed { "killed".to_string() } else { k.note.clone() })).collect::<Vec<_>>().join(", ")));
    }
    message.push_str(&format!(" Evidence: {}.", dir.display()));
    let mut warnings = Vec::new();
    if !fully {
        warnings.push(format!("The container is NOT fully cut off: {}. Stop it (it stays quarantined) or remove those interfaces.",
            if links.not_isolated.is_empty() { "no isolatable link".to_string() } else { links.not_isolated.join("; ") }));
    }
    if !frozen.is_empty() {
        warnings.push(format!("{} process(es) were frozen but not killed because their executable could not be captured as evidence: {}.",
            frozen.len(), frozen.iter().map(|k| format!("PID {} ({})", k.pid, k.note)).collect::<Vec<_>>().join("; ")));
    }
    Ok(Outcome { message, warning: (!warnings.is_empty()).then(|| warnings.join("\n\n")) })
}

/// Lift a quarantine. Evidence stays.
pub fn release(target_key: &str, actor: &str) -> Result<String, String> {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _fl = file_lock()?;
    let mut state = load()?;
    let Some(pos) = state.records.iter().position(|r| r.target_key == target_key) else {
        return Err(format!("{} is not quarantined", target_key));
    };
    let rec = state.records.remove(pos);
    save(&state)?;
    LAST_DEVICES.lock().unwrap_or_else(|e| e.into_inner()).remove(target_key);
    let all = targets::enumerate();
    apply_devices(devices_for(&state.records, &all))
        .map_err(|e| format!("quarantine record removed but the isolation table could not be rewritten: {}", e))?;
    tracing::warn!("SECURITY: quarantine of {} ({}) released by {}", rec.label, target_key, actor);
    Ok(format!("{} released — network restored. Evidence kept at {}.", rec.label, rec.evidence_dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_links_from_ip_o_link() {
        // `ip -o link` lines as printed inside an LXC container.
        let out = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n\
                   2: eth0@if123: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT\\    link/ether 00:16:3e:aa:bb:cc brd ff:ff:ff:ff:ff:ff link-netnsid 0\n\
                   3: eth1@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n";
        assert_eq!(parse_peer_links(out), vec![(2, "eth0".to_string(), 123), (3, "eth1".to_string(), 7)]);
    }

    #[test]
    fn link_details_parsing() {
        // `ip -d -o link show dev vethX` on a Docker host.
        let out = "22: veth48d73be@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default \\    link/ether 6a:1f:00:00:00:01 brd ff:ff:ff:ff:ff:ff link-netnsid 3 promiscuity 1 allmulti 1 minmtu 68 maxmtu 65535 \\    veth addrgenmode eui64";
        assert_eq!(parse_link_details(out), (true, Some(3)));
        assert_eq!(parse_link_details("2: enp7s0: <BROADCAST> mtu 1500 link/ether aa:bb"), (false, None));
    }

    #[test]
    fn own_netns_has_no_peer_id_or_an_answer() {
        // Our own namespace asked about itself: the kernel answers (an id,
        // or "not assigned"); the call must not hang or panic.
        let _ = netnsid_of_pid(std::process::id());
    }

    #[test]
    fn table_render_is_atomic_and_complete() {
        let s = render_table(&["veth107i0".into(), "vethbtCTBv".into()], true);
        assert!(s.starts_with("table netdev wolfstack_quarantine\ndelete table netdev wolfstack_quarantine\n"));
        assert!(s.contains(r#"chain in_0 { type filter hook ingress device "veth107i0" priority -500; policy drop; }"#));
        assert!(s.contains(r#"chain out_1 { type filter hook egress device "vethbtCTBv" priority -500; policy drop; }"#));
        let none = render_table(&[], true);
        assert!(!none.contains("chain"), "empty set just removes the table");
        assert!(!render_table(&["veth0".into()], false).contains("egress"));
    }

    #[test]
    fn interface_names_are_validated() {
        assert!(safe_ifname("vethbtCTBv"));
        assert!(safe_ifname("veth107i0"));
        assert!(!safe_ifname("x\" ; flush ruleset"));
        assert!(!safe_ifname("averyveryverylongname"));
    }
}
