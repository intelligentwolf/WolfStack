// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Live process indicators inside containers.
//!
//! * **Executing from `/tmp`, `/dev/shm` or memory** — the LILITH_VITE_V3
//!   miner re-drops itself to `/tmp/tmp.XXXXXX/xmrig-6.26.0/` every time
//!   it is killed. A process whose executable lives in a
//!   world-writable scratch directory, or in an anonymous `memfd`
//!   (fileless), is the compromise signal operators asked to be woken
//!   for.
//! * **Known miner names** — the same list the host scanner uses
//!   (`security::MINER_PROCS`). Container processes are reported here,
//!   host processes by the host scanner, so one miner pages once.
//! * **Loader hooks in a running process's environment** — see
//!   `hooks.rs`.
//! * **Freshly-dropped executables in a container's own `/tmp` and
//!   `/dev/shm`** — the host scanner only ever looked at the host's.
//!
//! Evidence carries what an investigator needs before touching anything:
//! PID, PPID, command line, user, executable path, its mode/size/mtime,
//! SHA-256 (for threat-intel lookups) and remote TCP peers.

use super::hooks::{self, Hook};
use super::net;
use super::rootfs::RootFs;
use super::targets::Target;
use std::collections::BTreeMap;

/// memfd names that are legitimate executables. runc re-executes itself
/// from a sealed memfd to defend against CVE-2019-5736; the name is
/// `RUNC_MEMFD_COMMENT` in libcontainer/nsenter/cloned_binary.c.
const BENIGN_MEMFD: &[&str] = &["runc_cloned:/proc/self/exe"];

/// memfds that are cleared only after their CONTENT is checked. A memfd
/// name is whatever its creator passed to memfd_create(2), so a name alone
/// would let malware hide by borrowing one. Each entry is the memfd name
/// and the HOST path of the binary it must be a byte-for-byte copy of;
/// that file must also be owned by a host package.
///
/// LXC's tools re-execute themselves from a sealed memfd (same defence as
/// runc's): `lxc_rexec("lxc-attach")` in src/lxc/tools/lxc_attach.c,
/// `memfd_create(memfd_name, ...)` in src/lxc/rexec.c. Proxmox's
/// `pct exec` / `pct enter` run lxc-attach, shipped as /usr/bin/lxc-attach
/// (lxc-pve; Debian/Fedora/Arch lxc packages install it there too).
const VERIFIED_MEMFD: &[(&str, &str)] = &[("lxc-attach", "/usr/bin/lxc-attach")];

/// The memfd name of an exe link (`/memfd:<name> (deleted)`), if it is one.
fn memfd_name(exe: &str) -> Option<&str> {
    exe.strip_prefix("/memfd:").map(|r| r.trim_end_matches(" (deleted)"))
}

/// Checks verifiable memfds ([`VERIFIED_MEMFD`]) against the host's
/// package-owned originals. The expected hash of each original is worked
/// out once per verifier (the ownership query streams the whole package
/// database), and only when such a memfd is actually seen.
#[derive(Default)]
pub struct MemfdVerifier {
    /// host path → SHA-256 of that file when a host package owns it.
    expected: std::collections::HashMap<&'static str, Option<String>>,
}

impl MemfdVerifier {
    fn expected_hash(&mut self, path: &'static str) -> Option<String> {
        self.expected.entry(path).or_insert_with(|| {
            // Through /proc/1/root, like every other host read here.
            let host = RootFs::for_pid(1)?;
            let (_, owned) = super::pkgdb::owned(&host, "/", &[path.to_string()])?;
            if !owned.contains(path) { return None; }
            let body = host.read(path, EXE_HASH_CAP as usize)?;
            Some(super::sysfiles::sha256_hex(&body))
        }).clone()
    }

    /// Is `pid`, running from memfd `exe`, a verified copy of a packaged
    /// host binary? Anything that cannot be checked is "no".
    pub fn is_verified(&mut self, pid: u32, exe: &str) -> bool {
        let Some(name) = memfd_name(exe) else { return false };
        let Some(&(_, path)) = VERIFIED_MEMFD.iter().find(|(n, _)| *n == name) else { return false };
        let Some(want) = self.expected_hash(path) else { return false };
        exe_sha256(pid).is_some_and(|got| got == want)
    }
}

/// [`staging_exe`] for a live process: a memfd listed in
/// [`VERIFIED_MEMFD`] whose content matches its packaged original is not
/// staging. Used by both the scan and quarantine's kill selection, so the
/// two cannot disagree about which processes are suspect.
pub fn staged_process(pid: u32, exe: &str, v: &mut MemfdVerifier) -> Option<&'static str> {
    let place = staging_exe(exe)?;
    if v.is_verified(pid, exe) { return None; }
    Some(place)
}

/// Where a process executes from, if that place is a staging area, by
/// path alone. Memfds in [`VERIFIED_MEMFD`] are still reported here —
/// clearing them takes [`staged_process`], which checks their content.
pub fn staging_exe(exe: &str) -> Option<&'static str> {
    if exe.starts_with("/tmp/") { return Some("/tmp"); }
    if exe.starts_with("/dev/shm/") { return Some("/dev/shm"); }
    if let Some(name) = memfd_name(exe) {
        if BENIGN_MEMFD.contains(&name) { return None; }
        return Some("memory (memfd)");
    }
    None
}

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub user: String,
    pub comm: String,
    pub cmdline: String,
    pub exe: String,
    /// "mode 0755, 8350992 bytes, mtime 2026-03-28T13:07:24Z", when the
    /// executable could be statted.
    pub exe_meta: Option<String>,
    pub sha256: Option<String>,
    pub remotes: Vec<String>,
}

fn status_field(status: &str, key: &str) -> Option<String> {
    status.lines().find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
}

/// uid → name from the target's own passwd (a container's uid 0 is its
/// root, whatever the host-side mapping).
fn user_name(passwd: &str, uid: u32) -> String {
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 2 && f[2].parse::<u32>().ok() == Some(uid)).then(|| f[0].to_string())
    }).unwrap_or_else(|| uid.to_string())
}

/// Device (decimal `maj:min`) of the file mapped at `exe`, from a
/// `/proc/<pid>/maps` body: `addr perms offset dev inode path`, dev in hex
/// (`00:1e`), as checked against a live host.
pub fn maps_dev_of(maps: &str, exe: &str) -> Option<String> {
    let exe = exe.trim_end_matches(" (deleted)");
    for line in maps.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 || f[4] == "0" { continue; }
        let path = f[5..].join(" ");
        if path.trim_end_matches(" (deleted)") != exe { continue; }
        let (maj, min) = f[3].split_once(':')?;
        return Some(format!("{}:{}", u32::from_str_radix(maj, 16).ok()?, u32::from_str_radix(min, 16).ok()?));
    }
    None
}

/// Filesystem type of the mount with device `dev` (decimal `maj:min`,
/// mountinfo field 3) in a mountinfo body.
pub fn fstype_of_dev(mountinfo: &str, dev: &str) -> Option<String> {
    mountinfo.lines().find_map(|l| {
        let f: Vec<&str> = l.split(' ').collect();
        if f.len() < 7 || f[2] != dev { return None; }
        let sep = f.iter().position(|x| *x == "-")?;
        f.get(sep + 1).map(|t| t.to_string())
    })
}

/// May `/proc/<pid>/exe` be opened or statted without risk of blocking?
/// A process can run from a FUSE or NFS mount (one the container mounted
/// itself, even); opening that file waits for the daemon. The answer
/// comes from kernel bookkeeping only — maps + the process's mountinfo —
/// so asking never touches the filesystem in question. Unknown = no.
pub fn exe_fs_safe(pid: u32) -> bool {
    let Ok(exe) = std::fs::read_link(format!("/proc/{}/exe", pid)) else { return false };
    let exe = exe.to_string_lossy();
    if exe.starts_with("/memfd:") { return true; } // anonymous memory, no filesystem
    let (Ok(maps), Ok(mi)) = (std::fs::read_to_string(format!("/proc/{}/maps", pid)),
        std::fs::read_to_string(format!("/proc/{}/mountinfo", pid))) else { return false };
    maps_dev_of(&maps, &exe)
        .and_then(|d| fstype_of_dev(&mi, &d))
        .is_some_and(|t| !super::rootfs::fstype_can_block(&t))
}

/// Largest executable hashed: a miner is ~8 MB, nothing staged in /tmp
/// legitimately approaches this.
const EXE_HASH_CAP: u64 = 256 << 20;

/// Hash an executable through /proc/<pid>/exe, which works even when the
/// file was deleted or the path is in another mount namespace (or is a
/// memfd). Capped at [`EXE_HASH_CAP`].
fn exe_sha256(pid: u32) -> Option<String> {
    use std::io::Read;
    if !exe_fs_safe(pid) { return None; }
    let f = std::fs::File::open(format!("/proc/{}/exe", pid)).ok()?;
    if f.metadata().ok()?.len() > EXE_HASH_CAP { return None; }
    let mut buf = Vec::new();
    f.take(EXE_HASH_CAP).read_to_end(&mut buf).ok()?;
    Some(super::sysfiles::sha256_hex(&buf))
}

fn exe_meta(pid: u32) -> Option<String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !exe_fs_safe(pid) { return Some("on a network/FUSE filesystem — not opened".into()); }
    let m = std::fs::metadata(format!("/proc/{}/exe", pid)).ok()?;
    let mtime = chrono::DateTime::from_timestamp(m.mtime(), 0)
        .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default();
    Some(format!("mode {:04o}, {} bytes, mtime {}", m.permissions().mode() & 0o7777, m.len(), mtime))
}

/// Full investigator record for one PID.
pub fn proc_info(pid: u32, passwd: &str, socks: &[net::Sock], hash: bool) -> Option<ProcInfo> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    let ppid = status_field(&status, "PPid:").and_then(|v| v.parse().ok()).unwrap_or(0);
    // /proc/<pid>/status reports the REAL uid as the host sees it; an
    // unprivileged container's root is e.g. 100000 there. The target's
    // passwd names ids as the container sees them, so translate.
    let host_uid: u32 = status_field(&status, "Uid:")
        .and_then(|v| v.split_whitespace().next().and_then(|x| x.parse().ok()))
        .unwrap_or(u32::MAX);
    let uid = ns_uid(pid, host_uid);
    let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid)).unwrap_or_default().trim().to_string();
    let cmdline = std::fs::read(format!("/proc/{}/cmdline", pid)).ok()
        .map(|b| String::from_utf8_lossy(&b).replace('\0', " ").trim().to_string())
        .unwrap_or_default();
    let exe = std::fs::read_link(format!("/proc/{}/exe", pid)).ok()
        .map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let inodes = net::socket_inodes(pid);
    let remotes = socks.iter()
        .filter(|s| s.state == net::TCP_ESTABLISHED && inodes.contains(&s.inode))
        .map(|s| format!("{}:{}", s.remote, s.remote_port))
        .collect();
    Some(ProcInfo {
        pid, ppid, uid, user: user_name(passwd, uid), comm,
        cmdline: cmdline.chars().take(400).collect(),
        exe_meta: exe_meta(pid),
        sha256: if hash { exe_sha256(pid) } else { None },
        exe, remotes,
    })
}

/// Map a host-side uid to the target's view using /proc/<pid>/uid_map
/// (user_namespaces(7): `inside outside count` per line).
fn ns_uid(pid: u32, host_uid: u32) -> u32 {
    let Ok(map) = std::fs::read_to_string(format!("/proc/{}/uid_map", pid)) else { return host_uid };
    for line in map.lines() {
        let f: Vec<u64> = line.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        if f.len() == 3 && (host_uid as u64) >= f[1] && (host_uid as u64) < f[1] + f[2] {
            return (host_uid as u64 - f[1] + f[0]) as u32;
        }
    }
    host_uid
}

#[derive(Debug, Default, Clone)]
pub struct ProcFindings {
    /// exe path → processes running it from a staging area.
    pub staging: BTreeMap<String, (String, Vec<ProcInfo>)>,
    /// miner name → processes.
    pub miners: BTreeMap<String, Vec<ProcInfo>>,
    /// (var, value) → (hook, processes).
    pub env_hooks: BTreeMap<(String, String), (Hook, Vec<ProcInfo>)>,
    /// Fresh executables in the target's /tmp and /dev/shm:
    /// (path, "mode, age").
    pub tmp_files: Vec<(String, String)>,
}

/// Scan one container target's processes.
pub fn scan(target: &Target, root: &RootFs, now: i64) -> ProcFindings {
    let mut f = ProcFindings::default();
    let passwd = root.read_string("etc/passwd", 4 << 20).unwrap_or_default();
    let socks = net::tcp_sockets(target.init_pid);
    let mut memfds = MemfdVerifier::default();
    for &pid in &target.pids {
        if super::targets::is_zombie(pid) { continue; }
        let exe = std::fs::read_link(format!("/proc/{}/exe", pid)).ok()
            .map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid)).unwrap_or_default().trim().to_string();
        let staged = staged_process(pid, &exe, &mut memfds);
        let miner = crate::security::MINER_PROCS.contains(&comm.as_str());
        let env = std::fs::read(format!("/proc/{}/environ", pid)).ok()
            .map(|b| hooks::hooks_in_environ(&b[..b.len().min(256 << 10)]))
            .unwrap_or_default();
        if staged.is_none() && !miner && env.is_empty() { continue; }
        let Some(info) = proc_info(pid, &passwd, &socks, staged.is_some() || miner) else { continue };
        if let Some(place) = staged {
            f.staging.entry(exe.trim_end_matches(" (deleted)").to_string())
                .or_insert_with(|| (place.to_string(), Vec::new())).1.push(info.clone());
        }
        if miner {
            f.miners.entry(comm.clone()).or_default().push(info.clone());
        }
        for h in env {
            f.env_hooks.entry((h.var.clone(), h.value.clone()))
                .or_insert_with(|| (h.clone(), Vec::new())).1.push(info.clone());
        }
    }
    for dir in ["tmp", "dev/shm"] {
        for e in root.list_dir(dir) {
            if !e.meta.is_file() { continue; }
            let age = now - e.meta.mtime;
            if !crate::security::tmp_file_flaggable(&e.name, e.meta.mode, age) { continue; }
            f.tmp_files.push((format!("/{}/{}", dir, e.name),
                format!("mode {:04o}, {} min old, {} bytes", e.meta.mode & 0o7777, age / 60, e.meta.size)));
        }
    }
    f
}

/// One-line evidence text for a process.
pub fn describe(p: &ProcInfo) -> String {
    let mut s = format!("PID {} (PPID {}) user {} (uid {}) — {}", p.pid, p.ppid, p.user, p.uid,
        if p.cmdline.is_empty() { &p.comm } else { &p.cmdline });
    s.push_str(&format!("\n  exe: {}", p.exe));
    if let Some(m) = &p.exe_meta { s.push_str(&format!(" ({})", m)); }
    if let Some(h) = &p.sha256 { s.push_str(&format!("\n  sha256: {}", h)); }
    if !p.remotes.is_empty() { s.push_str(&format!("\n  connected to: {}", p.remotes.join(", "))); }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_device_resolves_to_its_filesystem() {
        // Lines captured from a live host.
        let maps = "561fa43f6000-561fa43f8000 r--p 00000000 00:1e 3817113                    /usr/bin/head\n";
        assert_eq!(maps_dev_of(maps, "/usr/bin/head").as_deref(), Some("0:30"));
        let mi = "33 2 0:30 /@ / rw,noatime shared:1 - btrfs /dev/mapper/root rw\n\
                  90 33 0:61 / /tmp/f rw - fuse.rclone r: rw\n";
        assert_eq!(fstype_of_dev(mi, "0:30").as_deref(), Some("btrfs"));
        assert_eq!(fstype_of_dev(mi, "0:61").as_deref(), Some("fuse.rclone"));
        assert!(maps_dev_of(maps, "/usr/bin/other").is_none());
    }

    #[test]
    fn own_executable_is_safe_to_open() {
        assert!(exe_fs_safe(std::process::id()));
    }

    #[test]
    fn staging_locations() {
        // The exact path the LILITH_VITE_V3 miner re-drops itself to.
        assert_eq!(staging_exe("/tmp/tmp.Ph3NtrbbGj/xmrig-6.26.0/xmrig"), Some("/tmp"));
        assert_eq!(staging_exe("/dev/shm/.x/k"), Some("/dev/shm"));
        assert_eq!(staging_exe("/memfd:payload (deleted)"), Some("memory (memfd)"));
        assert_eq!(staging_exe("/memfd:runc_cloned:/proc/self/exe (deleted)"), None);
        // lxc-attach is cleared only by a content check, never by name.
        assert_eq!(staging_exe("/memfd:lxc-attach (deleted)"), Some("memory (memfd)"));
        assert_eq!(staging_exe("/usr/bin/node"), None);
        assert_eq!(staging_exe("/usr/bin/node (deleted)"), None);
        // /var/tmp is deliberately out of scope (too many legitimate layouts).
        assert_eq!(staging_exe("/var/tmp/x"), None);
    }

    #[test]
    fn memfd_named_like_lxc_attach_is_not_trusted_by_name() {
        // This test process is not a memfd copy of /usr/bin/lxc-attach, so
        // borrowing the name must not clear it — whatever the host has.
        let me = std::process::id();
        let mut v = MemfdVerifier::default();
        assert!(!v.is_verified(me, "/memfd:lxc-attach (deleted)"));
        assert_eq!(staged_process(me, "/memfd:lxc-attach (deleted)", &mut v), Some("memory (memfd)"));
        // Names not in the verified list are never cleared by content.
        assert!(!v.is_verified(me, "/memfd:payload (deleted)"));
        assert!(!v.is_verified(me, "/usr/bin/lxc-attach"));
    }

    #[test]
    fn memfd_copy_of_the_expected_binary_is_verified() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        // A real process executing from a memfd named "lxc-attach", the way
        // LXC's rexec.c builds it: copy the binary in, then exec the memfd.
        // /usr/bin/sleep stands in for lxc-attach so this runs on any host.
        let src = std::fs::read("/usr/bin/sleep").expect("sleep binary");
        let name = std::ffi::CString::new("lxc-attach").unwrap();
        // SAFETY: valid C string; result checked. No MFD_CLOEXEC, so the
        // child inherits it and can exec it by /proc/self/fd path.
        let raw = unsafe { libc::memfd_create(name.as_ptr(), 0) };
        assert!(raw >= 0, "memfd_create");
        // SAFETY: freshly returned descriptor, owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        std::io::Write::write_all(&mut std::fs::File::from(fd.try_clone().unwrap()), &src).unwrap();
        let mut child = std::process::Command::new(format!("/proc/self/fd/{}", fd.as_raw_fd()))
            .arg("30").spawn().expect("exec memfd");
        let pid = child.id();
        let exe = (0..200).find_map(|_| {
            let e = std::fs::read_link(format!("/proc/{}/exe", pid)).ok()?.to_string_lossy().into_owned();
            if e.starts_with("/memfd:") { Some(e) } else { std::thread::sleep(std::time::Duration::from_millis(10)); None }
        }).expect("child running from the memfd");
        assert_eq!(memfd_name(&exe), Some("lxc-attach"));

        let mut good = MemfdVerifier::default();
        good.expected.insert("/usr/bin/lxc-attach", Some(crate::predictive::intrusion::sysfiles::sha256_hex(&src)));
        let mut bad = MemfdVerifier::default();
        bad.expected.insert("/usr/bin/lxc-attach", Some("0".repeat(64)));
        let mut unowned = MemfdVerifier::default();
        unowned.expected.insert("/usr/bin/lxc-attach", None);
        let results = (good.is_verified(pid, &exe), staged_process(pid, &exe, &mut good),
            bad.is_verified(pid, &exe), unowned.is_verified(pid, &exe));
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(results, (true, None, false, false));
    }

    #[test]
    fn expected_hash_is_the_packaged_original_when_readable() {
        // Live host check: when this host has a packaged lxc-attach and the
        // host root is readable (/proc/1/root needs root), the expected hash
        // must be that file's. Otherwise it must be None, never a guess.
        let got = MemfdVerifier::default().expected_hash("/usr/bin/lxc-attach");
        if let Some(h) = got {
            let disk = std::fs::read("/usr/bin/lxc-attach").expect("lxc-attach readable");
            assert_eq!(h, crate::predictive::intrusion::sysfiles::sha256_hex(&disk));
        }
    }

    #[test]
    fn memfd_names_parse() {
        assert_eq!(memfd_name("/memfd:lxc-attach (deleted)"), Some("lxc-attach"));
        assert_eq!(memfd_name("/memfd:runc_cloned:/proc/self/exe (deleted)"), Some("runc_cloned:/proc/self/exe"));
        assert_eq!(memfd_name("/usr/bin/lxc-attach"), None);
    }

    #[test]
    fn user_names_come_from_the_targets_passwd() {
        assert_eq!(user_name("root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/sh\n", 1000), "bob");
        assert_eq!(user_name("", 42), "42");
    }
}
