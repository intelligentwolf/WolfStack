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

/// Where a process executes from, if that place is a staging area.
pub fn staging_exe(exe: &str) -> Option<&'static str> {
    if exe.starts_with("/tmp/") { return Some("/tmp"); }
    if exe.starts_with("/dev/shm/") { return Some("/dev/shm"); }
    if let Some(rest) = exe.strip_prefix("/memfd:") {
        let name = rest.trim_end_matches(" (deleted)");
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

/// Hash an executable through /proc/<pid>/exe, which works even when the
/// file was deleted or the path is in another mount namespace. Capped:
/// a miner is ~8 MB, nothing staged in /tmp legitimately approaches this.
fn exe_sha256(pid: u32) -> Option<String> {
    use std::io::Read;
    if !exe_fs_safe(pid) { return None; }
    const CAP: u64 = 256 << 20;
    let f = std::fs::File::open(format!("/proc/{}/exe", pid)).ok()?;
    if f.metadata().ok()?.len() > CAP { return None; }
    let mut buf = Vec::new();
    f.take(CAP).read_to_end(&mut buf).ok()?;
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
    for &pid in &target.pids {
        if super::targets::is_zombie(pid) { continue; }
        let exe = std::fs::read_link(format!("/proc/{}/exe", pid)).ok()
            .map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid)).unwrap_or_default().trim().to_string();
        let staged = staging_exe(&exe);
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
        assert_eq!(staging_exe("/usr/bin/node"), None);
        assert_eq!(staging_exe("/usr/bin/node (deleted)"), None);
        // /var/tmp is deliberately out of scope (too many legitimate layouts).
        assert_eq!(staging_exe("/var/tmp/x"), None);
    }

    #[test]
    fn user_names_come_from_the_targets_passwd() {
        assert_eq!(user_name("root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/sh\n", 1000), "bob");
        assert_eq!(user_name("", 42), "42");
    }
}
