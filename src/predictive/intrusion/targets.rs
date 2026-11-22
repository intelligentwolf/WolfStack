// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Enumerate what a scan covers on this node: the host, plus every
//! running container — native LXC, Proxmox CTs, Docker, Podman and
//! CRI (containerd / CRI-O) — straight from `/proc`.
//!
//! ## Why `/proc` and not `lxc-ls` / `pct list` / the Docker socket
//!
//! The LILITH_VITE_V3 compromise this was built from ran inside an LXC
//! container, and the host-only checks of the time saw nothing but
//! the miner's process name. A scanner that asks each runtime's CLI
//! for its containers needs one code path per runtime, each with its own failure modes
//! (a wedged dockerd, `pct` missing on a non-PVE host). Every container
//! runtime, however, leaves the same two facts in `/proc/<pid>`:
//!
//! * its **cgroup path** names the runtime and the container
//!   (`/lxc.payload.<name>/…`, `/lxc/<vmid>/…`, `docker-<id>.scope`,
//!   `libpod-<id>.scope`, `cri-containerd-<id>.scope`, `crio-<id>.scope`);
//! * its **mount namespace** differs from the host's.
//!
//! A cgroup match alone is not trusted: `lxc.monitor.*` and plain
//! systemd services can carry container-looking paths, and QEMU VMs
//! live in `machine.slice` — but none of those has its own mount
//! namespace *rooted elsewhere*. Requiring both keeps a VM or a
//! monitor process from ever being scanned as a "container".

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetKind {
    Host,
    Lxc,
    Proxmox,
    Docker,
    Podman,
    Cri,
}

impl TargetKind {
    pub fn is_container(self) -> bool { self != TargetKind::Host }
}

#[derive(Debug, Clone)]
pub struct Target {
    /// Stable identity used in proposal resource ids:
    /// `host`, `lxc:<name>`, `pve:<vmid>`, `docker:<id12>`,
    /// `podman:<id12>`, `cri:<id12>`.
    pub key: String,
    /// Human label for inbox cards.
    pub label: String,
    pub kind: TargetKind,
    /// Process whose root and namespaces represent the target
    /// (1 for the host; the container's init otherwise).
    pub init_pid: u32,
    /// Every PID currently in the target.
    pub pids: Vec<u32>,
}

/// Host target key. Kept as a constant because resource ids built from
/// it are persisted in the proposal store.
pub const HOST_KEY: &str = "host";

/// Classify one cgroup path. Pure so every runtime's real path shape is
/// unit-tested. Returns (kind, id) or None for host processes.
pub fn classify_cgroup_path(path: &str, proxmox: bool) -> Option<(TargetKind, String)> {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for (i, seg) in segs.iter().enumerate() {
        // LXC 4+: /lxc.payload.<name>/...
        if let Some(name) = seg.strip_prefix("lxc.payload.") {
            if name.is_empty() { return None; }
            return Some((TargetKind::Lxc, name.to_string()));
        }
        // The monitor process runs on the host side.
        if seg.starts_with("lxc.monitor") { return None; }
        // Proxmox (and LXC 3): /lxc/<vmid-or-name>/...
        if *seg == "lxc" {
            let id = segs.get(i + 1)?;
            if proxmox && id.chars().all(|c| c.is_ascii_digit()) {
                return Some((TargetKind::Proxmox, id.to_string()));
            }
            return Some((TargetKind::Lxc, id.to_string()));
        }
        // Docker under systemd cgroup driver: docker-<64hex>.scope
        if let Some(rest) = seg.strip_prefix("docker-").and_then(|r| r.strip_suffix(".scope"))
            && is_container_id(rest) {
            return Some((TargetKind::Docker, rest[..12].to_string()));
        }
        // Docker under cgroupfs driver: /docker/<64hex>
        if *seg == "docker"
            && let Some(id) = segs.get(i + 1)
            && is_container_id(id) {
            return Some((TargetKind::Docker, id[..12].to_string()));
        }
        // Podman: libpod-<64hex>.scope (libpod-conmon-* is the host-side monitor).
        if let Some(rest) = seg.strip_prefix("libpod-").and_then(|r| r.strip_suffix(".scope"))
            && is_container_id(rest) {
            return Some((TargetKind::Podman, rest[..12].to_string()));
        }
        if let Some(rest) = seg.strip_prefix("cri-containerd-").and_then(|r| r.strip_suffix(".scope"))
            .or_else(|| seg.strip_prefix("crio-").and_then(|r| r.strip_suffix(".scope")))
            && is_container_id(rest) {
            return Some((TargetKind::Cri, rest[..12].to_string()));
        }
    }
    None
}

/// 64 lowercase hex characters — the id form Docker, Podman, containerd
/// and CRI-O all use in their cgroup names.
fn is_container_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Pick the classified path out of a `/proc/<pid>/cgroup` body. cgroup
/// v2 has one `0::<path>` line; on v1 any line may carry the container
/// path, so the first that classifies wins.
pub fn classify_cgroup_file(body: &str, proxmox: bool) -> Option<(TargetKind, String)> {
    body.lines()
        .filter_map(|l| l.splitn(3, ':').nth(2))
        .find_map(|p| classify_cgroup_path(p, proxmox))
}

/// Is the process a zombie (`Z`) or dead (`X`)? Such an entry has already
/// exited: it runs no code, holds no executable (`/proc/<pid>/exe` is gone)
/// and only waits for a parent to reap it — which never happens under a
/// container init like `sleep infinity`. It still carries its old name, so
/// without this check a killed miner would be reported as running forever.
/// State is the field after the last ')' of /proc/<pid>/stat (proc(5)).
pub fn is_zombie(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()
        .and_then(|s| s.rfind(')').map(|i| s[i + 1..].trim_start().chars().next()))
        .flatten()
        .is_some_and(|c| c == 'Z' || c == 'X')
}

/// Process start time in clock ticks since boot (field 22 of
/// /proc/<pid>/stat, proc(5)). With the PID it identifies one process
/// for its whole life — a recycled PID has a different start time.
pub fn start_time(pid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Fields after the last ')' start at field 3 (state); 22 - 3 = 19.
    s[s.rfind(')')? + 1..].split_whitespace().nth(19)?.parse().ok()
}

fn ppid_of(pid: u32) -> Option<u32> {
    let s = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // comm is parenthesised and may contain spaces/parens — the fields
    // after the LAST ')' are fixed: state ppid ... (proc(5)).
    let after = &s[s.rfind(')')? + 1..];
    after.split_whitespace().nth(1)?.parse().ok()
}

fn mnt_ns(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{}/ns/mnt", pid)).ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Proxmox CT hostname from `/etc/pve/lxc/<vmid>.conf` (`hostname: x`).
fn pve_hostname(vmid: &str) -> Option<String> {
    let cfg = std::fs::read_to_string(format!("/etc/pve/lxc/{}.conf", vmid)).ok()?;
    cfg.lines()
        // Snapshot sections ([snap]) repeat keys; only the live config
        // before the first section header counts.
        .take_while(|l| !l.starts_with('['))
        .find_map(|l| l.strip_prefix("hostname:").map(|v| v.trim().to_string()))
        .filter(|v| !v.is_empty())
}

/// Docker container name from its config (`"Name":"/web"`). Only the
/// default data-root is consulted; a relocated data-root just yields
/// the short id, which is still a correct label.
fn docker_name(id12: &str) -> Option<String> {
    let dir = std::fs::read_dir("/var/lib/docker/containers").ok()?;
    for ent in dir.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if !name.starts_with(id12) { continue; }
        let body = std::fs::read_to_string(ent.path().join("config.v2.json")).ok()?;
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        return v.get("Name").and_then(|n| n.as_str())
            .map(|n| n.trim_start_matches('/').to_string())
            .filter(|n| !n.is_empty());
    }
    None
}

/// The environment a container was DEFINED with (image ENV + run/compose
/// `-e`), as `VAR=value` records. A loader variable declared here is part of
/// the image — the linuxserver.io desktop images, for one, ship
/// `LD_PRELOAD=/usr/lib/selkies_joystick_interposer.so:…` — not an injection.
///
/// * Docker: `Config.Env` of `/var/lib/docker/containers/<id>/config.v2.json`.
/// * Podman (rootful): `process.env` of the OCI spec podman reports as
///   `OCIConfigPath`, `/var/lib/containers/storage/overlay-containers/<id>/userdata/config.json`.
///
/// Empty for LXC (no declared environment) and when the file isn't there
/// (relocated data-root) — the processes are then judged on their own.
pub fn declared_env(kind: TargetKind, id12: &str) -> Vec<String> {
    let (dir, file, pointer) = match kind {
        TargetKind::Docker => ("/var/lib/docker/containers", "config.v2.json", "/Config/Env"),
        TargetKind::Podman => ("/var/lib/containers/storage/overlay-containers", "userdata/config.json", "/process/env"),
        _ => return Vec::new(),
    };
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    for ent in rd.flatten() {
        if !ent.file_name().to_string_lossy().starts_with(id12) { continue; }
        let Ok(body) = std::fs::read_to_string(ent.path().join(file)) else { return Vec::new() };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else { return Vec::new() };
        return v.pointer(pointer).and_then(|e| e.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
    }
    Vec::new()
}

fn label_for(kind: TargetKind, id: &str) -> String {
    match kind {
        TargetKind::Host => "host".into(),
        TargetKind::Lxc => format!("LXC {}", id),
        TargetKind::Proxmox => match pve_hostname(id) {
            Some(h) => format!("CT {} ({})", id, h),
            None => format!("CT {}", id),
        },
        TargetKind::Docker => match docker_name(id) {
            Some(n) => format!("Docker {} ({})", n, id),
            None => format!("Docker {}", id),
        },
        TargetKind::Podman => format!("Podman {}", id),
        TargetKind::Cri => format!("CRI container {}", id),
    }
}

fn key_for(kind: TargetKind, id: &str) -> String {
    match kind {
        TargetKind::Host => HOST_KEY.into(),
        TargetKind::Lxc => format!("lxc:{}", id),
        TargetKind::Proxmox => format!("pve:{}", id),
        TargetKind::Docker => format!("docker:{}", id),
        TargetKind::Podman => format!("podman:{}", id),
        TargetKind::Cri => format!("cri:{}", id),
    }
}

/// All PIDs currently in /proc.
pub fn all_pids() -> Vec<u32> {
    let Ok(rd) = std::fs::read_dir("/proc") else { return Vec::new() };
    rd.flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()))
        .collect()
}

/// Enumerate the host and every running container. The host target is
/// always first; containers are sorted by key for stable output. An
/// unreadable /proc yields the host target alone — callers for which
/// "no containers" and "could not look" differ use [`enumerate_checked`].
pub fn enumerate() -> Vec<Target> {
    enumerate_checked().unwrap_or_else(|| vec![Target {
        key: HOST_KEY.into(), label: "host".into(), kind: TargetKind::Host, init_pid: 1, pids: Vec::new(),
    }])
}

/// [`enumerate`], or None when /proc could not be listed.
pub fn enumerate_checked() -> Option<Vec<Target>> {
    std::fs::read_dir("/proc").ok()?;
    let proxmox = crate::containers::is_proxmox();
    let host_ns = mnt_ns(1);
    let mut groups: HashMap<(TargetKind, String), Vec<u32>> = HashMap::new();
    let mut host_pids = Vec::new();
    for pid in all_pids() {
        let body = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).unwrap_or_default();
        match classify_cgroup_file(&body, proxmox) {
            Some(k) => groups.entry(k).or_default().push(pid),
            None => host_pids.push(pid),
        }
    }
    let mut out = vec![Target {
        key: HOST_KEY.into(),
        label: "host".into(),
        kind: TargetKind::Host,
        init_pid: 1,
        pids: Vec::new(),
    }];
    let mut containers = Vec::new();
    for ((kind, id), mut pids) in groups {
        pids.sort_unstable();
        let set: HashSet<u32> = pids.iter().copied().collect();
        // The container's init is the process whose parent is outside
        // the container (lxc-start / containerd-shim / conmon). Among
        // several such (an `lxc-attach` / `docker exec` shell also has an
        // outside parent), the EARLIEST started — not the lowest PID, which
        // after a PID wrap can be a later shell.
        let init = pids.iter().copied()
            .filter(|p| ppid_of(*p).is_none_or(|pp| !set.contains(&pp)))
            .min_by_key(|p| start_time(*p).unwrap_or(u64::MAX));
        let Some(init) = init else { continue };
        let ns = mnt_ns(init);
        if ns.is_none() || ns == host_ns {
            // Same mount namespace as the host: not a container root we
            // can or should scan separately. Its processes are host ones.
            host_pids.extend(pids);
            continue;
        }
        containers.push(Target {
            key: key_for(kind, &id),
            label: label_for(kind, &id),
            kind,
            init_pid: init,
            pids,
        });
    }
    host_pids.sort_unstable();
    out[0].pids = host_pids;
    containers.sort_by(|a, b| a.key.cmp(&b.key));
    out.extend(containers);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_lxc_payload_path() {
        // Real line from a compromised container's miner.
        assert_eq!(
            classify_cgroup_path("/lxc.payload.nodejs/system.slice/cron.service", false),
            Some((TargetKind::Lxc, "nodejs".into())));
        assert_eq!(classify_cgroup_path("/lxc.monitor.nodejs", false), None);
    }

    #[test]
    fn proxmox_vmid_path() {
        assert_eq!(classify_cgroup_path("/lxc/107/ns/system.slice/cron.service", true),
            Some((TargetKind::Proxmox, "107".into())));
        // Same shape on a non-PVE host is a plain (LXC 3) container.
        assert_eq!(classify_cgroup_path("/lxc/web/ns/init.scope", false),
            Some((TargetKind::Lxc, "web".into())));
        assert_eq!(classify_cgroup_path("/lxc.monitor/107", true), None);
    }

    #[test]
    fn docker_podman_cri_paths() {
        let id = "a".repeat(64);
        assert_eq!(classify_cgroup_path(&format!("/system.slice/docker-{}.scope", id), false),
            Some((TargetKind::Docker, "a".repeat(12))));
        assert_eq!(classify_cgroup_path(&format!("/docker/{}", id), false),
            Some((TargetKind::Docker, "a".repeat(12))));
        assert_eq!(classify_cgroup_path(&format!("/machine.slice/libpod-{}.scope/container", id), false),
            Some((TargetKind::Podman, "a".repeat(12))));
        assert_eq!(classify_cgroup_path(&format!("/machine.slice/libpod-conmon-{}.scope", id), false), None);
        assert_eq!(classify_cgroup_path(
            &format!("/kubepods.slice/kubepods-pod1.slice/cri-containerd-{}.scope", id), false),
            Some((TargetKind::Cri, "a".repeat(12))));
        // Not 64-hex → not a container id.
        assert_eq!(classify_cgroup_path("/system.slice/docker-compose.scope", false), None);
    }

    #[test]
    fn host_paths_are_not_containers() {
        assert_eq!(classify_cgroup_path("/system.slice/sshd.service", true), None);
        assert_eq!(classify_cgroup_path("/machine.slice/machine-qemu\\x2d1\\x2dvm.scope", true), None);
        assert_eq!(classify_cgroup_path("/user.slice/user-0.slice/session-3.scope", false), None);
    }

    #[test]
    fn cgroup_v1_file_first_classifying_line_wins() {
        let body = "12:pids:/lxc.payload.web\n1:name=systemd:/lxc.payload.web/init.scope\n0::/\n";
        assert_eq!(classify_cgroup_file(body, false), Some((TargetKind::Lxc, "web".into())));
        assert_eq!(classify_cgroup_file("0::/system.slice/cron.service\n", false), None);
    }

    #[test]
    fn start_time_is_read_for_live_processes() {
        assert!(start_time(std::process::id()).is_some());
        assert!(start_time(u32::MAX).is_none());
    }

    #[test]
    fn this_process_is_not_a_zombie() {
        assert!(!is_zombie(std::process::id()));
        assert!(!is_zombie(u32::MAX), "a missing pid is not a zombie");
    }

    #[test]
    fn enumerate_always_has_host_first() {
        let t = enumerate();
        assert_eq!(t[0].key, HOST_KEY);
        assert_eq!(t[0].init_pid, 1);
    }
}
