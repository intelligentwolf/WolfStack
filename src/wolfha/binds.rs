// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Host storage a protected container bind-mounts, and the checks that
//! decide whether a copy can start on this node.
//!
//! Source: a promotion of `gateway` to wolfstack-2 on 2026-11-22 failed
//! with lxc-start "Received container state ABORTING instead of RUNNING".
//! The container's config carries
//! `lxc.mount.entry = /srv/shared/cs mnt/shared none bind,create=dir 0 0`
//! and `/srv/shared/cs` existed only on the primary's own disk. lxc can
//! create a missing mount TARGET (`create=dir`), never a missing SOURCE,
//! so the standby could not start — after the handoff had already stopped
//! the primary.
//!
//! WolfHA never copies bind-mount DATA: the right home for data several
//! nodes must see is shared storage (that directory sits beside the
//! Gluster volume `/mnt/shared` both hosts mount). What WolfHA does is:
//! - [`plan_requirements`] records, on the primary, where each bind
//!   source lives — the mount holding it and its filesystem type — and
//!   whether that is the primary's own disk (then no standby can ever
//!   have it, and the operator is told to move it);
//! - the primary pushes any WolfStack storage mount a container depends
//!   on to its standbys (`mod.rs`, through `/api/agent/storage/apply`, the
//!   same path a global mount's cluster sync uses);
//! - [`preflight_start`] checks, BEFORE a handoff stops the primary, that
//!   this node can start its copy: bridges present, every bind source
//!   present, and each one on the same kind of mount at the same mount
//!   point as on the primary — an unmounted Gluster volume still leaves
//!   an empty `/mnt/shared` directory behind, which "exists" but would
//!   start the container on no data.

use serde::{Deserialize, Serialize};

/// Host machinery a container may bind (`/dev/net/tun`, `/etc/resolv.conf`,
/// `/run/...` sockets, `/proc` and `/sys` files). Every host has its own;
/// they are neither data nor storage, so they carry no requirement beyond
/// existing.
const HOST_MACHINERY: [&str; 16] = [
    "/proc", "/sys", "/dev", "/run", "/tmp", "/var/run", "/var/tmp", "/etc",
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/boot",
];

/// Filesystems that live on one host's own disks. Data on any of these
/// cannot be present on another node except by copying it — which WolfHA
/// does not do — so a bind source on one blocks failover until it moves to
/// shared storage.
const LOCAL_DISK_FS: [&str; 11] = [
    "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs", "bcachefs", "nilfs2",
];

/// One `lxc.mount.entry` line. Format (lxc.container.conf(5)): the value
/// is an fstab(5) line — `source target fstype options [dump [pass]]`.
#[derive(Debug, Clone, PartialEq)]
pub struct MountEntry {
    pub source: String,
    pub target: String,
    pub options: Vec<String>,
}

impl MountEntry {
    pub fn is_bind(&self) -> bool {
        self.options.iter().any(|o| o == "bind" || o == "rbind")
    }
    /// lxc skips an `optional` entry whose source is missing instead of
    /// failing the start.
    pub fn is_optional(&self) -> bool {
        self.options.iter().any(|o| o == "optional")
    }
}

pub fn parse_mount_entries(config: &str) -> Vec<MountEntry> {
    config.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            if key.trim() != "lxc.mount.entry" {
                return None;
            }
            let parts: Vec<&str> = value.split_whitespace().collect();
            if parts.len() < 4 {
                return None;
            }
            Some(MountEntry {
                source: parts[0].to_string(),
                target: parts[1].to_string(),
                options: parts[3].split(',').map(|s| s.to_string()).collect(),
            })
        })
        .collect()
}

/// Every `lxc.net.<N>.link` value — the bridge (veth) or parent device
/// (macvlan/ipvlan/vlan/phys) lxc attaches that interface to.
pub fn parse_net_links(config: &str) -> Vec<String> {
    config.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let rest = key.trim().strip_prefix("lxc.net.")?;
            let (idx, field) = rest.split_once('.')?;
            (idx.chars().all(|c| c.is_ascii_digit()) && field == "link")
                .then(|| value.trim().to_string())
        })
        .filter(|v| !v.is_empty())
        .collect()
}

/// `bridge=` of every `net<N>:` line in a Proxmox container config
/// (pct.conf(5): `net[n]: name=<string>[,bridge=<bridge>][,...]`).
pub fn parse_pve_net_bridges(config: &str) -> Vec<String> {
    config.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            let idx = key.trim().strip_prefix("net")?;
            if idx.is_empty() || !idx.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            value.split(',').find_map(|kv| kv.trim().strip_prefix("bridge=").map(|b| b.to_string()))
        })
        .filter(|b| !b.is_empty())
        .collect()
}

fn under(path: &str, prefix: &str) -> bool {
    prefix == "/" || path == prefix || path.strip_prefix(prefix).is_some_and(|r| r.starts_with('/'))
}

pub fn is_host_machinery(path: &str) -> bool {
    HOST_MACHINERY.iter().any(|p| under(path, p))
}

/// Undo the octal escapes proc(5) applies to mountinfo paths (`\040` for
/// a space, `\011` tab, `\012` newline, `\134` backslash). Works on bytes,
/// so a multi-byte UTF-8 name can never split mid-character.
fn unescape_mountinfo(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 4 <= b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let v = (b[i + 1] - b'0') as u32 * 64 + (b[i + 2] - b'0') as u32 * 8 + (b[i + 3] - b'0') as u32;
            if let Ok(byte) = u8::try_from(v) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The mount holding `path` — `(mount point, fstype)` — from mountinfo
/// text. Format (proc(5)): `id parent major:minor root mountpoint options
/// [optional fields...] - fstype source superoptions`; the mount point is
/// field 5 and the fstype is the first field after the lone `-`. The
/// longest containing mount point wins; on a tie the LATER line wins, as
/// a later mount shadows an earlier one at the same point.
pub fn mount_for(mountinfo: &str, path: &str) -> Option<(String, String)> {
    let mut best: Option<(String, String)> = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let Some(mp) = fields.get(4).map(|m| unescape_mountinfo(m)) else { continue };
        let Some(sep) = fields.iter().position(|f| *f == "-") else { continue };
        let Some(fs) = fields.get(sep + 1) else { continue };
        if under(path, &mp) && best.as_ref().is_none_or(|(b, _)| mp.len() >= b.len()) {
            best = Some((mp, fs.to_string()));
        }
    }
    best
}

/// Where one bind source lives on the PRIMARY. Recorded every sync round
/// and carried to every standby in `HaMeta`, so a standby can check that
/// its copy would see the same storage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BindRequirement {
    /// The bind source path, e.g. `/srv/shared/cs`.
    pub path: String,
    /// The mount holding it on the primary, e.g. `/` or `/mnt/shared`.
    pub mount_point: String,
    /// That mount's filesystem type, e.g. `ext4`, `fuse.glusterfs`, `nfs4`.
    pub fstype: String,
    /// On the primary's own disk: no standby can ever have this data.
    #[serde(default)]
    pub on_local_disk: bool,
}

/// Every storage requirement of a native LXC `config`, judged on the
/// primary against its `mountinfo`. Pure. Host machinery, optional
/// entries and sources missing on the primary itself (the primary could
/// not be running with those either) carry no requirement.
pub fn plan_requirements(config: &str, mountinfo: &str, exists: impl Fn(&str) -> bool) -> Vec<BindRequirement> {
    let mut out: Vec<BindRequirement> = Vec::new();
    for e in parse_mount_entries(config) {
        if !e.is_bind() || !e.source.starts_with('/') || e.is_optional()
            || is_host_machinery(&e.source) || !exists(&e.source)
            || out.iter().any(|r| r.path == e.source)
        {
            continue;
        }
        let Some((mount_point, fstype)) = mount_for(mountinfo, &e.source) else { continue };
        out.push(BindRequirement {
            on_local_disk: LOCAL_DISK_FS.contains(&fstype.as_str()),
            path: e.source,
            mount_point,
            fstype,
        });
    }
    out
}

/// [`plan_requirements`] for a container on this node.
pub fn plan_requirements_live(config: &str) -> Vec<BindRequirement> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    plan_requirements(config, &mountinfo, |p| std::path::Path::new(p).exists())
}

/// Operator-facing sentence for requirements that block any failover.
pub fn local_disk_summary(reqs: &[BindRequirement]) -> Option<String> {
    let local: Vec<String> = reqs.iter()
        .filter(|r| r.on_local_disk)
        .map(|r| format!("{} ({} on {})", r.path, r.fstype, r.mount_point))
        .collect();
    (!local.is_empty()).then(|| format!(
        "{} {} on this node's own disk, so no standby can have {} — move {} onto shared storage mounted at the same path on every node (for example the cluster's Gluster or NFS volume)",
        local.join(", "),
        if local.len() == 1 { "is" } else { "are" },
        if local.len() == 1 { "it" } else { "them" },
        if local.len() == 1 { "it" } else { "them" }))
}

// ─── Can this node start its copy? ───

/// Network device names lxc/QEMU attach to must exist here.
fn net_device_exists(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && name != "." && name != ".."
        && std::path::Path::new(&format!("/sys/class/net/{}", name)).exists()
}

/// Problems that would stop native LXC `config` starting correctly on
/// this node. Pure apart from the probes, for tests:
/// - every `lxc.net.N.link` device exists;
/// - every non-optional bind source exists;
/// - each recorded requirement is met — not on the primary's own disk,
///   and here on the same mount point with the same filesystem type.
pub fn lxc_start_problems(
    config: &str,
    reqs: &[BindRequirement],
    mountinfo: &str,
    dev_exists: impl Fn(&str) -> bool,
    exists: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut problems = Vec::new();
    for link in parse_net_links(config) {
        if !dev_exists(&link) && !problems.iter().any(|p: &String| p.contains(&format!(" {} ", link))) {
            problems.push(format!("network device {} does not exist on this node", link));
        }
    }
    for m in parse_mount_entries(config) {
        if m.is_bind() && m.source.starts_with('/') && !m.is_optional() && !exists(&m.source)
            && !reqs.iter().any(|r| r.path == m.source && r.on_local_disk)
        {
            problems.push(format!("bind-mount source {} is missing on this node", m.source));
        }
    }
    if let Some(local) = local_disk_summary(reqs) {
        problems.push(local.replace("this node's own disk", "the primary's own disk"));
    }
    for r in reqs.iter().filter(|r| !r.on_local_disk) {
        match mount_for(mountinfo, &r.path) {
            Some((mp, fs)) if mp == r.mount_point && fs == r.fstype => {}
            Some((mp, fs)) => problems.push(format!(
                "{} is on {} at {} on the primary, but on {} at {} here — mount {} on this node first",
                r.path, r.fstype, r.mount_point, fs, mp, r.mount_point)),
            None => problems.push(format!("{} is not on any mount here", r.path)),
        }
    }
    problems
}

/// Every reason THIS node could not start its copy of `container` right
/// now. Run before a handoff stops the primary — a refusal here costs no
/// downtime, a failure after the handoff costs an outage.
pub fn preflight_start(kind: super::SubjectKind, container: &str) -> Result<(), String> {
    let problems: Vec<String> = match kind {
        super::SubjectKind::Container => {
            let dir = format!("{}/{}", crate::containers::lxc_base_dir(container), container);
            let config = std::fs::read_to_string(format!("{}/config", dir))
                .map_err(|e| format!("this node has no config for '{}': {}", container, e))?;
            if !std::path::Path::new(&format!("{}/rootfs", dir)).is_dir() {
                return Err(format!("this node has no rootfs for '{}' — it was never seeded here", container));
            }
            let reqs = super::HaStore::load().get(container).map(|e| e.bind_requirements.clone()).unwrap_or_default();
            let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
            lxc_start_problems(&config, &reqs, &mountinfo, net_device_exists, |p| std::path::Path::new(p).exists())
        }
        super::SubjectKind::PveContainer => {
            // Bind mounts are refused when a Proxmox container is
            // protected (zfs_send::container_volumes), so only its
            // bridges can be missing here.
            match std::fs::read_to_string(super::pve_config_path(container)) {
                Ok(cfg) => parse_pve_net_bridges(&super::replication::zfs_send::live_config_section(&cfg))
                    .into_iter()
                    .filter(|b| !net_device_exists(b))
                    .map(|b| format!("bridge {} does not exist on this node", b))
                    .collect(),
                Err(e) => return Err(format!("this node has no Proxmox config for container {}: {}", container, e)),
            }
        }
        super::SubjectKind::Vm => {
            let (_, cfg) = super::vm_disk_and_config(container)?;
            let mut p = Vec::new();
            if cfg.effective_network_mode() == "bridge"
                && let Some(b) = cfg.bridge.as_deref().filter(|b| !b.is_empty())
                && !net_device_exists(b)
            {
                p.push(format!("bridge {} does not exist on this node", b));
            }
            for nic in &cfg.extra_nics {
                if let Some(ifc) = nic.passthrough_interface.as_deref().filter(|s| !s.is_empty()) {
                    // WolfStack creates the passthrough bridge itself; the
                    // physical interface under it has to be here.
                    if !net_device_exists(ifc) {
                        p.push(format!("passthrough interface {} does not exist on this node", ifc));
                    }
                } else if let Some(b) = nic.bridge.as_deref().filter(|b| !b.is_empty())
                    && !net_device_exists(b)
                {
                    p.push(format!("bridge {} does not exist on this node", b));
                }
            }
            p
        }
    };
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!("this node cannot start '{}': {}", container, problems.join("; ")))
    }
}

/// The WolfStack storage mounts (storage.json) holding any of `reqs`:
/// pushed to every standby each round so the storage a container needs
/// is set up there by WolfStack itself. Only network/shared types — a
/// `directory` mount re-exposes a local path and a `disk` mount is a local
/// block device, so a definition copied to another node would mount that
/// node's OWN (different or absent) data under the same name.
pub fn storage_mounts_for(reqs: &[BindRequirement]) -> Vec<crate::storage::StorageMount> {
    use crate::storage::MountType;
    crate::storage::list_mounts().into_iter()
        .filter(|m| !matches!(m.mount_type, MountType::Directory | MountType::Disk))
        .filter(|m| {
            let mp = m.mount_point.trim_end_matches('/');
            reqs.iter().any(|r| !r.on_local_disk && r.mount_point == mp)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Source: /var/lib/lxc/gateway/config on wolfstack-2, 2026-11-22.
    const GATEWAY: &str = "lxc.rootfs.path = dir:/var/lib/lxc/gateway/rootfs\n\
lxc.mount.entry = /srv/shared/cs mnt/shared none bind,create=dir 0 0\n\
lxc.net.0.type = veth\nlxc.net.0.link = vmbr4001\nlxc.net.0.name = eth0\n\
lxc.net.1.type = veth\nlxc.net.1.link = vmbr4001\n\
lxc.mount.entry = /dev/net/tun dev/net/tun none bind,create=file 0 0\n\
lxc.mount.auto = proc:rw sys:rw cgroup:rw\n";

    // Shapes from /proc/self/mountinfo on wolfstack-1 (proc(5) format):
    // the root ext4 and the Gluster volume both hosts mount.
    const MI_PRIMARY: &str = "22 1 9:2 / / rw,relatime shared:1 - ext4 /dev/md2 rw\n\
40 22 0:50 / /mnt/shared rw,relatime shared:9 - fuse.glusterfs localhost:/shared rw\n";

    #[test]
    fn parses_the_gateway_config() {
        let m = parse_mount_entries(GATEWAY);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].source, "/srv/shared/cs");
        assert_eq!(m[0].target, "mnt/shared");
        assert!(m[0].is_bind() && !m[0].is_optional());
        assert_eq!(parse_net_links(GATEWAY), vec!["vmbr4001", "vmbr4001"]);
    }

    #[test]
    fn gateways_data_is_flagged_as_the_primarys_own_disk() {
        let reqs = plan_requirements(GATEWAY, MI_PRIMARY, |_| true);
        // /dev/net/tun is host machinery: no requirement.
        assert_eq!(reqs, vec![BindRequirement {
            path: "/srv/shared/cs".into(), mount_point: "/".into(), fstype: "ext4".into(), on_local_disk: true,
        }]);
        let s = local_disk_summary(&reqs).unwrap();
        assert!(s.contains("/srv/shared/cs (ext4 on /)") && s.contains("move it onto shared storage"), "{}", s);
    }

    #[test]
    fn data_on_gluster_is_a_shared_requirement() {
        let cfg = "lxc.mount.entry = /mnt/shared/cs mnt/shared none bind,create=dir 0 0\n";
        let reqs = plan_requirements(cfg, MI_PRIMARY, |_| true);
        assert_eq!(reqs[0].mount_point, "/mnt/shared");
        assert_eq!(reqs[0].fstype, "fuse.glusterfs");
        assert!(!reqs[0].on_local_disk);
        assert!(local_disk_summary(&reqs).is_none());
    }

    #[test]
    fn optional_and_missing_sources_carry_no_requirement() {
        let cfg = "lxc.mount.entry = /srv/maybe m none bind,optional,create=dir 0 0\n\
lxc.mount.entry = /srv/gone g none bind 0 0\n";
        assert!(plan_requirements(cfg, MI_PRIMARY, |p| p != "/srv/gone").is_empty());
    }

    #[test]
    fn mount_for_uses_the_longest_containing_mount_and_unescapes() {
        let mi = "22 1 9:2 / / rw - ext4 /dev/md2 rw\n\
40 22 0:50 / /mnt/gluster rw - fuse.glusterfs host:/vol rw\n\
41 22 0:51 / /srv/with\\040space rw - nfs4 nas:/x rw\n";
        assert_eq!(mount_for(mi, "/mnt/gluster/www"), Some(("/mnt/gluster".into(), "fuse.glusterfs".into())));
        // Component boundary: /mnt/glusterfs is NOT under /mnt/gluster.
        assert_eq!(mount_for(mi, "/mnt/glusterfs").map(|m| m.1), Some("ext4".into()));
        assert_eq!(mount_for(mi, "/srv/with space/x").map(|m| m.1), Some("nfs4".into()));
    }

    #[test]
    fn the_gateway_failure_is_caught_before_a_handoff() {
        // The exact 2026-11-22 situation on wolfstack-2: bridge present,
        // /srv/shared/cs absent, and recorded as the primary's local disk.
        let reqs = plan_requirements(GATEWAY, MI_PRIMARY, |_| true);
        let p = lxc_start_problems(GATEWAY, &reqs, MI_PRIMARY, |d| d == "vmbr4001", |s| s == "/dev/net/tun");
        assert_eq!(p.len(), 1, "{:?}", p);
        assert!(p[0].contains("/srv/shared/cs") && p[0].contains("the primary's own disk"), "{}", p[0]);
    }

    #[test]
    fn an_unmounted_gluster_volume_is_caught_although_the_directory_exists() {
        let cfg = "lxc.mount.entry = /mnt/shared/cs mnt/shared none bind,create=dir 0 0\n";
        let reqs = plan_requirements(cfg, MI_PRIMARY, |_| true);
        // Standby where Gluster is NOT mounted: /mnt/shared/cs is a plain
        // directory on the root ext4.
        let standby = "22 1 9:2 / / rw - ext4 /dev/md2 rw\n";
        let p = lxc_start_problems(cfg, &reqs, standby, |_| true, |_| true);
        assert_eq!(p.len(), 1, "{:?}", p);
        assert!(p[0].contains("on fuse.glusterfs at /mnt/shared on the primary, but on ext4 at /"), "{}", p[0]);
        // Mounted: no problem.
        assert!(lxc_start_problems(cfg, &reqs, MI_PRIMARY, |_| true, |_| true).is_empty());
    }

    #[test]
    fn a_missing_bridge_is_reported_once() {
        let p = lxc_start_problems(GATEWAY, &[], MI_PRIMARY, |_| false, |_| true);
        assert_eq!(p, vec!["network device vmbr4001 does not exist on this node".to_string()]);
    }

    #[test]
    fn an_old_primary_without_requirements_still_gets_existence_checks() {
        let p = lxc_start_problems(GATEWAY, &[], MI_PRIMARY, |_| true, |s| s == "/dev/net/tun");
        assert_eq!(p, vec!["bind-mount source /srv/shared/cs is missing on this node".to_string()]);
    }

    #[test]
    fn pve_bridges_are_read_from_net_lines() {
        let cfg = "arch: amd64\nnet0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=dhcp,type=veth\n\
net1: name=eth1,bridge=vmbr4001,type=veth\nmp0: local-zfs:subvol-104-disk-1,mp=/data\n";
        assert_eq!(parse_pve_net_bridges(cfg), vec!["vmbr0", "vmbr4001"]);
    }
}
