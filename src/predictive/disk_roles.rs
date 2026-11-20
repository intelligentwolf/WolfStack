// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! What lives on each mounted filesystem.
//!
//! A disk-space alert that says "/data/glusterfs/shared has 30 GB free"
//! leaves the operator to work out whether that matters. One that says
//! "holds LXC containers iw-db-2, iw-db-3" says it does. This module
//! answers "what's on this mount" for the disk analyzers, and the
//! answer also decides whether a slow-fill `Warn` is raised to a
//! notifying `High` (see `disk_verdict::escalate_for_role`).
//!
//! ## How a path is matched to a mount
//!
//! By device id (`st_dev`), not by path prefix. Path prefixes are wrong
//! for exactly the layouts that matter: an LXC rootfs bind-mounted from
//! a big data disk lives at `/var/lib/lxc/<name>/rootfs` but its bytes
//! land on the data disk (wolfstack-2/3, 2026-11-19). `stat` of the
//! path reports the device that actually takes the writes.
//!
//! Only mounts `df` already answered for this tick are stat'ed, so a
//! hung network mount (which made `df` time out) is never touched here.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

/// Well-known service data directories and the label each gets.
/// Each one, when present, is an outage if its filesystem fills.
const SERVICE_DATA_PATHS: &[(&str, &str)] = &[
    ("/var/lib/mysql", "MySQL/MariaDB data"),
    ("/var/lib/postgresql", "PostgreSQL data"),
    ("/var/lib/docker", "Docker data"),
    ("/var/lib/vz", "Proxmox guest storage"),
    ("/var/lib/libvirt/images", "VM disk images"),
];

/// Where LXC keeps one directory per container (config + rootfs).
const LXC_BASE: &str = "/var/lib/lxc";

/// Containers listed by name in a label before it's summarised as
/// "+N more" — keeps an email subject-line-sized.
const MAX_NAMED_CONTAINERS: usize = 6;

/// `mount point → human labels` for everything we found on it.
#[derive(Debug, Clone, Default)]
pub struct DiskRoles {
    by_mount: HashMap<String, Vec<String>>,
}

impl DiskRoles {
    /// Labels for `mount`, empty when nothing notable lives there.
    pub fn holds(&self, mount: &str) -> &[String] {
        self.by_mount.get(mount).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// True when filling `mount` would take a service down.
    pub fn holds_critical_data(&self, mount: &str) -> bool {
        !self.holds(mount).is_empty()
    }

    /// One-line summary for proposal text: "operating system (/), LXC
    /// containers: iw-db-2". `None` when nothing notable is there.
    pub fn summary(&self, mount: &str) -> Option<String> {
        let h = self.holds(mount);
        if h.is_empty() { None } else { Some(h.join("; ")) }
    }

    #[cfg(test)]
    pub fn from_map(by_mount: HashMap<String, Vec<String>>) -> Self {
        Self { by_mount }
    }
}

/// One thing that lives somewhere, before it's matched to a mount.
struct Resident {
    /// What to group it under ("LXC containers", "Docker data", …).
    kind: &'static str,
    /// Individual name within the kind (container name), if any.
    name: Option<String>,
}

/// Pure grouping step: given each mount's device id and each resident's
/// device id, build the label map. Split from the I/O so the matching
/// rules are testable.
fn build_roles(
    mount_devs: &[(String, u64)],
    residents: &[(Resident, u64)],
) -> DiskRoles {
    let mut grouped: HashMap<String, Vec<(&'static str, Option<String>)>> = HashMap::new();
    for (r, dev) in residents {
        // Several mounts can share a device (bind mounts of the same
        // filesystem). Attribute to every one df listed — the alert for
        // whichever of them fires should carry the label.
        for (mount, mdev) in mount_devs {
            if mdev == dev {
                grouped.entry(mount.clone()).or_default().push((r.kind, r.name.clone()));
            }
        }
    }
    let mut by_mount: HashMap<String, Vec<String>> = HashMap::new();
    for (mount, items) in grouped {
        let mut labels: Vec<String> = Vec::new();
        let mut kinds: Vec<&'static str> = items.iter().map(|(k, _)| *k).collect();
        kinds.sort_unstable();
        kinds.dedup();
        for kind in kinds {
            let mut names: Vec<String> = items.iter()
                .filter(|(k, _)| *k == kind)
                .filter_map(|(_, n)| n.clone())
                .collect();
            names.sort();
            names.dedup();
            if names.is_empty() {
                labels.push(kind.to_string());
            } else {
                let shown: Vec<&str> = names.iter().take(MAX_NAMED_CONTAINERS).map(|s| s.as_str()).collect();
                let more = names.len().saturating_sub(MAX_NAMED_CONTAINERS);
                let list = if more > 0 {
                    format!("{} +{} more", shown.join(", "), more)
                } else {
                    shown.join(", ")
                };
                labels.push(format!("{}: {}", kind, list));
            }
        }
        by_mount.insert(mount, labels);
    }
    DiskRoles { by_mount }
}

/// `lxc.rootfs.path` from an LXC config, with a `dir:` backend prefix
/// stripped. `None` for non-directory backends (`zfs:`, `lvm:`, …) whose
/// value isn't a path we can stat, and for configs without the key.
fn lxc_rootfs_from_config(config: &str) -> Option<String> {
    for line in config.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("lxc.rootfs.path") else { continue };
        let Some(val) = rest.trim_start().strip_prefix('=') else { continue };
        let val = val.trim();
        let val = val.strip_prefix("dir:").unwrap_or(val);
        if val.starts_with('/') { return Some(val.to_string()); }
        return None;
    }
    None
}

fn dev_of(path: &str) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.dev())
}

/// Blocking sample. `mounts` are the mount points df reported this tick.
pub fn sample_now(mounts: &[String]) -> DiskRoles {
    let mount_devs: Vec<(String, u64)> = mounts.iter()
        .filter_map(|m| dev_of(m).map(|d| (m.clone(), d)))
        .collect();

    let mut residents: Vec<(Resident, u64)> = Vec::new();

    // The OS root. Filling it stops logging, package management and
    // usually the services on it — always worth naming.
    if let Some(d) = dev_of("/") {
        residents.push((Resident { kind: "operating system (/)", name: None }, d));
    }

    for (path, label) in SERVICE_DATA_PATHS {
        if !Path::new(path).is_dir() { continue; }
        if let Some(d) = dev_of(path) {
            residents.push((Resident { kind: label, name: None }, d));
        }
    }

    // LXC containers. The rootfs is resolved from each container's
    // config so a relocated rootfs is attributed to where it really is.
    // An EMPTY rootfs directory is skipped: that's a Proxmox CT that's
    // stopped (its real volume isn't mounted), and attributing it to the
    // root filesystem would be wrong.
    if let Ok(entries) = std::fs::read_dir(LXC_BASE) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let cfg_path = e.path().join("config");
            let Ok(cfg) = std::fs::read_to_string(&cfg_path) else { continue };
            let rootfs = lxc_rootfs_from_config(&cfg)
                .unwrap_or_else(|| format!("{}/{}/rootfs", LXC_BASE, name));
            let non_empty = std::fs::read_dir(&rootfs)
                .map(|mut it| it.next().is_some())
                .unwrap_or(false);
            if !non_empty { continue; }
            if let Some(d) = dev_of(&rootfs) {
                residents.push((Resident { kind: "LXC containers", name: Some(name) }, d));
            }
        }
    }

    build_roles(&mount_devs, &residents)
}

/// Timeout-bounded async variant for the orchestrator. On timeout the
/// analyzers get an empty map: alerts still fire, just without the
/// "holds" line and the role escalation.
pub async fn sample_now_async(mounts: Vec<String>, timeout: Duration) -> DiskRoles {
    let fut = tokio::task::spawn_blocking(move || sample_now(&mounts));
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(r)) => r,
        _ => {
            tracing::warn!("predictive: disk-role sampling timed out or failed — alerts will omit what each disk holds this tick");
            DiskRoles::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(kind: &'static str, name: Option<&str>) -> Resident {
        Resident { kind, name: name.map(|s| s.to_string()) }
    }

    #[test]
    fn bind_mounted_rootfs_attributed_to_the_data_disk() {
        // wolfstack-2 layout: root on dev 1, gluster brick on dev 2;
        // iw-db-2's rootfs is bind-mounted from the brick.
        let mounts = vec![("/".to_string(), 1), ("/data/glusterfs/shared".to_string(), 2)];
        let residents = vec![
            (res("operating system (/)", None), 1),
            (res("LXC containers", Some("web1")), 1),
            (res("LXC containers", Some("iw-db-2")), 2),
        ];
        let r = build_roles(&mounts, &residents);
        assert_eq!(r.holds("/data/glusterfs/shared"), &["LXC containers: iw-db-2".to_string()]);
        let root = r.summary("/").unwrap();
        assert!(root.contains("operating system"), "{}", root);
        assert!(root.contains("web1") && !root.contains("iw-db-2"), "{}", root);
        assert!(r.holds_critical_data("/"));
    }

    #[test]
    fn mount_with_nothing_notable_is_not_critical() {
        let mounts = vec![("/".to_string(), 1), ("/srv/media".to_string(), 3)];
        let residents = vec![(res("operating system (/)", None), 1)];
        let r = build_roles(&mounts, &residents);
        assert!(!r.holds_critical_data("/srv/media"));
        assert!(r.summary("/srv/media").is_none());
    }

    #[test]
    fn long_container_lists_are_summarised() {
        let mounts = vec![("/".to_string(), 1)];
        let names = ["a", "b", "c", "d", "e", "f", "g", "h"];
        let residents: Vec<(Resident, u64)> = names.iter()
            .map(|n| (res("LXC containers", Some(n)), 1)).collect();
        let r = build_roles(&mounts, &residents);
        assert_eq!(r.holds("/"), &["LXC containers: a, b, c, d, e, f +2 more".to_string()]);
    }

    #[test]
    fn rootfs_path_parsing() {
        assert_eq!(lxc_rootfs_from_config("lxc.rootfs.path = dir:/var/lib/lxc/a/rootfs\n").as_deref(),
            Some("/var/lib/lxc/a/rootfs"));
        assert_eq!(lxc_rootfs_from_config("lxc.rootfs.path=/data/a/rootfs").as_deref(),
            Some("/data/a/rootfs"));
        assert_eq!(lxc_rootfs_from_config("lxc.rootfs.path = zfs:rpool/a"), None);
        assert_eq!(lxc_rootfs_from_config("lxc.uts.name = a"), None);
    }
}
