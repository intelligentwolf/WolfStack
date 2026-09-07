// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! ZFS-native replication for Proxmox-managed containers.
//!
//! Phase 1 excluded Proxmox-managed LXC because their rootfs "isn't a
//! stable host dir" — true for LVM-thin and raw images. On ZFS the
//! picture is different: every volume of a Proxmox container is a ZFS
//! filesystem (`<pool>/subvol-<vmid>-disk-<n>`), and ZFS itself provides
//! the incremental, atomic, byte-exact transfer that the file drivers
//! approximate — `zfs send -I` between two snapshots of the same dataset.
//! Colt (2026-09-06) measured a 52 GB first send at ~280 MB/s and
//! six-second incrementals across eight datasets.
//!
//! This is deliberately a *fast path*, not a replacement for the snapshot-
//! and-tar transport in `snapshot.rs`: it demands ZFS on BOTH ends, with
//! the same pool layout, which is exactly the coupling the general design
//! refuses to impose on a mixed fleet. Here that coupling is the point —
//! the subject is a Proxmox container whose volumes ARE ZFS datasets, so
//! a standby that cannot receive a ZFS stream cannot hold the container
//! at all. A subject of this kind therefore negotiates only
//! [`super::DriverKind::ZfsSend`]; when the standby lacks it, protection
//! is refused with the reason, never degraded to a payload that would
//! produce something unstartable (the same rule `detect_vm_capabilities`
//! applies to a raw VM disk).
//!
//! ## The chain is the snapshot history
//!
//! VMs need an explicit chain token because a qcow2 delta cannot prove
//! which base it fits. ZFS proves it for us: `zfs receive` of an
//! incremental requires that "the destination file system must already
//! exist, and its most recent snapshot must match the incremental
//! stream's source" (zfs-receive(8)). So the round asks the standby which
//! of our snapshots it holds, sends `-I <newest common> <new>`, and a
//! standby holding none is re-seeded with a full stream. Divergence
//! cannot go unnoticed and cannot be patched over.
//!
//! ## Primary sources, cited where used
//!
//! - `/etc/pve/storage.cfg` format and the `zfspool` `pool` option:
//!   Proxmox VE admin guide, "Storage" and "ZFS Backend" chapters
//!   (`<type>: <STORAGE_ID>` header, indented `<property> <value>` lines;
//!   container volumes are `subvol-<VMID>-<NAME>` datasets under `pool`).
//! - `/etc/pve/lxc/<CTID>.conf` format and option syntax: pct.conf(5)
//!   (`OPTION: value`; `rootfs: [volume=]<volume>[,…]`;
//!   `mp[n]: [volume=]<volume>,mp=<Path>[,…]`; `onboot: <boolean>`
//!   default 0; `lock:`; `net[n]: …,hwaddr=…,ip=<IPv4/CIDR|dhcp|manual>`).
//! - `zfs send -I|-i|-p|-L` and `zfs receive -F|-u`: zfs-send(8),
//!   zfs-receive(8) from the OpenZFS manual (quoted inline below).

use std::collections::{HashMap, HashSet};
use std::process::Command;

/// Snapshot prefix for this driver. Distinct from `snapshot::SNAP_PREFIX`
/// ("wolfha-<subject>-…"): that family is destroyed wholesale at the start
/// of every file-driver round, while these must PERSIST between rounds —
/// they are the incremental bases. A subject named like a VMID must never
/// have its bases swept by the other driver's cleanup.
pub const SNAP_PREFIX: &str = "wolfha-zfs";

/// Marker inside an error body telling the primary this standby needs a
/// full stream rather than an incremental. Travels between nodes; do not
/// change it.
pub const ZFS_NEEDS_SEED: &str = "WOLFHA_ZFS_NEEDS_SEED";

pub fn snapshot_name(vmid: &str, unix_secs: u64) -> String {
    format!("{}-{}-{}", SNAP_PREFIX, vmid, unix_secs)
}

pub fn is_ours(name: &str, vmid: &str) -> bool {
    name.starts_with(&format!("{}-{}-", SNAP_PREFIX, vmid))
        && name.rsplit('-').next().map(|t| t.chars().all(|c| c.is_ascii_digit())).unwrap_or(false)
}

/// The unix timestamp a snapshot name carries; 0 for anything malformed.
pub fn snapshot_ts(name: &str) -> u64 {
    name.rsplit('-').next().and_then(|t| t.parse().ok()).unwrap_or(0)
}

/// A Proxmox CT id is a positive integer (pct.conf(5): `<CTID>`).
pub fn is_vmid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 9 && s.chars().all(|c| c.is_ascii_digit()) && s != "0"
}

/// A dataset name we are willing to pass to `zfs`: pool-relative, no
/// leading slash, no `..`, no snapshot separator, ZFS's own character set.
pub fn is_safe_dataset(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && !s.starts_with('/')
        && !s.ends_with('/')
        && !s.contains("..")
        && !s.contains("//")
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':'))
}

// ─── /etc/pve/storage.cfg ───────────────────────────────────────────

/// `zfspool` storages by id → the `pool` dataset allocations live in.
///
/// Source: Proxmox VE admin guide, "Storage Configuration": each storage
/// is a stanza `<type>: <STORAGE_ID>` followed by indented
/// `<property> <value>` lines; "ZFS Backend": `zfspool: local-zfs` with
/// `pool rpool/data`. Other storage types are ignored — a volume on them
/// is not a ZFS dataset and cannot travel this way.
pub fn parse_storage_cfg_zfspools(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut current: Option<(String, bool)> = None; // (id, is_zfspool)
    for raw in text.lines() {
        let line = raw.trim_end();
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !raw.starts_with(char::is_whitespace) {
            // Stanza header.
            current = line.split_once(':').map(|(ty, id)| (id.trim().to_string(), ty.trim() == "zfspool"));
            continue;
        }
        if let Some((id, true)) = &current {
            let mut parts = line.trim().splitn(2, char::is_whitespace);
            if parts.next() == Some("pool")
                && let Some(pool) = parts.next()
            {
                out.insert(id.clone(), pool.trim().to_string());
            }
        }
    }
    out
}

// ─── /etc/pve/lxc/<vmid>.conf ───────────────────────────────────────

/// One ZFS-backed volume of a Proxmox container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PveVolume {
    /// `rootfs` or `mp<N>`.
    pub key: String,
    /// The storage id (`local-zfs`).
    pub storage: String,
    /// The volume name on that storage (`subvol-104-disk-0`).
    pub volume: String,
    /// The dataset: `<pool>/<volume>`.
    pub dataset: String,
}

/// The live section of a pct config: everything before the first
/// `[snapshot-name]` header. Snapshot sections describe Proxmox snapshots
/// that do not exist on a standby, so they never travel.
pub fn live_config_section(text: &str) -> String {
    let mut out: String = text
        .lines()
        .take_while(|l| !l.trim_start().starts_with('['))
        .collect::<Vec<_>>()
        .join("\n");
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Every volume the container mounts, resolved to ZFS datasets.
///
/// Errors when a `rootfs`/`mp<N>` is not on a `zfspool` storage — a bind
/// mount (`mp0: /host/path,mp=/data`) or a volume on LVM/dir storage would
/// be absent on the standby, and a promoted copy silently missing a mount
/// is worse than no HA (the same refusal `wolfha_enable` makes for a VM
/// with extra disks).
pub fn container_volumes(config: &str, pools: &HashMap<String, String>) -> Result<Vec<PveVolume>, String> {
    let mut vols = Vec::new();
    for line in live_config_section(config).lines() {
        let Some((key, val)) = line.split_once(':') else { continue };
        let key = key.trim();
        let is_mp = key.starts_with("mp") && key[2..].chars().all(|c| c.is_ascii_digit()) && key.len() > 2;
        if key != "rootfs" && !is_mp {
            continue;
        }
        // pct.conf(5): `[volume=]<volume>[,option=value…]` — the volume is
        // the first comma-separated field, optionally prefixed `volume=`.
        let first = val.trim().split(',').next().unwrap_or("").trim();
        let volume_id = first.strip_prefix("volume=").unwrap_or(first);
        if volume_id.starts_with('/') {
            return Err(format!(
                "{} is a bind mount of the host path {} — it would not exist on the standby, so this \
                 container cannot fail over. Move that data onto a ZFS volume to protect it.",
                key, volume_id
            ));
        }
        let Some((storage, volume)) = volume_id.split_once(':') else {
            return Err(format!("{}: cannot parse volume {:?}", key, volume_id));
        };
        let Some(pool) = pools.get(storage) else {
            return Err(format!(
                "{} is on storage '{}', which is not a ZFS pool storage — WolfHA replicates Proxmox \
                 containers with `zfs send`, so every volume must be on a zfspool storage",
                key, storage
            ));
        };
        let dataset = format!("{}/{}", pool.trim_end_matches('/'), volume);
        if !is_safe_dataset(&dataset) {
            return Err(format!("{}: dataset name {:?} is not safe to pass to zfs", key, dataset));
        }
        vols.push(PveVolume { key: key.to_string(), storage: storage.to_string(), volume: volume.to_string(), dataset });
    }
    if vols.is_empty() {
        return Err("the container config has no rootfs volume".to_string());
    }
    Ok(vols)
}

/// pct.conf(5): `onboot: <boolean> (default = 0)`.
pub fn config_onboot(config: &str) -> bool {
    live_config_section(config).lines().any(|l| {
        l.split_once(':').map(|(k, v)| k.trim() == "onboot" && v.trim() == "1").unwrap_or(false)
    })
}

/// The config a STANDBY stores: the live section with `onboot` forced to
/// 0 (a standby must never start itself at boot — the boot guard decides),
/// and any `lock:`/`parent:` state dropped (locks belong to the primary's
/// in-flight operation; `parent` names a Proxmox snapshot that is not
/// here). Identity — hostname, `net0` hwaddr and ip — is kept exactly.
pub fn replica_config(config: &str) -> String {
    let mut out: Vec<String> = live_config_section(config)
        .lines()
        .filter(|l| {
            let key = l.split_once(':').map(|(k, _)| k.trim()).unwrap_or("");
            !matches!(key, "onboot" | "lock" | "parent")
        })
        .map(|l| l.to_string())
        .collect();
    out.push("onboot: 0".to_string());
    let mut s = out.join("\n");
    s.push('\n');
    s
}

/// The static IPv4 of `net0`, if it has one (pct.conf(5): `ip=<IPv4/CIDR|dhcp|manual>`).
pub fn net0_static_ip(config: &str) -> Option<String> {
    let line = live_config_section(config).lines().find_map(|l| {
        l.split_once(':').filter(|(k, _)| k.trim() == "net0").map(|(_, v)| v.trim().to_string())
    })?;
    line.split(',')
        .filter_map(|p| p.trim().strip_prefix("ip="))
        .map(|v| v.split('/').next().unwrap_or("").trim().to_string())
        .find(|v| v.parse::<std::net::Ipv4Addr>().is_ok())
}

/// Where a config for `vmid` exists anywhere in this node's pmxcfs — the
/// cluster-wide tree `nodes/<NAME>/{lxc,qemu-server}/<VMID>.conf`. A
/// VMID is unique across a Proxmox cluster, so a standby must not install
/// a copy under an id some other node is using.
pub fn vmid_config_paths(vmid: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let Ok(nodes) = std::fs::read_dir("/etc/pve/nodes") else { return hits };
    for n in nodes.flatten() {
        for sub in ["lxc", "qemu-server"] {
            let p = n.path().join(sub).join(format!("{}.conf", vmid));
            if p.exists() {
                hits.push(p.to_string_lossy().to_string());
            }
        }
    }
    hits
}

// ─── zfs command construction (pure, tested) ────────────────────────

/// `zfs send` arguments for `dataset@to`, incremental from `from` when
/// given.
///
/// - `-L`: "Generate a stream which may contain blocks larger than 128 KiB"
///   (zfs-send(8)) — Proxmox datasets default to 128K records, but a
///   container may hold larger ones and the flag is harmless otherwise.
/// - `-p` on the FULL stream only: "Include the dataset's properties in
///   the stream" (zfs-send(8)) — `refquota`, `acltype`, `xattr` as
///   Proxmox created them, so the standby's copy is created the same way.
///   Left off incrementals because the manual does not state how `-p`
///   composes with `-I`, and a stream the receiver rejects is worse than
///   a property that lags a resize.
/// - `-I from`: "Generate a stream package that sends all intermediary
///   snapshots from the first snapshot to the second snapshot" — every
///   snapshot between the bases travels too, so a standby that missed a
///   round still ends at exactly the primary's newest.
pub fn send_args(dataset: &str, from: Option<&str>, to: &str) -> Vec<String> {
    let mut a = vec!["send".to_string(), "-L".to_string()];
    match from {
        Some(f) => {
            a.push("-I".to_string());
            a.push(format!("@{}", f));
        }
        None => a.push("-p".to_string()),
    }
    a.push(format!("{}@{}", dataset, to));
    a
}

/// `zfs receive` arguments. `-F`: "Force a rollback of the file system to
/// the most recent snapshot before performing the receive operation"
/// (zfs-receive(8)) — a standby dataset that was touched (mounted and
/// written, a stray file) is rolled back to the shared base rather than
/// refusing the incremental. Not `-u`: the received filesystem mounts at
/// its inherited mountpoint (`/<pool>/subvol-…`), which is where Proxmox
/// expects a container volume when it is started after promotion.
pub fn receive_args(dataset: &str) -> Vec<String> {
    vec!["receive".to_string(), "-F".to_string(), dataset.to_string()]
}

/// Which of `ours` to destroy so that only `keep` survive. Pure so the
/// prune policy is testable without a pool.
pub fn prune_plan(ours: &[String], keep: &HashSet<String>) -> Vec<String> {
    ours.iter().filter(|s| !keep.contains(*s)).cloned().collect()
}

/// The newest snapshot present in BOTH lists — the incremental base.
pub fn newest_common<'a>(primary: &'a [String], replica: &[String]) -> Option<&'a String> {
    primary.iter().filter(|s| replica.contains(s)).max_by_key(|s| snapshot_ts(s))
}

// ─── zfs command wrappers ───────────────────────────────────────────

fn run(bin: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| format!("{}: {}", bin, e))?;
    if !out.status.success() {
        return Err(format!(
            "{} {} failed: {}",
            bin,
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

pub fn have_zfs() -> bool {
    crate::mail_relay::which("zfs").is_some()
}

pub fn dataset_exists(dataset: &str) -> bool {
    run("zfs", &["list", "-H", "-o", "name", dataset]).is_ok()
}

/// One atomic `zfs snapshot` of every dataset: "Snapshots are taken
/// atomically, so that all snapshots correspond to the same moment in
/// time" (zfs-snapshot(8)) — a container with a data mount point gets a
/// consistent pair, not two instants.
pub fn snapshot_all(datasets: &[String], snap: &str) -> Result<(), String> {
    let names: Vec<String> = datasets.iter().map(|d| format!("{}@{}", d, snap)).collect();
    let mut args: Vec<&str> = vec!["snapshot"];
    args.extend(names.iter().map(|s| s.as_str()));
    run("zfs", &args).map(|_| ())
}

/// Our snapshots of `dataset` for `vmid`, oldest first.
pub fn list_ours(dataset: &str, vmid: &str) -> Result<Vec<String>, String> {
    let out = run("zfs", &["list", "-H", "-o", "name", "-t", "snapshot", "-s", "creation", "-d", "1", dataset])?;
    Ok(out
        .lines()
        .filter_map(|l| l.split_once('@').map(|(_, s)| s.to_string()))
        .filter(|s| is_ours(s, vmid))
        .collect())
}

pub fn destroy_snapshot(dataset: &str, snap: &str) -> Result<(), String> {
    run("zfs", &["destroy", &format!("{}@{}", dataset, snap)]).map(|_| ())
}

/// Destroy a dataset and its snapshots. Only ever called on a copy this
/// node's HA store says is OURS (a replica being re-seeded).
pub fn destroy_dataset(dataset: &str) -> Result<(), String> {
    run("zfs", &["destroy", "-r", dataset]).map(|_| ())
}

pub fn is_mounted(dataset: &str) -> bool {
    run("zfs", &["get", "-H", "-o", "value", "mounted", dataset])
        .map(|v| v.trim() == "yes")
        .unwrap_or(false)
}

pub fn mount(dataset: &str) -> Result<(), String> {
    if is_mounted(dataset) {
        return Ok(());
    }
    run("zfs", &["mount", dataset]).map(|_| ())
}

/// Parent dataset of `dataset` (`rpool/data` for `rpool/data/subvol-…`).
pub fn parent_dataset(dataset: &str) -> Option<&str> {
    dataset.rsplit_once('/').map(|(p, _)| p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_namespaced_and_distinct_from_the_file_driver() {
        let n = snapshot_name("104", 1_700_000_000);
        assert_eq!(n, "wolfha-zfs-104-1700000000");
        assert!(is_ours(&n, "104"));
        assert!(!is_ours(&n, "10"));
        assert!(!is_ours("wolfha-104-1700000000", "104"), "file-driver names are not ours");
        assert!(!is_ours("wolfha-zfs-104-nightly", "104"));
        assert_eq!(snapshot_ts(&n), 1_700_000_000);
        // The file driver must not see ours either.
        assert!(!super::super::snapshot::is_ours(&n, "104"));
    }

    #[test]
    fn vmid_and_dataset_validation() {
        assert!(is_vmid("104") && is_vmid("100000"));
        for bad in ["", "0", "abc", "10a", "-1", "1234567890"] {
            assert!(!is_vmid(bad), "{bad:?}");
        }
        assert!(is_safe_dataset("rpool/data/subvol-104-disk-0"));
        for bad in ["", "/rpool/x", "rpool/../x", "rpool//x", "rpool/x@snap", "rpool/x/", "a b"] {
            assert!(!is_safe_dataset(bad), "{bad:?}");
        }
    }

    // The default install's storage.cfg (admin guide "ZFS Backend" +
    // "Storage Configuration" examples), with a dir storage and a
    // commented line thrown in.
    const STORAGE_CFG: &str = "\
dir: local
\tpath /var/lib/vz
\tcontent iso,vztmpl,backup

# comment
zfspool: local-zfs
\tpool rpool/data
\tsparse
\tcontent images,rootdir

zfspool: tank
        pool tank/vmdata
        content rootdir,images
";

    #[test]
    fn storage_cfg_yields_only_zfspools() {
        let pools = parse_storage_cfg_zfspools(STORAGE_CFG);
        assert_eq!(pools.get("local-zfs").map(String::as_str), Some("rpool/data"));
        assert_eq!(pools.get("tank").map(String::as_str), Some("tank/vmdata"));
        assert!(!pools.contains_key("local"));
        assert_eq!(pools.len(), 2);
    }

    const CT_CONF: &str = "\
arch: amd64
cores: 2
hostname: paperless
memory: 2048
mp0: local-zfs:subvol-104-disk-1,mp=/data,size=50G
net0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:CC,ip=10.0.40.14/24,gw=10.0.40.1,type=veth
onboot: 1
ostype: debian
rootfs: volume=local-zfs:subvol-104-disk-0,size=8G
swap: 512
lock: backup
parent: before-upgrade
unprivileged: 1

[before-upgrade]
rootfs: local-zfs:subvol-104-disk-0,size=8G
snaptime: 1700000000
";

    #[test]
    fn volumes_resolve_to_datasets_in_config_order() {
        let pools = parse_storage_cfg_zfspools(STORAGE_CFG);
        let vols = container_volumes(CT_CONF, &pools).unwrap();
        let ds: Vec<&str> = vols.iter().map(|v| v.dataset.as_str()).collect();
        assert_eq!(ds, vec!["rpool/data/subvol-104-disk-1", "rpool/data/subvol-104-disk-0"]);
        assert_eq!(vols[1].key, "rootfs");
        assert_eq!(vols[1].volume, "subvol-104-disk-0");
        assert_eq!(vols[0].storage, "local-zfs");
    }

    #[test]
    fn bind_mounts_and_non_zfs_storage_are_refused() {
        let pools = parse_storage_cfg_zfspools(STORAGE_CFG);
        let bind = "rootfs: local-zfs:subvol-1-disk-0,size=8G\nmp0: /srv/share,mp=/share\n";
        assert!(container_volumes(bind, &pools).unwrap_err().contains("bind mount"));
        let lvm = "rootfs: local-lvm:vm-1-disk-0,size=8G\n";
        assert!(container_volumes(lvm, &pools).unwrap_err().contains("not a ZFS pool storage"));
        assert!(container_volumes("arch: amd64\n", &pools).unwrap_err().contains("no rootfs"));
    }

    #[test]
    fn replica_config_keeps_identity_and_never_boots_itself() {
        assert!(config_onboot(CT_CONF));
        let r = replica_config(CT_CONF);
        assert!(r.contains("hwaddr=BC:24:11:AA:BB:CC,ip=10.0.40.14/24"));
        assert!(r.contains("hostname: paperless\n"));
        assert!(r.ends_with("onboot: 0\n"));
        assert_eq!(r.matches("onboot:").count(), 1);
        assert!(!r.contains("lock:") && !r.contains("parent:"));
        assert!(!r.contains("[before-upgrade]") && !r.contains("snaptime"));
        assert!(!config_onboot(&r));
        assert_eq!(net0_static_ip(CT_CONF).as_deref(), Some("10.0.40.14"));
        assert_eq!(net0_static_ip("net0: name=eth0,bridge=vmbr0,ip=dhcp\n"), None);
    }

    #[test]
    fn send_and_receive_arguments() {
        assert_eq!(
            send_args("rpool/data/subvol-104-disk-0", None, "wolfha-zfs-104-2"),
            vec!["send", "-L", "-p", "rpool/data/subvol-104-disk-0@wolfha-zfs-104-2"]
        );
        assert_eq!(
            send_args("rpool/data/subvol-104-disk-0", Some("wolfha-zfs-104-1"), "wolfha-zfs-104-2"),
            vec!["send", "-L", "-I", "@wolfha-zfs-104-1", "rpool/data/subvol-104-disk-0@wolfha-zfs-104-2"]
        );
        assert_eq!(receive_args("rpool/data/subvol-104-disk-0"), vec!["receive", "-F", "rpool/data/subvol-104-disk-0"]);
        assert_eq!(parent_dataset("rpool/data/subvol-104-disk-0"), Some("rpool/data"));
        assert_eq!(parent_dataset("rpool"), None);
    }

    #[test]
    fn base_selection_and_prune_policy() {
        let primary: Vec<String> = ["wolfha-zfs-104-10", "wolfha-zfs-104-9", "wolfha-zfs-104-100"]
            .iter().map(|s| s.to_string()).collect();
        let replica: Vec<String> = ["wolfha-zfs-104-9", "wolfha-zfs-104-10"].iter().map(|s| s.to_string()).collect();
        // Numeric, not lexical: -10 beats -9, and -100 is absent on the replica.
        assert_eq!(newest_common(&primary, &replica).map(String::as_str), Some("wolfha-zfs-104-10"));
        assert_eq!(newest_common(&primary, &[]), None);
        let keep: HashSet<String> = ["wolfha-zfs-104-100", "wolfha-zfs-104-10"].iter().map(|s| s.to_string()).collect();
        assert_eq!(prune_plan(&primary, &keep), vec!["wolfha-zfs-104-9"]);
    }
}
