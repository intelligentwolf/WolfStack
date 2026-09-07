// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! WolfHA replication drivers — how a delta actually gets computed.
//!
//! WolfHA Phase 1 had exactly one strategy: walk the container rootfs,
//! build a per-file manifest, diff it against the replica's, and tar the
//! changed paths. That is incremental at *file* granularity, which is
//! fine for a rootfs of small files and badly wrong for a 10 GB database
//! file that took a 4 KB write — the whole file ships every round. It
//! also cannot replicate a VM at all: a qcow2 is one enormous file, so
//! "the file changed" degenerates to "send the disk", and copying a
//! running VM's disk at file level produces a torn image (which
//! `vms::manager` already refuses to do for exactly this reason).
//!
//! The fix is not to pick a better single algorithm. WolfStack runs on
//! thousands of machines whose storage we do not get to choose, so
//! replication is split into two INDEPENDENT axes:
//!
//! - **Transport** ([`DriverKind`]) — how the bytes travel. Negotiated
//!   with the replica, because both ends must understand the payload.
//! - **Consistency** ([`ConsistencySource`]) — what the bytes are read
//!   FROM. Purely a property of the primary's storage, so it is not
//!   negotiated at all: the replica cannot tell whether a file was read
//!   from the live rootfs or from a snapshot of it, and does not need to.
//!
//! Keeping them separate is what makes snapshots usable in the general
//! case. Using `zfs send` as a *transport* would demand the replica also
//! run ZFS with a matching snapshot — storage we do not control. Using a
//! snapshot as a *source* demands nothing of the replica, works with any
//! transport, and still buys the thing that actually matters: the copy is
//! taken at one instant, so the replica is crash-consistent instead of
//! holding a half-written database.
//!
//! The operator never picks either axis — they cannot be expected to know
//! whether their workload is "many small files" or "few huge ones", and on
//! a mixed fleet the right answer differs per node anyway.
//!
//! The bottom rung, [`DriverKind::FileManifest`], is the Phase 1
//! behaviour and is always available. Anything that fails to negotiate
//! lands there, which is what makes this safe to ship to existing
//! installs: a replica running an older build has no capabilities
//! endpoint, the probe fails, and both ends carry on doing exactly what
//! they did before.

pub mod qemu_bitmap;
pub mod zfs_send;
pub mod rolling;
pub mod snapshot;

use serde::{Deserialize, Serialize};
use std::process::Command;

/// A replication strategy. Ordered worst-to-best so `Ord` gives
/// "prefer the higher one" for free — see [`DriverKind::rank`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverKind {
    /// Whole-file tar of changed paths (WolfHA Phase 1). Works on any
    /// filesystem, needs no tooling, and is the guaranteed floor.
    ///
    /// Not crash-consistent: files are read live, so a replica can hold a
    /// torn database. Every rung above this one fixes that.
    FileManifest,
    /// Rolling-checksum block deltas within changed files (the rsync
    /// algorithm), carried over the existing agent HTTP channel. Same
    /// universal applicability as `FileManifest` but ships changed
    /// *blocks* rather than changed *files*.
    RollingDelta,
    /// QEMU persistent dirty bitmaps with incremental `blockdev-backup`.
    /// VM subjects only — the bitmap lives in the qcow2 and is a block
    /// layer feature, so it has no meaning for a container rootfs.
    QemuBitmap,
    /// `zfs send -I` between snapshots of the subject's own datasets.
    /// Proxmox-container subjects only — their volumes ARE ZFS datasets,
    /// and the standby must run ZFS with the same pool layout to receive
    /// them (see `zfs_send.rs` for why that coupling is acceptable here
    /// and nowhere else).
    ZfsSend,
}

impl DriverKind {
    /// Higher is better. Kept explicit rather than leaning on the enum
    /// discriminant so reordering the variants for readability can never
    /// silently change which driver a fleet negotiates.
    pub fn rank(self) -> u8 {
        match self {
            DriverKind::FileManifest => 0,
            DriverKind::RollingDelta => 1,
            DriverKind::QemuBitmap => 2,
            DriverKind::ZfsSend => 3,
        }
    }

    /// Short label for the UI and sync messages.
    pub fn label(self) -> &'static str {
        match self {
            DriverKind::FileManifest => "whole-file",
            DriverKind::RollingDelta => "block delta",
            DriverKind::QemuBitmap => "QEMU dirty bitmap",
            DriverKind::ZfsSend => "ZFS send",
        }
    }
}

/// What one node can do for one HA subject. Exchanged between primary
/// and replica before a sync so both ends agree on the strategy.
///
/// `#[serde(default)]` throughout: this crosses a version boundary, and
/// a field added later must not make an older peer's payload unparseable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplicationCapabilities {
    /// Every driver this node could use for this subject, unordered.
    #[serde(default)]
    pub drivers: Vec<DriverKind>,
    /// Storage identifier the chosen driver needs — the ZFS dataset name,
    /// btrfs subvolume path, or thin LV. Empty when not applicable.
    #[serde(default)]
    pub backing_id: String,
    /// Human-readable reason the better rungs are unavailable, shown in
    /// the UI so "why is this still whole-file?" has an answer that does
    /// not require reading the source.
    #[serde(default)]
    pub notes: Vec<String>,
}

impl ReplicationCapabilities {
    /// A node that can only do the Phase 1 strategy. Also what we assume
    /// of a peer that does not answer the capabilities probe at all.
    pub fn floor() -> Self {
        ReplicationCapabilities {
            drivers: vec![DriverKind::FileManifest],
            backing_id: String::new(),
            notes: Vec::new(),
        }
    }

    pub fn supports(&self, k: DriverKind) -> bool {
        self.drivers.contains(&k)
    }

    /// Drop any advertised driver that this build cannot actually run.
    ///
    /// Advertising a rung is a promise to the peer: negotiation would have
    /// both ends agree on a payload shape one of them cannot produce,
    /// breaking syncs that work today. Detection is therefore free to
    /// report what the *storage* supports, and this filter is the single
    /// gate deciding what the *code* supports — one list to update as each
    /// driver lands, instead of a comment nobody re-reads.
    pub fn retain_implemented(&mut self) {
        self.drivers.retain(|d| IMPLEMENTED_DRIVERS.contains(d));
        if !self.drivers.contains(&DriverKind::FileManifest) {
            // The floor is unconditional — a subject with nothing else
            // available must still replicate.
            self.drivers.push(DriverKind::FileManifest);
        }
    }
}

/// Drivers this build can actually execute end to end (produce a delta on
/// the primary AND apply it on a replica). Extended as each lands.
pub const IMPLEMENTED_DRIVERS: &[DriverKind] = &[
    DriverKind::FileManifest,
    // Wired end to end: signatures endpoint, delta bundle on the wire, and
    // the replica-side applier.
    DriverKind::RollingDelta,
    DriverKind::QemuBitmap,
    // Proxmox containers on ZFS: streamed send/receive, peer probe,
    // snapshot-history chain. See replication::zfs_send.
    DriverKind::ZfsSend,
];

/// Choose the strategy for a sync: the best driver BOTH ends support.
///
/// Deliberately an intersection rather than "what the primary can do".
/// A ZFS primary replicating to an ext4 replica cannot send a ZFS stream
/// the replica has no way to receive, and a newer primary talking to an
/// older replica must not send a payload shape that peer predates.
///
/// Always returns something: [`DriverKind::FileManifest`] is implicit on
/// both sides even if a malformed payload lists nothing at all, so a
/// negotiation failure degrades to Phase 1 behaviour instead of aborting
/// the sync.
pub fn negotiate(local: &ReplicationCapabilities, remote: &ReplicationCapabilities) -> DriverKind {
    local
        .drivers
        .iter()
        .filter(|k| remote.supports(**k))
        .copied()
        .max_by_key(|k| k.rank())
        .unwrap_or(DriverKind::FileManifest)
}

// ─── Capability detection ────────────────────────────────────────────
//
// Detection runs the storage tools rather than reading `statfs` magic
// numbers. Two reasons: a magic number is a constant that would have to
// come from a kernel header (and ZFS is out-of-tree, so its value is not
// in one), and we need the dataset/subvolume/LV *identifier* to drive a
// snapshot anyway — a yes/no answer would not be enough.

/// Locate a storage helper without assuming `which` exists — minimal
/// hosts and containers often do not ship it. Mirrors
/// `mail_relay::which`, which exists for the same reason.
fn have_tool(bin: &str) -> bool {
    crate::mail_relay::which(bin).is_some()
}

/// The ZFS dataset containing `path`, if any.
///
/// `zfs list -H -o name <path>` resolves a *path* to its dataset and
/// exits non-zero when the path is not on ZFS, so it answers "is this
/// ZFS" and "which dataset" in one call.
fn zfs_dataset_for(path: &str) -> Option<String> {
    if !have_tool("zfs") {
        return None;
    }
    let out = Command::new("zfs")
        .args(["list", "-H", "-o", "name", path])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

/// True when `path` is a btrfs subvolume. `btrfs subvolume show` exits
/// non-zero for a path that is not one (including a plain directory on a
/// btrfs filesystem, which cannot be snapshotted on its own).
fn btrfs_subvolume(path: &str) -> bool {
    if !have_tool("btrfs") {
        return false;
    }
    Command::new("btrfs")
        .args(["subvolume", "show", path])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The thin LV backing `path`, if it sits on an LVM thin pool.
///
/// `findmnt` gives the source device for the mount point; `lvs` then
/// reports that device's `pool_lv`, which is non-empty only for a thin
/// volume. A thick LV has no pool and cannot take the cheap snapshots
/// this driver depends on.
fn lvm_thin_lv_for(path: &str) -> Option<String> {
    if !have_tool("lvs") || !have_tool("findmnt") {
        return None;
    }
    let src = Command::new("findmnt")
        .args(["-n", "-o", "SOURCE", "--target", path])
        .output()
        .ok()?;
    if !src.status.success() {
        return None;
    }
    let dev = String::from_utf8_lossy(&src.stdout).trim().to_string();
    if dev.is_empty() {
        return None;
    }
    let out = Command::new("lvs")
        .args(["--noheadings", "-o", "lv_full_name,pool_lv", &dev])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut fields = text.split_whitespace();
    let lv = fields.next()?.to_string();
    let pool = fields.next().unwrap_or("");
    if pool.is_empty() { None } else { Some(lv) }
}

/// What this node can do for a CONTAINER rootfs at `rootfs`.
///
/// The returned list always contains [`DriverKind::FileManifest`], so a
/// caller can use the result unconditionally.
pub fn detect_container_capabilities(rootfs: &str) -> ReplicationCapabilities {
    let mut caps = ReplicationCapabilities::floor();
    caps.drivers.push(DriverKind::RollingDelta);
    let src = detect_consistency_source(rootfs);
    caps.backing_id = src.backing_id().to_string();
    if !src.crash_consistent() {
        caps.notes.push(
            "Rootfs is not on ZFS, btrfs or LVM-thin, so the copy is read while \
             the container is writing to it and replicas are not crash-consistent. \
             Block deltas are still used to avoid resending whole files."
                .to_string(),
        );
    }
    caps.retain_implemented();
    caps
}

/// Where a sync reads the primary's files FROM.
///
/// Not negotiated and not sent to the replica: it changes nothing about
/// the payload, only whether that payload represents a single instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsistencySource {
    /// Read the live rootfs. Always available; never crash-consistent.
    Live,
    /// Read through a ZFS snapshot of `dataset`.
    Zfs { dataset: String },
    /// Read through a read-only btrfs snapshot of `subvol`.
    Btrfs { subvol: String },
    /// Read through an LVM thin snapshot of `lv`.
    LvmThin { lv: String },
}

impl ConsistencySource {
    pub fn crash_consistent(&self) -> bool {
        !matches!(self, ConsistencySource::Live)
    }

    /// The storage identifier a snapshot needs, or "" for `Live`.
    pub fn backing_id(&self) -> &str {
        match self {
            ConsistencySource::Live => "",
            ConsistencySource::Zfs { dataset } => dataset,
            ConsistencySource::Btrfs { subvol } => subvol,
            ConsistencySource::LvmThin { lv } => lv,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ConsistencySource::Live => "live files",
            ConsistencySource::Zfs { .. } => "ZFS snapshot",
            ConsistencySource::Btrfs { .. } => "btrfs snapshot",
            ConsistencySource::LvmThin { .. } => "LVM-thin snapshot",
        }
    }
}

/// Best consistency source this node's storage supports for `rootfs`.
pub fn detect_consistency_source(rootfs: &str) -> ConsistencySource {
    if let Some(dataset) = zfs_dataset_for(rootfs) {
        return ConsistencySource::Zfs { dataset };
    }
    if btrfs_subvolume(rootfs) {
        return ConsistencySource::Btrfs { subvol: rootfs.to_string() };
    }
    if let Some(lv) = lvm_thin_lv_for(rootfs) {
        return ConsistencySource::LvmThin { lv };
    }
    ConsistencySource::Live
}

/// What this node can do for a VM subject.
///
/// `QemuBitmap` needs two things that are checked rather than assumed:
/// the disk must be qcow2 (persistent bitmaps are a qcow2 feature — see
/// `BlockDirtyBitmapAdd` in `qapi/block-core.json`, "For now only Qcow2
/// disks support persistent bitmaps"), and `qemu-img` must exist to apply
/// the delta on the replica.
///
/// A VM never falls back to the file drivers: replicating a live qcow2 at
/// file level yields a torn disk, which `vms::manager` already refuses to
/// produce. When the bitmap path is unavailable the caller must decline
/// rather than silently ship something unusable — see
/// [`vm_replication_blocked_reason`].
pub fn detect_vm_capabilities(disk_path: &str) -> ReplicationCapabilities {
    let mut caps = ReplicationCapabilities {
        drivers: Vec::new(),
        backing_id: disk_path.to_string(),
        notes: Vec::new(),
    };
    if !disk_path.ends_with(".qcow2") {
        caps.notes.push(
            "VM disk is not qcow2. Persistent dirty bitmaps are a qcow2 \
             feature, so incremental VM replication is unavailable."
                .to_string(),
        );
        return caps;
    }
    if !have_tool("qemu-img") {
        caps.notes.push(
            "qemu-img is not installed, so a replica could not apply an \
             incremental disk delta."
                .to_string(),
        );
        return caps;
    }
    caps.drivers.push(DriverKind::QemuBitmap);
    caps.retain_implemented();
    // The floor added by retain_implemented is meaningless for a VM: a
    // file-level driver would ship a torn disk. Drop it so callers see an
    // empty list and decline, rather than silently degrading.
    caps.drivers.retain(|d| *d != DriverKind::FileManifest);
    caps
}

/// Why VM replication cannot run, or `None` when it can. Returns the
/// detected notes so the operator gets the actual reason rather than a
/// generic failure.
pub fn vm_replication_blocked_reason(caps: &ReplicationCapabilities) -> Option<String> {
    if caps.supports(DriverKind::QemuBitmap) {
        return None;
    }
    Some(if caps.notes.is_empty() {
        "Incremental VM replication is unavailable on this node.".to_string()
    } else {
        caps.notes.join(" ")
    })
}

/// What THIS node can do for a Proxmox container whose volumes are the
/// given datasets — as the primary (they must exist here) or as a
/// standby (their parents must exist here, and the datasets must not
/// belong to something that is not our replica).
///
/// Like a VM, a Proxmox container never falls back to the file drivers:
/// its volumes are not a stable host directory, so the only thing a
/// standby can hold is a received ZFS stream. Missing pieces are named in
/// `notes` so "why can't I protect this?" has an answer.
pub fn detect_pve_capabilities(datasets: &[String], as_replica: bool) -> ReplicationCapabilities {
    let mut caps = ReplicationCapabilities {
        drivers: Vec::new(),
        backing_id: datasets.join(","),
        notes: Vec::new(),
    };
    if !crate::containers::is_proxmox() {
        caps.notes.push("this node is not a Proxmox host (no `pct`), so it cannot run a Proxmox container".into());
    }
    if !zfs_send::have_zfs() {
        caps.notes.push("ZFS is not installed on this node, so it cannot send or receive a ZFS stream".into());
    }
    if datasets.is_empty() {
        caps.notes.push("no ZFS datasets were named".into());
    }
    if caps.notes.is_empty() {
        for ds in datasets {
            if !zfs_send::is_safe_dataset(ds) {
                caps.notes.push(format!("dataset name {:?} is not valid", ds));
                continue;
            }
            if as_replica {
                match zfs_send::parent_dataset(ds) {
                    Some(parent) if zfs_send::dataset_exists(parent) => {}
                    Some(parent) => caps.notes.push(format!(
                        "this node has no ZFS dataset '{}' to receive '{}' into — the standby needs the \
                         same pool layout as the primary", parent, ds)),
                    None => caps.notes.push(format!("'{}' has no parent dataset", ds)),
                }
            } else if !zfs_send::dataset_exists(ds) {
                caps.notes.push(format!("dataset '{}' does not exist on this node", ds));
            }
        }
    }
    if caps.notes.is_empty() {
        caps.drivers.push(DriverKind::ZfsSend);
    }
    caps.retain_implemented();
    // As for VMs: the floor is meaningless for this subject kind.
    caps.drivers.retain(|d| *d != DriverKind::FileManifest);
    caps
}

/// Why a Proxmox container cannot be replicated to/from this node, or
/// `None` when it can.
pub fn pve_replication_blocked_reason(caps: &ReplicationCapabilities) -> Option<String> {
    if caps.supports(DriverKind::ZfsSend) {
        return None;
    }
    Some(if caps.notes.is_empty() {
        "ZFS replication is unavailable on this node.".to_string()
    } else {
        caps.notes.join("; ")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_is_always_available() {
        let c = ReplicationCapabilities::floor();
        assert!(c.supports(DriverKind::FileManifest));
    }

    /// The golden-rule case: a primary that has grown new capabilities
    /// must keep working with a replica running an older build. An older
    /// peer has no capabilities endpoint, so the caller substitutes
    /// `floor()` — and the negotiated result must be exactly the Phase 1
    /// behaviour, never a payload the old node cannot parse.
    #[test]
    fn new_primary_with_old_replica_degrades_to_phase_one() {
        let local = detect_container_capabilities("/nonexistent-path-for-test");
        let remote = ReplicationCapabilities::floor();
        assert_eq!(negotiate(&local, &remote), DriverKind::FileManifest);
    }

    /// A newer primary must not push a payload an older replica cannot
    /// parse: the shared rung wins, not the primary's best.
    #[test]
    fn negotiation_picks_the_best_shared_driver() {
        let local = ReplicationCapabilities {
            drivers: vec![DriverKind::FileManifest, DriverKind::RollingDelta],
            ..Default::default()
        };
        let remote = ReplicationCapabilities {
            drivers: vec![DriverKind::FileManifest],
            ..Default::default()
        };
        assert_eq!(negotiate(&local, &remote), DriverKind::FileManifest);
        assert_eq!(negotiate(&local, &local), DriverKind::RollingDelta);
    }

    /// Consistency is a primary-side property and must NOT appear in the
    /// negotiated set — advertising it would demand matching storage on
    /// the replica, which is exactly the coupling this design avoids.
    #[test]
    fn consistency_source_is_not_negotiated() {
        let caps = detect_container_capabilities("/nonexistent-path-for-test");
        for d in &caps.drivers {
            assert!(
                matches!(d, DriverKind::FileManifest | DriverKind::RollingDelta),
                "unexpected negotiated driver {:?}",
                d
            );
        }
    }

    #[test]
    fn only_snapshot_sources_are_crash_consistent() {
        assert!(!ConsistencySource::Live.crash_consistent());
        assert!(ConsistencySource::Zfs { dataset: "p/d".into() }.crash_consistent());
        assert!(ConsistencySource::Btrfs { subvol: "/s".into() }.crash_consistent());
        assert!(ConsistencySource::LvmThin { lv: "vg/lv".into() }.crash_consistent());
        assert_eq!(ConsistencySource::Live.backing_id(), "");
        assert_eq!(ConsistencySource::Zfs { dataset: "p/d".into() }.backing_id(), "p/d");
    }

    /// A path on no recognised snapshot store must fall back to Live and
    /// say so, rather than claiming a consistency it cannot deliver.
    #[test]
    fn unknown_storage_falls_back_to_live_with_a_note() {
        let caps = detect_container_capabilities("/nonexistent-path-for-test");
        assert_eq!(detect_consistency_source("/nonexistent-path-for-test"), ConsistencySource::Live);
        assert!(
            caps.notes.iter().any(|n| n.contains("crash-consistent")),
            "operator must be told why: {:?}",
            caps.notes
        );
    }

    /// A malformed or empty capability payload must not abort a sync.
    #[test]
    fn empty_capabilities_still_yield_a_usable_driver() {
        let empty = ReplicationCapabilities::default();
        assert_eq!(negotiate(&empty, &empty), DriverKind::FileManifest);
    }

    #[test]
    fn rank_order_is_strictly_increasing() {
        assert!(DriverKind::RollingDelta.rank() > DriverKind::FileManifest.rank());
        assert!(DriverKind::QemuBitmap.rank() > DriverKind::RollingDelta.rank());
        assert!(DriverKind::ZfsSend.rank() > DriverKind::QemuBitmap.rank());
    }

    /// A Proxmox container on a node without ZFS (this test box) must
    /// offer no driver and say why — never the file floor, which would
    /// ship a payload no Proxmox standby can start.
    #[test]
    fn pve_subject_without_zfs_offers_no_driver_and_explains_why() {
        let caps = detect_pve_capabilities(&["rpool/data/subvol-1-disk-0".to_string()], true);
        if caps.supports(DriverKind::ZfsSend) {
            // A real Proxmox+ZFS host running the tests: the probe is honest either way.
            return;
        }
        assert!(!caps.supports(DriverKind::FileManifest));
        let why = pve_replication_blocked_reason(&caps).expect("must give a reason");
        assert!(!why.is_empty());
        // A bad dataset name is refused before any zfs call.
        let bad = detect_pve_capabilities(&["../etc".to_string()], true);
        assert!(!bad.supports(DriverKind::ZfsSend));
    }

    /// A non-qcow2 VM disk must NOT silently fall back to a file-level
    /// driver — that is how you ship a torn disk image.
    #[test]
    fn raw_vm_disk_offers_no_driver_and_explains_why() {
        let caps = detect_vm_capabilities("/var/lib/wolfstack/vms/test.raw");
        assert!(caps.drivers.is_empty(), "raw disk must offer no driver");
        let reason = vm_replication_blocked_reason(&caps).expect("must give a reason");
        assert!(reason.contains("qcow2"), "reason should name the cause: {}", reason);
    }

    /// Capabilities cross a version boundary — an older peer's payload
    /// (fewer fields) must still parse.
    #[test]
    fn capabilities_payload_tolerates_missing_fields() {
        let old_wire = r#"{"drivers":["file_manifest"]}"#;
        let caps: ReplicationCapabilities =
            serde_json::from_str(old_wire).expect("old payload must parse");
        assert!(caps.supports(DriverKind::FileManifest));
        assert!(caps.backing_id.is_empty());
    }

    /// Driver names are wire values. Renaming a variant would silently
    /// break negotiation across a mixed-version fleet, so the serialised
    /// spelling is pinned.
    #[test]
    fn driver_wire_names_are_stable() {
        let pairs = [
            (DriverKind::FileManifest, "\"file_manifest\""),
            (DriverKind::RollingDelta, "\"rolling_delta\""),
            (DriverKind::QemuBitmap, "\"qemu_bitmap\""),
            (DriverKind::ZfsSend, "\"zfs_send\""),
        ];
        for (kind, wire) in pairs {
            assert_eq!(serde_json::to_string(&kind).unwrap(), wire);
        }
    }
}
