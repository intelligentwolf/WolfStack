// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! WolfHA — manual high availability for native LXC containers (Phase 1).
//!
//! Model: the container runs on ONE node (the primary). Each chosen
//! replica node holds a stopped copy with the SAME name, MAC, IP and
//! WolfNet marker — on a shared-L2 bridge (vSwitch) the copy can take
//! over the identity wholesale, so DNS never changes and no load
//! balancer is needed. The primary pushes incremental rootfs deltas to
//! every replica on a schedule (manifest diff over the agent HTTP
//! channel — no SSH provisioning). Failover and failback are OPERATOR
//! actions in this phase: promotion is a human decision, so the
//! split-brain class of automatic-failover bugs cannot occur.
//!
//! Replica hygiene rules (the difference between HA and self-inflicted
//! split-brain):
//! - replicas carry a `.wolfha-replica` marker and NEVER have
//!   `lxc.start.auto` — `lxc-autostart` at boot cannot start them;
//! - the PRIMARY's autostart flag is taken over by WolfHA
//!   (`autostart_managed`): stripped from the config and re-applied as
//!   a boot-time start that first asks every replica "did you take
//!   over while I was down?" (see [`boot_guard`]);
//! - after a failover the old primary's copy is marked stale and is
//!   only reused after a reverse sync (failback = promote on the
//!   original node once it has caught up).
//!
//! Subjects: native LXC (file drivers), native QEMU VMs (dirty-bitmap
//! deltas), and — since Colt's warm-standby report of 2026-09-06 —
//! Proxmox-managed containers whose volumes are ZFS datasets, replicated
//! with `zfs send` (see `replication::zfs_send`). Proxmox containers on
//! LVM-thin or directory storage are still out of scope: their rootfs is
//! neither a stable host directory nor a ZFS dataset.

pub mod replication;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use crate::node_identity::PeerAuth;

/// Marker file inside the container dir identifying an HA replica.
pub const REPLICA_MARKER: &str = ".wolfha-replica";

fn store_path() -> String {
    format!("{}/wolfha.json", crate::paths::get().config_dir)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HaRole {
    Primary,
    Replica,
}

/// What kind of thing is being protected.
///
/// `Container` is the default so every wolfha.json written before VM
/// support parses unchanged and keeps behaving exactly as it did — the
/// field simply appears absent and defaults back to what those entries
/// have always been.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    #[default]
    Container,
    Vm,
    /// A Proxmox-managed container (keyed by VMID) whose volumes are ZFS
    /// datasets. Replicated only by `zfs send`; runs through `pct`.
    PveContainer,
}

impl SubjectKind {
    pub fn label(self) -> &'static str {
        match self {
            SubjectKind::Container => "container",
            SubjectKind::Vm => "VM",
            SubjectKind::PveContainer => "Proxmox container",
        }
    }
}

/// Is the subject running on this node right now?
pub fn subject_is_running(kind: SubjectKind, name: &str) -> bool {
    match kind {
        // On a Proxmox host `lxc_is_running` asks `pct status`, which is
        // the right runtime for a Proxmox container.
        SubjectKind::Container | SubjectKind::PveContainer => crate::containers::lxc_is_running(name),
        SubjectKind::Vm => crate::vms::manager::VmManager::new().check_running(name),
    }
}

/// Start the subject. Used by promotion.
pub fn subject_start(kind: SubjectKind, name: &str) -> Result<(), String> {
    match kind {
        // `lxc_start` runs `pct start` on a Proxmox host.
        SubjectKind::Container | SubjectKind::PveContainer => crate::containers::lxc_start(name).map(|_| ()),
        SubjectKind::Vm => crate::vms::manager::VmManager::new().start_vm(name),
    }
}

/// Stop the subject. Used by demotion and self-fencing.
///
/// A VM is stopped gracefully (`force = false`): demotion happens when
/// another node is taking over, and a guest that is given the chance to
/// flush its filesystems hands over a cleaner copy.
pub fn subject_stop(kind: SubjectKind, name: &str) -> Result<(), String> {
    match kind {
        SubjectKind::Container | SubjectKind::PveContainer => crate::containers::lxc_stop(name).map(|_| ()),
        SubjectKind::Vm => crate::vms::manager::VmManager::new().stop_vm(name, false),
    }
}

/// A peer node in an HA relationship. The id is authoritative; address
/// and port are the last-known values so replication still works when
/// the cluster registry is briefly missing the node (refreshed from
/// live cluster state whenever resolvable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaPeer {
    pub node_id: String,
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HaSyncStatus {
    pub at: u64,
    pub ok: bool,
    pub message: String,
    #[serde(default)]
    pub files_sent: u64,
    #[serde(default)]
    pub bytes_sent: u64,
}

fn default_failover_after() -> u64 { 90 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaEntry {
    /// Name of the protected subject. Still called `container` because it
    /// is the on-disk and API key for every existing install; renaming it
    /// would invalidate every wolfha.json and every client in the field
    /// for no behavioural gain. Read it as "subject name".
    pub container: String,
    /// Container (the default, and everything written before VM support)
    /// or VM.
    #[serde(default)]
    pub kind: SubjectKind,
    pub role: HaRole,
    /// Primary: minutes between delta syncs.
    #[serde(default)]
    pub interval_minutes: u64,
    /// ORDERED replica set — the order IS the failover priority (first =
    /// preferred takeover node). On a primary: its replicas. On a
    /// replica: the full set as told by the primary (via seed/delta
    /// metadata), so each standby can rank itself against its peers.
    #[serde(default)]
    pub replicas: Vec<HaPeer>,
    /// Replica: who currently owns the container.
    #[serde(default)]
    pub primary: Option<HaPeer>,
    /// Primary: WolfHA owns this container's boot because it had
    /// `lxc.start.auto = 1` when HA was enabled (the flag is stripped
    /// so `lxc-autostart` can't race the takeover check).
    #[serde(default)]
    pub autostart_managed: bool,
    /// Primary: per-replica-node-id result of the latest sync.
    #[serde(default)]
    pub last_sync: HashMap<String, HaSyncStatus>,
    /// Replica: when the last delta (or seed) was applied.
    #[serde(default)]
    pub last_delta_at: u64,
    /// This copy is known stale (a replica was promoted while we were
    /// the primary). A stale copy must never start; it becomes a
    /// replica of the new primary and catches up via reverse sync.
    #[serde(default)]
    pub stale: bool,
    /// Phase 2: standbys promote themselves when the primary NODE dies.
    /// Off by default — automatic promotion is opt-in per container.
    #[serde(default)]
    pub auto_failover: bool,
    /// External witness for auto mode — an IP the node must be able to
    /// ping before it may act (fence itself, or promote). The network
    /// gateway is the natural choice: a node that can't reach the
    /// gateway isn't serving anyone anyway. Replaces quorum, so 2-node
    /// clusters work.
    #[serde(default)]
    pub witness: String,
    /// Auto mode: how long the primary must be continuously unreachable
    /// before a standby promotes. The primary self-fences at HALF this
    /// (min 30s), so on a clean partition it is stopped well before any
    /// standby starts.
    #[serde(default = "default_failover_after")]
    pub failover_after_secs: u64,
    /// Primary, VM only: a disk delta that has been taken but not yet
    /// confirmed by every replica.
    ///
    /// This exists because the bitmap is cleared when the BACKUP succeeds,
    /// which is before the delta reaches anyone. If a transfer then failed
    /// and we simply took a fresh delta next round, the blocks in the lost
    /// one would be in no delta ever again and that replica would diverge
    /// while continuing to report success — the worst failure an HA system
    /// can have. So the delta is retained until every replica has applied
    /// it, and no new one is taken while it is outstanding.
    #[serde(default)]
    pub pending_vm_delta: Option<replication::qemu_bitmap::PendingDelta>,
    /// VM only — the replication chain token.
    ///
    /// On a PRIMARY: the token every fully-caught-up replica currently
    /// holds. Each delta ships (prev = this, next = the pending delta's
    /// token); when every replica has applied the pending delta this
    /// advances to its token. A seed hands the receiving replica the
    /// then-current token directly (a seed taken now contains everything
    /// any outstanding delta contains, and everything since).
    ///
    /// On a REPLICA: the token describing this copy's exact disk state.
    /// A delta whose `prev` doesn't match is proof the copies diverged —
    /// the replica refuses it and the primary re-seeds automatically.
    /// `None` = state unknown (a demotion without a controlled final
    /// delta — crash takeover, boot-guard demote): the copy must be
    /// re-seeded before any incremental can be trusted on it.
    ///
    /// Containers don't need this: their sync diffs a manifest of the
    /// actual rootfs each round, so divergence is detected and repaired
    /// file-by-file. A VM disk has no manifest — the chain is what makes
    /// "this incremental fits that base" provable instead of assumed.
    #[serde(default)]
    pub vm_chain: Option<String>,
    /// Primary only: this node's own peer identity. Travels to standbys
    /// inside HaMeta.primary so every delta re-teaches them who the
    /// CURRENT primary is — without it, a standby that survived a
    /// failover keeps watching the old dead primary forever.
    #[serde(default)]
    pub self_identity: Option<HaPeer>,
    /// Proxmox container only: the ZFS datasets that make up the subject
    /// (`<pool>/subvol-<vmid>-disk-<n>`, rootfs first as listed in its
    /// config). On a standby they are the datasets to mount at promotion
    /// and destroy on drop; they arrive in HaMeta with every stream.
    #[serde(default)]
    pub zfs_datasets: Vec<String>,
}

/// The HA settings a primary pushes to its replicas with every seed and
/// delta, so standbys always know the current priority order, witness
/// and timings — setting changes propagate with the next sync round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaMeta {
    /// What the primary is protecting. `#[serde(default)]` so a delta
    /// from an older primary still parses and keeps meaning "container".
    #[serde(default)]
    pub kind: SubjectKind,
    pub interval_minutes: u64,
    pub replicas: Vec<HaPeer>,
    pub auto_failover: bool,
    pub witness: String,
    pub failover_after_secs: u64,
    /// The sender — i.e. the CURRENT primary. Standbys re-point their
    /// `primary` at this on every delta, so ownership changes propagate.
    #[serde(default)]
    pub primary: Option<HaPeer>,
    /// Proxmox container only — see `HaEntry::zfs_datasets`.
    #[serde(default)]
    pub zfs_datasets: Vec<String>,
}

impl HaMeta {
    pub fn from_entry(e: &HaEntry) -> Self {
        HaMeta {
            kind: e.kind,
            interval_minutes: e.interval_minutes,
            replicas: e.replicas.clone(),
            auto_failover: e.auto_failover,
            witness: e.witness.clone(),
            failover_after_secs: e.failover_after_secs,
            primary: e.self_identity.clone(),
            zfs_datasets: e.zfs_datasets.clone(),
        }
    }

    pub fn apply_to(&self, e: &mut HaEntry) {
        // The primary is authoritative about what it is replicating; a
        // standby that guessed wrong would start the wrong kind of thing
        // on failover.
        e.kind = self.kind;
        e.interval_minutes = self.interval_minutes;
        e.replicas = self.replicas.clone();
        e.auto_failover = self.auto_failover;
        e.witness = self.witness.clone();
        e.failover_after_secs = self.failover_after_secs;
        if !self.zfs_datasets.is_empty() {
            e.zfs_datasets = self.zfs_datasets.clone();
        }
        if e.role == HaRole::Replica
            && let Some(p) = &self.primary
        {
            e.primary = Some(p.clone());
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HaStore {
    #[serde(default)]
    pub entries: Vec<HaEntry>,
}

impl HaStore {
    pub fn load() -> Self {
        match std::fs::read_to_string(store_path()) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = store_path();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::paths::write_secure(&path, &json).map_err(|e| format!("save wolfha store: {}", e))
    }

    pub fn get(&self, container: &str) -> Option<&HaEntry> {
        self.entries.iter().find(|e| e.container == container)
    }

    pub fn get_mut(&mut self, container: &str) -> Option<&mut HaEntry> {
        self.entries.iter_mut().find(|e| e.container == container)
    }

    pub fn remove(&mut self, container: &str) {
        self.entries.retain(|e| e.container != container);
    }
}

// ─── Manifest: the incremental-sync unit ───

/// One filesystem object in a rootfs manifest. Field names are single
/// letters because a container manifest is ~50k-200k entries and this
/// JSON crosses the wire on every sync round.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManifestEntry {
    /// Path relative to the rootfs, e.g. `etc/hostname`.
    pub p: String,
    /// Kind: "f" file, "d" dir, "l" symlink, "o" other (device/fifo/socket).
    pub k: String,
    /// Size in bytes (files only; 0 otherwise).
    #[serde(default)]
    pub s: u64,
    /// mtime, unix seconds.
    #[serde(default)]
    pub m: i64,
    /// Symlink target (symlinks only).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub t: String,
}

/// Top-level rootfs dirs whose CONTENTS are volatile mount points, not
/// data — same exclusion set the export tar uses.
const SYNC_EXCLUDE_TOP: [&str; 3] = ["proc", "sys", "dev"];

/// Walk a rootfs and build its manifest. Symlinks are never followed.
pub fn build_manifest(rootfs: &str) -> Result<Vec<ManifestEntry>, String> {
    let root = std::path::Path::new(rootfs);
    if !root.is_dir() {
        return Err(format!("rootfs not found: {}", rootfs));
    }
    let mut out = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for de in rd.flatten() {
            let path = de.path();
            let Ok(rel) = path.strip_prefix(root) else { continue };
            let rel_str = rel.to_string_lossy().to_string();
            if rel_str.is_empty() || rel_str.contains('\n') {
                // Newlines can't ride in a NUL-free JSON-diff + tar -T
                // pipeline safely enough to be worth it — skip, they
                // don't occur in real rootfs content.
                continue;
            }
            // Excluded top-level dirs are listed as bare dirs (so they
            // exist on the replica) but never descended into.
            let top = rel_str.split('/').next().unwrap_or("");
            let Ok(md) = std::fs::symlink_metadata(&path) else { continue };
            let ft = md.file_type();
            if ft.is_dir() {
                out.push(ManifestEntry { p: rel_str.clone(), k: "d".into(), s: 0, m: 0, t: String::new() });
                if !(rel.components().count() == 1 && SYNC_EXCLUDE_TOP.contains(&top)) {
                    stack.push(path);
                }
            } else if ft.is_file() {
                use std::os::unix::fs::MetadataExt;
                out.push(ManifestEntry {
                    p: rel_str, k: "f".into(), s: md.len(), m: md.mtime(), t: String::new(),
                });
            } else if ft.is_symlink() {
                let target = std::fs::read_link(&path)
                    .map(|t| t.to_string_lossy().to_string())
                    .unwrap_or_default();
                out.push(ManifestEntry { p: rel_str, k: "l".into(), s: 0, m: 0, t: target });
            } else {
                // Device nodes / fifos / sockets: tracked by presence
                // only. They only exist under /dev in practice (excluded)
                // but a rootfs can technically carry them elsewhere.
                out.push(ManifestEntry { p: rel_str, k: "o".into(), s: 0, m: 0, t: String::new() });
            }
        }
    }
    Ok(out)
}

/// Compare a local (primary) manifest against a remote (replica) one.
/// Returns (paths to ship, paths to delete on the replica). Pure.
///
/// A file is "changed" on size or mtime difference — the same quick
/// check rsync defaults to. Kind changes (file→dir etc.) ship the new
/// object AND delete the old one first so extraction can't collide.
pub fn manifest_diff(
    local: &[ManifestEntry],
    remote: &[ManifestEntry],
) -> (Vec<String>, Vec<String>) {
    let remote_map: HashMap<&str, &ManifestEntry> =
        remote.iter().map(|e| (e.p.as_str(), e)).collect();
    let local_set: std::collections::HashSet<&str> =
        local.iter().map(|e| e.p.as_str()).collect();

    let mut changed = Vec::new();
    let mut deletions = Vec::new();

    for le in local {
        match remote_map.get(le.p.as_str()) {
            None => changed.push(le.p.clone()),
            Some(re) => {
                if re.k != le.k {
                    // Kind flip: clear the old object, ship the new.
                    deletions.push(le.p.clone());
                    changed.push(le.p.clone());
                } else {
                    match le.k.as_str() {
                        "f" if le.s != re.s || le.m != re.m => changed.push(le.p.clone()),
                        "l" if le.t != re.t => changed.push(le.p.clone()),
                        _ => {} // unchanged, or dirs/others where presence is enough
                    }
                }
            }
        }
    }
    for re in remote {
        if !local_set.contains(re.p.as_str()) {
            deletions.push(re.p.clone());
        }
    }
    // Delete children before parents.
    deletions.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| b.cmp(a)));
    deletions.dedup();
    (changed, deletions)
}

/// Reject any relative path that could escape the rootfs when joined.
/// Applied to every deletion path a peer sends us and to extraction
/// prep — a compromised or buggy peer must not be able to touch the
/// host outside the replica's rootfs.
pub fn is_safe_rel_path(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.contains('\0')
        && !p.split('/').any(|c| c == ".." || c.is_empty() || c == ".")
}

// ─── tar plumbing ───

/// Args ensuring a rootfs round-trips exactly between hosts: numeric
/// uids (an unprivileged container's shifted ids must not be remapped
/// through /etc/passwd name lookup), xattrs (file capabilities like
/// ping's CAP_NET_RAW) and ACLs.
const TAR_FIDELITY: [&str; 3] = ["--numeric-owner", "--xattrs", "--acls"];

/// Tar a set of rootfs-relative paths (NUL-separated list file) into
/// `archive`. Tolerates files changing mid-read — the source container
/// is running; a torn file is corrected by the next sync round.
fn tar_paths(rootfs: &str, list_file: &str, archive: &str) -> Result<(), String> {
    let mut args: Vec<&str> = vec!["-czf", archive, "-C", rootfs];
    args.extend_from_slice(&TAR_FIDELITY);
    args.extend_from_slice(&[
        "--null", "--no-recursion", "-T", list_file,
        "--warning=no-file-changed", "--warning=no-file-removed", "--ignore-failed-read",
    ]);
    let out = Command::new("tar").args(&args).output()
        .map_err(|e| format!("tar failed to start: {}", e))?;
    // Exit 1 = "file changed as we read it" — expected on a live rootfs.
    match out.status.code() {
        Some(0) | Some(1) => Ok(()),
        _ => Err(format!("tar failed: {}", String::from_utf8_lossy(&out.stderr).trim())),
    }
}

/// Tar an entire live rootfs for the initial replica seed. Same
/// exclusions as lxc_export, plus the fidelity flags above.
pub fn tar_full_rootfs(rootfs: &str, archive: &str) -> Result<(), String> {
    let mut args: Vec<&str> = vec!["-czf", archive, "-C", rootfs];
    args.extend_from_slice(&TAR_FIDELITY);
    args.extend_from_slice(&[
        "--exclude=./proc/*", "--exclude=./sys/*", "--exclude=./dev/*",
        "--warning=no-file-changed", "--warning=no-file-removed", "--ignore-failed-read",
        ".",
    ]);
    let out = Command::new("tar").args(&args).output()
        .map_err(|e| format!("tar failed to start: {}", e))?;
    match out.status.code() {
        Some(0) | Some(1) => Ok(()),
        _ => Err(format!("tar failed: {}", String::from_utf8_lossy(&out.stderr).trim())),
    }
}

/// Extract a delta/seed archive into a replica rootfs with the same
/// fidelity flags used on creation.
pub fn untar_into_rootfs(archive: &str, rootfs: &str) -> Result<(), String> {
    let mut args: Vec<&str> = vec!["-xzf", archive, "-C", rootfs];
    args.extend_from_slice(&TAR_FIDELITY);
    let out = Command::new("tar").args(&args).output()
        .map_err(|e| format!("tar failed to start: {}", e))?;
    if !out.status.success() {
        return Err(format!("tar extract failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

// ─── Replica-side operations (called from api handlers) ───

pub fn marker_path(container: &str) -> String {
    format!("{}/{}/{}", crate::containers::lxc_base_dir(container), container, REPLICA_MARKER)
}

pub fn is_replica(container: &str) -> bool {
    std::path::Path::new(&marker_path(container)).exists()
}

/// Apply a delta on a replica: extract changed files, then apply
/// deletions (children-first order is the caller's contract, enforced
/// again here by re-sorting). The container must be stopped.
pub fn apply_delta(
    container: &str,
    archive: &str,
    deletions: &[String],
    source_config: &str,
) -> Result<usize, String> {
    let base = crate::containers::lxc_base_dir(container);
    let container_dir = format!("{}/{}", base, container);
    let rootfs = format!("{}/rootfs", container_dir);
    if !std::path::Path::new(&rootfs).is_dir() {
        return Err(format!("replica rootfs missing: {}", rootfs));
    }
    if crate::containers::lxc_is_running(container) {
        return Err(format!("'{}' is running here — refusing to overwrite a live rootfs", container));
    }

    for d in deletions {
        if !is_safe_rel_path(d) {
            return Err(format!("unsafe deletion path rejected: {:?}", d));
        }
    }

    untar_into_rootfs(archive, &rootfs)?;

    let mut sorted: Vec<&String> = deletions.iter().collect();
    sorted.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| b.cmp(a)));
    let mut deleted = 0usize;
    for d in sorted {
        let target = format!("{}/{}", rootfs, d);
        let p = std::path::Path::new(&target);
        let Ok(md) = std::fs::symlink_metadata(p) else { continue };
        let res = if md.file_type().is_dir() {
            std::fs::remove_dir_all(p)
        } else {
            std::fs::remove_file(p)
        };
        if res.is_ok() {
            deleted += 1;
        }
    }

    write_replica_config(&container_dir, source_config);
    Ok(deleted)
}

/// Write a replica's LXC config from the primary's: identity keys
/// (uts.name, hwaddr, ipv4) stay EXACTLY as the primary has them —
/// that's the whole point — but rootfs.path is re-pointed at this
/// host's dir and `lxc.start.auto` is stripped so `lxc-autostart` can
/// never boot a standby into a split-brain.
fn write_replica_config(container_dir: &str, source_config: &str) {
    let name = container_dir.rsplit('/').next().unwrap_or("");
    let rewritten: Vec<String> = source_config
        .lines()
        .filter(|l| !l.trim_start().starts_with("lxc.start.auto"))
        .map(|l| {
            if l.trim_start().starts_with("lxc.rootfs.path") {
                format!("lxc.rootfs.path = dir:{}/rootfs", container_dir)
            } else {
                l.to_string()
            }
        })
        .collect();
    let mut out = rewritten.join("\n");
    if !out.ends_with('\n') {
        out.push('\n');
    }
    let _ = std::fs::write(format!("{}/config", container_dir), out);
    let _ = name; // container name only informs the path; uts.name is preserved
}

/// Refresh a replica's config from the primary's without touching the
/// rootfs — used by metadata-only heartbeats (quiet sync rounds).
pub fn refresh_replica_config(container: &str, source_config: &str) {
    if source_config.trim().is_empty() {
        return;
    }
    let dir = format!("{}/{}", crate::containers::lxc_base_dir(container), container);
    if std::path::Path::new(&dir).exists() {
        write_replica_config(&dir, source_config);
    }
}

/// Drop replica entries that are the same MACHINE under different
/// aliases. Registries know one node by different ids (and a node can
/// be reachable on several addresses — tailscale AND wolfnet, live-seen
/// 2026-08-08), so after a failover cycle a replica set can list the
/// same box twice → doubled delta shipping. Canonicalise through the
/// cluster registry (get_node resolves id aliases via self_id); fall
/// back to the address for nodes the registry doesn't know.
pub fn dedupe_replicas(container: &str, cluster: &crate::agent::ClusterState) {
    let mut store = HaStore::load();
    let Some(entry) = store.get_mut(container) else { return };
    let before = entry.replicas.len();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut kept: Vec<HaPeer> = Vec::new();
    for peer in entry.replicas.drain(..) {
        let key = cluster.get_node(&peer.node_id)
            .map(|n| n.id)
            .unwrap_or_else(|| peer.address.clone());
        if seen.insert(key) {
            kept.push(peer);
        }
    }
    entry.replicas = kept;
    if entry.replicas.len() != before {
        tracing::info!("wolfha: deduped '{}' replica set {} -> {}", container, before, entry.replicas.len());
        let _ = store.save();
    }
}

/// Install a full seed on this node: fresh container dir, extracted
/// rootfs, replica config, marker, optional WolfNet marker. Refuses to
/// clobber a real (non-replica) container of the same name.
pub fn install_seed(
    container: &str,
    kind: SubjectKind,
    archive: &str,
    source_config: &str,
    primary: HaPeer,
    wolfnet_ip: Option<&str>,
    meta: Option<&HaMeta>,
) -> Result<(), String> {
    let base = crate::containers::lxc_base_dir(container);
    let container_dir = format!("{}/{}", base, container);
    if std::path::Path::new(&container_dir).exists() {
        if !is_replica(container) {
            return Err(format!(
                "a container named '{}' already exists on this node and is NOT a WolfHA replica — refusing to overwrite it",
                container
            ));
        }
        // Re-seed of an existing replica: start clean.
        if crate::containers::lxc_is_running(container) {
            return Err(format!("replica '{}' is running here — stop it before re-seeding", container));
        }
        std::fs::remove_dir_all(&container_dir)
            .map_err(|e| format!("could not clear old replica dir: {}", e))?;
    }
    let rootfs = format!("{}/rootfs", container_dir);
    std::fs::create_dir_all(&rootfs).map_err(|e| format!("create replica dir: {}", e))?;

    if let Err(e) = untar_into_rootfs(archive, &rootfs) {
        let _ = std::fs::remove_dir_all(&container_dir);
        return Err(e);
    }
    write_replica_config(&container_dir, source_config);
    std::fs::write(marker_path(container), format!("primary={}\n", primary.node_id))
        .map_err(|e| format!("write replica marker: {}", e))?;
    if let Some(ip) = wolfnet_ip.filter(|s| !s.is_empty()) {
        let wn_dir = format!("{}/.wolfnet", container_dir);
        let _ = std::fs::create_dir_all(&wn_dir);
        let _ = std::fs::write(format!("{}/ip", wn_dir), ip);
    }

    let mut store = HaStore::load();
    store.remove(container);
    let mut entry = HaEntry {
        container: container.to_string(),
        kind,
        role: HaRole::Replica,
        interval_minutes: 0,
        replicas: Vec::new(),
        primary: Some(primary),
        autostart_managed: false,
        last_sync: HashMap::new(),
        last_delta_at: now_unix(),
        stale: false,
        pending_vm_delta: None,
        // Containers carry no chain — their divergence detection is the
        // per-round manifest diff.
        vm_chain: None,
        auto_failover: false,
        witness: String::new(),
        failover_after_secs: default_failover_after(),
        self_identity: None,
        zfs_datasets: Vec::new(),
    };
    if let Some(m) = meta {
        m.apply_to(&mut entry);
    }
    store.entries.push(entry);
    store.save()
}

/// Promote this node's copy: drop the replica marker, flip the store
/// entry to primary (old primary + other replicas become this entry's
/// replica set, minus this node itself), start the container. The
/// caller has already handled (or accepted the absence of) the old
/// primary. `me` is this node's own peer identity — recorded so every
/// future delta re-teaches the standbys who owns the container now.
pub fn promote_local(container: &str, me: Option<HaPeer>) -> Result<(), String> {
    let mut store = HaStore::load();
    let entry = store
        .get_mut(container)
        .ok_or_else(|| format!("'{}' is not WolfHA-managed on this node", container))?;
    let kind = entry.kind;
    if entry.role == HaRole::Primary && !entry.stale {
        return Err(format!("'{}' is already the active primary here", container));
    }

    let old_primary = entry.primary.take();
    entry.role = HaRole::Primary;
    entry.stale = false;
    entry.last_sync = HashMap::new();
    if let Some(p) = old_primary
        && !entry.replicas.iter().any(|r| r.node_id == p.node_id)
    {
        entry.replicas.push(p);
    }
    // The replica set came from the old primary's meta and includes THIS
    // node — a primary must not list (and sync to) itself. Filter by id
    // AND by address: registries alias the same machine under different
    // ids, so the id check alone provably misses (live test 2026-08-08).
    if let Some(ref me) = me {
        entry.replicas.retain(|r| r.node_id != me.node_id);
    }
    entry.replicas.retain(|r| !peer_is_local(r));
    entry.self_identity = me;
    if entry.interval_minutes == 0 {
        entry.interval_minutes = 5;
    }
    // The promoted copy owns boot from now on, same as any HA primary.
    entry.autostart_managed = true;
    let _ = std::fs::remove_file(marker_path(container));
    store.save()?;

    // A promoted VM becomes the delta SOURCE, so its disk needs a fresh
    // recording bitmap BEFORE the guest boots — attached online this
    // would race the first guest writes, and writes made before the
    // attach would be in no delta ever (the replicas would diverge from
    // the first round). `qemu-img bitmap --add` on the stopped image
    // creates it enabled; the persistent bitmap loads recording when the
    // VM starts. Any bitmap already inside the image (a file-copied seed
    // carries the old primary's) describes the WRONG history — replace,
    // never reuse.
    // The entry's vm_chain is deliberately KEPT: it describes this copy's
    // disk state, which is exactly the base the standbys share — the
    // first delta from here fits every caught-up standby, and the stale
    // ex-primary re-seeds automatically via the chain check.
    if kind == SubjectKind::Vm {
        let (disk, _) = vm_disk_and_config(container)?;
        replication::qemu_bitmap::offline_remove_bitmap(&disk, container);
        replication::qemu_bitmap::offline_add_bitmap(&disk, container)
            .map_err(|e| format!("promotion stopped before starting the VM: {}", e))?;
    }

    // A Proxmox container's volumes were received as datasets; Proxmox
    // expects each mounted at its inherited mountpoint before `pct start`.
    if kind == SubjectKind::PveContainer {
        let datasets = HaStore::load().get(container).map(|e| e.zfs_datasets.clone()).unwrap_or_default();
        if datasets.is_empty() {
            return Err(format!("no datasets are recorded for Proxmox container {} on this node — it was never seeded here", container));
        }
        for ds in &datasets {
            replication::zfs_send::mount(ds)
                .map_err(|e| format!("promotion stopped before starting the container: could not mount {}: {}", ds, e))?;
        }
    }

    subject_start(kind, container)
        .map_err(|e| format!("started promotion but the {} failed to start: {}", kind.label(), e))?;

    // Same MAC as the old primary, so peers' ARP caches stay valid; the
    // switch learns the new port from the first outbound frame. Nudge
    // that along with a best-effort gateway ping from inside.
    //
    // Container-only: the nudge runs a command INSIDE the guest via
    // lxc-attach, which has no VM equivalent. A VM sends its own traffic
    // as it boots, which teaches the switch the same thing slightly later.
    if kind == SubjectKind::Vm {
        return Ok(());
    }
    let c = container.to_string();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(3));
        const NUDGE: &str = "gw=$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}'); [ -n \"$gw\" ] && ping -c1 -W2 \"$gw\" >/dev/null 2>&1";
        let _ = if kind == SubjectKind::PveContainer {
            // pct(1): `pct exec <vmid> [<extra-args>]` — run a command inside
            // the container.
            Command::new("pct").args(["exec", &c, "--", "sh", "-c", NUDGE]).output()
        } else {
            Command::new("lxc-attach").args(["-n", &c, "--", "sh", "-c", NUDGE]).output()
        };
    });
    Ok(())
}

/// Demote this node's copy: stop the container if running, mark the
/// copy stale, become a replica of `new_primary`, write the marker.
pub fn demote_local(container: &str, new_primary: HaPeer) -> Result<(), String> {
    let kind = HaStore::load().get(container).map(|e| e.kind).unwrap_or_default();
    if subject_is_running(kind, container) {
        subject_stop(kind, container)
            .map_err(|e| format!("could not stop '{}' for demotion: {}", container, e))?;
    }
    // A demoted Proxmox container must not come back at the next boot
    // of this node — the boot guard decides, exactly as for a native one.
    if kind == SubjectKind::PveContainer
        && let Err(e) = pve_set_onboot(container, false)
    {
        tracing::warn!("wolfha[{}]: could not clear onboot on demotion: {}", container, e);
    }
    let base = crate::containers::lxc_base_dir(container);
    let container_dir = format!("{}/{}", base, container);
    if std::path::Path::new(&container_dir).exists() {
        let _ = std::fs::write(marker_path(container), format!("primary={}\n", new_primary.node_id));
        // A demoted copy must never autostart.
        if let Ok(cfg) = std::fs::read_to_string(format!("{}/config", container_dir)) {
            write_replica_config(&container_dir, &cfg);
        }
    }

    let mut store = HaStore::load();
    match store.get_mut(container) {
        Some(entry) => {
            entry.role = HaRole::Replica;
            entry.stale = true; // until the new primary syncs back over us
            entry.primary = Some(new_primary);
            entry.replicas.clear();
            entry.last_sync.clear();
            entry.self_identity = None;
            // A demoted VM copy's disk may hold writes no delta ever
            // captured (a crash takeover is exactly that case), so its
            // chain token cannot be trusted — clearing it makes the new
            // primary re-seed this copy instead of patching a diverged
            // base. The coordinated-handoff path in api::wolfha_demote
            // re-establishes the token AFTER its quiesced final delta
            // lands, which is the one case the copy is provably exact.
            if entry.kind == SubjectKind::Vm {
                entry.vm_chain = None;
            }
        }
        None => {
            store.entries.push(HaEntry {
                container: container.to_string(),
                // No prior entry, so the kind is not known here; the next
                // delta carries it in HaMeta and corrects this.
                kind: SubjectKind::default(),
                role: HaRole::Replica,
                interval_minutes: 0,
                replicas: Vec::new(),
                primary: Some(new_primary),
                autostart_managed: false,
                last_sync: HashMap::new(),
                last_delta_at: 0,
                stale: true,
                pending_vm_delta: None,
                // No prior entry means no provable disk state either — a
                // VM copy in this situation re-seeds via the chain check.
                vm_chain: None,
                auto_failover: false,
                witness: String::new(),
                failover_after_secs: default_failover_after(),
                self_identity: None,
                zfs_datasets: Vec::new(),
            });
        }
    }
    store.save()
}

// ─── Primary-side sync engine ───

/// One delta round from this (primary) node to one replica. Returns the
/// status to record. Blocking-free: all fs/tar work goes through
/// spawn_blocking; HTTP through the shared client.
/// Rebuild one file from a block delta and move it into place.
///
/// Reconstructs beside the target and renames only once the new content is
/// complete and fsynced: a crash midway must never leave a half-written
/// file where the old one was, because a replica exists to be promoted and
/// a truncated database is worse than a stale one.
///
/// Ownership and mode are copied from the file being replaced. The
/// reconstruction is a brand-new file created with this process's
/// defaults, so without this every delta would quietly turn its target
/// into root:root 0644 — and a rootfs whose files change owner on first
/// sync is a container that breaks the next time it starts.
fn install_reconstructed_file(target: &str, ops: &[replication::rolling::DeltaOp]) -> Result<(), String> {
    let tmp = format!("{}.wolfha-delta", target);
    if let Err(e) = replication::rolling::apply_delta(
        target,
        ops,
        &tmp,
        replication::rolling::BLOCK_SIZE,
    ) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Ok(meta) = std::fs::metadata(target) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let _ = std::fs::set_permissions(
            &tmp,
            std::fs::Permissions::from_mode(meta.permissions().mode()),
        );
        // chown needs the raw syscall — std has no stable API for it.
        if let Ok(c_tmp) = std::ffi::CString::new(tmp.as_str()) {
            // SAFETY: c_tmp is a NUL-terminated path we just created, and
            // uid/gid come from the file being replaced.
            unsafe {
                libc::chown(c_tmp.as_ptr(), meta.uid(), meta.gid());
            }
        }
    }
    std::fs::rename(&tmp, target).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("install: {}", e)
    })
}

/// Where a VM's OS disk lives on this node, and its config.
///
/// Both are needed together: replication carries the disk AND the
/// definition, because a replica that holds a perfect disk image but no
/// VM definition cannot start it on failover.
pub fn vm_disk_and_config(name: &str) -> Result<(String, crate::vms::manager::VmConfig), String> {
    let mgr = crate::vms::manager::VmManager::new();
    let cfg = mgr
        .get_vm(name)
        .ok_or_else(|| format!("VM '{}' not found on this node", name))?;
    let disk = mgr.os_disk_path_for(&cfg).to_string_lossy().to_string();
    Ok((disk, cfg))
}

/// This node's OVMF NVRAM file for a VM, when one exists. None for
/// SeaBIOS VMs and for OVMF VMs that have never been started (QEMU
/// creates the VARS copy on first boot).
pub fn vm_efivars_file(name: &str) -> Option<String> {
    let mgr = crate::vms::manager::VmManager::new();
    let cfg = mgr.get_vm(name)?;
    let p = mgr.efivars_path_for(&cfg);
    if p.exists() { Some(p.to_string_lossy().to_string()) } else { None }
}

/// Install a received OVMF NVRAM image where this node's copy of the VM
/// will look for it. Written to a temp alongside and renamed — a torn
/// VARS file is a VM that gets stuck in firmware.
pub fn vm_install_efivars(name: &str, staged: &str) -> Result<(), String> {
    let mgr = crate::vms::manager::VmManager::new();
    let cfg = mgr
        .get_vm(name)
        .ok_or_else(|| format!("VM '{}' not found on this node", name))?;
    let target = mgr.efivars_path_for(&cfg);
    if let Some(dir) = target.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create VM store dir: {}", e))?;
    }
    let tmp = target.with_extension("fd.tmp");
    std::fs::copy(staged, &tmp).map_err(|e| format!("stage NVRAM: {}", e))?;
    std::fs::rename(&tmp, &target).map_err(|e| format!("install NVRAM: {}", e))
}

/// Prepare a VM for incremental replication: attach the persistent dirty
/// bitmap that every later round encodes against.
///
/// Called when HA is enabled for a VM and again after any full seed. The
/// bitmap must exist BEFORE the seed is taken, or writes made during the
/// seed would be missed by the first incremental and the replica would
/// silently diverge from the moment it was created.
pub fn vm_begin_tracking(name: &str) -> Result<(), String> {
    let (disk, _) = vm_disk_and_config(name)?;
    let caps = replication::detect_vm_capabilities(&disk);
    if let Some(reason) = replication::vm_replication_blocked_reason(&caps) {
        return Err(reason);
    }
    let node = replication::qemu_bitmap::resolve_disk_node(name, &disk)?;
    match replication::qemu_bitmap::bitmap_state(name, &disk)? {
        replication::qemu_bitmap::BitmapState::Recording => Ok(()),
        replication::qemu_bitmap::BitmapState::Missing => {
            replication::qemu_bitmap::create_bitmap(name, &node)
        }
        // A bitmap that stopped recording, or one stored improperly by a
        // killed QEMU, cannot be trusted for an incremental — replace it
        // and let the caller re-seed.
        replication::qemu_bitmap::BitmapState::NotRecording
        | replication::qemu_bitmap::BitmapState::Inconsistent => {
            let _ = replication::qemu_bitmap::remove_bitmap(name, &node);
            replication::qemu_bitmap::create_bitmap(name, &node)
        }
    }
}

/// Stop tracking — called when HA is disabled so we do not leave a bitmap
/// growing inside the operator's disk image.
pub fn vm_end_tracking(name: &str) -> Result<(), String> {
    let (disk, _) = vm_disk_and_config(name)?;
    let node = replication::qemu_bitmap::resolve_disk_node(name, &disk)?;
    replication::qemu_bitmap::remove_bitmap(name, &node)
}

/// Write the primary's VM definition into this replica's VM store.
///
/// `running` is forced false whatever the primary sent: the definition
/// describes a VM that is running THERE, and a replica that records its
/// dormant copy as running would confuse both the UI and the duplicate
/// detection in the failover monitor.
pub fn vm_store_replica_config(
    name: &str,
    cfg: &crate::vms::manager::VmConfig,
) -> Result<(), String> {
    let mut cfg = cfg.clone();
    cfg.running = false;
    // The VM equivalent of stripping `lxc.start.auto` from a replica's
    // config (write_replica_config): `autostart_vms()` starts every
    // config with `auto_start` at machine boot, and a dormant standby
    // carrying the primary's flag would boot straight into a split brain.
    // Source: vms/manager.rs:3812-3836 autostart_vms() — `vm.auto_start
    // && !vm.running` is the whole gate.
    cfg.auto_start = false;
    // ISO paths are host files that were never replicated. QEMU refuses
    // to start when a configured -cdrom file is missing, so a promoted
    // copy carrying the primary's ISO path might not boot AT ALL on the
    // node that matters. Dropped: the copy boots from its disk, which is
    // the only thing a failover is for.
    cfg.iso_path = None;
    cfg.drivers_iso = None;
    // Never let a peer's payload rename the subject out from under us —
    // the file is keyed by the name WE are managing.
    cfg.name = name.to_string();
    let path = crate::vms::manager::VmManager::new().config_path_for(name);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("vm store dir: {}", e))?;
    }
    let json = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?;
    std::fs::write(&path, json)
        .map_err(|e| format!("write {}: {}", path.display(), e))
}

/// Delete a dormant VM replica: its disk image and its definition.
///
/// Refuses if the disk is missing rather than reporting a success that
/// removed nothing, and never touches a running VM (the caller checks,
/// and so does this).
pub fn vm_remove_replica(name: &str) -> Result<(), String> {
    if subject_is_running(SubjectKind::Vm, name) {
        return Err(format!("VM '{}' is running — refusing to delete it", name));
    }
    let mgr = crate::vms::manager::VmManager::new();
    let cfg_path = mgr.config_path_for(name);
    let disk = mgr
        .get_vm(name)
        .map(|c| mgr.os_disk_path_for(&c))
        .unwrap_or_else(|| cfg_path.with_extension("qcow2"));
    let mut removed_any = false;
    if disk.exists() {
        std::fs::remove_file(&disk)
            .map_err(|e| format!("delete {}: {}", disk.display(), e))?;
        removed_any = true;
    }
    if cfg_path.exists() {
        std::fs::remove_file(&cfg_path)
            .map_err(|e| format!("delete {}: {}", cfg_path.display(), e))?;
        removed_any = true;
    }
    if !removed_any {
        return Err(format!("no VM copy of '{}' found on this node to delete", name));
    }
    Ok(())
}

/// Take one incremental delta of a VM's disk into the staging directory.
///
/// Blocking. Returns the staged path and its size.
pub fn vm_take_delta(name: &str) -> Result<(String, u64), String> {
    let (disk, _) = vm_disk_and_config(name)?;
    let stage_dir = "/var/lib/wolfstack/wolfha";
    std::fs::create_dir_all(stage_dir).map_err(|e| format!("staging dir: {}", e))?;
    let out = format!("{}/vmdelta-{}.qcow2", stage_dir, uuid::Uuid::new_v4());
    // 6 hours: a backup job over a large, heavily-dirtied disk is slow,
    // and a timeout that fires mid-job leaves the round to retry from the
    // same bitmap rather than corrupting anything.
    replication::qemu_bitmap::take_incremental(name, &disk, &out, 6 * 60 * 60)?;
    let size = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    Ok((out, size))
}

/// Marker every "this VM copy needs a full re-seed" error carries, so the
/// primary can tell "re-seed and continue" apart from a genuinely failed
/// round. It travels inside HTTP error bodies between nodes — change it
/// and mixed-version clusters stop self-healing.
pub const VM_NEEDS_SEED: &str = "WOLFHA_VM_NEEDS_SEED";

/// Apply a received VM disk delta on this replica — but only when the
/// chain proves it fits.
///
/// An incremental contains just the clusters dirtied since the previous
/// round; applying one onto a disk that isn't byte-identical to that base
/// yields a copy that LOOKS healthy and is silently corrupt — the worst
/// failure an HA system can have. The chain makes the fit provable: the
/// delta carries the token its base holds (`prev`) and the token it
/// advances to (`next`); this copy applies only when its stored token is
/// exactly `prev`. Already at `next` = an idempotent retry, reported as
/// success. Anything else = diverged; the error carries [`VM_NEEDS_SEED`]
/// and the primary responds by shipping a full seed instead.
pub fn vm_apply_delta(
    name: &str,
    delta_path: &str,
    chain_prev: &str,
    chain_next: &str,
    efivars: Option<&str>,
) -> Result<(), String> {
    let entry_state = HaStore::load()
        .get(name)
        .map(|e| (e.kind, e.vm_chain.clone()));
    let Some((kind, my_token)) = entry_state else {
        return Err(format!(
            "{}: '{}' is not a WolfHA copy on this node",
            VM_NEEDS_SEED, name
        ));
    };
    if kind != SubjectKind::Vm {
        return Err(format!("'{}' is not a WolfHA-managed VM on this node", name));
    }
    if subject_is_running(SubjectKind::Vm, name) {
        return Err(format!(
            "VM '{}' is running here — refusing to write into a live disk image",
            name
        ));
    }
    if chain_prev.is_empty() || chain_next.is_empty() {
        return Err(format!(
            "{}: the delta arrived without chain tokens, so this copy cannot prove \
             the delta fits its disk — a full seed re-establishes the chain",
            VM_NEEDS_SEED
        ));
    }
    match my_token.as_deref() {
        // Retry of a delta this copy already holds — success, no rewrite.
        Some(t) if t == chain_next => return Ok(()),
        Some(t) if t == chain_prev => {}
        _ => {
            return Err(format!(
                "{}: this copy's disk state doesn't match the delta's base \
                 (it missed a round, or is an ex-primary with uncaptured writes) — \
                 it must be re-seeded, not patched",
                VM_NEEDS_SEED
            ));
        }
    }
    let (disk, _) = vm_disk_and_config(name)?;
    replication::qemu_bitmap::apply_delta(delta_path, &disk)?;
    // OVMF NVRAM refresh, when the primary sent one. After the disk on
    // purpose: a delta that failed must not leave firmware state from a
    // round the disk never got.
    if let Some(vars) = efivars {
        vm_install_efivars(name, vars)?;
    }
    // Advance the token only after the commit landed — a crash between
    // apply and save re-runs the same delta, which the `next` short-circuit
    // above absorbs... only if the apply completed; a HALF-applied commit
    // re-applies from `prev`, and qemu-img commit is a cluster-level
    // copy-down, so re-writing the same clusters is idempotent.
    let mut store = HaStore::load();
    if let Some(e) = store.get_mut(name) {
        e.vm_chain = Some(chain_next.to_string());
        store.save()?;
    }
    Ok(())
}

/// Persist a VM's `auto_start` flag — WolfHA takes a protected VM's boot
/// over exactly as it does a container's (`lxc_set_autostart`): the flag
/// is stripped when HA is enabled so `autostart_vms()` can't race the
/// boot-guard takeover check, and restored when HA is disabled.
///
/// Native sidecar JSON only — the whole VM HA path is native-QEMU (the
/// QMP socket in vms/manager.rs:4931 exists only for natively-started
/// VMs), so the Proxmox/libvirt arms of get_vm can't reach here.
// Source: vms/manager.rs:5159-5180 get_vm() reads the sidecar JSON at
// config_path_for(); vm_store_replica_config writes it the same way.
pub fn vm_set_autostart(name: &str, on: bool) -> Result<(), String> {
    let mgr = crate::vms::manager::VmManager::new();
    let path = mgr.config_path_for(name);
    // Straight off the sidecar, NOT get_vm(): get_vm overlays runtime
    // state (running, live VNC ports) onto what it returns, and writing
    // that back would persist runtime values into the config file.
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("VM '{}' has no config on this node: {}", name, e))?;
    let mut cfg: crate::vms::manager::VmConfig = serde_json::from_str(&content)
        .map_err(|e| format!("parse {}: {}", path.display(), e))?;
    if cfg.auto_start == on {
        return Ok(());
    }
    cfg.auto_start = on;
    let json = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("write {}: {}", path.display(), e))
}

/// Take a full seed image of a VM's disk into the staging directory.
/// Blocking. Returns (staged path, size, the VM's current definition).
///
/// Running VM → a QEMU `blockdev-backup sync: "full"` — copy-before-write,
/// so the image is a crash-consistent point-in-time copy and the guest
/// never pauses. Stopped VM → a plain file copy: nothing is writing, so
/// the file IS the point-in-time copy. Both are safe bases for the chain
/// because the dirty bitmap (attached before any seed is taken) records
/// every write from before the copy began.
pub fn vm_take_seed(name: &str) -> Result<(String, u64, crate::vms::manager::VmConfig), String> {
    let (disk, cfg) = vm_disk_and_config(name)?;
    let stage_dir = "/var/lib/wolfstack/wolfha";
    std::fs::create_dir_all(stage_dir).map_err(|e| format!("staging dir: {}", e))?;
    let out = format!("{}/vmseed-{}.qcow2", stage_dir, uuid::Uuid::new_v4());
    if subject_is_running(SubjectKind::Vm, name) {
        // Same 6-hour ceiling as vm_take_delta: a full copy of a large
        // disk is the slowest job this module runs.
        replication::qemu_bitmap::take_full(name, &disk, &out, 6 * 60 * 60)?;
    } else {
        std::fs::copy(&disk, &out)
            .map_err(|e| format!("copy {} to staging: {}", disk, e))?;
        // A file copy carries the source's persistent bitmap along inside
        // the qcow2. It describes the PRIMARY's write history, not this
        // copy's future — the replica must not inherit it. (A backup-made
        // seed is a fresh image and never has one.)
        replication::qemu_bitmap::offline_remove_bitmap(&out, name);
    }
    let size = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    Ok((out, size, cfg))
}

/// Install a VM seed on this node: the disk image moved into the VM
/// store, the definition written as a dormant replica, the HA entry
/// recorded with the seed's chain token. Refuses to clobber a VM of the
/// same name that is NOT a WolfHA copy — mirror of [`install_seed`]'s
/// guard for containers.
pub fn install_vm_seed(
    container: &str,
    archive: &str,
    cfg: &crate::vms::manager::VmConfig,
    primary: HaPeer,
    meta: Option<&HaMeta>,
    chain: &str,
    efivars: Option<&str>,
) -> Result<(), String> {
    if chain.is_empty() {
        return Err("a VM seed must carry its chain token".to_string());
    }
    let mgr = crate::vms::manager::VmManager::new();
    let store = HaStore::load();
    let existing_entry = store.get(container);
    if mgr.get_vm(container).is_some() || mgr.config_path_for(container).exists() {
        // A same-named VM exists here. Overwriting is only legitimate on
        // a copy WolfHA itself put here: a replica being re-seeded, or a
        // stale ex-primary being brought back into the chain (failback).
        let overwritable = matches!(
            existing_entry,
            Some(e) if e.kind == SubjectKind::Vm && (e.role == HaRole::Replica || e.stale)
        );
        if !overwritable {
            return Err(format!(
                "a VM named '{}' already exists on this node and is NOT a WolfHA copy — refusing to overwrite it",
                container
            ));
        }
        if subject_is_running(SubjectKind::Vm, container) {
            return Err(format!(
                "VM copy '{}' is running here — stop it before re-seeding",
                container
            ));
        }
    }
    // The disk lands where every later delta will look for it:
    // os_disk_path_for() of the stored definition. The definition keeps
    // the primary's storage_path so a promoted copy runs with the same
    // layout — the parent dir is created if this host doesn't have it.
    // Source: wolfha/mod.rs vm_disk_and_config() — the delta path resolves
    // the disk through get_vm + os_disk_path_for, so the seed must too.
    let disk = mgr.os_disk_path_for(cfg);
    if let Some(dir) = disk.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create VM store dir: {}", e))?;
    }
    let disk_str = disk.to_string_lossy().to_string();
    // rename() when staging and store share a filesystem (the default:
    // both under /var/lib/wolfstack), copy+remove across filesystems.
    if std::fs::rename(archive, &disk).is_err() {
        std::fs::copy(archive, &disk).map_err(|e| format!("install seed disk: {}", e))?;
        let _ = std::fs::remove_file(archive);
    }
    // Belt-and-braces: whatever route the seed took, the replica's copy
    // must not hold a bitmap. Absent = no-op.
    replication::qemu_bitmap::offline_remove_bitmap(&disk_str, container);
    if let Err(e) = vm_store_replica_config(container, cfg) {
        return Err(format!("seed disk installed but the VM definition failed: {}", e));
    }
    // After the definition is stored — vm_install_efivars resolves the
    // target path through it.
    if let Some(vars) = efivars {
        vm_install_efivars(container, vars)?;
    }

    let mut store = HaStore::load();
    store.remove(container);
    let mut entry = HaEntry {
        container: container.to_string(),
        kind: SubjectKind::Vm,
        role: HaRole::Replica,
        interval_minutes: 0,
        replicas: Vec::new(),
        primary: Some(primary),
        autostart_managed: false,
        last_sync: HashMap::new(),
        last_delta_at: now_unix(),
        stale: false,
        pending_vm_delta: None,
        vm_chain: Some(chain.to_string()),
        auto_failover: false,
        witness: String::new(),
        failover_after_secs: default_failover_after(),
        self_identity: None,
        zfs_datasets: Vec::new(),
    };
    if let Some(m) = meta {
        m.apply_to(&mut entry);
    }
    store.entries.push(entry);
    store.save()
}

/// Everything a full VM seed carries besides the image itself.
pub struct VmSeedPayload<'a> {
    /// Staged qcow2 on the sending primary.
    pub seed_path: &'a str,
    /// Serialized [`crate::vms::manager::VmConfig`] of the subject.
    pub vm_config_json: &'a str,
    /// Chain token the receiver stores — see [`HaEntry::vm_chain`].
    pub chain: &'a str,
    /// The sender's own peer identity (the receiver's `primary`).
    pub primary: &'a HaPeer,
    /// Serialized [`HaMeta`] so the standby learns settings immediately.
    pub ha_meta_json: &'a str,
}

/// Ship a staged full VM seed to one replica node. Used by `wolfha_enable`
/// for the initial seeds and by the sync loop to re-seed a replica that
/// refused a delta with [`VM_NEEDS_SEED`].
pub async fn vm_seed_replica(
    container: &str,
    peer: &HaPeer,
    secret: &str,
    payload: &VmSeedPayload<'_>,
) -> Result<(), String> {
    let VmSeedPayload { seed_path, vm_config_json, chain, primary, ha_meta_json } = *payload;
    let client = &*crate::api::API_HTTP_CLIENT;
    let primary_json = serde_json::to_string(primary).unwrap_or_default();
    // OVMF NVRAM rides along whenever the VM has one — a promoted copy
    // with fresh VARS has lost its boot entries.
    let efivars = vm_efivars_file(container);
    let urls = crate::api::build_node_urls(&peer.address, peer.port, "/api/wolfha/receive-seed");
    let mut last_err = String::new();
    for url in &urls {
        // Fresh streaming part per attempt — the image uploads straight
        // from disk, never through memory (the wolfstack-3 lesson).
        let part = match stream_archive_part(seed_path).await {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        let mut form = reqwest::multipart::Form::new()
            .text("container", container.to_string())
            .text("primary", primary_json.clone())
            .text("ha_meta", ha_meta_json.to_string())
            .text("vm_config", vm_config_json.to_string())
            .text("chain", chain.to_string())
            .part("archive", part.file_name("seed.qcow2"));
        if let Some(vars) = &efivars {
            match stream_archive_part(vars).await {
                Ok(p) => form = form.part("efivars", p.file_name("VARS.fd")),
                Err(e) => return Err(format!("VM NVRAM vanished mid-send: {}", e)),
            }
        }
        match client.post(url)
            .peer_auth(secret)
            .timeout(std::time::Duration::from_secs(3600))
            .multipart(form)
            .send().await
        {
            Ok(r) if r.status().is_success() => return Ok(()),
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                last_err = format!("{}: HTTP {} {}", url, status, body.chars().take(300).collect::<String>());
            }
            Err(e) => last_err = format!("{}: {}", url, e),
        }
    }
    Err(format!("VM seed upload failed: {}", last_err))
}

/// A full seed staged once per sync round and reused for every replica
/// that needs it (taking one per replica would double-read the disk for
/// nothing — the image is identical).
pub struct StagedVmSeed {
    pub path: String,
    pub size: u64,
    pub cfg_json: String,
    /// Chain token the seed hands its receiver — see [`HaEntry::vm_chain`].
    pub token: String,
}

/// Re-seed one replica during a sync round: stage a full image (once per
/// round), ship it, and record the outcome exactly as a delta ship would.
///
/// The token handed over is chosen so the NEXT delta fits: the pending
/// delta's token when one is outstanding (a seed taken now contains
/// everything the pending delta contains, so the receiver is marked as
/// having applied it), else the primary's current chain token, else — a
/// broken chain (lost delta, fresh promotion) — a newly minted token that
/// becomes the primary's chain, which every OTHER replica will fail to
/// match and be re-seeded against in turn.
async fn vm_reseed_replica_round(
    container: &str,
    peer: &HaPeer,
    secret: &str,
    staged: &mut Option<StagedVmSeed>,
) -> HaSyncStatus {
    let fail = |msg: String| HaSyncStatus {
        at: now_unix(), ok: false, message: msg, files_sent: 0, bytes_sent: 0,
    };
    if staged.is_none() {
        let c = container.to_string();
        let taken = tokio::task::spawn_blocking(move || vm_take_seed(&c)).await;
        let (path, size, cfg) = match taken {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return fail(format!("re-seed needed but the full image failed: {}", e)),
            Err(e) => return fail(format!("re-seed task: {}", e)),
        };
        let cfg_json = match serde_json::to_string(&cfg) {
            Ok(j) => j,
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                return fail(format!("re-seed: VM definition would not serialize: {}", e));
            }
        };
        let mut store = HaStore::load();
        let Some(e) = store.get_mut(container) else {
            let _ = std::fs::remove_file(&path);
            return fail(format!("'{}' vanished from the HA store mid-round", container));
        };
        let token = match (&e.pending_vm_delta, &e.vm_chain) {
            (Some(p), _) if !p.token.is_empty() => p.token.clone(),
            (_, Some(c)) => c.clone(),
            _ => {
                let minted = uuid::Uuid::new_v4().to_string();
                e.vm_chain = Some(minted.clone());
                if let Err(err) = store.save() {
                    let _ = std::fs::remove_file(&path);
                    return fail(format!("re-seed: could not persist the new chain: {}", err));
                }
                minted
            }
        };
        *staged = Some(StagedVmSeed { path, size, cfg_json, token });
    }
    let seed = staged.as_ref().expect("staged just set");

    let (self_peer, ha_meta_json) = {
        let store = HaStore::load();
        let Some(e) = store.get(container).filter(|e| e.role == HaRole::Primary) else {
            return fail(format!("'{}' is no longer a primary here — re-seed abandoned", container));
        };
        let Some(me) = e.self_identity.clone() else {
            return fail("re-seed needs this node's own peer identity and the HA entry \
                         has none — disable and re-enable HA for this VM".to_string());
        };
        (me, serde_json::to_string(&HaMeta::from_entry(e)).unwrap_or_default())
    };
    match vm_seed_replica(
        container, peer, secret,
        &VmSeedPayload {
            seed_path: &seed.path,
            vm_config_json: &seed.cfg_json,
            chain: &seed.token,
            primary: &self_peer,
            ha_meta_json: &ha_meta_json,
        },
    ).await {
        Ok(()) => {
            // The seed supersedes any outstanding delta for this replica —
            // it was taken later, so its image already contains those
            // blocks. Recorded durably for the same reason applied_by
            // exists at all.
            let mut store = HaStore::load();
            if let Some(e) = store.get_mut(container)
                && let Some(pd) = e.pending_vm_delta.as_mut()
                && !pd.applied_by.contains(&peer.node_id)
            {
                pd.applied_by.push(peer.node_id.clone());
                let _ = store.save();
            }
            HaSyncStatus {
                at: now_unix(),
                ok: true,
                message: format!("standby re-seeded with a full disk image ({})", human_bytes(seed.size)),
                files_sent: 1,
                bytes_sent: seed.size,
            }
        }
        Err(e) => fail(format!("re-seed failed: {}", e)),
    }
}

/// Apply a bundle of per-file block deltas to this replica's rootfs.
///
/// Each file is reconstructed into a temporary alongside its target and
/// renamed over it only once complete and fsynced. A partial write must
/// never be left where the file was: a replica exists to be promoted, and
/// a half-reconstructed database is worse than an out-of-date one.
///
/// Every path is checked with [`is_safe_rel_path`] before use — this
/// bundle came off the network, and a `../` in a path would otherwise let
/// a peer write outside the container.
pub fn apply_block_deltas(container: &str, bundle_path: &str) -> Result<usize, String> {
    let base = crate::containers::lxc_base_dir(container);
    let rootfs = format!("{}/{}/rootfs", base, container);
    let blob = std::fs::read(bundle_path)
        .map_err(|e| format!("read block delta bundle: {}", e))?;
    let items = replication::rolling::unpack_file_deltas(&blob)?;

    let mut applied = 0usize;
    for item in items {
        if !is_safe_rel_path(&item.path) {
            return Err(format!("block delta contains an unsafe path: {}", item.path));
        }
        let target = format!("{}/{}", rootfs, item.path);
        if !std::path::Path::new(&target).is_file() {
            return Err(format!(
                "block delta references {} which this replica does not have — the copies \
                 have diverged and a full resync is required",
                item.path
            ));
        }
        install_reconstructed_file(&target, &item.ops)
            .map_err(|e| format!("apply {}: {}", item.path, e))?;
        applied += 1;
    }
    Ok(applied)
}

/// Agree a replication driver with a replica.
///
/// Never fails: a peer that cannot be probed — older build, offline
/// endpoint, malformed reply — is treated as supporting only the floor,
/// which is exactly the behaviour that shipped before drivers existed.
/// Returning a driver rather than an error is deliberate; a sync must not
/// be abandoned because a capability probe did not answer.
async fn negotiate_driver(
    rootfs: &str,
    container: &str,
    peer: &HaPeer,
    secret: &str,
    client: &reqwest::Client,
) -> replication::DriverKind {
    let local = {
        let r = rootfs.to_string();
        tokio::task::spawn_blocking(move || replication::detect_container_capabilities(&r))
            .await
            .unwrap_or_else(|_| replication::ReplicationCapabilities::floor())
    };
    let urls = crate::api::build_node_urls(
        &peer.address,
        peer.port,
        &format!("/api/wolfha/capabilities?container={}", container),
    );
    for url in &urls {
        if let Ok(r) = client
            .get(url)
            .peer_auth(secret)
            .timeout(std::time::Duration::from_secs(20))
            .send()
            .await
            && r.status().is_success()
            && let Ok(remote) = r.json::<replication::ReplicationCapabilities>().await
        {
            return replication::negotiate(&local, &remote);
        }
    }
    replication::DriverKind::FileManifest
}

/// Fetch the replica's block signatures for `paths`.
async fn fetch_signatures(
    container: &str,
    peer: &HaPeer,
    secret: &str,
    client: &reqwest::Client,
    paths: &[String],
) -> Result<std::collections::HashMap<String, Vec<u8>>, String> {
    use base64::Engine;
    let urls = crate::api::build_node_urls(&peer.address, peer.port, "/api/wolfha/signatures");
    let body = serde_json::json!({ "container": container, "paths": paths });
    let mut last = String::new();
    for url in &urls {
        match client
            .post(url)
            .peer_auth(secret)
            // Signatures mean hashing every byte of the replica's copy of
            // these files, which for tens of gigabytes is not quick.
            .timeout(std::time::Duration::from_secs(900))
            .json(&body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                let v: serde_json::Value =
                    r.json().await.map_err(|e| format!("bad signature reply: {}", e))?;
                let obj = v.as_object().ok_or("signature reply was not an object")?;
                let mut out = std::collections::HashMap::new();
                for (k, val) in obj {
                    if let Some(s) = val.as_str()
                        && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(s)
                    {
                        out.insert(k.clone(), bytes);
                    }
                }
                return Ok(out);
            }
            Ok(r) => {
                last = format!("{}: HTTP {}", url, r.status());
            }
            Err(e) => last = format!("{}: {}", url, e),
        }
    }
    Err(last)
}

/// Encode block deltas for `paths` against the replica's signatures.
///
/// Returns the staged blob (if any) and the paths that must be sent whole
/// after all — a file whose signature was missing or unparseable, or whose
/// delta turned out no smaller than the file, falls back rather than
/// wasting the round.
///
/// Blocking: it hashes and rolls over every byte of each file.
fn build_block_deltas(
    rootfs: &str,
    paths: &[String],
    sigs: &std::collections::HashMap<String, Vec<u8>>,
) -> (Option<String>, Vec<String>) {
    let mut items = Vec::new();
    let mut fell_back = Vec::new();
    for rel in paths {
        let Some(raw) = sigs.get(rel) else {
            fell_back.push(rel.clone());
            continue;
        };
        let sig = match replication::rolling::decode_signatures(raw) {
            Ok(s) => s,
            Err(_) => {
                fell_back.push(rel.clone());
                continue;
            }
        };
        let full = format!("{}/{}", rootfs, rel);
        let file_len = std::fs::metadata(&full).map(|m| m.len()).unwrap_or(0);
        match replication::rolling::compute_delta(&full, &sig) {
            Ok(ops) => {
                // A delta bigger than the file itself is possible when a
                // file was rewritten wholesale; sending it would be strictly
                // worse than the tar path.
                let encoded = replication::rolling::encode_delta(&ops).len() as u64;
                if encoded >= file_len {
                    fell_back.push(rel.clone());
                } else {
                    items.push(replication::rolling::FileDelta { path: rel.clone(), ops });
                }
            }
            Err(_) => fell_back.push(rel.clone()),
        }
    }
    if items.is_empty() {
        return (None, fell_back);
    }
    let blob = replication::rolling::pack_file_deltas(&items);
    let stage_dir = "/var/lib/wolfstack/wolfha";
    if std::fs::create_dir_all(stage_dir).is_err() {
        // Staging is unavailable — fall the whole set back rather than
        // lose the changes.
        fell_back.extend(items.into_iter().map(|i| i.path));
        return (None, fell_back);
    }
    let path = format!("{}/blocks-{}.bin", stage_dir, uuid::Uuid::new_v4());
    if std::fs::write(&path, &blob).is_err() {
        fell_back.extend(items.into_iter().map(|i| i.path));
        return (None, fell_back);
    }
    (Some(path), fell_back)
}

pub async fn sync_one_replica(
    container: &str,
    peer: &HaPeer,
    secret: &str,
) -> HaSyncStatus {
    let started = now_unix();
    match sync_one_replica_inner(container, peer, secret).await {
        Ok((files, bytes, how)) => HaSyncStatus {
            at: started,
            ok: true,
            // Name the method used. "in sync" alone cannot tell an
            // operator whether this replica is crash-consistent, which is
            // the difference between a standby they can fail a database
            // onto and one they cannot.
            message: if files == 0 {
                format!("in sync — no changes ({})", how)
            } else {
                format!("{} files updated ({})", files, how)
            },
            files_sent: files,
            bytes_sent: bytes,
        },
        Err(e) => HaSyncStatus {
            at: started,
            ok: false,
            message: e,
            files_sent: 0,
            bytes_sent: 0,
        },
    }
}

/// Open a consistent view of the rootfs, run the round against it, and
/// tear the view down whatever happens.
///
/// The snapshot must be destroyed on EVERY exit, including the error
/// paths — a leaked snapshot pins the blocks it references, and enough of
/// them fills the pool. That is why the round's body lives in its own
/// function rather than being guarded by scattered cleanup calls.
async fn sync_one_replica_inner(
    container: &str,
    peer: &HaPeer,
    secret: &str,
) -> Result<(u64, u64, String), String> {
    let base = crate::containers::lxc_base_dir(container);
    let rootfs = format!("{}/{}/rootfs", base, container);
    let now = now_unix();

    let (session, read_root) = {
        let (r, c) = (rootfs.clone(), container.to_string());
        tokio::task::spawn_blocking(move || {
            let source = replication::detect_consistency_source(&r);
            let sess = replication::snapshot::SnapshotSession::open(&source, &r, &c, now);
            let path = sess.read_path().to_string();
            (sess, path)
        })
        .await
        .map_err(|e| format!("snapshot task: {}", e))?
    };
    let consistency = if session.is_snapshot() {
        replication::detect_consistency_source(&rootfs).label()
    } else {
        replication::ConsistencySource::Live.label()
    };

    let result = sync_one_replica_from(container, peer, secret, &rootfs, &read_root).await;

    if let Ok(Err(e)) = tokio::task::spawn_blocking(move || session.close()).await {
        // Not fatal to the round — the data already shipped — but it must
        // be visible, because the failure mode is a pool that slowly fills.
        tracing::warn!(
            "wolfha[{}]: could not remove the replication snapshot: {}",
            container, e
        );
    }
    result.map(|(files, bytes, driver)| {
        (files, bytes, format!("{}, {}", driver.label(), consistency))
    })
}

/// One replication round, reading files from `read_root`.
///
/// `rootfs` is the live path (used for capability detection and for the
/// container's config), `read_root` is what the round actually walks —
/// the same thing when no snapshot could be taken.
async fn sync_one_replica_from(
    container: &str,
    peer: &HaPeer,
    secret: &str,
    rootfs: &str,
    read_root: &str,
) -> Result<(u64, u64, replication::DriverKind), String> {
    let client = &*crate::api::API_HTTP_CLIENT;
    let base = crate::containers::lxc_base_dir(container);
    let config_path = format!("{}/{}/config", base, container);

    // 1. Remote manifest.
    let manifest_urls = crate::api::build_node_urls(
        &peer.address, peer.port,
        &format!("/api/wolfha/manifest?container={}", container),
    );
    let mut remote: Option<Vec<ManifestEntry>> = None;
    let mut last_err = String::new();
    for url in &manifest_urls {
        match client.get(url)
            .peer_auth(secret)
            .timeout(std::time::Duration::from_secs(120))
            .send().await
        {
            Ok(r) if r.status().is_success() => {
                match r.json::<Vec<ManifestEntry>>().await {
                    Ok(m) => { remote = Some(m); break; }
                    Err(e) => { last_err = format!("bad manifest from {}: {}", url, e); }
                }
            }
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                last_err = format!("{}: HTTP {} {}", url, status, body.chars().take(200).collect::<String>());
            }
            Err(e) => { last_err = format!("{}: {}", url, e); }
        }
    }
    let remote = remote.ok_or_else(|| format!("replica manifest unavailable: {}", last_err))?;

    // 2. Local manifest + diff (fs walk off the async runtime).
    let rootfs_c = read_root.to_string();
    let local = tokio::task::spawn_blocking(move || build_manifest(&rootfs_c))
        .await
        .map_err(|e| format!("manifest task: {}", e))??;
    let (changed, deletions) = manifest_diff(&local, &remote);

    // 2b. Agree a replication driver with the replica. A peer that
    // predates the capabilities endpoint 404s and we fall back to the
    // floor, which is byte-for-byte the behaviour before drivers existed —
    // so a half-upgraded cluster keeps replicating instead of failing.
    let driver = negotiate_driver(rootfs, container, peer, secret, client).await;

    // Files big enough to be worth delta-encoding. Below the threshold the
    // signature exchange costs more than the bytes it saves, so a rootfs of
    // small files behaves exactly as it always has.
    let (delta_paths, mut changed): (Vec<String>, Vec<String>) =
        if driver >= replication::DriverKind::RollingDelta {
            changed.iter().cloned().partition(|p| {
                std::fs::metadata(format!("{}/{}", read_root, p))
                    .map(|m| m.is_file() && m.len() >= replication::rolling::MIN_DELTA_SIZE)
                    .unwrap_or(false)
            })
        } else {
            (Vec::new(), changed)
        };

    // Ask the replica what it already holds for those files, then encode
    // only the blocks that differ. Anything the replica cannot describe
    // (missing, unreadable, kind mismatch) drops back to being tarred.
    let mut block_delta_path: Option<String> = None;
    if !delta_paths.is_empty() {
        match fetch_signatures(container, peer, secret, client, &delta_paths).await {
            Ok(sigs) => {
                let rootfs_c = read_root.to_string();
                let paths_c = delta_paths.clone();
                let (blob, fell_back) = tokio::task::spawn_blocking(move || {
                    build_block_deltas(&rootfs_c, &paths_c, &sigs)
                })
                .await
                .map_err(|e| format!("delta task: {}", e))?;
                changed.extend(fell_back);
                block_delta_path = blob;
            }
            Err(e) => {
                // Not fatal — the round still completes by sending the
                // files whole. Logged so a persistently failing probe does
                // not silently cost bandwidth forever.
                tracing::warn!(
                    "wolfha[{}]: signature exchange with {} failed ({}) — sending {} file(s) whole",
                    container, peer.address, e, delta_paths.len()
                );
                changed.extend(delta_paths.iter().cloned());
            }
        }
    }
    let changed = changed;

    // A quiet round still ships a metadata-only heartbeat (no archive):
    // settings changes must reach standbys without waiting for a file to
    // change, and last_delta_at must keep advancing on an IDLE container
    // or the auto-failover freshness gate would wrongly refuse it.
    //
    // The archive stays ON DISK and is streamed from there — the old
    // read-into-RAM + clone-per-attempt shipped the whole delta through
    // memory, which for a big container's first delta round was an OOM
    // risk on the primary (legolas/wolfstack-3, 2026-08-11 — same round
    // as the seed fix in api::wolfha_enable).
    let archive_on_disk: Option<String> = if changed.is_empty() && deletions.is_empty() {
        None
    } else {
        // 3. Tar the changed paths.
        let stage_dir = "/var/lib/wolfstack/wolfha";
        std::fs::create_dir_all(stage_dir).map_err(|e| format!("staging dir: {}", e))?;
        let uniq = uuid::Uuid::new_v4();
        let list_file = format!("{}/delta-{}.list", stage_dir, uniq);
        let archive = format!("{}/delta-{}.tar.gz", stage_dir, uniq);
        {
            let mut buf: Vec<u8> = Vec::new();
            for p in &changed {
                buf.extend_from_slice(p.as_bytes());
                buf.push(0);
            }
            std::fs::write(&list_file, buf).map_err(|e| format!("write list: {}", e))?;
        }
        let (rootfs_c, list_c, archive_c) =
            (read_root.to_string(), list_file.clone(), archive.clone());
        let tar_res = tokio::task::spawn_blocking(move || tar_paths(&rootfs_c, &list_c, &archive_c))
            .await
            .map_err(|e| format!("tar task: {}", e));
        let _ = std::fs::remove_file(&list_file);
        if let Err(e) = tar_res.and_then(|r| r) {
            let _ = std::fs::remove_file(&archive);
            return Err(e);
        }
        Some(archive)
    };
    let file_bytes = |p: Option<&str>| -> u64 {
        p.and_then(|p| std::fs::metadata(p).ok()).map(|m| m.len()).unwrap_or(0)
    };
    let bytes_len =
        file_bytes(archive_on_disk.as_deref()) + file_bytes(block_delta_path.as_deref());
    let delta_file_count = delta_paths.len().saturating_sub(
        // Any that fell back were moved into `changed` and are counted there.
        delta_paths.iter().filter(|p| changed.contains(p)).count(),
    );
    let config = std::fs::read_to_string(&config_path).unwrap_or_default();
    // Every exit path from here must clear BOTH staged files or a failing
    // replica leaks a delta per round into the staging directory.
    let cleanup = |a: Option<&str>, b: Option<&str>| {
        if let Some(p) = a { let _ = std::fs::remove_file(p); }
        if let Some(p) = b { let _ = std::fs::remove_file(p); }
    };

    // 4. Ship it — settings metadata rides along so standbys always
    // know the current priority order / witness / timings.
    let ha_meta_json = HaStore::load().get(container)
        .filter(|e| e.role == HaRole::Primary)
        .map(|e| serde_json::to_string(&HaMeta::from_entry(e)).unwrap_or_default())
        .unwrap_or_default();
    let apply_urls = crate::api::build_node_urls(&peer.address, peer.port, "/api/wolfha/apply-delta");
    let deletions_json = serde_json::to_string(&deletions).unwrap_or_else(|_| "[]".to_string());
    let mut last_err = String::new();
    for url in &apply_urls {
        let mut form = reqwest::multipart::Form::new()
            .text("container", container.to_string())
            .text("deletions", deletions_json.clone())
            .text("config", config.clone())
            .text("ha_meta", ha_meta_json.clone());
        form = form.text("driver", format!("{:?}", driver));
        if let Some(path) = archive_on_disk.as_deref() {
            // Fresh streaming part per attempt — a stream can't be
            // cloned the way the old in-RAM bytes could.
            match stream_archive_part(path).await {
                Ok(part) => form = form.part("archive", part.file_name("delta.tar.gz")),
                Err(e) => {
                    cleanup(archive_on_disk.as_deref(), block_delta_path.as_deref());
                    return Err(e);
                }
            }
        }
        if let Some(path) = block_delta_path.as_deref() {
            match stream_archive_part(path).await {
                Ok(part) => form = form.part("blockdelta", part.file_name("delta.blocks")),
                Err(e) => {
                    cleanup(archive_on_disk.as_deref(), block_delta_path.as_deref());
                    return Err(e);
                }
            }
        }
        match client.post(url)
            .peer_auth(secret)
            .timeout(std::time::Duration::from_secs(1800))
            .multipart(form)
            .send().await
        {
            Ok(r) if r.status().is_success() => {
                cleanup(archive_on_disk.as_deref(), block_delta_path.as_deref());
                return Ok(((changed.len() + delta_file_count) as u64, bytes_len, driver));
            }
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                last_err = format!("{}: HTTP {} {}", url, status, body.chars().take(300).collect::<String>());
            }
            Err(e) => { last_err = format!("{}: {}", url, e); }
        }
    }
    cleanup(archive_on_disk.as_deref(), block_delta_path.as_deref());
    Err(format!("delta upload failed: {}", last_err))
}

/// Build a streaming multipart part from a staged archive — the file is
/// read from disk as it uploads instead of being loaded into memory
/// (a 43 GB rootfs seed read into RAM is how wolfstack-3 nearly went
/// down on 2026-08-11). `stream_with_length` so the request carries
/// Content-Length — the receiver's progress and limits see a size, not
/// chunked-unknown.
pub async fn stream_archive_part(path: &str) -> Result<reqwest::multipart::Part, String> {
    let file = tokio::fs::File::open(path).await
        .map_err(|e| format!("open archive {}: {}", path, e))?;
    let len = file.metadata().await
        .map_err(|e| format!("archive metadata {}: {}", path, e))?
        .len();
    let stream = tokio_util::io::ReaderStream::new(file);
    Ok(reqwest::multipart::Part::stream_with_length(reqwest::Body::wrap_stream(stream), len))
}

/// Run a sync round for one primary entry: every replica, sequentially
/// (replicas share the primary's disk bandwidth; parallel rounds
/// double-read the rootfs for no wall-clock win on spinning disks).
/// Records per-replica status in the store.
pub async fn sync_container_now(container: &str) -> Result<(), String> {
    let store = HaStore::load();
    let entry = store.get(container)
        .ok_or_else(|| format!("'{}' is not WolfHA-managed here", container))?;
    if entry.role != HaRole::Primary {
        return Err(format!("'{}' is a replica on this node — syncs run on the primary", container));
    }
    if entry.stale {
        return Err(format!("'{}' is stale here (a replica was promoted) — it receives syncs now, it doesn't send them", container));
    }
    let peers = entry.replicas.clone();
    let kind = entry.kind;
    let secret = crate::auth::load_cluster_secret();

    // A VM's delta is taken ONCE per round and shipped to every replica.
    // Taking one per replica would hand the second replica an empty delta:
    // `bitmap-mode: on-success` clears the copied bits when the backup
    // job succeeds, so by the time the second call ran there would be
    // nothing left to copy and that replica would silently fall behind
    // while reporting success.
    // An outstanding delta is retried before any new one is taken — see
    // `pending_vm_delta`. Its blocks are gone from the bitmap, so it is the
    // only copy of those changes that exists.
    let recorded = entry.pending_vm_delta.clone();
    let pending = recorded.clone()
        .filter(|p| std::path::Path::new(&p.path).exists());
    // The record survived but the staged file did not (a cleaned /var, a
    // full disk, a reboot of a tmpfs staging dir). Those blocks are no
    // longer in the bitmap either, so every replica that had not applied
    // it is now behind by changes NO future delta will carry. Say so
    // loudly and mark them: a replica silently diverging while reporting
    // success is the worst failure this system can have.
    if let Some(lost) = recorded.as_ref()
        && pending.is_none()
    {
        let behind: Vec<String> = peers.iter()
            .filter(|r| !peer_is_local(r) && !lost.applied_by.contains(&r.node_id))
            .map(|r| r.node_id.clone())
            .collect();
        let mut st = HaStore::load();
        if let Some(e) = st.get_mut(container) {
            e.pending_vm_delta = None;
            // The lost blocks exist nowhere but this primary's disk, so
            // NO standby's state can be trusted against the chain any
            // more — breaking it forces every one of them through the
            // automatic full re-seed, which is the only thing that can
            // carry those blocks now.
            e.vm_chain = None;
            for id in &behind {
                e.last_sync.insert(id.clone(), HaSyncStatus {
                    at: now_unix(),
                    ok: false,
                    message: "staged disk delta was lost before this replica applied it — \
                              it is missing changes no later delta will contain. Every \
                              standby will be re-seeded with a full image on the coming \
                              rounds.".to_string(),
                    files_sent: 0,
                    bytes_sent: 0,
                });
            }
            let _ = st.save();
        }
        if !behind.is_empty() {
            tracing::error!(
                "wolfha[{}]: staged delta {} vanished before {} replica(s) applied it — \
                 the chain is broken; every standby will be re-seeded automatically",
                container, lost.path, behind.len()
            );
        }
    }
    let vm_delta: Option<replication::qemu_bitmap::PendingDelta> = if kind == SubjectKind::Vm {
        match pending {
            Some(p) => {
                tracing::info!(
                    "wolfha[{}]: retrying a disk delta {} replica(s) have not applied yet",
                    container,
                    peers.iter().filter(|r| !p.applied_by.contains(&r.node_id)).count(),
                );
                Some(p)
            }
            // A stopped VM writes nothing, so there is nothing new to
            // take (and no QMP monitor to take it through). The round
            // still visits every replica below: quiet status for the
            // healthy ones, re-seed (file copy — valid on a stopped
            // disk) for any that demanded one.
            None if !subject_is_running(SubjectKind::Vm, container) => None,
            None => {
                let c = container.to_string();
                match tokio::task::spawn_blocking(move || vm_take_delta(&c)).await {
                    Ok(Ok((path, _size))) => {
                        let p = replication::qemu_bitmap::PendingDelta {
                            path,
                            taken_at: now_unix(),
                            applied_by: Vec::new(),
                            // The token this delta advances the chain to —
                            // replicas store it on apply; the primary's
                            // vm_chain advances to it once ALL have.
                            token: uuid::Uuid::new_v4().to_string(),
                        };
                        // Record it BEFORE shipping: a crash between the
                        // backup and the first upload must not lose track
                        // of a delta the bitmap no longer describes.
                        let mut st = HaStore::load();
                        if let Some(e) = st.get_mut(container) {
                            e.pending_vm_delta = Some(p.clone());
                            let _ = st.save();
                        }
                        Some(p)
                    }
                    Ok(Err(e)) => return Err(format!("could not take a disk delta: {}", e)),
                    Err(e) => return Err(format!("delta task: {}", e)),
                }
            }
        }
    } else {
        None
    };

    // A Proxmox container's round is one atomic snapshot of every volume,
    // shipped to each standby as an incremental from whatever base that
    // standby holds; pruned once every standby has confirmed it.
    let pve_round: Option<PveRound> = if kind == SubjectKind::PveContainer {
        let c = container.to_string();
        match tokio::task::spawn_blocking(move || pve_take_snapshot(&c)).await {
            Ok(Ok(r)) => Some(r),
            Ok(Err(e)) => return Err(format!("could not snapshot the container's volumes: {}", e)),
            Err(e) => return Err(format!("snapshot task: {}", e)),
        }
    } else {
        None
    };
    let mut pve_all_ok = true;

    // One full seed image per round at most, shared by every replica that
    // turns out to need one; staged lazily, cleaned up after the loop.
    let mut staged_seed: Option<StagedVmSeed> = None;
    for peer in &peers {
        // Defensive: never sync to ourselves — an aliased self-entry can
        // survive in stored replica lists from before the promote filter.
        if peer_is_local(peer) {
            tracing::debug!("wolfha: skipping self-aliased replica entry {} for '{}'", peer.node_id, container);
            continue;
        }
        let status = match &vm_delta {
            Some(p) if p.applied_by.contains(&peer.node_id) => {
                // Already has this delta from an earlier round; nothing to
                // send until a new one is taken.
                HaSyncStatus {
                    at: now_unix(),
                    ok: true,
                    message: "already up to date with the current delta".to_string(),
                    files_sent: 0,
                    bytes_sent: 0,
                }
            }
            Some(p) => {
                // prev = the token every caught-up replica holds NOW.
                // An empty prev (broken chain) makes the replica refuse
                // and routes it through the re-seed below — deliberate.
                let chain_prev = HaStore::load().get(container)
                    .and_then(|e| e.vm_chain.clone())
                    .unwrap_or_default();
                let mut st = sync_vm_replica(container, peer, &secret, &p.path, &chain_prev, &p.token).await;
                if !st.ok && st.message.contains(VM_NEEDS_SEED) {
                    // The replica proved the delta doesn't fit its disk
                    // (divergence, a wiped copy, a broken chain). The
                    // repair is never "apply anyway" — it is a full image.
                    st = vm_reseed_replica_round(container, peer, &secret, &mut staged_seed).await;
                }
                if st.ok {
                    // Durably record WHICH replica has it, so a later
                    // failure cannot cause this delta to be dropped while
                    // another replica still needs it. (A successful
                    // re-seed recorded itself already — this is then a
                    // no-op thanks to the contains() check.)
                    let mut store = HaStore::load();
                    if let Some(e) = store.get_mut(container)
                        && let Some(pd) = e.pending_vm_delta.as_mut()
                        && !pd.applied_by.contains(&peer.node_id)
                    {
                        pd.applied_by.push(peer.node_id.clone());
                        let _ = store.save();
                    }
                }
                st
            }
            // VM with nothing staged: the VM is stopped (a running VM
            // always has a delta taken above). Heal any standby that
            // demanded a seed on an earlier round — a stopped disk copies
            // cleanly — and give the rest an honest quiet status.
            None if kind == SubjectKind::Vm => {
                let needs_seed = {
                    let store = HaStore::load();
                    store.get(container).map(|e| {
                        e.vm_chain.is_none()
                            || e.last_sync.get(&peer.node_id)
                                .map(|s| !s.ok && s.message.contains(VM_NEEDS_SEED))
                                .unwrap_or(false)
                    }).unwrap_or(false)
                };
                if needs_seed {
                    vm_reseed_replica_round(container, peer, &secret, &mut staged_seed).await
                } else {
                    HaSyncStatus {
                        at: now_unix(),
                        ok: true,
                        message: "VM is stopped — the standby holds its last delivered state; \
                                  deltas resume when it starts".to_string(),
                        files_sent: 0,
                        bytes_sent: 0,
                    }
                }
            }
            None if kind == SubjectKind::PveContainer => {
                let round = pve_round.as_ref().expect("a Proxmox container round was snapshotted above");
                let st = pve_ship_round(container, peer, &secret, round).await;
                pve_all_ok &= st.ok;
                st
            }
            None => sync_one_replica(container, peer, &secret).await,
        };
        let mut store = HaStore::load();
        let previous_ok = store.get(container)
            .and_then(|e| e.last_sync.get(&peer.node_id))
            .map(|s| s.ok);
        if let Some(e) = store.get_mut(container) {
            e.last_sync.insert(peer.node_id.clone(), status.clone());
            let _ = store.save();
        }
        if !status.ok {
            tracing::warn!("wolfha: sync of '{}' to {} failed: {}", container, peer.node_id, status.message);
        }
        // Alert on the TRANSITION, not every round: a replica that stops
        // receiving deltas is silently ageing your failover point — the
        // operator must hear about it once, and again when it heals.
        match (previous_ok, status.ok) {
            (Some(true), false) | (None, false) => {
                crate::alerting::send_local_alert(
                    crate::alerting::AlertCategory::Lifecycle,
                    &format!("WolfHA replica of '{}' is falling behind", container),
                    &format!(
                        "Delta sync to node {} failed: {}. The standby keeps its last good state — a failover to it loses everything since then. Fix the replica and use Sync now on the WolfHA page.",
                        peer.node_id, status.message
                    ),
                ).await;
            }
            (Some(false), true) => {
                crate::alerting::send_local_alert(
                    crate::alerting::AlertCategory::Lifecycle,
                    &format!("WolfHA replica of '{}' recovered", container),
                    &format!("Delta sync to node {} is working again ({}).", peer.node_id, status.message),
                ).await;
            }
            _ => {}
        }
    }
    if let Some(round) = pve_round {
        let c = container.to_string();
        let _ = tokio::task::spawn_blocking(move || pve_finish_round(&c, &round, pve_all_ok)).await;
    }
    // A seed staged for this round is done with — every replica that
    // needed one has been served (or failed and will retry next round
    // with a fresh image).
    if let Some(s) = staged_seed.take() {
        let _ = std::fs::remove_file(&s.path);
    }
    // Drop the staged delta ONLY once every replica has confirmed it.
    // Deleting it while one is still behind would strand those blocks:
    // the bitmap no longer describes them, so no future delta would carry
    // them and that replica would diverge silently.
    if vm_delta.is_some() {
        let mut store = HaStore::load();
        let done = store.get(container)
            .and_then(|e| e.pending_vm_delta.clone())
            .map(|p| {
                let outstanding = peers.iter()
                    .filter(|r| !peer_is_local(r))
                    .any(|r| !p.applied_by.contains(&r.node_id));
                (p.path, p.token.clone(), !outstanding)
            });
        if let Some((path, token, all_applied)) = done
            && all_applied
        {
            let _ = std::fs::remove_file(&path);
            if let Some(e) = store.get_mut(container) {
                e.pending_vm_delta = None;
                // Every replica now holds this delta's token — it becomes
                // the chain base the NEXT delta is taken against.
                if !token.is_empty() {
                    e.vm_chain = Some(token);
                }
                let _ = store.save();
            }
        }
    }
    Ok(())
}

/// Ship an already-taken VM disk delta to one replica.
pub async fn sync_vm_replica(
    container: &str,
    peer: &HaPeer,
    secret: &str,
    delta_path: &str,
    chain_prev: &str,
    chain_next: &str,
) -> HaSyncStatus {
    let started = now_unix();
    let bytes = std::fs::metadata(delta_path).map(|m| m.len()).unwrap_or(0);
    match sync_vm_replica_inner(container, peer, secret, delta_path, chain_prev, chain_next).await {
        Ok(()) => HaSyncStatus {
            at: started,
            ok: true,
            message: format!(
                "disk delta applied ({}, QEMU dirty bitmap)",
                human_bytes(bytes)
            ),
            files_sent: 1,
            bytes_sent: bytes,
        },
        Err(e) => HaSyncStatus {
            at: started,
            ok: false,
            message: e,
            files_sent: 0,
            bytes_sent: 0,
        },
    }
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{} {}", n, UNITS[0]) } else { format!("{:.1} {}", v, UNITS[u]) }
}

async fn sync_vm_replica_inner(
    container: &str,
    peer: &HaPeer,
    secret: &str,
    delta_path: &str,
    chain_prev: &str,
    chain_next: &str,
) -> Result<(), String> {
    let client = &*crate::api::API_HTTP_CLIENT;
    let ha_meta_json = HaStore::load().get(container)
        .filter(|e| e.role == HaRole::Primary)
        .map(|e| serde_json::to_string(&HaMeta::from_entry(e)).unwrap_or_default())
        .unwrap_or_default();
    // The VM definition travels with every delta: a replica holding a
    // perfect disk but no definition cannot start it on failover, and the
    // definition can change (RAM, cores, NICs) between rounds.
    let vm_config_json = vm_disk_and_config(container)
        .ok()
        .and_then(|(_, cfg)| serde_json::to_string(&cfg).ok())
        .unwrap_or_default();

    let urls = crate::api::build_node_urls(&peer.address, peer.port, "/api/wolfha/apply-vm-delta");
    let mut last_err = String::new();
    for url in &urls {
        let part = match stream_archive_part(delta_path).await {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        let mut form = reqwest::multipart::Form::new()
            .text("container", container.to_string())
            .text("ha_meta", ha_meta_json.clone())
            .text("vm_config", vm_config_json.clone())
            // The chain proof — the replica applies only when its stored
            // token is exactly chain_prev (see vm_apply_delta).
            .text("chain_prev", chain_prev.to_string())
            .text("chain_next", chain_next.to_string())
            .part("archive", part.file_name("vmdelta.qcow2"));
        // OVMF NVRAM rides with every round — tiny, and firmware state
        // (boot entries) must not lag the disk across a failover.
        if let Some(vars) = vm_efivars_file(container) {
            match stream_archive_part(&vars).await {
                Ok(p) => form = form.part("efivars", p.file_name("VARS.fd")),
                Err(e) => return Err(format!("VM NVRAM vanished mid-send: {}", e)),
            }
        }
        match client.post(url)
            .peer_auth(secret)
            .timeout(std::time::Duration::from_secs(3600))
            .multipart(form)
            .send().await
        {
            Ok(r) if r.status().is_success() => return Ok(()),
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                last_err = format!("{}: HTTP {} {}", url, status, body.chars().take(300).collect::<String>());
            }
            Err(e) => last_err = format!("{}: {}", url, e),
        }
    }
    Err(format!("VM delta upload failed: {}", last_err))
}

// ─── Proxmox containers on ZFS (SubjectKind::PveContainer) ───
//
// The subject is a Proxmox CT identified by its VMID; its volumes are ZFS
// datasets and travel as `zfs send` streams (replication::zfs_send). The
// standby holds the same datasets under the same names, a config under
// /etc/pve/lxc/<vmid>.conf with `onboot: 0`, and an HaStore entry.
// Colt's 2026-09-06 live failover is the shape this follows: WoL-driven
// incremental sends, operator promotion, reverse sync for failback.

pub fn pve_config_path(vmid: &str) -> String {
    format!("/etc/pve/lxc/{}.conf", vmid)
}

/// The live section of the container's config (no snapshot sections).
pub fn pve_read_config(vmid: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(pve_config_path(vmid))
        .map_err(|e| format!("Proxmox container {} has no config on this node: {}", vmid, e))?;
    Ok(replication::zfs_send::live_config_section(&text))
}

/// Every volume of the container as ZFS datasets, from its config and
/// this node's storage.cfg.
pub fn pve_volumes(vmid: &str) -> Result<Vec<replication::zfs_send::PveVolume>, String> {
    let storage_cfg = std::fs::read_to_string("/etc/pve/storage.cfg")
        .map_err(|e| format!("read /etc/pve/storage.cfg: {}", e))?;
    let pools = replication::zfs_send::parse_storage_cfg_zfspools(&storage_cfg);
    let config = pve_read_config(vmid)?;
    replication::zfs_send::container_volumes(&config, &pools)
}

pub fn pve_datasets(vmid: &str) -> Result<Vec<String>, String> {
    Ok(pve_volumes(vmid)?.into_iter().map(|v| v.dataset).collect())
}

/// Persist the container's `onboot` flag through Proxmox itself.
/// Source: pct(1) `pct set <vmid> [OPTIONS]`, `--onboot <boolean>` —
/// the same key pct.conf(5) documents. Used on the PRIMARY (a live,
/// registered container); a standby's config is written directly because
/// there is no registered container to `pct set` until the file exists.
pub fn pve_set_onboot(vmid: &str, on: bool) -> Result<(), String> {
    let out = Command::new("pct")
        .args(["set", vmid, "--onboot", if on { "1" } else { "0" }])
        .output()
        .map_err(|e| format!("pct: {}", e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// One round's snapshot across every volume, taken atomically.
#[derive(Debug, Clone)]
pub struct PveRound {
    pub datasets: Vec<String>,
    pub snapshot: String,
}

/// Blocking. Snapshot every volume of the container at one instant.
pub fn pve_take_snapshot(vmid: &str) -> Result<PveRound, String> {
    let datasets = pve_datasets(vmid)?;
    let snapshot = replication::zfs_send::snapshot_name(vmid, now_unix());
    replication::zfs_send::snapshot_all(&datasets, &snapshot)
        .map_err(|e| format!("zfs snapshot of the container's volumes failed: {}", e))?;
    Ok(PveRound { datasets, snapshot })
}

/// Blocking. After a round: when every standby confirmed the new
/// snapshot it is the only base anyone needs, so older ones go. When any
/// standby failed, everything is kept — its base is among them, and the
/// next fully successful round prunes.
pub fn pve_finish_round(vmid: &str, round: &PveRound, all_ok: bool) {
    if !all_ok {
        return;
    }
    let keep: std::collections::HashSet<String> = std::iter::once(round.snapshot.clone()).collect();
    for ds in &round.datasets {
        let Ok(ours) = replication::zfs_send::list_ours(ds, vmid) else { continue };
        for s in replication::zfs_send::prune_plan(&ours, &keep) {
            if let Err(e) = replication::zfs_send::destroy_snapshot(ds, &s) {
                tracing::warn!("wolfha[{}]: could not prune snapshot {}@{}: {}", vmid, ds, s, e);
            }
        }
    }
}

/// Blocking. Remove every replication snapshot of the container's
/// volumes — HA disabled, or a failed protect being unwound.
pub fn pve_destroy_our_snapshots(vmid: &str, datasets: &[String]) {
    for ds in datasets {
        let Ok(ours) = replication::zfs_send::list_ours(ds, vmid) else { continue };
        for s in ours {
            let _ = replication::zfs_send::destroy_snapshot(ds, &s);
        }
    }
}

/// Ask a standby whether it can hold this container: a Proxmox host with
/// ZFS and the same parent datasets. Run before anything is sent, so a
/// protect that cannot work is refused with the reason instead of failing
/// mid-seed.
pub async fn pve_probe_replica(
    vmid: &str,
    peer: &HaPeer,
    secret: &str,
    datasets: &[String],
) -> Result<(), String> {
    let client = &*crate::api::API_HTTP_CLIENT;
    let path = format!(
        "/api/wolfha/capabilities?container={}&kind=pve_container&datasets={}",
        vmid,
        datasets.join(",")
    );
    let mut last = String::new();
    for url in crate::api::build_node_urls(&peer.address, peer.port, &path) {
        match client.get(&url).peer_auth(secret).timeout(std::time::Duration::from_secs(20)).send().await {
            Ok(r) if r.status().is_success() => {
                let caps: replication::ReplicationCapabilities = r.json().await
                    .map_err(|e| format!("{}: unreadable capabilities reply: {}", peer.node_id, e))?;
                return match replication::pve_replication_blocked_reason(&caps) {
                    None => Ok(()),
                    Some(why) => Err(format!("standby {} cannot receive this container: {}", peer.node_id, why)),
                };
            }
            Ok(r) => last = format!("{}: HTTP {}", url, r.status()),
            Err(e) => last = format!("{}: {}", url, e),
        }
    }
    Err(format!("standby {} did not answer the capabilities probe ({}) — it may be running a WolfStack build without ZFS replication", peer.node_id, last))
}

/// Stream `zfs send` of one dataset straight into a peer's
/// `/api/wolfha/receive-zfs`. Never buffered: the child's stdout IS the
/// request body. Returns the byte count that went over the wire.
async fn zfs_stream_to_peer(
    peer: &HaPeer,
    secret: &str,
    fields: &[(&str, String)],
    dataset: &str,
    from: Option<&str>,
    to: &str,
) -> Result<u64, String> {
    use futures::StreamExt;
    use tokio::io::AsyncReadExt;
    let client = &*crate::api::API_HTTP_CLIENT;
    let args = replication::zfs_send::send_args(dataset, from, to);
    let mut last_err = String::new();
    for url in crate::api::build_node_urls(&peer.address, peer.port, "/api/wolfha/receive-zfs") {
        let mut child = tokio::process::Command::new("zfs")
            .args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("spawn zfs send: {}", e))?;
        let stdout = child.stdout.take().ok_or("zfs send: no stdout")?;
        let mut stderr = child.stderr.take().ok_or("zfs send: no stderr")?;
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let seen = counter.clone();
        let stream = tokio_util::io::ReaderStream::with_capacity(stdout, 1 << 20).inspect(move |chunk| {
            if let Ok(b) = chunk {
                seen.fetch_add(b.len() as u64, std::sync::atomic::Ordering::Relaxed);
            }
        });
        // Text fields FIRST so the receiver can validate the request and
        // refuse it before a single byte of the stream is consumed.
        let mut form = reqwest::multipart::Form::new();
        for (k, v) in fields {
            form = form.text((*k).to_string(), v.clone());
        }
        form = form.part(
            "stream",
            reqwest::multipart::Part::stream(reqwest::Body::wrap_stream(stream)).file_name("stream.zfs"),
        );
        let resp = client.post(&url)
            .peer_auth(secret)
            // A first full send of a large container is the slowest thing
            // this module does; same ceiling as a VM seed.
            .timeout(std::time::Duration::from_secs(6 * 60 * 60))
            .multipart(form)
            .send().await;
        let mut zfs_err = String::new();
        let _ = stderr.read_to_string(&mut zfs_err).await;
        let status = child.wait().await.map_err(|e| format!("zfs send: {}", e))?;
        let bytes = counter.load(std::sync::atomic::Ordering::Relaxed);
        match resp {
            Ok(r) if r.status().is_success() && status.success() => return Ok(bytes),
            Ok(r) => {
                let code = r.status();
                let body = r.text().await.unwrap_or_default();
                let body: String = body.chars().take(400).collect();
                if body.contains(replication::zfs_send::ZFS_NEEDS_SEED) {
                    // The standby's answer is final — no other port will
                    // change it, and the caller re-sends a full stream.
                    return Err(body);
                }
                last_err = format!("{}: HTTP {} {}{}", url, code, body,
                    if zfs_err.trim().is_empty() { String::new() } else { format!(" (zfs send: {})", zfs_err.trim()) });
            }
            Err(e) => last_err = format!("{}: {}{}", url, e,
                if zfs_err.trim().is_empty() { String::new() } else { format!(" (zfs send: {})", zfs_err.trim()) }),
        }
    }
    Err(format!("ZFS stream of {} failed: {}", dataset, last_err))
}

/// Ship this round's snapshot of every volume to one standby: an
/// incremental from the newest snapshot both sides hold, or a full
/// stream when they share none (first seed, diverged copy, wiped node).
pub async fn pve_ship_round(vmid: &str, peer: &HaPeer, secret: &str, round: &PveRound) -> HaSyncStatus {
    let started = now_unix();
    match pve_ship_round_inner(vmid, peer, secret, round).await {
        Ok((bytes, message)) => HaSyncStatus {
            at: started,
            ok: true,
            message,
            files_sent: round.datasets.len() as u64,
            bytes_sent: bytes,
        },
        Err(e) => HaSyncStatus { at: started, ok: false, message: e, files_sent: 0, bytes_sent: 0 },
    }
}

async fn pve_ship_round_inner(
    vmid: &str,
    peer: &HaPeer,
    secret: &str,
    round: &PveRound,
) -> Result<(u64, String), String> {
    let client = &*crate::api::API_HTTP_CLIENT;
    // 1. What the standby already holds, per dataset.
    let mut remote: Option<std::collections::HashMap<String, Vec<String>>> = None;
    let mut last = String::new();
    for url in crate::api::build_node_urls(&peer.address, peer.port,
        &format!("/api/wolfha/zfs-snapshots?container={}", vmid))
    {
        match client.get(&url).peer_auth(secret).timeout(std::time::Duration::from_secs(60)).send().await {
            Ok(r) if r.status().is_success() => {
                remote = Some(r.json().await.map_err(|e| format!("bad snapshot inventory from {}: {}", url, e))?);
                break;
            }
            Ok(r) if r.status().as_u16() == 404 => {
                return Err(format!("standby {} does not support ZFS replication (older WolfStack build) — upgrade it", peer.node_id));
            }
            Ok(r) => last = format!("{}: HTTP {}", url, r.status()),
            Err(e) => last = format!("{}: {}", url, e),
        }
    }
    let remote = remote.ok_or_else(|| format!("standby snapshot inventory unavailable: {}", last))?;

    // 2. What rides along with every dataset.
    let config = pve_read_config(vmid)?;
    let (primary_json, ha_meta_json) = {
        let store = HaStore::load();
        let e = store.get(vmid).filter(|e| e.role == HaRole::Primary)
            .ok_or_else(|| format!("'{}' is not a primary on this node", vmid))?;
        (
            serde_json::to_string(&e.self_identity).unwrap_or_default(),
            serde_json::to_string(&HaMeta::from_entry(e)).unwrap_or_default(),
        )
    };

    let mut total = 0u64;
    let (mut incremental, mut full) = (0usize, 0usize);
    for ds in &round.datasets {
        let (ds_c, v_c) = (ds.clone(), vmid.to_string());
        let ours = tokio::task::spawn_blocking(move || replication::zfs_send::list_ours(&ds_c, &v_c))
            .await.map_err(|e| e.to_string())??;
        let have = remote.get(ds).cloned().unwrap_or_default();
        let base = replication::zfs_send::newest_common(&ours, &have).cloned();
        let fields = |from: &str| -> Vec<(&'static str, String)> {
            vec![
                ("container", vmid.to_string()),
                ("kind", "pve_container".to_string()),
                ("dataset", ds.clone()),
                ("snapshot", round.snapshot.clone()),
                ("from", from.to_string()),
                ("config", config.clone()),
                ("primary", primary_json.clone()),
                ("ha_meta", ha_meta_json.clone()),
            ]
        };
        match base {
            Some(b) => match zfs_stream_to_peer(peer, secret, &fields(&b), ds, Some(&b), &round.snapshot).await {
                Ok(n) => { total += n; incremental += 1; }
                Err(e) if e.contains(replication::zfs_send::ZFS_NEEDS_SEED) => {
                    // The standby proved it lacks the base after all —
                    // the repair is a full stream, never a patch.
                    tracing::info!("wolfha[{}]: standby {} needs a full stream of {} ({})", vmid, peer.node_id, ds, e);
                    total += zfs_stream_to_peer(peer, secret, &fields(""), ds, None, &round.snapshot).await?;
                    full += 1;
                }
                Err(e) => return Err(e),
            },
            None => {
                total += zfs_stream_to_peer(peer, secret, &fields(""), ds, None, &round.snapshot).await?;
                full += 1;
            }
        }
    }
    Ok((
        total,
        format!(
            "{} dataset(s) sent, {} ({} incremental, {} full — ZFS send, crash-consistent)",
            round.datasets.len(), human_bytes(total), incremental, full
        ),
    ))
}

/// The handoff's final stream: the container is already stopped, so the
/// snapshot taken here IS its final state. Sent to the node about to
/// promote first (it must have it), then best-effort to every other
/// standby so their bases stay current.
pub async fn pve_final_sync(vmid: &str, new_primary: &HaPeer, secret: &str) -> HaSyncStatus {
    let c = vmid.to_string();
    let round = match tokio::task::spawn_blocking(move || pve_take_snapshot(&c)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return HaSyncStatus { at: now_unix(), ok: false, message: format!("final snapshot failed: {}", e), files_sent: 0, bytes_sent: 0 },
        Err(e) => return HaSyncStatus { at: now_unix(), ok: false, message: format!("final snapshot task: {}", e), files_sent: 0, bytes_sent: 0 },
    };
    let st = pve_ship_round(vmid, new_primary, secret, &round).await;
    let mut all_ok = st.ok;
    let others: Vec<HaPeer> = HaStore::load().get(vmid).map(|e| e.replicas.clone()).unwrap_or_default();
    for peer in others {
        if peer.node_id == new_primary.node_id || peer.address == new_primary.address || peer_is_local(&peer) {
            continue;
        }
        let ost = pve_ship_round(vmid, &peer, secret, &round).await;
        if !ost.ok {
            all_ok = false;
            tracing::warn!("wolfha[{}]: handoff stream did not reach standby {} ({}) — the new primary re-seeds it", vmid, peer.node_id, ost.message);
        }
    }
    let c = vmid.to_string();
    let _ = tokio::task::spawn_blocking(move || pve_finish_round(&c, &round, all_ok)).await;
    st
}

/// Standby side: which of our snapshots each of the container's datasets
/// holds here — the primary's incremental base inventory.
pub fn pve_replica_snapshots(vmid: &str) -> std::collections::HashMap<String, Vec<String>> {
    let mut out = std::collections::HashMap::new();
    let store = HaStore::load();
    let Some(e) = store.get(vmid).filter(|e| e.kind == SubjectKind::PveContainer) else { return out };
    for ds in &e.zfs_datasets {
        out.insert(ds.clone(), replication::zfs_send::list_ours(ds, vmid).unwrap_or_default());
    }
    out
}

/// Everything a standby checked BEFORE consuming a stream.
pub struct PveReceivePlan {
    pub vmid: String,
    pub dataset: String,
    pub snapshot: String,
    pub from: Option<String>,
    pub args: Vec<String>,
}

/// Standby side, blocking. Validate a receive request and ready the
/// dataset for it. Every refusal happens here, before the first byte, so
/// the primary's `zfs send` is cut off by the HTTP error rather than
/// streaming gigabytes into a request that was doomed.
pub fn pve_prepare_receive(f: &std::collections::HashMap<String, String>) -> Result<PveReceivePlan, String> {
    use replication::zfs_send as z;
    if !crate::containers::is_proxmox() {
        return Err("this node is not a Proxmox host, so it cannot hold a Proxmox container".into());
    }
    if !z::have_zfs() {
        return Err("ZFS is not installed on this node".into());
    }
    let get = |k: &str| f.get(k).map(|s| s.trim().to_string()).unwrap_or_default();
    let vmid = get("container");
    if !z::is_vmid(&vmid) {
        return Err(format!("invalid container id {:?}", vmid));
    }
    let dataset = get("dataset");
    if !z::is_safe_dataset(&dataset) {
        return Err(format!("invalid dataset {:?}", dataset));
    }
    let snapshot = get("snapshot");
    if !z::is_ours(&snapshot, &vmid) {
        return Err(format!("snapshot {:?} is not a WolfHA replication snapshot for {}", snapshot, vmid));
    }
    let from = Some(get("from")).filter(|s| !s.is_empty());
    if let Some(fr) = &from
        && !z::is_ours(fr, &vmid)
    {
        return Err(format!("incremental base {:?} is not a WolfHA replication snapshot for {}", fr, vmid));
    }
    let store = HaStore::load();
    let entry = store.get(&vmid);
    match entry {
        Some(e) if e.role == HaRole::Primary && !e.stale => {
            return Err(format!("'{}' is the ACTIVE primary here — refusing a stream that would overwrite it", vmid));
        }
        Some(e) if e.kind != SubjectKind::PveContainer => {
            return Err(format!("'{}' is WolfHA-managed here as a {}, not a Proxmox container", vmid, e.kind.label()));
        }
        _ => {}
    }
    if entry.is_none() && f.get("primary").map(|p| p.trim().is_empty()).unwrap_or(true) {
        return Err("a first stream must carry the primary's peer identity".into());
    }
    if subject_is_running(SubjectKind::PveContainer, &vmid) {
        return Err(format!("container {} is running here — refusing to overwrite a live volume", vmid));
    }
    let ours = entry.is_some();
    if !ours {
        let taken = z::vmid_config_paths(&vmid);
        if !taken.is_empty() {
            return Err(format!(
                "VMID {} is already in use on this Proxmox node or cluster ({}) and is not a WolfHA copy — refusing to overwrite it",
                vmid, taken.join(", ")
            ));
        }
        if z::dataset_exists(&dataset) {
            return Err(format!("dataset {} already exists here and is not a WolfHA copy — refusing to overwrite it", dataset));
        }
    }
    match &from {
        None => {
            // Full stream: the dataset must not exist. A copy WolfHA put
            // here (re-seed of a diverged standby) is replaced.
            if z::dataset_exists(&dataset) {
                z::destroy_dataset(&dataset)
                    .map_err(|e| format!("could not clear the old copy of {} for re-seeding: {}", dataset, e))?;
            }
            match z::parent_dataset(&dataset) {
                Some(p) if z::dataset_exists(p) => {}
                Some(p) => return Err(format!("this node has no dataset '{}' to receive into — the standby needs the primary's pool layout", p)),
                None => return Err(format!("'{}' has no parent dataset", dataset)),
            }
        }
        Some(fr) => {
            if !z::dataset_exists(&dataset) {
                return Err(format!("{}: no copy of {} on this node — a full stream is needed", z::ZFS_NEEDS_SEED, dataset));
            }
            let have = z::list_ours(&dataset, &vmid)?;
            if !have.contains(fr) {
                return Err(format!(
                    "{}: this node's copy of {} does not hold the base snapshot {} — a full stream is needed",
                    z::ZFS_NEEDS_SEED, dataset, fr
                ));
            }
        }
    }
    Ok(PveReceivePlan { args: z::receive_args(&dataset), vmid, dataset, snapshot, from })
}

/// Standby side, blocking. After `zfs receive` succeeded: store the
/// primary's config as a standby config, keep only the newest base, and
/// bring the HA entry up to date (creating it on the first stream).
pub fn pve_commit_receive(f: &std::collections::HashMap<String, String>, plan: &PveReceivePlan) -> Result<(), String> {
    use replication::zfs_send as z;
    let vmid = &plan.vmid;
    if let Some(cfg) = f.get("config").filter(|c| !c.trim().is_empty()) {
        std::fs::write(pve_config_path(vmid), z::replica_config(cfg))
            .map_err(|e| format!("write {}: {}", pve_config_path(vmid), e))?;
    }
    // Only the newest snapshot is a base anyone will send from.
    if let Ok(ours) = z::list_ours(&plan.dataset, vmid) {
        let keep: std::collections::HashSet<String> = std::iter::once(plan.snapshot.clone()).collect();
        for s in z::prune_plan(&ours, &keep) {
            let _ = z::destroy_snapshot(&plan.dataset, &s);
        }
    }
    let primary: Option<HaPeer> = f.get("primary").and_then(|p| serde_json::from_str(p).ok());
    let meta: Option<HaMeta> = f.get("ha_meta").and_then(|m| serde_json::from_str(m).ok());
    let mut store = HaStore::load();
    if store.get(vmid).is_none() {
        store.entries.push(HaEntry {
            container: vmid.clone(),
            kind: SubjectKind::PveContainer,
            role: HaRole::Replica,
            interval_minutes: 0,
            replicas: Vec::new(),
            primary: primary.clone(),
            autostart_managed: false,
            last_sync: HashMap::new(),
            last_delta_at: 0,
            stale: false,
            pending_vm_delta: None,
            vm_chain: None,
            auto_failover: false,
            witness: String::new(),
            failover_after_secs: default_failover_after(),
            self_identity: None,
            zfs_datasets: Vec::new(),
        });
    }
    let e = store.get_mut(vmid).ok_or("HA entry vanished")?;
    tracing::info!(
        "wolfha[{}]: {} of {} applied — copy is at {}",
        vmid,
        match &plan.from { Some(f) => format!("incremental from {}", f), None => "full stream".to_string() },
        plan.dataset, plan.snapshot
    );
    e.last_delta_at = now_unix();
    e.stale = false;
    if let Some(m) = &meta {
        m.apply_to(e);
    }
    if let Some(p) = primary
        && e.role == HaRole::Replica
    {
        e.primary = Some(p);
    }
    if !e.zfs_datasets.contains(&plan.dataset) {
        e.zfs_datasets.push(plan.dataset.clone());
    }
    store.save()
}

/// Standby side, blocking. Delete a dormant copy: the registered
/// container and its volumes through Proxmox (`pct destroy`), falling
/// back to destroying the datasets and the config directly when Proxmox
/// does not know the container (a half-installed copy).
/// Source: pct(1) `pct destroy <vmid>` — "Destroy the container (also
/// delete all uses files)".
pub fn pve_remove_replica(vmid: &str, datasets: &[String]) -> Result<String, String> {
    if subject_is_running(SubjectKind::PveContainer, vmid) {
        return Err(format!("container {} is RUNNING here — refusing to delete it", vmid));
    }
    let via_pct = std::path::Path::new(&pve_config_path(vmid)).exists()
        && Command::new("pct").args(["destroy", vmid]).output().map(|o| o.status.success()).unwrap_or(false);
    let mut left: Vec<String> = Vec::new();
    for ds in datasets {
        if replication::zfs_send::dataset_exists(ds)
            && let Err(e) = replication::zfs_send::destroy_dataset(ds)
        {
            left.push(format!("{} ({})", ds, e));
        }
    }
    let _ = std::fs::remove_file(pve_config_path(vmid));
    if left.is_empty() {
        Ok(format!("standby copy of container {} removed{}", vmid, if via_pct { " (pct destroy)" } else { "" }))
    } else {
        Err(format!("container {} unregistered but these datasets could not be destroyed: {}", vmid, left.join(", ")))
    }
}

// ─── Scheduler + boot guard (spawned from main.rs) ───

/// In-flight guard so a slow sync round and the scheduler can't overlap
/// on the same container.
static SYNC_IN_FLIGHT: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

pub fn try_begin_sync(container: &str) -> bool {
    SYNC_IN_FLIGHT.lock().map(|mut s| s.insert(container.to_string())).unwrap_or(false)
}

pub fn end_sync(container: &str) {
    if let Ok(mut s) = SYNC_IN_FLIGHT.lock() {
        s.remove(container);
    }
}

/// Periodic replication driver: every minute, start a sync round for
/// each primary entry whose oldest replica status is older than its
/// interval. Runs forever; spawned once at startup.
pub async fn scheduler_forever() {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let store = HaStore::load();
        let now = now_unix();
        for entry in &store.entries {
            if entry.role != HaRole::Primary || entry.stale {
                continue;
            }
            let interval_secs = entry.interval_minutes.max(1) * 60;
            let oldest = entry.replicas.iter()
                .map(|r| entry.last_sync.get(&r.node_id).map(|s| s.at).unwrap_or(0))
                .min()
                .unwrap_or(0);
            if now.saturating_sub(oldest) < interval_secs {
                continue;
            }
            let container = entry.container.clone();
            if !try_begin_sync(&container) {
                continue;
            }
            tokio::spawn(async move {
                if let Err(e) = sync_container_now(&container).await {
                    tracing::warn!("wolfha: scheduled sync of '{}': {}", container, e);
                }
                end_sync(&container);
            });
        }
    }
}

/// Boot-time start of WolfHA-managed primaries. `lxc-autostart` never
/// sees them (their `lxc.start.auto` was stripped when HA was enabled),
/// so a rebooted primary first asks every replica "did you take over
/// while I was down?" before starting anything.
///
/// If a replica reports the container ACTIVE, this copy demotes itself
/// (stale replica of the active node) instead of starting — that's the
/// post-failover recovery path. If replicas are unreachable, we start
/// anyway: in the manual-failover phase an unreachable replica most
/// likely simply isn't running the container, and refusing to start
/// would turn every full-cluster power cycle into an outage. This is
/// the documented split-brain window of Phase 1 (the operator performed
/// the failover by hand, so they know which copy is live).
pub async fn boot_guard() {
    // Same gate lxc_autostart_all uses: this must run after a MACHINE
    // boot, never after a mere wolfstack service restart — an HA primary
    // the operator deliberately stopped must stay stopped.
    if !crate::containers::host_recently_booted() {
        return;
    }
    let store = HaStore::load();
    let secret = crate::auth::load_cluster_secret();
    let client = &*crate::api::API_HTTP_CLIENT;

    for entry in &store.entries {
        if entry.role != HaRole::Primary || entry.stale || !entry.autostart_managed {
            continue;
        }
        let container = entry.container.clone();
        let kind = entry.kind;
        if subject_is_running(kind, &container) {
            continue;
        }

        let mut taken_over_by: Option<HaPeer> = None;
        for peer in &entry.replicas {
            let urls = crate::api::build_node_urls(
                &peer.address, peer.port,
                &format!("/api/wolfha/status?container={}", container),
            );
            for url in &urls {
                match client.get(url)
                    .peer_auth(secret.clone())
                    .timeout(std::time::Duration::from_secs(10))
                    .send().await
                {
                    Ok(r) if r.status().is_success() => {
                        if let Ok(v) = r.json::<serde_json::Value>().await {
                            let active = v.get("active").and_then(|a| a.as_bool()).unwrap_or(false);
                            let role_primary = v.get("role").and_then(|s| s.as_str()) == Some("primary");
                            if active || role_primary {
                                taken_over_by = Some(peer.clone());
                            }
                        }
                        break;
                    }
                    Ok(r) => { let _ = r.bytes().await; }
                    Err(_) => {}
                }
            }
            if taken_over_by.is_some() {
                break;
            }
        }

        match taken_over_by {
            Some(peer) => {
                tracing::warn!(
                    "wolfha: '{}' was taken over by node {} while this node was down — local copy demoted to stale replica, NOT started",
                    container, peer.node_id
                );
                if let Err(e) = demote_local(&container, peer) {
                    tracing::warn!("wolfha: demotion of '{}' failed: {}", container, e);
                }
            }
            None => {
                match subject_start(kind, &container) {
                    Ok(_) => tracing::info!(
                        "wolfha: started HA primary {} '{}' at boot", kind.label(), container
                    ),
                    Err(e) => tracing::warn!(
                        "wolfha: boot start of HA primary {} '{}' failed: {}",
                        kind.label(), container, e
                    ),
                }
            }
        }
    }
}

// ─── Phase 2: automatic failover ───
//
// Design (Paul, 2026-08-08): NO quorum — 2-node clusters must work.
// Instead, three independent gates replace it:
//
// 1. WITNESS — a node may only ACT (fence itself, or promote) while it
//    can ping the configured witness IP (normally the gateway). A
//    partitioned node fails the ping and does nothing.
// 2. PRIORITY — the ordered replica list is the succession order. A
//    standby defers to any healthier standby listed before it.
// 3. THE BRIDGE ITSELF — before promoting, a standby pings the
//    container's own IP on the shared L2. If ANYTHING answers, the
//    container is alive somewhere and promotion aborts. On a shared
//    vSwitch the resource is its own lock.
//
// Timing contract: the primary self-fences after failover_after/2 (min
// 30s) of witness loss; standbys promote only after the FULL
// failover_after of primary unreachability — so on a clean partition
// the incumbent is stopped well before any standby starts.

/// Sustained-failure clocks, keyed "kind:container". Instant-based —
/// wall-clock jumps must not fake a timeout.
static FAIL_SINCE: std::sync::LazyLock<std::sync::Mutex<HashMap<String, std::time::Instant>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

fn fail_elapsed(key: &str, failing: bool) -> u64 {
    let mut map = FAIL_SINCE.lock().unwrap();
    if !failing {
        map.remove(key);
        return 0;
    }
    let start = *map.entry(key.to_string()).or_insert_with(std::time::Instant::now);
    start.elapsed().as_secs()
}

/// One-shot alert latch so a persisting condition alerts once, not
/// every 15s cycle. Cleared when the condition clears.
static ALERT_LATCH: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

async fn alert_once(key: &str, title: &str, body: &str) {
    let fresh = ALERT_LATCH.lock().map(|mut s| s.insert(key.to_string())).unwrap_or(false);
    if fresh {
        crate::alerting::send_local_alert(crate::alerting::AlertCategory::Lifecycle, title, body).await;
    }
}

fn alert_clear(key: &str) {
    if let Ok(mut s) = ALERT_LATCH.lock() {
        s.remove(key);
    }
}

/// Can this node reach `host` right now? One packet, 2s ceiling.
fn ping_host(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    Command::new("ping").args(["-c", "1", "-W", "2", "-n", host]).output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The container's static IPv4 from its LXC config (CIDR stripped) —
/// the address the L2-aliveness probe pings before a promotion.
fn container_static_ip(container: &str) -> Option<String> {
    let path = format!("{}/{}/config", crate::containers::lxc_base_dir(container), container);
    let cfg = std::fs::read_to_string(path).ok()?;
    cfg.lines()
        .find(|l| l.trim().starts_with("lxc.net.0.ipv4.address"))
        .and_then(|l| l.split('=').nth(1))
        .map(|v| v.trim().split('/').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
}

/// The subject's own IP for the promotion GATE 5 ping — the last check
/// before a standby takes over: if the subject still answers on the
/// bridge, it is alive SOMEWHERE and promoting would split-brain.
/// Containers: the static lxc.net.0 address. VMs: the WolfNet IP from
/// this replica's stored definition (`VmConfig.wolfnet_ip` — the same
/// identity the promoted copy would take over).
fn subject_static_ip(kind: SubjectKind, name: &str) -> Option<String> {
    match kind {
        SubjectKind::Container => container_static_ip(name),
        SubjectKind::PveContainer => std::fs::read_to_string(pve_config_path(name))
            .ok()
            .and_then(|c| replication::zfs_send::net0_static_ip(&c)),
        SubjectKind::Vm => crate::vms::manager::VmManager::new()
            .get_vm(name)
            .and_then(|c| c.wolfnet_ip)
            .map(|ip| ip.trim().to_string())
            .filter(|s| !s.is_empty()),
    }
}

fn fence_secs(failover_after: u64) -> u64 {
    (failover_after / 2).max(30)
}

/// Is this peer actually THIS machine? Node ids alias across registries
/// (each node's registry may know the same machine under a different
/// id — live-tested 2026-08-08: a promoted standby's replica list
/// contained itself under the OLD primary's alias for it), so id
/// comparison is not enough. Addresses don't lie: compare against every
/// IP configured on this host.
pub fn peer_is_local(peer: &HaPeer) -> bool {
    let out = match Command::new("ip").args(["-j", "-o", "addr"]).output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => return false,
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out) else { return false };
    let Some(ifaces) = v.as_array() else { return false };
    for iface in ifaces {
        let Some(infos) = iface.get("addr_info").and_then(|a| a.as_array()) else { continue };
        for info in infos {
            if info.get("local").and_then(|l| l.as_str()) == Some(peer.address.as_str()) {
                return true;
            }
        }
    }
    false
}

/// Ask a peer for its /api/wolfha/status of one container.
/// Ok(json) when ANY of its urls answered; Err when none did.
async fn peer_status(peer: &HaPeer, container: &str, secret: &str) -> Result<serde_json::Value, ()> {
    let client = &*crate::api::API_HTTP_CLIENT;
    let urls = crate::api::build_node_urls(
        &peer.address, peer.port,
        &format!("/api/wolfha/status?container={}", container),
    );
    for url in &urls {
        match client.get(url)
            .peer_auth(secret)
            .timeout(std::time::Duration::from_secs(5))
            .send().await
        {
            Ok(r) if r.status().is_success() => {
                if let Ok(v) = r.json::<serde_json::Value>().await {
                    return Ok(v);
                }
                return Err(());
            }
            Ok(r) => { let _ = r.bytes().await; }
            Err(_) => {}
        }
    }
    Err(())
}

/// The auto-failover monitor: every 15s, walk this node's HA entries
/// and apply the state machine. Spawned once at startup.
pub async fn failover_monitor_forever(cluster: std::sync::Arc<crate::agent::ClusterState>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        let store = HaStore::load();
        let secret = crate::auth::load_cluster_secret();
        let me: Option<HaPeer> = cluster.get_all_nodes().into_iter().find(|n| n.is_self)
            .and_then(|n| {
                // The registry self-entry often carries the LISTEN address
                // (0.0.0.0) — substitute our WolfNet IP so the identity we
                // hand out is actually callable by peers.
                let unusable = n.address.is_empty() || n.address == "0.0.0.0" || n.address.starts_with("127.");
                let address = if unusable {
                    crate::networking::detect_wolfnet_gateway_ip()?
                } else {
                    n.address
                };
                Some(HaPeer { node_id: n.id, address, port: n.port })
            });
        let my_id = me.as_ref().map(|p| p.node_id.clone());

        for entry in &store.entries {
            let c = entry.container.clone();
            match (entry.role, entry.stale) {
                // ── Active primary: self-fence when the witness vanishes ──
                (HaRole::Primary, false) => {
                    // Heal alias-duplicated replica sets left by earlier
                    // failover cycles (no-op when already clean).
                    dedupe_replicas(&c, &cluster);
                    let running = {
                        let (cc, k) = (c.clone(), entry.kind);
                        tokio::task::spawn_blocking(move || subject_is_running(k, &cc))
                            .await.unwrap_or(false)
                    };
                    if !running {
                        // The container isn't running here. Usually that's
                        // an operator stop (not our business) — but it is
                        // also what a returned primary looks like after a
                        // standby promoted while this node was down WITHOUT
                        // a machine reboot (service restart / crash), which
                        // the boot guard never sees. If a peer is actively
                        // running the container, converge: become its
                        // replica instead of sitting here as a second
                        // "primary" whose syncs the real one refuses.
                        let mut active_peer: Option<HaPeer> = None;
                        for peer in &entry.replicas {
                            if let Ok(v) = peer_status(peer, &c, &secret).await {
                                let p_active = v.get("active").and_then(|a| a.as_bool()).unwrap_or(false);
                                let p_role = v.get("role").and_then(|s| s.as_str()).unwrap_or("");
                                if p_active && p_role == "primary" {
                                    active_peer = Some(peer.clone());
                                    break;
                                }
                            }
                        }
                        if let Some(peer) = active_peer {
                            tracing::warn!("wolfha: '{}' is actively primary on {} — this returned copy demotes to replica", c, peer.node_id);
                            let cc = c.clone();
                            let _ = tokio::task::spawn_blocking(move || demote_local(&cc, peer.clone())).await;
                            alert_once(&format!("superseded:{}", c),
                                &format!("WolfHA '{}' was taken over while this node was away", c),
                                "The local copy was demoted to a stale replica of the new primary and will catch up automatically.").await;
                        }
                        fail_elapsed(&format!("witness:{}", c), false);
                        continue;
                    }
                    if !entry.auto_failover || entry.witness.is_empty() {
                        continue;
                    }
                    let witness = entry.witness.clone();
                    let ok = tokio::task::spawn_blocking(move || ping_host(&witness))
                        .await.unwrap_or(false);
                    let elapsed = fail_elapsed(&format!("witness:{}", c), !ok);
                    if ok {
                        alert_clear(&format!("witnessdown:{}", c));
                        continue;
                    }
                    if elapsed >= fence_secs(entry.failover_after_secs) {
                        // Witness gone — but fencing is only right when this
                        // node is truly ISOLATED. If any replica still
                        // answers, the network is alive and the witness
                        // itself died: stay up (the standbys can't promote
                        // either — their witness gate fails the same way).
                        let mut any_replica_reachable = false;
                        for peer in &entry.replicas {
                            if peer_status(peer, &c, &secret).await.is_ok() {
                                any_replica_reachable = true;
                                break;
                            }
                        }
                        if any_replica_reachable {
                            alert_once(&format!("witnessdown:{}", c),
                                &format!("WolfHA witness for '{}' is down", c),
                                &format!("The witness ({}) has been unreachable for {}s but the replica nodes still answer — the witness itself has failed, not this node. '{}' keeps running; automatic failover is effectively suspended until the witness returns.", entry.witness, elapsed, c)).await;
                            continue;
                        }
                        alert_clear(&format!("witnessdown:{}", c));
                        tracing::warn!("wolfha: witness {} unreachable {}s and no replica answers — SELF-FENCING '{}'", entry.witness, elapsed, c);
                        let (cc, k) = (c.clone(), entry.kind);
                        let _ = tokio::task::spawn_blocking(move || subject_stop(k, &cc)).await;
                        let mut s = HaStore::load();
                        if let Some(e) = s.get_mut(&c) {
                            e.stale = true;
                            let _ = s.save();
                        }
                        fail_elapsed(&format!("witness:{}", c), false);
                        alert_once(&format!("fenced:{}", c),
                            &format!("WolfHA self-fenced '{}'", c),
                            &format!("This node lost its witness ({}) for {}s and stopped '{}' so a standby can take over safely. It rejoins as a replica automatically when connectivity returns.", entry.witness, elapsed, c)).await;
                    }
                }

                // ── Fenced / superseded primary: reconcile ──
                (HaRole::Primary, true) => {
                    let witness_ok = if entry.witness.is_empty() {
                        true
                    } else {
                        let w = entry.witness.clone();
                        tokio::task::spawn_blocking(move || ping_host(&w)).await.unwrap_or(false)
                    };
                    if !witness_ok {
                        continue;
                    }
                    let mut taken_over: Option<HaPeer> = None;
                    let mut all_reachable = true;
                    for peer in &entry.replicas {
                        match peer_status(peer, &c, &secret).await {
                            Ok(v) => {
                                let active = v.get("active").and_then(|a| a.as_bool()).unwrap_or(false);
                                let their_role = v.get("role").and_then(|s| s.as_str()).unwrap_or("");
                                if active || their_role == "primary" {
                                    taken_over = Some(peer.clone());
                                    break;
                                }
                            }
                            Err(()) => { all_reachable = false; }
                        }
                    }
                    match taken_over {
                        Some(peer) => {
                            tracing::info!("wolfha: '{}' active on {} — this fenced copy becomes its replica", c, peer.node_id);
                            let cc = c.clone();
                            let _ = tokio::task::spawn_blocking(move || demote_local(&cc, peer)).await;
                            alert_clear(&format!("fenced:{}", c));
                        }
                        None if all_reachable && entry.auto_failover => {
                            // Nobody took over (they deferred, or the outage
                            // was shorter than their window) — the incumbent
                            // resumes.
                            tracing::info!("wolfha: no standby took over '{}' — resuming as primary", c);
                            let mut s = HaStore::load();
                            if let Some(e) = s.get_mut(&c) {
                                e.stale = false;
                                let _ = s.save();
                            }
                            let (cc, k) = (c.clone(), entry.kind);
                            let _ = tokio::task::spawn_blocking(move || subject_start(k, &cc)).await;
                            alert_clear(&format!("fenced:{}", c));
                            alert_once(&format!("resumed:{}", c),
                                &format!("WolfHA '{}' resumed on its primary", c),
                                "Connectivity returned before any standby promoted — the container was restarted in place.").await;
                        }
                        None => {} // some standby unreachable — keep waiting
                    }
                }

                // ── Standby: watch the primary, promote through the gates ──
                (HaRole::Replica, false) => {
                    let Some(primary) = entry.primary.clone() else { continue };
                    let running_here = {
                        let (cc, k) = (c.clone(), entry.kind);
                        tokio::task::spawn_blocking(move || subject_is_running(k, &cc))
                            .await.unwrap_or(false)
                    };
                    let pstat = peer_status(&primary, &c, &secret).await;

                    // Active-active self-heal: a standby that is somehow
                    // running while the primary also runs is a duplicate —
                    // the incumbent wins, this copy stops.
                    if running_here {
                        if let Ok(v) = &pstat {
                            let p_active = v.get("active").and_then(|a| a.as_bool()).unwrap_or(false);
                            if p_active {
                                tracing::warn!("wolfha: BOTH '{}' copies running — stopping the standby copy", c);
                                let (cc, k) = (c.clone(), entry.kind);
                                let _ = tokio::task::spawn_blocking(move || subject_stop(k, &cc)).await;
                                alert_once(&format!("dup:{}", c),
                                    &format!("WolfHA duplicate '{}' stopped", c),
                                    &format!("This standby was running at the same time as the primary on {} — the standby copy was stopped and stays a replica. Check how it was started.", primary.node_id)).await;
                            }
                        }
                        continue;
                    }
                    alert_clear(&format!("dup:{}", c));

                    if !entry.auto_failover {
                        continue;
                    }
                    let elapsed = fail_elapsed(&format!("primary:{}", c), pstat.is_err());
                    if pstat.is_ok() {
                        alert_clear(&format!("asym:{}", c));
                        alert_clear(&format!("toostale:{}", c));
                        continue;
                    }
                    if elapsed < entry.failover_after_secs {
                        continue;
                    }

                    // GATE 1 — witness: an isolated node must not act.
                    let witness_ok = if entry.witness.is_empty() {
                        false // auto mode without a witness never promotes
                    } else {
                        let w = entry.witness.clone();
                        tokio::task::spawn_blocking(move || ping_host(&w)).await.unwrap_or(false)
                    };
                    if !witness_ok {
                        tracing::warn!("wolfha: primary of '{}' unreachable {}s but witness is too — this node is the isolated one, holding", c, elapsed);
                        continue;
                    }

                    // GATE 2 — the cluster's aggregated view: if gossip says
                    // the primary node is alive, only MY path to it is broken.
                    //
                    // get_node() returns the STORED online flag, which can
                    // stay true long after a node dies — only get_all_nodes()
                    // recomputes it from last_seen (agent/mod.rs). Recompute
                    // here the same way (fresh within 60s = alive); trusting
                    // the stored flag blocked auto-failover for 30+ minutes
                    // in the 2026-08-08 live test.
                    if let Some(n) = cluster.get_node(&primary.node_id)
                        && n.online
                        && now_unix().saturating_sub(n.last_seen) < 60
                    {
                        alert_once(&format!("asym:{}", c),
                            &format!("WolfHA cannot verify primary of '{}'", c),
                            &format!("This standby cannot reach the primary node {} for '{}', but the cluster still sees that node online — refusing to promote over a one-sided network problem. Check routing between the two nodes.", primary.node_id, c)).await;
                        continue;
                    }

                    // GATE 3 — priority: defer to a healthier standby listed
                    // before me in the succession order.
                    let mut defer = false;
                    if let Some(my_id) = &my_id {
                        for peer in &entry.replicas {
                            // Alias-safe self match: id OR local address.
                            if &peer.node_id == my_id || peer_is_local(peer) {
                                break; // everyone before me has been checked
                            }
                            if peer.node_id == primary.node_id {
                                continue;
                            }
                            if let Ok(v) = peer_status(peer, &c, &secret).await {
                                let their_role = v.get("role").and_then(|s| s.as_str()).unwrap_or("");
                                let their_stale = v.get("stale").and_then(|s| s.as_bool()).unwrap_or(false);
                                if their_role == "primary" || (their_role == "replica" && !their_stale) {
                                    defer = true; // a healthier, higher-priority copy exists
                                    break;
                                }
                            }
                        }
                    }
                    if defer {
                        continue;
                    }

                    // GATE 4 — freshness: never auto-promote an ancient copy.
                    let max_age = (entry.interval_minutes.max(1) * 60 * 6).max(1800);
                    let age = now_unix().saturating_sub(entry.last_delta_at);
                    if age > max_age {
                        alert_once(&format!("toostale:{}", c),
                            &format!("WolfHA cannot auto-fail-over '{}'", c),
                            &format!("The primary looks dead but this standby's copy is {}m old (limit {}m) — replication had been failing. Promote manually from the WolfHA page if this state is acceptable.", age / 60, max_age / 60)).await;
                        continue;
                    }

                    // GATE 5 — the bridge itself: if the subject's IP
                    // answers, it is alive SOMEWHERE. Abort.
                    if let Some(ip) = subject_static_ip(entry.kind, &c) {
                        let alive = tokio::task::spawn_blocking(move || ping_host(&ip)).await.unwrap_or(false);
                        if alive {
                            tracing::warn!("wolfha: '{}' answers on the bridge — its node is unreachable but the container is alive; NOT promoting", c);
                            continue;
                        }
                    }

                    // All gates passed — take over.
                    tracing::warn!("wolfha: AUTO-FAILOVER of '{}' — primary {} unreachable {}s, all gates passed", c, primary.node_id, elapsed);
                    let cc = c.clone();
                    let me_c = me.clone();
                    let res = tokio::task::spawn_blocking(move || promote_local(&cc, me_c)).await;
                    fail_elapsed(&format!("primary:{}", c), false);
                    match res {
                        Ok(Ok(())) => {
                            crate::alerting::send_local_alert(
                                crate::alerting::AlertCategory::Lifecycle,
                                &format!("WolfHA auto-failover: '{}' promoted", c),
                                &format!("Primary node {} was unreachable for {}s. '{}' is now running on this node with the state of its last sync ({}m old). The old node rejoins as a stale replica when it returns.", primary.node_id, elapsed, c, age / 60),
                            ).await;
                        }
                        other => {
                            let err = match other {
                                Ok(Err(e)) => e,
                                Err(e) => e.to_string(),
                                Ok(Ok(())) => unreachable!(),
                            };
                            crate::alerting::send_local_alert(
                                crate::alerting::AlertCategory::Lifecycle,
                                &format!("WolfHA auto-failover of '{}' FAILED", c),
                                &format!("All gates passed but promotion failed: {}. Intervene manually on the WolfHA page.", err),
                            ).await;
                        }
                    }
                }

                // ── Stale replica: deltas from the active node heal it ──
                (HaRole::Replica, true) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {

    /// End-to-end functional test of the replication pipeline against real
    /// files: signatures on the "replica" copy, delta on the "primary"
    /// copy, bundle over the wire format, then install on the replica.
    /// The reconstructed file must match the primary byte for byte.
    #[test]
    fn a_block_delta_round_trip_reproduces_the_primary_file() {
        use super::replication::rolling;
        let dir = std::env::temp_dir().join(format!("wolfha-e2e-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let replica = dir.join("data.bin");
        let primary = dir.join("data.new");

        // A file big enough to exercise real block matching.
        let mut base: Vec<u8> = (0..400_000u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
        std::fs::write(&replica, &base).unwrap();
        // One small edit deep inside, plus an append.
        base[250_000] ^= 0xff;
        base.extend_from_slice(b"appended tail bytes");
        std::fs::write(&primary, &base).unwrap();

        let sig = rolling::signatures(replica.to_str().unwrap(), rolling::BLOCK_SIZE).unwrap();
        let sig = rolling::decode_signatures(&rolling::encode_signatures(&sig)).unwrap();
        let ops = rolling::compute_delta(primary.to_str().unwrap(), &sig).unwrap();

        // Through the multi-file bundle format, as a real round does.
        let bundle = rolling::pack_file_deltas(&[rolling::FileDelta {
            path: "data.bin".to_string(),
            ops,
        }]);
        let items = rolling::unpack_file_deltas(&bundle).unwrap();
        assert_eq!(items.len(), 1);

        super::install_reconstructed_file(replica.to_str().unwrap(), &items[0].ops).unwrap();
        assert_eq!(std::fs::read(&replica).unwrap(), base, "replica must match the primary exactly");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The delta must cost about ONE BLOCK, not a fraction of the file —
    /// that is the invariant that makes this worth having, and it is what
    /// scales: the same single block whether the file is 600 KB or 10 GB.
    ///
    /// (Asserting a *percentage* would be wrong. With a 64 KiB block size a
    /// small file is only a handful of blocks, so one changed block is a
    /// large share of it — while for the 10 GB database this exists for it
    /// is 0.0006%.)
    #[test]
    fn a_one_byte_change_costs_about_one_block() {
        use super::replication::rolling;
        let dir = std::env::temp_dir().join(format!("wolfha-e2e-size-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let replica = dir.join("big.bin");
        let mut data: Vec<u8> = (0..600_000u32).map(|i| (i.wrapping_mul(40503) >> 8) as u8).collect();
        std::fs::write(&replica, &data).unwrap();
        let sig = rolling::signatures(replica.to_str().unwrap(), rolling::BLOCK_SIZE).unwrap();
        data[300_000] ^= 0xff;
        let ops = rolling::delta_from_bytes(&data, &sig);
        let bundle = rolling::pack_file_deltas(&[rolling::FileDelta { path: "big.bin".into(), ops }]);
        assert!(
            bundle.len() < rolling::BLOCK_SIZE * 3,
            "a one-byte change should cost ~1 block ({} bytes), got {} for a {} byte file",
            rolling::BLOCK_SIZE,
            bundle.len(),
            data.len()
        );
        // And it must genuinely be less than resending the file.
        assert!(bundle.len() < data.len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Mode must survive the swap. Without this a first sync silently
    /// turns every replicated file 0644 and the container breaks on its
    /// next start.
    #[test]
    fn installing_a_delta_preserves_the_files_mode() {
        use std::os::unix::fs::PermissionsExt;
        use super::replication::rolling;
        let dir = std::env::temp_dir().join(format!("wolfha-e2e-mode-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let target = dir.join("script.sh");
        std::fs::write(&target, b"#!/bin/sh\necho one\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o750)).unwrap();

        let new = b"#!/bin/sh\necho two\n".to_vec();
        let sig = rolling::signatures(target.to_str().unwrap(), rolling::BLOCK_SIZE).unwrap();
        let ops = rolling::delta_from_bytes(&new, &sig);
        super::install_reconstructed_file(target.to_str().unwrap(), &ops).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), new);
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o750, "mode changed to {:o}", mode);
        let _ = std::fs::remove_dir_all(&dir);
    }


    /// THE golden-rule guarantee for VM support: every wolfha.json written
    /// before `kind` existed must still parse, and must still mean
    /// "container". A regression here would make existing HA entries
    /// either fail to load or — far worse — be treated as VMs, so
    /// promotion would try to start a VM that does not exist.
    #[test]
    fn an_entry_without_kind_loads_as_a_container() {
        let old = r#"{
            "container": "web01",
            "role": "primary",
            "interval_minutes": 5,
            "replicas": [],
            "last_sync": {},
            "last_delta_at": 0,
            "stale": false
        }"#;
        let e: super::HaEntry = serde_json::from_str(old).expect("pre-VM entry must parse");
        assert_eq!(e.kind, super::SubjectKind::Container);
        assert!(e.pending_vm_delta.is_none());
    }

    /// The kind travels to standbys inside HaMeta. A delta from an older
    /// primary carries no `kind`, and must keep meaning "container".
    #[test]
    fn ha_meta_without_kind_means_container() {
        let old = r#"{
            "interval_minutes": 5,
            "replicas": [],
            "auto_failover": false,
            "witness": "",
            "failover_after_secs": 90,
            "primary": null
        }"#;
        let m: super::HaMeta = serde_json::from_str(old).expect("pre-VM meta must parse");
        assert_eq!(m.kind, super::SubjectKind::Container);
    }

    /// A standby must learn from the primary what it is holding — guessing
    /// wrong means starting the wrong kind of thing on failover.
    #[test]
    fn ha_meta_carries_the_kind_to_a_standby() {
        let mut e: super::HaEntry =
            serde_json::from_str(r#"{"container":"vm01","role":"primary","replicas":[],
                "last_sync":{},"last_delta_at":0,"stale":false}"#).unwrap();
        e.kind = super::SubjectKind::Vm;
        let meta = super::HaMeta::from_entry(&e);
        assert_eq!(meta.kind, super::SubjectKind::Vm);

        let mut standby: super::HaEntry =
            serde_json::from_str(r#"{"container":"vm01","role":"replica","replicas":[],
                "last_sync":{},"last_delta_at":0,"stale":false}"#).unwrap();
        assert_eq!(standby.kind, super::SubjectKind::Container);
        meta.apply_to(&mut standby);
        assert_eq!(standby.kind, super::SubjectKind::Vm, "standby must adopt the primary's kind");
    }

    /// Wire spelling is pinned: `kind` crosses between nodes, so renaming
    /// a variant would silently split a mixed-version cluster.
    #[test]
    fn subject_kind_wire_names_are_stable() {
        assert_eq!(serde_json::to_string(&super::SubjectKind::Container).unwrap(), "\"container\"");
        assert_eq!(serde_json::to_string(&super::SubjectKind::Vm).unwrap(), "\"vm\"");
        assert_eq!(serde_json::to_string(&super::SubjectKind::PveContainer).unwrap(), "\"pve_container\"");
    }

    /// A pending delta must survive a restart — it is the only copy of
    /// blocks the bitmap has already discarded.
    #[test]
    fn pending_delta_round_trips_through_the_store() {
        let mut e: super::HaEntry =
            serde_json::from_str(r#"{"container":"vm01","role":"primary","replicas":[],
                "last_sync":{},"last_delta_at":0,"stale":false}"#).unwrap();
        e.kind = super::SubjectKind::Vm;
        e.pending_vm_delta = Some(super::replication::qemu_bitmap::PendingDelta {
            path: "/var/lib/wolfstack/wolfha/vmdelta-x.qcow2".into(),
            taken_at: 42,
            applied_by: vec!["node-a".into()],
            token: "tok-1".into(),
        });
        e.vm_chain = Some("tok-0".into());
        let json = serde_json::to_string(&e).unwrap();
        let back: super::HaEntry = serde_json::from_str(&json).unwrap();
        let pd = back.pending_vm_delta.expect("pending delta must survive");
        assert_eq!(pd.applied_by, vec!["node-a".to_string()]);
        assert_eq!(pd.taken_at, 42);
        assert_eq!(pd.token, "tok-1");
        assert_eq!(back.vm_chain.as_deref(), Some("tok-0"), "the chain token must survive a restart");
    }

    /// The chain gate is what stands between an incremental and a
    /// diverged disk: only the exact expected token applies; the token
    /// the delta advances TO is an idempotent success; anything else —
    /// including an unknown state — demands a full seed, loudly.
    #[test]
    fn vm_delta_chain_gate_refuses_a_diverged_copy() {
        // No HA entry at all → not silently applied, and the error names
        // the remedy the primary automates (a full seed).
        let err = super::vm_apply_delta("no-such-vm-xyz", "/nonexistent.qcow2", "a", "b", None)
            .expect_err("must refuse");
        assert!(err.contains(super::VM_NEEDS_SEED), "wrong error: {}", err);
    }

    use super::*;

    fn f(p: &str, s: u64, m: i64) -> ManifestEntry {
        ManifestEntry { p: p.into(), k: "f".into(), s, m, t: String::new() }
    }
    fn d(p: &str) -> ManifestEntry {
        ManifestEntry { p: p.into(), k: "d".into(), s: 0, m: 0, t: String::new() }
    }
    fn l(p: &str, t: &str) -> ManifestEntry {
        ManifestEntry { p: p.into(), k: "l".into(), s: 0, m: 0, t: t.into() }
    }

    #[test]
    fn diff_ships_new_changed_and_retargeted_symlinks_only() {
        let local = vec![
            d("etc"),
            f("etc/hostname", 8, 100),
            f("etc/hosts", 20, 100),
            f("var/log/app.log", 900, 555),
            l("etc/localtime", "/usr/share/zoneinfo/Europe/London"),
        ];
        let remote = vec![
            d("etc"),
            f("etc/hostname", 8, 100),          // identical — not shipped
            f("etc/hosts", 20, 90),             // mtime differs — shipped
            l("etc/localtime", "/usr/share/zoneinfo/UTC"), // target differs — shipped
        ];
        let (changed, deletions) = manifest_diff(&local, &remote);
        assert_eq!(changed, vec!["etc/hosts", "var/log/app.log", "etc/localtime"]);
        assert!(deletions.is_empty());
    }

    #[test]
    fn diff_deletes_children_before_parents() {
        let local = vec![d("etc")];
        let remote = vec![
            d("etc"),
            d("opt"),
            d("opt/app"),
            f("opt/app/bin", 10, 1),
        ];
        let (changed, deletions) = manifest_diff(&local, &remote);
        assert!(changed.is_empty());
        assert_eq!(deletions, vec!["opt/app/bin", "opt/app", "opt"]);
    }

    #[test]
    fn kind_flip_deletes_then_ships() {
        let local = vec![f("srv/data", 5, 1)];
        let remote = vec![d("srv/data")];
        let (changed, deletions) = manifest_diff(&local, &remote);
        assert_eq!(changed, vec!["srv/data"]);
        assert_eq!(deletions, vec!["srv/data"]);
    }

    #[test]
    fn unsafe_rel_paths_are_rejected() {
        for bad in ["", "/etc/passwd", "../x", "a/../b", "a//b", "./a", "a/./b", "a\0b"] {
            assert!(!is_safe_rel_path(bad), "{:?} should be rejected", bad);
        }
        for good in ["etc/hostname", "var/log/app.log", "usr/share/x-y_z.1"] {
            assert!(is_safe_rel_path(good), "{:?} should be accepted", good);
        }
    }

    #[test]
    fn identical_manifests_are_a_noop() {
        let m = vec![d("etc"), f("etc/hostname", 8, 100)];
        let (changed, deletions) = manifest_diff(&m, &m.clone());
        assert!(changed.is_empty() && deletions.is_empty());
    }

    /// Full engine round-trip on a REAL filesystem with the REAL tar
    /// binary: seed a "replica" from a live "primary" rootfs, mutate the
    /// primary (edit / add / delete / retarget symlink), run one delta
    /// round exactly the way sync + apply do, and prove the replica is
    /// byte-identical afterwards. This is the closest a unit test gets
    /// to the wire path without a second node.
    #[test]
    fn seed_plus_delta_round_trip_converges_on_disk() {
        let base = std::env::temp_dir().join(format!("wolfha-test-{}", uuid::Uuid::new_v4()));
        let src = base.join("src");
        let dst = base.join("dst");
        std::fs::create_dir_all(src.join("etc")).unwrap();
        std::fs::create_dir_all(src.join("var/log")).unwrap();
        std::fs::create_dir_all(src.join("proc")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();

        std::fs::write(src.join("etc/hostname"), "legolas\n").unwrap();
        std::fs::write(src.join("etc/keepme.conf"), "stay\n").unwrap();
        std::fs::write(src.join("var/log/app.log"), "line1\n").unwrap();
        std::fs::write(src.join("var/log/old.log"), "obsolete\n").unwrap();
        // Contents of excluded top-level dirs must never travel.
        std::fs::write(src.join("proc/should-not-copy"), "x").unwrap();
        std::os::unix::fs::symlink("/usr/share/zoneinfo/Europe/London", src.join("etc/localtime")).unwrap();

        // Seed.
        let seed = base.join("seed.tar.gz");
        tar_full_rootfs(src.to_str().unwrap(), seed.to_str().unwrap()).unwrap();
        untar_into_rootfs(seed.to_str().unwrap(), dst.to_str().unwrap()).unwrap();
        assert!(dst.join("etc/hostname").exists());
        assert!(!dst.join("proc/should-not-copy").exists(), "excluded dir contents leaked into the seed");

        // Mutate the primary. Content changes also change SIZE so the
        // size+mtime quick-check can't be defeated by same-second writes.
        std::fs::write(src.join("var/log/app.log"), "line1\nline2 appended\n").unwrap();
        std::fs::write(src.join("etc/new-file.conf"), "brand new\n").unwrap();
        std::fs::remove_file(src.join("var/log/old.log")).unwrap();
        std::fs::remove_file(src.join("etc/localtime")).unwrap();
        std::os::unix::fs::symlink("/usr/share/zoneinfo/UTC", src.join("etc/localtime")).unwrap();

        // One delta round, exactly as sync_one_replica_inner + apply_delta do it.
        let local = build_manifest(src.to_str().unwrap()).unwrap();
        let remote = build_manifest(dst.to_str().unwrap()).unwrap();
        let (changed, deletions) = manifest_diff(&local, &remote);
        assert!(changed.iter().any(|p| p == "var/log/app.log"));
        assert!(changed.iter().any(|p| p == "etc/new-file.conf"));
        assert!(changed.iter().any(|p| p == "etc/localtime"));
        assert!(deletions.iter().any(|p| p == "var/log/old.log"));
        assert!(!changed.iter().any(|p| p == "etc/keepme.conf"), "unchanged file shipped");

        let list = base.join("delta.list");
        let mut buf: Vec<u8> = Vec::new();
        for p in &changed {
            buf.extend_from_slice(p.as_bytes());
            buf.push(0);
        }
        std::fs::write(&list, buf).unwrap();
        let delta = base.join("delta.tar.gz");
        tar_paths(src.to_str().unwrap(), list.to_str().unwrap(), delta.to_str().unwrap()).unwrap();
        untar_into_rootfs(delta.to_str().unwrap(), dst.to_str().unwrap()).unwrap();
        let mut sorted: Vec<&String> = deletions.iter().collect();
        sorted.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| b.cmp(a)));
        for d in sorted {
            let t = dst.join(d);
            if let Ok(md) = std::fs::symlink_metadata(&t) {
                if md.file_type().is_dir() { let _ = std::fs::remove_dir_all(&t); }
                else { let _ = std::fs::remove_file(&t); }
            }
        }

        // Converged: manifests identical, content identical, symlink retargeted.
        let mut after_src = build_manifest(src.to_str().unwrap()).unwrap();
        let mut after_dst = build_manifest(dst.to_str().unwrap()).unwrap();
        after_src.sort_by(|a, b| a.p.cmp(&b.p));
        after_dst.sort_by(|a, b| a.p.cmp(&b.p));
        assert_eq!(after_src, after_dst, "replica did not converge to the primary");
        assert_eq!(std::fs::read_to_string(dst.join("var/log/app.log")).unwrap(), "line1\nline2 appended\n");
        assert_eq!(std::fs::read_to_string(dst.join("etc/new-file.conf")).unwrap(), "brand new\n");
        assert_eq!(std::fs::read_link(dst.join("etc/localtime")).unwrap().to_string_lossy(), "/usr/share/zoneinfo/UTC");
        assert!(!dst.join("var/log/old.log").exists());
        let (c2, d2) = manifest_diff(&after_src, &after_dst);
        assert!(c2.is_empty() && d2.is_empty(), "second diff should be a no-op");

        let _ = std::fs::remove_dir_all(&base);
    }
}
