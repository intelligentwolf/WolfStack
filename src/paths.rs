// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! Centralised file location configuration.
//!
//! Every WolfStack path constant goes through this module so users can
//! override defaults via `/etc/wolfstack/paths.json` or the Settings UI.

use serde::{Deserialize, Serialize};
use std::sync::{LazyLock, RwLock};

const PATHS_CONFIG_FILE: &str = "/etc/wolfstack/paths.json";

/// All configurable file locations with their defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLocations {
    // ── Core config directory ─────────────────────
    #[serde(default = "default_config_dir")]
    pub config_dir: String,

    // ── Backup ────────────────────────────────────
    #[serde(default = "default_backup_config")]
    pub backup_config: String,
    #[serde(default = "default_backup_staging_dir")]
    pub backup_staging_dir: String,
    #[serde(default = "default_backup_received_dir")]
    pub backup_received_dir: String,
    // Where "Local" backups are written. Defaults to the WolfStack data dir,
    // but an operator can point it at any mount (e.g. an R2/S3 fuse mount) so
    // backups don't depend on the WolfStack folder structure.
    #[serde(default = "default_backup_local_dir")]
    pub backup_local_dir: String,

    // Where standalone Docker Compose stacks live (the Compose page). Point it
    // at an existing compose root and every `<name>/docker-compose.yml` under
    // it shows up as a managed stack — that's the "import existing compose
    // files" path. Default unchanged so existing stacks keep working.
    #[serde(default = "default_compose_dir")]
    pub compose_dir: String,

    // ── Storage ───────────────────────────────────
    #[serde(default = "default_storage_config")]
    pub storage_config: String,
    /// Per-job rclone logs for S3 bucket-sync passes.
    #[serde(default = "default_s3_sync_log_dir")]
    pub s3_sync_log_dir: String,
    #[serde(default = "default_gluster_config")]
    pub gluster_config: String,
    #[serde(default = "default_storage_mount_base")]
    pub storage_mount_base: String,
    #[serde(default = "default_s3_credentials_dir")]
    pub s3_credentials_dir: String,
    #[serde(default = "default_s3_cache_dir")]
    pub s3_cache_dir: String,

    // ── Cluster / Nodes ───────────────────────────
    #[serde(default = "default_nodes_config")]
    pub nodes_config: String,
    #[serde(default = "default_deleted_nodes_config")]
    pub deleted_nodes_config: String,
    #[serde(default = "default_self_cluster_config")]
    pub self_cluster_config: String,
    #[serde(default = "default_self_site_config")]
    pub self_site_config: String,
    #[serde(default = "default_self_display_name_config")]
    pub self_display_name_config: String,
    #[serde(default = "default_self_roles_config")]
    pub self_roles_config: String,
    #[serde(default = "default_pending_identity_config")]
    pub pending_identity_config: String,
    #[serde(default = "default_node_id_file")]
    pub node_id_file: String,
    #[serde(default = "default_xo_pools_config")]
    pub xo_pools_config: String,
    #[serde(default = "default_truenas_config")]
    pub truenas_config: String,
    #[serde(default = "default_unraid_config")]
    pub unraid_config: String,

    // ── Alerting ──────────────────────────────────
    #[serde(default = "default_alerts_config")]
    pub alerts_config: String,

    // ── Status pages ──────────────────────────────
    #[serde(default = "default_statuspage_config")]
    pub statuspage_config: String,
    #[serde(default = "default_statuspage_uptime")]
    pub statuspage_uptime: String,

    // ── AI Agent ──────────────────────────────────
    #[serde(default = "default_ai_config")]
    pub ai_config: String,
    #[serde(default = "default_ai_baseline")]
    pub ai_baseline: String,
    #[serde(default = "default_ai_suppress_secret")]
    pub ai_suppress_secret: String,

    // ── WolfRun ───────────────────────────────────
    #[serde(default = "default_wolfrun_dir")]
    pub wolfrun_dir: String,
    #[serde(default = "default_wolfrun_services")]
    pub wolfrun_services: String,
    #[serde(default = "default_wolfrun_failover_events")]
    pub wolfrun_failover_events: String,

    // ── WolfFunctions ─────────────────────────────
    #[serde(default = "default_wolffunctions_dir")]
    pub wolffunctions_dir: String,
    #[serde(default = "default_wolffunctions_functions")]
    pub wolffunctions_functions: String,
    #[serde(default = "default_wolffunctions_runtime_dir")]
    pub wolffunctions_runtime_dir: String,

    // ── WolfFlow ──────────────────────────────────
    #[serde(default = "default_wolfflow_dir")]
    pub wolfflow_dir: String,
    #[serde(default = "default_wolfflow_workflows")]
    pub wolfflow_workflows: String,
    #[serde(default = "default_wolfflow_runs")]
    pub wolfflow_runs: String,

    // ── Kubernetes ────────────────────────────────
    #[serde(default = "default_kubernetes_config")]
    pub kubernetes_config: String,

    // ── App Store ─────────────────────────────────
    #[serde(default = "default_appstore_dir")]
    pub appstore_dir: String,
    #[serde(default = "default_appstore_installed")]
    pub appstore_installed: String,
    #[serde(default = "default_appstore_pending_dir")]
    pub appstore_pending_dir: String,

    // ── Ceph ──────────────────────────────────────
    #[serde(default = "default_ceph_config")]
    pub ceph_config: String,

    // ── VMs ───────────────────────────────────────
    #[serde(default = "default_vms_dir")]
    pub vms_dir: String,

    // ── TLS ───────────────────────────────────────
    #[serde(default = "default_tls_cert")]
    pub tls_cert: String,
    #[serde(default = "default_tls_key")]
    pub tls_key: String,

    // ── Auth ──────────────────────────────────────
    #[serde(default = "default_cluster_secret")]
    pub cluster_secret: String,

    // ── Patreon ───────────────────────────────────
    #[serde(default = "default_patreon_config")]
    pub patreon_config: String,

    // ── IP Mappings ───────────────────────────────
    #[serde(default = "default_ip_mappings")]
    pub ip_mappings: String,

    // ── LXC Paths ─────────────────────────────────
    #[serde(default = "default_lxc_paths")]
    pub lxc_paths: String,

    // ── Containers ────────────────────────────────
    #[serde(default = "default_cluster_containers_dir")]
    pub cluster_containers_dir: String,

    // ── Icon Packs ────────────────────────────────
    #[serde(default = "default_icon_packs_dir")]
    pub icon_packs_dir: String,

    // ── PBS ───────────────────────────────────────
    #[serde(default = "default_pbs_config")]
    pub pbs_config: String,

    // ── WolfNote ───────────────────────────────────
    #[serde(default = "default_wolfnote_config")]
    pub wolfnote_config: String,

    // ── Web UI ────────────────────────────────────
    #[serde(default = "default_web_dir")]
    pub web_dir: String,

    // ── Ports ─────────────────────────────────────
    #[serde(default = "default_ports_config")]
    pub ports_config: String,

    // ── SQL Connections (agent + wolfflow) ────────
    #[serde(default = "default_sql_connections_config")]
    pub sql_connections_config: String,
    #[serde(default = "default_sql_audit_log")]
    pub sql_audit_log: String,

    // ── Wake-on-LAN targets (per node, never replicated) ──
    #[serde(default = "default_wol_targets_config")]
    pub wol_targets_config: String,

    // ── Fleet Logs (loghub) ───────────────────────
    // Bulk log-segment store lives under the data dir, NOT /etc — it grows
    // and is not config. Config (enable/hub/retention) is a small JSON file.
    #[serde(default = "default_loghub_dir")]
    pub loghub_dir: String,
    #[serde(default = "default_loghub_config")]
    pub loghub_config: String,
}

// ── Default value functions ──────────────────────────

fn default_config_dir() -> String { "/etc/wolfstack".into() }

fn default_backup_config() -> String { "/etc/wolfstack/backups.json".into() }
/// Staging is where a whole container/VM archive is built before it is shipped
/// to its destination, so it needs room for the largest single guest on the
/// node. The old default, `/tmp/wolfstack-backups`, is tmpfs (RAM) on most
/// systemd distros: on 2026-07-21 a 32 GB LXC tarball filled wolfstack-1's
/// 32 GB /tmp and every later container backup came back 0 bytes. Default to
/// disk instead, and fall back to the old path only if /var/lib is unusable.
/// An explicit `backup_staging_dir` in paths.json always wins.
fn default_backup_staging_dir() -> String {
    let preferred = "/var/lib/wolfstack/backup-staging";
    if std::fs::create_dir_all(preferred).is_ok() && !dir_is_memory_backed(preferred) {
        return preferred.into();
    }
    "/tmp/wolfstack-backups".into()
}

/// Directory for staging a large archive before it ships somewhere — a container
/// migration image, a backup bundle.
///
/// Reuses the operator's `backup_staging_dir`: it is the one path they have
/// already pointed at somewhere with room. Refuses to hand back a RAM-backed
/// directory, because staging a multi-GB image on tmpfs spends exactly the
/// memory the transfer itself needs — `docker save -o /tmp/...` on a stock
/// Debian 13 (tmpfs /tmp) put the whole image in RAM before curl had even been
/// invoked. Same failure shape as the 2026-07-21 wolfstack-1 incident described
/// on `default_backup_staging_dir`.
pub fn transfer_staging_dir() -> String {
    let configured = get().backup_staging_dir.clone();
    if std::fs::create_dir_all(&configured).is_ok() && !dir_is_memory_backed(&configured) {
        return configured;
    }
    let fallback = "/var/lib/wolfstack/transfer-staging";
    if std::fs::create_dir_all(fallback).is_ok() && !dir_is_memory_backed(fallback) {
        tracing::warn!(
            "staging: {} is memory-backed, using {} instead",
            configured, fallback
        );
        return fallback.to_string();
    }
    // Nothing better exists on this host. Proceed and let the caller fail
    // honestly rather than silently writing somewhere unexpected.
    tracing::warn!(
        "staging: no disk-backed staging directory available; using {} (RAM-backed) — \
         a large transfer may exhaust memory",
        configured
    );
    configured
}

/// Whether `path` lives on a RAM-backed filesystem — anything staged there is
/// competing with the machine's memory, not its disk.
///
/// Resolves against /proc/mounts by longest matching mount point, so a nested
/// mount (e.g. tmpfs on /var/lib/wolfstack) is reported correctly rather than
/// being masked by its parent.
pub fn dir_is_memory_backed(path: &str) -> bool {
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    matches!(fstype_for_path(&mounts, path).as_deref(), Some("tmpfs") | Some("ramfs"))
}

/// Filesystem type of the mount containing `path`, given /proc/mounts content.
///
/// Split out from `dir_is_memory_backed` so the matching rules are testable
/// without depending on how the host happens to be mounted.
fn fstype_for_path(mounts: &str, path: &str) -> Option<String> {
    let mut best: Option<(usize, String)> = None;
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        let (_device, mount_point, fstype) = match (fields.next(), fields.next(), fields.next()) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => continue,
        };
        // A mount point only contains `path` if it matches on whole path
        // components — "/var/lib" must not be read as covering "/var/libexec".
        let contains = path == mount_point
            || mount_point == "/"
            || path.strip_prefix(mount_point).is_some_and(|rest| rest.starts_with('/'));
        if !contains {
            continue;
        }
        // Deepest match wins, so a tmpfs nested inside a disk mount is seen.
        if best.as_ref().is_none_or(|(depth, _)| mount_point.len() > *depth) {
            best = Some((mount_point.len(), fstype.to_string()));
        }
    }
    best.map(|(_, fstype)| fstype)
}
fn default_backup_received_dir() -> String { "/var/lib/wolfstack/backups/received".into() }
fn default_backup_local_dir() -> String { "/var/lib/wolfstack/backups".into() }
fn default_compose_dir() -> String { "/etc/wolfstack/compose".into() }

fn default_storage_config() -> String { "/etc/wolfstack/storage.json".into() }
fn default_s3_sync_log_dir() -> String { "/var/log/wolfstack/s3-sync".into() }
fn default_gluster_config() -> String { "/etc/wolfstack/gluster.json".into() }
fn default_storage_mount_base() -> String { "/mnt/wolfstack".into() }
fn default_s3_credentials_dir() -> String { "/etc/wolfstack/s3".into() }
fn default_s3_cache_dir() -> String { "/var/cache/wolfstack/s3".into() }

fn default_nodes_config() -> String { "/etc/wolfstack/nodes.json".into() }
fn default_deleted_nodes_config() -> String { "/etc/wolfstack/deleted_nodes.json".into() }
fn default_self_cluster_config() -> String { "/etc/wolfstack/self_cluster.json".into() }
fn default_self_site_config() -> String { "/etc/wolfstack/self_site.json".into() }
fn default_self_display_name_config() -> String { "/etc/wolfstack/self_display_name.json".into() }
fn default_self_roles_config() -> String { "/etc/wolfstack/self_roles.json".into() }
fn default_pending_identity_config() -> String { "/etc/wolfstack/pending_identity.json".into() }
fn default_node_id_file() -> String { "/etc/wolfstack/node_id".into() }
fn default_xo_pools_config() -> String { "/etc/wolfstack/xo_pools.json".into() }
fn default_truenas_config() -> String { "/etc/wolfstack/truenas.json".into() }
fn default_unraid_config() -> String { "/etc/wolfstack/unraid.json".into() }

fn default_alerts_config() -> String { "/etc/wolfstack/alerts.json".into() }

fn default_statuspage_config() -> String { "/etc/wolfstack/statuspage.json".into() }
fn default_statuspage_uptime() -> String { "/etc/wolfstack/statuspage-uptime.json".into() }

fn default_ai_config() -> String { "/etc/wolfstack/ai-config.json".into() }
fn default_ai_baseline() -> String { "/var/lib/wolfstack/ai-baseline.json".into() }
fn default_ai_suppress_secret() -> String { "/etc/wolfstack/ai-suppress-secret".into() }

fn default_wolfrun_dir() -> String { "/etc/wolfstack/wolfrun".into() }
fn default_wolfrun_services() -> String { "/etc/wolfstack/wolfrun/services.json".into() }
fn default_wolfrun_failover_events() -> String { "/etc/wolfstack/wolfrun/failover-events.json".into() }

fn default_wolffunctions_dir() -> String { "/etc/wolfstack/wolffunctions".into() }
fn default_wolffunctions_functions() -> String { "/etc/wolfstack/wolffunctions/functions.json".into() }
fn default_wolffunctions_runtime_dir() -> String { "/var/lib/wolfstack/wolffunctions".into() }

fn default_wolfflow_dir() -> String { "/etc/wolfstack/wolfflow".into() }
fn default_wolfflow_workflows() -> String { "/etc/wolfstack/wolfflow/workflows.json".into() }
fn default_wolfflow_runs() -> String { "/etc/wolfstack/wolfflow/runs.json".into() }

fn default_kubernetes_config() -> String { "/etc/wolfstack/kubernetes.json".into() }

fn default_appstore_dir() -> String { "/etc/wolfstack/appstore".into() }
fn default_appstore_installed() -> String { "/etc/wolfstack/appstore/installed.json".into() }
fn default_appstore_pending_dir() -> String { "/etc/wolfstack/appstore/pending".into() }

fn default_ceph_config() -> String { "/etc/wolfstack/ceph.json".into() }

fn default_vms_dir() -> String { "/var/lib/wolfstack/vms".into() }

fn default_tls_cert() -> String { "/etc/wolfstack/cert.pem".into() }
fn default_tls_key() -> String { "/etc/wolfstack/key.pem".into() }

fn default_cluster_secret() -> String { "/etc/wolfstack/custom-cluster-secret".into() }

fn default_patreon_config() -> String { "/etc/wolfstack/patreon.json".into() }

fn default_ip_mappings() -> String { "/etc/wolfstack/ip-mappings.json".into() }

fn default_lxc_paths() -> String { "/etc/wolfstack/lxc-paths.json".into() }

fn default_cluster_containers_dir() -> String { "/etc/wolfstack/cluster-containers".into() }

fn default_icon_packs_dir() -> String { "/etc/wolfstack/icon-packs".into() }

fn default_pbs_config() -> String { "/etc/wolfstack/pbs/config.json".into() }

fn default_wolfnote_config() -> String { "/etc/wolfstack/wolfnote.json".into() }

fn default_web_dir() -> String { "/opt/wolfstack/web".into() }

fn default_ports_config() -> String { "/etc/wolfstack/ports.json".into() }

fn default_sql_connections_config() -> String { "/etc/wolfstack/sql-connections.json".into() }
fn default_sql_audit_log() -> String { "/var/log/wolfstack/sql-audit.log".into() }

fn default_wol_targets_config() -> String { "/etc/wolfstack/wol-targets.json".into() }

fn default_loghub_dir() -> String { "/var/lib/wolfstack/loghub".into() }
fn default_loghub_config() -> String { "/etc/wolfstack/loghub.json".into() }

impl Default for FileLocations {
    fn default() -> Self {
        serde_json::from_str("{}").unwrap()
    }
}

// ── Global singleton ─────────────────────────────────

static LOCATIONS: LazyLock<RwLock<FileLocations>> = LazyLock::new(|| {
    let locs = load_from_disk();
    RwLock::new(locs)
});

fn load_from_disk() -> FileLocations {
    match std::fs::read_to_string(PATHS_CONFIG_FILE) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => FileLocations::default(),
    }
}

/// Get a snapshot of the current file locations.
pub fn get() -> FileLocations {
    LOCATIONS.read().unwrap().clone()
}

/// Test-only: override the in-memory locations WITHOUT persisting to
/// disk. Lets tests point staging/config at a writable temp dir on a
/// dev box whose real /etc/wolfstack + /tmp/wolfstack-backups are
/// root-owned. Not compiled into the shipped binary.
#[cfg(test)]
pub fn set_for_test(locs: FileLocations) {
    *LOCATIONS.write().unwrap() = locs;
}

/// Update file locations and persist to disk.
pub fn update(locs: FileLocations) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&locs)
        .map_err(|e| format!("Failed to serialize paths config: {}", e))?;
    // 0600 — this file decides where secrets get written. An attacker
    // who can edit paths.json can redirect write_secure targets to
    // attacker-controlled locations. harden_existing covers the old
    // file on upgrade; write_secure covers fresh writes.
    write_secure(PATHS_CONFIG_FILE, json)
        .map_err(|e| format!("Failed to write paths config: {}", e))?;
    *LOCATIONS.write().unwrap() = locs;
    Ok(())
}

// ── Secure-write helpers ─────────────────────────────────────────────
//
// Prior to v18.7.27 every `std::fs::write` in the codebase inherited
// the process umask (typically 022), so secrets like the cluster
// secret, PVE tokens in nodes.json, and the join-token were created
// world-readable (0644). Any unprivileged local user could read them.
// These helpers plug that hole for NEW writes; `harden_existing()`
// fixes installs that already have the bad permissions.

/// Write a file with mode 0600 (owner-only). Used for anything
/// carrying credentials or auth tokens — cluster secret, join-token,
/// nodes.json (which contains pve_token fields), license.key.
///
/// Creates parent directories with mode 0700 as needed. On non-Unix
/// platforms mode is ignored (WolfStack is Linux-only in practice
/// but the code stays portable).
pub fn write_secure(path: &str, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    use std::io::Write;
    // Ensure parent exists. We don't chmod the parent here — that's
    // harden_existing()'s job, done once at startup, so we don't race
    // with other writers mid-operation.
    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents.as_ref())?;
        // If the file existed before with looser perms, the mode
        // argument above is ignored — explicitly enforce 0600 now.
        let _ = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600));
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true)
            .open(path)?;
        f.write_all(contents.as_ref())
    }
}

/// Wait, briefly and only when it will help, for the config directory to
/// become available before anything reads config from it.
///
/// On Unraid `/etc/wolfstack` is a symlink into appdata, which does not exist
/// until the array mounts. An agent that starts first reads NO config and
/// silently adopts defaults — most damagingly the built-in cluster secret,
/// which leaves the node polling and reporting online while every proxied
/// request is rejected by peers with 401 and none of its pages load
/// (klas, 2026-07-31).
///
/// Only a *dangling symlink* triggers the wait: that is the signal that the
/// target is expected but not mounted yet. A plainly absent directory is a
/// fresh install creating it for the first time and must never delay startup,
/// and a healthy host returns immediately. Bounded, so boot cannot hang.
pub async fn wait_for_config_dir(max_secs: u64) {
    let dir = get().config_dir.clone();
    let path = std::path::PathBuf::from(&dir);
    let dangling = |p: &std::path::Path| {
        std::fs::symlink_metadata(p).is_ok() && std::fs::metadata(p).is_err()
    };
    if !dangling(&path) {
        return;
    }
    tracing::warn!(
        "config directory {} is a symlink whose target is not available yet (array not mounted?) \
         — waiting up to {}s rather than starting on defaults",
        dir, max_secs
    );
    let mut waited = 0;
    while waited < max_secs {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        waited += 2;
        if !dangling(&path) {
            tracing::info!("config directory {} became available after {}s", dir, waited);
            return;
        }
    }
    tracing::error!(
        "config directory {} is still unavailable after {}s — starting with DEFAULTS. On a \
         clustered node that means the built-in cluster secret, and peers will reject every \
         proxied request with 401 while this node still reports itself online.",
        dir, max_secs
    );
}

/// One-shot: tighten permissions on `/etc/wolfstack` and any known
/// sensitive file that might already exist with 0644 from a pre-v18.7.27
/// install. Called once from main at startup. Silent on failure
/// (best-effort — not every install runs as root all the time, and a
/// failed chmod shouldn't block boot).
pub fn harden_existing() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let locs = get();
        // Directory: 0700 on /etc/wolfstack so the directory listing is
        // owner-only. Files inside inherit nothing from dir mode, but
        // a readable dir makes targeted secret-file reads easier for
        // an attacker even when the files themselves are locked down.
        if let Ok(meta) = std::fs::metadata(&locs.config_dir) {
            let _ = std::fs::set_permissions(
                &locs.config_dir,
                std::fs::Permissions::from_mode(0o700),
            );
            let _ = meta; // silence unused on some toolchains
        }
        // Files known to hold credentials or cluster auth state.
        // Legacy paths are included because old installs may still
        // carry `/etc/wolfstack/cluster-secret` from v11.26.3 even
        // though current code writes `custom-cluster-secret`.
        //
        // Extended list (v18.7.30) covers every writer migrated to
        // write_secure — existing installs get permissions tightened
        // on the next restart without needing the file to be rewritten.
        let sensitive = [
            locs.cluster_secret.clone(),
            "/etc/wolfstack/cluster-secret".to_string(),
            locs.nodes_config.clone(),
            "/etc/wolfstack/join-token".to_string(),
            "/etc/wolfstack/license.key".to_string(),
            locs.tls_key.clone(),
            "/etc/wolfstack/users.json".to_string(),         // password hashes
            "/etc/wolfstack/auth-config.json".to_string(),   // auth tuning
            "/etc/wolfstack/oidc.json".to_string(),          // OIDC client secrets
            "/etc/wolfstack/ai-config.json".to_string(),     // LLM API keys + SMTP pass
            "/etc/wolfstack/pbs/config.json".to_string(),    // PBS tokens
            // backups.json carries pbs_password / smb_password / secret_key /
            // access_key / pbs_token_secret in cleartext and shipped 0644
            // root:root until v25.6.8 — every install predating that fix is
            // still world-readable until this runs (production report, 3-node
            // "wolf" cluster, 2026-07-30).
            locs.backup_config.clone(),
            "/etc/wolfstack/backups.json".to_string(),       // default path, if remapped above
            // storage.json carries SMB `password` and S3 `secret_access_key`
            // in cleartext (see storage::SmbConfig / S3Config) and was written
            // with a plain fs::write — so 0644 root:root on every install
            // predating this entry, exactly the backups.json hole again.
            locs.storage_config.clone(),
            "/etc/wolfstack/storage.json".to_string(),       // default path, if remapped above
            "/etc/wolfstack/pbs/targets.json".to_string(),   // additional PBS destinations + their tokens
            "/etc/wolfstack/paths.json".to_string(),         // path remap — if attacker-controlled, can redirect secret writers
            "/etc/ppp/chap-secrets".to_string(),             // PPPoE passwords (WAN)
            "/etc/ppp/pap-secrets".to_string(),
        ];
        for path in &sensitive {
            if std::path::Path::new(path).exists() {
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
        // Sensitive directories — /etc/wolfstack/s3 contains per-mount
        // credentials files; /etc/wolfstack/config-backups holds whole-config
        // snapshots that embed storage / AI / PBS credentials. Lock the
        // directory itself (0700) AND every file inside it (0600). The runtime
        // already sets these on write, but harden a dir that pre-existed at
        // looser perms (e.g. created by a manual restore).
        let sensitive_dirs = [
            "/etc/wolfstack/s3",
            "/etc/wolfstack/config-backups",
        ];
        for dir in &sensitive_dirs {
            let p = std::path::Path::new(dir);
            if p.exists() {
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
                if let Ok(entries) = std::fs::read_dir(p) {
                    for entry in entries.flatten() {
                        let _ = std::fs::set_permissions(
                            entry.path(),
                            std::fs::Permissions::from_mode(0o600),
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod staging_fstype_tests {
    use super::*;

    const MOUNTS: &str = "\
/dev/sda1 / ext4 rw,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0
/dev/sdb1 /var/lib ext4 rw,relatime 0 0
tmpfs /var/lib/wolfstack/backup-staging tmpfs rw 0 0
";

    #[test]
    fn deepest_mount_wins() {
        // The wolfstack-1 shape: a tmpfs nested inside a disk-backed parent.
        assert_eq!(fstype_for_path(MOUNTS, "/var/lib/wolfstack/backup-staging").as_deref(), Some("tmpfs"));
        assert_eq!(fstype_for_path(MOUNTS, "/var/lib/wolfstack/backups").as_deref(), Some("ext4"));
    }

    #[test]
    fn the_old_default_is_recognised_as_memory_backed() {
        assert_eq!(fstype_for_path(MOUNTS, "/tmp/wolfstack-backups").as_deref(), Some("tmpfs"));
    }

    #[test]
    fn matching_respects_path_components() {
        // "/var/lib" must not claim "/var/libexec" — that would report the
        // wrong filesystem and either warn wrongly or miss a real tmpfs.
        assert_eq!(fstype_for_path(MOUNTS, "/var/libexec/staging").as_deref(), Some("ext4"));
        assert_eq!(fstype_for_path(MOUNTS, "/tmpfoo/staging").as_deref(), Some("ext4"));
    }

    #[test]
    fn falls_back_to_root_and_survives_junk() {
        assert_eq!(fstype_for_path(MOUNTS, "/srv/backups").as_deref(), Some("ext4"));
        assert_eq!(fstype_for_path("", "/anything"), None);
        assert_eq!(fstype_for_path("garbage line\nalso bad", "/anything"), None);
    }

    #[test]
    fn dev_shm_is_memory_backed_on_this_host() {
        // Sanity-check the real /proc/mounts path: /dev/shm is tmpfs on Linux.
        assert!(dir_is_memory_backed("/dev/shm"));
    }
}
