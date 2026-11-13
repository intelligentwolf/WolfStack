// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com
//
//! Galera cluster manager.
//!
//! Create or adopt MariaDB Galera clusters built from LXC containers across
//! the WolfStack cluster, then monitor and recover them. A cluster is a small
//! fellowship of nodes that must stay in lock-step; this module's job is to
//! keep that fellowship from fracturing (split-brain) and, when it does, to
//! rejoin it from the most-advanced survivor.
//!
//! Layers:
//!   * model + persistence (`/etc/wolfstack/galera.json`)
//!   * live status via SQL `SHOW GLOBAL STATUS LIKE 'wsrep_%'` per node
//!   * provisioning (create LXC + install MariaDB + configure wsrep + bootstrap)
//!   * lifecycle + evidence-based recovery (grastate.dat seqno)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use crate::node_identity::PeerAuth;

const GALERA_CONFIG_PATH: &str = "/etc/wolfstack/galera.json";
const GALERA_SECRET_PURPOSE: &[u8] = b"galera-cluster-secret-v1";

/// Serializes read-modify-write cycles on galera.json so concurrent writers
/// (a recovery self-heal racing an adopt/provision/delete) can't clobber each
/// other's update. Held only across sync file IO — never across an `.await`.
static GALERA_IO_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn default_mysql_port() -> u16 { 3306 }
fn default_sst() -> String { "mariabackup".into() }
fn default_db_user() -> String { "root".into() }
fn default_kind() -> String { "lxc".into() }

/// One MariaDB/Galera node — a container on a WolfStack host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GaleraNode {
    /// WolfStack host node id that runs this container.
    #[serde(default)]
    pub node_id: String,
    /// Container name on that host.
    pub container: String,
    /// Container runtime: "lxc" (default) or "docker" — decides how lifecycle
    /// ops exec into it (lxc-attach/pct vs docker exec).
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Address other nodes reach it on (WolfNet IP recommended) — used for
    /// gcomm:// peering and for status queries.
    pub address: String,
    #[serde(default = "default_mysql_port")]
    pub port: u16,
    /// wsrep_node_name (defaults to the container name when empty).
    #[serde(default)]
    pub node_name: String,
}

/// A managed Galera cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GaleraCluster {
    pub id: String,
    /// wsrep_cluster_name.
    pub name: String,
    /// WolfStack cluster this Galera cluster belongs to (scopes the UI). Empty
    /// on configs written before cluster-scoping; treated as unscoped.
    #[serde(default)]
    pub cluster: String,
    /// WolfStack host node id whose galera.json stores this cluster's definition
    /// (the node it was built/adopted on). The UI aggregates configs across the
    /// WS cluster's nodes and routes each cluster's ops back to its owner.
    #[serde(default)]
    pub owner_node: String,
    #[serde(default)]
    pub nodes: Vec<GaleraNode>,
    /// SST method: "mariabackup" (recommended) or "rsync".
    #[serde(default = "default_sst")]
    pub sst_method: String,
    /// DB user for status queries + management (typically "root").
    #[serde(default = "default_db_user")]
    pub db_user: String,
    /// AES-256-GCM encrypted DB password (never serialised in plaintext).
    #[serde(default)]
    pub db_password_enc: String,
    #[serde(default)]
    pub created_at: String,
    /// True for clusters WolfStack provisioned (vs adopted existing).
    #[serde(default)]
    pub provisioned: bool,
    /// MaxScale proxies WolfStack provisioned in front of this cluster. Kept here
    /// (not in `nodes`) because a proxy is NOT a Galera member — status, recovery
    /// and the gcomm member list must never treat it as one.
    #[serde(default)]
    pub proxies: Vec<MaxScaleProxy>,
}

/// A MaxScale proxy provisioned in front of a Galera cluster. The readwritesplit
/// listener is the single endpoint apps point at; MaxScale routes writes to the
/// primary and spreads reads across the synced members.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaxScaleProxy {
    /// WolfStack host node id that runs the proxy container.
    #[serde(default)]
    pub node_id: String,
    /// Proxy container name on that host (always LXC).
    pub container: String,
    /// Address apps reach the proxy on (its WolfNet IP).
    pub address: String,
    /// readwritesplit listener port (the endpoint apps connect to).
    #[serde(default = "default_mysql_port")]
    pub listener_port: u16,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GaleraConfig {
    #[serde(default)]
    pub clusters: Vec<GaleraCluster>,
}

// ── Persistence ──────────────────────────────────────────────────────

pub fn load_config() -> GaleraConfig {
    match fs::read_to_string(GALERA_CONFIG_PATH) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => GaleraConfig::default(),
    }
}

pub fn save_config(cfg: &GaleraConfig) -> Result<(), String> {
    if let Some(parent) = Path::new(GALERA_CONFIG_PATH).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(GALERA_CONFIG_PATH, json)
        .map_err(|e| format!("write {}: {}", GALERA_CONFIG_PATH, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(GALERA_CONFIG_PATH, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn get_cluster(id: &str) -> Option<GaleraCluster> {
    load_config().clusters.into_iter().find(|c| c.id == id)
}

/// Upsert a cluster (used by both adopt and create). Re-encrypts a non-empty
/// plaintext password into `db_password_enc`.
pub fn upsert_cluster(mut cluster: GaleraCluster, plain_password: Option<&str>) -> Result<GaleraCluster, String> {
    // Validate every value that later reaches a shell, an LXC command, a config
    // file, or a DOM onclick handler. These are names + addresses, not free
    // text — reject bad input rather than trying to escape it everywhere.
    safe_token(&cluster.name)?;
    if !cluster.sst_method.trim().is_empty() {
        safe_token(&cluster.sst_method)?;
    }
    for n in &cluster.nodes {
        safe_token(&n.container)?;
        if !n.node_name.trim().is_empty() {
            safe_token(&n.node_name)?;
        }
        if !valid_address(&n.address) {
            return Err(format!("invalid node address '{}' (expected an IP or hostname)", n.address));
        }
    }

    for n in cluster.nodes.iter_mut() {
        if n.node_name.trim().is_empty() {
            n.node_name = n.container.clone();
        }
    }
    // The config lives wherever it's saved — record that host so the UI can
    // aggregate across the cluster and route this cluster's ops back here.
    if cluster.owner_node.is_empty() {
        cluster.owner_node = crate::agent::self_node_id();
    }

    // Hold the IO lock across the read-modify-write so a concurrent writer
    // (e.g. a recovery self-heal) can't clobber this save. No `.await` inside.
    let _io = GALERA_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut cfg = load_config();
    // Never trust a client-supplied ciphertext: the stored secret is derived
    // ONLY from a fresh plaintext. When none is given (an edit that omits the
    // password), preserve whatever we already had for this id.
    let existing_enc = cfg.clusters.iter().find(|c| c.id == cluster.id)
        .map(|c| c.db_password_enc.clone()).unwrap_or_default();
    cluster.db_password_enc = match plain_password {
        Some(pw) if !pw.is_empty() => enc_secret(pw),
        _ => existing_enc,
    };
    match cfg.clusters.iter_mut().find(|c| c.id == cluster.id) {
        Some(slot) => *slot = cluster.clone(),
        None => cfg.clusters.push(cluster.clone()),
    }
    save_config(&cfg)?;
    Ok(cluster)
}

pub fn delete_cluster(id: &str) -> Result<(), String> {
    let _io = GALERA_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut cfg = load_config();
    let before = cfg.clusters.len();
    cfg.clusters.retain(|c| c.id != id);
    if cfg.clusters.len() == before {
        return Err(format!("cluster '{}' not found", id));
    }
    save_config(&cfg)
}

// ── Secrets (AES-256-GCM via at_rest_crypto, same as DNS/edge stores) ──

/// Re-tag stored clusters when a WolfStack cluster is renamed
/// (case-insensitive; empty/unscoped tags untouched). Returns changes.
pub fn rename_wolfstack_cluster_tags(old_name: &str, new_name: &str) -> usize {
    let mut cfg = load_config();
    let mut n = 0;
    for c in cfg.clusters.iter_mut() {
        if !c.cluster.is_empty() && c.cluster.eq_ignore_ascii_case(old_name) {
            c.cluster = new_name.to_string();
            n += 1;
        }
    }
    if n > 0 { let _ = save_config(&cfg); }
    n
}

pub fn enc_secret(plain: &str) -> String {
    crate::at_rest_crypto::encrypt(plain.as_bytes(), GALERA_SECRET_PURPOSE).unwrap_or_default()
}

pub fn dec_secret(stored: &str) -> String {
    if stored.is_empty() {
        return String::new();
    }
    crate::at_rest_crypto::decrypt_or_legacy(stored, GALERA_SECRET_PURPOSE, |_| String::new())
}

// ── Live status ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub container: String,
    pub address: String,
    pub reachable: bool,
    #[serde(default)]
    pub error: String,
    /// wsrep_local_state_comment (Synced / Joining / Donor/Desynced / ...).
    pub state: String,
    /// wsrep_cluster_size as seen by THIS node.
    pub cluster_size: i64,
    /// wsrep_cluster_status (Primary / non-Primary / Disconnected).
    pub cluster_status: String,
    /// wsrep_ready (ON/OFF).
    pub ready: bool,
    /// wsrep_cluster_state_uuid — identifies the segment a node belongs to.
    pub cluster_uuid: String,
    /// wsrep_connected.
    pub connected: bool,
    // ── Metrics for per-node charts (0 when unavailable) ──
    /// wsrep_local_recv_queue_avg — apply (write-set) backlog. Rising = this
    /// node can't keep up applying replicated writes.
    pub recv_queue_avg: f64,
    /// wsrep_local_send_queue_avg — replication send backlog.
    pub send_queue_avg: f64,
    /// wsrep_flow_control_paused — fraction of time (0..1) the cluster was
    /// paused by THIS node's flow control. High = this node throttles the rest.
    pub flow_control_paused: f64,
    /// wsrep_received — total write-sets received (counter → txns/sec via deltas).
    pub received: i64,
    /// wsrep_local_cert_failures — total certification conflicts (counter → /sec).
    pub cert_failures: i64,
    /// Threads_connected — current open connections (gauge).
    pub threads_connected: i64,
    /// @@max_connections — the connection ceiling (so the UI can warn near it).
    pub max_connections: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterStatus {
    pub cluster_id: String,
    pub nodes: Vec<NodeStatus>,
    /// Every node reachable, Synced, Primary, agreeing on one UUID + size.
    pub healthy: bool,
    /// Reachable nodes disagree on cluster UUID or size — the split-brain
    /// signal. The fellowship has fractured into separate components.
    pub split_brain: bool,
    pub summary: String,
}

pub async fn cluster_status(cluster: &GaleraCluster) -> ClusterStatus {
    let pw = dec_secret(&cluster.db_password_enc);
    // Query every node CONCURRENTLY — a slow/unreachable node must not stack its
    // 5s connect timeout onto the others and blow the node-proxy deadline (which
    // surfaces as a useless "status unavailable" instead of per-node detail).
    let nodes: Vec<NodeStatus> = futures::future::join_all(
        cluster.nodes.iter().map(|n| node_status(n, &cluster.db_user, &pw))
    ).await;

    let reachable: Vec<&NodeStatus> = nodes.iter().filter(|s| s.reachable).collect();
    let uuids: HashSet<&str> = reachable.iter()
        .map(|s| s.cluster_uuid.as_str())
        .filter(|u| !u.is_empty())
        .collect();
    let sizes: HashSet<i64> = reachable.iter()
        .filter(|s| s.cluster_status.eq_ignore_ascii_case("Primary"))
        .map(|s| s.cluster_size)
        .collect();
    // Split-brain: two or more reachable nodes in DIFFERENT primary segments
    // (distinct UUIDs), or Primary nodes that disagree on the member count.
    let split_brain = uuids.len() > 1 || sizes.len() > 1;
    let all_synced = !reachable.is_empty() && reachable.iter().all(|s| {
        s.state.eq_ignore_ascii_case("Synced")
            && s.ready
            && s.cluster_status.eq_ignore_ascii_case("Primary")
    });
    let healthy = all_synced && !split_brain && reachable.len() == cluster.nodes.len();

    let summary = if cluster.nodes.is_empty() {
        "No nodes registered".to_string()
    } else if split_brain {
        "Split-brain — nodes disagree on cluster membership".to_string()
    } else if healthy {
        format!("Healthy — {}/{} nodes Synced", reachable.len(), cluster.nodes.len())
    } else if reachable.is_empty() {
        "Down — no nodes reachable".to_string()
    } else {
        format!("Degraded — {}/{} nodes reachable", reachable.len(), cluster.nodes.len())
    };

    ClusterStatus {
        cluster_id: cluster.id.clone(),
        nodes,
        healthy,
        split_brain,
        summary,
    }
}

async fn node_status(n: &GaleraNode, user: &str, password: &str) -> NodeStatus {
    let mut st = NodeStatus {
        container: n.container.clone(),
        address: n.address.clone(),
        reachable: false,
        error: String::new(),
        state: String::new(),
        cluster_size: 0,
        cluster_status: String::new(),
        ready: false,
        cluster_uuid: String::new(),
        connected: false,
        recv_queue_avg: 0.0,
        send_queue_avg: 0.0,
        flow_control_paused: 0.0,
        received: 0,
        cert_failures: 0,
        threads_connected: 0,
        max_connections: 0,
    };
    let params = crate::mysql_editor::ConnParams {
        host: n.address.clone(),
        port: n.port,
        user: user.to_string(),
        password: password.to_string(),
        database: None,
        db_type: crate::mysql_editor::DbType::default(),
    };
    // Full status (not just wsrep_%) so we also get Threads_connected + the
    // wsrep counters the metrics dashboard charts.
    match crate::mysql_editor::execute_query(&params, "", "SHOW GLOBAL STATUS").await {
        Ok(v) => {
            st.reachable = true;
            let m = wsrep_map(&v);
            st.state = m.get("wsrep_local_state_comment").cloned().unwrap_or_default();
            st.cluster_size = m.get("wsrep_cluster_size").and_then(|s| s.parse().ok()).unwrap_or(0);
            st.cluster_status = m.get("wsrep_cluster_status").cloned().unwrap_or_default();
            st.ready = m.get("wsrep_ready").map(|s| s.eq_ignore_ascii_case("ON")).unwrap_or(false);
            st.cluster_uuid = m.get("wsrep_cluster_state_uuid").cloned().unwrap_or_default();
            st.connected = m.get("wsrep_connected").map(|s| s.eq_ignore_ascii_case("ON")).unwrap_or(false);
            let f = |k: &str| m.get(k).and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0);
            let i = |k: &str| m.get(k).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
            st.recv_queue_avg = f("wsrep_local_recv_queue_avg");
            st.send_queue_avg = f("wsrep_local_send_queue_avg");
            st.flow_control_paused = f("wsrep_flow_control_paused");
            st.received = i("wsrep_received");
            st.cert_failures = i("wsrep_local_cert_failures");
            st.threads_connected = i("Threads_connected");
            // The connection ceiling is a variable, not a status — one cheap query.
            if let Ok(mv) = crate::mysql_editor::execute_query(&params, "", "SHOW VARIABLES LIKE 'max_connections'").await {
                st.max_connections = wsrep_map(&mv).get("max_connections").and_then(|s| s.parse().ok()).unwrap_or(0);
            }
        }
        Err(e) => st.error = e,
    }
    st
}

/// Flatten a `SHOW STATUS`/`SHOW VARIABLES` resultset (`{columns, rows}` where
/// each row is `[Variable_name, Value]`) into a name→value map.
fn wsrep_map(v: &serde_json::Value) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Some(rows) = v.get("rows").and_then(|r| r.as_array()) {
        for row in rows {
            if let Some([name, val, ..]) = row.as_array().map(Vec::as_slice)
                && let (Some(name), Some(val)) = (name.as_str(), val.as_str())
            {
                m.insert(name.to_string(), val.to_string());
            }
        }
    }
    m
}

// ── Provisioning + lifecycle (LXC + MariaDB + Galera) ────────────────
//
// CAVEAT: the install/bootstrap/recovery shell below follows standard Galera
// practice, but auto-provisioning and auto-recovering a clustered database is
// data-loss-critical and CANNOT be validated without a real multi-node test.
// Recovery is deliberately conservative — it refuses to bootstrap a node whose
// committed position is unknown, rather than guessing (which is how a stale
// node bootstrapping wipes the cluster's progress).

use std::sync::mpsc::Sender;

fn logln(log: &Sender<String>, msg: impl Into<String>) {
    let _ = log.send(msg.into());
}

/// Validate a name that will be interpolated into a shell command — keeps the
/// provisioner from ever building a command from attacker-controlled input.
fn safe_token(s: &str) -> Result<(), String> {
    // Reject `..` too: these names ride in inter-node URL path segments
    // (/api/galera/local/{op}/{container}), so a `..` would be path traversal.
    if s.is_empty() || s.len() > 64 || s.contains("..")
        || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!("invalid name '{}' (allowed: letters, digits, - _ .)", s));
    }
    Ok(())
}

/// Validate a node address (IPv4 / IPv6 / hostname) before it is stored. Keeps
/// injection out of gcomm config + DOM handlers without rejecting real hosts.
fn valid_address(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'))
}

/// Run a command inside a container by runtime; stdout on success, stderr on
/// failure. "docker" → `docker exec`; "lxc" → `pct exec` on Proxmox else
/// `lxc-attach`. So an adopted Docker MariaDB is managed the same as an LXC one.
fn cexec(kind: &str, container: &str, cmd: &str) -> Result<String, String> {
    let mut c = if kind == "docker" {
        let mut c = std::process::Command::new("docker");
        c.arg("exec").arg(container).arg("sh").arg("-c").arg(cmd);
        c
    } else if std::process::Command::new("which").arg("pct").output().map(|o| o.status.success()).unwrap_or(false) {
        let mut c = std::process::Command::new("pct");
        c.arg("exec").arg(container).arg("--").arg("sh").arg("-c").arg(cmd);
        c
    } else {
        let mut c = std::process::Command::new("lxc-attach");
        c.arg("-n").arg(container).arg("--").arg("sh").arg("-c").arg(cmd);
        c
    };
    let out = c.output().map_err(|e| format!("{} exec {}: {}", kind, container, e))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!("[{}] command failed: {}", container, String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// LXC-only exec wrapper for the provisioner (which only ever builds LXC nodes).
fn lxc_exec(container: &str, cmd: &str) -> Result<String, String> {
    cexec("lxc", container, cmd)
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionRequest {
    pub cluster_name: String,
    /// WolfStack cluster this Galera cluster belongs to (scopes the UI).
    #[serde(default)]
    pub cluster: String,
    pub node_count: usize,
    #[serde(default = "default_prefix")]
    pub name_prefix: String,
    /// Explicit per-node container names. When non-empty, these are used (and
    /// drive node_count); otherwise `{name_prefix}-{i}` is generated.
    #[serde(default)]
    pub container_names: Vec<String>,
    /// Per-node target host (WolfStack node self_id), parallel to
    /// `container_names`. An entry that's empty or absent falls back to
    /// `node_id` (the home host) — so an all-on-one-host build needs none of
    /// these and behaves exactly as before. Lets a cluster be spread across
    /// different WolfStack hosts for hardware HA at create time.
    #[serde(default)]
    pub container_hosts: Vec<String>,
    #[serde(default = "default_distro")]
    pub distribution: String,
    #[serde(default = "default_release")]
    pub release: String,
    pub root_password: String,
    #[serde(default = "default_sst")]
    pub sst_method: String,
    /// WolfStack host node id these containers live on (recorded on the nodes).
    #[serde(default)]
    pub node_id: String,
}
fn default_prefix() -> String { "galera".into() }
fn default_distro() -> String { "debian".into() }
fn default_release() -> String { "bookworm".into() }

fn distro_family(distro: &str) -> &'static str {
    match distro.to_lowercase().as_str() {
        "debian" | "ubuntu" => "deb",
        "fedora" | "centos" | "rhel" | "rocky" | "almalinux" => "rhel",
        "alpine" => "alpine",
        "arch" | "manjaro" => "arch",
        _ => "deb",
    }
}

fn galera_provider_path(distro: &str) -> &'static str {
    match distro_family(distro) {
        "rhel" => "/usr/lib64/galera/libgalera_smm.so",
        _ => "/usr/lib/galera/libgalera_smm.so",
    }
}

fn galera_cnf_path(distro: &str) -> &'static str {
    match distro_family(distro) {
        "deb" => "/etc/mysql/mariadb.conf.d/60-galera.cnf",
        _ => "/etc/my.cnf.d/galera.cnf",
    }
}

fn install_cmd(distro: &str) -> Result<&'static str, String> {
    Ok(match distro_family(distro) {
        "deb" => "export DEBIAN_FRONTEND=noninteractive; apt-get update -y && apt-get install -y mariadb-server mariadb-client galera-4 mariadb-backup rsync socat",
        "rhel" => "dnf install -y mariadb-server-galera mariadb-backup rsync socat || yum install -y mariadb-server-galera mariadb-backup rsync socat",
        "alpine" => "apk add --no-cache mariadb mariadb-client mariadb-server-utils mariadb-backup rsync socat && (rc-update add mariadb default || true)",
        "arch" => "pacman -Syu --noconfirm mariadb galera rsync socat && mariadb-install-db --user=mysql --basedir=/usr --datadir=/var/lib/mysql",
        other => return Err(format!("unsupported distribution: {}", other)),
    })
}

/// Find the real `libgalera_smm.so` inside a container after install. The path
/// varies by package (galera-3 → /usr/lib/galera, galera-4 → an arch-triple
/// subdir, /usr/lib64 on RHEL), so we read it from disk rather than guessing —
/// a wrong `wsrep_provider` silently fails to load and the bootstrap dies.
/// Falls back to the family default only when the search finds nothing.
fn detect_galera_provider(container: &str, distro: &str) -> String {
    let found = lxc_exec(container, "find /usr/lib /usr/lib64 -name 'libgalera_smm.so' 2>/dev/null | head -1")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if found.is_empty() { galera_provider_path(distro).to_string() } else { found }
}

/// Render a Galera config file for one node. `provider` is the resolved
/// `libgalera_smm.so` path (see `detect_galera_provider`).
fn galera_cnf(provider: &str, cluster_name: &str, gcomm: &str, node_addr: &str, node_name: &str, sst: &str) -> String {
    format!(
        "[galera]\n\
         wsrep_on=ON\n\
         wsrep_provider={provider}\n\
         wsrep_cluster_name=\"{cluster}\"\n\
         wsrep_cluster_address=\"gcomm://{gcomm}\"\n\
         wsrep_node_address=\"{addr}\"\n\
         wsrep_node_name=\"{name}\"\n\
         wsrep_sst_method={sst}\n\
         binlog_format=row\n\
         default_storage_engine=InnoDB\n\
         innodb_autoinc_lock_mode=2\n\
         \n\
         [mysqld]\n\
         bind-address=0.0.0.0\n",
        provider = provider,
        cluster = cluster_name, gcomm = gcomm, addr = node_addr, name = node_name, sst = sst,
    )
}

/// Container-level lifecycle for a Docker node (`docker start|stop|restart`).
/// A MariaDB Docker container's PID 1 *is* mysqld, so the DB is controlled by
/// controlling the container — not by systemctl inside it.
fn docker_lifecycle(action: &str, container: &str) -> Result<String, String> {
    let out = std::process::Command::new("docker").arg(action).arg(container).output()
        .map_err(|e| format!("docker {} {}: {}", action, container, e))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!("[{}] docker {} failed: {}", container, action, String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// Start/stop/restart MariaDB in a node by runtime. Docker → container-level;
/// LXC → systemctl-or-fallback inside (handles mariadb vs mysqld, Alpine OpenRC).
fn svc(kind: &str, container: &str, action: &str) -> Result<String, String> {
    if kind == "docker" {
        docker_lifecycle(action, container)
    } else {
        cexec(kind, container, &format!(
            "systemctl {a} mariadb 2>/dev/null || systemctl {a} mysqld 2>/dev/null || rc-service mariadb {a} 2>/dev/null || true",
            a = action
        ))
    }
}

/// Best-effort wait for a freshly-started container's init + network to settle
/// before we install packages — otherwise apt/dnf race the dpkg lock or hit a
/// not-yet-up network. Capped so a stuck container can't hang provisioning.
fn wait_container_ready(container: &str) {
    let _ = lxc_exec(container,
        "cloud-init status --wait >/dev/null 2>&1; \
         for i in $(seq 1 30); do \
           if command -v systemctl >/dev/null 2>&1; then \
             systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break; \
           else break; fi; \
           sleep 1; \
         done");
}

/// Like `cexec`, but STREAMS the command's combined output line-by-line to the
/// SSE log so the operator watches a long install/bootstrap happen live (a real
/// terminal feel) instead of staring at a frozen "installing…". stderr is
/// merged into stdout so we read a single pipe (no two-pipe deadlock).
fn cexec_streamed(kind: &str, container: &str, cmd: &str, log: &Sender<String>) -> Result<(), String> {
    use std::io::{BufReader, Read};
    use std::process::Stdio;
    let merged = format!("{{ {} ; }} 2>&1", cmd);
    let mut command = if kind == "docker" {
        let mut c = std::process::Command::new("docker");
        c.arg("exec").arg(container).arg("sh").arg("-c").arg(&merged);
        c
    } else if std::process::Command::new("which").arg("pct").output().map(|o| o.status.success()).unwrap_or(false) {
        let mut c = std::process::Command::new("pct");
        c.arg("exec").arg(container).arg("--").arg("sh").arg("-c").arg(&merged);
        c
    } else {
        let mut c = std::process::Command::new("lxc-attach");
        c.arg("-n").arg(container).arg("--").arg("sh").arg("-c").arg(&merged);
        c
    };
    command.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = command.spawn().map_err(|e| format!("{} exec {}: {}", kind, container, e))?;
    if let Some(out) = child.stdout.take() {
        let mut reader = BufReader::new(out);
        let mut byte = [0u8; 1];
        let mut line = String::new();
        while reader.read(&mut byte).unwrap_or(0) > 0 {
            let ch = byte[0] as char;
            if ch == '\n' || ch == '\r' {
                let t = line.trim_end();
                if !t.is_empty() { let _ = log.send(format!("  {}", t)); }
                line.clear();
            } else {
                line.push(ch);
            }
        }
        let t = line.trim_end();
        if !t.is_empty() { let _ = log.send(format!("  {}", t)); }
    }
    let status = child.wait().map_err(|e| format!("[{}] wait failed: {}", container, e))?;
    if status.success() { Ok(()) } else { Err(format!("[{}] command failed (see output above)", container)) }
}

/// Install MariaDB+Galera with a few retries (a transient dpkg lock or mirror
/// hiccup shouldn't abort the provision), streaming live output to the log.
fn run_install(container: &str, install: &str, log: &Sender<String>) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 1..=3 {
        match cexec_streamed("lxc", container, install, log) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last = e;
                if attempt < 3 {
                    logln(log, format!("[{}] install attempt {} failed — retrying in 5s…", container, attempt));
                    // Host-side sleep: an in-container `sleep` would itself fail
                    // when the container is the reason the install failed.
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
            }
        }
    }
    Err(last)
}

/// Provision a brand-new Galera cluster. Each node's container is built on ITS
/// chosen WolfStack host (`container_hosts[i]`, defaulting to the home host
/// `node_id`), so a cluster can be spread across hosts for hardware HA. The
/// orchestration runs on the home host (where the definition is stored): it
/// allocates every WolfNet IP up front, builds each node on its host (locally
/// or via the build primitive on a peer), then bootstraps the first and joins
/// the rest. Returns the persisted cluster on success.
pub fn provision_cluster(p: &ProvisionRequest, log: &Sender<String>, ctx: &GaleraOpCtx) -> Result<GaleraCluster, String> {
    // Explicit names (from the create wizard) win and set the count; otherwise
    // generate `{prefix}-{i}`.
    let names: Vec<String> = if !p.container_names.is_empty() {
        p.container_names.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    } else {
        safe_token(&p.name_prefix)?;
        (1..=p.node_count).map(|i| format!("{}-{}", p.name_prefix, i)).collect()
    };
    if names.is_empty() || names.len() > 9 {
        return Err("a cluster needs between 1 and 9 nodes".into());
    }
    if p.root_password.is_empty() {
        return Err("a root password is required".into());
    }
    safe_token(&p.cluster_name)?;
    for cname in &names { safe_token(cname)?; }
    let _ = install_cmd(&p.distribution)?; // validate distro up front

    // Per-node target host: container_hosts[i] when present + non-empty, else the
    // home host. Empty/absent everywhere → all on the home host (old behaviour).
    let hosts: Vec<String> = (0..names.len()).map(|i| {
        p.container_hosts.get(i).map(|h| h.trim().to_string()).filter(|h| !h.is_empty())
            .unwrap_or_else(|| p.node_id.clone())
    }).collect();

    // Reserve every WolfNet IP in one batch on this host so the addresses are
    // distinct across the whole cluster (see next_available_wolfnet_ips). These
    // come from THIS host's view (config peers + poll route cache + local
    // containers); a peer's brand-new, not-yet-polled container could in theory
    // overlap, so we log the picks for the operator to eyeball.
    let ips = crate::containers::next_available_wolfnet_ips(names.len())
        .ok_or_else(|| format!("not enough free WolfNet IPs for {} node(s)", names.len()))?;
    logln(log, format!("Reserved {} WolfNet address(es): {}.", ips.len(), ips.join(", ")));

    // Stable id minted before any container exists, so a failed final upsert
    // can't strand a live cluster under a fresh id on retry.
    let cluster_id = uuid::Uuid::new_v4().to_string();
    let nodes: Vec<GaleraNode> = names.iter().enumerate().map(|(i, cname)| GaleraNode {
        node_id: hosts[i].clone(),
        container: cname.clone(),
        kind: "lxc".into(),
        address: ips[i].clone(),
        port: 3306,
        node_name: cname.clone(),
    }).collect();

    // Persist the definition NOW — before any container work — so the cluster
    // appears in the list immediately and survives the operator closing the
    // progress window or a mid-build failure (they can watch it, retry, or
    // forget it). Status shows "unreachable" until MariaDB is actually up.
    let spread = hosts.iter().collect::<HashSet<_>>().len();
    logln(log, format!("Registered '{}' — building {} node(s) across {} host(s)…", p.cluster_name, nodes.len(), spread));
    let saved = upsert_cluster(GaleraCluster {
        id: cluster_id,
        name: p.cluster_name.clone(),
        cluster: p.cluster.clone(),
        owner_node: String::new(), // filled by upsert_cluster = this (home) node
        nodes: nodes.clone(),
        sst_method: p.sst_method.clone(),
        db_user: "root".into(),
        db_password_enc: String::new(),
        created_at: chrono::Utc::now().to_rfc3339(),
        provisioned: true,
        proxies: Vec::new(),
    }, Some(&p.root_password))?;

    // 1. Build each node's container ON ITS HOST (create + WolfNet IP + install).
    for n in &nodes {
        if ctx.is_self_host(&n.node_id) {
            logln(log, format!("[{}] creating container…", n.container));
            build_node_local(&n.container, &p.distribution, &p.release, &n.address, log)?;
        } else {
            logln(log, format!("[{}] building on {}…", n.container, host_label(ctx, &n.node_id)));
            build_node_remote(ctx, &n.node_id, &n.container, &p.distribution, &p.release, &n.address, log)
                .map_err(|e| format!("[{}] build on {} failed: {}", n.container, host_label(ctx, &n.node_id), e))?;
            logln(log, format!("[{}] built on {}.", n.container, host_label(ctx, &n.node_id)));
        }
    }

    // 2. Config + bootstrap the first node (new primary + root password), then
    //    join the rest one at a time so each SSTs cleanly from a Synced donor.
    //    Every node gets the SAME full gcomm member list.
    let gcomm = nodes.iter().map(|n| n.address.as_str()).collect::<Vec<_>>().join(",");
    launch_node(ctx, &nodes[0], p, &gcomm, "bootstrap", log)?;
    for n in nodes.iter().skip(1) {
        launch_node(ctx, n, p, &gcomm, "join", log)?;
    }

    logln(log, "All nodes joined — cluster is up.");
    Ok(saved)
}

/// Display name (hostname) for a host id, for the progress log.
fn host_label(ctx: &GaleraOpCtx, host: &str) -> String {
    ctx.resolve_host(host)
        .map(|n| n.hostname.clone())
        .filter(|h| !h.trim().is_empty())
        .unwrap_or_else(|| host.to_string())
}

/// Create + start an LXC container, attach the GIVEN WolfNet IP, install
/// MariaDB+Galera, and stop it (configured offline; launched explicitly later).
/// Factored from provision so the exact same steps run locally or on a peer host.
fn build_node_local(container: &str, distribution: &str, release: &str, address: &str, log: &Sender<String>) -> Result<(), String> {
    safe_token(container)?;
    crate::containers::lxc_create(container, distribution, release, crate::containers::host_container_arch(), None, None)?;
    crate::containers::lxc_start(container)?;
    logln(log, format!("[{}] attaching WolfNet IP {}…", container, address));
    let _ = crate::containers::lxc_attach_wolfnet(container, address);
    logln(log, format!("[{}] waiting for container to be ready…", container));
    wait_container_ready(container);
    logln(log, format!("[{}] installing MariaDB + Galera…", container));
    let install = install_cmd(distribution)?;
    run_install(container, install, log)?;
    let _ = svc("lxc", container, "stop"); // configure offline; launched explicitly
    Ok(())
}

/// Write the Galera config on a built node, then EITHER bootstrap it (new
/// primary component + set the root password, which replicates to the rest via
/// Galera) or start it to join via SST. `role` is "bootstrap" or "join".
/// Factored from provision so the exact same steps run locally or on a peer.
#[allow(clippy::too_many_arguments)]
fn launch_node_local(container: &str, distribution: &str, cluster_name: &str, gcomm: &str, node_address: &str, node_name: &str, sst_method: &str, role: &str, root_password: &str, log: &Sender<String>) -> Result<(), String> {
    safe_token(container)?;
    // Guard the role explicitly: anything but "bootstrap"/"join" would silently
    // take the join branch. Reject it — a peer call with role="bootstrap" must
    // never be aimed at an already-running container (that would split a cluster).
    if role != "bootstrap" && role != "join" {
        return Err(format!("invalid launch role '{}' (expected bootstrap or join)", role));
    }
    // Provider path is read from disk per node — see detect_galera_provider.
    let provider = detect_galera_provider(container, distribution);
    let cnf = galera_cnf(&provider, cluster_name, gcomm, node_address, node_name, sst_method);
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(cnf.as_bytes());
    let cnf_path = galera_cnf_path(distribution);
    // base64 the file to avoid any shell-quoting hazard with the content.
    lxc_exec(container, &format!("mkdir -p \"$(dirname {path})\" && printf %s '{b64}' | base64 -d > {path}", path = cnf_path, b64 = b64))?;
    if role == "bootstrap" {
        logln(log, format!("[{}] bootstrapping new cluster…", container));
        lxc_exec(container, "sed -i 's/^safe_to_bootstrap:.*/safe_to_bootstrap: 1/' /var/lib/mysql/grastate.dat 2>/dev/null || true")?;
        lxc_exec(container, "galera_new_cluster 2>/dev/null || (systemctl set-environment _WSREP_NEW_CLUSTER='--wsrep-new-cluster' >/dev/null 2>&1; systemctl start mariadb)")?;
        // Root password + TCP grant. SQL-escaped (\\ and ' doubled) and the whole
        // script is base64-piped into mysql's STDIN, so the password never
        // touches `sh -c`: a value like `$(id)` or a backtick can't reach the shell.
        let pw_sql = root_password.replace('\\', "\\\\").replace('\'', "''");
        let sql = format!(
            "ALTER USER 'root'@'localhost' IDENTIFIED BY '{pw}'; \
             CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '{pw}'; \
             GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;",
            pw = pw_sql);
        let sql_b64 = base64::engine::general_purpose::STANDARD.encode(sql.as_bytes());
        lxc_exec(container, &format!("printf %s '{}' | base64 -d | mysql", sql_b64))?;
    } else {
        logln(log, format!("[{}] joining cluster (SST)…", container));
        svc("lxc", container, "start")?;
    }
    Ok(())
}

/// Build primitive entry point (the cluster's home host calls this on a peer to
/// build a node that lives there). Peer-side progress is not streamed back, so
/// the throwaway log channel is fine — the orchestrator reports milestones.
pub fn local_build_node(container: &str, distribution: &str, release: &str, address: &str) -> Result<(), String> {
    let (tx, _rx) = std::sync::mpsc::channel();
    build_node_local(container, distribution, release, address, &tx)
}

/// Launch primitive entry point (home host → peer, for a node living there).
#[allow(clippy::too_many_arguments)]
pub fn local_launch_node(container: &str, distribution: &str, cluster_name: &str, gcomm: &str, node_address: &str, node_name: &str, sst_method: &str, role: &str, root_password: &str) -> Result<(), String> {
    let (tx, _rx) = std::sync::mpsc::channel();
    launch_node_local(container, distribution, cluster_name, gcomm, node_address, node_name, sst_method, role, root_password, &tx)
}

/// Build a node's container on a peer host via its build primitive. Install can
/// take a while, so the timeout is generous.
fn build_node_remote(ctx: &GaleraOpCtx, host: &str, container: &str, distribution: &str, release: &str, address: &str, log: &Sender<String>) -> Result<(), String> {
    let target = ctx.resolve_host(host).ok_or_else(|| format!("host '{}' is not a node in this cluster", host))?;
    let path = format!("/api/galera/local/build/{}", container);
    let urls = crate::api::build_node_urls(&target.address, target.port, &path);
    let body = serde_json::json!({ "distribution": distribution, "release": release, "address": address });
    post_to_peer(ctx, &urls, &body, 1800, host, log, &format!("installing on {}", container))
}

/// Configure + launch (bootstrap or join) a node on a peer host via its launch
/// primitive.
#[allow(clippy::too_many_arguments)]
fn launch_node_remote(ctx: &GaleraOpCtx, host: &str, container: &str, distribution: &str, cluster_name: &str, gcomm: &str, node_address: &str, node_name: &str, sst_method: &str, role: &str, root_password: &str, log: &Sender<String>) -> Result<(), String> {
    let target = ctx.resolve_host(host).ok_or_else(|| format!("host '{}' is not a node in this cluster", host))?;
    let path = format!("/api/galera/local/launch/{}", container);
    let urls = crate::api::build_node_urls(&target.address, target.port, &path);
    let body = serde_json::json!({
        "distribution": distribution, "cluster_name": cluster_name, "gcomm": gcomm,
        "node_address": node_address, "node_name": node_name, "sst_method": sst_method,
        "role": role, "root_password": root_password,
    });
    post_to_peer(ctx, &urls, &body, 1800, host, log, &format!("launching {}", container))
}

/// Dispatch a node's configure+launch to its host — local fast-path or peer
/// primitive. The root password only rides along for the bootstrap node.
fn launch_node(ctx: &GaleraOpCtx, n: &GaleraNode, p: &ProvisionRequest, gcomm: &str, role: &str, log: &Sender<String>) -> Result<(), String> {
    let pw = if role == "bootstrap" { p.root_password.as_str() } else { "" };
    if ctx.is_self_host(&n.node_id) {
        launch_node_local(&n.container, &p.distribution, &p.cluster_name, gcomm, &n.address, &n.node_name, &p.sst_method, role, pw, log)
    } else {
        let verb = if role == "bootstrap" { "bootstrapping" } else { "joining (SST)" };
        logln(log, format!("[{}] {} on {}…", n.container, verb, host_label(ctx, &n.node_id)));
        launch_node_remote(ctx, &n.node_id, &n.container, &p.distribution, &p.cluster_name, gcomm, &n.address, &n.node_name, &p.sst_method, role, pw, log)
            .map_err(|e| format!("[{}] launch on {} failed: {}", n.container, host_label(ctx, &n.node_id), e))
    }
}

/// POST a JSON body to a peer host's local galera primitive, trying the URL
/// fallback list, authenticated with the cluster secret. Ok on 2xx, else the
/// peer's error string. Shared by the build + launch dispatchers. A remote
/// build/launch is a single blocking request with no streamed output, so we
/// emit a heartbeat line every 20s while it runs — that keeps the operator's
/// SSE progress stream from going idle (and being closed by a proxy) during a
/// multi-minute install.
#[allow(clippy::too_many_arguments)]
fn post_to_peer(ctx: &GaleraOpCtx, urls: &[String], body: &serde_json::Value, timeout_secs: u64, host: &str, log: &Sender<String>, label: &str) -> Result<(), String> {
    let secret = ctx.cluster_secret.clone();
    ctx.rt.block_on(async move {
        let mut last = format!("could not reach host '{}'", host);
        for url in urls {
            let req = crate::api::API_HTTP_CLIENT.post(url)
                .peer_auth(&secret)
                .timeout(std::time::Duration::from_secs(timeout_secs))
                .json(body)
                .send();
            tokio::pin!(req);
            let mut beat = tokio::time::interval(std::time::Duration::from_secs(20));
            beat.tick().await; // first tick fires immediately — consume it
            let resp = loop {
                tokio::select! {
                    r = &mut req => break r,
                    _ = beat.tick() => { let _ = log.send(format!("  …{}", label)); }
                }
            };
            match resp {
                Ok(resp) => {
                    let ok = resp.status().is_success();
                    let v: serde_json::Value = resp.json().await.unwrap_or_default();
                    if ok { return Ok(()); }
                    last = v.get("error").and_then(|e| e.as_str()).unwrap_or("remote error").to_string();
                }
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    })
}

// ── Grow an existing cluster (add nodes) ─────────────────────────────

/// Body for POST /api/galera/clusters/{id}/add-nodes.
#[derive(Debug, Clone, Deserialize)]
pub struct AddNodesRequest {
    /// New container names to create + join (built on the cluster's owner host).
    pub container_names: Vec<String>,
    #[serde(default = "default_distro")]
    pub distribution: String,
    #[serde(default = "default_release")]
    pub release: String,
}

/// Add new MariaDB+Galera nodes to an EXISTING cluster. The new LXC containers
/// are created on THIS host (the cluster's owner — the frontend routes here),
/// installed, configured to join the live cluster, then started so each requests
/// an SST and copies the full dataset (users + grants included) from a synced
/// donor. We NEVER bootstrap — the cluster is already primary. The existing LXC
/// nodes' gcomm seed list is rewritten (no restart) to include the newcomers so
/// a later cold recovery can find them. Returns the updated cluster.
pub fn add_nodes(cluster: &GaleraCluster, p: &AddNodesRequest, log: &Sender<String>, ctx: &GaleraOpCtx) -> Result<GaleraCluster, String> {
    let names: Vec<String> = p.container_names.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if names.is_empty() {
        return Err("name at least one new node".into());
    }
    if cluster.nodes.is_empty() {
        return Err("this cluster has no existing nodes to join — build a cluster instead".into());
    }
    if cluster.nodes.len() + names.len() > 9 {
        return Err(format!("a cluster is capped at 9 nodes ({} existing + {} new exceeds it)", cluster.nodes.len(), names.len()));
    }
    let _ = install_cmd(&p.distribution)?; // validate distro up front
    // Reject names that collide with an existing node, a proxy, OR each other.
    let existing: HashSet<&str> = cluster.nodes.iter().map(|n| n.container.as_str())
        .chain(cluster.proxies.iter().map(|x| x.container.as_str()))
        .collect();
    let mut seen: HashSet<String> = HashSet::new();
    for cname in &names {
        safe_token(cname)?;
        if existing.contains(cname.as_str()) {
            return Err(format!("'{}' already exists in this cluster", cname));
        }
        if !seen.insert(cname.clone()) {
            return Err(format!("duplicate new node name '{}'", cname));
        }
    }

    // 1. Create + start each new container on this host, give it a WolfNet IP.
    let mut new_nodes: Vec<GaleraNode> = Vec::new();
    for cname in &names {
        logln(log, format!("[{}] creating container…", cname));
        crate::containers::lxc_create(cname, &p.distribution, &p.release, crate::containers::host_container_arch(), None, None)?;
        crate::containers::lxc_start(cname)?;
        let ip = crate::containers::next_available_wolfnet_ip()
            .ok_or("no free WolfNet IP available for the new node")?;
        logln(log, format!("[{}] attaching WolfNet IP {}…", cname, ip));
        let _ = crate::containers::lxc_attach_wolfnet(cname, &ip);
        new_nodes.push(GaleraNode { node_id: ctx.self_id.clone(), container: cname.clone(), kind: "lxc".into(), address: ip, port: 3306, node_name: cname.clone() });
    }

    // Persist the new nodes NOW (status "unreachable" until they SST) so they
    // appear immediately and survive a mid-join failure — same as provision.
    let mut updated = cluster.clone();
    updated.nodes.extend(new_nodes.iter().cloned());
    logln(log, format!("Registered {} new node(s) on '{}'.", new_nodes.len(), cluster.name));
    let saved = upsert_cluster(updated, None)?;

    // 2. Install MariaDB + Galera on each new node, then stop it (it starts as a
    //    joiner below — bootstrapping a second primary would split the cluster).
    let install = install_cmd(&p.distribution)?;
    for n in &new_nodes {
        logln(log, format!("[{}] waiting for container to be ready…", n.container));
        wait_container_ready(&n.container);
        logln(log, format!("[{}] installing MariaDB + Galera…", n.container));
        run_install(&n.container, install, log)?;
        let _ = svc("lxc", &n.container, "stop");
    }

    // 3. Full member list = existing + new. New nodes get the complete gcomm so
    //    they can seed off any member.
    let gcomm = saved.nodes.iter().map(|n| n.address.as_str()).collect::<Vec<_>>().join(",");
    let cnf_path = galera_cnf_path(&p.distribution);
    for n in &new_nodes {
        let provider = detect_galera_provider(&n.container, &p.distribution);
        let cnf = galera_cnf(&provider, &saved.name, &gcomm, &n.address, &n.node_name, &saved.sst_method);
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(cnf.as_bytes());
        lxc_exec(&n.container, &format!("mkdir -p \"$(dirname {path})\" && printf %s '{b64}' | base64 -d > {path}", path = cnf_path, b64 = b64))?;
    }

    // 4. Point the existing nodes' seed lists at the full membership so a future
    //    cold recovery (which can bootstrap any node) can locate the newcomers.
    //    Best-effort: a transiently-unreachable peer must not fail the add — the
    //    new nodes already joined off the live members. LXC only; a Docker node's
    //    config is image-managed, so we note it and skip.
    for n in &cluster.nodes {
        if n.kind == "docker" {
            logln(log, format!("[{}] Docker node — update its gcomm wherever it's managed (skipped).", n.container));
            continue;
        }
        let host = locate_host(ctx, &n.kind, &n.container, &n.node_id).unwrap_or_else(|_| n.node_id.clone());
        match set_gcomm(ctx, &host, &n.kind, &n.container, &gcomm) {
            Ok(()) => logln(log, format!("[{}] seed list updated to {} members.", n.container, saved.nodes.len())),
            Err(e) => logln(log, format!("[{}] couldn't update seed list ({}); it stays usable while a current member is up.", n.container, e)),
        }
    }

    // 5. Start each new node — it requests an SST from a synced donor, copying
    //    the WHOLE dataset, so the first sync can take a while on a large cluster.
    //    Best-effort start: if `systemctl start` reports failure (e.g. the SST
    //    outran the unit's start timeout) the transfer is still running and the
    //    node is already registered, so we surface it and let the dashboard track
    //    it to Synced rather than aborting a half-finished add.
    for n in &new_nodes {
        logln(log, format!("[{}] joining cluster (SST — copies the full dataset, may take a while)…", n.container));
        if let Err(e) = svc("lxc", &n.container, "start") {
            logln(log, format!("[{}] start reported '{}' — if the dataset is large the SST is still running; watch the dashboard until it shows Synced.", n.container, e));
        }
    }

    logln(log, format!("{} node(s) added to '{}' — they appear as joining until the SST completes.", new_nodes.len(), saved.name));
    Ok(saved)
}

/// Rewrite the `wsrep_cluster_address` seed list in a node's Galera config IN
/// PLACE — replace only that one line, leave everything else untouched. Used
/// when growing a cluster so existing nodes learn the newcomers. Takes effect
/// on the node's next MariaDB restart; we deliberately do NOT restart here.
pub fn set_gcomm_local(kind: &str, container: &str, gcomm: &str) -> Result<(), String> {
    safe_token(container)?;
    // gcomm is a comma-separated address list (IPv4/IPv6/hostnames-as-IPs here):
    // only hex digits + . : , — nothing that could escape the shell or awk.
    if gcomm.is_empty() || !gcomm.chars().all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | ',')) {
        return Err("invalid gcomm member list".into());
    }
    let new_line = format!("wsrep_cluster_address=\"gcomm://{}\"", gcomm);
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(new_line.as_bytes());
    // Find the file that declares wsrep_cluster_address and replace that line.
    // The replacement is base64'd then awk-substituted as a literal (-v), so the
    // member list never reaches `sh -c` raw and no regex metachar is interpreted.
    let script = format!(
        "f=$(grep -rlsE '^[[:space:]]*wsrep_cluster_address' /etc/mysql /etc/my.cnf /etc/my.cnf.d 2>/dev/null | head -1); \
         if [ -z \"$f\" ]; then echo 'no galera config file declaring wsrep_cluster_address found'; exit 1; fi; \
         line=$(printf %s '{b64}' | base64 -d); \
         awk -v repl=\"$line\" '/^[[:space:]]*wsrep_cluster_address[[:space:]]*=/{{print repl; next}} {{print}}' \"$f\" > \"$f.wstmp\" && mv \"$f.wstmp\" \"$f\"",
        b64 = b64);
    cexec(kind, container, &script).map(|_| ())
}

/// POST the gcomm rewrite to a peer host's local endpoint (the cluster owner
/// calls this for members that live on other hosts).
fn set_gcomm_remote(ctx: &GaleraOpCtx, host: &str, kind: &str, container: &str, gcomm: &str) -> Result<(), String> {
    let target = ctx.resolve_host(host)
        .ok_or_else(|| format!("host '{}' is not a node in this cluster", host))?;
    let path = format!("/api/galera/local/gcomm/{}/{}", kind, container);
    let urls = crate::api::build_node_urls(&target.address, target.port, &path);
    let secret = ctx.cluster_secret.clone();
    let body = serde_json::json!({ "gcomm": gcomm });
    ctx.rt.block_on(async move {
        let mut last = format!("could not reach host '{}'", host);
        for url in &urls {
            match crate::api::API_HTTP_CLIENT.post(url)
                .peer_auth(&secret)
                .timeout(std::time::Duration::from_secs(20))
                .json(&body)
                .send().await
            {
                Ok(resp) => {
                    let ok = resp.status().is_success();
                    let v: serde_json::Value = resp.json().await.unwrap_or_default();
                    if ok { return Ok(()); }
                    last = v.get("error").and_then(|e| e.as_str()).unwrap_or("remote error").to_string();
                }
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    })
}

/// Rewrite a node's gcomm seed list, host-aware (local fast-path for self).
fn set_gcomm(ctx: &GaleraOpCtx, host: &str, kind: &str, container: &str, gcomm: &str) -> Result<(), String> {
    if ctx.is_self_host(host) {
        set_gcomm_local(kind, container, gcomm)
    } else {
        set_gcomm_remote(ctx, host, kind, container, gcomm)
    }
}

// ── MaxScale proxy provisioning ──────────────────────────────────────

/// Body for POST /api/galera/clusters/{id}/maxscale.
#[derive(Debug, Clone, Deserialize)]
pub struct MaxScaleRequest {
    /// Container name for the proxy (created as LXC on the cluster owner host).
    pub container_name: String,
    #[serde(default = "default_distro")]
    pub distribution: String,
    #[serde(default = "default_release")]
    pub release: String,
    /// MaxScale's own DB user (monitor + service auth). Created on the cluster.
    #[serde(default = "default_maxscale_user")]
    pub proxy_user: String,
    pub proxy_password: String,
    /// readwritesplit listener port apps connect to.
    #[serde(default = "default_mysql_port")]
    pub listener_port: u16,
}
fn default_maxscale_user() -> String { "maxscale".into() }

/// MaxScale package install per distro. The MariaDB repo-setup script URL is the
/// official one from MariaDB's MaxScale install guide
/// (mariadb.com/docs/maxscale … installation-guide). MaxScale ships only for
/// Debian/Ubuntu + RHEL/Rocky — Alpine/Arch have no official package, so we
/// refuse rather than half-install something that won't run. We also pull in the
/// MariaDB client (best-effort) so the operator can test the listener from the
/// proxy box itself.
fn maxscale_install_cmd(distro: &str) -> Result<&'static str, String> {
    Ok(match distro_family(distro) {
        "deb" => "export DEBIAN_FRONTEND=noninteractive; apt-get update -y && apt-get install -y curl ca-certificates && curl -LsS https://r.mariadb.com/downloads/mariadb_repo_setup | bash && apt-get update -y && apt-get install -y maxscale && (apt-get install -y mariadb-client || true)",
        "rhel" => "curl -LsS https://r.mariadb.com/downloads/mariadb_repo_setup | bash && (dnf install -y maxscale || yum install -y maxscale) && (dnf install -y MariaDB-client || dnf install -y mariadb || yum install -y mariadb || true)",
        other => return Err(format!(
            "MaxScale has no official package for '{}' — build the proxy on a Debian/Ubuntu or RHEL/Rocky base.", other)),
    })
}

/// Render /etc/maxscale.cnf for a Galera cluster: a [serverN] per member, a
/// galeramon monitor, a readwritesplit service, and its listener. `servers` is
/// (label, address, port) tuples. Values come from validated names + IPs; the
/// password is charset-restricted (see `valid_proxy_secret`) so it's INI/SQL-safe.
fn maxscale_cnf(servers: &[(String, String, u16)], user: &str, password: &str, listener_port: u16) -> String {
    let mut s = String::from("[maxscale]\nthreads=auto\n\n");
    for (label, addr, port) in servers {
        s.push_str(&format!("[{label}]\ntype=server\naddress={addr}\nport={port}\n\n", label = label, addr = addr, port = port));
    }
    let list = servers.iter().map(|(l, _, _)| l.as_str()).collect::<Vec<_>>().join(",");
    // galeramon elects one synced member as the write master; readwritesplit
    // sends writes there and balances reads across the rest.
    s.push_str(&format!(
        "[Galera-Monitor]\ntype=monitor\nmodule=galeramon\nservers={list}\nuser={user}\npassword={pw}\n\n",
        list = list, user = user, pw = password));
    // enable_root_user so the cluster's root@'%' account (which WolfStack already
    // provisions for TCP management) works THROUGH the proxy — MaxScale blocks
    // root by default. Apps still authenticate with their own backend users.
    s.push_str(&format!(
        "[Read-Write-Service]\ntype=service\nrouter=readwritesplit\nservers={list}\nuser={user}\npassword={pw}\nenable_root_user=true\n\n",
        list = list, user = user, pw = password));
    s.push_str(&format!(
        "[Read-Write-Listener]\ntype=listener\nservice=Read-Write-Service\naddress=0.0.0.0\nport={port}\n\n",
        port = listener_port));
    // A master-only route on the next port, for apps that read their own
    // writes straight back (see ensure_master_listener).
    s.push_str(&format!(
        "[{svc}]\ntype=service\nrouter=readconnroute\nrouter_options=master\nservers={list}\nuser={user}\npassword={pw}\n\n\
         [{lst}]\ntype=listener\nservice={svc}\naddress=0.0.0.0\nport={port}\n",
        svc = MASTER_ONLY_SERVICE, lst = MASTER_ONLY_LISTENER, list = list, user = user, pw = password,
        port = listener_port + 1));
    s
}

/// MaxScale objects for the master-only route.
pub const MASTER_ONLY_SERVICE: &str = "Master-Only-Service";
pub const MASTER_ONLY_LISTENER: &str = "Master-Only-Listener";

/// Make sure the cluster's MaxScale proxy has a master-only route, and return
/// its `(address, port)`.
///
/// readwritesplit sends a write to the primary and the very next read to
/// another member, which may not have applied it yet. An app that writes then
/// reads straight back sees its own write missing — measured on the grid
/// 2026-07-27 at 4–37% of write-then-read pairs (robust logins), and hit by a
/// Stalwart mail install 2026-11-13 ("invalidForeignKey" on a domain it had
/// just written). `wsrep_sync_wait` did NOT fix it on the MaxScale path; a
/// readconnroute `router_options=master` service did (400/400). This adds
/// that service + a listener on the read/write port + 1 at runtime with
/// maxctrl (no MaxScale restart; runtime objects persist in
/// /var/lib/maxscale/maxscale.cnf.d/), reusing the existing service's
/// servers and MaxScale user. Proxies WolfStack builds already carry it
/// (maxscale_cnf); this covers older ones. MaxScale still follows galeramon's
/// primary election, so failover is kept.
pub fn ensure_master_listener(cluster: &GaleraCluster, ctx: &GaleraOpCtx) -> Result<(String, u16), String> {
    let proxy = cluster.proxies.first().ok_or_else(|| format!("Galera cluster '{}' has no MaxScale proxy", cluster.name))?;
    if !proxy.node_id.is_empty() && !ctx.is_self_host(&proxy.node_id) {
        return Err(format!("the MaxScale proxy '{}' runs on another server — open the installer from the server that hosts it", proxy.container));
    }
    let port = proxy.listener_port + 1;
    let services = lxc_exec(&proxy.container, "maxctrl --tsv list services")?;
    if services.lines().any(|l| l.split('\t').next() == Some(MASTER_ONLY_SERVICE)) {
        return Ok((proxy.address.clone(), port));
    }
    // servers / user / password of the existing read-write service.
    let cnf = lxc_exec(&proxy.container, "cat /etc/maxscale.cnf")?;
    let mut in_rw = false;
    let (mut servers, mut user, mut password) = (String::new(), String::new(), String::new());
    for line in cnf.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            in_rw = l == "[Read-Write-Service]";
            continue;
        }
        if !in_rw { continue; }
        if let Some((k, v)) = l.split_once('=') {
            match k.trim() {
                "servers" => servers = v.trim().to_string(),
                "user" => user = v.trim().to_string(),
                "password" => password = v.trim().to_string(),
                _ => {}
            }
        }
    }
    let server_list: Vec<&str> = servers.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()).collect();
    if server_list.is_empty() || user.is_empty() || password.is_empty() {
        return Err(format!("could not read the read-write service from {}'s /etc/maxscale.cnf", proxy.container));
    }
    for t in server_list.iter().chain([&user.as_str()]) { safe_token(t)?; }
    if !valid_proxy_secret(&password) {
        return Err("the MaxScale service password has characters WolfStack won't pass to maxctrl".into());
    }
    // Every value is validated above (no quotes/spaces), and single-quoted.
    lxc_exec(&proxy.container, &format!(
        "maxctrl create service '{svc}' readconnroute 'user={u}' 'password={p}' router_options=master --servers {srv}",
        svc = MASTER_ONLY_SERVICE, u = user, p = password, srv = server_list.join(" ")))?;
    lxc_exec(&proxy.container, &format!(
        "maxctrl create listener '{svc}' '{lst}' {port} protocol=MariaDBClient address=0.0.0.0",
        svc = MASTER_ONLY_SERVICE, lst = MASTER_ONLY_LISTENER, port = port))?;
    Ok((proxy.address.clone(), port))
}

/// A password that's safe to drop into BOTH a maxscale.cnf value AND a SQL
/// string literal without escaping surprises: no quotes, backslash, whitespace,
/// or INI comment chars. Restrictive on purpose — this is a fresh user we mint.
fn valid_proxy_secret(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | '%' | '+' | '=' | '!' | '~'))
}

/// Create MaxScale's combined monitor+service user on the cluster, over a normal
/// SQL connection to the first reachable member (Galera replicates it to all).
/// Privileges verified against MariaDB's MaxScale docs: SELECT on mysql.* +
/// SHOW DATABASES for service auth; REPLICATION CLIENT (accepted on every
/// MariaDB version we provision/adopt) + PROCESS for galeramon.
fn maxscale_create_user(cluster: &GaleraCluster, ctx: &GaleraOpCtx, user: &str, password: &str) -> Result<(), String> {
    let pw = dec_secret(&cluster.db_password_enc);
    let admin = cluster.db_user.clone();
    let nodes = cluster.nodes.clone();
    let stmts = vec![
        format!("CREATE USER IF NOT EXISTS '{u}'@'%' IDENTIFIED BY '{p}'", u = user, p = password),
        format!("ALTER USER '{u}'@'%' IDENTIFIED BY '{p}'", u = user, p = password),
        format!("GRANT SELECT ON mysql.* TO '{u}'@'%'", u = user),
        format!("GRANT SHOW DATABASES, PROCESS, REPLICATION CLIENT ON *.* TO '{u}'@'%'", u = user),
        "FLUSH PRIVILEGES".to_string(),
    ];
    ctx.rt.block_on(async move {
        let mut last = "no reachable cluster member to create the MaxScale user on".to_string();
        for n in &nodes {
            let params = crate::mysql_editor::ConnParams {
                host: n.address.clone(), port: n.port, user: admin.clone(),
                password: pw.clone(), database: None,
                db_type: crate::mysql_editor::DbType::default(),
            };
            // Probe this member first; skip unreachable ones.
            if crate::mysql_editor::execute_query(&params, "", "SELECT 1").await.is_err() {
                last = format!("[{}] unreachable", n.container);
                continue;
            }
            for s in &stmts {
                if let Err(e) = crate::mysql_editor::execute_query(&params, "", s).await {
                    return Err(format!("[{}] {}", n.container, e));
                }
            }
            return Ok(());
        }
        Err(last)
    })
}

/// Provision a MaxScale proxy in front of an existing cluster: create the proxy
/// user on the cluster, build an LXC container on THIS host (the owner), install
/// MaxScale, write a cluster-specific /etc/maxscale.cnf, and start it. Records
/// the proxy on the cluster (NOT as a Galera member). Returns the updated cluster.
pub fn provision_maxscale(cluster: &GaleraCluster, p: &MaxScaleRequest, log: &Sender<String>, ctx: &GaleraOpCtx) -> Result<GaleraCluster, String> {
    let cname = p.container_name.trim().to_string();
    safe_token(&cname)?;
    safe_token(&p.proxy_user)?;
    if !valid_proxy_secret(&p.proxy_password) {
        return Err("proxy password must be 1–128 chars from letters, digits and . _ - @ % + = ! ~ (no quotes or spaces)".into());
    }
    if cluster.nodes.is_empty() {
        return Err("this cluster has no nodes to proxy".into());
    }
    if cluster.nodes.iter().any(|n| n.container == cname) || cluster.proxies.iter().any(|x| x.container == cname) {
        return Err(format!("'{}' already exists in this cluster", cname));
    }
    let install = maxscale_install_cmd(&p.distribution)?; // validate distro up front

    // 1. Mint the proxy user on the cluster FIRST so MaxScale can authenticate
    //    the moment it starts.
    logln(log, "Creating the MaxScale proxy user on the cluster…");
    maxscale_create_user(cluster, ctx, &p.proxy_user, &p.proxy_password)?;
    logln(log, format!("Proxy user '{}' created (replicated to every node).", p.proxy_user));

    // 2. Create + start the proxy container on this host, give it a WolfNet IP.
    logln(log, format!("[{}] creating proxy container…", cname));
    crate::containers::lxc_create(&cname, &p.distribution, &p.release, crate::containers::host_container_arch(), None, None)?;
    crate::containers::lxc_start(&cname)?;
    let ip = crate::containers::next_available_wolfnet_ip()
        .ok_or("no free WolfNet IP available for the proxy")?;
    logln(log, format!("[{}] attaching WolfNet IP {}…", cname, ip));
    let _ = crate::containers::lxc_attach_wolfnet(&cname, &ip);

    // Record the proxy NOW so a mid-install failure doesn't strand it untracked.
    let mut updated = cluster.clone();
    updated.proxies.push(MaxScaleProxy {
        node_id: ctx.self_id.clone(),
        container: cname.clone(),
        address: ip.clone(),
        listener_port: p.listener_port,
        created_at: chrono::Utc::now().to_rfc3339(),
    });
    let saved = upsert_cluster(updated, None)?;

    // 3. Install MaxScale (MariaDB repo + package).
    logln(log, format!("[{}] waiting for container to be ready…", cname));
    wait_container_ready(&cname);
    logln(log, format!("[{}] installing MaxScale…", cname));
    run_install(&cname, install, log)?;

    // 4. Write /etc/maxscale.cnf for this cluster's members.
    let servers: Vec<(String, String, u16)> = saved.nodes.iter().enumerate()
        .map(|(i, n)| (format!("server{}", i + 1), n.address.clone(), n.port))
        .collect();
    let cnf = maxscale_cnf(&servers, &p.proxy_user, &p.proxy_password, p.listener_port);
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(cnf.as_bytes());
    lxc_exec(&cname, &format!("printf %s '{b64}' | base64 -d > /etc/maxscale.cnf", b64 = b64))?;

    // 5. Enable + start MaxScale. The proxy base is always systemd (we reject
    //    Alpine/Arch above), so verify it actually came up — stream the restart
    //    and fail loudly if the service isn't active, rather than reporting
    //    "ready" for a proxy that silently crashed on a bad config.
    logln(log, format!("[{}] starting MaxScale…", cname));
    let _ = lxc_exec(&cname, "systemctl enable maxscale >/dev/null 2>&1 || true"); // boot-persist (best-effort)
    cexec_streamed("lxc", &cname, "systemctl restart maxscale && sleep 1 && systemctl is-active maxscale", log)
        .map_err(|e| format!(
            "MaxScale didn't start in '{}' ({}). Console in and run 'maxscale --config-check -f /etc/maxscale.cnf' to see why.",
            cname, e))?;

    logln(log, format!(
        "MaxScale ready — point apps at {}:{}. It routes writes to the elected primary and balances reads across synced members.",
        ip, p.listener_port));
    Ok(saved)
}

/// Remove a MaxScale proxy from a cluster: best-effort stop its MaxScale service
/// (when the container is on THIS host), then drop the tracking entry. The
/// container's filesystem is left intact — the operator can delete the (stopped)
/// container from the Containers view. Returns the updated cluster.
pub fn remove_proxy(cluster_id: &str, container: &str) -> Result<GaleraCluster, String> {
    safe_token(container)?;
    // Stop MaxScale if this proxy container lives on this host (the owner runs
    // this op). A proxy holds no data, so leaving the stopped container is safe.
    if container_exists_local("lxc", container) {
        let _ = cexec("lxc", container, "systemctl stop maxscale 2>/dev/null || true");
    }
    let _io = GALERA_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut cfg = load_config();
    let updated = {
        let c = cfg.clusters.iter_mut().find(|c| c.id == cluster_id)
            .ok_or_else(|| format!("cluster '{}' not found", cluster_id))?;
        let before = c.proxies.len();
        c.proxies.retain(|x| x.container != container);
        if c.proxies.len() == before {
            return Err(format!("proxy '{}' is not registered on this cluster", container));
        }
        c.clone()
    };
    save_config(&cfg)?;
    Ok(updated)
}

// ── Lifecycle + evidence-based recovery (host-aware) ─────────────────
//
// A cluster's containers can live on different WolfStack hosts (an adopted
// cross-host cluster, or a provisioned one whose containers were later
// migrated). lxc-attach only works on the host a container physically sits on,
// so every per-node op is dispatched to that host: run locally if it's this
// node, else POST to the host's `/api/galera/local/{op}/{container}` primitive
// over the inter-node channel. We find a container's CURRENT host by probing
// (so a migrated container is reached where it now lives) and self-heal the
// stored host. This requires the container's host to be in the same WolfStack
// cluster — otherwise there's nothing to route through.

/// One atomic node operation, dispatched locally or to a peer host. `Address`
/// resolves a container's reachable IP (used when adopting from the picker).
#[derive(Clone, Copy, PartialEq)]
pub enum NodeOp { Start, Stop, Restart, Bootstrap, Seqno, IsDown, Exists, Address, Sysinfo, Gcomm }

impl NodeOp {
    fn as_str(self) -> &'static str {
        match self {
            NodeOp::Start => "start", NodeOp::Stop => "stop", NodeOp::Restart => "restart",
            NodeOp::Bootstrap => "bootstrap", NodeOp::Seqno => "seqno",
            NodeOp::IsDown => "isdown", NodeOp::Exists => "exists", NodeOp::Address => "address",
            NodeOp::Sysinfo => "sysinfo", NodeOp::Gcomm => "gcomm",
        }
    }
    pub fn from_str(s: &str) -> Option<NodeOp> {
        Some(match s {
            "start" => NodeOp::Start, "stop" => NodeOp::Stop, "restart" => NodeOp::Restart,
            "bootstrap" => NodeOp::Bootstrap, "seqno" => NodeOp::Seqno,
            "isdown" => NodeOp::IsDown, "exists" => NodeOp::Exists, "address" => NodeOp::Address,
            "sysinfo" => NodeOp::Sysinfo, "gcomm" => NodeOp::Gcomm,
            _ => return None,
        })
    }
    /// Per-op remote timeout. Read-only probes are fast and shouldn't tie up a
    /// blocking slot if a peer hangs; service/bootstrap ops legitimately take time.
    fn timeout_secs(self) -> u64 {
        match self {
            NodeOp::Seqno | NodeOp::IsDown | NodeOp::Exists | NodeOp::Address
            | NodeOp::Sysinfo | NodeOp::Gcomm => 20,
            NodeOp::Start | NodeOp::Stop | NodeOp::Restart | NodeOp::Bootstrap => 180,
        }
    }
}

/// Runtime context for routing per-node ops to the host that runs each
/// container. Built once per request from AppState.
pub struct GaleraOpCtx {
    pub self_id: String,
    pub nodes: Vec<crate::agent::Node>,
    pub cluster_secret: String,
    pub rt: tokio::runtime::Handle,
}

impl GaleraOpCtx {
    /// Resolve a host reference to its cluster Node, matching EITHER the
    /// locally-assigned `node-{uuid}` key OR the peer's stable `self_id`. The
    /// two are different namespaces: each host mints its own random key for a
    /// peer (`add_server_full`), so a key is only meaningful on the host that
    /// minted it, whereas `self_id` (the peer's `/etc/wolfstack/node_id`) is the
    /// same everywhere. Cross-host calls (e.g. adopting a cluster whose nodes
    /// sit on other hosts) arrive with the self_id — a strict `n.id == host`
    /// match silently dropped them. Mirrors `ClusterState::get_node`.
    fn resolve_host(&self, host: &str) -> Option<&crate::agent::Node> {
        self.nodes.iter().find(|n| n.id == host || n.self_id.as_deref() == Some(host))
    }

    /// True when `host` denotes THIS node — empty, the self_id, or the self
    /// node's locally-assigned key (so either namespace routes locally).
    fn is_self_host(&self, host: &str) -> bool {
        host.is_empty()
            || host == self.self_id
            || self.nodes.iter().any(|n| n.is_self && (n.id == host || n.self_id.as_deref() == Some(host)))
    }
}

/// Read the last-committed seqno from a node's grastate.dat. Returns -1 when
/// unknown (file missing, or the node crashed mid-transaction = `-1`).
fn node_seqno(kind: &str, container: &str) -> i64 {
    cexec(kind, container, "awk -F': *' '/^seqno:/{print $2}' /var/lib/mysql/grastate.dat 2>/dev/null")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(-1)
}

/// Is this container present on THIS host? Docker → `docker ps -a`; LXC → list.
fn container_exists_local(kind: &str, container: &str) -> bool {
    if kind == "docker" {
        std::process::Command::new("docker")
            .args(["ps", "-a", "--format", "{{.Names}}"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).lines().any(|l| l.trim() == container))
            .unwrap_or(false)
    } else {
        crate::containers::lxc_list_all_cached().iter().any(|c| c.name == container)
    }
}

/// Strip an optional `:port` from a wsrep address token. Handles the
/// `[v6]:port` bracket form, bare IPv4/IPv6, and `host:port` — a bare
/// IPv6 address parses whole and is never split on its colons.
fn strip_wsrep_port(s: &str) -> String {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return rest[..end].to_string();
    }
    if s.parse::<std::net::IpAddr>().is_ok() {
        return s.to_string();
    }
    if let Some((host, port)) = s.rsplit_once(':')
        && !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
    {
        return host.to_string();
    }
    s.to_string()
}

/// Pull the wsrep addresses out of MariaDB config text: the node's own
/// `wsrep_node_address` (when set) and the `gcomm://` member list. Last
/// occurrence wins, matching how MariaDB layers config files. Options
/// after `?` in the gcomm URL (e.g. `?gmcast.segment=1`) are dropped.
fn wsrep_addresses_from_config(text: &str) -> (Option<String>, Vec<String>) {
    let mut node_addr: Option<String> = None;
    let mut gcomm: Vec<String> = Vec::new();
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let key = k.trim();
        let val = v.trim().trim_matches('"').trim_matches('\'').trim();
        if key == "wsrep_node_address" && !val.is_empty() {
            let addr = strip_wsrep_port(val);
            // 0.0.0.0 / loopback would tell peers to talk to themselves —
            // never adopt those; fall through to the gcomm match instead.
            let usable = match addr.parse::<std::net::IpAddr>() {
                Ok(ip) => !ip.is_unspecified() && !ip.is_loopback(),
                Err(_) => !addr.is_empty(), // hostnames pass
            };
            if usable {
                node_addr = Some(addr);
            }
        } else if key == "wsrep_cluster_address" {
            let list = val
                .strip_prefix("gcomm://")
                .unwrap_or(val)
                .split('?')
                .next()
                .unwrap_or("");
            gcomm = list
                .split(',')
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .map(strip_wsrep_port)
                .collect();
        }
    }
    (node_addr, gcomm)
}

/// The address a Galera node's OWN configuration says it replicates on —
/// the authoritative answer for adopt, because it is the address the
/// running cluster already uses (Paul, 2026-08-14: "go look at the galera
/// config in one of the nodes to get the ips").
///
/// `wsrep_node_address` when the config sets one; otherwise the member of
/// the `gcomm://` list that is one of this container's own live IPs
/// (Galera auto-detects its bind address in that setup, but the gcomm
/// list still names every node exactly as its peers reach it). None when
/// the container has no wsrep config (not a Galera node yet) or can't be
/// exec'd (stopped) — callers fall back to NIC-based picking then.
fn galera_config_address(kind: &str, container: &str) -> Option<String> {
    // Same config roots set_gcomm() searches — they cover Debian/Ubuntu
    // (/etc/mysql/**, incl. WolfStack's own 60-galera.cnf) and RHEL/Alpine
    // (/etc/my.cnf, /etc/my.cnf.d/**, incl. galera.cnf).
    let out = cexec(
        kind,
        container,
        "grep -rhsE '^[[:space:]]*wsrep_(node_address|cluster_address)[[:space:]]*=' \
         /etc/mysql /etc/my.cnf /etc/my.cnf.d 2>/dev/null",
    )
    .ok()?;
    let (node_addr, gcomm) = wsrep_addresses_from_config(&out);
    if node_addr.is_some() {
        return node_addr;
    }
    if gcomm.is_empty() {
        return None;
    }
    let mine = cexec(kind, container, "hostname -I 2>/dev/null").unwrap_or_default();
    let my_ips: std::collections::HashSet<&str> = mine.split_whitespace().collect();
    gcomm.iter().find(|m| my_ips.contains(m.as_str())).cloned()
}

/// Resolve a (local) container's address for Galera peering + status queries.
/// The container's own wsrep config is the ground truth; the NIC-based pick
/// (WolfNet-preferred) covers containers with no wsrep config yet. Empty if
/// not resolvable.
fn node_address_local(kind: &str, container: &str) -> String {
    // The node's own Galera config is the ground truth — the cluster is
    // already replicating over these addresses, so nothing needs asking
    // or guessing.
    if let Some(addr) = galera_config_address(kind, container) {
        return addr;
    }
    // No wsrep config to read (fresh container being provisioned, or a
    // stopped one) — fall back to NIC-based resolution.
    if kind == "docker" {
        std::process::Command::new("docker")
            .args(["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", container])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().next().unwrap_or("").to_string())
            .unwrap_or_default()
    } else {
        // `ip_address` is the raw multi-homed string for a container with
        // several NICs ("10.0.10.111, 10.0.3.3, 10.10.10.3" — bridge + LAN
        // + overlay). Returning it verbatim is how adopt failed with "no
        // reachable address found" on iw-db-2 (Paul, 2026-08-14): the list
        // isn't an address. Pick ONE here, on the container's own host,
        // where the WolfNet marker is readable.
        // Source: containers/mod.rs pick_cross_host_ip() + lxc_get_wolfnet_ip().
        let raw = crate::containers::lxc_list_all_cached().iter()
            .find(|c| c.name == container)
            .map(|c| c.ip_address.clone())
            .unwrap_or_default();
        let wolfnet = crate::containers::lxc_get_wolfnet_ip(container);
        crate::containers::pick_cross_host_ip(&raw, wolfnet.as_deref()).unwrap_or(raw)
    }
}

/// Resolve a (local) container's total RAM (bytes) + CPU cores as `"BYTES CORES"`
/// — what the tuning analyzer sizes the buffer pool / slave threads against.
fn node_sysinfo_local(kind: &str, container: &str) -> String {
    cexec(kind, container, "echo \"$(awk '/^MemTotal:/{print $2*1024}' /proc/meminfo 2>/dev/null) $(nproc 2>/dev/null || echo 1)\"")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Is MariaDB stopped in this (local) container? Unreadable ⇒ false (can't
/// confirm ⇒ treat as not-down, so recovery refuses rather than risks data).
fn node_is_down_local(kind: &str, container: &str) -> bool {
    if kind == "docker" {
        // A stopped container can't be exec'd — ask the daemon if it's running.
        return std::process::Command::new("docker")
            .args(["inspect", "-f", "{{.State.Running}}", container])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "false")
            .unwrap_or(false);
    }
    cexec(kind, container, "if pgrep -x mariadbd >/dev/null 2>&1 || pgrep -x mysqld >/dev/null 2>&1; then echo UP; else echo DOWN; fi")
        .map(|s| s.trim() == "DOWN")
        .unwrap_or(false)
}

/// Bootstrap a NEW primary component on this (local) container. We force
/// safe_to_bootstrap:1 deliberately — the caller has already proven (every node
/// down + this one holding the highest committed seqno) what that flag certifies.
/// (Docker isn't reached here — recovery refuses Docker clusters upstream.)
fn bootstrap_local(kind: &str, container: &str) -> Result<String, String> {
    if kind == "docker" {
        // A stopped Docker MariaDB can't be exec'd (its PID 1 is mysqld), so we
        // can't sed grastate first — a restart re-reads safe_to_bootstrap from
        // the volume. (Recovery refuses Docker upstream; this is best-effort.)
        docker_lifecycle("restart", container)?;
    } else {
        cexec(kind, container, "sed -i 's/^safe_to_bootstrap:.*/safe_to_bootstrap: 1/' /var/lib/mysql/grastate.dat 2>/dev/null || true")?;
        cexec(kind, container, "galera_new_cluster 2>/dev/null || (systemctl set-environment _WSREP_NEW_CLUSTER='--wsrep-new-cluster' >/dev/null 2>&1; systemctl start mariadb)")?;
    }
    Ok("bootstrapped".into())
}

/// Run ONE node op against a container that lives on THIS host. The single
/// entry point the local-op HTTP primitive calls. `Exists` is the probe used to
/// locate a container's host; every other op first requires the container here.
pub fn local_node_op(kind: &str, container: &str, op: NodeOp) -> Result<String, String> {
    safe_token(container)?;
    if op == NodeOp::Exists {
        return Ok(if container_exists_local(kind, container) { "yes".into() } else { "no".into() });
    }
    if !container_exists_local(kind, container) {
        return Err(format!("container '{}' is not on this host", container));
    }
    match op {
        NodeOp::Start => svc(kind, container, "start"),
        NodeOp::Stop => svc(kind, container, "stop"),
        NodeOp::Restart => svc(kind, container, "restart"),
        NodeOp::Seqno => Ok(node_seqno(kind, container).to_string()),
        NodeOp::IsDown => Ok(if node_is_down_local(kind, container) { "down".into() } else { "up".into() }),
        NodeOp::Bootstrap => bootstrap_local(kind, container),
        NodeOp::Address => Ok(node_address_local(kind, container)),
        NodeOp::Sysinfo => Ok(node_sysinfo_local(kind, container)),
        NodeOp::Gcomm => Ok(node_gcomm_local(kind, container)),
        NodeOp::Exists => unreachable!(),
    }
}

/// The gcomm member list from this (local) container's own Galera config,
/// comma-joined with ports/options stripped — empty when the container has
/// no wsrep config or declares the bootstrap form `gcomm://`. Used by adopt
/// to verify the picked containers cover the WHOLE membership.
fn node_gcomm_local(kind: &str, container: &str) -> String {
    let Ok(out) = cexec(
        kind,
        container,
        "grep -rhsE '^[[:space:]]*wsrep_cluster_address[[:space:]]*=' \
         /etc/mysql /etc/my.cnf /etc/my.cnf.d 2>/dev/null",
    ) else {
        return String::new();
    };
    let (_, gcomm) = wsrep_addresses_from_config(&out);
    gcomm.join(",")
}

/// Run a node op on a peer host via its `/api/galera/local/{kind}/{op}/{container}`
/// primitive, authenticated with the cluster secret. Tries the standard URL
/// fallback list (HTTPS / WolfNet / HTTP).
fn remote_op(ctx: &GaleraOpCtx, host: &str, kind: &str, container: &str, op: NodeOp) -> Result<String, String> {
    let target = ctx.resolve_host(host)
        .ok_or_else(|| format!("host '{}' is not a node in this cluster", host))?;
    let path = format!("/api/galera/local/{}/{}/{}", kind, op.as_str(), container);
    let urls = crate::api::build_node_urls(&target.address, target.port, &path);
    let secret = ctx.cluster_secret.clone();
    ctx.rt.block_on(async move {
        let mut last = format!("could not reach host '{}'", host);
        for url in &urls {
            match crate::api::API_HTTP_CLIENT.post(url)
                .peer_auth(&secret)
                .timeout(std::time::Duration::from_secs(op.timeout_secs()))
                .send().await
            {
                Ok(resp) => {
                    let ok = resp.status().is_success();
                    let v: serde_json::Value = resp.json().await.unwrap_or_default();
                    if ok {
                        return Ok(v.get("output").and_then(|o| o.as_str()).unwrap_or("").to_string());
                    }
                    last = v.get("error").and_then(|e| e.as_str()).unwrap_or("remote error").to_string();
                }
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    })
}

/// Run a node op against `host` — local fast-path when it's this node.
fn run_op(ctx: &GaleraOpCtx, host: &str, kind: &str, container: &str, op: NodeOp) -> Result<String, String> {
    if ctx.is_self_host(host) {
        local_node_op(kind, container, op)
    } else {
        remote_op(ctx, host, kind, container, op)
    }
}

/// Does `host` currently run `container`? Local check for self, `Exists` probe
/// for a peer. Unreachable peers answer "no" (skip), not an error.
fn exists_on_host(ctx: &GaleraOpCtx, host: &str, kind: &str, container: &str) -> bool {
    if ctx.is_self_host(host) {
        return container_exists_local(kind, container);
    }
    remote_op(ctx, host, kind, container, NodeOp::Exists)
        .map(|o| o.trim() == "yes")
        .unwrap_or(false)
}

/// Find which WolfStack host currently runs `container`. Tries the recorded
/// host first (one check in the common case), then this node, then every other
/// cluster node — so a migrated container is located where it now lives.
fn locate_host(ctx: &GaleraOpCtx, kind: &str, container: &str, recorded: &str) -> Result<String, String> {
    let mut candidates: Vec<String> = Vec::new();
    for id in std::iter::once(recorded.to_string())
        .chain(std::iter::once(ctx.self_id.clone()))
        .chain(ctx.nodes.iter().map(|n| n.id.clone()))
    {
        if !id.is_empty() && !candidates.contains(&id) {
            candidates.push(id);
        }
    }
    for host in &candidates {
        if exists_on_host(ctx, host, kind, container) {
            return Ok(host.clone());
        }
    }
    Err(format!(
        "container '{}' was not found on any WolfStack node in this cluster — \
         confirm its host is part of this cluster and the container exists.",
        container))
}

/// Self-heal the stored host for a container when discovery found it elsewhere
/// (e.g. after a migration), so status + future ops target the right host.
fn persist_node_host(cluster_id: &str, container: &str, host: &str) {
    if host.is_empty() { return; }
    let _io = GALERA_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut cfg = load_config();
    let mut changed = false;
    if let Some(c) = cfg.clusters.iter_mut().find(|c| c.id == cluster_id)
        && let Some(n) = c.nodes.iter_mut().find(|n| n.container == container)
        && n.node_id != host
    {
        n.node_id = host.to_string();
        changed = true;
    }
    if changed { let _ = save_config(&cfg); }
}

/// Recover a fully-stopped cluster. Locates each node's current host, stops
/// every node, reads each grastate seqno, bootstraps the MOST-ADVANCED node,
/// then rejoins the rest. Refuses to act unless every node is confirmed down
/// and at least one reports a known position — guessing there is how data is lost.
pub fn recover_cluster(cluster: &GaleraCluster, log: &Sender<String>, ctx: &GaleraOpCtx) -> Result<String, String> {
    if cluster.nodes.is_empty() {
        return Err("cluster has no nodes".into());
    }
    // Automated recovery is LXC-only: a stopped Docker MariaDB container can't
    // be exec'd to read its grastate position (its PID 1 is mysqld), so we can't
    // safely pick the most-advanced survivor. Refuse rather than guess.
    if let Some(d) = cluster.nodes.iter().find(|n| n.kind == "docker") {
        return Err(format!(
            "Automated recovery is LXC-only — this cluster has a Docker node ('{}'). \
             Recover Docker Galera nodes through whatever orchestrates them (it controls \
             how each container is restarted with the bootstrap flag).",
            d.container));
    }
    // Resolve each node's CURRENT host once (handles migration) + self-heal.
    let mut located: Vec<(GaleraNode, String)> = Vec::with_capacity(cluster.nodes.len());
    for n in &cluster.nodes {
        let host = locate_host(ctx, &n.kind, &n.container, &n.node_id)
            .map_err(|e| format!("[{}] {}", n.container, e))?;
        persist_node_host(&cluster.id, &n.container, &host);
        located.push((n.clone(), host));
    }
    for (n, host) in &located {
        logln(log, format!("[{}] stopping mariadb to flush its position…", n.container));
        let _ = run_op(ctx, host, &n.kind, &n.container, NodeOp::Stop);
    }
    // Verify every node is actually DOWN before reading positions. A node still
    // running reports seqno -1 (grastate is only written on clean shutdown), and
    // bootstrapping while another node is live corrupts the cluster. If we can't
    // confirm a node is stopped (including: host unreachable), refuse — a wrong
    // bootstrap here rolls the database back. Data safety > convenience.
    for (n, host) in &located {
        let down = run_op(ctx, host, &n.kind, &n.container, NodeOp::IsDown)
            .map(|s| s.trim() == "down").unwrap_or(false);
        if !down {
            return Err(format!(
                "Node '{}' is still running or unreachable after stop — refusing to recover. \
                 A clean recovery needs every node stopped so its committed position is on disk. \
                 Stop MariaDB there (and confirm its host is reachable), then retry.",
                n.container));
        }
    }
    let mut best: Option<(GaleraNode, String, i64)> = None;
    for (n, host) in &located {
        let seq = run_op(ctx, host, &n.kind, &n.container, NodeOp::Seqno)
            .ok().and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(-1);
        logln(log, format!("[{}] grastate seqno = {}", n.container, seq));
        if best.as_ref().map(|(_, _, b)| seq > *b).unwrap_or(true) {
            best = Some((n.clone(), host.clone(), seq));
        }
    }
    let (boot, boot_host, boot_seq) = best.ok_or("could not read any node state")?;
    if boot_seq < 0 {
        return Err(
            "No node reports a known committed position (all seqno = -1). \
             Refusing to bootstrap — picking one here could roll the cluster \
             back. Inspect /var/lib/mysql/grastate.dat on each node and \
             recover the most-advanced one by hand.".to_string()
        );
    }
    logln(log, format!("[{}] is most-advanced (seqno {}) — bootstrapping it.", boot.container, boot_seq));
    run_op(ctx, &boot_host, &boot.kind, &boot.container, NodeOp::Bootstrap)?;
    for (n, host) in &located {
        if n.container == boot.container { continue; }
        logln(log, format!("[{}] rejoining…", n.container));
        let _ = run_op(ctx, host, &n.kind, &n.container, NodeOp::Start);
    }
    Ok(format!("Recovered from '{}' (seqno {}); rejoined {} node(s).", boot.container, boot_seq, cluster.nodes.len() - 1))
}

/// Start / stop / restart MariaDB on one node of a cluster (lifecycle),
/// dispatched to the host that currently runs the container (LXC or Docker).
pub fn node_service(cluster: &GaleraCluster, container: &str, action: &str, ctx: &GaleraOpCtx) -> Result<String, String> {
    let (recorded, kind) = match cluster.nodes.iter().find(|n| n.container == container) {
        Some(n) => (n.node_id.clone(), n.kind.clone()),
        None => return Err(format!("'{}' is not a node of this cluster", container)),
    };
    let op = match action {
        "start" => NodeOp::Start,
        "stop" => NodeOp::Stop,
        "restart" => NodeOp::Restart,
        _ => return Err("action must be start, stop or restart".into()),
    };
    let host = locate_host(ctx, &kind, container, &recorded)?;
    persist_node_host(&cluster.id, container, &host);
    run_op(ctx, &host, &kind, container, op)
}

/// One container the operator picked to adopt: which host runs it, its name,
/// and its runtime.
pub struct AdoptPick {
    pub node_id: String,
    pub container: String,
    pub kind: String,
}

/// Adopt existing containers into a new managed Galera cluster. For each picked
/// container we resolve its reachable address ON ITS HOST (no typing IPs), then
/// persist the cluster scoped to `ws_cluster`. Returns the saved cluster.
pub fn adopt_cluster(
    ws_cluster: &str, name: &str, sst: &str, db_user: &str, db_password: &str,
    picks: &[AdoptPick], ctx: &GaleraOpCtx,
) -> Result<GaleraCluster, String> {
    if picks.is_empty() {
        return Err("select at least one container".into());
    }
    safe_token(name)?;
    let mut nodes: Vec<GaleraNode> = Vec::with_capacity(picks.len());
    for p in picks {
        safe_token(&p.container)?;
        let kind = if p.kind == "docker" { "docker" } else { "lxc" };
        // ALWAYS locate the container by probing every cluster host (the picker's
        // host is only a hint). Probing routes by each host's own local key, so
        // it resolves even when the picked id is a peer self_id this node hasn't
        // directly polled — the case that broke cross-host adopt in a large mesh.
        let host = locate_host(ctx, kind, &p.container, &p.node_id)?;
        let raw = run_op(ctx, &host, kind, &p.container, NodeOp::Address)
            .map_err(|e| format!("[{}] couldn't resolve address: {}", p.container, e))?;
        // The host normally returns one picked address, but an older
        // remote (≤ v25.14.0) sends the raw multi-homed list — pick here
        // too so a mixed-version cluster still adopts. A bare hostname
        // has no parseable IP and passes through untouched.
        let addr = crate::containers::pick_cross_host_ip(&raw, None)
            .unwrap_or_else(|| raw.trim().to_string());
        if !valid_address(&addr) {
            return Err(format!(
                "[{}] no reachable address found (got '{}') — is the container running and on WolfNet?",
                p.container, raw.trim()));
        }
        nodes.push(GaleraNode {
            node_id: host,
            container: p.container.clone(),
            kind: kind.to_string(),
            address: addr,
            port: 3306,
            node_name: p.container.clone(),
        });
    }
    // The cluster's own gcomm list is the authoritative membership — the
    // picked containers must cover ALL of it. Adopting a subset would put
    // WolfStack in charge of a cluster it can only half see: recovery
    // stops "every node" and bootstraps the most-advanced, and doing that
    // while an unmanaged member is still live corrupts the cluster (the
    // exact hazard recover_cluster's down-check exists for). The list is
    // read from a picked node's config; when none yields one (stopped
    // containers, or their hosts run an older WolfStack without the gcomm
    // op) the check is skipped rather than blocking the adopt.
    let picked: std::collections::HashSet<&str> =
        nodes.iter().map(|n| n.address.as_str()).collect();
    for n in &nodes {
        let Ok(list) = run_op(ctx, &n.node_id, &n.kind, &n.container, NodeOp::Gcomm) else { continue };
        let members: Vec<&str> = list.trim().split(',').map(str::trim)
            .filter(|m| !m.is_empty()).collect();
        if members.is_empty() {
            continue;
        }
        let missing: Vec<&str> = members.iter()
            .filter(|m| !picked.contains(**m))
            .filter(|m| {
                // A gcomm member named by HOSTNAME can still be a picked
                // node whose address resolved as an IP — resolve before
                // calling it missing (DNS is fine here: adopt runs on the
                // blocking pool).
                use std::net::ToSocketAddrs;
                let covered_via_dns = (**m, 0u16).to_socket_addrs()
                    .map(|addrs| {
                        let mut addrs = addrs;
                        addrs.any(|a| picked.contains(a.ip().to_string().as_str()))
                    })
                    .unwrap_or(false);
                !covered_via_dns
            })
            .copied().collect();
        if !missing.is_empty() {
            return Err(format!(
                "[{}] this cluster's own config (gcomm) also lists {} — tick the container(s) \
                 holding those addresses too, so WolfStack manages the WHOLE cluster. Managing \
                 a subset would make recovery unsafe (it must be able to stop every member).",
                n.container, missing.join(", ")));
        }
        break; // one authoritative list verified is enough
    }
    let cluster = GaleraCluster {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        cluster: ws_cluster.to_string(),
        owner_node: String::new(), // filled by upsert_cluster = this node
        nodes,
        sst_method: if sst.is_empty() { default_sst() } else { sst.to_string() },
        db_user: if db_user.is_empty() { default_db_user() } else { db_user.to_string() },
        db_password_enc: String::new(),
        created_at: chrono::Utc::now().to_rfc3339(),
        provisioned: false,
        proxies: Vec::new(),
    };
    let pw = if db_password.is_empty() { None } else { Some(db_password) };
    upsert_cluster(cluster, pw)
}

// ── Tuning analyzer (advisory + one-click apply) ─────────────────────
//
// For each node we read SHOW GLOBAL VARIABLES + STATUS (over SQL) and the
// container's RAM/cores (host-aware Sysinfo op), then flag the settings that
// matter for a Galera node and recommend values. "Apply" is allowlist-gated:
// SET GLOBAL live on every reachable node (dynamic settings) AND persist the
// value to a managed include file so it survives a restart.

#[derive(Debug, Clone, Serialize)]
pub struct Recommendation {
    pub key: String,
    pub current: String,
    pub current_display: String,
    pub recommended: String,
    pub recommended_display: String,
    /// "ok" | "improve" | "warn"
    pub severity: String,
    pub why: String,
    /// SET GLOBAL applies live; otherwise it needs a node restart.
    pub dynamic: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeAnalysis {
    pub container: String,
    pub reachable: bool,
    pub error: String,
    pub ram_bytes: u64,
    pub cores: u32,
    pub recommendations: Vec<Recommendation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterAnalysis {
    pub cluster_id: String,
    pub nodes: Vec<NodeAnalysis>,
}

/// Per-node SHOW GLOBAL VARIABLES + STATUS, gathered over SQL.
pub struct NodeSql {
    pub container: String,
    pub kind: String,
    pub node_id: String,
    pub reachable: bool,
    pub error: String,
    pub vars: HashMap<String, String>,
    pub status: HashMap<String, String>,
}

/// Settings the analyzer may recommend AND apply. Returns whether each is
/// dynamic (SET GLOBAL-able). Anything not here is REFUSED by apply — we never
/// set an arbitrary variable.
pub fn is_tunable(key: &str) -> Option<bool> {
    Some(match key {
        "innodb_buffer_pool_size" => true,
        "wsrep_slave_threads" => true,
        "innodb_flush_log_at_trx_commit" => true,
        "sync_binlog" => true,
        "query_cache_type" => true,
        "query_cache_size" => true,
        "max_connections" => true,
        "innodb_log_file_size" => false,        // needs restart
        "innodb_buffer_pool_instances" => false, // needs restart
        _ => return None,
    })
}

fn human_bytes(b: u64) -> String {
    const G: u64 = 1 << 30;
    const M: u64 = 1 << 20;
    if b >= G { format!("{:.1}G", b as f64 / G as f64) }
    else if b >= M { format!("{}M", b / M) }
    else if b >= 1024 { format!("{}K", b / 1024) }
    else { b.to_string() }
}

/// Compute recommendations for one node from its variables + status + resources.
fn analyze_node(vars: &HashMap<String, String>, status: &HashMap<String, String>, ram: u64, cores: u32) -> Vec<Recommendation> {
    let mut recs = Vec::new();
    let vs = |k: &str| vars.get(k).cloned().unwrap_or_default();
    let vu = |k: &str| vars.get(k).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let su = |k: &str| status.get(k).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let mut push = |key: &str, current: String, current_display: String, recommended: String, recommended_display: String, severity: &str, why: String, dynamic: bool| {
        recs.push(Recommendation { key: key.into(), current, current_display, recommended, recommended_display, severity: severity.into(), why, dynamic });
    };

    // innodb_buffer_pool_size ≈ 70% of RAM.
    if ram > 0 {
        let cur = vu("innodb_buffer_pool_size");
        let rec = {
            let raw = (ram as f64 * 0.70) as u64;
            let step = 128 * (1 << 20);
            (raw / step).max(1) * step
        };
        let (sev, why) = if (cur as f64) < ram as f64 * 0.5 {
            ("improve", format!("Buffer pool is {} of {} RAM — undersized, so InnoDB keeps re-reading from disk. ~70% RAM lets the working set live in memory.", human_bytes(cur), human_bytes(ram)))
        } else if (cur as f64) > ram as f64 * 0.85 {
            ("warn", format!("Buffer pool is {} of only {} RAM — leaves little headroom for connections/temp tables and risks the OOM killer.", human_bytes(cur), human_bytes(ram)))
        } else {
            ("ok", format!("Buffer pool {} is a healthy share of {} RAM.", human_bytes(cur), human_bytes(ram)))
        };
        push("innodb_buffer_pool_size", cur.to_string(), human_bytes(cur), rec.to_string(), human_bytes(rec), sev, why, true);
    }

    // wsrep_slave_threads ≈ CPU cores.
    {
        let cur = vu("wsrep_slave_threads");
        let rec = (cores as u64).clamp(2, 16);
        let (sev, why) = if cur < rec {
            ("improve", format!("Only {} apply thread(s) for {} cores — replicated writes apply mostly serially. Match it to the cores to parallelise apply.", cur.max(1), cores))
        } else {
            ("ok", format!("{} apply threads suits {} cores.", cur, cores))
        };
        push("wsrep_slave_threads", cur.to_string(), cur.to_string(), rec.to_string(), rec.to_string(), sev, why, true);
    }

    // innodb_flush_log_at_trx_commit → 2 on a cluster (only flag when it's 1).
    if vs("innodb_flush_log_at_trx_commit") == "1" {
        push("innodb_flush_log_at_trx_commit", "1".into(), "1".into(), "2".into(), "2".into(), "improve",
            "On a Galera cluster durability comes from synchronous replication to the other nodes, so flushing the redo log to disk on every commit (=1) costs throughput for little gain. 2 flushes once per second.".into(), true);
    }

    // sync_binlog → 0 when the binlog is on. (log_bin may be reported ON or 1.)
    if vs("log_bin").eq_ignore_ascii_case("ON") || vs("log_bin") == "1" {
        let cur = vs("sync_binlog");
        if cur != "0" {
            push("sync_binlog", cur.clone(), cur, "0".into(), "0".into(), "improve",
                "fsync-per-write to the binlog (=1) is redundant durability under Galera and throttles writes. 0 lets the OS flush it.".into(), true);
        }
    }

    // query cache → off.
    {
        let qct = vs("query_cache_type");
        let qcs = vu("query_cache_size");
        let on = qcs > 0 && !qct.eq_ignore_ascii_case("OFF") && qct != "0";
        if on {
            push("query_cache_type", qct.clone(), qct, "0".into(), "OFF".into(), "warn",
                "The query cache serialises writes behind a global mutex — it hurts throughput on a write-replicated cluster (and is removed in MariaDB 10.6+). Turn it off.".into(), true);
            push("query_cache_size", qcs.to_string(), human_bytes(qcs), "0".into(), "0".into(), "warn",
                "Free the query-cache memory once the cache is disabled.".into(), true);
        }
    }

    // max_connections vs observed peak.
    {
        let cur = vu("max_connections");
        let peak = su("Max_used_connections");
        if cur > 0 && peak.saturating_mul(100) > cur.saturating_mul(80) {
            let rec = ((peak as f64 * 1.5) as u64).max(cur + 50);
            push("max_connections", cur.to_string(), cur.to_string(), rec.to_string(), rec.to_string(), "improve",
                format!("Peak usage hit {} — over 80% of the {} limit. Raise it before clients start getting 'Too many connections'.", peak, cur), true);
        }
    }

    // innodb_log_file_size ≈ 25% of buffer pool (restart needed).
    {
        let cur = vu("innodb_log_file_size");
        let bp = vu("innodb_buffer_pool_size");
        if bp > 0 {
            let rec = (bp / 4).clamp(256 * (1 << 20), 4 * (1u64 << 30));
            if cur > 0 && cur * 2 < rec {
                push("innodb_log_file_size", cur.to_string(), human_bytes(cur), rec.to_string(), human_bytes(rec), "improve",
                    format!("Redo log {} is small for a {} buffer pool — forces frequent checkpoint flushing under write load. (Requires a node restart.)", human_bytes(cur), human_bytes(bp)), false);
            }
        }
    }

    recs
}

/// Gather SHOW GLOBAL VARIABLES + STATUS for every node, concurrently.
pub async fn analyze_sql(cluster: &GaleraCluster) -> Vec<NodeSql> {
    let pw = dec_secret(&cluster.db_password_enc);
    futures::future::join_all(cluster.nodes.iter().map(|n| node_vars_status(n, &cluster.db_user, &pw))).await
}

async fn node_vars_status(n: &GaleraNode, user: &str, pw: &str) -> NodeSql {
    let params = crate::mysql_editor::ConnParams {
        host: n.address.clone(), port: n.port, user: user.to_string(), password: pw.to_string(),
        database: None, db_type: crate::mysql_editor::DbType::default(),
    };
    let mut out = NodeSql {
        container: n.container.clone(), kind: n.kind.clone(), node_id: n.node_id.clone(),
        reachable: false, error: String::new(), vars: HashMap::new(), status: HashMap::new(),
    };
    match crate::mysql_editor::execute_query(&params, "", "SHOW GLOBAL VARIABLES").await {
        Ok(v) => {
            out.reachable = true;
            out.vars = wsrep_map(&v);
            if let Ok(s) = crate::mysql_editor::execute_query(&params, "", "SHOW GLOBAL STATUS").await {
                out.status = wsrep_map(&s);
            }
        }
        Err(e) => out.error = e,
    }
    out
}

/// Build the full analysis: combine the SQL with each node's RAM/cores (resolved
/// host-aware via the Sysinfo op) and compute recommendations. Sync — call from
/// `web::block` (it uses run_op/block_on).
pub fn build_analysis(cluster: &GaleraCluster, sqls: Vec<NodeSql>, ctx: &GaleraOpCtx) -> ClusterAnalysis {
    let nodes = sqls.into_iter().map(|sql| {
        if !sql.reachable {
            return NodeAnalysis { container: sql.container, reachable: false, error: sql.error, ram_bytes: 0, cores: 0, recommendations: vec![] };
        }
        let host = locate_host(ctx, &sql.kind, &sql.container, &sql.node_id).unwrap_or_else(|_| sql.node_id.clone());
        let si = run_op(ctx, &host, &sql.kind, &sql.container, NodeOp::Sysinfo).unwrap_or_default();
        let mut parts = si.split_whitespace();
        let ram = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        let cores = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(1);
        let recs = analyze_node(&sql.vars, &sql.status, ram, cores);
        NodeAnalysis { container: sql.container, reachable: true, error: String::new(), ram_bytes: ram, cores, recommendations: recs }
    }).collect();
    ClusterAnalysis { cluster_id: cluster.id.clone(), nodes }
}

/// `SET GLOBAL key = value` on every reachable node (live, dynamic settings).
/// Concurrent. Returns (container, ok?) per node.
pub async fn set_global_cluster(cluster: &GaleraCluster, key: &str, value: &str) -> Vec<(String, Result<(), String>)> {
    let pw = dec_secret(&cluster.db_password_enc);
    let user = cluster.db_user.clone();
    futures::future::join_all(cluster.nodes.iter().map(|n| {
        let (user, pw, key, value) = (user.clone(), pw.clone(), key.to_string(), value.to_string());
        async move {
            let params = crate::mysql_editor::ConnParams {
                host: n.address.clone(), port: n.port, user, password: pw,
                database: None, db_type: crate::mysql_editor::DbType::default(),
            };
            let sql = format!("SET GLOBAL {} = {}", key, value);
            let r = crate::mysql_editor::execute_query(&params, "", &sql).await.map(|_| ());
            (n.container.clone(), r)
        }
    })).await
}

/// Persist `key = value` into a managed include file inside THIS (local)
/// container so it survives a restart. key + value are allowlist/format checked.
pub fn write_tuning_local(kind: &str, container: &str, key: &str, value: &str) -> Result<(), String> {
    if is_tunable(key).is_none() {
        return Err(format!("'{}' is not a tunable setting", key));
    }
    if value.is_empty() || !value.chars().all(|c| c.is_ascii_digit()) {
        return Err("value must be a non-negative integer".into());
    }
    safe_token(container)?;
    // Pick the distro's conf.d include dir, drop a 99-wolfstack-tuning.cnf, and
    // replace any prior line for this key. key/value are validated, so safe.
    let script = format!(
        "f=\"\"; for d in /etc/mysql/mariadb.conf.d /etc/my.cnf.d /etc/mysql/conf.d; do [ -d \"$d\" ] && f=\"$d/99-wolfstack-tuning.cnf\" && break; done; \
         [ -z \"$f\" ] && {{ mkdir -p /etc/mysql/mariadb.conf.d; f=/etc/mysql/mariadb.conf.d/99-wolfstack-tuning.cnf; }}; \
         grep -q '^\\[mysqld\\]' \"$f\" 2>/dev/null || printf '[mysqld]\\n' >> \"$f\"; \
         sed -i '/^{key}[[:space:]]*=/d' \"$f\"; \
         printf '{key} = {value}\\n' >> \"$f\"",
        key = key, value = value);
    cexec(kind, container, &script).map(|_| ())
}

/// Persist a setting into every node's managed include, host-aware. Sync — call
/// from `web::block`. Returns (container, ok?) per node.
pub fn persist_tuning_cluster(cluster: &GaleraCluster, key: &str, value: &str, ctx: &GaleraOpCtx) -> Vec<(String, Result<(), String>)> {
    cluster.nodes.iter().map(|n| {
        let host = locate_host(ctx, &n.kind, &n.container, &n.node_id).unwrap_or_else(|_| n.node_id.clone());
        let r = if ctx.is_self_host(&host) {
            write_tuning_local(&n.kind, &n.container, key, value)
        } else {
            persist_tuning_remote(ctx, &host, &n.kind, &n.container, key, value)
        };
        (n.container.clone(), r)
    }).collect()
}

/// POST the tuning write to a peer host's local endpoint.
fn persist_tuning_remote(ctx: &GaleraOpCtx, host: &str, kind: &str, container: &str, key: &str, value: &str) -> Result<(), String> {
    let target = ctx.resolve_host(host)
        .ok_or_else(|| format!("host '{}' is not a node in this cluster", host))?;
    let path = format!("/api/galera/local/tuning/{}/{}", kind, container);
    let urls = crate::api::build_node_urls(&target.address, target.port, &path);
    let secret = ctx.cluster_secret.clone();
    let body = serde_json::json!({ "key": key, "value": value });
    ctx.rt.block_on(async move {
        let mut last = format!("could not reach host '{}'", host);
        for url in &urls {
            match crate::api::API_HTTP_CLIENT.post(url)
                .peer_auth(&secret)
                .timeout(std::time::Duration::from_secs(20))
                .json(&body)
                .send().await
            {
                Ok(resp) => {
                    let ok = resp.status().is_success();
                    let v: serde_json::Value = resp.json().await.unwrap_or_default();
                    if ok { return Ok(()); }
                    last = v.get("error").and_then(|e| e.as_str()).unwrap_or("remote error").to_string();
                }
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    })
}

#[cfg(test)]
mod tests {
    use super::{strip_wsrep_port, wsrep_addresses_from_config};

    /// Adopt reads the addresses the running cluster ALREADY uses out of
    /// each node's own config (Paul, 2026-08-14) — a realistic
    /// 60-galera.cnf must yield the node address exactly.
    #[test]
    fn node_address_is_read_from_a_real_galera_cnf() {
        let cnf = r#"
[galera]
wsrep_on=ON
wsrep_provider=/usr/lib/galera/libgalera_smm.so
wsrep_cluster_name="wolf-galera"
wsrep_cluster_address="gcomm://10.0.10.111,10.0.10.112,10.0.10.113"
wsrep_node_address="10.0.10.111"
wsrep_node_name=iw-db-1
"#;
        let (node, gcomm) = wsrep_addresses_from_config(cnf);
        assert_eq!(node.as_deref(), Some("10.0.10.111"));
        assert_eq!(gcomm, vec!["10.0.10.111", "10.0.10.112", "10.0.10.113"]);
    }

    /// Without wsrep_node_address (Galera auto-detects its bind), the
    /// gcomm member list is still authoritative — ports and gmcast
    /// options must not leak into the parsed members.
    #[test]
    fn gcomm_members_are_parsed_with_ports_and_options_stripped() {
        let cnf = "wsrep_cluster_address = gcomm://10.0.10.111:4567,10.0.10.112:4567?gmcast.segment=1\n";
        let (node, gcomm) = wsrep_addresses_from_config(cnf);
        assert_eq!(node, None);
        assert_eq!(gcomm, vec!["10.0.10.111", "10.0.10.112"]);
    }

    /// MariaDB layers config files with last-occurrence-wins; the parser
    /// must agree, and must never adopt an address that tells peers to
    /// talk to themselves.
    #[test]
    fn last_occurrence_wins_and_unusable_addresses_are_refused() {
        let cnf = "wsrep_node_address=10.9.9.9\nwsrep_node_address=10.0.10.111:4567\n";
        assert_eq!(wsrep_addresses_from_config(cnf).0.as_deref(), Some("10.0.10.111"));
        assert_eq!(wsrep_addresses_from_config("wsrep_node_address=0.0.0.0\n").0, None);
        assert_eq!(wsrep_addresses_from_config("wsrep_node_address=127.0.0.1\n").0, None);
        // An empty bootstrap-form gcomm has no members to match against.
        assert_eq!(wsrep_addresses_from_config("wsrep_cluster_address=gcomm://\n").1.len(), 0);
    }

    /// Port stripping across the address forms wsrep accepts.
    #[test]
    fn wsrep_port_stripping_handles_v4_v6_and_hostnames() {
        assert_eq!(strip_wsrep_port("10.0.10.111:4567"), "10.0.10.111");
        assert_eq!(strip_wsrep_port("10.0.10.111"), "10.0.10.111");
        assert_eq!(strip_wsrep_port("[2a01:4f8::1]:4567"), "2a01:4f8::1");
        // A bare IPv6 address parses whole — its colons are not a port.
        assert_eq!(strip_wsrep_port("2a01:4f8::1"), "2a01:4f8::1");
        assert_eq!(strip_wsrep_port("db-node-2.internal:4567"), "db-node-2.internal");
        assert_eq!(strip_wsrep_port("db-node-2.internal"), "db-node-2.internal");
    }
}
