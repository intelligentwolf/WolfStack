// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Agent — handles server-to-server communication
//!
//! Each WolfStack instance runs an agent that:
//! - Reports its metrics to the cluster
//! - Accepts commands from other WolfStack nodes
//! - Discovers other nodes (via WolfNet or direct IP)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::monitoring::SystemMetrics;
use crate::installer::ComponentStatus;
use crate::node_identity::PeerAuth;

/// Per-file result of `leave_wipe_membership_files`. A `cleared` of
/// `false` either means the file was already absent (treat as success)
/// or the unlink failed; `error` differentiates the two so the CLI can
/// print a useful message and the HTTP handler can surface it to the UI.
#[derive(Debug, Clone, Serialize)]
pub struct LeaveWipeFile {
    pub path: String,
    pub cleared: bool,
    pub already_absent: bool,
    pub error: Option<String>,
}

/// Summary of the on-disk side of leaving the cluster. Returned by
/// `leave_wipe_membership_files` and surfaced to both the CLI and the
/// HTTP response. `previous_cluster_name` is captured before deletion
/// so the operator can see which cluster they were just in.
#[derive(Debug, Clone, Serialize)]
pub struct LeaveWipeResult {
    pub previous_cluster_name: Option<String>,
    pub files: Vec<LeaveWipeFile>,
}

/// Delete the on-disk files that make this node a member of its cluster:
///   • `self_cluster.json`  — this node's chosen cluster name
///   • `nodes.json`         — every peer we know about
///   • `deleted_nodes.json` — tombstones (stale once we're starting fresh)
///   • `node_id`            — this node's stable identity; regenerated on
///                            next start so any tombstones held by old peers
///                            for our prior ID can't block a clean re-join
///
/// Does NOT touch `custom-cluster-secret` — secret rotation is a separate
/// opt-in step so the operator can decide whether to lock old peers out.
/// Caller is responsible for ensuring the running service won't immediately
/// re-write these files (`ClusterState::clear_membership_in_memory` first,
/// or stop the service for the CLI path).
pub fn leave_wipe_membership_files() -> LeaveWipeResult {
    let p = crate::paths::get();
    let previous_cluster_name = std::fs::read_to_string(&p.self_cluster_config)
        .ok()
        .and_then(|s| serde_json::from_str::<String>(s.trim()).ok())
        .filter(|s| !s.is_empty());

    let targets = [
        p.self_cluster_config.clone(),
        p.nodes_config.clone(),
        p.deleted_nodes_config.clone(),
        p.node_id_file.clone(),
    ];

    let mut files = Vec::with_capacity(targets.len());
    for path in &targets {
        match std::fs::remove_file(path) {
            Ok(()) => files.push(LeaveWipeFile {
                path: path.clone(),
                cleared: true,
                already_absent: false,
                error: None,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => files.push(LeaveWipeFile {
                path: path.clone(),
                cleared: false,
                already_absent: true,
                error: None,
            }),
            Err(e) => files.push(LeaveWipeFile {
                path: path.clone(),
                cleared: false,
                already_absent: false,
                error: Some(e.to_string()),
            }),
        }
    }
    LeaveWipeResult { previous_cluster_name, files }
}

/// Check whether `wolfstack.service` is currently active. Used by the
/// `--leave-cluster` CLI to refuse a wipe while the daemon is running
/// (otherwise its in-memory copies would race-rewrite the files we just
/// deleted). Returns `None` when systemctl isn't available — caller
/// should treat that as "unknown, allow with warning".
pub fn leave_is_service_active() -> Option<bool> {
    let out = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "wolfstack"])
        .status()
        .ok()?;
    Some(out.success())
}

/// Check if an address is on a private/local network (RFC1918 + loopback + link-local)
/// This is used to restrict gossip auto-discovery to local networks only.
fn is_private_address(addr: &str) -> bool {
    // Parse as IP address. to_canonical: judge a mapped ::ffff:a.b.c.d
    // by its real v4 identity (dual-stack [::] listeners report those).
    if let Ok(ip) = addr.parse::<std::net::IpAddr>().map(|a| a.to_canonical()) {
        match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_private()       // 10.x, 172.16-31.x, 192.168.x
                || v4.is_loopback()   // 127.x
                || v4.is_link_local() // 169.254.x
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()                          // ::1
                // RFC 4193 ULA fc00::/7 — the v6 analogue of RFC1918
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // RFC 4291 link-local fe80::/10 — private but unusable
                // as an advertised address; is_usable_addr rejects it
                || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    } else {
        // Not a valid IP (could be a hostname) — treat as local
        // This handles things like "localhost" or hostnames on local DNS
        true
    }
}

/// The `/24` prefix (`a.b.c`) of a private IPv4 address, else None. Used to
/// match a node's local LAN IP to the subnet its private peers live on.
fn lan24_prefix(addr: &str) -> Option<String> {
    let ip = addr.parse::<std::net::Ipv4Addr>().ok()?;
    if !ip.is_private() {
        return None;
    }
    let o = ip.octets();
    Some(format!("{}.{}.{}", o[0], o[1], o[2]))
}

/// An address peers can actually CONNECT to. A node advertises its own address
/// as the bind address (`cli.bind`, usually the wildcard `0.0.0.0`), which is
/// unreachable from anywhere else — so a self-entry carrying `0.0.0.0` must
/// never be added or used to overwrite a real address. Peers learn a node's
/// real address from the source IP of its inbound pushes instead (GitHub: the
/// hub "main" was missing from every other node because its self-entry's
/// 0.0.0.0 failed is_private_address).
///
/// IPv6 link-local (fe80::/10) is also unusable as a STORED address: it is
/// only reachable with a zone/scope id ("fe80::1%eth0") which is meaningless
/// on any other host, and a v6 peer connecting from link-local would
/// otherwise be "learned" under an address nobody can dial back.
pub fn is_usable_addr(addr: &str) -> bool {
    let a = addr.trim();
    if a.is_empty()
        || a == "0.0.0.0"
        || a == "::"
        || a == "[::]"
        || a == "0.0.0.0/0"
        || a.starts_with("0.0.0.0:")
        || a.starts_with("[::]:")
    {
        return false;
    }
    // Reject v6 link-local in every spelling we can see: bare, bracketed,
    // and zone-scoped (the %zone suffix fails Ipv6Addr parsing, so match
    // on the prefix for that form). Also reject IPv4-mapped forms
    // (::ffff:a.b.c.d): they are dual-stack socket artifacts, dialable
    // only from the host that saw them — learn sites canonicalize to
    // plain v4 BEFORE storing, so a mapped string reaching here is junk
    // that would otherwise become an undialable [::ffff:…] URL.
    let bare = a.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(a);
    if let Ok(v6) = bare.parse::<std::net::Ipv6Addr>()
        && ((v6.segments()[0] & 0xffc0) == 0xfe80 || v6.to_ipv4_mapped().is_some())
    {
        return false;
    }
    let lower = bare.to_ascii_lowercase();
    if lower.starts_with("fe8") || lower.starts_with("fe9")
        || lower.starts_with("fea") || lower.starts_with("feb")
    {
        // Zone-scoped fallback ONLY: fe80::/10 spans fe80..febf, and a
        // "%zone" suffix makes the Ipv6Addr parse above fail, so those
        // forms are caught here by prefix. Require a colon so a hostname
        // like "fe8-server.lan" is never rejected.
        if lower.contains(':') {
            return false;
        }
    }
    true
}

/// Track consecutive poll failures per node — only mark offline after 2+ failures
static POLL_FAIL_COUNTS: std::sync::LazyLock<std::sync::Mutex<HashMap<String, u32>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// A tier role an operator can assign to a node so it serves ONE part of an
/// HA hosting stack (NoroNetwork 2026-07-09). A node's roles are the keystone
/// the DNS / mail / ingress / host tiers dispatch on: config for a subsystem
/// is pushed only to the nodes that carry its role.
///
/// An EMPTY roles list is the default and means "general-purpose node" — it
/// participates in everything exactly as before roles existed (Golden Rule:
/// older nodes.json and older peers deserialize `roles` as empty, so nothing
/// changes for an existing cluster until an operator assigns a role). Roles
/// are additive: one node may be both `Dns` and `MailRelay`, e.g. a cheap VPS
/// acting as a nameserver AND a backup MX.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Authoritative DNS server (one of the ≥3 NS tier). WolfHost zone
    /// writes fan out to every node carrying this role.
    Dns,
    /// Dedicated mail store (the ≥2-node mail tier).
    Mail,
    /// SMTP relay / backup MX — pairs well with `Dns` on a cheap VPS with a
    /// good PTR record.
    MailRelay,
    /// Public ingress / reverse proxy. Client traffic enters here and is
    /// proxied to `Host` nodes.
    Ingress,
    /// Web host — runs client websites. Site data lives on shared storage so
    /// another `Host` can take over when one fails.
    Host,
    /// Database tier node (Galera / Postgres HA member).
    Database,
    /// Catch-all for a role a newer peer added that this build doesn't know.
    /// Never assigned locally, never offered in the UI — keeps a mixed-version
    /// gossip payload decodable instead of rejecting the whole node.
    #[serde(other)]
    Unknown,
}

impl NodeRole {
    /// Operator-facing label.
    pub fn label(&self) -> &'static str {
        match self {
            NodeRole::Dns => "DNS",
            NodeRole::Mail => "Mail",
            NodeRole::MailRelay => "Mail relay",
            NodeRole::Ingress => "Ingress",
            NodeRole::Host => "Web host",
            NodeRole::Database => "Database",
            NodeRole::Unknown => "Unknown",
        }
    }

    /// The roles an operator can pick in the UI (excludes `Unknown`).
    pub fn assignable() -> &'static [NodeRole] {
        &[
            NodeRole::Dns, NodeRole::Mail, NodeRole::MailRelay,
            NodeRole::Ingress, NodeRole::Host, NodeRole::Database,
        ]
    }
}

/// A node in the WolfStack cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub hostname: String,
    pub address: String,
    pub port: u16,
    /// Optional address to use for MIGRATION / bulk-transfer traffic to this
    /// node, so an operator can pin VM/LXC migration uploads onto a dedicated
    /// NIC (e.g. a 2.5GbE link) while control/cluster comms keep using
    /// `address`. Local per-peer routing knowledge, exactly like `address` —
    /// set via node settings, preserved across gossip polls (NOT self-reported
    /// by the peer). `None`/blank ⇒ fall back to `address` (see
    /// `migration_host`). Backward-compat: missing in older configs/peers.
    #[serde(default)]
    pub migration_address: Option<String>,
    pub last_seen: u64,     // unix timestamp
    pub metrics: Option<SystemMetrics>,
    pub components: Vec<ComponentStatus>,
    pub online: bool,
    pub is_self: bool,
    #[serde(default)]
    pub docker_count: u32,
    #[serde(default)]
    pub lxc_count: u32,
    #[serde(default)]
    pub vm_count: u32,
    /// Number of Docker Compose stacks on this node — shown in the nav next to
    /// Docker/LXC/VM counts (Gary/KO4BSR 2026-06-27). Backward-compat: missing
    /// in older nodes.json / older peers' gossip → deserializes as 0.
    #[serde(default)]
    pub compose_count: u32,
    #[serde(default)]
    pub public_ip: Option<String>,
    #[serde(default = "default_node_type")]
    pub node_type: String,              // "wolfstack" or "proxmox"
    #[serde(default)]
    pub pve_token: Option<String>,      // PVEAPIToken string
    #[serde(default)]
    pub pve_fingerprint: Option<String>,
    #[serde(default)]
    pub pve_node_name: Option<String>,  // Proxmox node name for API calls
    #[serde(default)]
    pub pve_cluster_name: Option<String>, // User-friendly cluster name for sidebar grouping
    #[serde(default)]
    pub cluster_name: Option<String>,     // Generic cluster name for WolfStack nodes
    #[serde(default)]
    pub join_verified: bool,              // Whether this node was added with a valid join token
    #[serde(default)]
    pub has_docker: bool,                 // Whether Docker is installed on this node
    #[serde(default)]
    pub has_lxc: bool,                    // Whether LXC is installed on this node
    #[serde(default)]
    pub has_kvm: bool,                    // Whether KVM/QEMU is installed on this node
    #[serde(default)]
    pub login_disabled: bool,             // Whether direct login is disabled on this node
    #[serde(default)]
    pub tls: bool,                        // Whether this node serves HTTPS on its main port
    #[serde(default)]
    pub update_script: Option<String>,    // Custom install/update script command
    /// The peer's own self_id (from its `/etc/wolfstack/node_id`). Captured
    /// on first successful poll. Cluster.nodes is keyed by a locally-assigned
    /// `node-{uuid}` ID, but topology / router config / WolfNet endpoints
    /// stamp responses with the peer's self_id — so cross-node proxy lookups
    /// must accept either form. `get_node` falls back to a self_id scan when
    /// the direct key lookup misses; this field is what that scan reads.
    /// `None` until the first poll succeeds (and forever for self).
    #[serde(default)]
    pub self_id: Option<String>,
    /// This node's Ed25519 public key (base64), pinned from its OWN status
    /// report — never copied from another peer's gossip. `None` until the
    /// node runs a build that signs. See `node_identity`.
    #[serde(default)]
    pub pubkey: Option<String>,
    /// Whether peers accept operator actions forwarded BY this node
    /// (`X-WolfStack-Proxied` from it). Operator-set, distributed to every
    /// peer, never self-reported. Defaults to true so an upgrade changes
    /// nothing; tighten it for nodes where nobody logs in.
    #[serde(default = "default_true")]
    pub manager: bool,
    /// Workload subnets (Docker / LXC / VM bridges) on this peer. Shipped
    /// in every StatusReport so the cluster can detect when WolfRouter
    /// subnet_routes are missing for a remote peer's workloads — that's
    /// the "peers reachable but the VMs behind them aren't" symptom Klas
    /// 2026-05-11 hit, and what the `missing_wolfnet_subnet_route`
    /// analyzer scans for. Empty for self until populated by the agent
    /// loop on first poll. Backward-compat: nodes from older versions
    /// deserialize this as an empty Vec.
    #[serde(default)]
    pub workload_subnets: Vec<String>,
    /// Optional physical-location tag declared by the operator. Two
    /// nodes that share a `site` are considered to be on the same
    /// L2/L3 LAN and can dial each other directly at their
    /// `lan_address`; nodes with different sites (or one tagged + one
    /// untagged in a way that doesn't match) must go via public IP.
    ///
    /// Drives `pick_wolfnet_endpoint` in the cluster-sync. When `None`,
    /// `networking::effective_site` falls back to the first three
    /// octets of `address` (e.g. `auto:192.168.10`) so single-LAN
    /// clusters keep their pre-tag behaviour — all members share an
    /// auto-derived site and dial directly. The operator-set value
    /// overrides the auto-derived one and is what shows up in the
    /// UI's "Site" field.
    ///
    /// Backward-compat: serializes/deserializes as missing for older
    /// configs and older peers (gossip stays compatible).
    #[serde(default)]
    pub site: Option<String>,
    /// Operator-set friendly DISPLAY NAME, distinct from the OS `hostname`.
    /// Persisted on the OWNING node (`self_display_name.json`), carried in
    /// its StatusReport, and authoritative on merge — exactly like `site`.
    /// The UI shows `display_name` when set, else falls back to `hostname`.
    /// Keeping it separate from `hostname` is what stops a rename from being
    /// clobbered by the node's self-reported OS hostname every poll.
    ///
    /// Backward-compat: missing for older configs and older peers (gossip
    /// stays compatible); `None` means "no override, show the hostname".
    #[serde(default)]
    pub display_name: Option<String>,
    /// Tier roles assigned to this node (DNS / mail / ingress / host / …).
    /// Persisted on the OWNING node (`self_roles.json`), carried in its
    /// StatusReport, authoritative on merge — exactly like `site` and
    /// `display_name`. Empty = general-purpose node (the default).
    ///
    /// Backward-compat: missing for older configs and older peers → empty Vec.
    #[serde(default)]
    pub roles: Vec<NodeRole>,
}

impl Node {
    /// Host to dial for MIGRATION / bulk data transfer to this node. Returns
    /// the operator-set `migration_address` when present and non-blank,
    /// otherwise falls back to `address`. Everything that is NOT migration
    /// (cluster gossip, control-plane calls) keeps using `address` directly.
    pub fn migration_host(&self) -> &str {
        match self.migration_address.as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => s,
            _ => &self.address,
        }
    }
}

fn default_true() -> bool { true }

fn default_node_type() -> String { "wolfstack".to_string() }

/// Case-insensitive equality for optional cluster names (`None == None`).
/// A cluster name is an identifier, so "minio" and "Minio" are the SAME
/// cluster — comparing them case-sensitively made same-cluster nodes split
/// into two groups and let gossip flip-flop a node between the two cases
/// (each node kept re-asserting its own stored case). Matching/adoption goes
/// through this; the operator's typed case is still what gets stored + shown.
pub fn cluster_eq(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => x.eq_ignore_ascii_case(y),
        (None, None) => true,
        _ => false,
    }
}

/// True when `node_cluster` belongs to the display group `old_name` for the
/// purposes of a GROUP rename. Beyond the case-insensitive name match, a node
/// with NO cluster assigned (`None`) displays under the default "WolfStack"
/// group in every UI — so renaming that group must take the unassigned nodes
/// along, or they reappear in a freshly-respawned "WolfStack" group and the
/// cluster visibly splits (fleet-screen audit, 2026-06-11).
pub fn cluster_rename_member_matches(node_cluster: Option<&str>, old_name: &str) -> bool {
    cluster_eq(node_cluster, Some(old_name))
        || (node_cluster.is_none() && old_name.eq_ignore_ascii_case("WolfStack"))
}

/// True when two nodes sit in the same display cluster — the predicate to use
/// when deciding whether a config push may cross from one node to another.
///
/// This is `cluster_rename_member_matches` made symmetric, and it exists
/// because the naive version (compare names, treating `None` as `""`) splits a
/// genuinely-single cluster: an unassigned node reports `None` while its peers
/// report `Some("WolfStack")`, and the unassigned one then silently stops
/// receiving cluster-wide settings. Scoping a push is a security boundary — a
/// multi-cluster bastion must not hand one operator's SMTP password or AI keys
/// to another's fleet — so it has to be both tight and correct.
pub fn same_display_cluster(a: Option<&str>, b: Option<&str>) -> bool {
    let is_default_group = |c: Option<&str>| {
        c.is_none() || c.is_some_and(|s| s.trim().is_empty() || s.trim().eq_ignore_ascii_case("WolfStack"))
    };
    match (a, b) {
        _ if is_default_group(a) && is_default_group(b) => true,
        (Some(x), Some(y)) => x.trim().eq_ignore_ascii_case(y.trim()),
        _ => false,
    }
}

#[cfg(test)]
mod same_display_cluster_tests {
    use super::same_display_cluster;

    #[test]
    fn unassigned_nodes_share_the_default_group() {
        // The regression this predicate exists to prevent: a node that never
        // had a cluster name assigned must still count as a peer of one
        // explicitly labelled "WolfStack", or it stops receiving settings.
        assert!(same_display_cluster(None, Some("WolfStack")));
        assert!(same_display_cluster(Some("WolfStack"), None));
        assert!(same_display_cluster(None, None));
        assert!(same_display_cluster(Some(""), None));
        assert!(same_display_cluster(Some("  "), Some("wolfstack")));
    }

    #[test]
    fn names_match_case_and_whitespace_insensitively() {
        assert!(same_display_cluster(Some("Prod"), Some("prod")));
        assert!(same_display_cluster(Some(" prod "), Some("prod")));
    }

    #[test]
    fn distinct_clusters_never_match() {
        assert!(!same_display_cluster(Some("prod"), Some("staging")));
        // A named cluster is NOT the default group, so an unassigned node on a
        // multi-cluster bastion must not receive its secrets.
        assert!(!same_display_cluster(None, Some("customer-a")));
        assert!(!same_display_cluster(Some("customer-a"), None));
    }
}

/// Migrate every NODE-LOCAL cluster-tagged store from `old_name` to
/// `new_name` when a WolfStack cluster is renamed: TrueNAS + Unraid
/// instances, Galera + WolfScale cluster definitions, and the cluster's
/// WireGuard bridge. Called wherever a node learns its cluster was renamed —
/// the rename handler (locally), the `/api/agent/cluster-name` receiver
/// (pushed members, incl. offline ones via the intent sweep), and the gossip
/// self-adoption path — so per-node files converge on every member without a
/// separate fan-out. Gateways are NOT here: their store replicates fleet-wide
/// on its own, so the rename handler re-tags them exactly once. Status-page +
/// WolfRun data live in AppState and are migrated by the handler as before.
/// Alert-log entries keep their historical cluster stamp on purpose — they
/// record where an alert happened at the time, not a live grouping.
pub fn migrate_local_cluster_tags(old_name: &str, new_name: &str) -> usize {
    let mut n = 0;
    n += crate::truenas::TrueNasStore::load().rename_cluster(old_name, new_name);
    n += crate::unraid::UnraidStore::load().rename_cluster(old_name, new_name);
    n += crate::galera::rename_wolfstack_cluster_tags(old_name, new_name);
    n += crate::postgres_ha::rename_wolfstack_cluster_tags(old_name, new_name);
    n += crate::site_failover::rename_wolfstack_cluster_tags(old_name, new_name);
    n += crate::wolfscale::rename_wolfstack_cluster_tags(old_name, new_name);
    n += crate::networking::rename_wireguard_bridge_cluster(old_name, new_name);
    if n > 0 {
        tracing::info!(
            "cluster rename: migrated {} local cluster tag(s) '{}' -> '{}'",
            n, old_name, new_name
        );
    }
    n
}

/// Read this node's ID from the persisted file (cheap, no state needed)
pub fn self_node_id() -> String {
    std::fs::read_to_string(&crate::paths::get().node_id_file)
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Seconds since the Unix epoch, saturating to 0 if the system clock is
/// set before 1970.
///
/// Several of these timestamps are taken *while holding the membership
/// write lock*. `duration_since(UNIX_EPOCH).unwrap()` there would panic
/// on a backwards clock and poison the lock for the life of the process,
/// which is exactly the failure mode `nodes_read` exists to survive — so
/// the panic is removed at source rather than only absorbed downstream.
/// A bogus clock now yields a bogus-but-harmless timestamp instead of
/// taking the node's whole control plane down.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Cluster state
pub struct ClusterState {
    /// Private on purpose. Every reader and writer must go through
    /// [`ClusterState::nodes_read`] / [`ClusterState::nodes_write`], which
    /// recover from lock poisoning. Making the field private is what
    /// *enforces* that — a `.read().unwrap()` on this map cannot be
    /// reintroduced from another module without a compile error.
    nodes: RwLock<HashMap<String, Node>>,
    pub self_id: String,
    pub self_address: String,
    pub port: u16,
    /// Tombstone set: node IDs that were explicitly deleted and must not be re-added by gossip
    deleted_ids: RwLock<HashSet<String>>,
}

impl ClusterState {
    fn nodes_file() -> String { crate::paths::get().nodes_config }
    fn deleted_file() -> String { crate::paths::get().deleted_nodes_config }
    fn self_cluster_file() -> String { crate::paths::get().self_cluster_config }
    fn self_site_file() -> String { crate::paths::get().self_site_config }
    fn self_display_name_file() -> String { crate::paths::get().self_display_name_config }
    const SELF_LOGIN_DISABLED_FILE: &'static str = "/etc/wolfstack/login_disabled";

    pub fn new(self_id: String, self_address: String, port: u16) -> Self {
        let state = Self {
            nodes: RwLock::new(HashMap::new()),
            self_id,
            self_address,
            port,
            deleted_ids: RwLock::new(HashSet::new()),
        };
        // Load persisted state
        state.load_deleted_ids();
        state.load_nodes();
        // Auto-remove legacy Proxmox-API entries (writes a one-shot notice for the UI)
        state.cleanup_proxmox_legacy();
        // Remove ghost nodes (same IP/port but different ID)
        state.cleanup_ghosts();
        // Purge unverified wolfstack nodes (except self)
        state.purge_unverified();
        // Heal a list bloated by a pre-fix build: collapse duplicate records
        // (the multi-homed self_id explosion). This self-recovers a node hit by
        // the v24.27 convergence storm on its first restart after upgrading.
        // NOTE: peers are NEVER dropped for belonging to another named cluster —
        // control-plane replication shows the whole multi-cluster fleet.
        let pruned = state.prune_duplicate_nodes();
        if pruned > 0 {
            tracing::warn!(
                "cluster: collapsed {} duplicate node record(s) in membership at startup",
                pruned
            );
        }
        state
    }

    /// Read-lock the membership map, recovering from poisoning.
    ///
    /// A `std::sync::RwLock` stays poisoned for the life of the process
    /// once any thread panics while holding it. With `.read().unwrap()`
    /// at every call site, a single transient panic in one background
    /// task became a permanent outage: every handler that reads
    /// membership would panic in turn, and actix renders a handler panic
    /// as HTTP 500. The whole Fleet Security page (which fans out over
    /// this map) would stay broken until WolfStack was restarted.
    ///
    /// Recovering is the right trade here. The guarded value is a
    /// `HashMap<String, Node>` whose mutations are individually atomic
    /// (`insert` / `remove`), so the worst a poisoned map can hold is a
    /// stale or missing peer record — and the 10s polling loop rewrites
    /// it anyway. Serving slightly stale membership beats serving 500s
    /// forever.
    pub fn nodes_read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, Node>> {
        self.nodes.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Write-lock the membership map, recovering from poisoning.
    /// See [`ClusterState::nodes_read`] for why recovery is safe here.
    pub fn nodes_write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, Node>> {
        self.nodes.write().unwrap_or_else(|e| e.into_inner())
    }

    /// Read-lock the deletion tombstone set, recovering from poisoning.
    /// Same reasoning as [`ClusterState::nodes_read`]: a poisoned set
    /// would otherwise make every membership merge panic, and gossip
    /// would stop honouring deletions entirely.
    fn deleted_read(&self) -> std::sync::RwLockReadGuard<'_, HashSet<String>> {
        self.deleted_ids.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Write-lock the deletion tombstone set, recovering from poisoning.
    fn deleted_write(&self) -> std::sync::RwLockWriteGuard<'_, HashSet<String>> {
        self.deleted_ids.write().unwrap_or_else(|e| e.into_inner())
    }

    /// Remove ghost nodes: nodes with same hostname or matching self_id pattern but different ID
    fn cleanup_ghosts(&self) {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_default();
        let mut nodes = self.nodes_write();
        
        // Collect IDs of ghost nodes to remove:
        // - Any non-self WolfStack node whose hostname matches ours (previous restarts of this server)
        // - Any non-self node whose ID matches our self_id (shouldn't happen, but safety)
        let ghost_ids: Vec<String> = nodes.values()
            .filter(|n| {
                if n.is_self || n.id == self.self_id {
                    return false;
                }
                // Ghost: same hostname + same port + wolfstack type
                n.hostname == hostname && n.port == self.port && n.node_type == "wolfstack"
            })
            .map(|n| n.id.clone())
            .collect();

        for id in &ghost_ids {
            nodes.remove(id);
        }

        if !ghost_ids.is_empty() {

            // Persist the cleaned-up state
            drop(nodes);
            self.save_nodes();
        }
    }

    /// Remove non-self WolfStack nodes that were not added with a verified join token
    fn purge_unverified(&self) {
        let mut nodes = self.nodes_write();
        let unverified: Vec<String> = nodes.values()
            .filter(|n| !n.is_self && n.node_type == "wolfstack" && !n.join_verified)
            .map(|n| n.id.clone())
            .collect();

        for id in &unverified {
            nodes.remove(id);
        }

        if !unverified.is_empty() {
            tracing::warn!("Purged {} unverified WolfStack node(s)", unverified.len());
            drop(nodes);
            self.save_nodes();
        }
    }

    /// Load saved remote nodes from disk
    fn load_nodes(&self) {
        if let Ok(data) = std::fs::read_to_string(Self::nodes_file())
            && let Ok(saved) = serde_json::from_str::<Vec<Node>>(&data) {
                let mut nodes = self.nodes_write();
                for mut node in saved {
                    node.online = false; // Will be updated by polling
                    node.is_self = false;
                    // H7 fix: do NOT silently overwrite `None` cluster_name
                    // with the hardcoded "WolfStack" — that masks the
                    // genuine "this peer was never assigned to a cluster"
                    // state. The sidebar grouping handles None at display
                    // time via its own normalise() helper.
                    nodes.insert(node.id.clone(), node);
                }
            }
    }

    /// Save remote nodes to disk
    pub fn save_nodes(&self) {
        let nodes = self.nodes_read();
        let remote_nodes: Vec<&Node> = nodes.values()
            .filter(|n| !n.is_self)
            .collect();
        if let Ok(json) = serde_json::to_string_pretty(&remote_nodes) {
            let path = Self::nodes_file();
            // Written with mode 0600 because each Node row embeds the
            // peer's pve_token (if any) and pve_fingerprint. Pre-v18.7.27
            // nodes.json was world-readable — any unprivileged local user
            // could siphon every PVE API token on the cluster.
            if let Err(e) = crate::paths::write_secure(&path, json) {
                warn!("Failed to save nodes: {}", e);
            }
        }
    }

    /// The address this node advertises to peers in its OWN self entry.
    ///
    /// Normally the configured `self_address`. But a node reached via a
    /// reverse-proxy WAN hostname (or a public IP) has a `self_address` that
    /// LAN peers cannot dial — they end up with an un-pollable entry and the
    /// node shows up nowhere / as a red phantom (wabil 2026-06-28). When
    /// `self_address` is NOT already a private LAN IPv4, substitute a local LAN
    /// IP, preferring one whose `/24` matches a known private peer so we pick
    /// the cluster-facing NIC deterministically on a multi-bridge Proxmox host
    /// (the same determinism v25.1.5 added to wolfnet-sync). If nothing matches
    /// (fresh cluster, no private peers yet) keep `self_address` — never guess.
    fn self_registry_address(
        &self,
        nodes: &HashMap<String, Node>,
        my_ips: &std::collections::HashSet<String>,
    ) -> String {
        let already_lan_ip = self
            .self_address
            .parse::<std::net::IpAddr>()
            .map(|a| a.to_canonical())
            .map(|ip| matches!(ip, std::net::IpAddr::V4(v4) if v4.is_private()))
            .unwrap_or(false);
        if already_lan_ip {
            return self.self_address.clone();
        }
        let peer_prefixes: std::collections::HashSet<String> = nodes
            .values()
            .filter(|n| !n.is_self && n.node_type == "wolfstack")
            .filter_map(|n| lan24_prefix(&n.address))
            .collect();
        if peer_prefixes.is_empty() {
            // Fresh cluster / no private peers yet — nothing to match against, so
            // keep the configured address rather than guess a NIC.
            return self.self_address.clone();
        }
        if let Some(ip) = my_ips
            .iter()
            .find(|ip| lan24_prefix(ip).map(|p| peer_prefixes.contains(&p)).unwrap_or(false))
        {
            // debug, not info: update_self runs every ~2s — an info line here
            // would be a per-tick heartbeat. Operators diagnosing visibility
            // enable debug to confirm the substitution is active.
            tracing::debug!("agent: advertising LAN address {} to peers (self_address {} is not a private IP)", ip, self.self_address);
            return ip.clone();
        }
        tracing::debug!("agent: self_address {} is not a private IP and no local IP shares a /24 with a peer — peers may not reach this node; set a LAN bind address", self.self_address);
        self.self_address.clone()
    }

    /// Update this node's own status
    pub fn update_self(&self, metrics: SystemMetrics, components: Vec<ComponentStatus>, docker_count: u32, lxc_count: u32, vm_count: u32, compose_count: u32, public_ip: Option<String>, has_docker: bool, has_lxc: bool, has_kvm: bool, tls_enabled: bool) {
        // Our own LAN IPs (cached 60s) — used both to advertise a dialable
        // address and to self-heal phantoms saved under one of our own IPs.
        let my_ips = local_ipv4_addrs();
        // Resolve the address we advertise to peers under a READ lock, so the
        // (rare, cached) interface enumeration never runs under the write lock.
        let registry_address = {
            let nodes_r = self.nodes_read();
            self.self_registry_address(&nodes_r, &my_ips)
        };
        let mut nodes = self.nodes_write();
        // Fetch existing cluster_name: in-memory first, then persisted file, then default
        let cluster_name = nodes.get(&self.self_id)
            .and_then(|n| n.cluster_name.clone())
            .or_else(Self::load_self_cluster_name)
            .or_else(|| Some("WolfStack".to_string()));

        let now = now_unix();
        let prev_login_disabled = nodes.get(&self.self_id).map(|n| n.login_disabled);
        let prev_update_script = nodes.get(&self.self_id).and_then(|n| n.update_script.clone());
        // Site is persisted to disk via the same path as cluster_name —
        // in-memory if present, else the file written by
        // `update_node_settings`, else None (which lets the cluster-sync
        // auto-derive the site from this node's address).
        let prev_site = nodes.get(&self.self_id)
            .and_then(|n| n.site.clone())
            .or_else(Self::load_self_site);
        // Display name follows the same in-memory-then-disk re-assertion as
        // site, so this node's StatusReport keeps carrying the operator's
        // chosen name and it never reverts to the OS hostname.
        let prev_display_name = nodes.get(&self.self_id)
            .and_then(|n| n.display_name.clone())
            .or_else(Self::load_self_display_name);
        // Roles re-assert from in-memory then disk, same as site/display_name,
        // so this node keeps advertising its assigned tier roles on every poll.
        let prev_roles = nodes.get(&self.self_id)
            .map(|n| n.roles.clone())
            .filter(|r| !r.is_empty())
            .unwrap_or_else(Self::load_self_roles);
        let prev_manager = nodes.get(&self.self_id).map(|n| n.manager).unwrap_or(true);
        nodes.insert(self.self_id.clone(), Node {
            id: self.self_id.clone(),
            hostname: metrics.hostname.clone(),
            address: registry_address,
            migration_address: None,
            port: self.port,
            last_seen: now,
            metrics: Some(metrics),
            components,
            online: true,
            is_self: true,
            docker_count,
            lxc_count,
            vm_count,
            // Computed in the caller's spawn_blocking with the other counts
            // (Gary/KO4BSR 2026-06-27) — keeps blocking I/O off the async task.
            compose_count,
            public_ip,
            node_type: "wolfstack".to_string(),
            pve_token: None,
            pve_fingerprint: None,
            pve_node_name: None,

            pve_cluster_name: None,
            cluster_name,
            join_verified: true, // self is always verified
            pubkey: crate::node_identity::self_pubkey(),
            manager: prev_manager,
            has_docker,
            has_lxc,
            has_kvm,
            login_disabled: prev_login_disabled.or_else(Self::load_self_login_disabled).unwrap_or(false),
            tls: tls_enabled,
            update_script: prev_update_script,
            // Self's id IS the self_id by construction; the field is for
            // OTHER nodes' self_ids as observed via polling. Self has no
            // need to record one.
            self_id: None,
            // Snapshot the current workload subnets — Docker / LXC / VM
            // bridges live on this node. Other peers consume this via
            // gossip to detect missing subnet_routes.
            workload_subnets: crate::networking::collect_workload_subnets(),
            site: prev_site,
            display_name: prev_display_name,
            roles: prev_roles,
        });

        // Self-heal: drop any NON-self entry previously saved under one of our
        // OWN LAN IPs. Pre-fix gossip (before the address-based is_self check)
        // admitted this node's LAN IP as a foreign "red" phantom; on upgrade
        // those entries reload from nodes.json. They are unambiguously us (their
        // address is one of our local IPs), never pollable as a real peer, and
        // the is_self check now prevents re-creation, so removing them here
        // self-heals the cluster without operator action (wabil 2026-06-28).
        let self_id = self.self_id.clone();
        let before = nodes.len();
        // Keep everything that is NOT a self-phantom: the self entry, any
        // is_self entry, address-less entries, and any peer whose address is
        // not one of our own IPs.
        nodes.retain(|id, n| {
            *id == self_id
                || n.is_self
                || n.address.is_empty()
                || !my_ips.contains(&n.address)
        });
        let phantom_removed = nodes.len() < before;
        // Drop the write guard BEFORE save_nodes (which takes a read lock), and
        // only persist when we actually removed something — otherwise the
        // healed phantom lingers in nodes.json until some other write fires,
        // reloading on the next restart (re-trimmed from memory but never from
        // disk). The guard means a healthy cluster does no I/O here.
        drop(nodes);
        if phantom_removed {
            self.save_nodes();
        }
    }

    /// Update a remote node's status
    pub fn update_remote(&self, node: Node) {
        let mut nodes = self.nodes_write();
        nodes.insert(node.id.clone(), node);
    }

    /// True when a peer's PERSISTED, self-reported identity/topology fields
    /// differ between the previous snapshot and a freshly-polled report.
    ///
    /// `update_remote` only writes RAM, so `/etc/wolfstack/nodes.json` used to
    /// go stale indefinitely on a healthy cluster — save_nodes() only fired on
    /// add/remove/settings events. Several consumers read that FILE directly
    /// (predictive `missing_subnet_route`, WolfRouter
    /// `auto_apply_missing_workload_routes`, auth, pools), so e.g. a peer
    /// migrating its Docker bridge off 172.17.0.0/16 kept producing findings
    /// and route decisions from the pre-migration subnets for hours (nc
    /// cluster report, 2026-08-15).
    ///
    /// Deliberately EXCLUDES per-poll churn — `last_seen`, `metrics`,
    /// `online`, and the container/VM counts — so the poll loop persists at
    /// most once per cycle and only when something meaningful changed, not
    /// every 10 seconds on every node.
    fn persistent_peer_fields_changed(old: &Node, new: &Node) -> bool {
        old.hostname != new.hostname
            || old.pubkey != new.pubkey
            || old.manager != new.manager
            || old.self_id != new.self_id
            || old.public_ip != new.public_ip
            || old.workload_subnets != new.workload_subnets
            || old.site != new.site
            || old.display_name != new.display_name
            || old.roles != new.roles
            || old.tls != new.tls
            || old.has_docker != new.has_docker
            || old.has_lxc != new.has_lxc
            || old.has_kvm != new.has_kvm
    }

    /// Get all nodes (deduplicated: if a non-self WolfStack node has same hostname+port as self, skip it)
    /// Every cluster node carrying `role`, deduplicated via `get_all_nodes`.
    /// The tier subsystems (DNS zone fan-out, mail, ingress) dispatch on this:
    /// "write this zone to all Dns nodes", "this MX pair is the Mail nodes".
    pub fn nodes_with_role(&self, role: NodeRole) -> Vec<Node> {
        self.get_all_nodes().into_iter()
            .filter(|n| n.node_type == "wolfstack" && n.roles.contains(&role))
            .collect()
    }

    pub fn get_all_nodes(&self) -> Vec<Node> {
        let nodes = self.nodes_read();
        let now = now_unix();
        // Find self node's hostname and port for dedup
        let self_hostname = nodes.get(&self.self_id).map(|n| n.hostname.clone()).unwrap_or_default();
        let self_port = self.port;
        nodes.values().filter(|n| {
            // Filter out non-self wolfstack nodes that are actually us (duplicate from gossip)
            if !n.is_self && n.id != self.self_id && n.node_type == "wolfstack"
                && n.hostname == self_hostname && n.port == self_port {
                return false;
            }
            true
        }).map(|n| {
            let mut node = n.clone();
            if !node.is_self {
                node.online = now - node.last_seen < 60;
            }
            node
        }).collect()
    }

    /// All WolfStack cluster-node IPs — this node plus every known wolfstack
    /// peer's LAN `address` and any `public_ip`, sorted and deduped. Used to
    /// auto-whitelist the cluster in the kernel-block guard and fail2ban's
    /// `ignoreip` so nodes never ban each other (klasSponsor 2026-06-08).
    /// proxmox-type nodes are excluded — this targets WolfStack node<->node
    /// traffic. Validity (loopback/unspecified) filtering is left to consumers.
    pub fn wolfstack_node_ips(&self) -> Vec<String> {
        let mut ips: Vec<String> = Vec::new();
        if !self.self_address.is_empty() {
            ips.push(self.self_address.clone());
        }
        for n in self.get_all_nodes() {
            if n.node_type != "wolfstack" { continue; }
            // SECURITY: only whitelist peers that completed the authenticated
            // join handshake (the same trust bar as purge_unverified). Gossip
            // seeds peers as join_verified=false; without this filter a spoofed
            // gossip entry could add an attacker's RFC1918 IP to the protected
            // set and permanently suppress blocking for it (code review,
            // 2026-06-08). self is always trusted.
            if !n.join_verified && !n.is_self { continue; }
            if !n.address.is_empty() { ips.push(n.address); }
            if let Some(p) = n.public_ip
                && !p.is_empty()
            {
                ips.push(p);
            }
        }
        ips.sort();
        ips.dedup();
        ips
    }

    /// Get a single node by either its locally-assigned cluster key
    /// (`node-{uuid}`) or its self-reported self_id (from
    /// `/etc/wolfstack/node_id` on the peer). The direct key lookup
    /// is the hot path; the self_id scan handles cross-node calls
    /// where the caller (WolfRouter topology, LAN records, WolfNet
    /// peer tables) only knows the peer's self_id. Linear scan is
    /// fine — clusters are tens of nodes, not thousands.
    pub fn get_node(&self, id: &str) -> Option<Node> {
        let nodes = self.nodes_read();
        if let Some(n) = nodes.get(id) { return Some(n.clone()); }
        nodes.values().find(|n| n.self_id.as_deref() == Some(id)).cloned()
    }

    /// Get this node's cluster name
    pub fn get_self_cluster_name(&self) -> String {
        let nodes = self.nodes_read();
        nodes.get(&self.self_id)
            .and_then(|n| n.cluster_name.clone())
            .unwrap_or_else(|| "WolfStack".to_string())
    }

    /// Add a server by address — persists to disk (join_verified=true because only called after token validation)
    pub fn add_server(&self, address: String, port: u16, cluster_name: Option<String>) -> String {
        let id = self.add_server_full(address, port, "wolfstack".to_string(), None, None, None, None, cluster_name);
        self.mark_verified(&id);
        id
    }

    /// Add a Proxmox server (always verified — PVE API token is its own auth)
    #[allow(dead_code)]
    pub fn add_proxmox_server(&self, address: String, port: u16, token: String, fingerprint: Option<String>, node_name: String, pve_cluster_name: Option<String>) -> String {
        // Use pve_cluster_name as the generic cluster_name too
        let id = self.add_server_full(address, port, "proxmox".to_string(), Some(token), fingerprint, Some(node_name), pve_cluster_name.clone(), pve_cluster_name);
        self.mark_verified(&id);
        id
    }

    /// Mark a node as join-verified
    pub fn mark_verified(&self, id: &str) {
        let mut nodes = self.nodes_write();
        if let Some(node) = nodes.get_mut(id) {
            node.join_verified = true;
        }
        drop(nodes);
        self.save_nodes();
    }

    /// Add a server with full options (deduplicates by address+port+pve_node_name)
    fn add_server_full(&self, address: String, port: u16, node_type: String, pve_token: Option<String>, pve_fingerprint: Option<String>, pve_node_name: Option<String>, pve_cluster_name: Option<String>, cluster_name: Option<String>) -> String {
        let mut nodes = self.nodes_write();
        
        // Dedup: check if a node with the same address+port+node_type already exists
        if let Some(existing) = nodes.values().find(|n| {
            n.address == address && n.port == port && n.node_type == node_type
                && n.pve_node_name == pve_node_name
        }) {
            let existing_id = existing.id.clone();

            return existing_id;
        }
        
        let id = format!("node-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let now = now_unix();
        nodes.insert(id.clone(), Node {
            pubkey: None,
            manager: true,
            id: id.clone(),
            hostname: address.clone(),
            address,
            migration_address: None,
            port,
            last_seen: now,
            metrics: None,
            components: vec![],
            online: false,
            is_self: false,
            docker_count: 0,
            lxc_count: 0,
            vm_count: 0,
            compose_count: 0,
            public_ip: None,
            node_type,
            pve_token,
            pve_fingerprint,
            pve_node_name,
            pve_cluster_name,
            cluster_name,
            join_verified: false, // will be set true by add_node after token validation
            has_docker: false,
            has_lxc: false,
            has_kvm: false,
            login_disabled: false,
            tls: false,
            update_script: None,
            // Filled in on first successful poll from the peer's status report.
            self_id: None,
            workload_subnets: Vec::new(),
            // Site arrives on the first successful poll (gossip carries
            // each peer's own declared site). Until then we don't know
            // it; effective_site() will auto-derive from the address.
            site: None,
            // Display name likewise arrives on the first poll from the
            // peer's own self-report.
            display_name: None,
            // Roles likewise arrive from the peer's own self-report.
            roles: Vec::new(),
        });
        drop(nodes);
        self.save_nodes();
        id
    }

    /// Remove a server — persists to disk and adds to tombstone set
    pub fn remove_server(&self, id: &str) -> bool {
        let mut nodes = self.nodes_write();
        let removed = nodes.remove(id).is_some();
        drop(nodes);
        if removed {
            self.save_nodes();
            // Tombstone: prevent gossip from re-adding this node
            self.add_tombstone(id);
        }
        removed
    }

    /// Add a node ID to the tombstone set (prevents gossip re-adding)
    fn add_tombstone(&self, id: &str) {
        let mut deleted = self.deleted_write();
        deleted.insert(id.to_string());
        drop(deleted);
        self.save_deleted_ids();
    }

    /// Check if a node ID is tombstoned
    pub fn is_tombstoned(&self, id: &str) -> bool {
        self.deleted_read().contains(id)
    }

    /// Merge remote tombstones into local set
    pub fn merge_tombstones(&self, remote_deleted: &[String]) {
        let mut deleted = self.deleted_write();
        let mut changed = false;
        for id in remote_deleted {
            if id != &self.self_id && deleted.insert(id.clone()) {
                changed = true;
            }
        }
        drop(deleted);
        if changed {
            // Also remove any nodes that are now tombstoned
            let mut nodes = self.nodes_write();
            let to_remove: Vec<String> = nodes.keys()
                .filter(|k| self.deleted_read().contains(*k))
                .cloned()
                .collect();
            for id in &to_remove {
                nodes.remove(id);
            }
            drop(nodes);
            self.save_deleted_ids();
            if !to_remove.is_empty() {
                self.save_nodes();

            }
        }
    }

    /// Get the current tombstone set
    pub fn get_deleted_ids(&self) -> Vec<String> {
        self.deleted_read().iter().cloned().collect()
    }

    /// Merge a peer's advertised cluster members into our own list so that ANY
    /// node converges to the full mesh — not just the node the cluster was
    /// built on. This is what lets an operator log into a secondary node and
    /// see every other node (the previous behaviour showed only itself,
    /// because membership only ever flowed toward the polling node).
    ///
    /// Conservative and re-injection-safe — mirrors the pull-gossip merge's
    /// rules: it only ADDS peers we don't already know, skips ourselves (by
    /// local id, global self_id, or hostname/address + port), and skips any
    /// tombstoned (operator-removed) node, so it can never resurrect a peer the
    /// operator deleted. Node settings and online status stay owned by the
    /// regular poll — this only seeds the existence of a peer so the poll can
    /// then reach it.
    pub fn merge_member_refs(&self, members: &[Node]) {
        let self_hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_default();
        let current = self.get_all_nodes();
        // Our own addresses across every NIC — so we never seed ourselves as a
        // peer under a secondary IP (the multi-homed self-poll that storms).
        let local = local_ipv4_addrs();
        // Dedup WITHIN this single bundle too: a sender that hasn't been pruned
        // yet can advertise the same physical node under two record ids sharing
        // one self_id. `current` is a pre-loop snapshot, so without this set both
        // would pass the already-known check and both get inserted.
        let mut added_self_ids: HashSet<String> = HashSet::new();
        for m in members {
            if m.node_type != "wolfstack" { continue; }
            // Skip a self-entry carrying the wildcard bind address (0.0.0.0):
            // it's unreachable, and the sender's REAL address is repaired into
            // the bundle from the connection source IP before we get here.
            if !is_usable_addr(&m.address) { continue; }
            // REQUIRE a stable global self_id before seeding. Without it we can
            // only dedup by address, which FAILS for multi-homed nodes (a node
            // with both a LAN IP and a 10.x WolfNet IP looks like two different
            // peers, and the v24.27 peer-IP repair added a third address
            // variant). That mismatch is what let the same physical node be
            // added over and over until every node's poll list exploded and the
            // 10s poll loop pegged the CPU. Skipping here only DEFERS the seed:
            // the regular pull-gossip poll populates self_id on first contact,
            // after which convergence proceeds with a reliable identity key.
            let m_self_id = match m.self_id.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => continue,
            };
            // Never seed ourselves as a peer.
            if m.id == self.self_id { continue; }
            if m_self_id == self.self_id.as_str() { continue; }
            if m.hostname == self_hostname && m.port == self.port { continue; }
            if m.address == self.self_address && m.port == self.port { continue; }
            // Any of OUR addresses (LAN/WolfNet/VLAN/storage) — it's us under
            // another NIC, never a peer.
            if local.contains(&m.address) { continue; }
            // Already seeded earlier in THIS same bundle (under another record
            // id sharing this self_id)? Skip — the snapshot below can't see it.
            if added_self_ids.contains(m_self_id) { continue; }
            // Never resurrect an operator-removed node (same guard the pull
            // gossip uses).
            if self.is_tombstoned(&m.id) { continue; }
            // Already known — dedup STRICTLY by the stable self_id first, then
            // fall back to id / address+port / hostname+port for records that
            // predate self_id. Leave refinement to the regular poll.
            let already_known = current.iter().any(|n| {
                n.self_id.as_deref() == Some(m_self_id)
                    || n.id == m.id
                    || (n.address == m.address && n.port == m.port && n.pve_node_name == m.pve_node_name)
                    || (n.hostname == m.hostname && n.port == m.port && n.node_type == m.node_type)
            });
            if already_known { continue; }
            // Only auto-seed nodes on private/local networks — a public-IP node
            // must be added manually. Mirrors the pull-gossip guard so a
            // tampered or compromised peer can't make us start polling an
            // attacker-controlled address.
            if !is_private_address(&m.address) { continue; }
            // Mirror the pull-gossip new-node path: carry the peer's full
            // record (id, self_id, cluster_name…), marked offline until our own
            // poll reaches it. (update_remote, NOT add_server — keeps the
            // global self_id so cross-node proxy lookups resolve.)
            let mut new_node = m.clone();
            new_node.online = false;
            new_node.is_self = false;
            // Keys are pinned only from the node's own report, never relayed.
            new_node.pubkey = None;
            new_node.manager = true;
            self.update_remote(new_node);
            self.save_nodes();
            added_self_ids.insert(m_self_id.to_string());
        }
    }

    /// One-shot cleanup of a node list that a pre-fix build may have bloated:
    /// collapse duplicate records (same global `self_id`, or same address+port)
    /// down to a single best entry. This heals a list exploded by the v24.27
    /// multi-homed convergence storm on the first restart after upgrading — the
    /// operator does not have to hand-edit `nodes.json`.
    ///
    /// Cluster-agnostic by design: control-plane replication shows the WHOLE
    /// fleet across clusters (`cluster_name` is a display grouping, NEVER a
    /// membership boundary), so a peer is never dropped for belonging to a
    /// different named cluster — that mistake (v24.29.1) deleted whole federated
    /// clusters down to a single node. `is_self` is always kept; the keeper for
    /// each duplicate group is the most trustworthy record
    /// (self > verified > online > usable-address). Returns the number of
    /// entries removed. Saves to disk only if something changed.
    pub fn prune_duplicate_nodes(&self) -> usize {
        let mut nodes = self.nodes_write();
        let before = nodes.len();
        let entries: Vec<Node> = nodes.values().cloned().collect();
        let remove = Self::plan_prune(entries);
        for id in &remove {
            nodes.remove(id);
        }
        let removed = before.saturating_sub(nodes.len());
        drop(nodes);
        if removed > 0 {
            self.save_nodes();
        }
        removed
    }

    /// Pure decision core of `prune_duplicate_nodes`: given the node records,
    /// return the ids of duplicate records to remove (same global `self_id`, or
    /// same address+port). Cluster membership is never a reason to remove a peer.
    /// Split out so the data-loss-sensitive logic is unit-testable without disk
    /// or a live `ClusterState`.
    fn plan_prune(mut entries: Vec<Node>) -> Vec<String> {
        // Choose keepers deterministically: sort so the best record of each
        // duplicate group is visited first and therefore retained.
        entries.sort_by_key(|n| {
            (
                !n.is_self,                    // self first
                !n.join_verified,              // verified first
                !n.online,                     // online first
                !is_usable_addr(&n.address),   // usable address first
                n.id.clone(),                  // stable tiebreaker (HashMap order is not)
            )
        });

        let mut seen_self_ids: HashSet<String> = HashSet::new();
        let mut seen_addrs: HashSet<String> = HashSet::new();
        let mut remove: Vec<String> = Vec::new();
        for n in &entries {
            if n.is_self {
                continue;
            }
            let sid = n.self_id.as_deref().filter(|s| !s.is_empty());
            let addr_key = if is_usable_addr(&n.address) {
                Some(format!("{}:{}", n.address, n.port))
            } else {
                None
            };
            let dup = sid.map(|s| seen_self_ids.contains(s)).unwrap_or(false)
                || addr_key.as_ref().map(|a| seen_addrs.contains(a)).unwrap_or(false);
            if dup {
                remove.push(n.id.clone());
                continue;
            }
            if let Some(s) = sid {
                seen_self_ids.insert(s.to_string());
            }
            if let Some(a) = addr_key {
                seen_addrs.insert(a);
            }
        }
        remove
    }

    /// Drop every non-self peer and clear all tombstones in memory.
    /// Used by POST /api/cluster/leave so that — during the short window
    /// between the on-disk wipe and the scheduled service restart — any
    /// gossip-triggered `save_nodes()` writes an empty list instead of
    /// resurrecting the cluster we just left. Caller is responsible for
    /// wiping the on-disk files (`leave_wipe_membership_files`).
    pub fn clear_membership_in_memory(&self) {
        let self_id = self.self_id.clone();
        let mut nodes = self.nodes_write();
        let keep_self = nodes.remove(&self_id);
        nodes.clear();
        if let Some(s) = keep_self {
            nodes.insert(self_id, s);
        }
        drop(nodes);
        self.deleted_write().clear();
    }

    /// Load tombstoned node IDs from disk
    fn load_deleted_ids(&self) {
        if let Ok(data) = std::fs::read_to_string(Self::deleted_file())
            && let Ok(ids) = serde_json::from_str::<Vec<String>>(&data) {
                let mut deleted = self.deleted_write();
                for id in ids {
                    deleted.insert(id);
                }

            }
    }

    /// Save tombstoned node IDs to disk
    fn save_deleted_ids(&self) {
        let deleted = self.deleted_read();
        let ids: Vec<&String> = deleted.iter().collect();
        if let Ok(json) = serde_json::to_string_pretty(&ids) {
            let path = Self::deleted_file();
            if let Some(dir) = std::path::Path::new(&path).parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Err(e) = std::fs::write(&path, json) {
                warn!("Failed to save deleted nodes: {}", e);
            }
        }
    }

    /// On startup, purge any legacy Proxmox-API entries from nodes.json.
    /// Backs the file up first so the user can recover if needed, then writes
    /// a small notice file the UI reads to render the deprecation banner.
    fn cleanup_proxmox_legacy(&self) {
        let proxmox_entries: Vec<Node> = {
            let nodes = self.nodes_read();
            nodes.values().filter(|n| n.node_type == "proxmox").cloned().collect()
        };
        if proxmox_entries.is_empty() {
            return;
        }

        let nodes_path = Self::nodes_file();
        let timestamp = now_unix();
        let backup_path = format!("{}.proxmox-backup-{}", nodes_path, timestamp);
        if let Err(e) = std::fs::copy(&nodes_path, &backup_path) {
            warn!("Failed to back up nodes.json before Proxmox cleanup: {}", e);
            // Don't proceed with deletion if we can't back up.
            return;
        }

        {
            let mut nodes = self.nodes_write();
            let mut deleted = self.deleted_write();
            for n in &proxmox_entries {
                nodes.remove(&n.id);
                deleted.insert(n.id.clone());
            }
        }
        self.save_nodes();
        self.save_deleted_ids();

        let addresses: Vec<String> = proxmox_entries.iter()
            .map(|n| {
                let label = n.pve_node_name.clone()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| n.hostname.clone());
                if label.is_empty() {
                    n.address.clone()
                } else {
                    format!("{} ({})", label, n.address)
                }
            })
            .collect();

        let notice = ProxmoxCleanupNotice {
            removed_count: proxmox_entries.len(),
            addresses,
            backup_path,
            timestamp,
        };
        if let Err(e) = notice.save() {
            warn!("Failed to write Proxmox cleanup notice: {}", e);
        }
        tracing::info!(
            "Removed {} legacy Proxmox-API entries from nodes.json (backed up to {})",
            notice.removed_count, notice.backup_path
        );
    }
}

/// Notice written once on startup when legacy Proxmox-API entries are auto-removed.
/// The UI reads this to render the deprecation banner; deleting the file dismisses it.
#[derive(Serialize, Deserialize, Clone)]
pub struct ProxmoxCleanupNotice {
    pub removed_count: usize,
    pub addresses: Vec<String>,
    pub backup_path: String,
    pub timestamp: u64,
}

impl ProxmoxCleanupNotice {
    fn notice_file() -> String {
        let nodes_path = crate::paths::get().nodes_config.clone();
        // Sit alongside nodes.json: same directory, dedicated name.
        let dir = std::path::Path::new(&nodes_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/etc/wolfstack".to_string());
        format!("{}/proxmox-cleanup.json", dir)
    }

    pub fn load() -> Option<Self> {
        let data = std::fs::read_to_string(Self::notice_file()).ok()?;
        serde_json::from_str(&data).ok()
    }

    fn save(&self) -> std::io::Result<()> {
        let path = Self::notice_file();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(std::io::Error::other)?;
        std::fs::write(&path, json)
    }

    pub fn dismiss() -> std::io::Result<()> {
        let path = Self::notice_file();
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl ClusterState {

    /// Update node settings (hostname, address, port, token, fingerprint, cluster name, site)
    #[allow(clippy::too_many_arguments)]
    pub fn update_node_settings(&self, id: &str, hostname: Option<String>, address: Option<String>, port: Option<u16>, pve_token: Option<String>, pve_fingerprint: Option<Option<String>>, cluster_name: Option<String>, login_disabled: Option<bool>, update_script: Option<String>, site: Option<String>, display_name: Option<String>, migration_address: Option<String>, manager: Option<bool>) -> bool {
        let mut nodes = self.nodes_write();
        if let Some(node) = nodes.get_mut(id) {
            if let Some(m) = manager { node.manager = m; }
            if let Some(h) = hostname { node.hostname = h; }
            if let Some(a) = address { node.address = a; }
            if let Some(p) = port { node.port = p; }
            if let Some(ma) = migration_address.as_ref() {
                // Empty string clears the override → migration falls back to
                // `address` (migration_host). Non-empty pins migration/bulk
                // transfer to that host (e.g. a 2.5GbE NIC's IP). `None` (field
                // absent) leaves it untouched — safe under gossip mirroring.
                node.migration_address = if ma.trim().is_empty() { None } else { Some(ma.trim().to_string()) };
            }
            if let Some(token) = pve_token { node.pve_token = Some(token); }
            if let Some(fp) = pve_fingerprint { node.pve_fingerprint = fp; }
            if let Some(disabled) = login_disabled { node.login_disabled = disabled; }
            if let Some(script) = update_script { node.update_script = if script.is_empty() { None } else { Some(script) }; }
            if let Some(s) = site.as_ref() {
                // Empty string clears the explicit tag — effective_site
                // will fall back to the auto-derived value. Anything
                // non-empty is the operator's chosen label.
                node.site = if s.is_empty() { None } else { Some(s.clone()) };
            }
            if let Some(dn) = display_name.as_ref() {
                // Empty string clears the override (UI falls back to the OS
                // hostname); non-empty is the operator's chosen name. A `None`
                // arg means "leave untouched" — which is exactly what makes
                // gossip mirroring safe (an older peer's None never clears it).
                node.display_name = if dn.is_empty() { None } else { Some(dn.clone()) };
            }
            if let Some(ref name) = cluster_name {
                // Update both cluster_name fields so sidebar grouping works
                node.cluster_name = Some(name.clone());
                if node.node_type == "proxmox" {
                    node.pve_cluster_name = Some(name.clone());
                }
            }
            // If updating self node's cluster name, persist it so it survives reinstalls
            let is_self = node.is_self;
            let final_cluster = node.cluster_name.clone();
            let final_site = node.site.clone();
            let final_display_name = node.display_name.clone();
            drop(nodes);
            self.save_nodes();
            if is_self {
                if let Some(ref name) = final_cluster {
                    Self::save_self_cluster_name(name);
                }
                // Persist site for self node — save_nodes skips self so
                // we need a dedicated file (same pattern as cluster_name
                // and login_disabled).
                if site.is_some() {
                    Self::save_self_site(final_site.as_deref().unwrap_or(""));
                }
                // Persist display name for self node (save_nodes skips self).
                if display_name.is_some() {
                    Self::save_self_display_name(final_display_name.as_deref().unwrap_or(""));
                }
                // Persist login_disabled for self node (since save_nodes skips self)
                if let Some(disabled) = login_disabled {
                    Self::save_login_disabled_file(disabled);
                }
            }
            true
        } else {
            false
        }
    }

    /// Load persisted self cluster_name from disk
    /// This node's cluster DISPLAY label — the persisted name, or the
    /// "WolfStack" default an unassigned node is grouped under everywhere.
    pub fn self_cluster_label() -> String {
        Self::load_self_cluster_name().unwrap_or_else(|| "WolfStack".to_string())
    }

    fn load_self_cluster_name() -> Option<String> {
        if let Ok(data) = std::fs::read_to_string(Self::self_cluster_file())
            && let Ok(name) = serde_json::from_str::<String>(&data)
                && !name.is_empty() {
                    return Some(name);
                }
        None
    }

    /// Persist self cluster_name to disk (survives reinstalls)
    pub fn save_self_cluster_name(name: &str) {
        let path = Self::self_cluster_file();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(json) = serde_json::to_string(name)
            && let Err(e) = std::fs::write(&path, json) {
                warn!("Failed to save self cluster name: {}", e);
            }
    }

    /// Load persisted self site tag from disk. Same path/format as
    /// cluster_name persistence so the two are consistent. Returns
    /// `None` for missing/empty/malformed files; callers fall through
    /// to the auto-derived site.
    fn load_self_site() -> Option<String> {
        if let Ok(data) = std::fs::read_to_string(Self::self_site_file())
            && let Ok(name) = serde_json::from_str::<String>(&data)
                && !name.is_empty() {
                    return Some(name);
                }
        None
    }

    /// Persist self site tag to disk (survives reinstalls). Empty
    /// string is treated as "clear the file" so the operator can
    /// remove an explicit tag and fall back to auto-derived.
    pub fn save_self_site(site: &str) {
        let path = Self::self_site_file();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if site.is_empty() {
            let _ = std::fs::remove_file(&path);
            return;
        }
        if let Ok(json) = serde_json::to_string(site)
            && let Err(e) = std::fs::write(&path, json) {
                warn!("Failed to save self site: {}", e);
            }
    }

    fn self_roles_file() -> String { crate::paths::get().self_roles_config }

    /// Load persisted self roles from disk. Empty vec for missing/malformed —
    /// a node with no roles is a general-purpose node (the default).
    pub fn load_self_roles() -> Vec<NodeRole> {
        if let Ok(data) = std::fs::read_to_string(Self::self_roles_file())
            && let Ok(roles) = serde_json::from_str::<Vec<NodeRole>>(&data)
        {
            return roles;
        }
        Vec::new()
    }

    /// Persist self roles to disk (survives reinstalls). An empty list clears
    /// the file so the node reverts to general-purpose.
    pub fn save_self_roles(roles: &[NodeRole]) {
        let path = Self::self_roles_file();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if roles.is_empty() {
            let _ = std::fs::remove_file(&path);
            return;
        }
        if let Ok(json) = serde_json::to_string(roles)
            && let Err(e) = std::fs::write(&path, json)
        {
            warn!("Failed to save self roles: {}", e);
        }
    }

    /// Load persisted self display name from disk. Same path/format as the
    /// site tag. `None` for missing/empty/malformed — UI then shows the
    /// hostname.
    fn load_self_display_name() -> Option<String> {
        if let Ok(data) = std::fs::read_to_string(Self::self_display_name_file())
            && let Ok(name) = serde_json::from_str::<String>(&data)
                && !name.is_empty() {
                    return Some(name);
                }
        None
    }

    /// Persist self display name to disk (survives reinstalls). Empty string
    /// clears the file so the operator can drop the override and fall back to
    /// the OS hostname.
    pub fn save_self_display_name(name: &str) {
        let path = Self::self_display_name_file();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if name.is_empty() {
            let _ = std::fs::remove_file(&path);
            return;
        }
        if let Ok(json) = serde_json::to_string(name)
            && let Err(e) = std::fs::write(&path, json) {
                warn!("Failed to save self display name: {}", e);
            }
    }

    /// Load persisted login_disabled for self node
    fn load_self_login_disabled() -> Option<bool> {
        if let Ok(data) = std::fs::read_to_string(Self::SELF_LOGIN_DISABLED_FILE) {
            let trimmed = data.trim();
            match trimmed {
                "true" | "1" => return Some(true),
                "false" | "0" => return Some(false),
                _ => {}
            }
        }
        None
    }

    /// Persist self login_disabled to disk
    pub fn save_login_disabled_file(disabled: bool) {
        let _ = std::fs::create_dir_all("/etc/wolfstack");
        if let Err(e) = std::fs::write(Self::SELF_LOGIN_DISABLED_FILE, if disabled { "true" } else { "false" }) {
            warn!("Failed to save self login_disabled: {}", e);
        }
    }

}

/// Message exchanged between agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentMessage {
    /// "Hello, here's my status"
    StatusReport {
        node_id: String,
        hostname: String,
        metrics: SystemMetrics,
        components: Vec<ComponentStatus>,
        #[serde(default)]
        docker_count: u32,
        #[serde(default)]
        lxc_count: u32,
        #[serde(default)]
        vm_count: u32,
        #[serde(default)]
        compose_count: u32,
        #[serde(default)]
        public_ip: Option<String>,
        #[serde(default)]
        known_nodes: Vec<Node>,
        #[serde(default)]
        deleted_ids: Vec<String>,
        /// WolfNet IPs in use on this node (host IP first, then the IPs of
        /// RUNNING containers/VMs). Receivers build the route map from this.
        #[serde(default)]
        wolfnet_ips: Vec<String>,
        /// Every WolfNet IP this node holds, stopped workloads included —
        /// for allocation on peers only, never for routing. Empty from a
        /// node older than v25.25.3 (its `wolfnet_ips` is then the used set).
        #[serde(default)]
        wolfnet_reserved_ips: Vec<String>,
        #[serde(default)]
        has_docker: bool,
        #[serde(default)]
        has_lxc: bool,
        #[serde(default)]
        has_kvm: bool,
        /// Workload subnets (CIDRs) on this peer — Docker / LXC / VM
        /// bridges. Consumed by the missing-route analyzer so peers see
        /// what subnet_routes need to point at this node. See
        /// `networking::collect_workload_subnets`.
        #[serde(default)]
        workload_subnets: Vec<String>,
        /// Operator-declared physical-location tag — see `Node::site`.
        /// `None` from older peers; the cluster-sync site decision
        /// falls back to auto-derive from address in that case.
        #[serde(default)]
        site: Option<String>,
        /// Operator-set friendly display name — see `Node::display_name`.
        /// `None` from older peers; the UI then shows the hostname.
        #[serde(default)]
        display_name: Option<String>,
        /// Tier roles assigned to this node — see `Node::roles`. Empty from
        /// older peers → general-purpose node.
        #[serde(default)]
        roles: Vec<NodeRole>,
        /// Enterprise license key — propagated to cluster nodes that don't have one
        #[serde(default)]
        license_key: Option<String>,
        /// Sender's Ed25519 public key (base64). Older peers omit it.
        #[serde(default)]
        pubkey: Option<String>,
    },
    /// "Give me your status"
    StatusRequest,
    /// "Install this component"
    InstallRequest { component: String },
    /// "Start/stop/restart this service"
    ServiceAction { service: String, action: String },
    /// Response
    Response { success: bool, message: String },
}

// REMOVED in v25.5.5: `sweep_push_cluster_names`, the retroactive
// cluster-name heal sweep (added by 85e3553a for fleets joined before
// C1-Fix-2). Do not reintroduce it.
//
// It read THIS node's `nodes.json` record for each peer and POSTed that
// name to the peer's `/api/agent/cluster-name` every 30 minutes. Two
// things make that wrong:
//
//  1. Our `cluster_name` for a peer is a MIRROR, not a command. The
//     gossip merge in `poll_remote_nodes` syncs it *from* whatever peers
//     report (`eff_cluster = known.cluster_name`) and only holds a local
//     value while an identity intent is open. The sweep took that mirror
//     and re-broadcast it as an instruction, so every node asserted every
//     other node's identity with no record that an operator asked for it.
//
//  2. Its "fundamentally one-shot, idempotent" premise only holds if the
//     name never legitimately changes. Once it does, the sweep re-asserts
//     the stale value and UNDOES the correction.
//
// Observed 2026-07-28 (Wolf Territories): wolfstack-1 adopted a region
// cluster's name via the weak-IP gossip bug fixed in v25.5.4, self-reported
// it, and five peers faithfully mirrored it. v25.5.4 stopped the adoption
// but the stale value was already replicated, and this sweep pushed it back
// from four nodes at once — wolfstack-1 reverted within three minutes of
// every manual correction.
//
// Cluster/display identity now travels ONLY through the identity-intent
// queue below: an operator edit records an intent, `sweep_identity_intents`
// re-pushes until the owner confirms, then clears it. One authority, and a
// deliberate operator action behind every change.

// ─── Identity-intent queue (reliable rename / move propagation) ──────
//
// An operator rename (display_name) or move (cluster_name) made on the admin
// node must reach the OWNING node — only its own self-report is authoritative,
// so until the owner adopts the value, the next poll would revert it. We push
// synchronously on edit, but the owner may be offline or briefly unreachable;
// `pending_identity.json` records the intended value (keyed by the node's
// local id) and `sweep_identity_intents` re-pushes every cycle until the
// owner's self-report confirms it, then clears the intent. This is what makes
// "rename an offline node, it applies when it reconnects" work, and stops a
// gossip race from reverting an applied edit.

/// One node's pending identity edit. A field set to `Some` is what we want
/// the owner to end up with (`display_name: Some("")` means "clear the
/// override"); `None` means "no intent for this field".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityIntent {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub cluster_name: Option<String>,
    #[serde(default)]
    pub ts: u64,
}

fn identity_intents_file() -> String { crate::paths::get().pending_identity_config }

/// Load the intent map (node id → intent). Missing/malformed → empty.
pub fn load_identity_intents() -> HashMap<String, IdentityIntent> {
    std::fs::read_to_string(identity_intents_file()).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_identity_intents(map: &HashMap<String, IdentityIntent>) {
    let path = identity_intents_file();
    if let Some(dir) = std::path::Path::new(&path).parent() { let _ = std::fs::create_dir_all(dir); }
    if map.is_empty() { let _ = std::fs::remove_file(&path); return; }
    if let Ok(json) = serde_json::to_string_pretty(map)
        && let Err(e) = std::fs::write(&path, json) { warn!("Failed to save identity intents: {}", e); }
}

/// Record (merge) an intent to push `display_name`/`cluster_name` to node `id`
/// until the owner confirms. Only the `Some` fields are recorded.
pub fn record_identity_intent(id: &str, display_name: Option<String>, cluster_name: Option<String>, ts: u64) {
    if display_name.is_none() && cluster_name.is_none() { return; }
    let mut map = load_identity_intents();
    let e = map.entry(id.to_string()).or_default();
    if display_name.is_some() { e.display_name = display_name; }
    if cluster_name.is_some() { e.cluster_name = cluster_name; }
    e.ts = ts;
    save_identity_intents(&map);
}

/// Drop any pending intent for `id` (node deleted, or edit confirmed).
pub fn clear_identity_intent(id: &str) {
    let mut map = load_identity_intents();
    if map.remove(id).is_some() { save_identity_intents(&map); }
}

/// Push one node's intended identity fields to it. Best-effort; returns true
/// if every requested field was accepted by the owner.
pub async fn push_identity_to_node(node: &Node, intent: &IdentityIntent, cluster_secret: &str) -> bool {
    let client = crate::api::API_HTTP_CLIENT.clone();
    let mut all_ok = true;
    // Each field is its own receiver, mirroring the existing cluster-name push.
    let pushes: Vec<(&str, String)> = [
        intent.display_name.as_ref().map(|v| ("/api/agent/display-name", serde_json::json!({ "display_name": v }).to_string())),
        intent.cluster_name.as_ref().map(|v| ("/api/agent/cluster-name", serde_json::json!({ "cluster_name": v }).to_string())),
    ].into_iter().flatten().collect();
    for (route, payload) in pushes {
        let urls = crate::api::build_node_urls(&node.address, node.port, route);
        let mut ok = false;
        for url in &urls {
            if let Ok(resp) = client.post(url)
                .timeout(std::time::Duration::from_secs(5))
                .peer_auth(cluster_secret)
                .header("Content-Type", "application/json")
                .body(payload.clone())
                .send().await
            {
                let success = resp.status().is_success();
                let _ = resp.bytes().await;
                if success { ok = true; break; }
            }
        }
        all_ok &= ok;
    }
    all_ok
}

/// Whether a pending identity intent may be cleared on this sweep.
///
/// Successful DELIVERY to the owner is the only admissible evidence. The
/// tempting alternative — "clear once our own node record matches the intent"
/// — is unsound: both edit paths (`update_node_settings`, `add_node`) write
/// the intended value into our `nodes.json` record BEFORE recording the
/// intent, so that record always matches and would clear an intent the owner
/// never received. Pure so this rule (silent edit-loss if wrong) is unit-tested.
fn intent_may_clear(node_online: bool, push_all_ok: bool) -> bool {
    node_online && push_all_ok
}

/// Reconcile loop: re-push every pending intent to its owner until the owner's
/// self-report (its current cluster view) confirms the value, then clear it.
/// Clears intents for nodes that vanished or aren't WolfStack agents.
pub async fn sweep_identity_intents(cluster: Arc<ClusterState>, cluster_secret: String) {
    let intents = load_identity_intents();
    if intents.is_empty() { return; }
    for (id, intent) in intents {
        let Some(node) = cluster.get_node(&id) else { clear_identity_intent(&id); continue; };
        // Self never needs a push; Proxmox labels are admin-local only.
        if node.is_self || node.node_type != "wolfstack" { clear_identity_intent(&id); continue; }
        // DELIVERY is the only evidence that may clear an intent. Do NOT
        // consult our own nodes.json record here: both edit paths
        // (update_node_settings, add_node) write the intended value into that
        // record BEFORE recording the intent, so the mirror always "matches"
        // and would clear an intent that never reached the owner. Until
        // v25.5.5 that early clear was masked by the retroactive cluster-name
        // sweep, which re-pushed the mirror every 30 minutes; with that sweep
        // gone (see the tombstone above) a mirror-based clear would silently
        // lose any edit made while the owner was unreachable.
        //
        // A successful push IS adoption: the receivers persist synchronously
        // (self_cluster.json / self display name) before answering 2xx, and
        // push_identity_to_node only reports true when EVERY requested field
        // was accepted. So there is no window where we clear ahead of the
        // owner actually holding the value.
        // Short-circuits when the owner is unreachable: no HTTP is attempted,
        // the intent stays pending, and it applies on reconnect.
        let delivered = node.online
            && push_identity_to_node(&node, &intent, &cluster_secret).await;
        if intent_may_clear(node.online, delivered) {
            clear_identity_intent(&id);
        }
    }
}

// ─── Control-plane replication (cluster membership + users + auth) ───
//
// So that logging into ANY node shows the same fleet view and the same
// WolfStack users — not just the node the cluster was built on. Membership
// converges (re-injection-safe via tombstones); users.json + auth-config.json
// replicate last-write-wins by their logical version.

/// The replicable control-plane state a node pushes to its peers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ControlPlaneBundle {
    /// Sender's self_id (diagnostics only).
    #[serde(default)]
    pub from_id: String,
    /// Sender's view of cluster members (metrics stripped) — for convergence.
    #[serde(default)]
    pub members: Vec<Node>,
    /// Sender's tombstones — merged first so we never re-add a removed node.
    #[serde(default)]
    pub deleted_ids: Vec<String>,
    /// Raw users.json (UserStore) + its logical version.
    #[serde(default)]
    pub users_json: String,
    #[serde(default)]
    pub users_version: u64,
    /// Raw auth-config.json (AuthConfig) + its logical version.
    #[serde(default)]
    pub auth_json: String,
    #[serde(default)]
    pub auth_version: u64,
}

/// Build the local control-plane bundle to push to peers. Member metrics and
/// components are stripped — the receiver only needs the existence + address of
/// each peer; status is filled in by its own poll.
pub fn build_control_plane_bundle(cluster: &ClusterState) -> ControlPlaneBundle {
    let (users_json, users_version, auth_json, auth_version) =
        crate::auth::users::control_plane_snapshot();
    let self_id = cluster.self_id.clone();
    // Advertise the WHOLE fleet — control-plane replication is "log into any
    // node, see every cluster". `cluster_name` is a display grouping, not a
    // membership boundary; filtering it here is what severed federated clusters
    // (v24.29.1). The receiver dedups by stable self_id, so multi-homed records
    // can't pile up regardless of how many peers we advertise.
    let members = cluster.get_all_nodes().into_iter()
        .map(|mut n| {
            n.metrics = None;
            n.components = Vec::new();
            // The self-entry's self_id field is None by construction (its id IS
            // the self_id). Stamp it so the receiver can dedup us by the stable
            // global key instead of by address — without this, our hub entry
            // gets re-added under each address variant on every receiver.
            if n.is_self && n.self_id.as_deref().filter(|s| !s.is_empty()).is_none() {
                n.self_id = Some(self_id.clone());
            }
            n
        })
        .collect();
    ControlPlaneBundle {
        from_id: cluster.self_id.clone(),
        members,
        deleted_ids: cluster.get_deleted_ids(),
        users_json,
        users_version,
        auth_json,
        auth_version,
    }
}

/// Apply a received control-plane bundle: merge tombstones, converge
/// membership, then last-write-wins the users/auth blobs. `sender_addr` is the
/// source IP of the inbound connection — used to repair the sender's own
/// member entry, which carries its (unreachable) bind address (0.0.0.0). This
/// is how every other node learns the hub "main"'s real, reachable address.
/// Returns a one-line summary for logging.
pub fn apply_control_plane_bundle(cluster: &ClusterState, bundle: &ControlPlaneBundle, sender_addr: Option<String>) -> String {
    cluster.merge_tombstones(&bundle.deleted_ids);
    let mut members = bundle.members.clone();
    if let Some(addr) = sender_addr.filter(|a| is_usable_addr(a)) {
        // Repair the sender's self-entry (id/self_id == from_id) when it
        // advertised an unusable address — the connection source IP is how it
        // actually reached us, so it's reachable back on the LAN.
        for m in members.iter_mut() {
            let is_sender = m.id == bundle.from_id
                || m.self_id.as_deref() == Some(bundle.from_id.as_str());
            if is_sender && !is_usable_addr(&m.address) {
                m.address = addr.clone();
            }
        }
    }
    cluster.merge_member_refs(&members);
    let (users_updated, auth_updated) = crate::auth::users::control_plane_apply(
        &bundle.users_json,
        bundle.users_version,
        &bundle.auth_json,
        bundle.auth_version,
    );
    format!(
        "members={} users_updated={} auth_updated={}",
        bundle.members.len(), users_updated, auth_updated
    )
}

/// Parse `ip -j addr show` JSON into the set of non-loopback IPv4 addresses.
/// Pure (no I/O) for testability.
fn parse_local_ipv4(json: &[u8]) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    let Ok(entries) = serde_json::from_slice::<Vec<serde_json::Value>>(json) else { return set; };
    for entry in &entries {
        if entry["ifname"].as_str() == Some("lo") { continue; }
        let Some(ai) = entry["addr_info"].as_array() else { continue; };
        for a in ai {
            if a["family"].as_str() != Some("inet") { continue; }
            if let Some(ip) = a["local"].as_str().filter(|ip| !ip.starts_with("127.")) {
                set.insert(ip.to_string());
            }
        }
    }
    set
}

/// How strongly does a gossiped node entry identify as *us*?
///
/// Returns `(is_self, is_self_strong)`.
///
/// * **strong** — the entry carries our global id (`id` or `self_id`). Only a
///   strong match is authoritative enough to let a peer rewrite our identity
///   (cluster name, display name).
/// * **weak** — the entry merely carries one of our own LAN/tunnel IPs. That is
///   enough to stop admitting ourselves into the node list as a foreign "red"
///   node (a host behind a reverse-proxy WAN hostname self-identifies by that
///   hostname, so a peer gossiping our LAN IP back matches neither id), but it
///   must NOT be treated as authoritative: a peer gossips back *its* view of us,
///   addressed by whatever IP it reaches us on and tagged with *that peer's*
///   cluster. Adopting from a weak match silently moves us into their cluster.
pub(crate) fn gossip_identity_match(
    known_id: &str,
    known_self_id: Option<&str>,
    known_address: &str,
    self_id: &str,
    local_ips: &std::collections::HashSet<String>,
) -> (bool, bool) {
    let strong = known_id == self_id || known_self_id == Some(self_id);
    let weak = !known_address.is_empty() && local_ips.contains(known_address);
    (strong || weak, strong)
}

/// Every IPv4 address currently configured on this host (each NIC: LAN,
/// WolfNet, VLAN, storage, swarm overlay…), loopback excluded. Used so the
/// poll/replicate loops never contact OUR OWN addresses — a self entry under a
/// secondary NIC, which on a multi-homed host is the feedback that turns a
/// bloated node list into a CPU storm. Cached 60s (IPs rarely change; a new
/// WolfNet/VLAN attach is picked up within a minute). On an `ip` hiccup it
/// reuses the last good set rather than returning empty, so a transient failure
/// can never make us suddenly treat our own IPs as pollable peers.
pub fn local_ipv4_addrs() -> std::collections::HashSet<String> {
    static CACHE: std::sync::Mutex<Option<(std::time::Instant, HashSet<String>)>> =
        std::sync::Mutex::new(None);
    if let Some(set) = CACHE.lock().ok().and_then(|g| {
        g.as_ref()
            .filter(|(at, _)| at.elapsed() < std::time::Duration::from_secs(60))
            .map(|(_, set)| set.clone())
    }) {
        return set;
    }
    let set: HashSet<String> = std::process::Command::new("ip")
        .args(["-j", "addr", "show"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| parse_local_ipv4(&o.stdout))
        .unwrap_or_default();
    if set.is_empty() {
        // Enumeration failed — reuse the last good set so we don't momentarily
        // forget our own IPs (which would let the loops poll us).
        return CACHE.lock().ok()
            .and_then(|g| g.as_ref().map(|(_, last)| last.clone()))
            .unwrap_or_default();
    }
    if let Ok(mut g) = CACHE.lock() {
        *g = Some((std::time::Instant::now(), set.clone()));
    }
    set
}

/// Push our control-plane bundle to every online WolfStack peer. Runs both as
/// a periodic sweep (heals nodes that were offline) and one-shot right after a
/// user/auth change (so edits land in seconds). Cluster-secret authed.
pub async fn sweep_replicate_control_plane(cluster: Arc<ClusterState>, cluster_secret: String) {
    // Emergency kill switch — set WOLFSTACK_DISABLE_CP_SYNC=1 to halt all
    // control-plane replication without a rebuild. A clean off-switch for any
    // future convergence storm.
    if std::env::var("WOLFSTACK_DISABLE_CP_SYNC").map(|v| v != "0" && !v.is_empty()).unwrap_or(false) {
        return;
    }
    // Replicate to every online WolfStack peer across the whole fleet. The CPU
    // storm was unbounded GROWTH of nodes.json (the same multi-homed node
    // re-added under each address forever), now fixed by self_id dedup — NOT the
    // count of distinct peers we push to, which is bounded by the real fleet.
    let local = local_ipv4_addrs();
    let peers: Vec<(String, u16)> = {
        let nodes = cluster.nodes_read();
        let mut seen: std::collections::HashSet<(String, u16)> = std::collections::HashSet::new();
        nodes.values()
            .filter(|n| !n.is_self && n.node_type == "wolfstack" && n.online)
            .map(|n| (n.address.clone(), n.port))
            // Skip our OWN addresses (a self entry under another NIC) and push to
            // each distinct endpoint once — duplicate/self records can't multiply
            // the sweep into a storm. Removes only redundant pushes; every real
            // peer (a distinct, non-local endpoint) is still reached.
            .filter(|(addr, _)| !local.contains(addr))
            .filter(|key| seen.insert(key.clone()))
            .collect()
    };
    if peers.is_empty() { return; }

    let payload = match serde_json::to_value(build_control_plane_bundle(&cluster)) {
        Ok(v) => v,
        Err(_) => return,
    };
    let client = crate::api::API_HTTP_CLIENT.clone();
    for (address, port) in peers {
        let urls = crate::api::build_node_urls(&address, port, "/api/cluster/control-plane");
        for url in &urls {
            match client.post(url)
                .timeout(std::time::Duration::from_secs(8))
                .peer_auth(&cluster_secret)
                .json(&payload)
                .send()
                .await
            {
                Ok(resp) => {
                    let ok = resp.status().is_success();
                    let _ = resp.bytes().await;
                    if ok { break; } // delivered — don't try the next URL scheme
                }
                Err(_) => { /* try next URL */ }
            }
        }
    }
}

/// Poll remote nodes for their status
pub async fn poll_remote_nodes(cluster: Arc<ClusterState>, cluster_secret: String, ai_agent: Option<Arc<crate::ai::AiAgent>>) {
    // Snapshot previous online state BEFORE polling
    let previous_states: HashMap<String, (bool, String)> = {
        let nodes = cluster.nodes_read();
        let now = now_unix();
        nodes.values()
            .filter(|n| !n.is_self)
            .map(|n| (n.id.clone(), (now - n.last_seen < 60, n.hostname.clone())))
            .collect()
    };

    let nodes = cluster.get_all_nodes();
    // Our own addresses (every NIC) + the endpoints already polled this cycle,
    // so the loop never contacts itself or the same endpoint twice (storm guard).
    let local_ips = local_ipv4_addrs();
    let mut polled_endpoints: HashSet<(String, u16)> = HashSet::new();
    // Collect subnet routes from all remote nodes' wolfnet_ips
    let mut subnet_routes: HashMap<String, String> = HashMap::new();
    // Set when a poll changes a peer's persisted identity/topology fields
    // (workload_subnets, hostname, self_id, …) — flushed as ONE save_nodes()
    // after the loop, so a cycle costs at most one disk write and a steady-
    // state cluster costs none. Without this, update_remote() only touched
    // RAM and nodes.json stayed stale until some unrelated settings event,
    // feeding obsolete workload_subnets to every consumer that reads the
    // file (predictive missing_subnet_route, WolfRouter auto-apply).
    let mut persist_after_cycle = false;
    for node in nodes {
        if node.is_self { continue; }

        if node.node_type == "proxmox" {
            // Deprecated: the standalone Proxmox API integration is no longer supported.
            // These entries are surfaced through the deprecation banner so the user can
            // remove them and re-add the hosts as full WolfStack nodes. Do not poll.
            continue;
        }

        // Never poll our OWN addresses (a self entry under another NIC), and poll
        // each distinct endpoint at most once per cycle. These two guards bound
        // the 10s loop to distinct, non-local peers — so a bloated or multi-homed
        // node list can't turn it into a CPU storm. No real peer is dropped: a
        // distinct, non-local endpoint is always polled.
        if local_ips.contains(&node.address) { continue; }
        if !polled_endpoints.insert((node.address.clone(), node.port)) { continue; }

        // ── Poll WolfStack node via agent ──
        // v23.12: HTTPS-first via build_node_urls. CA-signed-cert peers no
        // longer bind the second listener, so the pre-v23.12 chain that
        // led with http://addr:port+1 silently dropped them. The shared
        // POLL_CLIENT below has danger_accept_invalid_certs so self-signed
        // peers still answer on HTTPS.
        let urls = crate::api::build_node_urls(&node.address, node.port, "/api/agent/status");


        let client = {
            // Reuse a single client across all poll cycles for connection pooling & keep-alive
            static POLL_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
                crate::api::ipv4_only_client_builder()
                    .timeout(Duration::from_secs(10))
                    // A connect timeout is NOT optional here, and its absence
                    // took the production fleet down on 2026-08-05.
                    //
                    // `timeout()` bounds the whole request, but a SYN to a
                    // black-holed address never reaches the point where that
                    // clock does any good — the socket sits in SYN-SENT for the
                    // kernel's full retry window (~130s with the default
                    // tcp_syn_retries=6). This poller fires every 10 seconds at
                    // every peer, and `build_node_urls` gives each peer THREE
                    // targets (https :api, http :inter_node, http :api). So each
                    // unreachable peer-URL stacked ~13 cycles of connections on
                    // top of each other, for ever.
                    //
                    // Measured on wolfstack-1: 2,422 sockets in SYN-SENT (1,302
                    // to :8553, 997 to :8554) plus 2,868 in CLOSE-WAIT — 6,349
                    // sockets on one node, climbing ~700/min until the fd table
                    // was exhausted and epoll cost put four actix workers at
                    // ~80% each in kernel time.
                    //
                    // API_HTTP_CLIENT already carried connect_timeout(3s) for
                    // exactly this reason (Bel's 5827 CLOSE_WAIT report). The
                    // poller — the one client that dials EVERY peer on a timer,
                    // reachable or not — was the one that never got it.
                    .connect_timeout(Duration::from_secs(3))
                    .danger_accept_invalid_certs(true)
                    // Aggressive pool tuning so cluster polling doesn't
                    // leave orphaned idle sockets in CLOSE_WAIT when
                    // peers close early. See api/mod.rs API_HTTP_CLIENT.
                    .pool_idle_timeout(Duration::from_secs(15))
                    .pool_max_idle_per_host(4)
                    .tcp_keepalive(Duration::from_secs(30))
                    .build()
                    .unwrap_or_else(|_| reqwest::Client::new())
            });
            &*POLL_CLIENT
        };

        let mut poll_ok = false;
        for url in &urls {
            match client.get(url)
                .peer_auth(&cluster_secret)
                .send().await
            {
                Ok(resp) => {
                    // Only treat a peer as "polled" when we actually
                    // parsed a StatusReport from its body. A 401 / 404 /
                    // 500 response from a misconfigured peer used to fall
                    // into the catch-all `poll_ok = true` below — the
                    // node looked successfully polled while we'd
                    // collected zero data, which then caused
                    // `replace_wolfnet_routes` to wipe that host's
                    // container/VM routes from `routes.json` (because
                    // its host wolfnet IP wasn't added to `fresh_hosts`
                    // and existing entries pointing at it were dropped
                    // from `final_routes`). klasSponsor 2026-05-13:
                    // intermittent container/VM WolfNet IP unreachability
                    // from the VPS while peer-to-peer ping kept working.
                    if !resp.status().is_success() {
                        // DRAIN BEFORE LEAVING. reqwest cannot release the
                        // socket until the body is consumed, so a bare
                        // `continue` here strands the connection: the peer
                        // FINs after its error response and our side never
                        // closes, parking the socket in CLOSE-WAIT forever.
                        //
                        // This is the highest-frequency dial in the product
                        // — every peer, every 10s — so against a peer that
                        // answers non-2xx it leaks ~8,640 sockets per day.
                        // klas's hemulen reached 18,122 CLOSE-WAIT across two
                        // such peers and exhausted the 65,535 fd table, at
                        // which point actix_server could no longer accept
                        // ("No file descriptors available (os error 24)") and
                        // the node dropped off the cluster (2026-08-12).
                        //
                        // A healthy peer answers 200 and is drained by
                        // `resp.json()` below, which is why this never
                        // surfaced on a fleet whose peers are all well.
                        let _ = resp.bytes().await;
                        continue;
                    }
                    if let Ok(msg) = resp.json::<AgentMessage>().await
                        && let AgentMessage::StatusReport { node_id: peer_self_id, hostname, metrics, components, docker_count, lxc_count, vm_count, compose_count, public_ip, known_nodes, deleted_ids, wolfnet_ips, wolfnet_reserved_ips, has_docker, has_lxc, has_kvm, workload_subnets: peer_workload_subnets, site: peer_site, display_name: peer_display_name, roles: peer_roles, license_key, pubkey: peer_pubkey } = msg {
                            let now = now_unix();
                            // Detect TLS by the URL scheme that actually
                            // answered. v23.12 chain is HTTPS → HTTP-over-
                            // WolfNet → legacy plaintext; only the last
                            // (plain http://addr:port) implies a `--no-tls`
                            // peer. The WolfNet HTTP overlay step is also
                            // a TLS peer (the peer binds the second
                            // listener only because it's self-signed).
                            // Must build the comparison prefix the same way
                            // build_node_urls does (bracketed v6) or the
                            // legacy-plaintext match never fires for v6 peers.
                            let node_tls = url.starts_with("https://")
                                || !url.starts_with(&format!("http://{}:{}/", crate::netaddr::bracket_host(&node.address), node.port));
                            // Capture fresh hostname + public_ip BEFORE the move into
                            // update_remote so we can pass them to the wolfnet endpoint
                            // reconciler below without re-locking cluster state.
                            let peer_hostname_for_reconcile = hostname.clone();
                            let peer_public_ip_for_reconcile = public_ip.clone();
                            // `node` is a snapshot from the start of this poll
                            // cycle. Operator-set fields (manager policy, a
                            // pinned-key reset) can change while the poll is in
                            // flight; read them live at write time or the
                            // snapshot silently undoes the operator's change
                            // (seen on the dev cluster 2026-08-29).
                            let (live_pubkey, live_manager) = cluster.get_node(&node.id)
                                .map(|n| (n.pubkey, n.manager))
                                .unwrap_or((node.pubkey.clone(), node.manager));
                            let updated_node = Node {
                                id: node.id.clone(),
                                hostname,
                                address: node.address.clone(),
                                port: node.port,
                                // Local per-peer routing override — preserve it
                                // across polls exactly like `address`; the peer
                                // never self-reports this.
                                migration_address: node.migration_address.clone(),
                                last_seen: now,
                                metrics: Some(metrics),
                                components,
                                online: true,
                                is_self: false,
                                docker_count,
                                lxc_count,
                                vm_count,
                                compose_count,
                                public_ip: public_ip.clone(),
                                node_type: "wolfstack".to_string(),
                                pve_token: None,
                                pve_fingerprint: None,
                                pve_node_name: None,
                                pve_cluster_name: None,
                                cluster_name: node.cluster_name.clone(),
                                join_verified: node.join_verified,
                                has_docker,
                                has_lxc,
                                has_kvm,
                                login_disabled: node.login_disabled,
                                tls: node_tls,
                                update_script: node.update_script.clone(),
                                // Capture the peer's own self_id from its
                                // status report so cross-node proxy calls
                                // that arrive with the self_id (topology,
                                // LAN records) resolve via the get_node
                                // self_id fallback.
                                //
                                // If the peer's report is anomalously empty
                                // (transient bug, partial config), preserve
                                // the previously-captured self_id rather
                                // than wiping it — otherwise a single bad
                                // poll re-opens the 404 window until the
                                // next good poll.
                                self_id: if peer_self_id.is_empty() {
                                    node.self_id.clone()
                                } else {
                                    Some(peer_self_id)
                                },
                                workload_subnets: peer_workload_subnets,
                                // Peer's own declared site (None for
                                // older peers and for nodes the
                                // operator hasn't tagged yet). We
                                // trust the peer's self-report —
                                // that's the source of truth for a
                                // node's own location.
                                site: peer_site,
                                // The owner is authoritative for its own
                                // display name — trust its self-report, same
                                // as site. (None = no override → show hostname.)
                                display_name: peer_display_name,
                                // The owner is authoritative for its own roles
                                // too — trust the self-report. Empty = a
                                // general-purpose node (or an older peer).
                                roles: peer_roles,
                                // Pin the peer's key on first sight (TOFU over
                                // the same channel the cluster already trusts).
                                // A DIFFERENT key later is never adopted
                                // silently: keep the pinned one and say so — a
                                // reinstalled node is reset by the operator
                                // (node settings → Reset identity key).
                                pubkey: match (live_pubkey.as_deref().filter(|k| !k.is_empty()), peer_pubkey.as_deref().filter(|k| !k.is_empty())) {
                                    (None, Some(k)) => {
                                        tracing::info!("node identity: pinned public key for {} ({})", node.hostname, node.id);
                                        Some(k.to_string())
                                    }
                                    (Some(old), Some(k)) if old != k => {
                                        warn!("node identity: {} ({}) now advertises a DIFFERENT key than the one pinned — keeping the pinned key. If the node was reinstalled, reset its identity key from node settings.", node.hostname, node.id);
                                        Some(old.to_string())
                                    }
                                    (old, _) => old.map(str::to_string),
                                },
                                // Local operator policy about this peer — never
                                // taken from the peer's own report.
                                manager: live_manager,
                            };
                            // `node` is the pre-poll snapshot from
                            // get_all_nodes() at cycle start — compare the
                            // persisted fields BEFORE the fresh report
                            // replaces it in RAM, and remember to flush
                            // nodes.json once after the loop.
                            if ClusterState::persistent_peer_fields_changed(&node, &updated_node) {
                                persist_after_cycle = true;
                            }
                            cluster.update_remote(updated_node);

                            // Reset fail count on success
                            POLL_FAIL_COUNTS.lock().unwrap().remove(&node.id);

                            // Hook B for WolfNet endpoint self-healing — cheap O(1)
                            // check against the local wolfnet config; only acts on
                            // the demonstrably-bad pattern (public self + RFC1918
                            // peer endpoint). See
                            // networking::reconcile_local_wolfnet_endpoint_if_needed
                            // for the conservative decision rule, and
                            // networking::decide_peer_endpoint for the five safety
                            // guards (wolfnet-subnet loop, self-loop,
                            // loopback/link-local, behind-NAT, no-public-ip). Runs
                            // in a blocking task to keep file I/O off the poll
                            // task.
                            {
                                let self_addr = cluster.self_address.clone();
                                let hn = peer_hostname_for_reconcile;
                                let plan = node.address.clone();
                                let pip = peer_public_ip_for_reconcile;
                                tokio::task::spawn_blocking(move || {
                                    crate::networking::reconcile_local_wolfnet_endpoint_if_needed(
                                        &self_addr,
                                        &hn,
                                        Some(&plan),
                                        pip.as_deref(),
                                    );
                                });
                            }

                            // Enterprise license propagation: if a remote node has a
                            // valid license and we don't, save it locally.
                            if let Some(ref lk) = license_key
                                && !lk.is_empty() && !crate::compat::platform_ready() {
                                    let dm_path = crate::compat::dm_path();
                                    if std::fs::read_to_string(&dm_path).map(|s| s.trim().is_empty()).unwrap_or(true) {
                                        if let Some(parent) = std::path::Path::new(&dm_path).parent() {
                                            let _ = std::fs::create_dir_all(parent);
                                        }
                                        if std::fs::write(&dm_path, lk).is_ok() {
                                            tracing::info!("Enterprise license received from cluster node '{}'", node.hostname);
                                        }
                                    }
                                }

                            // Merge tombstones first — so we don't re-add deleted nodes
                            cluster.merge_tombstones(&deleted_ids);

                            // Merge known_nodes (gossip) — mirror node settings from remote
                            let current_nodes = cluster.get_all_nodes();
                            // Pending identity edits (display name / cluster move) made on
                            // THIS node that their owner hasn't confirmed yet. While such an
                            // intent is open, a peer that still gossips the OLD value must
                            // not revert our local view — the operator just made the edit
                            // and the sweep is still pushing it to the owner. Without this
                            // guard, moving an OFFLINE node visibly snapped back in the UI
                            // on the next 10s poll of any peer (fleet audit, 2026-06-11).
                            let pending_intents = load_identity_intents();
                            let self_hostname = hostname::get()
                                .map(|h| h.to_string_lossy().to_string())
                                .unwrap_or_default();
                            for known in known_nodes {
                                // Self-identification in a gossip entry: match EITHER
                                // by the entry's id (only fires when a node gossips its
                                // OWN view, which is rare) OR by the entry's `self_id`
                                // field (populated from the remote's StatusReport.node_id,
                                // which is the canonical `ws-{uuid}` from /etc/wolfstack/
                                // node_id). Pre-fix this only checked `known.id` against
                                // `self_id`, but those live in disjoint ID namespaces —
                                // `id` is the LOCALLY-ASSIGNED `node-{uuid}` of the
                                // sending peer, while `self_id` is the global ws-{uuid}.
                                // The pre-fix condition never matched cross-node, so
                                // gossip-driven cluster-name adoption was dead code.
                                // Also recognise a gossip entry carrying one of our OWN
                                // LAN IPs as self. A node behind a reverse-proxy WAN
                                // hostname self-identifies by that hostname, so when a peer
                                // gossips this node's LAN IP back, neither id nor self_id
                                // match and it was admitted as a foreign, un-pollable "red"
                                // node named after our own IP (wabil 2026-06-28: main showed
                                // a red 192.168.1.10, immich a red 192.168.1.4). `local_ips`
                                // is the cached set already computed at the top of this fn.
                                let (is_self, is_self_strong) = gossip_identity_match(
                                    &known.id,
                                    known.self_id.as_deref(),
                                    &known.address,
                                    &cluster.self_id,
                                    &local_ips,
                                );
                                if is_self {
                                    // A node is AUTHORITATIVE about its own cluster membership.
                                    // We NEVER adopt our own cluster_name from a peer's gossip.
                                    //
                                    // History: this block used to adopt a gossiped cluster on a
                                    // strong self-id match, as a "safety net" for an admin rename
                                    // made on another node. But a gossiped record is a MIRROR —
                                    // every peer syncs its copy of us from other peers — and it
                                    // carries no intent or timestamp, so there is no way to tell a
                                    // fresh admin change from a STALE mirror re-asserting an old
                                    // value. On 2026-07-28 adding the Wolf-Grid-Regions region
                                    // servers left them holding wolfstack-1's record labelled
                                    // "Wolf-Grid-Regions"; because that mirror carried wolfstack-1's
                                    // real global id, the strong-match gate passed and wolfstack-1
                                    // re-adopted the stale label within one gossip round of every
                                    // correction — a permanent flap that silently reorganised the
                                    // operator's whole fleet view. It recurred on v25.9.3
                                    // (Paul 2026-08-01), because the stale mirrors were still out
                                    // there and this adoption path kept honouring them.
                                    //
                                    // A legitimate reassignment travels via the delivery-confirmed
                                    // identity-intent queue + the /api/agent/cluster-name push
                                    // receiver (which retries until the target actually applies it
                                    // and re-delivers to a node that was offline). Passive gossip
                                    // adoption was only ever a redundant crutch on top of that, and
                                    // it is the crutch that caused the flap — so it is gone. Our
                                    // own self_cluster.json is the single source of truth for our
                                    // membership; peers learn it FROM us, never the reverse.
                                    if is_self_strong {
                                        // Same gossip-adoption safety net for the display name an
                                        // admin set on another node. Only adopt a Some value —
                                        // an older peer that doesn't know the field gossips None,
                                        // which must NOT wipe an operator-set name.
                                        if let Some(ref gossiped_name) = known.display_name {
                                            // Normalise empty → cleared so memory and the
                                            // on-disk file (which save_* removes on empty)
                                            // never disagree and re-assert a stale "".
                                            let want = if gossiped_name.is_empty() { None } else { Some(gossiped_name.clone()) };
                                            let current_name = {
                                                let nodes_r = cluster.nodes_read();
                                                nodes_r.get(&cluster.self_id).and_then(|n| n.display_name.clone())
                                            };
                                            if current_name != want {
                                                let mut nodes_w = cluster.nodes_write();
                                                if let Some(n) = nodes_w.get_mut(&cluster.self_id) {
                                                    n.display_name = want.clone();
                                                }
                                                drop(nodes_w);
                                                ClusterState::save_self_display_name(want.as_deref().unwrap_or(""));
                                            }
                                        }
                                    } // end is_self_strong — identity adoption requires a global id match
                                    continue;
                                }
                                // Also skip if this is us by hostname+port (gossip may report different address)
                                if known.node_type == "wolfstack" && known.hostname == self_hostname && known.port == cluster.port {
                                    continue;
                                }

                                // Skip tombstoned nodes
                                if cluster.is_tombstoned(&known.id) {
                                    continue;
                                }

                                // Check if this node is already known by ID
                                let existing_by_id = current_nodes.iter().find(|n| n.id == known.id);

                                if let Some(existing) = existing_by_id {
                                    // While an unconfirmed local intent covers a field, ignore
                                    // what peers gossip for it and keep our own (already-edited)
                                    // value — the intent sweep converges the owner, and the
                                    // intent clears once the owner self-reports the new value.
                                    let intent = pending_intents.get(&known.id);
                                    let eff_cluster: Option<String> =
                                        if intent.is_some_and(|i| i.cluster_name.is_some()) {
                                            existing.cluster_name.clone()
                                        } else {
                                            known.cluster_name.clone()
                                        };
                                    let eff_display: Option<String> =
                                        if intent.is_some_and(|i| i.display_name.is_some()) {
                                            existing.display_name.clone()
                                        } else {
                                            known.display_name.clone()
                                        };
                                    // Node already known — update its settings to mirror the source.
                                    // A wildcard (0.0.0.0) gossiped address doesn't count as a
                                    // change — it's preserved below — so don't let it trigger a
                                    // spurious write on its own.
                                    if (is_usable_addr(&known.address) && existing.address != known.address)
                                        || existing.hostname != known.hostname
                                        || existing.port != known.port
                                        || existing.pve_token != known.pve_token
                                        || existing.pve_fingerprint != known.pve_fingerprint
                                        // Case-insensitive: a different-CASE spelling of the same
                                        // cluster isn't a change (prevents the gossip flip-flop that
                                        // kept a node bouncing between e.g. "minio" and "Minio").
                                        || !cluster_eq(existing.cluster_name.as_deref(), eff_cluster.as_deref())
                                        // Only a Some gossiped display name counts as a change —
                                        // a None from an older peer must never clear an operator-set name.
                                        || (eff_display.is_some() && existing.display_name != eff_display)
                                    {


                                        cluster.update_node_settings(
                                            &known.id,
                                            Some(known.hostname.clone()),
                                            // Never overwrite a real, reachable address with a
                                            // peer's unusable self-entry (0.0.0.0 bind address) —
                                            // that's what dropped the hub "main" from other nodes.
                                            if is_usable_addr(&known.address) {
                                                Some(known.address.clone())
                                            } else {
                                                Some(existing.address.clone())
                                            },
                                            Some(known.port),
                                            known.pve_token.clone(),
                                            if known.pve_fingerprint.is_some() || existing.pve_fingerprint.is_some() {
                                                Some(known.pve_fingerprint.clone())
                                            } else {
                                                None
                                            },
                                            eff_cluster,
                                            None,  // don't propagate login_disabled via gossip
                                            None,  // don't propagate update_script via gossip
                                            None,  // site is propagated via StatusReport, not nested gossip
                                            // Mirror the gossiped display name (None = leave
                                            // untouched, so an older peer can't wipe it).
                                            eff_display,
                                            None,  // migration_address is LOCAL per-peer; never set it via gossip
                                            None,  // manager is operator policy; never set it via gossip
                                        );
                                    }
                                } else {
                                    // Dedup STRICTLY by the stable global self_id first
                                    // (mirrors merge_member_refs). A multi-homed node is
                                    // gossiped under its LAN IP, its WolfNet 10.x IP and
                                    // the v24.27 source-IP-repair variant — three different
                                    // addresses, ONE self_id. Keying only on address/hostname
                                    // (as before) let each variant be admitted as a fresh
                                    // record on successive polls, re-bloating nodes.json
                                    // between restarts — the same vector as the v24.27 storm.
                                    let known_sid = known.self_id.as_deref().filter(|s| !s.is_empty());
                                    let already_known = current_nodes.iter().any(|n| {
                                        (known_sid.is_some() && n.self_id.as_deref() == known_sid)
                                        || (n.address == known.address && n.port == known.port && n.pve_node_name == known.pve_node_name)
                                        || (n.hostname == known.hostname && n.port == known.port && n.node_type == known.node_type)
                                    });
                                    if !already_known {
                                        // Only auto-add nodes on private/local networks
                                        // Public-IP nodes must be added manually to prevent
                                        // machines from accidentally switching hosts
                                        if !is_private_address(&known.address) {

                                            continue;
                                        }

                                        let mut new_node = known.clone();
                                        new_node.online = false;
                                        new_node.is_self = false;
                                        // Keys are pinned only from the node's own report, never relayed.
                                        new_node.pubkey = None;
                                        new_node.manager = true;
                                        cluster.update_remote(new_node);
                                        cluster.save_nodes();
                                    }
                                }
                            }
                            // Collect subnet routes from this node's wolfnet_ips.
                            // First IP = host WolfNet address, remaining =
                            // container/VM IPs. Validate the host entry
                            // before treating it as a gateway: if `wolfnet0`
                            // had no IP on the peer at the moment its
                            // status was built, `wolfnet_used_ips()`
                            // returns containers WITHOUT a host index 0,
                            // and the old code would happily map
                            // container_b → container_a — poisoning
                            // routes.json on receivers.
                            let self_cluster = cluster.get_self_cluster_name();
                            let peer_cluster = node.cluster_name.as_deref().unwrap_or("WolfStack");
                            if peer_cluster == self_cluster && wolfnet_ips.len() > 1 {
                                let host_wn_ip = &wolfnet_ips[0];
                                let host_ok = !host_wn_ip.is_empty()
                                    && host_wn_ip.parse::<std::net::Ipv4Addr>().is_ok();
                                if host_ok {
                                    for container_ip in &wolfnet_ips[1..] {
                                        if container_ip.is_empty() { continue; }
                                        if container_ip == host_wn_ip { continue; }
                                        if container_ip.parse::<std::net::Ipv4Addr>().is_err() { continue; }
                                        subnet_routes.insert(container_ip.clone(), host_wn_ip.clone());
                                    }
                                } else {
                                    tracing::warn!(
                                        "poll_remote_nodes: peer {} returned {} wolfnet_ips with no valid host IP at [0]; skipping container-route propagation for this peer",
                                        node.id, wolfnet_ips.len()
                                    );
                                }
                            }
                            // Remember what this peer holds: its running set
                            // for conflict detection, its full set so a stopped
                            // container there keeps its IP reserved here.
                            if peer_cluster == self_cluster {
                                let label = if node.hostname.is_empty() { node.address.clone() } else { node.hostname.clone() };
                                let host = wolfnet_ips.first().cloned().unwrap_or_default();
                                // A peer older than v25.25.3 sends no reserved
                                // list and its `wolfnet_ips` IS the used set
                                // (stopped included) — usable as reservations,
                                // not as a running set for conflict detection.
                                let (active, reserved): (&[String], &[String]) = if wolfnet_reserved_ips.is_empty() {
                                    (&[], &wolfnet_ips)
                                } else {
                                    (&wolfnet_ips, &wolfnet_reserved_ips)
                                };
                                crate::containers::record_remote_wolfnet_ips(&node.id, &label, &host, active, reserved);
                            }
                            // Cache the peer's host WolfNet IP so future
                            // build_node_urls calls can insert a
                            // HTTP-over-WolfNet attempt before falling
                            // back to plaintext on the public address.
                            // Same validity guard as above — never cache
                            // a bogus "host IP" that's actually a
                            // container address.
                            if let Some(host_wn_ip) = wolfnet_ips.first()
                                && !host_wn_ip.is_empty()
                                    && host_wn_ip.parse::<std::net::Ipv4Addr>().is_ok() {
                                    crate::api::record_node_wolfnet_ip(&node.address, host_wn_ip);
                                }
                            // Only mark this poll as successful when we
                            // actually parsed a StatusReport. A 200 with
                            // a non-StatusReport body (corrupt agent, mid-
                            // restart partial JSON, version mismatch)
                            // used to also set poll_ok=true and cause
                            // the route-merge phase to treat the peer as
                            // authoritative-but-empty, dropping its
                            // routes.
                            poll_ok = true;
                        }
                    if poll_ok { break; }
                    // Body wasn't a StatusReport — try the next URL in
                    // the fallback chain rather than declaring success.
                    continue;
                }
                Err(_) => {
                    continue; // Try next URL
                }
            }
        }

        if !poll_ok {

            // Increment fail count; keep node online until 2 consecutive failures
            let mut fails = POLL_FAIL_COUNTS.lock().unwrap();
            let count = fails.entry(node.id.clone()).or_insert(0);
            *count += 1;
            if *count < 2 {
                let now = now_unix();
                let mut nodes = cluster.nodes_write();
                if let Some(n) = nodes.get_mut(&node.id) {
                    n.last_seen = now;
                }
            }
        }
    }

    // Batched flush of the persisted-field changes detected above — one
    // write per cycle at most, none when nothing meaningful changed.
    if persist_after_cycle {
        cluster.save_nodes();
    }

    // Build updated route table. Strategy:
    // - Start from existing routes (preserves routes for nodes we couldn't reach)
    // - Remove entries for nodes we successfully polled AND got container
    //   routes from (we have fresh authoritative data for those hosts)
    // - Add all fresh routes (local + successfully polled remote nodes)
    //
    // IMPORTANT interaction with the push path:
    //   The push handler (wolfnet_routes_announce) modifies WOLFNET_ROUTES
    //   in-place between poll cycles. This replace_wolfnet_routes call is
    //   authoritative and overwrites the cache. Routes from the push are
    //   preserved IFF the poll ALSO collected routes for that host (they
    //   end up in subnet_routes). If the poll returned only the host IP
    //   (no containers), the host is NOT in fresh_hosts, so any routes
    //   the push delivered for that host survive the replace.
    //
    //   The one race: if a container was JUST created, the push fires
    //   instantly (WOLFNET_ROUTES_CHANGED), but the poll's StatusReport
    //   cache (5s TTL) may still be stale. The poll then overwrites the
    //   push-delivered route with stale data. This heals on the next
    //   poll cycle (10s) when the StatusReport cache refreshes.

    // 1. Add LOCAL container/VM/VIP IPs → this node's wolfnet IP.
    //    RUNNING workloads only: a stopped container's IP claimed here
    //    (and pushed by the announce) fought the node actually running
    //    it, and the winner changed on every poll. Allocation still sees
    //    stopped IPs through wolfnet_used_ips / wolfnet_reserved_ips.
    let local_ips = crate::containers::wolfnet_active_ips_cached();
    let local_wn_ip = local_ips.first().cloned().unwrap_or_default();
    if local_ips.len() > 1 {
        let host_wn_ip = &local_ips[0];
        for ip in &local_ips[1..] {
            if !ip.is_empty() && ip != host_wn_ip {
                subnet_routes.insert(ip.clone(), host_wn_ip.clone());
            }
        }
    }

    // 2. subnet_routes now has: local container routes + remote container routes

    // 3. Build the safe replacement.
    //    Collect which host IPs we have AUTHORITATIVE fresh data for:
    //    - Our own local wolfnet IP (always authoritative — we just scanned)
    //    - Gateway IPs from subnet_routes (only populated when
    //      wolfnet_ips.len() > 1, i.e. the peer reported containers)
    //    A host NOT in this set keeps its existing routes — they came
    //    from either a previous poll or a push, both are valid.
    let mut fresh_hosts: std::collections::HashSet<String> = std::collections::HashSet::new();
    if !local_wn_ip.is_empty() {
        fresh_hosts.insert(local_wn_ip);
    }
    for v in subnet_routes.values() {
        fresh_hosts.insert(v.clone());
    }

    // Start from existing routes, remove entries for hosts we have fresh data for
    // Also remove any entries with invalid (non-IP) gateway values (cleanup from past bug)
    let existing = crate::containers::WOLFNET_ROUTES.lock().unwrap().clone();
    let mut final_routes = std::collections::HashMap::new();
    for (k, v) in &existing {
        // Skip entries with invalid gateway values (e.g. "remote" from a past bug)
        if v.split('.').count() != 4 || v.parse::<std::net::Ipv4Addr>().is_err() {
            continue;
        }
        if !fresh_hosts.contains(v) {
            // Keep routes for hosts we COULDN'T poll or that returned
            // no container data — stale/push-delivered but better than nothing
            final_routes.insert(k.clone(), v.clone());
        }
    }
    // Add all fresh routes (overwrites stale entries for the same container IP)
    final_routes.extend(subnet_routes);

    // Replace atomically
    crate::containers::replace_wolfnet_routes(final_routes);


    // After polling, detect state changes and send emails
    // Only the node with the lowest ID sends emails to avoid duplicates
    if let Some(ref ai) = ai_agent {
        let config = ai.config.lock().unwrap().clone();
        if config.email_enabled && !config.email_to.is_empty() {
            let current_nodes = cluster.get_all_nodes();
            // Determine if we are the primary alerter (lowest self_id among online nodes)
            let self_id = &cluster.self_id;
            let is_primary = current_nodes.iter()
                .filter(|n| n.online)
                .map(|n| &n.id)
                .min()
                .map(|min_id| min_id == self_id)
                .unwrap_or(true); // If no nodes online, we're it

            if is_primary {
                // Load alerting config for webhook channels
                let alert_config = crate::alerting::AlertConfig::load();

                for node in current_nodes.iter().filter(|n| !n.is_self) {
                    let (was_online, hostname) = previous_states.get(&node.id)
                        .cloned()
                        .unwrap_or((false, node.hostname.clone()));

                    let display_name = if hostname.is_empty() { &node.address } else { &hostname };

                    // Node offline / restored are Lifecycle events: visible
                    // on the dashboard, so Simple mode suppresses the push.
                    // Operators who want every flap by email switch to Verbose.
                    let lifecycle_allowed = crate::alerting::should_send(
                        &alert_config,
                        crate::alerting::AlertCategory::Lifecycle,
                    );
                    if was_online && !node.online {
                        // Node went OFFLINE
                        let raw_subject = format!("[WolfStack ALERT] {} has gone offline", display_name);
                        let raw_body = format!(
                            "⚠️ Node Offline Alert\n\n\
                             Hostname: {}\n\
                             Address: {}:{}\n\
                             Status: OFFLINE\n\
                             Time: {}\n\n\
                             This node is no longer responding to cluster health checks.\n\
                             Please investigate immediately.",
                            display_name, node.address, node.port,
                            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                        );
                        // Decorate with the observer node's cluster + host so
                        // multi-cluster operators see WHICH primary detected
                        // the failure. The failing peer is named in the
                        // (un-prefixed) title text and the body's Hostname:
                        // line — between the two, recipients have both
                        // observer and subject context.
                        let (subject, body) = crate::alerting::decorate_local(&raw_subject, &raw_body);
                        if lifecycle_allowed
                            && let Err(e) = crate::ai::send_alert_email(&config, &subject, &body) {
                                warn!("Failed to send node-offline email for {}: {}", display_name, e);
                            }
                        // Send to webhook channels
                        if alert_config.enabled && alert_config.alert_node_offline {
                            let ac = alert_config.clone();
                            let subj = subject.clone();
                            let b = body.clone();
                            tokio::spawn(async move {
                                crate::alerting::send_alert(
                                    &ac,
                                    crate::alerting::AlertCategory::Lifecycle,
                                    &subj, &b,
                                ).await;
                            });
                        }
                    } else if !was_online && node.online {
                        // Node came back ONLINE
                        let raw_subject = format!("[WolfStack OK] {} has been restored", display_name);
                        let raw_body = format!(
                            "✅ Node Restored\n\n\
                             Hostname: {}\n\
                             Address: {}:{}\n\
                             Status: ONLINE\n\
                             Time: {}\n\n\
                             This node is responding to cluster health checks again.",
                            display_name, node.address, node.port,
                            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                        );
                        // Decorate with observer cluster + host — same shape as
                        // every other WolfStack alert.
                        let (subject, body) = crate::alerting::decorate_local(&raw_subject, &raw_body);
                        if lifecycle_allowed
                            && let Err(e) = crate::ai::send_alert_email(&config, &subject, &body) {
                                warn!("Failed to send node-restored email for {}: {}", display_name, e);
                            }
                        // Send to webhook channels
                        if alert_config.enabled && alert_config.alert_node_restored {
                            let ac = alert_config.clone();
                            let subj = subject.clone();
                            let b = body.clone();
                            tokio::spawn(async move {
                                crate::alerting::send_alert(
                                    &ac,
                                    crate::alerting::AlertCategory::Lifecycle,
                                    &subj, &b,
                                ).await;
                            });
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod role_tests {
    use super::*;

    #[test]
    fn role_serde_is_snake_case_and_stable() {
        assert_eq!(serde_json::to_string(&NodeRole::MailRelay).unwrap(), "\"mail_relay\"");
        assert_eq!(serde_json::to_string(&NodeRole::Dns).unwrap(), "\"dns\"");
        let parsed: NodeRole = serde_json::from_str("\"host\"").unwrap();
        assert_eq!(parsed, NodeRole::Host);
    }

    #[test]
    fn unknown_role_token_decodes_to_unknown_not_error() {
        // A newer peer gossips a role this build predates — the whole node
        // must still decode (serde(other)), not reject the payload.
        let parsed: NodeRole = serde_json::from_str("\"quantum_tier\"").unwrap();
        assert_eq!(parsed, NodeRole::Unknown);
        // And a node carrying it round-trips as a Vec.
        let roles: Vec<NodeRole> = serde_json::from_str("[\"dns\",\"quantum_tier\"]").unwrap();
        assert_eq!(roles, vec![NodeRole::Dns, NodeRole::Unknown]);
    }

    #[test]
    fn assignable_excludes_unknown() {
        assert!(!NodeRole::assignable().contains(&NodeRole::Unknown));
        assert!(NodeRole::assignable().contains(&NodeRole::Dns));
        // Every assignable role has a non-empty label.
        for r in NodeRole::assignable() {
            assert!(!r.label().is_empty());
        }
    }

    #[test]
    fn empty_roles_default_for_backward_compat() {
        // A node from before roles existed (field absent) deserializes with
        // an empty roles list = general-purpose node.
        #[derive(serde::Deserialize)]
        struct OldNodeShape {
            #[serde(default)]
            roles: Vec<NodeRole>,
        }
        let old: OldNodeShape = serde_json::from_str("{}").unwrap();
        assert!(old.roles.is_empty());
    }
}

#[cfg(test)]
mod convergence_tests {
    use super::*;

    #[test]
    fn cluster_names_match_case_insensitively() {
        // Same cluster regardless of case — this is what stops "minio" and
        // "Minio" from splitting into two groups / flip-flopping via gossip.
        assert!(cluster_eq(Some("minio"), Some("Minio")));
        assert!(cluster_eq(Some("Minio"), Some("MINIO")));
        assert!(cluster_eq(None, None));
        // Genuinely different names are still different (a real rename).
        assert!(!cluster_eq(Some("Minio"), Some("Dodgy")));
        assert!(!cluster_eq(Some("Minio"), None));
        assert!(!cluster_eq(None, Some("Minio")));
    }

    #[test]
    fn identity_intent_serde_defaults_golden_rule() {
        // An older/empty file must deserialize (no panic, all fields default).
        let i: IdentityIntent = serde_json::from_str("{}").unwrap();
        assert!(i.display_name.is_none() && i.cluster_name.is_none() && i.ts == 0);
        // A whole map keyed by node id round-trips.
        let parsed: std::collections::HashMap<String, IdentityIntent> =
            serde_json::from_str(r#"{"node-1":{"display_name":"web","ts":5}}"#).unwrap();
        assert_eq!(parsed["node-1"].display_name.as_deref(), Some("web"));
        assert!(parsed["node-1"].cluster_name.is_none());
    }

    #[test]
    fn identity_intent_clears_only_on_confirmed_delivery() {
        // Reachable owner accepted every field → the value is persisted on the
        // owner (the receivers write before answering 2xx), so clear.
        assert!(intent_may_clear(true, true));

        // Reachable but the push failed → keep it and retry next sweep.
        assert!(!intent_may_clear(true, false));

        // Unreachable → keep, so the edit applies on reconnect. This is the
        // case the pre-v25.5.5 mirror-based rule got wrong: our own nodes.json
        // record already held the intended value (the edit handler writes it
        // before recording the intent), so it "confirmed" and cleared an intent
        // the owner had never seen. The retroactive cluster-name sweep hid the
        // resulting edit-loss by re-pushing every 30 minutes; that sweep is
        // gone, so this rule now has to be right on its own.
        assert!(!intent_may_clear(false, false));
        assert!(!intent_may_clear(false, true));
    }

    #[test]
    fn unusable_addresses_are_rejected() {
        // The wildcard bind address a node advertises for itself must never be
        // treated as reachable — this was why the hub "main" vanished from
        // every other node.
        assert!(!is_usable_addr("0.0.0.0"));
        assert!(!is_usable_addr("0.0.0.0:8553"));
        assert!(!is_usable_addr("::"));
        assert!(!is_usable_addr("[::]"));
        assert!(!is_usable_addr("[::]:8553"));
        assert!(!is_usable_addr(""));
        assert!(!is_usable_addr("   "));
        // IPv6 link-local needs a zone id to be reachable — it must never
        // be stored as a peer's address, in any spelling.
        assert!(!is_usable_addr("fe80::1"));
        assert!(!is_usable_addr("[fe80::1]"));
        assert!(!is_usable_addr("fe80::1%eth0"));
        assert!(!is_usable_addr("FE80::dead:beef"));
        assert!(!is_usable_addr("febf::1")); // top of fe80::/10
        // IPv4-mapped forms are dual-stack socket artifacts, never a
        // dialable peer address — learn sites canonicalize to plain v4
        // before storage; raw mapped strings must be refused.
        assert!(!is_usable_addr("::ffff:192.168.1.5"));
        assert!(!is_usable_addr("[::ffff:10.0.0.7]"));
    }

    #[test]
    fn real_addresses_are_usable() {
        assert!(is_usable_addr("192.168.5.10"));
        assert!(is_usable_addr("10.2.0.153"));
        assert!(is_usable_addr("nas.lan"));
        // Routable IPv6 — ULA and global — is a real address.
        assert!(is_usable_addr("fd00:10:100::7"));
        assert!(is_usable_addr("2001:db8::1"));
        assert!(is_usable_addr("fec0::1")); // deprecated site-local is NOT fe80::/10
        // Hostname that merely starts with "fe8" must not be rejected.
        assert!(is_usable_addr("fe8-server.lan"));
    }

    #[test]
    fn private_guard_allows_lan_and_hostnames_but_not_public() {
        assert!(is_private_address("192.168.5.10"));
        assert!(is_private_address("10.0.0.1"));
        assert!(is_private_address("127.0.0.1"));
        assert!(is_private_address("nas.lan"));       // hostname → treated local
        assert!(!is_private_address("8.8.8.8"));      // public → not auto-added
        assert!(!is_private_address("0.0.0.0"));       // wildcard → not private
        // IPv6: loopback + ULA (fc00::/7) + link-local are private/local;
        // global unicast is public and must not be gossip-auto-added.
        assert!(is_private_address("::1"));
        assert!(is_private_address("fd00:10:100::7")); // ULA fd00::/8
        assert!(is_private_address("fc00::1"));        // ULA fc00::/8
        assert!(is_private_address("fe80::1"));        // link-local
        assert!(!is_private_address("2001:db8::1"));   // global → not private
        assert!(!is_private_address("2606:4700::1111")); // global → not private
        // Mapped v4 is judged by its REAL v4 identity (dual-stack [::]
        // listeners report v4 peers this way).
        assert!(is_private_address("::ffff:192.168.1.5"));
        assert!(!is_private_address("::ffff:8.8.8.8"));
    }

    #[test]
    fn exported_nodes_bundle_deserializes_as_array() {
        // nodes.json (and the config-export "nodes" key) is a JSON ARRAY of
        // Node — NOT a map. config_import::import_nodes used to parse it as a
        // map, so every restore failed with "invalid type: sequence, expected
        // a map" and the operator's whole fleet+cluster grouping couldn't be
        // restored. This shape matches a real v24.0.2 export (only `site` is
        // absent — it post-dates the export and has #[serde(default)]).
        let array_json = r#"[
            {"id":"node-233a2011","hostname":"wolf3","address":"wolf3.wolf.uk.com","port":8553,
             "last_seen":0,"metrics":null,"components":[],"online":true,"is_self":false,
             "node_type":"wolfstack","self_id":"ws-33548073","cluster_name":"WolfStack-Shannon"},
            {"id":"node-641fb254","hostname":"sophie","address":"sophie.wolfterritories.org","port":8553,
             "last_seen":0,"metrics":null,"components":[],"online":false,"is_self":false,
             "node_type":"wolfstack","self_id":"ws-286f90be","cluster_name":"Minio"}
        ]"#;
        let nodes: Vec<Node> = serde_json::from_str(array_json)
            .expect("exported nodes array must deserialize as Vec<Node>");
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].cluster_name.as_deref(), Some("WolfStack-Shannon"));
        assert_eq!(nodes[1].cluster_name.as_deref(), Some("Minio"));

        // The legacy/hand-edited object/map form must still parse too (the
        // importer accepts both).
        let map_json = r#"{"node-233a2011":{"id":"node-233a2011","hostname":"wolf3",
            "address":"wolf3.wolf.uk.com","port":8553,"last_seen":0,"metrics":null,
            "components":[],"online":true,"is_self":false,"node_type":"wolfstack",
            "cluster_name":"WolfStack-Shannon"}}"#;
        let map: std::collections::HashMap<String, Node> = serde_json::from_str(map_json)
            .expect("legacy nodes map must still deserialize");
        assert_eq!(map.len(), 1);
    }

    // Build a Node with only the fields the prune logic reads; the rest take
    // their serde defaults.
    fn mk(
        id: &str,
        addr: &str,
        self_id: Option<&str>,
        cluster: Option<&str>,
        is_self: bool,
        verified: bool,
        online: bool,
    ) -> Node {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "hostname": id,
            "address": addr,
            "port": 8553,
            "last_seen": 0,
            "metrics": null,
            "components": [],
            "online": online,
            "is_self": is_self,
            "node_type": "wolfstack",
            "self_id": self_id,
            "cluster_name": cluster,
            "join_verified": verified,
        }))
        .unwrap()
    }

    #[test]
    fn gossip_weak_ip_match_must_not_adopt_identity() {
        // A peer gossips back ITS view of us: addressed by the IP it reaches us
        // on (our WireGuard endpoint) and tagged with THAT peer's cluster.
        // The IP is genuinely ours, so this must still count as "self" so we do
        // not admit ourselves as a foreign node — but it must NOT be strong,
        // because adopting from it silently moves us into the peer's cluster.
        // Regression: 2026-07-28, adding the Wolf-Grid-Regions region servers
        // repeatedly dragged wolfstack-1 out of intelligentwolf.
        let mut ips = std::collections::HashSet::new();
        ips.insert("10.203.0.1".to_string());

        let (is_self, strong) = super::gossip_identity_match(
            "node-remote-view", None, "10.203.0.1", "ws-me", &ips);
        assert!(is_self, "our own IP must still be recognised as self");
        assert!(!strong, "an IP-only match must never be authoritative for identity");

        // Strong matches remain authoritative, by either id field.
        let (a, sa) = super::gossip_identity_match("ws-me", None, "", "ws-me", &ips);
        assert!(a && sa, "matching id is a strong match");
        let (b, sb) = super::gossip_identity_match(
            "node-x", Some("ws-me"), "", "ws-me", &ips);
        assert!(b && sb, "matching self_id is a strong match");

        // A genuinely foreign node is neither.
        let (c, sc) = super::gossip_identity_match(
            "node-y", Some("ws-other"), "10.203.0.12", "ws-me", &ips);
        assert!(!c && !sc, "a foreign node must not match at all");
    }

    #[test]
    fn prune_keeps_peers_from_other_clusters() {
        // Control-plane replication shows the WHOLE fleet across clusters —
        // `cluster_name` is a display grouping, never a membership boundary.
        // Peers in OTHER named clusters (and untagged peers) must be KEPT; the
        // v24.29.1 regression pruned them and deleted ~5 federated clusters
        // down to a single node.
        let nodes = vec![
            mk("self", "10.0.0.1", None, Some("HomeLab"), true, true, true),
            mk("a", "10.0.0.2", Some("ws-a"), Some("HomeLab"), false, true, true),
            mk("b", "10.0.0.3", Some("ws-b"), Some("Production"), false, true, true),
            mk("c", "10.0.0.4", Some("ws-c"), None, false, true, true),
        ];
        let remove = ClusterState::plan_prune(nodes);
        assert!(remove.is_empty(), "no peer may be pruned for cluster membership");
    }

    #[test]
    fn prune_collapses_multihomed_duplicates_by_self_id() {
        // The storm: one physical node seen under LAN, WolfNet, and source-IP
        // address variants — same self_id. Keep the best record, drop the rest.
        let nodes = vec![
            mk("self", "10.0.0.1", None, Some("HomeLab"), true, true, true),
            mk("a-lan", "192.168.1.5", Some("ws-a"), Some("HomeLab"), false, true, true),
            mk("a-wg", "10.10.10.5", Some("ws-a"), Some("HomeLab"), false, false, false),
            mk("a-src", "172.16.0.5", Some("ws-a"), Some("HomeLab"), false, false, false),
        ];
        let remove = ClusterState::plan_prune(nodes);
        assert_eq!(remove.len(), 2);
        assert!(!remove.contains(&"a-lan".to_string())); // verified+online keeper survives
    }

    #[test]
    fn prune_collapses_duplicates_by_address_when_no_self_id() {
        let nodes = vec![
            mk("self", "10.0.0.1", None, Some("HomeLab"), true, true, true),
            mk("x1", "192.168.1.9", None, Some("HomeLab"), false, true, true),
            mk("x2", "192.168.1.9", None, Some("HomeLab"), false, false, false),
        ];
        let remove = ClusterState::plan_prune(nodes);
        assert_eq!(remove.len(), 1);
        assert!(remove.contains(&"x2".to_string()));
    }
}

#[cfg(test)]
mod fleet_rename_tests {
    use super::*;

    #[test]
    fn rename_member_match_is_case_insensitive() {
        assert!(cluster_rename_member_matches(Some("minio"), "Minio"));
        assert!(cluster_rename_member_matches(Some("Minio"), "Minio"));
        assert!(!cluster_rename_member_matches(Some("Prod"), "Minio"));
    }

    #[test]
    fn parse_local_ipv4_collects_every_nic_skips_lo_and_ipv6() {
        // Multi-homed: LAN + WolfNet (10.x) + a storage NIC + IPv6 + loopback.
        let json = br#"[
            {"ifname":"lo","addr_info":[
                {"family":"inet","local":"127.0.0.1","prefixlen":8},
                {"family":"inet6","local":"::1","prefixlen":128}]},
            {"ifname":"eth0","addr_info":[
                {"family":"inet","local":"192.168.1.50","prefixlen":24},
                {"family":"inet6","local":"fe80::1","prefixlen":64}]},
            {"ifname":"wolfnet0","addr_info":[
                {"family":"inet","local":"10.100.10.5","prefixlen":16}]},
            {"ifname":"eth1.20","addr_info":[
                {"family":"inet","local":"10.20.0.5","prefixlen":24}]}
        ]"#;
        let set = parse_local_ipv4(json);
        // Every NIC's IPv4 is captured — these are the addresses a multi-homed
        // self entry could appear under, and must be recognised as "us".
        assert!(set.contains("192.168.1.50"));
        assert!(set.contains("10.100.10.5"));
        assert!(set.contains("10.20.0.5"));
        assert_eq!(set.len(), 3, "exactly the 3 non-loopback IPv4 addresses");
        // Loopback and IPv6 are excluded.
        assert!(!set.contains("127.0.0.1"));
        assert!(!set.contains("::1"));
        assert!(!set.contains("fe80::1"));
        // Garbage input doesn't panic; yields an empty set.
        assert!(parse_local_ipv4(b"not json").is_empty());
    }

    #[test]
    fn renaming_default_group_takes_unassigned_nodes_along() {
        // A node with no cluster displays under "WolfStack" in every UI, so
        // renaming that group must include it — otherwise the group splits.
        assert!(cluster_rename_member_matches(None, "WolfStack"));
        assert!(cluster_rename_member_matches(None, "wolfstack"));
        // …but renaming any OTHER cluster must not grab unassigned nodes.
        assert!(!cluster_rename_member_matches(None, "Minio"));
    }
}

#[cfg(test)]
mod lock_poison_tests {
    use super::*;
    use std::sync::Arc;

    /// Build a ClusterState without touching disk. `ClusterState::new`
    /// loads and writes `/etc/wolfstack` state, which a unit test must
    /// not do; the struct literal is available here because the test
    /// module sits inside the defining module.
    fn bare_state() -> ClusterState {
        ClusterState {
            nodes: RwLock::new(HashMap::new()),
            self_id: "ws-test".to_string(),
            self_address: "127.0.0.1".to_string(),
            port: 8553,
            deleted_ids: RwLock::new(HashSet::new()),
        }
    }

    /// Build a `Node` through its own `Deserialize` impl rather than
    /// deriving `Default` on the production struct purely for tests.
    /// Only the fields without a serde default need to be present.
    fn test_node(id: &str) -> Node {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "hostname": id,
            "address": "127.0.0.1",
            "port": 8553,
            "last_seen": 0,
            "metrics": null,
            "components": [],
            "online": false,
            "is_self": false,
        }))
        .expect("test node should deserialise")
    }

    /// The regression this guards: a panic while holding the membership
    /// write lock used to poison it for the life of the process, so every
    /// later `.read().unwrap()` panicked and actix turned each one into a
    /// 500. Fleet Security stayed broken until WolfStack was restarted.
    #[test]
    fn membership_survives_a_poisoned_lock() {
        let state = Arc::new(bare_state());
        state.nodes_write().insert(
            "peer-1".to_string(),
            test_node("peer-1"),
        );

        // Poison the lock exactly the way a panicking background task would.
        let poisoner = Arc::clone(&state);
        let joined = std::thread::spawn(move || {
            let _guard = poisoner.nodes_write();
            panic!("simulated panic while holding the membership write lock");
        })
        .join();
        assert!(joined.is_err(), "the spawned thread was supposed to panic");
        assert!(state.nodes.is_poisoned(), "lock should now be poisoned");

        // Both accessors must still work, and the data must still be there.
        assert_eq!(state.nodes_read().len(), 1);
        state.nodes_write().insert(
            "peer-2".to_string(),
            test_node("peer-2"),
        );
        assert_eq!(state.nodes_read().len(), 2);
    }

    /// Same contract for the tombstone set: a poisoned set must not stop
    /// gossip from honouring deletions.
    #[test]
    fn tombstones_survive_a_poisoned_lock() {
        let state = Arc::new(bare_state());
        let poisoner = Arc::clone(&state);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.deleted_write();
            panic!("simulated panic while holding the tombstone write lock");
        })
        .join();
        assert!(state.deleted_ids.is_poisoned());

        state.deleted_write().insert("gone-1".to_string());
        assert!(state.deleted_read().contains("gone-1"));
    }

    /// `now_unix` replaced seven `duration_since(UNIX_EPOCH).unwrap()`
    /// calls, several of them taken while holding the membership write
    /// lock. It must never panic, and must still return a real timestamp.
    #[test]
    fn now_unix_is_sane_and_never_panics() {
        // 1_700_000_000 = 2023-11-14. Any correct clock is past it.
        assert!(now_unix() > 1_700_000_000);
    }
}

#[cfg(test)]
mod persistence_change_tests {
    use super::*;

    /// Same technique as `lock_poison_tests::test_node`: build through
    /// Deserialize so the production struct never needs a test-only Default.
    fn test_node(id: &str) -> Node {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "hostname": id,
            "address": "127.0.0.1",
            "port": 8553,
            "last_seen": 0,
            "metrics": null,
            "components": [],
            "online": false,
            "is_self": false,
        }))
        .expect("test node should deserialise")
    }

    /// The nc-cluster regression (2026-08-15): per-poll churn must NOT
    /// trigger a disk write, or every WolfStack node would rewrite
    /// nodes.json every 10 seconds forever.
    #[test]
    fn per_poll_churn_does_not_count_as_a_persistent_change() {
        let old = test_node("pve1");
        let mut new = test_node("pve1");
        new.last_seen = 9_999_999;
        new.online = true;
        new.docker_count = 42;
        new.lxc_count = 7;
        new.vm_count = 3;
        new.compose_count = 2;
        assert!(!ClusterState::persistent_peer_fields_changed(&old, &new));
    }

    /// …but a migrated Docker bridge (workload_subnets change) MUST — that
    /// staleness is exactly what fed the predictive rule and WolfRouter
    /// auto-apply obsolete 172.17.0.0/16 subnets for hours.
    #[test]
    fn changed_workload_subnets_must_persist() {
        let mut old = test_node("pve1");
        old.workload_subnets = vec!["172.17.0.0/16".into()];
        let mut new = test_node("pve1");
        new.workload_subnets = vec!["172.23.0.0/24".into()];
        assert!(ClusterState::persistent_peer_fields_changed(&old, &new));
    }

    /// The other persisted self-reported fields each count too.
    #[test]
    fn identity_field_changes_persist() {
        let old = test_node("pve1");

        let mut renamed = test_node("pve1");
        renamed.hostname = "pve1-new".into();
        assert!(ClusterState::persistent_peer_fields_changed(&old, &renamed));

        let mut self_id = test_node("pve1");
        self_id.self_id = Some("abc-123".into());
        assert!(ClusterState::persistent_peer_fields_changed(&old, &self_id));

        let mut sited = test_node("pve1");
        sited.site = Some("rack-2".into());
        assert!(ClusterState::persistent_peer_fields_changed(&old, &sited));

        let mut roled = test_node("pve1");
        roled.roles = vec![NodeRole::Dns];
        assert!(ClusterState::persistent_peer_fields_changed(&old, &roled));

        let mut pub_ip = test_node("pve1");
        pub_ip.public_ip = Some("203.0.113.9".into());
        assert!(ClusterState::persistent_peer_fields_changed(&old, &pub_ip));
    }
}
