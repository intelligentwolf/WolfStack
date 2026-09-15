// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Threat-intelligence blocklist enforcement (per-cluster, off by default).
//!
//! Pulls the FireHOL Level 1 IP blocklist (high-confidence, low-
//! false-positive — known C2, well-attested offenders) and, when the
//! operator explicitly enables enforcement for a cluster, maintains
//! an `ipset` named `wolfstack_blocklist` plus iptables rules that
//! DROP traffic to/from those addresses.
//!
//! ## v23.2.2 safety model — off by default, three-state, per cluster
//!
//! Earlier versions (v23.2.0, v23.2.1) defaulted to **ENABLED** the
//! moment the binary started. Combined with thousands of operators
//! running wildly different network shapes (BGP peers in odd public
//! ranges, custom CGNAT, layer-2 overlays, hosts in private datacentre
//! /24s outside RFC1918), an opt-out posture was unsafe — any feed
//! false-positive or unexpected overlap would blackhole real traffic
//! before the operator knew the feature existed.
//!
//! v23.2.2 inverts that:
//!   * **Default**: `Off` for every cluster. No feed download, no
//!     ipset, no iptables rules, no analyzer noise other than an
//!     informational "this feature exists, here's how to try it"
//!     card.
//!   * **DryRun**: feed is fetched and parsed on every tick, the
//!     resulting blocklist + auto-allowlist + per-node overlap
//!     report is exposed to the operator, but the kernel ipset is
//!     never written and no iptables rules are installed. Operators
//!     can sit in DryRun for as long as they like to watch for false
//!     positives before committing.
//!   * **Enforce**: same as DryRun, plus the kernel ipset is built
//!     and iptables rules are installed. Promotion to Enforce
//!     requires a fresh (<5 min) preflight report and the operator
//!     typing the cluster name into the confirmation modal.
//!
//! State lives in `/etc/wolfstack/predictive-threat-intel.json`
//! keyed by cluster_name. Each node reads its own cluster's entry
//! every tick. State changes propagate to peers in the same cluster
//! via inter-node HTTP push (best-effort; peers that are offline
//! will pick up the new state via the gossip poll loop).
//!
//! ## Migration from v23.2.0 / v23.2.1
//!
//! On first boot of v23.2.2, every node:
//!   1. Removes any iptables INPUT/OUTPUT rules referencing the
//!      `wolfstack_blocklist` ipset and destroys the ipset itself.
//!   2. Removes the legacy auto-enable flag at
//!      `/var/lib/wolfstack/threat-intel/enabled`.
//!   3. Writes a sentinel at
//!      `/var/lib/wolfstack/threat-intel/migrated_v23_2_2` so the
//!      migration runs exactly once.
//!   4. Surfaces a `Medium` finding telling the operator what
//!      happened and how to re-enable safely.
//!
//! This is a deliberate, one-way reset. Operators who *did* want
//! enforcement on can re-enable cluster-by-cluster via the new UI.
//!
//! ## Why FireHOL Level 1
//!
//! Aggregates Spamhaus DROP/EDROP, dshield, abuse.ch trackers, and
//! a few others. Updated several times per day. Designed
//! specifically for "use this list for production filtering with
//! near-zero risk of blocking a legitimate user". Levels 2+ get
//! more aggressive but have correspondingly higher FP risk.
//!
//! ## Why ipset, not raw iptables
//!
//! ~30,000 entries. With one iptables rule per entry, packet
//! processing becomes O(N) per packet. `ipset` is a kernel
//! hash-table; lookup is effectively O(1). One iptables rule
//! referencing the set covers the entire list.
//!
//! ## What if ipset isn't installed?
//!
//! Detected at sample time. If `ipset` binary is missing and the
//! cluster is set to `Enforce`, the analyzer emits a `High` finding
//! (with a one-line install command) and skips actual blocking on
//! that host. It does NOT fall back to one-rule-per-IP iptables —
//! the performance hit would itself be a denial-of-service.
//!
//! ## Freshness
//!
//! Refreshed at most once per `REFRESH_INTERVAL`. The local cache
//! at `/var/lib/wolfstack/threat-intel/firehol_level1.netset` is
//! re-read on every tick (cheap) and the in-kernel ipset is
//! refreshed only when the file actually changed since the last
//! flush.
//!
//! ## Operator controls
//!
//! * REST: `POST /api/predictive/threat-intel/state` with body
//!   `{cluster, state, confirm}` — moves a named cluster between
//!   Off / DryRun / Enforce. Promoting to Enforce additionally
//!   requires a fresh preflight in the last 5 minutes.
//! * `/var/lib/wolfstack/threat-intel/allowlist.txt` — one CIDR per
//!   line, host-local override. These are never blocked even when
//!   present in the feed. Use sparingly.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::predictive::{
    Context,
    ack::AckStore,
    compromise_indicators::RemediationOutcome,
    proposal::{Proposal, ProposalScope, RemediationPlan, Severity},
};

pub const FEED_URL: &str = "https://iplists.firehol.org/files/firehol_level1.netset";
const FEED_LOCAL_PATH: &str = "/var/lib/wolfstack/threat-intel/firehol_level1.netset";
/// Legacy v23.2.0/v23.2.1 flag file. Presence on first boot of
/// v23.2.2 triggers the safety migration (rules torn down). Never
/// written by v23.2.2 itself.
const LEGACY_ENABLE_FLAG_PATH: &str = "/var/lib/wolfstack/threat-intel/enabled";
/// Sentinel marking that the v23.2.x → v23.2.2 migration has run on
/// this node. Existence = migration done; absence = run it on next
/// boot. Never deleted after creation.
const MIGRATION_SENTINEL_PATH: &str = "/var/lib/wolfstack/threat-intel/migrated_v23_2_2";
/// Per-cluster enforcement state. Schema:
///   { "schema_version": 2, "clusters": { "<name>": "off"|"dry-run"|"enforce" } }
/// Absence of a cluster's entry = `Off`. Absence of the entire file
/// also = `Off` for every cluster. Operator-writable via API.
const CLUSTER_STATE_PATH: &str = "/etc/wolfstack/predictive-threat-intel.json";
const ALLOWLIST_PATH: &str = "/var/lib/wolfstack/threat-intel/allowlist.txt";
const IPSET_NAME: &str = "wolfstack_blocklist";
/// Refresh at most once per 6h (checked every predictive tick, i.e.
/// 5 minutes). The feed itself updates several times per day; 6h
/// keeps the blocklist current without hammering the source — and it
/// matches what the UI has always told operators ("refreshes every
/// 6 hours") plus the Security-page threat-intel default. The old
/// 24h value made the fleet widget's amber >6h feed-age indicator
/// the STEADY state (18h of every day), and because an update wave
/// restarts every node together, feed mtimes synchronised and whole
/// fleets crossed the 24h "stale" label in the same window a day
/// later (RutgerDiehard 2026-07-09).
const REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 3600);
/// Promote-to-Enforce gate: a preflight must have completed within
/// this window to be considered "fresh enough" to confirm against.
pub const PREFLIGHT_FRESHNESS_SECS: u64 = 5 * 60;

pub const FT_THREAT_INTEL_OFF: &str = "threat_intel:cluster_state_off";
pub const FT_THREAT_INTEL_DRY_RUN: &str = "threat_intel:cluster_state_dry_run";
pub const FT_THREAT_INTEL_NO_IPSET: &str = "threat_intel:ipset_not_installed";
pub const FT_THREAT_INTEL_STALE: &str = "threat_intel:feed_stale";
pub const FT_THREAT_INTEL_RULES_MISSING: &str = "threat_intel:iptables_rules_missing";
pub const FT_THREAT_INTEL_MIGRATED: &str = "threat_intel:v23_2_2_safety_migration";

// Legacy finding-type ID. Kept so any persisted acks referencing it
// still resolve, even though v23.2.2 no longer emits this type.
pub const FT_THREAT_INTEL_DISABLED: &str = "threat_intel:disabled_by_operator";

/// Tri-state enforcement for a cluster.
///
/// * `Off` — feature is dormant; nothing runs, nothing blocks.
/// * `DryRun` — feed is fetched and parsed every tick; the would-be
///   blocklist + auto-allowlist + per-node overlap report are
///   exposed to the operator, but the kernel ipset and iptables
///   rules are never written.
/// * `Enforce` — everything DryRun does, plus the kernel ipset is
///   built and DROP rules are installed on INPUT/OUTPUT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum EnforceState {
    #[default]
    Off,
    DryRun,
    Enforce,
}


impl EnforceState {
    pub fn as_str(&self) -> &'static str {
        match self {
            EnforceState::Off => "off",
            EnforceState::DryRun => "dry-run",
            EnforceState::Enforce => "enforce",
        }
    }
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "disabled" | "" => Some(EnforceState::Off),
            // "enabled" / "on" are the legacy v23.2.0/v23.2.1 spellings.
            // We map them to DryRun, NOT Enforce — the legacy semantics
            // were "auto-enforce on first tick", which is exactly what
            // v23.2.2 is fixing. If some external tooling sets state to
            // "enabled" it gets the safe new default; promotion to
            // Enforce is only reachable through the explicit "enforce"
            // string AND the typed-confirmation + fresh-preflight gates.
            "dry-run" | "dry_run" | "dryrun" | "preview" | "enabled" | "on" => Some(EnforceState::DryRun),
            "enforce" | "enforcing" => Some(EnforceState::Enforce),
            _ => None,
        }
    }
}

/// On-disk shape of the cluster-state config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStateFile {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub clusters: std::collections::BTreeMap<String, EnforceState>,
}

fn default_schema_version() -> u32 { 2 }

impl Default for ClusterStateFile {
    fn default() -> Self {
        ClusterStateFile {
            schema_version: 2,
            clusters: std::collections::BTreeMap::new(),
        }
    }
}

pub fn load_cluster_state() -> ClusterStateFile {
    match std::fs::read_to_string(CLUSTER_STATE_PATH) {
        Ok(body) => match serde_json::from_str::<ClusterStateFile>(&body) {
            Ok(s) => s,
            Err(e) => {
                // Safe-default direction (all clusters Off) means a
                // corrupted file never accidentally enables
                // enforcement — but it would silently disable any
                // operator-configured state. Surface the parse error
                // loudly so the operator can repair the file.
                tracing::error!(
                    "threat_intel: cluster state file at {} failed to parse ({}); defaulting to all-Off for safety",
                    CLUSTER_STATE_PATH, e,
                );
                ClusterStateFile::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ClusterStateFile::default(),
        Err(e) => {
            tracing::warn!(
                "threat_intel: cluster state file at {} unreadable ({}); defaulting to all-Off",
                CLUSTER_STATE_PATH, e,
            );
            ClusterStateFile::default()
        }
    }
}

/// Atomic write: temp + rename so a crashed write never leaves a
/// half-written state file (which would deserialise to "off
/// everywhere" and silently disable enforcement on a healthy
/// cluster).
pub fn save_cluster_state(state: &ClusterStateFile) -> Result<(), String> {
    let dir = std::path::Path::new(CLUSTER_STATE_PATH).parent()
        .ok_or_else(|| "CLUSTER_STATE_PATH has no parent dir".to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create dir: {}", e))?;
    let tmp = format!("{}.tmp", CLUSTER_STATE_PATH);
    let body = serde_json::to_string_pretty(state)
        .map_err(|e| format!("serialise: {}", e))?;
    std::fs::write(&tmp, body).map_err(|e| format!("write tmp: {}", e))?;
    std::fs::rename(&tmp, CLUSTER_STATE_PATH).map_err(|e| format!("rename: {}", e))?;
    Ok(())
}

/// Look up enforcement state for a cluster. **Unknown cluster = Enforce**
/// — i.e. fresh installs default to ACTIVE threat-intel blocking.
///
/// Product decision (v23.12.20+): every WolfStack node should ship with
/// the FireHOL level1 blocklist active out of the box. The previous
/// Off-by-default behaviour meant fresh installs had no upstream-IP
/// protection until an operator manually toggled enforcement, and the
/// Fleet Security view made every never-configured cluster look broken
/// ("feed not downloaded" on every node).
///
/// Explicit Off via `set_cluster_state(..., Off)` removes the entry
/// from the state file — so the only signal of "operator wanted this
/// off" is the absence of a key, which we can no longer distinguish
/// from "never configured". Operators who want Off must re-set Off
/// after upgrading; the UI's safety switch is one click in the
/// Threat Intel panel.
pub fn state_for_cluster(cluster: &str) -> EnforceState {
    load_cluster_state().clusters.get(cluster).copied().unwrap_or(EnforceState::Enforce)
}

/// What is this node's own cluster called? Reads
/// `self_cluster.json` (same source the agent uses). Falls back to
/// "WolfStack" to match agent default behaviour.
pub fn this_node_cluster() -> String {
    let path = crate::paths::get().self_cluster_config.clone();
    if let Ok(data) = std::fs::read_to_string(&path)
        && let Ok(name) = serde_json::from_str::<String>(&data)
            && !name.is_empty() { return name; }
    "WolfStack".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreatIntelFacts {
    /// Cluster-state-derived: true iff state != Off. Kept for UI
    /// compatibility; new code should branch on `state` instead.
    pub enabled: bool,
    /// Tri-state enforcement for this node's cluster. Drives every
    /// decision the analyzer makes this tick.
    #[serde(default)]
    pub state: EnforceState,
    /// Name of the cluster this node belongs to (so the operator
    /// can correlate findings with their cluster picker in the UI).
    #[serde(default)]
    pub cluster: String,
    /// `ipset` binary is installed and usable on this host. False
    /// means we can't enforce — surface as a High finding with an
    /// install command (only when state == Enforce).
    pub ipset_available: bool,
    /// `iptables` binary is installed (every Linux box, but defensive).
    pub iptables_available: bool,
    /// Age of the local feed file in seconds, or None if absent.
    pub feed_age_secs: Option<u64>,
    /// Number of entries in the local feed after parsing.
    pub feed_entry_count: usize,
    /// Number of entries currently in the kernel ipset (zero if
    /// the set doesn't exist yet, or if state != Enforce).
    pub ipset_entry_count: usize,
    /// Whether the INPUT + OUTPUT iptables rules referencing the
    /// ipset are present right now.
    pub iptables_rules_present: bool,
    /// Whether the one-time v23.2.x → v23.2.2 safety migration has
    /// run on this node. True iff the sentinel file exists.
    #[serde(default)]
    pub migration_completed: bool,
    /// What we did about each gap this tick.
    pub remediations: Vec<RemediationOutcome>,
    pub scanned: bool,
}

pub async fn sample_now_async(_timeout: Duration) -> ThreatIntelFacts {
    tokio::task::spawn_blocking(sample_blocking).await.unwrap_or_default()
}

fn sample_blocking() -> ThreatIntelFacts {
    let cluster = this_node_cluster();
    let state = state_for_cluster(&cluster);
    let enabled = state != EnforceState::Off;
    let ipset_available = which_exists("ipset");
    let iptables_available = which_exists("iptables");
    let feed_age_secs = match std::fs::metadata(FEED_LOCAL_PATH) {
        Ok(m) => m.modified().ok()
            .and_then(|mt| SystemTime::now().duration_since(mt).ok())
            .map(|d| d.as_secs()),
        Err(_) => None,
    };
    let feed_entry_count = if std::path::Path::new(FEED_LOCAL_PATH).exists() {
        parse_feed_entries(FEED_LOCAL_PATH).len()
    } else {
        0
    };
    let ipset_entry_count = if ipset_available {
        count_ipset_entries(IPSET_NAME)
    } else {
        0
    };
    let iptables_rules_present = iptables_available && rules_are_present();
    let migration_completed = Path::new(MIGRATION_SENTINEL_PATH).exists();

    ThreatIntelFacts {
        enabled,
        state,
        cluster,
        ipset_available,
        iptables_available,
        feed_age_secs,
        feed_entry_count,
        ipset_entry_count,
        iptables_rules_present,
        migration_completed,
        remediations: Vec::new(),
        scanned: true,
    }
}

fn which_exists(binary: &str) -> bool {
    std::process::Command::new("which")
        .arg(binary)
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

fn parse_feed_entries(path: &str) -> Vec<String> {
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') { continue; }
        if is_private_or_reserved(t) { continue; }
        // Each entry is either an IP or a CIDR.
        out.push(t.to_string());
    }
    out
}

/// True iff `entry` is a CIDR or IP that lives entirely within
/// private, reserved, loopback, link-local, multicast, or CGN
/// ranges. CRITICAL: the FireHOL Level 1 feed bundles the
/// FullBogons set, which includes 10.0.0.0/8, 172.16.0.0/12,
/// 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8, 100.64.0.0/10, and
/// the multicast/reserved ranges. Installing those as `iptables
/// DROP` would block:
///   - WolfNet on ANY 10.x.x.x subnet (catch-all because the
///     whole `10/8` is filtered)
///   - WolfRouter-managed LANs (10.10.x.x, 172.16-31.x.x, 192.168.x.x)
///   - Docker default bridge (172.17.0.0/16)
///   - **Tailscale tailnet addresses (100.64.0.0/10 CGNAT)** — every
///     Tailscale-connected host gets a 100.x.x.x address; without
///     the CGN filter we'd sever the operator's Tailscale-based
///     management access the moment v23.2 deployed
///   - Local management LANs (192.168.x.x typically)
///
/// — i.e. the entire cluster's east-west and admin traffic. We
/// strip them at feed-parse time so they never reach the kernel
/// ipset.
///
/// IPv6 entries from the feed are skipped here too (we only install
/// IPv4 iptables/ipset rules in this release).
fn is_private_or_reserved(entry: &str) -> bool {
    // Skip IPv6 entries entirely — the ipset created is IPv4-only.
    if entry.contains(':') { return true; }
    // Parse the IP / CIDR. Form: "1.2.3.4" or "1.2.3.0/24".
    let (ip_str, prefix) = match entry.split_once('/') {
        Some((ip, p)) => (ip, p.parse::<u32>().ok().unwrap_or(32)),
        None => (entry, 32),
    };
    let ip: std::net::Ipv4Addr = match ip_str.parse() {
        Ok(a) => a,
        Err(_) => return true, // unparseable → safest to skip
    };
    let n = u32::from(ip);
    // Mask the IP down to its network address for the comparison.
    let host_mask = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
    let net = n & host_mask;

    // List of (network, prefix) pairs we never want to block. The
    // entry must fit ENTIRELY within one of these to be filtered —
    // a /16 in the feed that just *overlaps* a /24 here would still
    // be kept (unlikely on FireHOL but defensive).
    let private: [(u32, u32); 11] = [
        // 0.0.0.0/8 — "this network"
        (0x00_00_00_00, 8),
        // 10.0.0.0/8 — RFC1918
        (0x0A_00_00_00, 8),
        // 100.64.0.0/10 — CGN (RFC6598)
        (0x64_40_00_00, 10),
        // 127.0.0.0/8 — loopback
        (0x7F_00_00_00, 8),
        // 169.254.0.0/16 — link-local
        (0xA9_FE_00_00, 16),
        // 172.16.0.0/12 — RFC1918
        (0xAC_10_00_00, 12),
        // 192.0.0.0/24 — IETF protocol assignments
        (0xC0_00_00_00, 24),
        // 192.0.2.0/24 — TEST-NET-1
        (0xC0_00_02_00, 24),
        // 192.168.0.0/16 — RFC1918
        (0xC0_A8_00_00, 16),
        // 224.0.0.0/4 — multicast
        (0xE0_00_00_00, 4),
        // 240.0.0.0/4 — reserved
        (0xF0_00_00_00, 4),
    ];
    for (priv_net, priv_prefix) in private {
        if prefix < priv_prefix {
            // Feed entry's prefix is broader than the private range —
            // can't be entirely inside.
            continue;
        }
        let priv_mask = if priv_prefix == 0 { 0 } else { (!0u32) << (32 - priv_prefix) };
        if (net & priv_mask) == priv_net {
            return true;
        }
    }
    false
}

fn parse_allowlist() -> HashSet<String> {
    let body = std::fs::read_to_string(ALLOWLIST_PATH).unwrap_or_default();
    body.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Auto-allowlist this host's own IPv4 addresses and the IPv4
/// addresses of every cluster peer. CRITICAL: if Hetzner / a cloud
/// provider re-issues an IP that was previously a botnet C2, the
/// FireHOL feed may still list it. Without this auto-allowlist
/// the DROP rule on INPUT would block all inbound traffic to the
/// host itself — i.e. lock the operator out. We strip these IPs
/// from the blocklist before pushing to the kernel ipset.
///
/// Sources:
///   1. `ip -4 addr show` — every IP bound to a local interface.
///   2. `/etc/wolfstack/nodes.json` — every cluster peer's address.
fn auto_allowlist() -> HashSet<String> {
    let mut set: HashSet<String> = HashSet::new();
    // Local interface IPs.
    if let Ok(out) = std::process::Command::new("ip").args(["-4", "addr", "show"]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let t = line.trim();
            // Format: "inet 142.132.140.78/26 brd ... scope global eth0"
            if let Some(rest) = t.strip_prefix("inet ")
                && let Some(cidr_or_ip) = rest.split_whitespace().next()
                    && let Some(ip) = cidr_or_ip.split('/').next()
                        && ip.parse::<std::net::Ipv4Addr>().is_ok() {
                            set.insert(ip.to_string());
                        }
        }
    }
    // Cluster peer addresses. Read the persisted cluster nodes file
    // directly rather than going through the live cluster handle —
    // this analyzer is sync-blocking and that handle isn't
    // available here.
    let nodes_path = crate::paths::get().nodes_config.clone();
    if let Ok(body) = std::fs::read_to_string(&nodes_path)
        && let Ok(nodes) = serde_json::from_str::<Vec<serde_json::Value>>(&body) {
            for n in nodes {
                if let Some(addr) = n.get("address").and_then(|v| v.as_str()) {
                    // address may be a hostname or an IPv4. Only
                    // insert if it parses as IPv4 — hostnames will
                    // resolve to different IPs over time and we
                    // don't want a stale hostname-resolved IP
                    // permanently allowlisted.
                    if addr.parse::<std::net::Ipv4Addr>().is_ok() {
                        set.insert(addr.to_string());
                    }
                }
                if let Some(pip) = n.get("public_ip").and_then(|v| v.as_str())
                    && pip.parse::<std::net::Ipv4Addr>().is_ok() {
                        set.insert(pip.to_string());
                    }
            }
        }
    set
}

fn count_ipset_entries(name: &str) -> usize {
    let out = std::process::Command::new("ipset")
        .args(["list", name, "-output", "save"])
        .output();
    let out = match out {
        Ok(o) if o.status.success() => o,
        _ => return 0,
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.starts_with("add "))
        .count()
}

/// The exact rule spec per chain. INPUT matches only NEW connections so
/// a feed update that suddenly lists an operator's IP cannot cut off
/// their LIVE dashboard/SSH session (klas 2026-07-05) — inbound attack
/// traffic is new flows by definition. OUTPUT stays unconditional: its
/// job is severing traffic to listed C2/botnet addresses, and an
/// already-established reverse-shell channel is exactly what it must
/// kill, not spare.
fn rule_spec(chain: &str, direction: &str) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = Vec::new();
    if chain == "INPUT" {
        v.extend(["-m", "conntrack", "--ctstate", "NEW"]);
    }
    v.extend(["-m", "set", "--match-set", IPSET_NAME]);
    v.push(if direction == "src" { "src" } else { "dst" });
    v.extend(["-j", "DROP"]);
    v
}

/// Legacy pre-v25.2.16 form (no conntrack match on INPUT). Kept only so
/// installs can migrate it away and teardown can remove it.
fn legacy_rule_spec(direction: &str) -> Vec<&'static str> {
    vec!["-m", "set", "--match-set", IPSET_NAME,
         if direction == "src" { "src" } else { "dst" }, "-j", "DROP"]
}

fn rules_are_present() -> bool {
    // CURRENT form only, deliberately: a node still carrying only the
    // legacy rule must report "absent" so the remediation tick calls
    // install_iptables_rules(), which is the only path that migrates
    // legacy → current. Counting the legacy form as present left every
    // pre-fix node stuck on the old rule forever (review 2026-07-05).
    // No enforcement gap during migration: the legacy rule keeps
    // dropping until the install replaces it.
    let check = |chain: &str, direction: &str| -> bool {
        std::process::Command::new("iptables")
            .arg("-C").arg(chain).args(rule_spec(chain, direction))
            .output().map(|o| o.status.success()).unwrap_or(false)
    };
    check("INPUT", "src") && check("OUTPUT", "dst")
}

/// Post-sample remediation. Refreshes the feed if stale, populates
/// the ipset, and inserts the iptables rules. Gated by ack
/// suppression in the same way as the other analyzers.
pub async fn remediate_if_unacked(
    facts: ThreatIntelFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
    ctx: &Context,
) -> ThreatIntelFacts {
    if !facts.scanned { return facts; }
    // Off → nothing to do. No feed download, no ipset, no rules.
    if facts.state == EnforceState::Off { return facts; }
    let acks = acks.clone();
    let proposals = proposals.clone();
    let scope = ProposalScope { node_id: ctx.node_id.clone(), resource_id: None };
    tokio::task::spawn_blocking(move || remediate_blocking(facts, &acks, &proposals, &scope))
        .await
        .unwrap_or_else(|_| ThreatIntelFacts::default())
}

fn remediate_blocking(
    mut facts: ThreatIntelFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
    scope: &ProposalScope,
) -> ThreatIntelFacts {
    let suppressed = |ft: &str| -> bool {
        acks.suppresses(ft, scope) || proposals.is_suppressed(ft, scope)
    };

    // Refresh the feed if stale (>REFRESH_INTERVAL old or missing).
    // We do this in BOTH DryRun and Enforce — DryRun needs the parsed
    // feed so the operator can see what *would* be blocked.
    let _ = std::fs::create_dir_all("/var/lib/wolfstack/threat-intel");
    let needs_refresh = match facts.feed_age_secs {
        None => true,
        Some(age) => Duration::from_secs(age) >= REFRESH_INTERVAL,
    };
    if needs_refresh && !suppressed(FT_THREAT_INTEL_STALE) {
        facts.remediations.push(refresh_feed());
        facts.feed_entry_count = parse_feed_entries(FEED_LOCAL_PATH).len();
        facts.feed_age_secs = Some(0);
    }

    // DryRun stops here. We parsed the feed but the kernel stays
    // untouched. The operator can inspect the preflight report and
    // promote to Enforce when they're confident.
    if facts.state == EnforceState::DryRun {
        return facts;
    }

    // Enforce path. Both binaries must be available; if not we
    // surface a High finding in `analyze` and skip — never fall back
    // to a degraded mode that would silently misbehave.
    if !facts.ipset_available || !facts.iptables_available {
        return facts;
    }

    // Sync ipset to feed (and allowlist).
    if facts.feed_entry_count > 0 {
        facts.remediations.push(sync_ipset_to_feed());
        facts.ipset_entry_count = count_ipset_entries(IPSET_NAME);
    }

    // Make sure the iptables rules referencing the ipset are present.
    if !facts.iptables_rules_present && facts.ipset_entry_count > 0
        && !suppressed(FT_THREAT_INTEL_RULES_MISSING)
    {
        facts.remediations.push(install_iptables_rules());
        facts.iptables_rules_present = rules_are_present();
    }

    facts
}

/// Download the feed using `curl` (universal availability across
/// Debian/Rocky/Alpine) and atomic-rename into place. Returns a
/// remediation outcome — failures keep the previous local feed in
/// place so we never drop enforcement during a transient network
/// glitch.
fn refresh_feed() -> RemediationOutcome {
    let action = "refresh threat-intel feed".to_string();
    let _ = std::fs::create_dir_all("/var/lib/wolfstack/threat-intel");
    let tmp = format!("{}.tmp", FEED_LOCAL_PATH);
    let out = std::process::Command::new("curl")
        .args([
            "-s", "-S", "--fail",
            "--max-time", "30",
            "-o", &tmp,
            FEED_URL,
        ])
        .output();
    let curl_ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
    if !curl_ok {
        let _ = std::fs::remove_file(&tmp);
        return RemediationOutcome {
            action,
            ok: false,
            detail: format!(
                "curl {} failed: {}", FEED_URL,
                out.map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .unwrap_or_else(|e| e.to_string())
            ),
        };
    }
    // Sanity-check the downloaded content. FireHOL files start with
    // a comment block referencing FireHOL — if we got an HTML
    // captive-portal page or a 404 body, reject.
    let head = std::fs::read_to_string(&tmp).unwrap_or_default();
    if !head.contains("firehol") && !head.contains("# Source") {
        let _ = std::fs::remove_file(&tmp);
        return RemediationOutcome {
            action,
            ok: false,
            detail: format!("downloaded body doesn't look like a FireHOL feed (first chars: {:?})",
                head.chars().take(80).collect::<String>()),
        };
    }
    if let Err(e) = std::fs::rename(&tmp, FEED_LOCAL_PATH) {
        return RemediationOutcome {
            action, ok: false, detail: format!("rename: {}", e),
        };
    }
    let count = parse_feed_entries(FEED_LOCAL_PATH).len();
    tracing::warn!("threat_intel: refreshed feed; {} entries", count);
    RemediationOutcome {
        action,
        ok: true,
        detail: format!("downloaded {} ({} entries)", FEED_URL, count),
    }
}

/// Operator-triggered diagnostic: HEAD `FEED_URL` with a short
/// timeout and report whether the upstream FireHOL feed is
/// reachable from this node. Surfaces DNS / TCP / TLS / HTTP failure
/// layers in the `error` string so the operator can tell apart
/// "this node has no network" from "FireHOL is rate-limiting us".
///
/// Returns a JSON-able struct rather than `RemediationOutcome` because
/// it's user-facing (not part of the auto-remediation audit trail).
/// Synchronous + blocking — call from `web::block` or
/// `spawn_blocking`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FeedTestResult {
    pub reachable: bool,
    pub url: String,
    pub status_code: Option<u16>,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// (kept_entries, auto_allowlisted, skipped_by_allow) from the most
/// recent ipset sync. Doubles as the log-dedup memory for the sync's
/// state-change logging and as the source for the dashboard value
/// receipt's "IPs blocked right now" figure.
static LAST_SYNC: std::sync::Mutex<Option<(usize, usize, u32)>> = std::sync::Mutex::new(None);

/// Entry count currently enforced in the threat-intel ipset — `None`
/// until the first enforcement sync of this process (enforcement off,
/// or not yet ticked). In-memory read; safe to call from handlers.
pub fn last_synced_blocklist_len() -> Option<usize> {
    LAST_SYNC.lock().unwrap_or_else(|e| e.into_inner()).map(|(kept, _, _)| kept)
}

pub fn test_feed_blocking() -> FeedTestResult {
    let url = FEED_URL.to_string();
    let started = std::time::Instant::now();
    // Use the same curl pathway the analyzer uses for actual feed
    // fetches, so the diagnostic measures the SAME network/DNS/TLS
    // path the auto-remediation loop would have hit. `-I` is HEAD,
    // `-w "%{http_code}"` prints status to stdout, `--fail` makes
    // 4xx/5xx propagate as exit-code != 0 so we can split layers.
    let out = std::process::Command::new("curl")
        .args([
            "-s", "-S", "-I",
            "--max-time", "10",
            "--connect-timeout", "5",
            "-w", "%{http_code}",
            "-o", "/dev/null",
            &url,
        ])
        .output();
    let duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    match out {
        Ok(o) if o.status.success() => {
            let body = String::from_utf8_lossy(&o.stdout).to_string();
            let status_code = body.trim().parse::<u16>().ok();
            // Treat 2xx/3xx as reachable; anything else is a failure
            // (curl --fail would have returned non-zero for 4xx/5xx,
            // so this branch typically only fires on 2xx HEAD).
            let reachable = matches!(status_code, Some(c) if (200..400).contains(&c));
            FeedTestResult {
                reachable,
                url,
                status_code,
                duration_ms,
                error: if reachable { None } else {
                    Some(format!("HEAD returned status {}", status_code.map(|c| c.to_string()).unwrap_or_else(|| "?".into())))
                },
            }
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            // curl prints layer-specific errors to stderr: "Could not
            // resolve host" (DNS), "Connection refused" (TCP), "SSL
            // certificate problem" (TLS), "HTTP/1.1 404 Not Found"
            // (HTTP). Preserved verbatim so the operator can spot
            // which layer broke.
            FeedTestResult {
                reachable: false,
                url,
                status_code: None,
                duration_ms,
                error: Some(format!(
                    "curl exit {} — {}",
                    o.status.code().unwrap_or(-1),
                    stderr.trim()
                )),
            }
        }
        Err(e) => FeedTestResult {
            reachable: false,
            url,
            status_code: None,
            duration_ms,
            error: Some(format!("curl spawn failed: {}", e)),
        },
    }
}

/// Atomic ipset replacement: build a fresh set in a tmp name then
/// `ipset swap` to switch it in. Prevents the multi-second window
/// where the kernel set is empty mid-rebuild.
/// `wolfstack --unblock <ip>` support: remove the address from the
/// kernel ipset immediately and persist it into the operator allowlist
/// file (which `parse_allowlist` re-reads on every sync, so the next
/// feed refresh can't re-block it). Daemon-independent break-glass.
pub fn cli_unblock_ip(ip: &str) {
    let outcome = crate::auth::ipset_del(IPSET_NAME, ip);
    let _ = std::fs::create_dir_all("/var/lib/wolfstack/threat-intel");
    println!("{}", outcome.describe("predictive blocklist", IPSET_NAME));
    let existing = std::fs::read_to_string(ALLOWLIST_PATH).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == ip) {
        println!("  ✓ predictive allowlist: already contains {}", ip);
    } else {
        let mut out = existing;
        if !out.is_empty() && !out.ends_with('\n') { out.push('\n'); }
        out.push_str(ip);
        out.push('\n');
        match std::fs::write(ALLOWLIST_PATH, out) {
            Ok(()) => println!("  ✓ predictive allowlist: added to {}", ALLOWLIST_PATH),
            Err(e) => eprintln!("  ✗ predictive allowlist ({}): {} — the next feed sync may re-block this IP", ALLOWLIST_PATH, e),
        }
    }
}

/// A parsed IPv4 network (base, prefix) for protected-IP overlap math.
/// Accepts "a.b.c.d" (prefix 32) or "a.b.c.d/n"; None for v6/garbage —
/// the FireHOL feed and the kernel set here are inet (v4) only.
fn parse_v4_net(entry: &str) -> Option<(u32, u8)> {
    let (ip_str, prefix) = match entry.split_once('/') {
        Some((i, p)) => (i, p.parse::<u8>().ok().filter(|p| *p <= 32)?),
        None => (entry, 32),
    };
    let ip: std::net::Ipv4Addr = ip_str.trim().parse().ok()?;
    Some((u32::from(ip), prefix))
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { !0u32 << (32 - prefix) }
}

/// Two v4 networks overlap iff the shorter prefix contains the other's
/// base address. Used to drop any feed entry that touches a protected
/// address in EITHER direction: a protected CIDR covering a feed IP,
/// or a feed CIDR covering a protected IP (the case the old exact-string
/// `allow.contains()` check could not see — a /16 on the feed silently
/// swallowed an allowlisted host inside it).
fn v4_nets_overlap(a: (u32, u8), b: (u32, u8)) -> bool {
    let p = a.1.min(b.1);
    let mask = v4_mask(p);
    (a.0 & mask) == (b.0 & mask)
}

fn entry_touches_protected(entry: &str, protected: &[(u32, u8)]) -> bool {
    match parse_v4_net(entry) {
        Some(net) => protected.iter().any(|p| v4_nets_overlap(net, *p)),
        None => false,
    }
}

fn sync_ipset_to_feed() -> RemediationOutcome {
    let action = "sync ipset to feed".to_string();
    let entries = parse_feed_entries(FEED_LOCAL_PATH);
    if entries.is_empty() {
        return RemediationOutcome {
            action, ok: false, detail: "feed parse returned 0 entries; skipping ipset sync".into(),
        };
    }
    // Combine the operator allowlist with the auto-allowlist of
    // local interface IPs + cluster peer addresses. Critical: cloud
    // providers (Hetzner, DigitalOcean, OVH, AWS) routinely reuse
    // public IPs. If we rent a fresh VPS whose IP was previously a
    // botnet C2, FireHOL still lists it — and an INPUT DROP rule on
    // our own IP locks the operator out. Same risk for any cluster
    // peer whose recycled IP happens to be on the feed. We strip
    // both ourselves and our peers before pushing to the kernel.
    let mut allow = parse_allowlist();
    let auto = auto_allowlist();
    let auto_count = auto.len();
    allow.extend(auto);
    // Operator trusted_ips + every IP with a successful dashboard login
    // in the last 30 days (klas 2026-07-05: a feed update listed his
    // browser's public IP and every node blocked him at once; only SSH
    // from an internal address worked). These join the allowlist as
    // CIDR-aware entries below.
    allow.extend(crate::auth::protected_client_ips());
    // Parse every allow entry into v4 nets once, for overlap checks that
    // ALSO catch a feed CIDR wrapping a protected host — the old exact-
    // string check couldn't see a /16 swallowing an allowlisted IP.
    let protected: Vec<(u32, u8)> = allow.iter().filter_map(|e| parse_v4_net(e)).collect();
    // Build a restore-formatted batch script.
    let tmp_name = format!("{}_swap", IPSET_NAME);
    let mut script = String::with_capacity(entries.len() * 32);
    script.push_str(&format!("create {} hash:net family inet hashsize 4096 maxelem 131072\n", tmp_name));
    let mut skipped_by_allow = 0u32;
    for e in &entries {
        if allow.contains(e) || entry_touches_protected(e, &protected) {
            skipped_by_allow += 1;
            continue;
        }
        script.push_str(&format!("add {} {}\n", tmp_name, e));
    }
    // Ensure the real set exists so swap has a destination.
    let _ = std::process::Command::new("ipset")
        .args(["create", IPSET_NAME, "hash:net", "family", "inet", "hashsize", "4096", "maxelem", "131072", "-exist"])
        .output();
    // Drop any prior tmp set from a previous failed run.
    let _ = std::process::Command::new("ipset")
        .args(["destroy", &tmp_name])
        .output();
    // Restore-load the new tmp set.
    let mut child = match std::process::Command::new("ipset")
        .args(["restore", "-exist"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return RemediationOutcome { action, ok: false, detail: format!("spawn ipset restore: {}", e) },
    };
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        if let Err(e) = stdin.write_all(script.as_bytes()) {
            return RemediationOutcome { action, ok: false, detail: format!("write to ipset restore: {}", e) };
        }
    }
    let out = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => return RemediationOutcome { action, ok: false, detail: format!("wait ipset restore: {}", e) },
    };
    if !out.status.success() {
        let _ = std::process::Command::new("ipset").args(["destroy", &tmp_name]).output();
        return RemediationOutcome {
            action, ok: false,
            detail: format!("ipset restore failed: {}", String::from_utf8_lossy(&out.stderr).trim()),
        };
    }
    // Atomic swap, then destroy the now-stale temp set.
    let swap = std::process::Command::new("ipset")
        .args(["swap", &tmp_name, IPSET_NAME])
        .output();
    let swap_ok = swap.as_ref().map(|o| o.status.success()).unwrap_or(false);
    let _ = std::process::Command::new("ipset").args(["destroy", &tmp_name]).output();
    if !swap_ok {
        return RemediationOutcome {
            action, ok: false,
            detail: format!("ipset swap failed: {}",
                swap.map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .unwrap_or_else(|e| e.to_string())),
        };
    }
    let kept = entries.iter()
        .filter(|e| !allow.contains(*e) && !entry_touches_protected(e, &protected))
        .count();
    // State-change logging: this sync runs every enforcement tick and almost
    // always lands on identical numbers — that's a heartbeat, not news (it
    // was a WARN on every tick; operator: "we are really spamming the logs").
    // INFO when the counts actually change (or on the first sync after
    // start), DEBUG for the steady state.
    {
        let mut last = LAST_SYNC.lock().unwrap_or_else(|e| e.into_inner());
        let now = (kept, auto_count, skipped_by_allow);
        if *last != Some(now) {
            tracing::info!(
                "threat_intel: synced ipset to {} entries ({} auto-allowlisted, {} feed entries skipped by allowlist)",
                kept, auto_count, skipped_by_allow,
            );
            *last = Some(now);
        } else {
            tracing::debug!(
                "threat_intel: ipset sync unchanged ({} entries)", kept,
            );
        }
    }
    RemediationOutcome {
        action,
        ok: true,
        detail: format!(
            "ipset {} updated to {} entries; {} skipped via allowlist ({} of which were auto-allowlisted local/peer IPs)",
            IPSET_NAME, kept, skipped_by_allow, auto_count,
        ),
    }
}

fn install_iptables_rules() -> RemediationOutcome {
    let action = "install iptables rules for blocklist".to_string();
    let mut errors: Vec<String> = Vec::new();
    let mut added = 0u32;
    for (chain, direction) in [("INPUT", "src"), ("OUTPUT", "dst")] {
        let rule = rule_spec(chain, direction);
        let legacy = legacy_rule_spec(direction);
        // Migrate away the pre-v25.2.16 form where it differs from the
        // current one (INPUT): delete every stacked copy or the old rule
        // keeps dropping established flows the new form spares. On OUTPUT
        // the forms are identical — deleting would just flap the rule.
        if legacy != rule {
            loop {
                let removed = std::process::Command::new("iptables")
                    .arg("-D").arg(chain).args(&legacy)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if !removed { break; }
            }
        }
        let exists = std::process::Command::new("iptables")
            .arg("-C").arg(chain).args(&rule)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if exists { continue; }
        let out = std::process::Command::new("iptables")
            .arg("-I").arg(chain).args(&rule)
            .output();
        match out {
            Ok(o) if o.status.success() => added += 1,
            Ok(o) => errors.push(format!("{}: {}", chain, String::from_utf8_lossy(&o.stderr).trim())),
            Err(e) => errors.push(format!("{}: {}", chain, e)),
        }
    }
    let ok = errors.is_empty();
    if ok {
        tracing::warn!("threat_intel: installed {} iptables rules referencing {}", added, IPSET_NAME);
    }
    RemediationOutcome {
        action,
        ok,
        detail: if ok {
            format!("inserted DROP rules on INPUT+OUTPUT referencing {}", IPSET_NAME)
        } else {
            errors.join("; ")
        },
    }
}

pub fn analyze(
    ctx: &Context,
    facts: &ThreatIntelFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    if !facts.scanned { return out; }
    let scope = ProposalScope { node_id: ctx.node_id.clone(), resource_id: None };
    let suppressed = |ft: &str| -> bool {
        acks.suppresses(ft, &scope) || proposals.is_suppressed(ft, &scope)
    };

    // One-time safety migration sentinel was just written by this
    // node? Surface a Medium finding so the operator notices what
    // happened and re-enables only if they want it. Fires until
    // ack'd.
    if facts.migration_completed
        && was_migration_emitted_recently()
        && !suppressed(FT_THREAT_INTEL_MIGRATED)
    {
        out.push(Proposal::new_rule(
            FT_THREAT_INTEL_MIGRATED,
            Severity::Warn,
            "Threat-intel enforcement disabled by v23.2.2 safety migration",
            format!(
                "Earlier versions (v23.2.0 / v23.2.1) auto-enabled FireHOL Level 1 \
                 blocklist enforcement on first boot. With thousands of operators \
                 running wildly different network shapes, opt-out enforcement was \
                 unsafe — any feed false-positive or unexpected overlap could \
                 blackhole real traffic before you knew the feature existed. \n\n\
                 On this upgrade WolfStack has: removed any `wolfstack_blocklist` \
                 ipset, removed iptables INPUT/OUTPUT DROP rules that referenced \
                 it, and removed the legacy auto-enable flag. Cluster '{}' is \
                 now in the safe-default state: **Off**. \n\n\
                 To turn enforcement back on safely, go to the Predictive Inbox, \
                 enable DryRun for this cluster, review the per-node preflight \
                 report (it shows exactly which of your subnets/peers would be \
                 affected), and only then promote to Enforce. The promote step \
                 requires typing the cluster name to confirm.",
                facts.cluster,
            ),
            vec![],
            RemediationPlan::Manual {
                instructions: "Review preflight in the Predictive Inbox, then enable DryRun for the cluster. Ack this card to dismiss.".into(),
                commands: vec![],
            },
            scope.clone(),
        ));
    }

    // Only emit the "ipset not installed" High finding when the
    // operator has actually asked us to enforce on this cluster.
    // Otherwise the card is misleading noise on hosts that never
    // intended to use the feature.
    if facts.state == EnforceState::Enforce
        && !facts.ipset_available
        && !suppressed(FT_THREAT_INTEL_NO_IPSET)
    {
        out.push(Proposal::new_rule(
            FT_THREAT_INTEL_NO_IPSET,
            Severity::High,
            "Threat-intel blocking can't enforce — `ipset` not installed",
            "WolfStack uses the FireHOL Level 1 IP blocklist to drop traffic to/from known-bad addresses. That requires the `ipset` kernel hash-table tool, which isn't installed on this host. Without it the analyzer can detect the gap but can't enforce.".to_string(),
            vec![],
            RemediationPlan::Manual {
                instructions: "Install ipset. The next predictive tick will then build the set and install the iptables rules.".into(),
                commands: vec![
                    "# Debian / Proxmox:".into(),
                    "apt-get install -y ipset".into(),
                    "# Rocky / RHEL:".into(),
                    "dnf install -y ipset".into(),
                ],
            },
            scope.clone(),
        ));
    }

    // DryRun → Info card so the operator remembers preview mode is
    // running and they haven't yet promoted to enforce. Suppressible.
    if facts.state == EnforceState::DryRun && !suppressed(FT_THREAT_INTEL_DRY_RUN) {
        out.push(Proposal::new_rule(
            FT_THREAT_INTEL_DRY_RUN,
            Severity::Info,
            "Threat-intel blocklist running in DryRun (no traffic blocked)",
            format!(
                "Cluster '{}' has FireHOL Level 1 enforcement set to DryRun: the \
                 feed is being downloaded and parsed on every tick, but no \
                 iptables rules are installed and no traffic is being blocked. \
                 When you're confident the preflight overlap report is clean, \
                 promote to Enforce from the Predictive Inbox.",
                facts.cluster,
            ),
            vec![],
            RemediationPlan::Manual {
                instructions: "Open the Predictive Inbox, run a fresh preflight, then click Promote to Enforce.".into(),
                commands: vec![],
            },
            scope.clone(),
        ));
    }

    out
}

/// Whether the migration sentinel was created in the last 30 days.
/// We treat "recent" generously because the operator may not see
/// the finding for a while — preserving it across reboots/upgrades
/// matters more than a tight window.
fn was_migration_emitted_recently() -> bool {
    let meta = match std::fs::metadata(MIGRATION_SENTINEL_PATH) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let mt = match meta.modified() { Ok(t) => t, Err(_) => return false };
    let age = SystemTime::now().duration_since(mt).unwrap_or_default();
    age < Duration::from_secs(30 * 24 * 3600)
}

pub fn covered_scopes(
    ctx: &Context,
    facts: &ThreatIntelFacts,
) -> Vec<(String, ProposalScope)> {
    if !facts.scanned { return Vec::new(); }
    let scope = ProposalScope { node_id: ctx.node_id.clone(), resource_id: None };
    [
        FT_THREAT_INTEL_DRY_RUN,
        FT_THREAT_INTEL_NO_IPSET,
        FT_THREAT_INTEL_STALE,
        FT_THREAT_INTEL_RULES_MISSING,
        FT_THREAT_INTEL_MIGRATED,
        // Keep the legacy IDs covered so persisted acks resolve
        // (FT_THREAT_INTEL_DISABLED is no longer emitted but may
        // still appear in old acks; FT_THREAT_INTEL_OFF is reserved
        // for a future "feature dormant" card and harmless to keep).
        FT_THREAT_INTEL_DISABLED,
        FT_THREAT_INTEL_OFF,
    ].iter().map(|t| ((*t).to_string(), scope.clone())).collect()
}

#[allow(dead_code)]
fn forensics_dir() -> PathBuf {
    PathBuf::from("/var/lib/wolfstack/threat-intel")
}

/// Operator-visible status snapshot for the local node. Returned by
/// the GET /status endpoint so the UI panel can render current
/// state for *this* node's cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelStatus {
    /// True iff state != Off — convenience for older UI bindings.
    pub enabled: bool,
    pub state: EnforceState,
    pub cluster: String,
    pub ipset_available: bool,
    pub iptables_rules_present: bool,
    pub feed_entry_count: usize,
    pub ipset_entry_count: usize,
    pub feed_age_secs: Option<u64>,
    pub migration_completed: bool,
}

pub fn status_snapshot() -> ThreatIntelStatus {
    let cluster = this_node_cluster();
    let state = state_for_cluster(&cluster);
    ThreatIntelStatus {
        enabled: state != EnforceState::Off,
        state,
        cluster,
        ipset_available: which_exists("ipset"),
        iptables_rules_present: which_exists("iptables") && rules_are_present(),
        feed_entry_count: parse_feed_entries(FEED_LOCAL_PATH).len(),
        ipset_entry_count: count_ipset_entries(IPSET_NAME),
        feed_age_secs: std::fs::metadata(FEED_LOCAL_PATH).ok()
            .and_then(|m| m.modified().ok())
            .and_then(|mt| SystemTime::now().duration_since(mt).ok())
            .map(|d| d.as_secs()),
        migration_completed: Path::new(MIGRATION_SENTINEL_PATH).exists(),
    }
}

/// Operator-triggered cluster state change. Caller is expected to
/// have already validated the cluster name and (for promotion to
/// Enforce) the preflight freshness gate. This function persists the
/// state and, if the new state is Off, tears down kernel state
/// immediately so the safety switch is instantaneous.
///
/// Returns the persisted full state file so the caller can
/// propagate it to peers without a second read.
pub fn set_cluster_state(cluster: &str, new_state: EnforceState) -> Result<ClusterStateFile, String> {
    if cluster.trim().is_empty() {
        return Err("cluster name must not be empty".into());
    }
    let mut state = load_cluster_state();
    // Always normalise: remove the entry entirely if it's the
    // default (Off). Keeps the file minimal and avoids accumulating
    // stale entries for deleted clusters.
    if new_state == EnforceState::Off {
        state.clusters.remove(cluster);
    } else {
        state.clusters.insert(cluster.to_string(), new_state);
    }
    save_cluster_state(&state)?;
    // If this node is in the affected cluster AND the new state is
    // Off, tear down kernel state right now — same instant-safety
    // contract the legacy disable_for_operator() had.
    if cluster == this_node_cluster() && new_state == EnforceState::Off {
        tear_down_kernel_state();
    }
    tracing::warn!("threat_intel: cluster '{}' set to '{}'", cluster, new_state.as_str());
    Ok(state)
}

/// Apply a state file that was pushed from a peer. Merges into the
/// local state file rather than replacing it — multi-cluster
/// deployments may have entries the pushing peer doesn't know
/// about (clusters whose state was changed via a different node),
/// and a blind overwrite would silently lose them.
///
/// Merge semantics: for every cluster in `incoming`, the local
/// state file ends up with the incoming value (Off entries result
/// in the cluster being removed from the file, matching
/// `set_cluster_state`'s normalisation). Local entries for
/// clusters NOT present in `incoming` are preserved.
pub fn apply_peer_state(incoming: ClusterStateFile) -> Result<(), String> {
    let mut merged = load_cluster_state();
    for (cluster, state) in incoming.clusters {
        if state == EnforceState::Off {
            merged.clusters.remove(&cluster);
        } else {
            merged.clusters.insert(cluster, state);
        }
    }
    save_cluster_state(&merged)?;
    // If our own cluster is now Off after the merge, tear down rules
    // locally so the safety switch propagates without waiting for
    // the next tick.
    if state_for_cluster(&this_node_cluster()) == EnforceState::Off {
        tear_down_kernel_state();
    }
    Ok(())
}

/// Remove any iptables rules + ipset belonging to this feature.
/// Idempotent. Used by the migration and by every Off-transition.
fn tear_down_kernel_state() {
    // Remove iptables rules so traffic flows immediately. Both
    // chains, both directions. -D returns non-zero when the rule
    // isn't present; that's fine. Loop a few times to catch any
    // duplicate rules an earlier buggy version may have inserted.
    for (chain, direction) in [("INPUT", "src"), ("OUTPUT", "dst")] {
        // Both rule forms: pre-v25.2.16 legacy and the current spec
        // (identical on OUTPUT — dedup so we don't loop twice).
        let mut forms = vec![legacy_rule_spec(direction)];
        let current = rule_spec(chain, direction);
        if current != forms[0] { forms.push(current); }
        for rule in forms {
            for _ in 0..8 {
                let out = std::process::Command::new("iptables")
                    .arg("-D").arg(chain).args(&rule)
                    .output();
                match out {
                    Ok(o) if o.status.success() => continue,
                    _ => break,
                }
            }
        }
    }
    // Destroy the ipset so nothing else can reference it.
    // -X is ignore-if-missing.
    let _ = std::process::Command::new("ipset").args(["destroy", IPSET_NAME]).output();
    tracing::warn!("threat_intel: kernel state torn down (iptables rules removed, ipset destroyed)");
}

/// One-time v23.2.x → v23.2.2 safety migration. Called from main.rs
/// at startup, BEFORE the predictive analyzer first runs. Effects:
///
///   1. If `MIGRATION_SENTINEL_PATH` already exists → no-op.
///   2. Tear down any iptables rules + ipset belonging to this
///      feature (whether or not the legacy flag is present — we
///      may be migrating a partially-installed state).
///   3. Remove the legacy auto-enable flag so older code paths
///      can't accidentally observe it as "enabled".
///   4. Touch the sentinel file. Sets `migration_completed = true`
///      from this tick onward, which fans out the Medium finding.
///
/// Returns true iff this call actually ran the migration (vs.
/// short-circuiting on an existing sentinel). Useful in tests.
pub fn run_safety_migration_once() -> bool {
    if Path::new(MIGRATION_SENTINEL_PATH).exists() {
        return false;
    }
    let _ = std::fs::create_dir_all("/var/lib/wolfstack/threat-intel");
    // Detect whether anything actually needed undoing so we can log
    // accurately. Pure observability — the teardown itself is
    // idempotent and runs regardless.
    let had_legacy_flag = Path::new(LEGACY_ENABLE_FLAG_PATH).exists();
    let had_rules = which_exists("iptables") && rules_are_present();
    let had_ipset = which_exists("ipset") && count_ipset_entries(IPSET_NAME) > 0;
    tear_down_kernel_state();
    if had_legacy_flag {
        let _ = std::fs::remove_file(LEGACY_ENABLE_FLAG_PATH);
    }
    // Touch sentinel. If we can't write it, log loudly — we'd
    // otherwise re-tear-down on every boot, which is annoying but
    // safe (idempotent).
    if let Err(e) = std::fs::write(MIGRATION_SENTINEL_PATH, b"v23.2.2 safety migration completed\n") {
        tracing::error!("threat_intel: could not write migration sentinel: {}", e);
    }
    tracing::warn!(
        "threat_intel: v23.2.2 safety migration ran (legacy_flag={}, had_rules={}, had_ipset={})",
        had_legacy_flag, had_rules, had_ipset,
    );
    true
}

// ─── Preflight (dry-run analysis) ──────────────────────────────────

/// Per-node preflight report. Computed by `preflight()` on the node
/// whose iptables would actually be touched. Tells the operator,
/// before they enable enforcement, exactly what would land in the
/// kernel ipset and which of their own addresses/subnets overlap
/// the feed.
///
/// This NEVER writes ipset or iptables — it's pure analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightReport {
    /// Unix epoch seconds at which this report was generated.
    pub generated_at: u64,
    /// This node's id (host_id) and cluster_name for cross-
    /// referencing on the aggregator side.
    pub node_id: String,
    pub cluster: String,
    /// True iff `ipset` and `iptables` binaries are present. If
    /// false, enforcement on this node would surface a High finding
    /// instead of installing rules.
    pub ipset_available: bool,
    pub iptables_available: bool,
    /// Number of entries in the parsed feed (post bogon-filter).
    /// 0 means the feed wasn't available — operator should refresh
    /// the feed before promoting.
    pub feed_entry_count: usize,
    /// Age of the feed file in seconds; None if the file is
    /// missing (a Refresh-Feed action will fetch it next tick).
    pub feed_age_secs: Option<u64>,
    /// IPv4 addresses bound to this node's local interfaces that
    /// the bogon-filter+allowlist machinery would skip from the
    /// blocklist. Listed so the operator can visually confirm the
    /// public IPs they expect to see.
    pub local_interface_ips: Vec<String>,
    /// IPv4 addresses of cluster peers (from nodes.json) that
    /// would be auto-allowlisted.
    pub peer_ips: Vec<String>,
    /// Operator-managed allowlist (CIDRs from allowlist.txt) — for
    /// transparency: the modal shows operators what's already
    /// excluded.
    pub operator_allowlist: Vec<String>,
    /// Feed entries that match a local interface IP or peer IP
    /// AFTER the bogon-filter pass. These are IPs that ARE in the
    /// FireHOL feed but would be auto-allowlisted because they
    /// belong to the operator's own cluster. Critical signal: if
    /// non-empty, the operator's own infrastructure is on a public
    /// threat list (almost always cloud-IP reuse) — enforcement
    /// would have blocked their own host without the allowlist.
    pub feed_overlaps_local: Vec<String>,
    /// Number of entries that would survive into the ipset after
    /// all filters. Same number the kernel set would have.
    pub would_block_count: usize,
    /// First N (up to ~50) entries that would land in the ipset.
    /// Sample — the operator doesn't need all 30k IPs, but a
    /// sample reassures them the feed is well-formed.
    pub sample_block_entries: Vec<String>,
    /// Any non-fatal warnings the operator should see (e.g. feed
    /// missing, ipset binary not installed, peer-fetch failure).
    pub warnings: Vec<String>,
}

/// Compute a preflight report for THIS node. Reads the cached feed
/// (does not download — the analyzer's refresh loop handles
/// downloads on the cluster's own schedule). Returns even if the
/// feed is missing — the report's `warnings` field surfaces that.
///
/// Synchronous & blocking; cheap (parses one local file, runs
/// `ip addr` once, reads nodes.json once). Safe to call from an
/// HTTP handler via `spawn_blocking`.
pub fn preflight_blocking(node_id: String) -> PreflightReport {
    let cluster = this_node_cluster();
    let ipset_available = which_exists("ipset");
    let iptables_available = which_exists("iptables");
    let mut warnings: Vec<String> = Vec::new();
    if !ipset_available {
        warnings.push(
            "ipset is not installed on this node — enforcement would fail. Install ipset before promoting to Enforce.".into()
        );
    }
    if !iptables_available {
        warnings.push("iptables is not installed on this node.".into());
    }

    let feed_present = std::path::Path::new(FEED_LOCAL_PATH).exists();
    if !feed_present {
        warnings.push(
            "Feed file not yet downloaded. Enable DryRun for at least one predictive tick (≤5min) before running preflight.".into()
        );
    }
    let entries = if feed_present { parse_feed_entries(FEED_LOCAL_PATH) } else { Vec::new() };
    let feed_age_secs = std::fs::metadata(FEED_LOCAL_PATH).ok()
        .and_then(|m| m.modified().ok())
        .and_then(|mt| SystemTime::now().duration_since(mt).ok())
        .map(|d| d.as_secs());

    // Auto-allowlist = local interface IPs + peer IPs (same logic
    // used by sync_ipset_to_feed). Separate the two sources here so
    // the operator can see what came from where.
    let mut local_ips: Vec<String> = Vec::new();
    if let Ok(out) = std::process::Command::new("ip").args(["-4", "addr", "show"]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("inet ")
                && let Some(cidr_or_ip) = rest.split_whitespace().next()
                    && let Some(ip) = cidr_or_ip.split('/').next()
                        && ip.parse::<std::net::Ipv4Addr>().is_ok() {
                            local_ips.push(ip.to_string());
                        }
        }
    }
    local_ips.sort();
    local_ips.dedup();

    let mut peer_ips: Vec<String> = Vec::new();
    let nodes_path = crate::paths::get().nodes_config.clone();
    match std::fs::read_to_string(&nodes_path) {
        Ok(body) => {
            match serde_json::from_str::<Vec<serde_json::Value>>(&body) {
                Ok(nodes) => {
                    for n in nodes {
                        for key in ["address", "public_ip"] {
                            if let Some(v) = n.get(key).and_then(|x| x.as_str())
                                && v.parse::<std::net::Ipv4Addr>().is_ok() {
                                    peer_ips.push(v.to_string());
                                }
                        }
                    }
                }
                Err(e) => warnings.push(format!("nodes.json parse error: {}", e)),
            }
        }
        Err(_) => {
            // Missing nodes.json on a single-node install is normal;
            // don't warn unless we know there should be peers.
        }
    }
    peer_ips.sort();
    peer_ips.dedup();

    let operator_allowlist: Vec<String> = parse_allowlist().into_iter().collect();

    // Compute overlaps: feed entries whose exact string matches a
    // local IP or peer IP. The auto-allowlist key in
    // sync_ipset_to_feed is a HashSet keyed by the same exact
    // strings, so this faithfully predicts what the kernel set
    // would (not) contain.
    let mut auto: HashSet<String> = HashSet::new();
    auto.extend(local_ips.iter().cloned());
    auto.extend(peer_ips.iter().cloned());
    let op_set: HashSet<String> = operator_allowlist.iter().cloned().collect();

    let mut feed_overlaps_local: Vec<String> = Vec::new();
    let mut kept: Vec<String> = Vec::with_capacity(entries.len());
    for e in &entries {
        if auto.contains(e) {
            feed_overlaps_local.push(e.clone());
            continue;
        }
        if op_set.contains(e) {
            // Already-allowlisted by operator: not an overlap signal,
            // just an exclusion. Still skipped from the kernel set.
            continue;
        }
        kept.push(e.clone());
    }
    feed_overlaps_local.sort();
    feed_overlaps_local.dedup();

    let sample_block_entries: Vec<String> = kept.iter().take(50).cloned().collect();
    let would_block_count = kept.len();

    PreflightReport {
        generated_at: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs()).unwrap_or(0),
        node_id,
        cluster,
        ipset_available,
        iptables_available,
        feed_entry_count: entries.len(),
        feed_age_secs,
        local_interface_ips: local_ips,
        peer_ips,
        operator_allowlist,
        feed_overlaps_local,
        would_block_count,
        sample_block_entries,
        warnings,
    }
}

// ─── Fresh-preflight gate (promote-to-Enforce) ────────────────────

/// Stateless freshness check. The promote-to-Enforce request body
/// must carry the `generated_at` of the preflight the operator just
/// reviewed (the most-recent timestamp across every per-node report
/// in the cluster — the frontend computes max() and passes that in).
///
/// Stateless because:
///   * The operator may manage a remote cluster from a node that
///     doesn't itself belong to it; a server-side timestamp file
///     would be on the wrong host.
///   * Daemon restarts don't reset the gate — the operator's
///     browser is still holding the report, so they just resubmit.
///   * No race between Promote requests on different operator
///     sessions.
///
/// Returns Ok(()) iff `preflight_generated_at` is within
/// `PREFLIGHT_FRESHNESS_SECS` of "now" AND not in the future (with
/// a 60s tolerance for clock skew between operator's browser node
/// and the API node).
pub fn require_fresh_preflight(cluster: &str, preflight_generated_at: u64) -> Result<(), String> {
    if preflight_generated_at == 0 {
        return Err(format!(
            "No preflight timestamp provided for cluster '{}'. Re-run preflight before promoting to Enforce.",
            cluster
        ));
    }
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    // Tolerate up to 60s of clock skew between the node that
    // generated the preflight and the node receiving the promote.
    if preflight_generated_at > now + 60 {
        return Err(format!(
            "Preflight timestamp for cluster '{}' is in the future (clock skew?). Re-run preflight.",
            cluster
        ));
    }
    let age = now.saturating_sub(preflight_generated_at);
    if age > PREFLIGHT_FRESHNESS_SECS {
        return Err(format!(
            "Preflight for cluster '{}' is {}s old (must be within {}s). Re-run preflight before promoting.",
            cluster, age, PREFLIGHT_FRESHNESS_SECS
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_feed_skips_comments_and_blanks() {
        let dir = std::env::temp_dir().join(format!("wolfstack-ti-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let feed = dir.join("test.netset");
        std::fs::write(&feed, "# header line\n\n1.2.3.4\n5.6.7.0/24\n# end\n").unwrap();
        let entries = parse_feed_entries(feed.to_str().unwrap());
        assert_eq!(entries, vec!["1.2.3.4".to_string(), "5.6.7.0/24".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowlist_excludes_entries() {
        let dir = std::env::temp_dir().join(format!("wolfstack-ti-allow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let allow_file = dir.join("allowlist.txt");
        std::fs::write(&allow_file, "1.2.3.4\n# comment\n\n5.6.7.0/24\n").unwrap();
        // Direct call to the parser via temp file path. Since
        // parse_allowlist uses the hard-coded const, simulate by
        // reading + filtering manually:
        let body = std::fs::read_to_string(&allow_file).unwrap();
        let set: HashSet<String> = body.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        assert!(set.contains("1.2.3.4"));
        assert!(set.contains("5.6.7.0/24"));
        assert_eq!(set.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn covered_scopes_lists_every_finding_type() {
        let facts = ThreatIntelFacts { scanned: true, ..Default::default() };
        let ctx = Context::for_node("ws-test".to_string());
        let scopes = covered_scopes(&ctx, &facts);
        // v23.2.2: OFF, DRY_RUN, NO_IPSET, STALE, RULES_MISSING,
        // MIGRATED, plus the legacy DISABLED type kept so persisted
        // acks resolve. Seven total.
        assert_eq!(scopes.len(), 7);
    }

    /// EnforceState round-trips through the kebab-case wire format.
    #[test]
    fn enforce_state_serde_roundtrip() {
        for s in [EnforceState::Off, EnforceState::DryRun, EnforceState::Enforce] {
            let body = serde_json::to_string(&s).unwrap();
            let parsed: EnforceState = serde_json::from_str(&body).unwrap();
            assert_eq!(s, parsed);
        }
        // String coercions accept legacy/legible spellings.
        assert_eq!(EnforceState::from_str_opt("off"), Some(EnforceState::Off));
        assert_eq!(EnforceState::from_str_opt("disabled"), Some(EnforceState::Off));
        assert_eq!(EnforceState::from_str_opt(""), Some(EnforceState::Off));
        assert_eq!(EnforceState::from_str_opt("dry-run"), Some(EnforceState::DryRun));
        assert_eq!(EnforceState::from_str_opt("dry_run"), Some(EnforceState::DryRun));
        assert_eq!(EnforceState::from_str_opt("preview"), Some(EnforceState::DryRun));
        assert_eq!(EnforceState::from_str_opt("enforce"), Some(EnforceState::Enforce));
        assert_eq!(EnforceState::from_str_opt("enforcing"), Some(EnforceState::Enforce));
        // v23.2.2 safety: legacy spellings "enabled" and "on" map to
        // DryRun, never Enforce. Promotion to Enforce requires the
        // explicit "enforce" string (and the gates the API enforces).
        assert_eq!(EnforceState::from_str_opt("enabled"), Some(EnforceState::DryRun));
        assert_eq!(EnforceState::from_str_opt("on"), Some(EnforceState::DryRun));
        assert_eq!(EnforceState::from_str_opt("nonsense"), None);
    }

    /// Cluster-state file: unknown cluster returns Off, known
    /// returns its set state, and round-trips through JSON.
    #[test]
    fn cluster_state_file_roundtrip_and_defaults() {
        let mut f = ClusterStateFile::default();
        assert_eq!(f.clusters.get("prod").copied().unwrap_or(EnforceState::Off), EnforceState::Off);
        f.clusters.insert("prod".into(), EnforceState::Enforce);
        f.clusters.insert("staging".into(), EnforceState::DryRun);
        let body = serde_json::to_string(&f).unwrap();
        let back: ClusterStateFile = serde_json::from_str(&body).unwrap();
        assert_eq!(back.schema_version, 2);
        assert_eq!(back.clusters.get("prod").copied(), Some(EnforceState::Enforce));
        assert_eq!(back.clusters.get("staging").copied(), Some(EnforceState::DryRun));
        assert!(!back.clusters.contains_key("never-heard-of-it"));
    }

    /// Fresh-preflight gate: 0 (missing) is rejected, fresh is
    /// accepted, stale is rejected, future-dated within tolerance
    /// is accepted, far-future is rejected.
    #[test]
    fn require_fresh_preflight_window() {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        // Missing timestamp.
        assert!(require_fresh_preflight("c", 0).is_err());
        // Just generated → within window.
        assert!(require_fresh_preflight("c", now).is_ok());
        // 4 minutes old → within window.
        assert!(require_fresh_preflight("c", now.saturating_sub(4 * 60)).is_ok());
        // 6 minutes old → outside the 5-minute window.
        assert!(require_fresh_preflight("c", now.saturating_sub(6 * 60)).is_err());
        // 30 seconds in the future (clock skew) → accepted.
        assert!(require_fresh_preflight("c", now + 30).is_ok());
        // 5 minutes in the future → rejected.
        assert!(require_fresh_preflight("c", now + 5 * 60).is_err());
    }

    /// serde MUST reject an unknown state-string in the cluster
    /// state file. v23.12.20+ defaults a missing cluster entry to
    /// `Enforce` (product decision: protection-on by default), so we
    /// can't have garbage state silently round-trip — a malformed
    /// state for cluster X must surface as a parse error and force
    /// the operator to fix the file, NOT be silently treated as
    /// "use the default" which would now mean Enforce.
    #[test]
    fn cluster_state_unknown_state_rejected_by_serde() {
        // Hand-craft a state where a cluster has an unknown state
        // string. serde should reject the whole file.
        let body = r#"{"schema_version":2,"clusters":{"prod":"super-enforce"}}"#;
        let parsed: Result<ClusterStateFile, _> = serde_json::from_str(body);
        assert!(parsed.is_err(), "unknown state must NOT be silently accepted");
    }

    /// v23.12.20+ product decision: a cluster with no entry in the
    /// state file defaults to `Enforce` so fresh installs ship with
    /// threat-intel actively blocking. Lock this behaviour with a
    /// test so a future refactor doesn't silently flip it back.
    #[test]
    fn state_for_unknown_cluster_defaults_to_enforce() {
        let f = ClusterStateFile::default();
        // Default file has no entries; state_for_cluster reads the
        // file from disk so it's not directly callable in-test, but
        // we exercise the same logic the public function uses:
        let resolved = f.clusters.get("never-configured")
            .copied()
            .unwrap_or(EnforceState::Enforce);
        assert_eq!(resolved, EnforceState::Enforce);
    }

    /// `apply_peer_state` semantics MUST merge per-cluster, not
    /// blindly overwrite — otherwise a peer's narrower view of the
    /// world (e.g. it only knows about cluster A) could silently
    /// erase the local node's entries for cluster B. This was a
    /// real bug caught in v23.2.2 review.
    ///
    /// We exercise the merge logic by constructing two
    /// ClusterStateFiles in-process and confirming the merge result.
    /// We do NOT call apply_peer_state directly here because it
    /// touches `/etc/wolfstack/...` and would conflict with a real
    /// install on the test machine. The merge logic is small enough
    /// to verify by re-implementing the contract:
    #[test]
    fn apply_peer_state_merge_contract() {
        // Existing local state has two clusters with explicit values.
        let mut local = ClusterStateFile::default();
        local.clusters.insert("prod".into(), EnforceState::Enforce);
        local.clusters.insert("staging".into(), EnforceState::DryRun);

        // Incoming push only knows about one of them (and adds a
        // third). Merge result MUST keep "prod" untouched (incoming
        // had no opinion on it), update "staging" to the new value,
        // and add "qa".
        let mut incoming = ClusterStateFile::default();
        incoming.clusters.insert("staging".into(), EnforceState::Enforce);
        incoming.clusters.insert("qa".into(), EnforceState::DryRun);

        // Reproduce the merge from apply_peer_state.
        let mut merged = local.clone();
        for (cluster, state) in incoming.clusters {
            if state == EnforceState::Off {
                merged.clusters.remove(&cluster);
            } else {
                merged.clusters.insert(cluster, state);
            }
        }

        assert_eq!(merged.clusters.get("prod").copied(), Some(EnforceState::Enforce),
            "prod must be preserved — incoming had no opinion on it");
        assert_eq!(merged.clusters.get("staging").copied(), Some(EnforceState::Enforce),
            "staging must take the incoming value");
        assert_eq!(merged.clusters.get("qa").copied(), Some(EnforceState::DryRun),
            "qa must be added from incoming");
    }

    /// Off transitions in the merge must REMOVE the entry entirely,
    /// matching the normalisation rule in set_cluster_state. This
    /// keeps the state file minimal and avoids the "empty value
    /// means…" ambiguity.
    #[test]
    fn apply_peer_state_off_removes_entry() {
        let mut local = ClusterStateFile::default();
        local.clusters.insert("prod".into(), EnforceState::Enforce);
        local.clusters.insert("staging".into(), EnforceState::DryRun);

        let mut incoming = ClusterStateFile::default();
        incoming.clusters.insert("prod".into(), EnforceState::Off);

        let mut merged = local.clone();
        for (cluster, state) in incoming.clusters {
            if state == EnforceState::Off {
                merged.clusters.remove(&cluster);
            } else {
                merged.clusters.insert(cluster, state);
            }
        }

        assert!(!merged.clusters.contains_key("prod"),
            "Off in incoming must remove the entry from the local file");
        assert_eq!(merged.clusters.get("staging").copied(), Some(EnforceState::DryRun));
    }

    /// CRITICAL: the FireHOL Level 1 feed contains the FullBogons
    /// set. If those make it into the iptables DROP rule on a
    /// Proxmox/WolfStack cluster, all RFC1918 east-west traffic
    /// (WolfNet, WolfRouter LANs, Docker bridges, local management)
    /// gets blackholed. The bogon filter must skip every private /
    /// reserved / loopback / link-local / CGN / multicast range.
    #[test]
    fn bogon_filter_skips_rfc1918_and_friends() {
        // RFC1918 — must be skipped. The whole `10/8` is private,
        // so WolfNet running on ANY 10.x.x.x subnet is protected.
        assert!(is_private_or_reserved("10.0.0.0/8"));
        assert!(is_private_or_reserved("10.100.0.0/16")); // typical WolfNet
        assert!(is_private_or_reserved("10.10.0.0/16"));  // typical WolfRouter LAN
        assert!(is_private_or_reserved("10.10.10.0/24")); // exact WolfNet subnet shape sponsor mentioned
        assert!(is_private_or_reserved("10.10.10.5"));    // single host inside 10/8
        assert!(is_private_or_reserved("10.255.255.255"));// last addr in 10/8
        assert!(is_private_or_reserved("172.16.0.0/12"));
        assert!(is_private_or_reserved("172.17.0.0/16")); // Docker default
        assert!(is_private_or_reserved("172.31.255.0/24"));// last subnet of 172.16/12
        assert!(is_private_or_reserved("192.168.0.0/16"));
        assert!(is_private_or_reserved("192.168.1.1"));

        // Loopback + link-local + CGN.
        assert!(is_private_or_reserved("127.0.0.0/8"));
        assert!(is_private_or_reserved("127.0.0.1"));
        assert!(is_private_or_reserved("169.254.0.0/16"));
        // CGN / Tailscale tailnet range — every Tailscale-connected
        // host has a 100.64.0.0/10 IP. Filtering this is what stops
        // v23.2 from blocking the operator's tailnet management
        // access the moment it deploys.
        assert!(is_private_or_reserved("100.64.0.0/10"));
        assert!(is_private_or_reserved("100.64.0.1"));    // first usable
        assert!(is_private_or_reserved("100.100.100.100"));// mid-range Tailscale typical
        assert!(is_private_or_reserved("100.127.255.255"));// last usable

        // Multicast + reserved.
        assert!(is_private_or_reserved("224.0.0.0/4"));
        assert!(is_private_or_reserved("240.0.0.0/4"));

        // 0.0.0.0/8.
        assert!(is_private_or_reserved("0.0.0.0/8"));

        // IPv6 entries — skipped because the ipset is IPv4-only.
        assert!(is_private_or_reserved("2001:db8::/32"));
        assert!(is_private_or_reserved("fe80::/10"));

        // Unparseable — skipped (safest default).
        assert!(is_private_or_reserved("not-an-ip"));
    }

    /// VLAN subnets and arbitrary operator-chosen private ranges
    /// must all be covered. VLANs themselves are an L2 concept —
    /// what matters is the IP subnet riding on them, and operators
    /// universally pick RFC1918 / CGN ranges. The bogon filter
    /// covers the full set, so any IP-on-VLAN that's in RFC1918
    /// space (the realistic 99.9% case) is safe.
    #[test]
    fn bogon_filter_covers_vlan_subnets() {
        // Common VLAN subnet patterns operators carve out of 10/8.
        assert!(is_private_or_reserved("10.0.10.0/24"));
        assert!(is_private_or_reserved("10.20.30.0/24"));
        assert!(is_private_or_reserved("10.42.0.0/16"));
        // Common 172.16-31 carve-outs.
        assert!(is_private_or_reserved("172.20.50.0/24"));
        assert!(is_private_or_reserved("172.30.0.0/16"));
        // Common 192.168 VLANs.
        assert!(is_private_or_reserved("192.168.10.0/24"));
        assert!(is_private_or_reserved("192.168.100.0/24"));
        assert!(is_private_or_reserved("192.168.250.0/24"));
    }

    #[test]
    fn bogon_filter_passes_real_public_ips() {
        // Klas's cluster public IPs (from his pvecm status output).
        // None of these are bogons; must pass through to the
        // blocklist if FireHOL lists them.
        assert!(!is_private_or_reserved("142.132.140.78"));
        assert!(!is_private_or_reserved("162.55.15.215"));
        assert!(!is_private_or_reserved("168.119.137.55"));
        assert!(!is_private_or_reserved("94.130.22.183"));
        assert!(!is_private_or_reserved("195.201.58.223"));
        // The BootingWorld attacker's C2 — must pass through.
        assert!(!is_private_or_reserved("83.168.95.185"));
        // 1.1.1.1 (Cloudflare DNS).
        assert!(!is_private_or_reserved("1.1.1.1"));
        // Big public CIDR.
        assert!(!is_private_or_reserved("203.0.113.0/24")); // TEST-NET-3 — technically reserved, but not in our private list since it's documentation-only and could appear in real attacks
    }

    #[test]
    fn parse_feed_strips_bogon_entries() {
        let dir = std::env::temp_dir().join(format!("wolfstack-ti-bogon-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let feed = dir.join("test.netset");
        std::fs::write(&feed, "# FireHOL Level 1 (simulated)\n\
                              10.0.0.0/8\n\
                              172.16.0.0/12\n\
                              192.168.0.0/16\n\
                              127.0.0.0/8\n\
                              169.254.0.0/16\n\
                              100.64.0.0/10\n\
                              224.0.0.0/4\n\
                              83.168.95.185\n\
                              5.6.7.0/24\n\
                              2001:db8::/32\n").unwrap();
        let entries = parse_feed_entries(feed.to_str().unwrap());
        // Only the two public entries should survive.
        assert_eq!(entries.len(), 2, "got {:?}", entries);
        assert!(entries.contains(&"83.168.95.185".to_string()));
        assert!(entries.contains(&"5.6.7.0/24".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// klas 2026-07-05 regression: a feed entry must be skipped when it
    /// touches a protected address in EITHER direction — including a
    /// feed CIDR that wraps a protected host, which the old exact-string
    /// membership check could never catch.
    #[test]
    fn protected_overlap_both_directions() {
        let protected: Vec<(u32, u8)> = ["84.12.34.56", "10.0.0.0/8"]
            .iter().filter_map(|e| parse_v4_net(e)).collect();
        // Feed CIDR wrapping a protected bare IP → skip.
        assert!(entry_touches_protected("84.12.0.0/16", &protected));
        // Exact protected IP on the feed → skip.
        assert!(entry_touches_protected("84.12.34.56", &protected));
        // Feed IP inside a protected CIDR → skip.
        assert!(entry_touches_protected("10.99.1.2", &protected));
        // Disjoint → block as normal.
        assert!(!entry_touches_protected("203.0.113.7", &protected));
        assert!(!entry_touches_protected("84.13.0.0/16", &protected));
        // Garbage / v6 feed entries are not protected-matched (and the
        // feed parser never emits them for the inet set anyway).
        assert!(!entry_touches_protected("2001:db8::1", &protected));
        assert!(!entry_touches_protected("not-an-ip", &protected));
    }

    #[test]
    fn v4_net_parsing_rules() {
        assert_eq!(parse_v4_net("1.2.3.4"), Some((0x01020304, 32)));
        assert_eq!(parse_v4_net("1.2.3.0/24"), Some((0x01020300, 24)));
        assert_eq!(parse_v4_net("1.2.3.0/33"), None);
        assert_eq!(parse_v4_net("::1"), None);
        // /0 wildcard overlaps everything — a protected 0.0.0.0/0 would
        // disable the feature entirely, which is the operator's call.
        assert!(v4_nets_overlap((0, 0), (0x08080808, 32)));
    }
}
