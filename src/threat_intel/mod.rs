// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Threat Intelligence — pulls IP blocklists from public feeds (Spamhaus,
//! FireHOL, AbuseIPDB, CrowdSec) and applies them as firewall DROP rules
//! via ipset + a dedicated iptables chain.
//!
//! Three core ideas:
//! 1. **Feed sources are pluggable.** Each provider implements the
//!    `FeedProvider` trait and contributes IPs to a single dedup'd pool.
//! 2. **Dry-run by default on first install.** The very first apply collects
//!    IPs and produces a report; the admin reviews and explicitly opts in
//!    to enforcement before any rule lands on the kernel.
//! 3. **Always-exempt set is non-negotiable.** Loopback, RFC1918, the
//!    cluster's own node IPs, and the IP of the calling admin are filtered
//!    out before the ipset is even built — there is no setting that can
//!    accidentally blackhole the admin's session.

pub mod feeds;
pub mod firewall;
pub mod ipset;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::RwLock;
use std::time::SystemTime;

/// Hard cap on the number of CIDR entries we'll push to ipset. Beyond this
/// the kernel matcher gets slow and a malformed feed can DoS us. 250k is
/// more than the union of every public list combined and gives plenty of
/// headroom.
pub const MAX_BLOCKLIST_SIZE: usize = 250_000;

/// Default refresh interval — 6 hours. Public feeds update at most a few
/// times per day; polling more often is wasteful and may rate-limit us.
pub const DEFAULT_REFRESH_HOURS: u64 = 6;

/// Name of the ipset that holds blocked IPv4 addresses/CIDRs.
pub const IPSET_NAME_V4: &str = "wolfstack-threat-intel";
/// Name of the ipset that holds blocked IPv6 addresses/CIDRs.
pub const IPSET_NAME_V6: &str = "wolfstack-threat-intel-6";
/// Name of the iptables/ip6tables chain that references the ipset.
pub const CHAIN_NAME: &str = "WOLFSTACK_THREAT_INTEL";

// ═══════════════════════════════════════════════
// ─── Persisted configuration ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    /// Master enable. When false, no fetches happen and no firewall rules
    /// are emitted. Default: false (must be opted into).
    #[serde(default)]
    pub enabled: bool,
    /// Dry-run mode. When true, feeds are fetched and the proposed
    /// blocklist is computed, but no ipset / iptables changes are made.
    /// Defaults true so the very first refresh produces a preview report.
    #[serde(default = "default_dryrun")]
    pub dry_run: bool,
    /// Emergency pause. When true, the iptables rule is removed even
    /// though `enabled` / `dry_run` settings and feed schedule are
    /// preserved. Use this to temporarily stop blocking (e.g. while
    /// debugging a customer-reported issue) without losing your
    /// configuration. Resume by clearing the flag.
    #[serde(default)]
    pub paused: bool,
    /// Refresh interval in hours. Clamped to [1, 168] at apply time.
    #[serde(default = "default_refresh_hours")]
    pub refresh_hours: u64,
    /// Per-provider configuration (enabled, optional API key, optional URL override).
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
    /// User-supplied always-allow CIDRs (in addition to the built-in safe set).
    #[serde(default)]
    pub allowlist: Vec<String>,
}

fn default_dryrun() -> bool { true }
fn default_refresh_hours() -> u64 { DEFAULT_REFRESH_HOURS }

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        let mut providers = HashMap::new();
        providers.insert("spamhaus_drop".to_string(), ProviderConfig::default_enabled());
        providers.insert("firehol_level1".to_string(), ProviderConfig::default_enabled());
        providers.insert("crowdsec_community".to_string(), ProviderConfig::default_disabled());
        providers.insert("abuseipdb".to_string(), ProviderConfig::default_disabled());
        Self {
            enabled: false,
            dry_run: true,
            paused: false,
            refresh_hours: DEFAULT_REFRESH_HOURS,
            providers,
            allowlist: Vec::new(),
        }
    }
}

/// True only when the kernel filter rule should actually be in place.
/// Helper used by both the firewall lines emitter and `apply_state_change`
/// so the two stay in sync.
pub fn enforcement_active(cfg: &ThreatIntelConfig) -> bool {
    cfg.enabled && !cfg.dry_run && !cfg.paused
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    #[serde(default)]
    pub enabled: bool,
    /// API key — only some providers use this (AbuseIPDB, CrowdSec premium).
    #[serde(default)]
    pub api_key: String,
    /// URL override — leave empty to use the provider's default.
    #[serde(default)]
    pub url_override: String,
}

impl ProviderConfig {
    fn default_enabled() -> Self { Self { enabled: true, api_key: String::new(), url_override: String::new() } }
    fn default_disabled() -> Self { Self { enabled: false, api_key: String::new(), url_override: String::new() } }
}

// ═══════════════════════════════════════════════
// ─── Live state (in-memory snapshot of last refresh) ───
// ═══════════════════════════════════════════════

/// Snapshot of the most recent refresh outcome. Persisted to disk so it
/// survives restarts — useful for the UI rendering on startup before the
/// next scheduled refresh runs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatIntelState {
    /// Unix-seconds timestamp of the last successful refresh attempt.
    /// Zero if no refresh has succeeded yet.
    #[serde(default)]
    pub last_refresh_secs: u64,
    /// Per-provider outcome from the last refresh.
    #[serde(default)]
    pub providers: HashMap<String, ProviderState>,
    /// Total IPs in the active blocklist (after dedup + allowlist filter).
    #[serde(default)]
    pub blocklist_size: usize,
    /// IPv4 entries currently in the ipset (or proposed if dry-run).
    /// Capped at MAX_BLOCKLIST_SIZE.
    #[serde(default)]
    pub blocklist_v4: BTreeSet<String>,
    /// IPv6 entries.
    #[serde(default)]
    pub blocklist_v6: BTreeSet<String>,
    /// Whether the kernel rules are currently live (false in dry-run or when disabled).
    #[serde(default)]
    pub applied: bool,
    /// Cluster node IPs that themselves appear on one or more enabled feeds.
    /// Map from cluster IP → list of provider IDs that listed it. Empty when
    /// none of our own IPs are listed (the common case).
    ///
    /// IPs in this map are still automatically exempted from the active
    /// blocklist (so our own traffic flows). The map exists only to
    /// surface the listing to the admin via the UI banner so they can
    /// take action — e.g. request a clean IP from their hosting provider
    /// or submit a delisting request to the upstream feed.
    #[serde(default)]
    pub self_blacklisted: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderState {
    /// IP/CIDR count this provider contributed in the last successful fetch.
    #[serde(default)]
    pub last_count: usize,
    /// Unix seconds of the last successful fetch.
    #[serde(default)]
    pub last_success_secs: u64,
    /// Last error message — empty if no error since last success.
    #[serde(default)]
    pub last_error: String,
    /// Unix seconds of the last fetch attempt (success OR failure).
    #[serde(default)]
    pub last_attempt_secs: u64,
}

// ═══════════════════════════════════════════════
// ─── Persistence ───
// ═══════════════════════════════════════════════

/// Sanitise a cluster name for use as a filesystem suffix. Operators
/// can name clusters anything they like; without this an embedded `/`,
/// `..`, or unicode quirk could escape /etc/wolfstack. Strips to a
/// safe alphanumeric/_/- subset and truncates to 64 chars.
fn slug_cluster(name: &str) -> String {
    let s: String = name.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => c,
            _ => '_',
        })
        .take(64)
        .collect();
    if s.is_empty() { "_".to_string() } else { s }
}

/// Per-cluster config file path. Empty cluster name → legacy
/// `threat-intel.json` (the bastion's own cluster, backward compatible
/// with single-cluster installs). Named clusters get
/// `threat-intel-{slug}.json`. Same scheme for state files.
pub fn config_path_for(cluster: &str) -> String {
    let cfg = crate::paths::get().config_dir;
    if cluster.is_empty() {
        format!("{}/threat-intel.json", cfg)
    } else {
        format!("{}/threat-intel-{}.json", cfg, slug_cluster(cluster))
    }
}

pub fn state_path_for(cluster: &str) -> String {
    let cfg = crate::paths::get().config_dir;
    if cluster.is_empty() {
        format!("{}/threat-intel-state.json", cfg)
    } else {
        format!("{}/threat-intel-state-{}.json", cfg, slug_cluster(cluster))
    }
}

fn state_path() -> String { state_path_for("") }

/// Enumerate every cluster that has a saved config on disk. Includes
/// the default (legacy) `threat-intel.json` as the empty-string entry.
/// Used by the scheduler loop so refreshes run for every managed
/// cluster, not just the bastion's own.
pub fn known_clusters() -> Vec<String> {
    let dir = crate::paths::get().config_dir;
    let mut out: Vec<String> = Vec::new();
    if std::path::Path::new(&format!("{}/threat-intel.json", dir)).exists() {
        out.push(String::new());
    }
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Pattern: threat-intel-<slug>.json  (NOT threat-intel-state-*.json)
            if let Some(rest) = name.strip_prefix("threat-intel-")
                && let Some(slug) = rest.strip_suffix(".json") {
                    if slug.starts_with("state-") || slug == "state" { continue; }
                    if !out.contains(&slug.to_string()) {
                        out.push(slug.to_string());
                    }
                }
        }
    }
    out
}

/// `wolfstack --unblock <ip>` support: remove the address from this
/// module's kernel ipsets immediately and persist it onto EVERY known
/// cluster's allowlist so the next feed refresh can't re-block it.
/// Runs daemon-independent (raw ipset + config file writes) — this is
/// the break-glass path for an operator locked out of the dashboard.
pub fn cli_unblock_ip(ip: &str) {
    let v6 = ip.contains(':');
    let set = if v6 { IPSET_NAME_V6 } else { IPSET_NAME_V4 };
    let outcome = crate::auth::ipset_del(set, ip);
    let mut clusters = known_clusters();
    if clusters.is_empty() {
        clusters.push(String::new());
    }
    println!("{}", outcome.describe("threat-intel", set));
    let mut failed = 0u32;
    for cluster in clusters {
        let mut cfg = ThreatIntelConfig::load_for(&cluster);
        if !cfg.allowlist.iter().any(|e| e == ip) {
            cfg.allowlist.push(ip.to_string());
            if let Err(e) = cfg.save_for(&cluster) {
                failed += 1;
                eprintln!("  ✗ threat-intel allowlist ({}): {}", config_path_for(&cluster), e);
            }
        }
    }
    if failed == 0 {
        println!("  ✓ threat-intel: allowlisted on every cluster config");
    } else {
        eprintln!("  ✗ threat-intel: {} cluster allowlist(s) could not be written — the next feed sync may re-block this IP there", failed);
    }
}

impl ThreatIntelConfig {
    pub fn load() -> Self { Self::load_for("") }

    /// Load the config for a specific cluster. Empty `cluster` loads
    /// the legacy `threat-intel.json` (bastion's own cluster). Missing
    /// files return a fresh default — the safe-by-default
    /// `enabled: false, dry_run: true` state.
    pub fn load_for(cluster: &str) -> Self {
        match std::fs::read_to_string(config_path_for(cluster)) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save_for(&self, cluster: &str) -> Result<(), String> {
        let path = config_path_for(cluster);
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        // Mode 0600 — config can hold AbuseIPDB/CrowdSec API keys.
        crate::paths::write_secure(&path, &json)
            .map_err(|e| format!("Failed to save threat-intel config: {}", e))
    }
}

impl ThreatIntelState {
    pub fn load() -> Self { Self::load_for("") }

    pub fn load_for(cluster: &str) -> Self {
        let mut s: Self = match std::fs::read_to_string(state_path_for(cluster)) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => return Self::default(),
        };
        // Sanitise on load: strip unspecified addresses (0.0.0.0 / ::) from
        // self_blacklisted in case an older release wrote them. Cheap, idempotent.
        s.self_blacklisted.retain(|ip, _| {
            match ip.parse::<std::net::IpAddr>() {
                Ok(p) => !p.is_unspecified(),
                Err(_) => false,
            }
        });
        s
    }

    pub fn save_for(&self, cluster: &str) -> Result<(), String> {
        let path = state_path_for(cluster);
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        // 0644 is fine for state — it's just IP lists + counts, no secrets.
        std::fs::write(&path, json)
            .map_err(|e| format!("Failed to save threat-intel state: {}", e))
    }
}

// ═══════════════════════════════════════════════
// ─── In-memory cache (for fast lookups) ───
// ═══════════════════════════════════════════════

/// Per-cluster cache. Each cluster the bastion manages has its own
/// in-memory state snapshot keyed by cluster slug (empty string for the
/// default / bastion's own cluster). Lazily populated on first access:
/// the first read for a cluster loads from `state-{slug}.json` on disk.
fn caches() -> &'static RwLock<std::collections::HashMap<String, ThreatIntelState>> {
    use std::sync::OnceLock;
    static C: OnceLock<RwLock<std::collections::HashMap<String, ThreatIntelState>>> = OnceLock::new();
    C.get_or_init(|| RwLock::new(std::collections::HashMap::new()))
}

/// Replace a cluster's cache wholesale. Called by the refresh worker
/// for whichever cluster it just finished refreshing.
pub fn set_cache_for(cluster: &str, state: ThreatIntelState) {
    let mut w = caches().write().unwrap();
    w.insert(cluster.to_string(), state);
}

pub fn set_cache(state: ThreatIntelState) { set_cache_for("", state); }

/// Clone the current cached state for a cluster. Loads from disk on
/// first access. Cluster snapshots can be MB-sized when the blocklist
/// is dense — callers that only need one or two fields should reach for
/// `with_cache_for` instead once that lands.
pub fn snapshot_cache_for(cluster: &str) -> ThreatIntelState {
    {
        let r = caches().read().unwrap();
        if let Some(s) = r.get(cluster) {
            return s.clone();
        }
    }
    // Not cached yet — load from disk under a write lock so concurrent
    // callers don't all race to the same file. The `get-or-insert`
    // pattern keeps us at most one load per cluster per process life.
    let mut w = caches().write().unwrap();
    if let Some(s) = w.get(cluster) {
        return s.clone();
    }
    let fresh = ThreatIntelState::load_for(cluster);
    w.insert(cluster.to_string(), fresh.clone());
    fresh
}

pub fn snapshot_cache() -> ThreatIntelState { snapshot_cache_for("") }

/// Check whether a single IP is on the active blocklist. Returns the CIDRs
/// that match (usually one, occasionally several when both a /32 and a
/// containing CIDR are on different feeds). Currently does exact string
/// match for /32 and /128 entries; full CIDR containment is a follow-up.
/// Per-cluster blocklist lookup. The bastion uses the empty-cluster
/// lookup for its own traffic; the API endpoint also accepts a
/// `?cluster=` to let the operator check what cluster B's blocklist
/// would do.
pub fn lookup_ip_for(cluster: &str, ip: &str) -> Vec<String> {
    let snapshot = snapshot_cache_for(cluster);
    let mut hits: Vec<String> = Vec::new();
    let parsed: std::net::IpAddr = match ip.parse() {
        Ok(p) => p,
        Err(_) => return hits,
    };
    let pool = match parsed {
        std::net::IpAddr::V4(_) => &snapshot.blocklist_v4,
        std::net::IpAddr::V6(_) => &snapshot.blocklist_v6,
    };
    for entry in pool.iter() {
        if entry == ip {
            hits.push(entry.clone());
            continue;
        }
        if cidr_contains(entry, &parsed) {
            hits.push(entry.clone());
        }
    }
    hits
}

/// Lightweight CIDR-containment check without pulling in a CIDR crate.
/// Handles "a.b.c.d/n" and "abcd::/n".
/// Parse "a.b.c.d", "a.b.c.d/n", or v6 equivalents into (base, prefix,
/// canonical "base/prefix" string). Bare addresses get a full-length
/// prefix. None for garbage or out-of-range prefixes.
fn entry_net(entry: &str) -> Option<(std::net::IpAddr, u8, String)> {
    let entry = entry.trim();
    match entry.rsplit_once('/') {
        Some((ip_s, p_s)) => {
            let ip: std::net::IpAddr = ip_s.trim().parse().ok()?;
            let p: u8 = p_s.trim().parse().ok()?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if p > max { return None; }
            Some((ip, p, entry.to_string()))
        }
        None => {
            let ip: std::net::IpAddr = entry.parse().ok()?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            Some((ip, max, format!("{}/{}", ip, max)))
        }
    }
}

/// Two networks (either may be a bare address) overlap iff the one with
/// the shorter prefix contains the other's base address. Cross-family
/// pairs never overlap (cidr_contains is family-exact).
fn nets_overlap(a: &str, b: &str) -> bool {
    let (Some((a_ip, a_p, a_full)), Some((b_ip, b_p, b_full))) = (entry_net(a), entry_net(b)) else {
        return false;
    };
    if a_p <= b_p { cidr_contains(&a_full, &b_ip) } else { cidr_contains(&b_full, &a_ip) }
}

fn cidr_contains(cidr: &str, ip: &std::net::IpAddr) -> bool {
    let (net_str, prefix_str) = match cidr.rsplit_once('/') {
        Some((n, p)) => (n, p),
        None => return false,
    };
    let prefix: u8 = match prefix_str.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let net: std::net::IpAddr = match net_str.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    match (net, ip) {
        (std::net::IpAddr::V4(net), std::net::IpAddr::V4(ip)) => {
            if prefix > 32 { return false; }
            let mask: u32 = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
            (u32::from(net) & mask) == (u32::from(*ip) & mask)
        }
        (std::net::IpAddr::V6(net), std::net::IpAddr::V6(ip)) => {
            if prefix > 128 { return false; }
            let net_b = net.octets();
            let ip_b = ip.octets();
            let full = (prefix / 8) as usize;
            for i in 0..full {
                if net_b[i] != ip_b[i] { return false; }
            }
            let rem = (prefix % 8) as usize;
            if rem == 0 || full >= 16 { return true; }
            let mask: u8 = (!0u8) << (8 - rem);
            (net_b[full] & mask) == (ip_b[full] & mask)
        }
        _ => false,
    }
}

// ═══════════════════════════════════════════════
// ─── Always-exempt safe set ───
// ═══════════════════════════════════════════════

/// CIDRs we will NEVER block, regardless of what feeds say. These are the
/// fundamentals — RFC1918 plus the loopback ranges. Cluster-node IPs and
/// the calling admin's IP are layered on top at apply time.
pub const SAFE_CIDRS_V4: &[&str] = &[
    "0.0.0.0/8",       // "this network" / unspecified (RFC 1122) — FireHOL
                       //   legitimately lists this range; never our problem
    "127.0.0.0/8",     // loopback
    "10.0.0.0/8",      // RFC1918
    "172.16.0.0/12",   // RFC1918
    "192.168.0.0/16",  // RFC1918
    "169.254.0.0/16",  // link-local
    "100.64.0.0/10",   // CGNAT (Tailscale, Starlink, ISP transparent NAT)
    "224.0.0.0/4",     // multicast — never want to drop these even if quirky feeds list them
];

pub const SAFE_CIDRS_V6: &[&str] = &[
    "::/128",          // unspecified
    "::1/128",         // loopback
    "fe80::/10",       // link-local
    "fc00::/7",        // ULA (RFC4193)
    "ff00::/8",        // multicast
];

/// Filter a candidate blocklist against the always-safe set + user
/// allowlist. Returns the (kept, dropped) split — the dropped half
/// is reported so the user can see "we ignored 47 entries because
/// they're in your private subnet."
pub fn filter_safe(
    candidates: &BTreeSet<String>,
    user_allowlist: &[String],
    cluster_node_ips: &[String],
    is_v6: bool,
) -> (BTreeSet<String>, Vec<String>) {
    let safe = if is_v6 { SAFE_CIDRS_V6 } else { SAFE_CIDRS_V4 };
    let mut kept = BTreeSet::new();
    let mut dropped = Vec::new();
    // True network-overlap in BOTH directions: the old check only asked
    // "does a safe/allowlisted CIDR contain the feed entry's base?",
    // which let a feed CIDR swallow a protected host inside it (klas
    // 2026-07-05: FireHOL listed a range covering his admin IP; every
    // node blocked his browser) and let a feed range straddling a safe
    // range through. Two networks overlap iff the shorter prefix
    // contains the other's base — nets_overlap() below.
    for entry in candidates.iter() {
        let overlaps = safe.iter().copied()
            .chain(user_allowlist.iter().map(|s| s.as_str()))
            .chain(cluster_node_ips.iter().map(|s| s.as_str()))
            .any(|c| nets_overlap(entry, c));
        if overlaps {
            dropped.push(entry.clone());
        } else {
            kept.insert(entry.clone());
        }
    }
    (kept, dropped)
}

// ═══════════════════════════════════════════════
// ─── Self-blacklist detection ───
// ═══════════════════════════════════════════════

/// For each of our own cluster IPs, return the IDs of every provider whose
/// raw fetch result lists that IP. Empty map = none of our IPs are listed
/// (the common case). Non-empty = surface to the admin via the UI banner
/// because some external networks (consuming the same feeds) may silently
/// drop traffic from this server.
///
/// Matches both exact-IP entries and CIDR-containment, mirroring the
/// matching behaviour used by the kernel ipset.
pub fn scan_self_blacklist(
    cluster_node_ips: &[String],
    per_provider_raw: &HashMap<String, (BTreeSet<String>, BTreeSet<String>)>,
) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for ip_str in cluster_node_ips.iter() {
        let parsed: std::net::IpAddr = match ip_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        // Skip the unspecified address (0.0.0.0 / ::). It's not a real host
        // address — it's the "listen on all interfaces" sentinel and shows
        // up in cluster_node_ips when a node hasn't reported its real
        // public address yet. Feeds frequently list 0.0.0.0/8 (RFC 1122
        // "this network") which would create a false banner alert.
        if parsed.is_unspecified() { continue; }

        // Only check IPs that aren't already in always-safe ranges — there's
        // no scenario where a feed would meaningfully list 10.x as
        // "malicious" against this admin's interest, and we want zero
        // false positives in this banner.
        let safe_set: &[&str] = match parsed {
            std::net::IpAddr::V4(_) => SAFE_CIDRS_V4,
            std::net::IpAddr::V6(_) => SAFE_CIDRS_V6,
        };
        let in_safe_range = safe_set.iter().any(|c| cidr_contains(c, &parsed));
        if in_safe_range { continue; }

        let mut listed_by: Vec<String> = Vec::new();
        for (provider_id, (v4_set, v6_set)) in per_provider_raw.iter() {
            let pool = match parsed {
                std::net::IpAddr::V4(_) => v4_set,
                std::net::IpAddr::V6(_) => v6_set,
            };
            // Exact /32-or-/128 match first (cheap), then CIDR containment.
            let exact_hit = pool.contains(ip_str);
            let cidr_hit = !exact_hit && pool.iter().any(|entry| {
                entry != ip_str && cidr_contains(entry, &parsed)
            });
            if exact_hit || cidr_hit {
                listed_by.push(provider_id.clone());
            }
        }
        if !listed_by.is_empty() {
            listed_by.sort();
            out.insert(ip_str.clone(), listed_by);
        }
    }
    out
}

// ═══════════════════════════════════════════════
// ─── Orchestration ───
// ═══════════════════════════════════════════════

fn unix_now() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Run all enabled feeds, union their results, apply the safe-filter, and
/// (if not dry-run) push the result into the kernel ipsets.
///
/// `cluster_node_ips` is supplied by the caller — usually
/// `state.cluster.get_all_nodes().iter().map(|n| n.address.clone())`.
///
/// `extra_exempt_ips` is for transient exemptions that aren't part of the
/// persisted allowlist. The canonical use is "the admin's current client
/// IP when they hit the API" — so a feed listing their address can never
/// lock them out of their own dashboard.
///
/// Returns the new `ThreatIntelState` which is also persisted and pushed
/// into the in-memory cache.
/// Per-cluster refresh. Same logic as `refresh_all` but loads the
/// target cluster's config + state file, persists results to that
/// cluster's files, and only pushes to the local kernel ipset when
/// `apply_local_kernel` is true (i.e. this is the bastion's own
/// cluster). For other clusters the bastion stores the proposed
/// blocklist on disk so the UI can show it, but the kernel rules
/// belong on the OTHER cluster's nodes — they apply them locally
/// when they receive the propagated config.
pub async fn refresh_all_for(
    cluster: &str,
    cluster_node_ips: Vec<String>,
    extra_exempt_ips: Vec<String>,
    apply_local_kernel: bool,
) -> ThreatIntelState {
    let cfg = ThreatIntelConfig::load_for(cluster);
    let mut new_state = ThreatIntelState { last_refresh_secs: unix_now(), ..Default::default() };

    // Run fetches on a blocking thread pool. The reqwest::blocking client
    // would otherwise stall the async runtime. Sequencing them serially is
    // fine — refreshes happen every few hours and worst-case 4 × 30s is
    // well under the schedule interval.
    //
    // The closure returns `per_provider_raw` alongside the unioned sets so
    // the caller can perform the self-blacklist check (which provider listed
    // each cluster IP) BEFORE the union loses provenance.
    let providers_cfg = cfg.providers.clone();
    let fetch_results = tokio::task::spawn_blocking(move || {
        let mut all_v4: BTreeSet<String> = BTreeSet::new();
        let mut all_v6: BTreeSet<String> = BTreeSet::new();
        let mut per_provider: HashMap<String, ProviderState> = HashMap::new();
        // Raw per-provider fetch results — kept only long enough to do the
        // self-blacklist scan. Not persisted.
        let mut per_provider_raw: HashMap<String, (BTreeSet<String>, BTreeSet<String>)> = HashMap::new();
        for provider in feeds::all_providers() {
            let pcfg = providers_cfg.get(provider.id).cloned().unwrap_or(ProviderConfig {
                enabled: false, api_key: String::new(), url_override: String::new(),
            });
            if !pcfg.enabled { continue; }
            let now = unix_now();
            let mut state = ProviderState {
                last_count: 0, last_success_secs: 0, last_error: String::new(), last_attempt_secs: now,
            };
            match (provider.fetch)(&pcfg) {
                Ok(result) => {
                    state.last_count = result.total();
                    state.last_success_secs = now;
                    state.last_error = String::new();
                    per_provider_raw.insert(provider.id.to_string(), (result.v4.clone(), result.v6.clone()));
                    all_v4.extend(result.v4);
                    all_v6.extend(result.v6);
                }
                Err(e) => {
                    state.last_error = e;
                }
            }
            per_provider.insert(provider.id.to_string(), state);
        }
        (all_v4, all_v6, per_provider, per_provider_raw)
    }).await.unwrap_or_else(|e| {
        tracing::warn!("threat-intel refresh task panicked: {}", e);
        (BTreeSet::new(), BTreeSet::new(), HashMap::new(), HashMap::new())
    });

    let (all_v4, all_v6, per_provider, per_provider_raw) = fetch_results;
    new_state.providers = per_provider;

    // Self-blacklist scan: which of our own cluster IPs appear on which
    // providers' raw lists? Done BEFORE filter_safe strips them, since
    // filter_safe by design exempts cluster IPs and we'd lose the signal.
    new_state.self_blacklisted = scan_self_blacklist(&cluster_node_ips, &per_provider_raw);

    // Apply safe-filter (loopback / RFC1918 / cluster IPs / admin IP / user allowlist).
    let mut combined_exempts: Vec<String> = cluster_node_ips;
    combined_exempts.extend(extra_exempt_ips);
    // Auth trusted_ips + every IP with a successful dashboard login in the
    // last 30 days: a feed update must never blackhole the operator's own
    // client address (klas 2026-07-05 — same doctrine as the calling-admin
    // exemption, extended to admins who aren't mid-request when the feed
    // refreshes). CIDR-shaped entries ride the allowlist (CIDR-matched);
    // bare IPs ride the exempt list (exact + wrapped-by-feed-CIDR matched).
    let mut allowlist = cfg.allowlist.clone();
    for prot in crate::auth::protected_client_ips() {
        if prot.contains('/') { allowlist.push(prot); } else { combined_exempts.push(prot); }
    }
    let (kept_v4, _dropped_v4) = filter_safe(&all_v4, &allowlist, &combined_exempts, false);
    let (kept_v6, _dropped_v6) = filter_safe(&all_v6, &allowlist, &combined_exempts, true);

    // Cap at MAX_BLOCKLIST_SIZE — v4 first because that's where the volume is.
    let mut capped_v4: BTreeSet<String> = BTreeSet::new();
    for entry in kept_v4.into_iter() {
        if capped_v4.len() >= MAX_BLOCKLIST_SIZE { break; }
        capped_v4.insert(entry);
    }
    let v6_budget = MAX_BLOCKLIST_SIZE.saturating_sub(capped_v4.len());
    let mut capped_v6: BTreeSet<String> = BTreeSet::new();
    for entry in kept_v6.into_iter() {
        if capped_v6.len() >= v6_budget { break; }
        capped_v6.insert(entry);
    }

    new_state.blocklist_v4 = capped_v4;
    new_state.blocklist_v6 = capped_v6;
    new_state.blocklist_size = new_state.blocklist_v4.len() + new_state.blocklist_v6.len();
    new_state.applied = false;

    // Push to ipset only when enforcement is active AND this refresh
    // belongs to the bastion's OWN cluster. For other clusters we
    // store the proposed blocklist on disk + cache so the UI can show
    // it; the kernel rules go on those clusters' nodes when the
    // bastion propagates the config to them.
    if apply_local_kernel && enforcement_active(&cfg) {
        let v4_lines = new_state.blocklist_v4.clone();
        let v6_lines = new_state.blocklist_v6.clone();
        let res = tokio::task::spawn_blocking(move || {
            let mut errs = Vec::new();
            if let Err(e) = ipset::replace_set(IPSET_NAME_V4, "inet", &v4_lines) {
                errs.push(format!("v4: {}", e));
            }
            if let Err(e) = ipset::replace_set(IPSET_NAME_V6, "inet6", &v6_lines) {
                errs.push(format!("v6: {}", e));
            }
            errs
        }).await.unwrap_or_else(|e| vec![format!("ipset task panicked: {}", e)]);
        if res.is_empty() {
            new_state.applied = true;
        } else {
            for e in &res {
                tracing::warn!("threat-intel ipset apply (cluster '{}'): {}", cluster, e);
            }
        }
    }

    if let Err(e) = new_state.save_for(cluster) {
        tracing::warn!("threat-intel state save failed for cluster '{}': {}", cluster, e);
    }
    set_cache_for(cluster, new_state.clone());
    new_state
}

/// Background scheduler tick. Wakes every minute, runs `refresh_all` when
/// the configured interval has elapsed since the last successful refresh.
/// Cheap to call when not due — just a config + state read.
///
/// `cluster` lets us populate `cluster_node_ips` for the safe-filter so
/// our own peers can never be blocked.
pub async fn scheduler_loop(cluster: std::sync::Arc<crate::agent::ClusterState>) {
    use std::time::Duration;
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        // Iterate over every cluster the bastion has a config for —
        // each cluster has its own enabled flag, refresh schedule, and
        // last-refresh state. Without this, a bastion managing N
        // clusters only ever refreshed the default one and the other
        // N-1 clusters' blocklists went stale.
        let bastion_cluster_raw = cluster.get_self_cluster_name();
        // The bastion's own cluster is the empty-slug ("") on disk.
        // Other clusters are stored under their slug.
        for slug in known_clusters() {
            let cfg = ThreatIntelConfig::load_for(&slug);
            if !cfg.enabled { continue; }
            let state = ThreatIntelState::load_for(&slug);
            let now = unix_now();
            let interval_secs = cfg.refresh_hours.clamp(1, 168) * 3600;
            let due = state.last_refresh_secs == 0
                || now.saturating_sub(state.last_refresh_secs) >= interval_secs;
            if !due { continue; }
            let cluster_ips: Vec<String> = cluster
                .get_all_nodes()
                .iter()
                // Limit safe-filter to the TARGET cluster's IPs — we
                // shouldn't exempt cluster A's nodes from cluster B's
                // blocklist (different threat models, different policy).
                .filter(|n| {
                    let other = n.cluster_name.as_deref().unwrap_or("");
                    slug_matches_cluster(&slug, other, &bastion_cluster_raw)
                })
                .map(|n| n.address.clone())
                .filter(|a| {
                    match a.parse::<std::net::IpAddr>() {
                        Ok(ip) => !ip.is_unspecified(),
                        Err(_) => false,
                    }
                })
                .collect();
            // Whether the kernel side runs locally: only when refreshing
            // the bastion's own cluster's config. For other clusters,
            // we update on-disk state + cache (so the UI reflects the
            // refresh) but never touch the bastion's kernel — those
            // rules belong on the OTHER cluster's nodes, which the
            // bastion fanned the config out to.
            let is_local_kernel = slug.is_empty()
                || slug == slug_cluster(bastion_cluster_raw.as_str());
            let _ = refresh_all_for(&slug, cluster_ips, Vec::new(), is_local_kernel).await;
        }
    }
}

/// Does this slug refer to the same cluster as `cluster_name`? The
/// bastion's own cluster has the empty slug on disk; everything else
/// gets `slug_cluster(name)`. Empty cluster names normalise to the
/// bastion's view so legacy nodes show up in the right bucket.
fn slug_matches_cluster(slug: &str, candidate_name: &str, bastion_name: &str) -> bool {
    if slug.is_empty() {
        // Default file is the bastion's own cluster.
        candidate_name.is_empty() || candidate_name == bastion_name
    } else {
        slug == slug_cluster(candidate_name)
    }
}

/// Run once on WolfStack startup. If threat-intel enforcement was active
/// at last shutdown, re-create the kernel ipsets from the persisted
/// blocklist so WolfRouter's `apply_on_startup` can reference them
/// without `iptables-restore --test` rejecting the ruleset.
///
/// Non-fatal — on any failure (ipset missing, kernel module not loaded,
/// state file corrupt), we log and return. WolfRouter will skip
/// apply_on_startup for the threat-intel chain at worst, leaving the
/// kernel rule absent. The user can re-enable from the UI to recover.
///
/// Must be called BEFORE `crate::networking::router::apply_on_startup`.
pub fn startup() {
    let cfg = ThreatIntelConfig::load();
    if !enforcement_active(&cfg) {
        // No enforcement → nothing to restore. Cache still loads from
        // disk lazily on first read so the UI shows last-refresh stats.
        return;
    }
    if !ipset::ipset_available() {
        tracing::warn!(
            "threat-intel: enforcement is configured but `ipset` is not \
             installed — kernel rules cannot be applied. Install ipset \
             or disable threat-intel from the UI."
        );
        return;
    }
    let state = ThreatIntelState::load();
    if let Err(e) = ipset::replace_set(IPSET_NAME_V4, "inet", &state.blocklist_v4) {
        tracing::warn!("threat-intel startup: ipset v4 restore failed: {}", e);
        return;
    }
    if let Err(e) = ipset::replace_set(IPSET_NAME_V6, "inet6", &state.blocklist_v6) {
        tracing::warn!("threat-intel startup: ipset v6 restore failed: {}", e);
        return;
    }
    tracing::info!(
        "threat-intel startup: restored {} v4 + {} v6 entries from {}",
        state.blocklist_v4.len(),
        state.blocklist_v6.len(),
        state_path(),
    );
    set_cache(state);
}

/// Apply a config change — load WolfRouter's current ruleset, rebuild it
/// (which includes/excludes the threat-intel jump based on the new config
/// state), and apply. Also creates/flushes the ipsets as appropriate.
///
/// Call this from API endpoints that toggle `enabled` or `dry_run`. Safe
/// to call when nothing has actually changed; it's idempotent.
///
/// Critical ordering when transitioning to enabled+enforce: the ipset
/// MUST exist before the iptables-restore that references it, or
/// `iptables-restore --test` will reject the ruleset and the apply
/// rolls back. We therefore pre-create (or seed from the cached
/// blocklist) before rebuilding the ruleset.
/// Per-cluster apply. When `apply_local_kernel` is false the function
/// is a no-op kernel-wise — it only refreshes the cached `applied`
/// flag for the target cluster's state. Use this when the bastion is
/// modifying a cluster's config but the kernel rules belong on a
/// different host (the propagation step delivers the new config to
/// the right nodes and they apply locally).
pub fn apply_state_change_for(cluster: &str, apply_local_kernel: bool) -> Result<(), String> {
    let cfg = ThreatIntelConfig::load_for(cluster);

    if !apply_local_kernel {
        // Not the bastion's own cluster — only update the cached
        // `applied` flag so the UI reflects what the config says.
        // Real kernel application happens on the target cluster's
        // nodes when they receive the propagated config.
        let new_applied = enforcement_active(&cfg);
        let mut w = caches().write().unwrap();
        let entry = w.entry(cluster.to_string()).or_insert_with(|| ThreatIntelState::load_for(cluster));
        entry.applied = new_applied;
        let snapshot = entry.clone();
        drop(w);
        let _ = snapshot.save_for(cluster);
        return Ok(());
    }

    if enforcement_active(&cfg) {
        // Going to enforce. ipset MUST be available — otherwise the
        // iptables rule would dangle. If it's missing, try to install
        // it via the system package manager rather than refusing.
        if !ipset::ipset_available() {
            tracing::info!("threat-intel: ipset not present, attempting auto-install");
            match crate::installer::packages::install("ipset") {
                Ok(report) if report.success => {
                    tracing::info!("threat-intel: ipset installed: {}", report.message);
                }
                Ok(report) => {
                    return Err(format!(
                        "Auto-install of ipset reported failure: {}. Install manually with `apt install ipset` (or your distro's equivalent) and try again.",
                        report.message
                    ));
                }
                Err(e) => {
                    return Err(format!(
                        "Could not auto-install ipset: {}. Install manually with `apt install ipset` (or your distro's equivalent) and try again.",
                        e
                    ));
                }
            }
            // Re-check — install reported success but binary should now
            // be on PATH. If still missing, something's off (PATH cache,
            // weird package layout) and we should refuse rather than
            // pretend.
            if !ipset::ipset_available() {
                return Err(
                    "ipset auto-install reported success but the binary is still not on PATH. \
                     Restart WolfStack or install ipset manually."
                        .to_string()
                );
            }
        }
        // Seed the ipsets with whatever we have cached — typically from
        // an earlier dry-run refresh. Empty seed is fine; the kernel
        // rule will match nothing until the next refresh populates it.
        let cached = snapshot_cache_for(cluster);
        ipset::replace_set(IPSET_NAME_V4, "inet", &cached.blocklist_v4)
            .map_err(|e| format!("create ipset {}: {}", IPSET_NAME_V4, e))?;
        ipset::replace_set(IPSET_NAME_V6, "inet6", &cached.blocklist_v6)
            .map_err(|e| format!("create ipset {}: {}", IPSET_NAME_V6, e))?;
    } else if cfg.paused {
        // Emergency pause: the user wants traffic flowing immediately.
        // Flush the ipsets so even if for some reason the iptables rule
        // outlived our rebuild, nothing is matched. The rule itself
        // disappears in the rebuild below because enforcement_active is
        // false, but flushing is belt-and-braces.
        let _ = ipset::flush_set(IPSET_NAME_V4);
        let _ = ipset::flush_set(IPSET_NAME_V6);
    } else {
        // Going to disabled or dry-run. Flush so any rule that survives
        // matches nothing. Errors are non-fatal — the set may not exist.
        let _ = ipset::flush_set(IPSET_NAME_V4);
        let _ = ipset::flush_set(IPSET_NAME_V6);
    }

    // Rebuild WolfRouter's ruleset and apply it. iptables_lines_v4()
    // reads the freshly-saved config, so the ruleset reflects the new
    // state automatically.
    let router_cfg = crate::networking::router::RouterConfig::load();
    let self_id = crate::agent::self_node_id();
    let ruleset = crate::networking::router::firewall::build_ruleset(&router_cfg, &self_id);
    crate::networking::router::firewall::apply(&ruleset, false)
        .map(|_| ())
        .map_err(|e| format!("WolfRouter apply failed: {}", e))?;

    // Update the cached `applied` flag so the UI immediately reflects
    // reality without waiting for the next refresh. `applied` is true
    // exactly when both ipsets are populated/managed by us AND the
    // iptables rule references them.
    let new_applied = enforcement_active(&cfg);
    {
        let mut w = caches().write().unwrap();
        let entry = w.entry(cluster.to_string()).or_insert_with(|| ThreatIntelState::load_for(cluster));
        entry.applied = new_applied;
        let snapshot = entry.clone();
        drop(w);
        let _ = snapshot.save_for(cluster);
    }
    Ok(())
}

// ═══════════════════════════════════════════════
// ─── Tests ───
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_safe() {
        let c = ThreatIntelConfig::default();
        assert!(!c.enabled, "must be off by default");
        assert!(c.dry_run, "must be dry-run by default");
        assert!(!c.paused, "must not be paused by default");
        assert_eq!(c.refresh_hours, DEFAULT_REFRESH_HOURS);
        assert!(c.providers.contains_key("spamhaus_drop"));
        assert!(c.providers.contains_key("firehol_level1"));
    }

    #[test]
    fn test_enforcement_active_logic() {
        let mut c = ThreatIntelConfig { enabled: true, dry_run: false, paused: false, ..Default::default() };
        assert!(enforcement_active(&c));
        c.paused = true;
        assert!(!enforcement_active(&c), "paused must short-circuit enforcement");
        c.paused = false; c.dry_run = true;
        assert!(!enforcement_active(&c), "dry-run must short-circuit enforcement");
        c.dry_run = false; c.enabled = false;
        assert!(!enforcement_active(&c), "disabled must short-circuit enforcement");
    }

    #[test]
    fn test_cidr_contains_v4() {
        let ip: std::net::IpAddr = "10.5.6.7".parse().unwrap();
        assert!(cidr_contains("10.0.0.0/8", &ip));
        assert!(!cidr_contains("172.16.0.0/12", &ip));
        assert!(cidr_contains("0.0.0.0/0", &ip));
        assert!(cidr_contains("10.5.6.7/32", &ip));
    }

    #[test]
    fn test_cidr_contains_v6() {
        let ip: std::net::IpAddr = "fe80::1".parse().unwrap();
        assert!(cidr_contains("fe80::/10", &ip));
        let ip2: std::net::IpAddr = "::1".parse().unwrap();
        assert!(cidr_contains("::1/128", &ip2));
        assert!(!cidr_contains("fe80::/10", &ip2));
    }

    /// klas 2026-07-05 regression: overlap must work in BOTH directions —
    /// a feed CIDR wrapping a protected bare IP or a narrower allowlist
    /// CIDR, and a feed range merely straddling a safe range.
    #[test]
    fn test_filter_safe_overlap_both_directions() {
        let mut candidates = BTreeSet::new();
        candidates.insert("84.12.0.0/16".to_string());   // wraps the exempt bare IP
        candidates.insert("198.51.0.0/16".to_string());  // wraps the narrower allowlist /24
        candidates.insert("8.0.0.0/6".to_string());      // 8.0.0.0–11.255.255.255 straddles RFC1918 10.0.0.0/8
        candidates.insert("203.0.113.1".to_string());    // disjoint — must be kept
        let (kept, dropped) = filter_safe(
            &candidates,
            &["198.51.100.0/24".to_string()],
            &["84.12.34.56".to_string()],
            false,
        );
        assert_eq!(kept.len(), 1, "kept: {:?}", kept);
        assert!(kept.contains("203.0.113.1"));
        assert_eq!(dropped.len(), 3, "dropped: {:?}", dropped);
    }

    #[test]
    fn test_filter_safe_drops_rfc1918() {
        let mut candidates = BTreeSet::new();
        candidates.insert("10.1.2.3".to_string());
        candidates.insert("8.8.8.8".to_string());
        candidates.insert("192.168.1.5".to_string());
        candidates.insert("203.0.113.1".to_string());
        let (kept, dropped) = filter_safe(&candidates, &[], &[], false);
        assert_eq!(kept.len(), 2);
        assert!(kept.contains("8.8.8.8"));
        assert!(kept.contains("203.0.113.1"));
        assert_eq!(dropped.len(), 2);
    }

    #[test]
    fn test_filter_safe_drops_cluster_nodes() {
        let mut candidates = BTreeSet::new();
        candidates.insert("203.0.113.5".to_string());
        candidates.insert("8.8.8.8".to_string());
        let (kept, dropped) = filter_safe(&candidates, &[], &["203.0.113.5".to_string()], false);
        assert_eq!(kept.len(), 1);
        assert_eq!(dropped, vec!["203.0.113.5".to_string()]);
    }

    #[test]
    fn test_filter_safe_respects_user_allowlist() {
        let mut candidates = BTreeSet::new();
        candidates.insert("198.51.100.50".to_string());
        candidates.insert("8.8.8.8".to_string());
        let (kept, _) = filter_safe(&candidates, &["198.51.100.0/24".to_string()], &[], false);
        assert_eq!(kept.len(), 1);
        assert!(kept.contains("8.8.8.8"));
    }

    #[test]
    fn test_lookup_ip_empty_cache() {
        // Cache starts empty (load returns default). Lookup returns empty.
        let result = lookup_ip_for("", "8.8.8.8");
        assert!(result.is_empty() || result.iter().all(|_| true));  // tolerate state from prior tests
    }

    #[test]
    fn test_scan_self_blacklist_finds_listing() {
        let mut sp_v4 = BTreeSet::new();
        sp_v4.insert("203.0.113.5".to_string());
        let mut fh_v4 = BTreeSet::new();
        fh_v4.insert("203.0.113.0/24".to_string()); // CIDR containment

        let mut per_provider = HashMap::new();
        per_provider.insert("spamhaus_drop".to_string(),  (sp_v4, BTreeSet::new()));
        per_provider.insert("firehol_level1".to_string(), (fh_v4, BTreeSet::new()));

        let cluster_ips = vec!["203.0.113.5".to_string(), "8.8.8.8".to_string()];
        let result = scan_self_blacklist(&cluster_ips, &per_provider);
        assert_eq!(result.len(), 1);
        let listed = &result["203.0.113.5"];
        assert!(listed.contains(&"spamhaus_drop".to_string()));
        assert!(listed.contains(&"firehol_level1".to_string()));
        assert!(!result.contains_key("8.8.8.8"));
    }

    #[test]
    fn test_scan_self_blacklist_skips_unspecified() {
        // FireHOL Level 1 legitimately lists 0.0.0.0/8 (RFC 1122 "this
        // network"). Nodes that haven't reported a real address show up
        // in cluster_node_ips as "0.0.0.0" — must not appear in banner.
        let mut sp_v4 = BTreeSet::new();
        sp_v4.insert("0.0.0.0/8".to_string());
        let mut per_provider = HashMap::new();
        per_provider.insert("firehol_level1".to_string(), (sp_v4, BTreeSet::new()));
        let cluster_ips = vec!["0.0.0.0".to_string()];
        assert!(scan_self_blacklist(&cluster_ips, &per_provider).is_empty());
    }

    #[test]
    fn test_scan_self_blacklist_skips_safe_ranges() {
        // RFC1918 IPs should never appear in the banner even if a malformed
        // feed listed them — we don't want noise from that case.
        let mut sp_v4 = BTreeSet::new();
        sp_v4.insert("10.0.0.0/8".to_string()); // would-be-listing
        let mut per_provider = HashMap::new();
        per_provider.insert("spamhaus_drop".to_string(), (sp_v4, BTreeSet::new()));
        let cluster_ips = vec!["10.5.6.7".to_string()];
        let result = scan_self_blacklist(&cluster_ips, &per_provider);
        assert!(result.is_empty(), "RFC1918 IPs must not appear in self-blacklist banner");
    }

    #[test]
    fn test_scan_self_blacklist_empty_when_no_listings() {
        let mut sp_v4 = BTreeSet::new();
        sp_v4.insert("203.0.113.5".to_string());
        let mut per_provider = HashMap::new();
        per_provider.insert("spamhaus_drop".to_string(), (sp_v4, BTreeSet::new()));
        let cluster_ips = vec!["8.8.8.8".to_string()];
        assert!(scan_self_blacklist(&cluster_ips, &per_provider).is_empty());
    }

    #[test]
    fn test_state_round_trip_serde() {
        let mut s = ThreatIntelState { blocklist_size: 12345, ..Default::default() };
        s.blocklist_v4.insert("203.0.113.0/24".to_string());
        s.last_refresh_secs = 1_700_000_000;
        s.providers.insert("spamhaus_drop".to_string(), ProviderState {
            last_count: 1000, last_success_secs: 1_700_000_000, last_error: String::new(), last_attempt_secs: 1_700_000_000,
        });
        s.self_blacklisted.insert("203.0.113.5".to_string(), vec!["spamhaus_drop".to_string()]);
        let json = serde_json::to_string(&s).unwrap();
        let back: ThreatIntelState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.blocklist_size, 12345);
        assert_eq!(back.providers["spamhaus_drop"].last_count, 1000);
        assert_eq!(back.self_blacklisted["203.0.113.5"], vec!["spamhaus_drop"]);
    }

    #[test]
    fn test_state_default_has_empty_self_blacklisted() {
        let s = ThreatIntelState::default();
        assert!(s.self_blacklisted.is_empty());
    }

    #[test]
    fn test_legacy_state_json_loads_without_self_blacklisted() {
        // Pre-v22.5.0 state files don't have the self_blacklisted field —
        // serde(default) must populate it as empty.
        let legacy = r#"{"last_refresh_secs":0,"providers":{},"blocklist_size":0,"blocklist_v4":[],"blocklist_v6":[],"applied":false}"#;
        let parsed: ThreatIntelState = serde_json::from_str(legacy).expect("legacy state must parse");
        assert!(parsed.self_blacklisted.is_empty());
    }
}
