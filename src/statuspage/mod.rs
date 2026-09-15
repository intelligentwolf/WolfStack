// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Status Page — built-in uptime monitoring with public-facing status pages
//!
//! Supports **multiple status pages**, each with:
//! - A unique slug (e.g. `/status/wolfgrid`, `/status/wolfterritories`)
//! - Its own title, branding, and set of services
//! - Global pool of monitors (HTTP, TCP, Ping, Container) shared across pages
//! - Automatic incident management per page
//! - 90-day uptime history with daily aggregation

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use crate::node_identity::PeerAuth;

/// Consecutive failed checks before a monitor is considered Down (vs
/// Degraded). Drives both the status computation and the "N consecutive
/// failed checks" wording in the down notification.
const DOWN_THRESHOLD: usize = 3;

fn config_file() -> String { crate::paths::get().statuspage_config }
fn uptime_file() -> String { crate::paths::get().statuspage_uptime }

// ─── Shared HTTP clients ───
//
// Same pattern as src/wolfrun/mod.rs (fixed in v19.8.1). Building a
// `reqwest::Client` per call leaks: each client owns its own
// keep-alive pool, and dropping the client strands idle connections
// that the remote eventually FINs — sockets then sit in CLOSE_WAIT
// on our side until the fd is forcibly reclaimed. One pool for the
// lifetime of the process, reused by every call site in this module,
// eliminates that accumulation.
//
// Two clients because the cluster-RPC path wants a uniform 10s
// timeout, while monitor HTTP checks set their timeout per-request
// from the user-configured `timeout_secs` (different per monitor)
// via RequestBuilder::timeout.

static SP_RPC_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .pool_idle_timeout(std::time::Duration::from_secs(15))
            .pool_max_idle_per_host(4)
            .tcp_keepalive(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

static SP_HTTP_CHECK_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .danger_accept_invalid_certs(true)
            // Monitors hit user-configured external URLs — each
            // target probably answers once per tick and stays idle
            // otherwise, so a short idle timeout keeps orphaned
            // sockets from piling up.
            .pool_idle_timeout(std::time::Duration::from_secs(15))
            .pool_max_idle_per_host(2)
            .tcp_keepalive(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

/// Drain a response body and discard it. reqwest cannot return the
/// TCP socket to its keep-alive pool until the body is consumed;
/// without this, every non-success `.send().await` branch that only
/// inspects `.status()` leaks a socket. Mirrors the `send_and_drain`
/// helper added to src/wolfrun/mod.rs in v19.8.1.
async fn drain_response(resp: reqwest::Response) {
    let _ = resp.bytes().await;
}

// ═══════════════════════════════════════════════
// ─── Data Types ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckType {
    Http {
        url: String,
        #[serde(default = "default_expected_status")]
        expected_status: u16,
    },
    Tcp {
        host: String,
        port: u16,
    },
    Ping {
        host: String,
    },
    Container {
        runtime: String, // "docker" or "lxc"
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node_id: Option<String>,
    },
    Wolfrun {
        service_id: String,
        #[serde(default)]
        service_name: String,
        #[serde(default = "default_min_healthy")]
        min_healthy: u32,
        #[serde(default = "default_health_check")]
        health_check: String,
    },
}

fn default_min_healthy() -> u32 { 1 }
fn default_health_check() -> String { "running".to_string() }

fn default_expected_status() -> u16 { 200 }
fn default_interval() -> u64 { 60 }
fn default_timeout() -> u64 { 10 }

/// A health check monitor — shared globally, referenced by services across pages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Monitor {
    pub id: String,
    pub name: String,
    pub check: CheckType,
    pub cluster: String,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool { true }


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Investigating,
    Identified,
    Monitoring,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentUpdate {
    pub timestamp: String,
    pub status: IncidentStatus,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub title: String,
    pub status: IncidentStatus,
    pub cluster: String,
    #[serde(default)]
    pub impact: Option<String>,
    #[serde(default)]
    pub service_ids: Vec<String>,
    #[serde(default)]
    pub updates: Vec<IncidentUpdate>,
    pub created_at: String,
    #[serde(default)]
    pub resolved_at: Option<String>,
    #[serde(default)]
    pub auto_created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub timestamp: u64,
    pub success: bool,
    pub latency_ms: u32,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyUptime {
    pub date: String, // YYYY-MM-DD
    pub total_checks: u32,
    pub successful_checks: u32,
    pub uptime_percent: f32,
}

/// A single status page — one of potentially many
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusPage {
    pub id: String,
    /// URL slug — the page is served at /status/{slug}
    pub slug: String,
    pub title: String,
    pub cluster: String,
    #[serde(default)]
    pub logo_url: Option<String>,
    #[serde(default)]
    pub footer_text: Option<String>,
    /// Theme for the public status page (dark, light, midnight, datacenter, forest, amber, glass, deepred)
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default)]
    pub monitor_ids: Vec<String>,
    #[serde(default)]
    pub incident_ids: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// ═══════════════════════════════════════════════
// ─── Configuration ───
// ═══════════════════════════════════════════════

/// Top-level configuration: global monitors + multiple status pages
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct StatusPageConfig {
    /// Global pool of monitors (shared across all pages)
    #[serde(default)]
    pub monitors: Vec<Monitor>,
    /// Global pool of incidents (shared across all pages)
    #[serde(default)]
    pub incidents: Vec<Incident>,
    /// Multiple status pages, each with their own slug, monitors, incidents
    #[serde(default)]
    pub pages: Vec<StatusPage>,
}


impl StatusPageConfig {
    pub fn load() -> Self {
        let path = config_file();
        match std::fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = config_file();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| e.to_string())
    }

    /// Rename all cluster references from old_name to new_name.
    /// Called when the cluster name is changed so monitors, pages,
    /// and incidents don't become orphaned under the old name.
    /// Case-insensitive on `old_name`, like every cluster-name comparison —
    /// a rename of "Minio" must also collect items whose stored tag drifted
    /// to "minio".
    pub fn rename_cluster(&mut self, old_name: &str, new_name: &str) -> usize {
        let mut count = 0;
        for m in &mut self.monitors {
            if m.cluster.eq_ignore_ascii_case(old_name) {
                m.cluster = new_name.to_string();
                count += 1;
            }
        }
        for p in &mut self.pages {
            if p.cluster.eq_ignore_ascii_case(old_name) {
                p.cluster = new_name.to_string();
                count += 1;
            }
        }
        for i in &mut self.incidents {
            if i.cluster.eq_ignore_ascii_case(old_name) {
                i.cluster = new_name.to_string();
                count += 1;
            }
        }
        count
    }
}

// ═══════════════════════════════════════════════
// ─── Shared State ───
// ═══════════════════════════════════════════════

/// Maximum recent results to keep per monitor (1440 = ~24h at 1/min)
const MAX_RESULTS: usize = 1440;
/// Maximum daily uptime entries (90 days)
const MAX_DAILY_ENTRIES: usize = 90;

pub struct StatusPageState {
    pub config: RwLock<StatusPageConfig>,
    /// Recent check results per monitor ID
    pub results: RwLock<HashMap<String, VecDeque<CheckResult>>>,
    /// Daily uptime aggregation per monitor ID
    pub daily_uptime: RwLock<HashMap<String, VecDeque<DailyUptime>>>,
    /// Monitor ID → unix time it was observed entering Down. Presence in
    /// the map = this node currently considers the monitor down; drives
    /// the WolfFunctions monitor_down/monitor_up trigger events. In-memory
    /// only: after a restart the node re-observes an ongoing outage and
    /// re-fires monitor_down once, which beats persisting per-check state.
    pub down_since: RwLock<HashMap<String, u64>>,
}

impl StatusPageState {
    pub fn new() -> Self {
        let config = StatusPageConfig::load();
        let daily_uptime = Self::load_daily_uptime();

        Self {
            config: RwLock::new(config),
            results: RwLock::new(HashMap::new()),
            daily_uptime: RwLock::new(daily_uptime),
            down_since: RwLock::new(HashMap::new()),
        }
    }

    /// Check if any status pages are configured
    pub fn has_any_pages(&self) -> bool {
        let config = self.config.read().unwrap();
        !config.pages.is_empty()
    }

    /// Get current status for a specific monitor
    pub fn monitor_status(&self, monitor_id: &str) -> MonitorStatus {
        let results = self.results.read().unwrap();
        match results.get(monitor_id) {
            Some(deque) if !deque.is_empty() => {
                let last = deque.back().unwrap();
                if last.success {
                    MonitorStatus::Up
                } else {
                    let recent_failures = deque.iter().rev().take(DOWN_THRESHOLD).filter(|r| !r.success).count();
                    if recent_failures >= DOWN_THRESHOLD {
                        MonitorStatus::Down
                    } else {
                        MonitorStatus::Degraded
                    }
                }
            }
            _ => MonitorStatus::Unknown,
        }
    }

    /// Get overall status for a specific page by aggregating its monitors
    pub fn page_overall_status(&self, page: &StatusPage) -> MonitorStatus {
        if page.monitor_ids.is_empty() {
            return MonitorStatus::Unknown;
        }
        let mut worst = MonitorStatus::Up;
        for mid in &page.monitor_ids {
            worst = worst.worst(self.monitor_status(mid));
        }
        worst
    }

    /// Get the latest check result for a monitor
    pub fn latest_result(&self, monitor_id: &str) -> Option<CheckResult> {
        let results = self.results.read().unwrap();
        results.get(monitor_id).and_then(|d| d.back().cloned())
    }

    /// Record a check result
    pub fn record_result(&self, monitor_id: &str, result: CheckResult) {
        {
            let mut results = self.results.write().unwrap();
            let deque = results.entry(monitor_id.to_string()).or_insert_with(|| VecDeque::with_capacity(MAX_RESULTS));
            if deque.len() >= MAX_RESULTS {
                deque.pop_front();
            }
            deque.push_back(result.clone());
        }
        self.update_daily_uptime(monitor_id, &result);
    }

    /// Update daily uptime stats
    fn update_daily_uptime(&self, monitor_id: &str, result: &CheckResult) {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let mut daily = self.daily_uptime.write().unwrap();
        let deque = daily.entry(monitor_id.to_string()).or_insert_with(|| VecDeque::with_capacity(MAX_DAILY_ENTRIES));

        if let Some(entry) = deque.back_mut().filter(|e| e.date == today) {
            entry.total_checks += 1;
            if result.success {
                entry.successful_checks += 1;
            }
            entry.uptime_percent = if entry.total_checks > 0 {
                (entry.successful_checks as f32 / entry.total_checks as f32) * 100.0
            } else {
                100.0
            };
        } else {
            if deque.len() >= MAX_DAILY_ENTRIES {
                deque.pop_front();
            }
            deque.push_back(DailyUptime {
                date: today,
                total_checks: 1,
                successful_checks: if result.success { 1 } else { 0 },
                uptime_percent: if result.success { 100.0 } else { 0.0 },
            });
        }

        Self::save_daily_uptime_data(&daily);
    }

    fn save_daily_uptime_data(data: &HashMap<String, VecDeque<DailyUptime>>) {
        let path = uptime_file();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(json) = serde_json::to_string(data) {
            let _ = std::fs::write(&path, json);
        }
    }

    fn load_daily_uptime() -> HashMap<String, VecDeque<DailyUptime>> {
        match std::fs::read_to_string(uptime_file()) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => HashMap::new(),
        }
    }

    /// Get 90-day uptime data for a monitor
    pub fn get_daily_uptime(&self, monitor_id: &str) -> Vec<DailyUptime> {
        let daily = self.daily_uptime.read().unwrap();
        daily.get(monitor_id).map(|d| d.iter().cloned().collect()).unwrap_or_default()
    }

    /// Calculate overall uptime percentage for a monitor (last 90 days)
    pub fn uptime_percent(&self, monitor_id: &str) -> f32 {
        let daily = self.daily_uptime.read().unwrap();
        match daily.get(monitor_id) {
            Some(deque) if !deque.is_empty() => {
                let total: u32 = deque.iter().map(|d| d.total_checks).sum();
                let success: u32 = deque.iter().map(|d| d.successful_checks).sum();
                if total > 0 { (success as f32 / total as f32) * 100.0 } else { 100.0 }
            }
            _ => 100.0,
        }
    }

    /// Find a page by slug, restricted to a specific cluster
    pub fn find_page_by_slug_and_cluster(&self, slug: &str, cluster: &str) -> Option<StatusPage> {
        let config = self.config.read().unwrap();
        config.pages.iter().find(|p| p.slug == slug && p.cluster == cluster).cloned()
    }

    /// Find a page by slug (any cluster — safe because replication only stores own-cluster data)
    pub fn find_page_by_slug(&self, slug: &str) -> Option<StatusPage> {
        let config = self.config.read().unwrap();
        config.pages.iter().find(|p| p.slug == slug).cloned()
    }

    /// List page slugs + titles for a specific cluster only
    pub fn list_pages_for_cluster(&self, cluster: &str) -> Vec<(String, String, bool)> {
        let config = self.config.read().unwrap();
        config.pages.iter()
            .filter(|p| p.cluster == cluster)
            .map(|p| (p.slug.clone(), p.title.clone(), p.enabled))
            .collect()
    }

    /// Merge status page config received from a cluster peer.
    /// Replaces all local pages/monitors/incidents for the incoming clusters.
    pub fn merge_from_peer(&self, peer_config: StatusPageConfig) {
        // Identify which clusters the peer is sending data for
        let peer_clusters: std::collections::HashSet<String> = peer_config.pages.iter()
            .map(|p| p.cluster.clone())
            .chain(peer_config.monitors.iter().map(|m| m.cluster.clone()))
            .chain(peer_config.incidents.iter().map(|i| i.cluster.clone()))
            .collect();

        if peer_clusters.is_empty() { return; }

        let mut config = self.config.write().unwrap();

        // Remove all local data for the incoming clusters
        config.pages.retain(|p| !peer_clusters.contains(&p.cluster));
        config.monitors.retain(|m| !peer_clusters.contains(&m.cluster));
        config.incidents.retain(|i| !peer_clusters.contains(&i.cluster));

        // Add all peer data
        config.pages.extend(peer_config.pages);
        config.monitors.extend(peer_config.monitors);
        config.incidents.extend(peer_config.incidents);

        drop(config);
        self.config.read().unwrap().save().ok();
    }

}

// ═══════════════════════════════════════════════
// ─── Cluster Broadcast ───
// ═══════════════════════════════════════════════

/// Broadcast this cluster's status page config to all online same-cluster peers.
/// Only sends pages/monitors/incidents that belong to this node's cluster so
/// we never overwrite another cluster's data on the receiving end.
pub async fn broadcast_to_cluster(
    state: &Arc<StatusPageState>,
    cluster: &crate::agent::ClusterState,
    cluster_secret: &str,
) {
    let nodes = cluster.get_all_nodes();

    // Find our cluster name
    let self_cluster = nodes.iter()
        .find(|n| n.is_self)
        .and_then(|n| n.cluster_name.clone())
        .unwrap_or_else(|| "WolfStack".to_string());

    // Filter config to only our cluster's data
    let full_config = state.config.read().unwrap().clone();
    let filtered = StatusPageConfig {
        monitors: full_config.monitors.into_iter().filter(|m| m.cluster == self_cluster).collect(),
        pages: full_config.pages.into_iter().filter(|p| p.cluster == self_cluster).collect(),
        incidents: full_config.incidents.into_iter().filter(|i| i.cluster == self_cluster).collect(),
    };

    let page_count = filtered.pages.len();
    let monitor_count = filtered.monitors.len();

    // Nothing to send
    if page_count == 0 && monitor_count == 0 && filtered.incidents.is_empty() {
        return;
    }

    // Shared process-wide client — see SP_RPC_CLIENT docs at top of
    // file. Previously built a fresh Client here on every 60s tick,
    // which was the primary statuspage contribution to CLOSE_WAIT
    // accumulation reported by Bel.
    let client = &*SP_RPC_CLIENT;

    // Send to all online same-cluster peers (not self)
    for node in &nodes {
        if node.is_self || !node.online {
            continue;
        }
        let node_cluster = node.cluster_name.as_deref().unwrap_or("WolfStack");
        if node_cluster != self_cluster {
            continue;
        }

        let urls = crate::api::build_node_urls(&node.address, node.port, "/api/statuspage/sync");
        let mut sent = false;
        for url in &urls {
            match client.post(url)
                .peer_auth(cluster_secret)
                .json(&filtered)
                .send().await
            {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!("StatusPage sync: sent {} pages, {} monitors to {} ({})",
                        page_count, monitor_count, node.hostname, url);
                    // Drain the ack body so the socket returns to the
                    // keep-alive pool cleanly.
                    drain_response(resp).await;
                    sent = true;
                    break;
                }
                Ok(resp) => {
                    let status = resp.status();
                    tracing::warn!("StatusPage sync: {} returned HTTP {} — trying next URL",
                        url, status);
                    // Non-success responses still have a body (often
                    // an error message) — drain it or the socket
                    // leaks the same way as success would.
                    drain_response(resp).await;
                    continue;
                }
                Err(e) => {
                    tracing::debug!("StatusPage sync: {} failed: {} — trying next URL", url, e);
                    continue;
                }
            }
        }
        if !sent {
            tracing::warn!("StatusPage sync: failed to reach {} (all URLs failed)", node.hostname);
        }
    }
}

/// Pull status page config from cluster peers.
/// Tries each online same-cluster peer until one responds with data.
pub async fn pull_from_peers(
    state: &Arc<StatusPageState>,
    cluster: &crate::agent::ClusterState,
    cluster_secret: &str,
) {
    let nodes = cluster.get_all_nodes();

    let self_cluster = nodes.iter()
        .find(|n| n.is_self)
        .and_then(|n| n.cluster_name.clone())
        .unwrap_or_else(|| "WolfStack".to_string());

    // Check if we already have pages for our cluster
    {
        let config = state.config.read().unwrap();
        if config.pages.iter().any(|p| p.cluster == self_cluster) {
            return;
        }
    }

    // Shared process-wide client — see SP_RPC_CLIENT docs at top of
    // file. Building per-call was the same leak as broadcast_to_cluster.
    let client = &*SP_RPC_CLIENT;

    // Try each online same-cluster peer
    for peer in nodes.iter().filter(|n| {
        !n.is_self && n.online && n.cluster_name.as_deref().unwrap_or("WolfStack") == self_cluster
    }) {
        let urls = crate::api::build_node_urls(&peer.address, peer.port, "/api/statuspage/config");
        for url in &urls {
            match client.get(url)
                .peer_auth(cluster_secret)
                .send().await
            {
                Ok(resp) if resp.status().is_success() => {
                    // `.json()` consumes the body internally, which
                    // returns the socket to the pool — so this arm is
                    // already drain-safe.
                    if let Ok(peer_config) = resp.json::<StatusPageConfig>().await {
                        // Filter to only our cluster's data — peer may have replicated data from other clusters
                        let filtered = StatusPageConfig {
                            monitors: peer_config.monitors.into_iter().filter(|m| m.cluster == self_cluster).collect(),
                            pages: peer_config.pages.into_iter().filter(|p| p.cluster == self_cluster).collect(),
                            incidents: peer_config.incidents.into_iter().filter(|i| i.cluster == self_cluster).collect(),
                        };
                        if !filtered.pages.is_empty() {
                            tracing::info!("StatusPage pull: got config from {} ({} pages, {} monitors)",
                                peer.hostname, filtered.pages.len(), filtered.monitors.len());
                            state.merge_from_peer(filtered);
                            return;
                        }
                    }
                    break; // Peer responded but had no data — try next peer
                }
                // Non-success HTTP: bind resp so we can drain the
                // error body before discarding. The old `Ok(_)` arm
                // dropped an unconsumed Response, which prevented the
                // socket from going back to the keep-alive pool.
                Ok(resp) => {
                    drain_response(resp).await;
                    continue;
                }
                Err(_) => continue, // Network error — no Response to drain.
            }
        }
    }
    tracing::debug!("StatusPage pull: no peer had pages for cluster '{}'", self_cluster);
}

// ═══════════════════════════════════════════════
// ─── Monitor Status ───
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorStatus {
    Up,
    Degraded,
    Down,
    Unknown,
}

impl MonitorStatus {
    pub fn worst(self, other: MonitorStatus) -> MonitorStatus {
        match (self, other) {
            (MonitorStatus::Down, _) | (_, MonitorStatus::Down) => MonitorStatus::Down,
            (MonitorStatus::Degraded, _) | (_, MonitorStatus::Degraded) => MonitorStatus::Degraded,
            (MonitorStatus::Unknown, _) | (_, MonitorStatus::Unknown) => MonitorStatus::Unknown,
            _ => MonitorStatus::Up,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            MonitorStatus::Up => "Operational",
            MonitorStatus::Degraded => "Degraded",
            MonitorStatus::Down => "Major Outage",
            MonitorStatus::Unknown => "Unknown",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            MonitorStatus::Up => "🟢",
            MonitorStatus::Degraded => "🟡",
            MonitorStatus::Down => "🔴",
            MonitorStatus::Unknown => "⚪",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            MonitorStatus::Up => "#22c55e",
            MonitorStatus::Degraded => "#eab308",
            MonitorStatus::Down => "#ef4444",
            MonitorStatus::Unknown => "#6b7280",
        }
    }
}

// ═══════════════════════════════════════════════
// ─── Check Runner ───
// ═══════════════════════════════════════════════

/// Run all enabled monitors and record results.
/// Called periodically by the background task in main.rs.
pub async fn run_checks(
    state: &Arc<StatusPageState>,
    cluster: &crate::agent::ClusterState,
    cluster_secret: &str,
) {
    let monitors = {
        let config = state.config.read().unwrap();
        config.monitors.iter()
            .filter(|m| m.enabled)
            .cloned()
            .collect::<Vec<_>>()
    };

    // Check every enabled monitor regardless of whether a status PAGE exists.
    // Monitors are useful on their own (the admin uptime view, alerting), and
    // the old `has_pages` gate left freshly-created monitors stuck showing
    // "Unknown" forever until the user also created and enabled a status page
    // (user report 2026-06-06).
    if monitors.is_empty() {
        return;
    }

    for monitor in &monitors {
        let timeout = std::time::Duration::from_secs(monitor.timeout_secs);
        let start = std::time::Instant::now();

        let (success, error) = match &monitor.check {
            CheckType::Http { url, expected_status } => {
                run_http_check(url, *expected_status, timeout).await
            }
            CheckType::Tcp { host, port } => {
                run_tcp_check(host, *port, timeout).await
            }
            CheckType::Ping { host } => {
                run_ping_check(host, timeout).await
            }
            CheckType::Container { runtime, name, node_id } => {
                run_container_check_routed(runtime, name, node_id, cluster, cluster_secret).await
            }
            CheckType::Wolfrun { service_id, min_healthy, health_check, .. } => {
                run_wolfrun_check(service_id, *min_healthy, health_check).await
            }
        };

        let latency_ms = start.elapsed().as_millis() as u32;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        state.record_result(&monitor.id, CheckResult {
            timestamp: now,
            success,
            latency_ms,
            error,
        });
    }

    // Auto-create/resolve incidents on each page
    auto_manage_incidents(state);

    // WolfFunctions monitor_down / monitor_up trigger events + channel
    // notifications. Cluster passed so the notification fires from the
    // LEADER only — every node runs every replicated monitor, so without
    // this the operator would get one Discord/ntfy/email per node.
    fire_monitor_transition_events(state, &monitors, cluster);
}

/// Fire WolfFunctions trigger events on monitor state transitions.
///
/// Every node runs its own checks, so every node detects the transition;
/// dispatch uses `force_local=false` so only the cluster leader actually
/// invokes subscribed functions — same dedupe as node_offline/online.
///
/// Latch semantics: a monitor is "down" from the moment it computes
/// `MonitorStatus::Down` (3 consecutive failures) until it computes `Up`.
/// Degraded (1-2 failures) and Unknown never change the latch, so a flap
/// through Degraded during recovery can't strand the latch or double-fire.
fn fire_monitor_transition_events(state: &Arc<StatusPageState>, monitors: &[Monitor], cluster: &crate::agent::ClusterState) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // (monitor, went_down, downtime_secs) — collected under the lock,
    // fired after it's released.
    let mut transitions: Vec<(Monitor, bool, u64)> = Vec::new();
    {
        let mut down_since = state.down_since.write().unwrap();
        // Deleted/disabled monitors: drop their latch so the map can't
        // grow unbounded and a re-enabled monitor starts fresh.
        down_since.retain(|id, _| monitors.iter().any(|m| &m.id == id));
        for monitor in monitors {
            let status = state.monitor_status(&monitor.id);
            match status {
                MonitorStatus::Down => {
                    if !down_since.contains_key(&monitor.id) {
                        down_since.insert(monitor.id.clone(), now);
                        transitions.push((monitor.clone(), true, 0));
                    }
                }
                MonitorStatus::Up => {
                    if let Some(since) = down_since.remove(&monitor.id) {
                        transitions.push((monitor.clone(), false, now.saturating_sub(since)));
                    }
                }
                MonitorStatus::Degraded | MonitorStatus::Unknown => {}
            }
        }
    }
    for (monitor, went_down, downtime_secs) in transitions {
        // Direct channel notification (Discord/Slack/Telegram/ntfy/email)
        // on down + recovery — klas's request. Fires independent of the
        // WolfFunctions trigger below; skips the security-alert verbosity
        // gate (see send_monitor_alert). Recovery pings honour the
        // operator's recovery_notifications toggle. LEADER ONLY — every
        // node runs every replicated monitor, so gating here prevents one
        // notification per node (same dedup as the WolfFunctions dispatch).
        if crate::wolfrun::is_leader(cluster) {
            let send_recovery = crate::alerting::AlertConfig::load().recovery_notifications;
            let mname = monitor.name.clone();
            if went_down {
                let title = format!("🔴 Monitor down: {}", mname);
                let body = format!(
                    "Status-page monitor '{}' (cluster {}) is DOWN — {} consecutive failed checks.",
                    mname, monitor.cluster, DOWN_THRESHOLD,
                );
                tokio::spawn(async move {
                    crate::alerting::send_monitor_alert(&title, &body, true).await;
                });
            } else if send_recovery {
                let mins = downtime_secs / 60;
                let title = format!("🟢 Monitor recovered: {}", mname);
                let body = format!(
                    "Status-page monitor '{}' (cluster {}) is back UP after ~{} min of downtime.",
                    mname, monitor.cluster, mins,
                );
                tokio::spawn(async move {
                    crate::alerting::send_monitor_alert(&title, &body, false).await;
                });
            }
        }

        let (event, payload) = if went_down {
            (
                crate::wolffunctions::TriggerEvent::MonitorDown,
                serde_json::json!({
                    "monitor_id": monitor.id,
                    "monitor_name": monitor.name,
                    "cluster": monitor.cluster,
                    "check": monitor.check,
                    "status": "down",
                }),
            )
        } else {
            (
                crate::wolffunctions::TriggerEvent::MonitorUp,
                serde_json::json!({
                    "monitor_id": monitor.id,
                    "monitor_name": monitor.name,
                    "cluster": monitor.cluster,
                    "check": monitor.check,
                    "status": "up",
                    "downtime_secs": downtime_secs,
                }),
            )
        };
        crate::wolffunctions::fire_event_global(event, payload, false);
    }
}

async fn run_http_check(url: &str, expected_status: u16, timeout: std::time::Duration) -> (bool, Option<String>) {
    // Shared pool (SP_HTTP_CHECK_CLIENT) carries no default timeout —
    // each monitor has its own `timeout_secs`, so we set it per
    // request via RequestBuilder::timeout. Previously this function
    // built a fresh Client per monitor per 30s tick; on a host with
    // N monitors that was N leaked connection pools per tick, the
    // dominant fire source for Bel's CLOSE_WAIT climb.
    let client = &*SP_HTTP_CHECK_CLIENT;

    match client.get(url).timeout(timeout).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            // Drain the body BEFORE returning so the socket goes
            // back to the keep-alive pool. `status()` doesn't consume
            // the response; dropping it unread was the second half of
            // the leak. Errors from drain are ignored — the check's
            // pass/fail verdict is already decided by status code.
            let _ = resp.bytes().await;
            if status == expected_status {
                (true, None)
            } else {
                (false, Some(format!("Expected {}, got {}", expected_status, status)))
            }
        }
        Err(e) => {
            if e.is_timeout() {
                (false, Some("Timeout".to_string()))
            } else if e.is_connect() {
                (false, Some("Connection refused".to_string()))
            } else {
                (false, Some(format!("{}", e)))
            }
        }
    }
}

async fn run_tcp_check(host: &str, port: u16, timeout: std::time::Duration) -> (bool, Option<String>) {
    // host_port brackets bare IPv6 monitor targets — "2001:db8::1:9600"
    // is unconnectable; "[2001:db8::1]:9600" resolves.
    let addr = crate::netaddr::host_port(host, port);
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => (true, None),
        Ok(Err(e)) => (false, Some(format!("Connection failed: {}", e))),
        Err(_) => (false, Some("Timeout".to_string())),
    }
}

async fn run_ping_check(host: &str, timeout: std::time::Duration) -> (bool, Option<String>) {
    let timeout_secs = timeout.as_secs().max(1).to_string();
    let output = tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", &timeout_secs, host])
        .output()
        .await;

    match output {
        Ok(out) => {
            if out.status.success() {
                (true, None)
            } else {
                (false, Some("Host unreachable".to_string()))
            }
        }
        Err(e) => (false, Some(format!("Ping failed: {}", e))),
    }
}

/// Public wrapper so the inter-node container-check endpoint
/// (`/api/statuspage/container-check`) can run the same local probe a
/// direct check uses. See `run_container_check`.
pub fn check_container_local(runtime: &str, name: &str) -> (bool, Option<String>) {
    run_container_check(runtime, name)
}

/// Resolve a Container check that may target a remote node. Container
/// monitors are replicated cluster-wide and every node runs every
/// monitor (see run_checks), so a container living on node B was being
/// probed with LOCAL `docker inspect` on node A — where it doesn't
/// exist — and reported "major outage" while the owning node saw it
/// healthy (klas, 2026-07-15). When `node_id` names another online
/// node, proxy the probe to it so every node computes the correct
/// answer regardless of where the container runs.
async fn run_container_check_routed(
    runtime: &str,
    name: &str,
    node_id: &Option<String>,
    cluster: &crate::agent::ClusterState,
    cluster_secret: &str,
) -> (bool, Option<String>) {
    // No node pinned, or it's this node → local probe (unchanged path).
    let target = match node_id {
        Some(id) if !id.is_empty() && *id != cluster.self_id => id.clone(),
        _ => {
            let rt = runtime.to_string();
            let nm = name.to_string();
            return tokio::task::spawn_blocking(move || run_container_check(&rt, &nm))
                .await.unwrap_or((false, Some("Check task failed".to_string())));
        }
    };

    let node = match cluster.get_node(&target) {
        Some(n) if n.is_self => {
            // node_id points at us after all (id mirror / alias) — local.
            let rt = runtime.to_string();
            let nm = name.to_string();
            return tokio::task::spawn_blocking(move || run_container_check(&rt, &nm))
                .await.unwrap_or((false, Some("Check task failed".to_string())));
        }
        Some(n) => n,
        None => return (false, Some(format!("target node {} not found in cluster", target))),
    };
    if !node.online {
        return (false, Some(format!("node {} is offline", node.hostname)));
    }

    let path = format!(
        "/api/statuspage/container-check?runtime={}&name={}",
        urlencoding::encode(runtime),
        urlencoding::encode(name),
    );
    let urls = crate::api::build_node_urls(&node.address, node.port, &path);
    let client = &*SP_RPC_CLIENT;
    let mut last_err = String::new();
    for url in &urls {
        match client.get(url)
            .peer_auth(cluster_secret)
            .send().await
        {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(v) => {
                        let up = v.get("up").and_then(|b| b.as_bool()).unwrap_or(false);
                        let err = v.get("error").and_then(|e| e.as_str())
                            .filter(|s| !s.is_empty()).map(|s| s.to_string());
                        return (up, err);
                    }
                    Err(e) => { last_err = format!("bad response from {}: {}", node.hostname, e); }
                }
            }
            Ok(resp) if resp.status().as_u16() == 404 => {
                // Node predates the container-check endpoint (rolling
                // upgrade). Fall back to /api/containers/running — present
                // on older builds — so a healthy container isn't false-
                // flagged as a major outage mid-upgrade.
                return remote_container_running_fallback(&node, runtime, name, cluster_secret).await;
            }
            Ok(resp) => {
                last_err = format!("node {} returned HTTP {}", node.hostname, resp.status());
            }
            Err(e) => { last_err = format!("could not reach node {}: {}", node.hostname, e); }
        }
    }
    (false, Some(if last_err.is_empty() { "remote container check failed".into() } else { last_err }))
}

/// Backward-compat container probe for peers that predate
/// /api/statuspage/container-check: list the node's running containers
/// and check membership. Only reached on a 404 from the primary path.
async fn remote_container_running_fallback(
    node: &crate::agent::Node,
    runtime: &str,
    name: &str,
    cluster_secret: &str,
) -> (bool, Option<String>) {
    let urls = crate::api::build_node_urls(&node.address, node.port, "/api/containers/running");
    let client = &*SP_RPC_CLIENT;
    for url in &urls {
        if let Ok(resp) = client.get(url).peer_auth(cluster_secret).send().await {
            // Drain before leaving — a bare `continue` strands the socket
            // in CLOSE-WAIT (see the drain_response doc comment above).
            if !resp.status().is_success() { drain_response(resp).await; continue; }
            if let Ok(list) = resp.json::<Vec<serde_json::Value>>().await {
                let running = list.iter().any(|c| {
                    c.get("runtime").and_then(|r| r.as_str()) == Some(runtime)
                        && c.get("name").and_then(|n| n.as_str()) == Some(name)
                });
                return if running {
                    (true, None)
                } else {
                    (false, Some("Container not running".to_string()))
                };
            }
        }
    }
    (false, Some(format!("node {} unreachable (needs update for container monitoring)", node.hostname)))
}

fn run_container_check(runtime: &str, name: &str) -> (bool, Option<String>) {
    match runtime {
        "docker" => {
            let output = std::process::Command::new("docker")
                .args(["inspect", "-f", "{{.State.Running}}", name])
                .output();
            match output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if stdout == "true" {
                        (true, None)
                    } else {
                        (false, Some(format!("Container not running (state: {})", stdout)))
                    }
                }
                Err(e) => (false, Some(format!("Docker error: {}", e))),
            }
        }
        "lxc" => {
            let output = std::process::Command::new("lxc-info")
                .args(["-n", name, "-s"])
                .output();
            match output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    if stdout.contains("RUNNING") {
                        (true, None)
                    } else {
                        (false, Some("Container not running".to_string()))
                    }
                }
                Err(e) => (false, Some(format!("LXC error: {}", e))),
            }
        }
        _ => (false, Some(format!("Unknown runtime: {}", runtime))),
    }
}

/// Check WolfRun service health by counting running instances
async fn run_wolfrun_check(service_id: &str, min_healthy: u32, _health_check: &str) -> (bool, Option<String>) {
    // Try to read WolfRun services from the local file
    let wolfrun_path = std::path::Path::new("data/wolfrun.json");
    if !wolfrun_path.exists() {
        return (false, Some("WolfRun not configured".to_string()));
    }
    
    let content = match std::fs::read_to_string(wolfrun_path) {
        Ok(c) => c,
        Err(e) => return (false, Some(format!("Failed to read WolfRun config: {}", e))),
    };
    
    let services: Vec<serde_json::Value> = match serde_json::from_str(&content) {
        Ok(s) => s,
        Err(e) => return (false, Some(format!("Failed to parse WolfRun config: {}", e))),
    };
    
    // Find the service
    let service = match services.iter().find(|s| s.get("id").and_then(|v| v.as_str()) == Some(service_id)) {
        Some(s) => s,
        None => return (false, Some(format!("Service {} not found", service_id))),
    };
    
    // Count running instances
    let instances = service.get("instances").and_then(|v| v.as_array()).map(|a| a.to_vec()).unwrap_or_default();
    let running_count = instances.iter().filter(|i| {
        i.get("status").and_then(|v| v.as_str()) == Some("running")
    }).count() as u32;
    
    if running_count >= min_healthy {
        (true, None)
    } else {
        (false, Some(format!("Only {}/{} instances running", running_count, min_healthy)))
    }
}

/// Auto-create incidents when monitors go down, auto-resolve when back up.
fn auto_manage_incidents(state: &Arc<StatusPageState>) {
    let mut config = state.config.write().unwrap();
    let now_str = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Iterate over all monitors in the global pool that are enabled
    let active_monitors: Vec<_> = config.monitors.iter().filter(|m| m.enabled).cloned().collect();

    for monitor in active_monitors {
        let status = compute_monitor_status(state, &monitor.id);

        let cluster = monitor.cluster.clone();
        
        // Find existing auto-incident for this monitor
        let existing = config.incidents.iter_mut().find(|i| {
            i.auto_created && i.status != IncidentStatus::Resolved && i.service_ids.contains(&monitor.id)
        });

        match status {
            MonitorStatus::Down | MonitorStatus::Degraded => {
                if existing.is_none() {
                    config.incidents.push(Incident {
                        id: uuid::Uuid::new_v4().to_string(),
                        title: format!("{} — {}", monitor.name, status.label()),
                        status: IncidentStatus::Investigating,
                        cluster,
                        impact: Some(if status == MonitorStatus::Down { "critical".to_string() } else { "minor".to_string() }),
                        service_ids: vec![monitor.id.clone()],
                        updates: vec![IncidentUpdate {
                            timestamp: now_str.clone(),
                            status: IncidentStatus::Investigating,
                            message: format!("Automated detection: {} is {}", monitor.name, status.label().to_lowercase()),
                        }],
                        created_at: now_str.clone(),
                        resolved_at: None,
                        auto_created: true,
                    });
                }
            }
            MonitorStatus::Up => {
                if let Some(incident) = existing {
                    incident.status = IncidentStatus::Resolved;
                    incident.resolved_at = Some(now_str.clone());
                    incident.updates.push(IncidentUpdate {
                        timestamp: now_str.clone(),
                        status: IncidentStatus::Resolved,
                        message: format!("{} has recovered and is operational", monitor.name),
                    });
                }
            }
            _ => {}
        }
    }

    let _ = config.save();
}

/// Compute monitor status from check results (uses state.results directly to avoid RwLock issues)
fn compute_monitor_status(state: &Arc<StatusPageState>, monitor_id: &str) -> MonitorStatus {
    let results = state.results.read().unwrap();
    match results.get(monitor_id) {
        Some(deque) if !deque.is_empty() => {
            let last = deque.back().unwrap();
            if last.success {
                MonitorStatus::Up
            } else {
                let recent_failures = deque.iter().rev().take(3).filter(|r| !r.success).count();
                if recent_failures >= 3 { MonitorStatus::Down } else { MonitorStatus::Degraded }
            }
        }
        _ => MonitorStatus::Unknown,
    }
}

// ═══════════════════════════════════════════════
// ─── Public Status Page HTML Renderer ───
// ═══════════════════════════════════════════════

/// Theme color palette for public status pages
struct ThemeColors {
    body_bg: &'static str,
    text: &'static str,
    heading: &'static str,
    card_bg: &'static str,
    card_border: &'static str,
    muted: &'static str,
    secondary: &'static str,
    divider: &'static str,
    bar_empty: &'static str,
}

fn theme_colors(theme: Option<&str>) -> ThemeColors {
    match theme {
        Some("light") => ThemeColors {
            body_bg: "#f5f6fa", text: "#1a1d2e", heading: "#0f1118", card_bg: "#ffffff",
            card_border: "#e2e4ea", muted: "#8b90a0", secondary: "#5a5f72",
            divider: "#e2e4ea", bar_empty: "#e2e4ea",
        },
        Some("midnight") => ThemeColors {
            body_bg: "#000000", text: "#e4e4f0", heading: "#f0f0ff", card_bg: "#111118",
            card_border: "#1e1e2e", muted: "#555570", secondary: "#8888a8",
            divider: "#1e1e2e", bar_empty: "#111118",
        },
        Some("datacenter") => ThemeColors {
            body_bg: "#1d2733", text: "#dce3eb", heading: "#eef2f7", card_bg: "#2a3849",
            card_border: "#374b5e", muted: "#607588", secondary: "#8fa4b8",
            divider: "#374b5e", bar_empty: "#2a3849",
        },
        Some("forest") => ThemeColors {
            body_bg: "#0c1a10", text: "#d8eedc", heading: "#e8ffe8", card_bg: "#1a3020",
            card_border: "#264030", muted: "#5a7868", secondary: "#88b098",
            divider: "#264030", bar_empty: "#1a3020",
        },
        Some("amber") => ThemeColors {
            body_bg: "#0a0800", text: "#f0d890", heading: "#ffe8a0", card_bg: "#1a1610",
            card_border: "#2e2818", muted: "#786840", secondary: "#b8a060",
            divider: "#2e2818", bar_empty: "#1a1610",
        },
        Some("glass") => ThemeColors {
            body_bg: "#020512", text: "#c8e0ff", heading: "#e0f0ff", card_bg: "#0a1840",
            card_border: "rgba(55,110,220,0.20)", muted: "#2e4d78", secondary: "#5a88c0",
            divider: "rgba(55,110,220,0.20)", bar_empty: "#0a1840",
        },
        Some("deepred") => ThemeColors {
            body_bg: "#100408", text: "#f0dde2", heading: "#fff0f2", card_bg: "#240c14",
            card_border: "#3a1420", muted: "#704858", secondary: "#b08090",
            divider: "#3a1420", bar_empty: "#240c14",
        },
        _ => ThemeColors { // dark (default)
            body_bg: "#0f172a", text: "#e2e8f0", heading: "#f8fafc", card_bg: "#1e293b",
            card_border: "#334155", muted: "#64748b", secondary: "#94a3b8",
            divider: "#1e293b", bar_empty: "#1e293b",
        },
    }
}

/// Render the public status page for a specific page slug (only if it belongs to this cluster)
pub fn render_public_page(state: &Arc<StatusPageState>, slug: &str, local_cluster: &str) -> Option<String> {
    let page = state.find_page_by_slug_and_cluster(slug, local_cluster)?;
    render_public_page_inner(state, &page)
}

/// Shared rendering logic for public status pages
pub fn render_public_page_inner(state: &Arc<StatusPageState>, page: &StatusPage) -> Option<String> {
    if !page.enabled {
        return Some(not_enabled_html());
    }

    let overall = state.page_overall_status(page);
    let tc = theme_colors(page.theme.as_deref());

    let config = state.config.read().unwrap();

    // Build monitors HTML
    let mut services_html = String::new();
    for mid in &page.monitor_ids {
        if let Some(monitor) = config.monitors.iter().find(|m| m.id == *mid) {
            let m_status = state.monitor_status(mid);
            let uptime = state.uptime_percent(mid);

            let daily = state.get_daily_uptime(mid);
            let bars_html = build_uptime_bars(&daily, tc.bar_empty);

            services_html.push_str(&format!(
                r#"<div class="service-row">
                    <div class="service-header">
                        <div class="service-name">{name}</div>
                        <div class="service-status" style="color:{color}">{emoji} {label}</div>
                    </div>
                    <div class="uptime-section">
                        <div class="uptime-bars">{bars}</div>
                        <div class="uptime-legend">
                            <span>90 days ago</span>
                            <span class="uptime-pct">{uptime:.2}% uptime</span>
                            <span>Today</span>
                        </div>
                    </div>
                </div>"#,
                name = html_escape(&monitor.name),
                color = m_status.color(),
                emoji = m_status.emoji(),
                label = m_status.label(),
                bars = bars_html,
                uptime = uptime,
            ));
        }
    }

    // Build incidents HTML — all incidents for this page, newest first
    let mut incidents_html = String::new();

    let mut all_incidents: Vec<&Incident> = config.incidents.iter()
        .filter(|i| page.incident_ids.contains(&i.id))
        .collect();
    all_incidents.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    if all_incidents.is_empty() {
        incidents_html.push_str(r#"<p class="no-incidents">No incidents reported.</p>"#);
    } else {
        for incident in &all_incidents {
            let status_badge = match incident.status {
                IncidentStatus::Investigating => r#"<span class="badge badge-red">Investigating</span>"#,
                IncidentStatus::Identified => r#"<span class="badge badge-orange">Identified</span>"#,
                IncidentStatus::Monitoring => r#"<span class="badge badge-yellow">Monitoring</span>"#,
                IncidentStatus::Resolved => r#"<span class="badge badge-green">Resolved</span>"#,
            };

            let impact_badge = match incident.impact.as_deref() {
                Some("critical") => r#" <span class="badge badge-red">Critical</span>"#,
                Some("major") => r#" <span class="badge badge-orange">Major</span>"#,
                Some("minor") => r#" <span class="badge badge-yellow">Minor</span>"#,
                _ => "",
            };

            let formatted_date = format_iso_date(&incident.created_at);

            let mut updates_html = String::new();
            for update in incident.updates.iter().rev() {
                let formatted_update_time = format_iso_date(&update.timestamp);
                updates_html.push_str(&format!(
                    r#"<div class="incident-update">
                        <div class="update-time">{}</div>
                        <div class="update-msg">{}</div>
                    </div>"#,
                    html_escape(&formatted_update_time),
                    html_escape(&update.message),
                ));
            }

            incidents_html.push_str(&format!(
                r#"<div class="incident" data-incident>
                    <div class="incident-header">
                        <div class="incident-title">{title}</div>
                        <div>{badge}{impact}</div>
                    </div>
                    <div class="incident-date">{date}</div>
                    <div class="incident-updates">{updates}</div>
                </div>"#,
                title = html_escape(&incident.title),
                badge = status_badge,
                impact = impact_badge,
                date = html_escape(&formatted_date),
                updates = updates_html,
            ));
        }
    }

    let logo_html = page.logo_url.as_ref()
        .map(|url| format!(r#"<img src="{}" alt="Logo" class="logo">"#, html_escape(url)))
        .unwrap_or_default();

    let footer_text = page.footer_text.as_deref().unwrap_or("Powered by WolfStack");

    Some(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="{title} — Current system status and uptime">
    <title>{title}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <meta http-equiv="refresh" content="60">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            background: {body_bg};
            color: {text};
            min-height: 100vh;
        }}
        .container {{ max-width: 720px; margin: 0 auto; padding: 2rem 1.5rem; }}
        .header {{ text-align: center; margin-bottom: 2rem; }}
        .logo {{ max-height: 60px; margin-bottom: 1rem; }}
        .header h1 {{ font-size: 1.5rem; font-weight: 700; color: {heading}; }}
        .overall-status {{
            text-align: center; padding: 1.25rem; margin-bottom: 2rem;
            border-radius: 12px; font-size: 1.1rem; font-weight: 600;
            background: {overall_bg};
            border: 1px solid {overall_border};
            color: {overall_color};
        }}
        .section-title {{ font-size: 0.8rem; font-weight: 600; text-transform: uppercase;
            letter-spacing: 0.05em; color: {secondary}; margin-bottom: 0.75rem; }}
        .service-row {{
            background: {card_bg}; border: 1px solid {card_border}; border-radius: 10px;
            padding: 1.25rem; margin-bottom: 0.75rem;
        }}
        .service-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }}
        .service-name {{ font-weight: 600; font-size: 0.95rem; }}
        .service-status {{ font-size: 0.85rem; font-weight: 500; }}
        .uptime-section {{ margin-top: 0.5rem; }}
        .uptime-bars {{ display: flex; gap: 1px; height: 28px; border-radius: 4px; overflow: hidden; }}
        .uptime-bar {{ flex: 1; min-width: 2px; transition: opacity 0.2s; cursor: default; }}
        .uptime-bar:hover {{ opacity: 0.8; }}
        .uptime-legend {{ display: flex; justify-content: space-between; font-size: 0.7rem; color: {muted}; margin-top: 4px; }}
        .uptime-pct {{ font-weight: 600; color: {secondary}; }}
        .incidents-section {{ margin-top: 2rem; }}
        .incident {{
            background: {card_bg}; border: 1px solid {card_border}; border-radius: 10px;
            padding: 1.25rem; margin-bottom: 0.75rem;
        }}
        .incident-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }}
        .incident-title {{ font-weight: 600; font-size: 0.95rem; }}
        .incident-date {{ font-size: 0.75rem; color: {muted}; margin-bottom: 0.75rem; }}
        .badge {{ padding: 3px 10px; border-radius: 100px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }}
        .badge-red {{ background: rgba(239,68,68,0.15); color: #ef4444; }}
        .badge-orange {{ background: rgba(249,115,22,0.15); color: #f97316; }}
        .badge-yellow {{ background: rgba(234,179,8,0.15); color: #eab308; }}
        .badge-green {{ background: rgba(34,197,94,0.15); color: #22c55e; }}
        .incident-update {{ padding: 0.5rem 0; border-top: 1px solid {card_border}; }}
        .incident-update:first-child {{ border-top: none; }}
        .update-time {{ font-size: 0.7rem; color: {muted}; margin-bottom: 2px; }}
        .update-msg {{ font-size: 0.85rem; color: {secondary}; }}
        .no-incidents {{ color: {muted}; font-size: 0.9rem; text-align: center; padding: 1rem; }}
        .footer {{ text-align: center; margin-top: 3rem; padding-top: 1.5rem;
            border-top: 1px solid {divider}; font-size: 0.75rem; color: {muted}; }}
        .footer a {{ color: {secondary}; text-decoration: underline; }}
        .incident-pagination {{ display: flex; justify-content: center; align-items: center; gap: 8px; margin-top: 1rem; }}
        .incident-pagination button {{
            background: {card_bg}; border: 1px solid {card_border}; color: {secondary};
            padding: 6px 14px; border-radius: 6px; font-size: 0.8rem; cursor: pointer;
            font-family: inherit;
        }}
        .incident-pagination button:hover:not(:disabled) {{ background: {card_border}; }}
        .incident-pagination button:disabled {{ opacity: 0.4; cursor: default; }}
        .incident-pagination .page-info {{ font-size: 0.8rem; color: {muted}; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {logo}
            <h1>{title}</h1>
        </div>
        <div class="overall-status">{overall_emoji} {overall_label}</div>
        <div class="section-title">Services</div>
        {services}
        <div class="incidents-section">
            <div class="section-title">Recent Incidents</div>
            <div id="incidents-container">{incidents}</div>
            <div class="incident-pagination" id="incident-pagination"></div>
        </div>
        <div class="footer">
            <p>{footer} &bull; <a href="https://wolfscale.org" target="_blank">wolfscale.org</a></p>
        </div>
    </div>
    <script>
    (function() {{
        var perPage = 10;
        var items = document.querySelectorAll('[data-incident]');
        if (items.length <= perPage) return;
        var page = 0;
        var totalPages = Math.ceil(items.length / perPage);
        var pag = document.getElementById('incident-pagination');
        function show() {{
            for (var i = 0; i < items.length; i++) {{
                items[i].style.display = (i >= page * perPage && i < (page + 1) * perPage) ? '' : 'none';
            }}
            pag.innerHTML = '<button id="ip-prev">&larr; Prev</button>' +
                '<span class="page-info">Page ' + (page + 1) + ' of ' + totalPages + ' (' + items.length + ' incidents)</span>' +
                '<button id="ip-next">Next &rarr;</button>';
            document.getElementById('ip-prev').disabled = page === 0;
            document.getElementById('ip-next').disabled = page >= totalPages - 1;
            document.getElementById('ip-prev').onclick = function() {{ if (page > 0) {{ page--; show(); }} }};
            document.getElementById('ip-next').onclick = function() {{ if (page < totalPages - 1) {{ page++; show(); }} }};
        }}
        show();
    }})();
    </script>
</body>
</html>"#,
        title = html_escape(&page.title),
        logo = logo_html,
        body_bg = tc.body_bg,
        text = tc.text,
        heading = tc.heading,
        card_bg = tc.card_bg,
        card_border = tc.card_border,
        muted = tc.muted,
        secondary = tc.secondary,
        divider = tc.divider,
        overall_bg = overall_status_bg(overall),
        overall_border = overall_status_border(overall),
        overall_color = overall.color(),
        overall_emoji = overall.emoji(),
        overall_label = match overall {
            MonitorStatus::Up => "All Systems Operational",
            MonitorStatus::Degraded => "Some Systems Degraded",
            MonitorStatus::Down => "Major System Outage",
            MonitorStatus::Unknown => "Status Unknown",
        },
        services = services_html,
        incidents = incidents_html,
        footer = html_escape(footer_text),
    ))
}

/// Render a status page index listing all available pages for this cluster
pub fn render_index_page(state: &Arc<StatusPageState>, local_cluster: &str) -> String {
    let pages = state.list_pages_for_cluster(local_cluster);
    let enabled_pages: Vec<_> = pages.iter().filter(|(_, _, enabled)| *enabled).collect();

    if enabled_pages.is_empty() {
        return not_enabled_html();
    }

    // If only one page, redirect to it
    if enabled_pages.len() == 1 {
        return format!(
            r#"<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=/status/{}"></head><body></body></html>"#,
            html_escape(&enabled_pages[0].0)
        );
    }

    let mut links_html = String::new();
    for (slug, title, _) in &enabled_pages {
        links_html.push_str(&format!(
            r#"<a href="/status/{slug}" class="page-link">
                <div class="page-title">{title}</div>
                <div class="page-url">/status/{slug}</div>
            </a>"#,
            slug = html_escape(slug),
            title = html_escape(title),
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Status Pages</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Inter', sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh;
            display: flex; align-items: center; justify-content: center; }}
        .container {{ max-width: 480px; width: 100%; padding: 2rem; }}
        h1 {{ text-align: center; font-size: 1.3rem; margin-bottom: 1.5rem; color: #f8fafc; }}
        .page-link {{ display: block; background: #1e293b; border: 1px solid #334155; border-radius: 10px;
            padding: 1.25rem; margin-bottom: 0.75rem; text-decoration: none; color: #e2e8f0;
            transition: all 0.2s; }}
        .page-link:hover {{ border-color: #22c55e; transform: translateY(-2px); }}
        .page-title {{ font-weight: 600; font-size: 1rem; }}
        .page-url {{ font-size: 0.8rem; color: #64748b; margin-top: 4px; }}
        .footer {{ text-align: center; margin-top: 2rem; font-size: 0.75rem; color: #475569; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Status Pages</h1>
        {links}
        <div class="footer">Powered by WolfStack</div>
    </div>
</body>
</html>"#,
        links = links_html,
    )
}

fn not_enabled_html() -> String {
    r#"<!DOCTYPE html><html><head><title>Status</title></head><body style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;background:#0f172a;color:#fff;"><p>Status page is not enabled.</p></body></html>"#.to_string()
}

/// Number of daily bars drawn on the uptime strip. The admin UI's monitor
/// cards draw the same window (`renderUptimeBar` in web/js/app.js) so the
/// two views cannot disagree.
pub const UPTIME_BAR_DAYS: i64 = 90;

/// Colour for a single day's uptime. Mirrored in `renderUptimeBar`
/// (web/js/app.js) — change both together.
fn uptime_bar_color(uptime_percent: f32) -> &'static str {
    if uptime_percent >= 99.5 {
        "#22c55e"
    } else if uptime_percent >= 95.0 {
        "#eab308"
    } else {
        "#ef4444"
    }
}

fn build_uptime_bars(daily: &[DailyUptime], bar_empty: &str) -> String {
    // Anchor every bar to a calendar date rather than walking the stored
    // entries in order. Days with no checks at all (monitor paused, node
    // down) write no entry, so index-walking would silently slide older
    // days rightwards and make "Today" a bar from some earlier date.
    let by_date: HashMap<&str, &DailyUptime> =
        daily.iter().map(|d| (d.date.as_str(), d)).collect();
    let today = chrono::Utc::now().date_naive();
    let mut bars = String::new();

    for offset in (0..UPTIME_BAR_DAYS).rev() {
        let date = (today - chrono::Duration::days(offset)).format("%Y-%m-%d").to_string();
        match by_date.get(date.as_str()) {
            Some(day) => bars.push_str(&format!(
                r#"<div class="uptime-bar" style="background:{};" title="{}: {:.1}% uptime"></div>"#,
                uptime_bar_color(day.uptime_percent), day.date, day.uptime_percent
            )),
            None => bars.push_str(&format!(
                r#"<div class="uptime-bar" style="background:{};" title="{}: no data"></div>"#,
                bar_empty, date
            )),
        }
    }
    bars
}

fn overall_status_bg(status: MonitorStatus) -> &'static str {
    match status {
        MonitorStatus::Up => "rgba(34,197,94,0.1)",
        MonitorStatus::Degraded => "rgba(234,179,8,0.1)",
        MonitorStatus::Down => "rgba(239,68,68,0.1)",
        MonitorStatus::Unknown => "rgba(107,114,128,0.1)",
    }
}

fn overall_status_border(status: MonitorStatus) -> &'static str {
    match status {
        MonitorStatus::Up => "rgba(34,197,94,0.3)",
        MonitorStatus::Degraded => "rgba(234,179,8,0.3)",
        MonitorStatus::Down => "rgba(239,68,68,0.3)",
        MonitorStatus::Unknown => "rgba(107,114,128,0.3)",
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Format an ISO 8601 timestamp into a human-readable date/time string.
/// e.g. "2025-03-15T14:30:00Z" → "15 Mar 2025, 14:30 UTC"
fn format_iso_date(iso: &str) -> String {
    // Try parsing with timezone suffix
    let normalized = if let Some(without_z) = iso.strip_suffix('Z') {
        format!("{}+00:00", without_z)
    } else if iso.contains('+') || iso.matches('-').count() > 2 {
        iso.to_string()
    } else {
        format!("{}+00:00", iso)
    };
    match chrono::DateTime::parse_from_rfc3339(&normalized) {
        Ok(dt) => dt.format("%d %b %Y, %H:%M UTC").to_string(),
        Err(_) => iso.to_string(), // fallback to raw string
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_incident_deser() {
        // With impact field
        let json = r#"{"id":"i1","title":"Test","status":"investigating","cluster":"WolfStack","impact":"critical","service_ids":[],"updates":[],"created_at":"2025-01-01T00:00:00Z"}"#;
        let result: Result<Incident, _> = serde_json::from_str(json);
        assert!(result.is_ok(), "with impact failed: {:?}", result.err());
        assert_eq!(result.unwrap().impact, Some("critical".to_string()));

        // Without impact field (should default to None)
        let json = r#"{"id":"i2","title":"Test","status":"investigating","cluster":"WolfStack","created_at":"2025-01-01T00:00:00Z"}"#;
        let result: Result<Incident, _> = serde_json::from_str(json);
        assert!(result.is_ok(), "without impact failed: {:?}", result.err());
        assert_eq!(result.unwrap().impact, None);

        // Without service_ids (should default to empty vec)
        let json = r#"{"id":"i3","title":"Test","status":"resolved","cluster":"WolfStack","created_at":"2025-01-01T00:00:00Z"}"#;
        let result: Result<Incident, _> = serde_json::from_str(json);
        assert!(result.is_ok(), "without service_ids failed: {:?}", result.err());
        assert!(result.unwrap().service_ids.is_empty());
    }

    #[test]
    fn test_monitor_deser() {
        let cases = vec![
            ("http", r#"{"id":"t1","name":"HTTP","cluster":"WolfStack","check":{"type":"http","url":"https://google.com","expected_status":200},"interval_secs":60,"timeout_secs":10,"enabled":true}"#),
            ("tcp", r#"{"id":"t2","name":"TCP","cluster":"WolfStack","check":{"type":"tcp","host":"1.2.3.4","port":80},"interval_secs":60,"timeout_secs":10,"enabled":true}"#),
            ("ping", r#"{"id":"t3","name":"Ping","cluster":"WolfStack","check":{"type":"ping","host":"1.2.3.4"},"interval_secs":60,"timeout_secs":10,"enabled":true}"#),
            ("container", r#"{"id":"t4","name":"Container","cluster":"WolfStack","check":{"type":"container","runtime":"docker","name":"nginx"},"interval_secs":60,"timeout_secs":10,"enabled":true}"#),
            ("container+node", r#"{"id":"t5","name":"Container","cluster":"WolfStack","check":{"type":"container","runtime":"docker","name":"nginx","node_id":"abc"},"interval_secs":60,"timeout_secs":10,"enabled":true}"#),
            ("wolfrun", r#"{"id":"t6","name":"WR","cluster":"WolfStack","check":{"type":"wolfrun","service_id":"s1","service_name":"Svc","min_healthy":1,"health_check":"running"},"interval_secs":60,"timeout_secs":10,"enabled":true}"#),
        ];
        for (label, json) in cases {
            let result: Result<Monitor, _> = serde_json::from_str(json);
            assert!(result.is_ok(), "{} failed: {:?}", label, result.err());
        }
    }
}
