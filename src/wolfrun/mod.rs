// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! WolfRun — Native Container Orchestration for WolfStack
//!
//! Schedules Docker and LXC containers across cluster nodes using:
//! - ClusterState for node metrics and health
//! - WolfNet for automatic overlay networking
//! - AppStore manifests for deployment configuration
//!
//! Zero external dependencies — no etcd, kubelet, or CNI plugins.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::agent::ClusterState;
use crate::node_identity::PeerAuth;

// ─── Shared HTTP client for cluster RPC ───
//
// Every HTTP call this module makes to a peer goes through one of these
// two statics. Previously `reconcile()` and `broadcast_to_cluster()`
// built a fresh `reqwest::Client` on every 15s tick — each client owns
// its own connection pool + background worker, so dropping it orphaned
// live connections that the kernel eventually parked in CLOSE_WAIT on
// our side once the peer FIN'd them. On long-running cluster hosts
// this accumulated to tens of thousands of leaked FDs and eventually
// knocked out actix_server with "No file descriptors available".
//
// LazyLock<Client> means one pool for the lifetime of the process,
// connections keep-alive between calls, and everything drops cleanly
// only on process exit. Same pattern the agent poller uses at
// src/agent/mod.rs:765-772.
//
// Two clients because reconcile needs a longer timeout (container
// state queries can be slow on a loaded node); sync + broadcast
// prefer a tighter 10s so a hung peer doesn't stall the whole tick.
// Pool tuning, shared across all three clients:
// - `pool_idle_timeout(15s)`: reap idle pooled connections after 15s
//   instead of the reqwest default of 90s. Peers often close their
//   side well before 90s, leaving us with CLOSE_WAIT sockets until
//   the reap. Reported by Bel after v19.9.0.
// - `pool_max_idle_per_host(4)`: keep the per-peer pool small —
//   there's only one tick firing at a time.
// - `tcp_keepalive(30s)`: kernel probes detect half-dead connections
//   and tear them down before they need app-level cleanup.
static RPC_CLIENT_SHORT: std::sync::LazyLock<reqwest::Client> =
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

static RPC_CLIENT_LONG: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .timeout(std::time::Duration::from_secs(120))
            .danger_accept_invalid_certs(true)
            .pool_idle_timeout(std::time::Duration::from_secs(15))
            .pool_max_idle_per_host(4)
            .tcp_keepalive(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

static RPC_CLIENT_MIGRATE: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .timeout(std::time::Duration::from_secs(600))
            .danger_accept_invalid_certs(true)
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .pool_max_idle_per_host(2)
            .tcp_keepalive(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

/// Fire a request, drain the body so the socket can return to the
/// keepalive pool, and return whether the response was 2xx. Dropping
/// a `reqwest::Response` without consuming its body prevents reqwest
/// from reclaiming the underlying TCP connection — on the next call
/// a new connection is opened, and the unread one eventually shows up
/// in `ss -tn state close-wait`. Every call site in this module that
/// used to do `.send().await.is_ok()` or drop the Response unconsumed
/// now goes through here.
async fn send_and_drain(req: reqwest::RequestBuilder) -> Option<bool> {
    match req.send().await {
        Ok(resp) => {
            let ok = resp.status().is_success();
            let _ = resp.bytes().await;
            Some(ok)
        }
        Err(_) => None,
    }
}

// ─── Data Model ───

/// Container runtime for a service
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[derive(Default)]
pub enum Runtime {
    #[default]
    Docker,
    Lxc,
}


/// Placement strategy for a service
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub enum Placement {
    /// Schedule on any eligible node (default — spread across nodes)
    #[default]
    Any,
    /// Prefer a specific node but allow others if unavailable
    PreferNode(String),
    /// Only run on a specific node
    RequireNode(String),
}


/// Restart policy for containers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub enum RestartPolicy {
    #[default]
    Always,
    OnFailure,
    Never,
}


/// A single running instance of a service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInstance {
    pub node_id: String,
    pub container_name: String,
    pub wolfnet_ip: Option<String>,
    pub status: String,        // "running", "stopped", "pending", "lost", "standby"
    pub last_seen: u64,        // unix timestamp
    /// Standby instance — pre-created but stopped, ready for failover
    #[serde(default)]
    pub standby: bool,
}

/// A failover event — records when a standby was promoted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverEvent {
    pub timestamp: u64,
    pub service_id: String,
    pub service_name: String,
    pub from_node: String,
    pub to_node: String,
    pub container_name: String,
    pub detail: String,
}

/// LXC-specific configuration for a service
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LxcConfig {
    #[serde(default = "default_distro")]
    pub distribution: String,
    #[serde(default = "default_release")]
    pub release: String,
    #[serde(default = "default_arch")]
    pub architecture: String,
}
fn default_distro() -> String { "ubuntu".to_string() }
fn default_release() -> String { "jammy".to_string() }
// Host arch (arm64 on RK3588/OrangePi), so a config predating the arch field
// doesn't default an ARM node's LXC to an unbootable amd64 rootfs.
fn default_arch() -> String { crate::containers::host_container_arch().to_string() }

/// A WolfRun service definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfRunService {
    pub id: String,
    pub name: String,
    /// Docker image (for Docker runtime) or unused for LXC
    pub image: String,
    pub replicas: u32,
    /// Minimum number of replicas (scale-down floor)
    #[serde(default)]
    pub min_replicas: u32,
    /// Maximum number of replicas (scale-up ceiling)
    #[serde(default = "default_max_replicas")]
    pub max_replicas: u32,
    #[serde(default)]
    pub runtime: Runtime,
    #[serde(default)]
    pub lxc_config: Option<LxcConfig>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
    pub cluster_name: String,
    #[serde(default)]
    pub placement: Placement,
    #[serde(default)]
    pub restart_policy: RestartPolicy,
    #[serde(default)]
    pub instances: Vec<ServiceInstance>,
    /// Load-balanced virtual IP on WolfNet (auto-assigned)
    #[serde(default)]
    pub service_ip: Option<String>,
    /// Load balancer policy: "round_robin" (default) or "ip_hash" (sticky sessions)
    #[serde(default = "default_lb_policy")]
    pub lb_policy: String,
    /// Allowed node IDs — empty means all nodes are eligible
    #[serde(default)]
    pub allowed_nodes: Vec<String>,
    /// Failover enabled — pre-stage standby containers on other nodes
    #[serde(default)]
    pub failover: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

fn default_max_replicas() -> u32 { 10 }
fn default_lb_policy() -> String { "round_robin".to_string() }

// ─── State Management ───

fn services_dir() -> String { crate::paths::get().wolfrun_dir }
fn services_file() -> String { crate::paths::get().wolfrun_services }
fn failover_events_file() -> String { crate::paths::get().wolfrun_failover_events }
fn tombstones_file() -> String { format!("{}/deleted.json", services_dir()) }

/// How long a deletion tombstone is remembered. Long enough that any
/// node that was offline across the deletion (an update, an outage)
/// still hits the tombstone when it comes back with its stale
/// services.json; short enough the file can't grow forever.
const TOMBSTONE_RETENTION_SECS: u64 = 30 * 24 * 3600;
/// Hard cap on remembered tombstones — oldest are dropped first.
const TOMBSTONE_MAX: usize = 500;

/// Shared WolfRun state
pub struct WolfRunState {
    services: RwLock<Vec<WolfRunService>>,
    failover_events: RwLock<Vec<FailoverEvent>>,
    /// Deletion tombstones: service id → unix time it was deleted.
    ///
    /// Why these exist: a deleted service used to resurrect. The
    /// services-list broadcast skips entirely when the local list is
    /// empty, and merge_from_peer only replaces clusters PRESENT in an
    /// incoming payload — so "the last service of a cluster was
    /// deleted" was unrepresentable on the wire. Any peer still holding
    /// the service (or a node restarting with a stale services.json
    /// after an update) gossiped it straight back, and the leader
    /// dutifully recreated its containers (klas, 2026-08-12).
    /// Tombstones make deletion explicit: merges drop tombstoned ids,
    /// and the sync reply tells the stale sender to clean up too.
    deleted: RwLock<HashMap<String, u64>>,
}

/// True if registry node `n` is the node referenced by `id`, matching EITHER its
/// locally-assigned key (`node-…`, used for remote nodes) OR its global self_id
/// (`ws-…`, which is the registry key for the SELF node). WolfRun records an
/// instance's `node_id` as whichever form the registry used at schedule time, so
/// a later lookup MUST accept both — otherwise an instance whose recorded form no
/// longer matches the entry's current key is false-orphaned (reported on a "dead"
/// id, or wrongly rescheduled) even though the node is online. This is the online
/// `node-…`/`ws-…` mismatch AstroMando hit (2026-06-28); it mirrors how
/// ClusterState::get_node already resolves either form.
pub(crate) fn node_matches_id(n: &crate::agent::Node, id: &str) -> bool {
    n.id == id || n.self_id.as_deref() == Some(id)
}

impl WolfRunState {
    pub fn new() -> Self {
        let state = Self {
            services: RwLock::new(Vec::new()),
            failover_events: RwLock::new(Vec::new()),
            deleted: RwLock::new(HashMap::new()),
        };
        state.load();
        state.load_failover_events();
        state.load_tombstones();
        state
    }

    /// Load services from disk
    fn load(&self) {
        if let Ok(data) = std::fs::read_to_string(services_file())
            && let Ok(services) = serde_json::from_str::<Vec<WolfRunService>>(&data) {
                let mut svcs = self.services.write().unwrap();
                *svcs = services;

            }
    }

    /// Save services to disk
    fn save(&self) {
        let svcs = self.services.read().unwrap();
        if let Ok(json) = serde_json::to_string_pretty(&*svcs) {
            let _ = std::fs::create_dir_all(services_dir());
            if let Err(e) = std::fs::write(services_file(), json) {
                warn!("WolfRun: failed to save services: {}", e);
            }
        }
    }

    /// Load failover events from disk
    fn load_failover_events(&self) {
        if let Ok(data) = std::fs::read_to_string(failover_events_file())
            && let Ok(events) = serde_json::from_str::<Vec<FailoverEvent>>(&data) {
                let mut evts = self.failover_events.write().unwrap();
                *evts = events;
            }
    }

    /// Save failover events to disk
    fn save_failover_events(&self) {
        let evts = self.failover_events.read().unwrap();
        if let Ok(json) = serde_json::to_string_pretty(&*evts) {
            let _ = std::fs::create_dir_all(services_dir());
            if let Err(e) = std::fs::write(failover_events_file(), json) {
                warn!("WolfRun: failed to save failover events: {}", e);
            }
        }
    }

    /// Load deletion tombstones from disk
    fn load_tombstones(&self) {
        if let Ok(data) = std::fs::read_to_string(tombstones_file())
            && let Ok(map) = serde_json::from_str::<HashMap<String, u64>>(&data)
        {
            let mut del = self.deleted.write().unwrap();
            *del = map;
            Self::prune_tombstones(&mut del);
        }
    }

    /// Save deletion tombstones to disk
    fn save_tombstones(&self) {
        let del = self.deleted.read().unwrap();
        if let Ok(json) = serde_json::to_string_pretty(&*del) {
            let _ = std::fs::create_dir_all(services_dir());
            if let Err(e) = std::fs::write(tombstones_file(), json) {
                warn!("WolfRun: failed to save deletion tombstones: {}", e);
            }
        }
    }

    /// Drop tombstones past retention, and oldest-first past the cap.
    fn prune_tombstones(del: &mut HashMap<String, u64>) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        del.retain(|_, ts| now.saturating_sub(*ts) < TOMBSTONE_RETENTION_SECS);
        while del.len() > TOMBSTONE_MAX {
            if let Some(oldest) = del.iter().min_by_key(|(_, ts)| **ts).map(|(id, _)| id.clone()) {
                del.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// Remember that `service_id` was deleted so peer gossip can never
    /// resurrect it. Idempotent.
    pub fn record_tombstone(&self, service_id: &str) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut del = self.deleted.write().unwrap();
        del.insert(service_id.to_string(), now);
        Self::prune_tombstones(&mut del);
        drop(del);
        self.save_tombstones();
    }

    /// True if this service id was deleted here (or a deletion was
    /// learned from a peer) within the tombstone retention window.
    /// Production code never asks — the merge does its own filtering
    /// under one lock — so this is a test-only observation point.
    #[cfg(test)]
    pub fn is_tombstoned(&self, service_id: &str) -> bool {
        self.deleted.read().unwrap().contains_key(service_id)
    }

    /// Record a failover event
    pub fn add_failover_event(&self, event: FailoverEvent) {
        let mut evts = self.failover_events.write().unwrap();
        evts.push(event);
        // Keep last 100 events
        if evts.len() > 100 {
            let drain = evts.len() - 100;
            evts.drain(..drain);
        }
        drop(evts);
        self.save_failover_events();
    }

    /// Get failover events, optionally filtered by service ID
    pub fn get_failover_events(&self, service_id: Option<&str>) -> Vec<FailoverEvent> {
        let evts = self.failover_events.read().unwrap();
        match service_id {
            Some(id) => evts.iter().filter(|e| e.service_id == id).cloned().collect(),
            None => evts.clone(),
        }
    }

    /// Re-point every service instance recorded against `old_node_id` onto
    /// `new_node_id`, returning how many were moved. Used by join-time
    /// identity reconciliation: when a reimaged node returns under a new
    /// registry id, the instances it was running were recorded against its
    /// pre-reimage id. Without remapping, WolfRun would keep reporting those
    /// workloads "running" on a node that no longer exists and schedule
    /// replacements against a dead id (AstroMando #3, 2026-06-27).
    pub fn remap_node_id(&self, old_node_id: &str, new_node_id: &str) -> usize {
        if old_node_id == new_node_id || old_node_id.is_empty() { return 0; }
        let mut svcs = self.services.write().unwrap();
        let mut moved = 0usize;
        for svc in svcs.iter_mut() {
            for inst in svc.instances.iter_mut() {
                if inst.node_id == old_node_id {
                    inst.node_id = new_node_id.to_string();
                    moved += 1;
                }
            }
        }
        drop(svcs);
        if moved > 0 {
            self.save();
        }
        moved
    }

    /// Rename all cluster references from old_name to new_name.
    pub fn rename_cluster(&self, old_name: &str, new_name: &str) -> usize {
        let mut svcs = self.services.write().unwrap();
        let mut count = 0;
        for svc in svcs.iter_mut() {
            // Case-insensitive, like every cluster-name comparison.
            if svc.cluster_name.eq_ignore_ascii_case(old_name) {
                svc.cluster_name = new_name.to_string();
                count += 1;
            }
        }
        drop(svcs);
        if count > 0 {
            self.save();
        }
        count
    }

    /// List all services, optionally filtered by cluster
    pub fn list(&self, cluster: Option<&str>) -> Vec<WolfRunService> {
        let svcs = self.services.read().unwrap();
        match cluster {
            Some(c) => svcs.iter().filter(|s| s.cluster_name == c).cloned().collect(),
            None => svcs.clone(),
        }
    }

    /// Get a single service by ID
    pub fn get(&self, id: &str) -> Option<WolfRunService> {
        let svcs = self.services.read().unwrap();
        svcs.iter().find(|s| s.id == id).cloned()
    }

    /// Create a new service
    #[allow(clippy::too_many_arguments)]
    pub fn create(&self, name: String, image: String, replicas: u32, cluster_name: String,
                  env: Vec<String>, ports: Vec<String>, volumes: Vec<String>,
                  placement: Placement, restart_policy: RestartPolicy,
                  runtime: Runtime, lxc_config: Option<LxcConfig>,
                  failover: bool) -> WolfRunService {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let id = format!("svc-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        // Allocate a Service VIP on WolfNet for load balancing
        let service_ip = crate::containers::next_available_wolfnet_ip();

        let svc = WolfRunService {
            id: id.clone(),
            name,
            image,
            replicas,
            min_replicas: 0,
            max_replicas: 10,
            runtime,
            lxc_config,
            env,
            ports,
            volumes,
            cluster_name,
            placement,
            restart_policy,
            instances: Vec::new(),
            service_ip,
            lb_policy: "round_robin".to_string(),
            allowed_nodes: Vec::new(),
            failover,
            created_at: now,
            updated_at: now,
        };
        {
            let mut svcs = self.services.write().unwrap();
            svcs.push(svc.clone());
        }
        self.save();

        svc
    }

    /// Delete a service by ID — returns the removed service (caller should stop instances).
    /// Records a tombstone so peer gossip can't resurrect the service.
    pub fn delete(&self, id: &str) -> Option<WolfRunService> {
        let mut svcs = self.services.write().unwrap();
        let idx = svcs.iter().position(|s| s.id == id);
        let removed = idx.map(|i| svcs.remove(i));
        drop(svcs);
        if removed.is_some() {
            self.save();
            self.record_tombstone(id);
        }
        removed
    }

    /// Scale a service — updates desired replica count
    pub fn scale(&self, id: &str, replicas: u32) -> bool {
        let mut svcs = self.services.write().unwrap();
        if let Some(svc) = svcs.iter_mut().find(|s| s.id == id) {
            // Auto-raise max if user is scaling beyond current max
            if replicas > svc.max_replicas {
                svc.max_replicas = replicas;
            }
            let clamped = replicas.max(svc.min_replicas).min(svc.max_replicas);
            svc.replicas = clamped;
            svc.updated_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            drop(svcs);
            self.save();

            true
        } else {
            false
        }
    }

    /// Update service settings (min, max, desired replicas)
    pub fn update_settings(&self, id: &str, min: Option<u32>, max: Option<u32>, desired: Option<u32>, lb_policy: Option<String>, allowed_nodes: Option<Vec<String>>, failover: Option<bool>) -> bool {
        let mut svcs = self.services.write().unwrap();
        if let Some(svc) = svcs.iter_mut().find(|s| s.id == id) {
            if let Some(mn) = min { svc.min_replicas = mn; }
            if let Some(mx) = max { svc.max_replicas = mx; }
            if let Some(d) = desired { svc.replicas = d; }
            if let Some(p) = lb_policy
                && (p == "ip_hash" || p == "round_robin") { svc.lb_policy = p; }
            if let Some(nodes) = allowed_nodes {
                svc.allowed_nodes = nodes;
            }
            if let Some(f) = failover { svc.failover = f; }
            // Enforce: min <= desired <= max
            if svc.min_replicas > svc.max_replicas { svc.min_replicas = svc.max_replicas; }
            svc.replicas = svc.replicas.max(svc.min_replicas).min(svc.max_replicas);
            svc.updated_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            drop(svcs);
            self.save();
            true
        } else {
            false
        }
    }

    /// Update image for a service (for rolling updates — Docker only)
    pub fn update_image(&self, id: &str, image: String) -> bool {
        let mut svcs = self.services.write().unwrap();
        if let Some(svc) = svcs.iter_mut().find(|s| s.id == id) {
            svc.image = image.clone();
            svc.updated_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            drop(svcs);
            self.save();

            true
        } else {
            false
        }
    }

    /// Update instances for a service (called by reconciliation)
    pub fn update_instances(&self, id: &str, instances: Vec<ServiceInstance>) {
        let mut svcs = self.services.write().unwrap();
        if let Some(svc) = svcs.iter_mut().find(|s| s.id == id) {
            svc.instances = instances;
            svc.updated_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        }
        drop(svcs);
        self.save();
    }

    /// Adopt an existing container as a WolfRun service.
    /// The container is registered as the first running instance.
    pub fn adopt(
        &self,
        name: String,
        container_name: String,
        node_id: String,
        image: String,
        runtime: Runtime,
        cluster_name: String,
        env: Vec<String>,
        ports: Vec<String>,
        volumes: Vec<String>,
    ) -> WolfRunService {
        let id = uuid::Uuid::new_v4().to_string();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let instance = ServiceInstance {
            container_name: container_name.clone(),
            node_id,
            status: "running".to_string(),
            wolfnet_ip: None,
            last_seen: now,
            standby: false,
        };

        // Allocate a Service VIP on WolfNet for load balancing
        let service_ip = crate::containers::next_available_wolfnet_ip();

        let svc = WolfRunService {
            id: id.clone(),
            name,
            image: image.clone(),
            replicas: 1,
            min_replicas: 1,
            max_replicas: 10,
            runtime: runtime.clone(),
            lxc_config: match &runtime {
                Runtime::Lxc => {
                    // Parse image field like "ubuntu 24.04" into distribution + release
                    let parts: Vec<&str> = image.splitn(2, ' ').collect();
                    Some(LxcConfig {
                        distribution: parts.first().unwrap_or(&"ubuntu").to_string(),
                        release: parts.get(1).unwrap_or(&"24.04").to_string(),
                        // Host arch (arm64 on RK3588/OrangePi), not a hardcoded
                        // amd64 — else the LXC pulls a wrong-arch, unbootable rootfs.
                        architecture: crate::containers::host_container_arch().to_string(),
                    })
                }
                _ => None,
            },
            env,
            ports,
            volumes,
            cluster_name,
            placement: Placement::Any,
            restart_policy: RestartPolicy::Always,
            instances: vec![instance],
            service_ip,
            lb_policy: "round_robin".to_string(),
            allowed_nodes: Vec::new(),
            failover: false,
            created_at: now,
            updated_at: now,
        };
        {
            let mut svcs = self.services.write().unwrap();
            svcs.push(svc.clone());
        }
        self.save();

        svc
    }

    /// Add an instance to a service
    pub fn add_instance(&self, service_id: &str, instance: ServiceInstance) {
        let mut svcs = self.services.write().unwrap();
        if let Some(svc) = svcs.iter_mut().find(|s| s.id == service_id) {
            svc.instances.push(instance);
        }
        drop(svcs);
        self.save();
    }

    /// Remove an instance from a service by container name
    pub fn remove_instance(&self, service_id: &str, container_name: &str) {
        let mut svcs = self.services.write().unwrap();
        if let Some(svc) = svcs.iter_mut().find(|s| s.id == service_id) {
            svc.instances.retain(|i| i.container_name != container_name);
        }
        drop(svcs);
        self.save();
    }

    /// Look up which WolfRun services reference a given container —
    /// used by the UI to warn users before they delete a container
    /// that will just be reconciled back into existence by this
    /// service. Returns the list of (service_id, service_name) pairs.
    pub fn services_managing(&self, container_name: &str) -> Vec<(String, String)> {
        self.services.read().unwrap().iter()
            .filter(|s| s.instances.iter().any(|i| i.container_name == container_name))
            .map(|s| (s.id.clone(), s.name.clone()))
            .collect()
    }


    /// Merge services received from a cluster peer.
    /// Strategy: for each cluster represented in the incoming data, REPLACE all
    /// local services for that cluster with the peer's versions. Services for
    /// clusters NOT in the incoming data are preserved unchanged.
    /// This ensures stale/junk entries don't accumulate.
    ///
    /// Tombstoned services are NEVER accepted — a peer that missed the
    /// deletion (offline, mid-update, stale services.json) would otherwise
    /// resurrect the service here. Returns the ids that were rejected so
    /// the sync endpoint can tell the sender to delete them too.
    pub fn merge_from_peer(&self, peer_services: Vec<WolfRunService>) -> Vec<String> {
        if peer_services.is_empty() { return Vec::new(); }

        // Identify which clusters the peer is sending data for — from the
        // FULL payload, before tombstone filtering: if the peer's whole view
        // of a cluster is one tombstoned service, the truthful merged view
        // of that cluster is "empty", not "unchanged".
        let peer_clusters: std::collections::HashSet<String> = peer_services.iter()
            .map(|s| s.cluster_name.clone())
            .collect();

        let (rejected, accepted): (Vec<WolfRunService>, Vec<WolfRunService>) = {
            let del = self.deleted.read().unwrap();
            peer_services.into_iter().partition(|s| del.contains_key(&s.id))
        };
        let rejected_ids: Vec<String> = rejected.into_iter().map(|s| s.id).collect();

        let mut svcs = self.services.write().unwrap();

        // Remove all local services for the incoming clusters
        svcs.retain(|s| !peer_clusters.contains(&s.cluster_name));

        // Add the peer services that survived the tombstone filter
        svcs.extend(accepted);

        drop(svcs);
        self.save();
        rejected_ids
    }

    /// Mark a service as deleted by removing it from our list (called when a
    /// peer broadcasts a deletion via /api/wolfrun/sync-delete). Always
    /// records the tombstone — even when the service isn't present locally —
    /// so later gossip carrying it is rejected too.
    pub fn remove_if_exists(&self, service_id: &str) -> bool {
        let mut svcs = self.services.write().unwrap();
        let before = svcs.len();
        svcs.retain(|s| s.id != service_id);
        let removed = svcs.len() < before;
        drop(svcs);
        if removed {
            self.save();
        }
        self.record_tombstone(service_id);
        removed
    }

    /// Get all services (no filter) — used for broadcasting
    pub fn list_all(&self) -> Vec<WolfRunService> {
        self.services.read().unwrap().clone()
    }
}

/// Broadcast the current WolfRun services list to all online same-cluster peers.
/// Called after any mutation (create, delete, scale, adopt, update settings).
pub async fn broadcast_to_cluster(
    wolfrun: &WolfRunState,
    cluster: &ClusterState,
    cluster_secret: &str,
) {
    let services = wolfrun.list_all();
    // Zero-service fast path — skip the whole peer fan-out. Without
    // this every node was POSTing an empty services payload to every
    // peer every 15s, burning sockets + CPU even on clusters that
    // don't use WolfRun at all. Reported by Bel: CPU climbing from
    // ~15% baseline to 90% alongside CLOSE_WAIT accumulation at
    // :8553, no WolfRun services configured.
    if services.is_empty() {
        return;
    }
    let nodes = cluster.get_all_nodes();

    // Find our cluster name
    let self_cluster = nodes.iter()
        .find(|n| n.is_self)
        .and_then(|n| n.cluster_name.clone())
        .unwrap_or_else(|| "WolfStack".to_string());

    // Process-wide shared client — see RPC_CLIENT_SHORT docs at top of
    // file. Previously we built a fresh client here on every 15s tick;
    // that was the primary cause of CLOSE_WAIT accumulation to peers.
    let client = &*RPC_CLIENT_SHORT;

    // A peer that already knows a service was deleted answers the sync
    // with the tombstoned ids it refused. That is how a STALE node —
    // one that slept through the deletion and is now re-broadcasting
    // the ghost service — learns the truth: it destroys the containers
    // it recreated and drops the service. Without this reply channel a
    // stale leader would resurrect the service forever.
    #[derive(Deserialize)]
    struct SyncReply {
        #[serde(default)]
        deleted_ids: Vec<String>,
    }
    let mut peer_deleted: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Send to all online same-cluster peers (not self)
    for node in &nodes {
        if node.is_self || !node.online {
            continue;
        }
        let node_cluster = node.cluster_name.as_deref().unwrap_or("WolfStack");
        if node_cluster != self_cluster {
            continue;
        }

        let urls = crate::api::build_node_urls(&node.address, node.port, "/api/wolfrun/sync");
        for url in &urls {
            // The body is always consumed (json() or bytes()) so the
            // connection returns to the pool. `Ok(_)` previously dropped
            // the Response unconsumed, which was the leak source.
            match client.post(url)
                .peer_auth(cluster_secret)
                .json(&services)
                .send().await
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        // Old peers reply {"synced":true} with no
                        // deleted_ids — serde default gives an empty list.
                        if let Ok(reply) = resp.json::<SyncReply>().await {
                            peer_deleted.extend(reply.deleted_ids);
                        }
                    } else {
                        let _ = resp.bytes().await;
                    }
                    break;  // Success (or HTTP error) — move to next node
                }
                Err(_) => continue,
            }
        }
    }

    // Act on deletions we learned about: destroy the instances this stale
    // copy re-created, then drop the service (delete() records the
    // tombstone, so our next broadcast no longer carries the ghost).
    for id in peer_deleted {
        if let Some(svc) = wolfrun.get(&id) {
            tracing::info!(
                "WolfRun: peer reports service '{}' ({}) was deleted elsewhere — removing local copy and its instances",
                svc.name, id
            );
            if let Some(vip) = svc.service_ip.clone() {
                let _ = tokio::task::spawn_blocking(move || remove_lb_rules_for_vip(&vip)).await;
            }
            destroy_service_instances(&svc, cluster, cluster_secret).await;
            wolfrun.delete(&id);
        } else {
            // Nothing local to clean up — just remember the deletion.
            wolfrun.record_tombstone(&id);
        }
    }
}

/// Tell every online same-cluster peer that `service_id` was deleted.
/// Runs on the node where the operator deleted the service. This is
/// deliberately NOT part of the services-list broadcast: that broadcast
/// skips when the list is empty and replaces per-cluster, so "this
/// service is gone" was unrepresentable — the bug that resurrected
/// deleted services from peers (klas, 2026-08-12).
pub async fn broadcast_delete(
    cluster: &ClusterState,
    cluster_secret: &str,
    service_id: &str,
) {
    let nodes = cluster.get_all_nodes();
    let self_cluster = nodes.iter()
        .find(|n| n.is_self)
        .and_then(|n| n.cluster_name.clone())
        .unwrap_or_else(|| "WolfStack".to_string());
    let client = &*RPC_CLIENT_SHORT;
    let payload = serde_json::json!({ "service_id": service_id });

    for node in &nodes {
        if node.is_self || !node.online {
            continue;
        }
        if node.cluster_name.as_deref().unwrap_or("WolfStack") != self_cluster {
            continue;
        }
        let urls = crate::api::build_node_urls(&node.address, node.port, "/api/wolfrun/sync-delete");
        for url in &urls {
            if send_and_drain(
                client.post(url)
                    .peer_auth(cluster_secret)
                    .json(&payload)
            ).await.is_some() {
                break;
            }
        }
    }
}

/// Stop and destroy a service's instances everywhere, honouring the
/// delete-time keep rule: clones (names containing "wolfrun") and
/// standby instances are destroyed; an adopted original template
/// container is kept. Returns (destroyed, kept) container names.
/// Shared by the API delete handler and the stale-copy cleanup in
/// broadcast_to_cluster.
pub async fn destroy_service_instances(
    svc: &WolfRunService,
    cluster: &ClusterState,
    cluster_secret: &str,
) -> (Vec<String>, Vec<String>) {
    let mut destroyed: Vec<String> = Vec::new();
    let mut kept: Vec<String> = Vec::new();
    // Long-timeout client: a remote stop waits for the container's
    // grace period before the reply comes back.
    let client = &*RPC_CLIENT_LONG;

    for inst in &svc.instances {
        // Destroy clones and standby instances, leave the original template
        if !inst.container_name.contains("wolfrun") && !inst.standby {
            kept.push(inst.container_name.clone());
            continue;
        }
        if let Some(node) = cluster.get_node(&inst.node_id)
            && stop_and_remove(client, cluster_secret, &node, &inst.container_name, &svc.runtime).await
        {
            destroyed.push(inst.container_name.clone());
        }
    }
    (destroyed, kept)
}

/// Check if this node is the WolfRun leader for its cluster.
/// Leader = lowest alphabetical node ID among online same-cluster nodes.
/// This is deterministic and requires no election protocol.
pub fn is_leader(cluster: &ClusterState) -> bool {
    is_leader_among(&cluster.get_all_nodes(), &cluster.self_id)
}

/// Pure leader test — extracted from `is_leader` so it can be unit-tested
/// without constructing a `ClusterState` (which does filesystem I/O).
///
/// Elects on each node's CANONICAL global id (its `self_id`, the `ws-…`
/// form) rather than the local registry key. Remote nodes are often keyed
/// locally as `node-…` (e.g. on public-address joins) while the SELF node is
/// keyed as its `ws-…` self_id. Sorting raw keys sorts every peer's `node-…`
/// ahead of the self `ws-…`, so NO node ever sees its own id as lowest and
/// the cluster is left with no leader (placement/reconcile silently never
/// runs). Canonicalising first makes every node agree on the same ordering
/// and elect exactly one leader.
fn is_leader_among(nodes: &[crate::agent::Node], self_id: &str) -> bool {
    let self_cluster = nodes.iter()
        .find(|n| n.is_self)
        .and_then(|n| n.cluster_name.clone())
        .unwrap_or_else(|| "WolfStack".to_string());

    let mut cluster_node_ids: Vec<String> = nodes.iter()
        .filter(|n| {
            n.online && n.cluster_name.as_deref().unwrap_or("WolfStack") == self_cluster
        })
        .map(|n| n.self_id.clone().unwrap_or_else(|| n.id.clone()))
        .collect();

    cluster_node_ids.sort();

    // Leader is the lowest canonical id; if no nodes found, we are leader.
    match cluster_node_ids.first() {
        Some(leader_id) => leader_id == self_id,
        None => true,
    }
}

#[cfg(test)]
mod leader_election_tests {
    use super::is_leader_among;

    // Build a Node from a compact JSON spec (Node has no Default and 31
    // fields; most carry serde defaults). Pure — no filesystem I/O.
    fn node(id: &str, self_id: Option<&str>, is_self: bool) -> crate::agent::Node {
        serde_json::from_value(serde_json::json!({
            "id": id, "hostname": id, "address": "10.0.0.1", "port": 8553u16,
            "last_seen": 0, "metrics": serde_json::Value::Null, "components": [],
            "online": true, "is_self": is_self,
            "node_type": "wolfstack", "cluster_name": "intelligentwolf",
            "self_id": self_id,
        })).expect("valid test node")
    }

    // Each node's OWN registry view: itself keyed by its ws- self_id, peers
    // keyed by a local node- key but carrying their gossiped ws- self_id.
    fn view(me: &str, peers: &[(&str, &str)]) -> Vec<crate::agent::Node> {
        let mut nodes = vec![node(me, Some(me), true)];
        for (local_key, ws_id) in peers {
            nodes.push(node(local_key, Some(ws_id), false));
        }
        nodes
    }

    #[test]
    fn exactly_one_leader_on_mixed_id_cluster() {
        let a = view("ws-a", &[("node-b", "ws-b"), ("node-c", "ws-c")]);
        let b = view("ws-b", &[("node-a", "ws-a"), ("node-c", "ws-c")]);
        let c = view("ws-c", &[("node-a", "ws-a"), ("node-b", "ws-b")]);
        // ws-a is the lowest canonical id, so it is leader on every node's view.
        assert!(is_leader_among(&a, "ws-a"));
        assert!(!is_leader_among(&b, "ws-b"));
        assert!(!is_leader_among(&c, "ws-c"));
        let count = [
            is_leader_among(&a, "ws-a"),
            is_leader_among(&b, "ws-b"),
            is_leader_among(&c, "ws-c"),
        ].iter().filter(|x| **x).count();
        assert_eq!(count, 1, "exactly one node must be leader");
    }

    #[test]
    fn solo_node_is_leader() {
        assert!(is_leader_among(&view("ws-a", &[]), "ws-a"));
    }

    #[test]
    fn all_consistent_ids_still_elect_lowest() {
        // A normal cluster keyed entirely by ws- ids behaves unchanged.
        let nodes = view("ws-b", &[("ws-a", "ws-a"), ("ws-c", "ws-c")]);
        assert!(is_leader_among(&nodes, "ws-a"));
        assert!(!is_leader_among(&nodes, "ws-b"));
    }

    #[test]
    fn offline_lowest_is_skipped() {
        // If the lowest-id node is offline, leadership moves to the next.
        let mut nodes = view("ws-b", &[("node-a", "ws-a"), ("node-c", "ws-c")]);
        nodes.iter_mut().find(|n| n.self_id.as_deref() == Some("ws-a"))
            .unwrap().online = false;
        assert!(is_leader_among(&nodes, "ws-b"));
    }
}

#[cfg(test)]
mod tombstone_tests {
    use super::*;

    // Build a service from a compact JSON spec — most fields carry serde
    // defaults, so only the always-present ones are needed.
    fn svc(id: &str, cluster: &str) -> WolfRunService {
        serde_json::from_value(serde_json::json!({
            "id": id, "name": id, "image": "nginx", "replicas": 1u32,
            "cluster_name": cluster, "created_at": 0u64, "updated_at": 0u64,
        })).expect("valid test service")
    }

    // ONE test fn on purpose: paths::set_for_test mutates process-global
    // state and cargo runs tests in parallel — a second test in this
    // module could race another module's set_for_test.
    #[test]
    fn deleted_services_stay_deleted() {
        let tmp = std::env::temp_dir()
            .join(format!("wolfrun-tombstone-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("create temp wolfrun dir");
        let mut locs = crate::paths::FileLocations::default();
        locs.wolfrun_dir = tmp.to_string_lossy().into_owned();
        locs.wolfrun_services = tmp.join("services.json").to_string_lossy().into_owned();
        locs.wolfrun_failover_events =
            tmp.join("failover-events.json").to_string_lossy().into_owned();
        crate::paths::set_for_test(locs);

        let state = WolfRunState::new();

        // A peer pushes two services; both merge in cleanly.
        let rejected = state.merge_from_peer(vec![svc("svc-aaaa", "c1"), svc("svc-bbbb", "c1")]);
        assert!(rejected.is_empty());
        assert_eq!(state.list_all().len(), 2);

        // Local delete records a tombstone.
        assert!(state.delete("svc-aaaa").is_some());
        assert!(state.is_tombstoned("svc-aaaa"));
        assert_eq!(state.list_all().len(), 1);

        // The stale peer gossips the deleted service back — the exact
        // resurrection klas hit. It must be rejected AND reported, and the
        // live service from the same payload must still merge.
        let rejected = state.merge_from_peer(vec![svc("svc-aaaa", "c1"), svc("svc-bbbb", "c1")]);
        assert_eq!(rejected, vec!["svc-aaaa".to_string()]);
        let ids: Vec<String> = state.list_all().into_iter().map(|s| s.id).collect();
        assert_eq!(ids, vec!["svc-bbbb".to_string()]);

        // A peer-broadcast deletion (sync-delete path) tombstones even a
        // service we never held, so later gossip can't introduce it.
        assert!(!state.remove_if_exists("svc-cccc"));
        assert!(state.is_tombstoned("svc-cccc"));
        let rejected = state.merge_from_peer(vec![svc("svc-cccc", "c2")]);
        assert_eq!(rejected, vec!["svc-cccc".to_string()]);
        assert_eq!(state.list_all().len(), 1);

        // Tombstones survive a restart (the after-update case).
        let reloaded = WolfRunState::new();
        assert!(reloaded.is_tombstoned("svc-aaaa"));
        assert!(reloaded.is_tombstoned("svc-cccc"));
        let rejected = reloaded.merge_from_peer(vec![svc("svc-aaaa", "c1")]);
        assert_eq!(rejected, vec!["svc-aaaa".to_string()]);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}

// ─── Scheduler ───

// ─── Restart backoff ───
//
// Per-container failure history for the restart-policy path. A container
// that keeps dying gets progressively longer gaps between restart
// attempts, then stops being retried at all. Keyed by container name;
// entries are dropped once the container is seen running (recovered) or
// leaves the service (see `prune_restart_backoff`).
struct RestartRecord {
    /// Consecutive restart attempts since the container was last seen running.
    attempts: u32,
    /// Unix time of the most recent attempt.
    last_attempt: u64,
    /// True once we've given up and logged it, so the warning fires once.
    gave_up: bool,
}

static RESTART_BACKOFF: std::sync::LazyLock<std::sync::Mutex<HashMap<String, RestartRecord>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Stop retrying after this many consecutive failures. Docker's own
/// `--restart` policy (if the operator set one) keeps working — WolfRun
/// just stops fighting it.
const MAX_RESTART_ATTEMPTS: u32 = 8;
/// First retry waits this long; each subsequent attempt doubles it.
const RESTART_BACKOFF_BASE_SECS: u64 = 15;
/// Ceiling on the doubling, so a long-dead container is still retried
/// occasionally rather than never.
const RESTART_BACKOFF_MAX_SECS: u64 = 600;

/// Delay required before attempt number `attempts` (1-based).
fn restart_backoff_delay(attempts: u32) -> u64 {
    // attempts == 1 is the first retry after a failure: base delay.
    RESTART_BACKOFF_BASE_SECS
        .saturating_mul(1u64 << attempts.saturating_sub(1).min(31))
        .min(RESTART_BACKOFF_MAX_SECS)
}

/// True if `container` is due a restart attempt now. Records the attempt
/// when it returns true.
fn should_attempt_restart(container: &str) -> bool {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut map = RESTART_BACKOFF.lock().unwrap();
    let rec = map.entry(container.to_string()).or_insert(RestartRecord {
        attempts: 0,
        last_attempt: 0,
        gave_up: false,
    });

    if rec.attempts >= MAX_RESTART_ATTEMPTS {
        if !rec.gave_up {
            rec.gave_up = true;
            warn!(
                "WolfRun: '{}' failed to stay running after {} restart attempts — \
                 no longer restarting it. Fix the container (check its logs) or \
                 delete the service; the reconciler will resume automatically \
                 once it is seen running again.",
                container, MAX_RESTART_ATTEMPTS
            );
        }
        return false;
    }

    // First-ever attempt for this container fires immediately; later ones
    // wait out the doubling delay.
    if rec.attempts > 0 && now.saturating_sub(rec.last_attempt) < restart_backoff_delay(rec.attempts) {
        return false;
    }

    rec.attempts += 1;
    rec.last_attempt = now;
    true
}

/// Forget a container's failure history — it is running again.
fn clear_restart_backoff(container: &str) {
    RESTART_BACKOFF.lock().unwrap().remove(container);
}

/// Drop history for containers no longer managed by any service, so the
/// map can't grow without bound across a long uptime.
fn prune_restart_backoff(live: &std::collections::HashSet<String>) {
    RESTART_BACKOFF.lock().unwrap().retain(|name, _| live.contains(name));
}

#[cfg(test)]
mod restart_backoff_tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_caps_and_gives_up() {
        // Delay schedule: 15, 30, 60, 120, 240, 480, then capped at 600.
        assert_eq!(restart_backoff_delay(1), 15);
        assert_eq!(restart_backoff_delay(2), 30);
        assert_eq!(restart_backoff_delay(3), 60);
        assert_eq!(restart_backoff_delay(6), 480);
        assert_eq!(restart_backoff_delay(7), RESTART_BACKOFF_MAX_SECS);
        // Never overflows, however long a container has been broken.
        assert_eq!(restart_backoff_delay(u32::MAX), RESTART_BACKOFF_MAX_SECS);

        let name = "wolfrun-backoff-unit-test";
        clear_restart_backoff(name);

        // First attempt is immediate; the next is gated by the delay.
        assert!(should_attempt_restart(name), "first attempt must fire at once");
        assert!(!should_attempt_restart(name), "second attempt must wait out the backoff");

        // Drive it to the give-up threshold — the exact behaviour that
        // stops the 100-restarts-per-tick storm.
        for _ in 0..MAX_RESTART_ATTEMPTS {
            let mut map = RESTART_BACKOFF.lock().unwrap();
            let rec = map.get_mut(name).unwrap();
            rec.last_attempt = 0; // pretend the delay elapsed
            drop(map);
            should_attempt_restart(name);
        }
        {
            let mut map = RESTART_BACKOFF.lock().unwrap();
            map.get_mut(name).unwrap().last_attempt = 0;
        }
        assert!(!should_attempt_restart(name), "must give up past the attempt cap");

        // Recovery wipes the history so a later stop restarts immediately.
        clear_restart_backoff(name);
        assert!(should_attempt_restart(name), "a recovered container restarts at once");

        // Pruning drops containers no longer in any service.
        prune_restart_backoff(&std::collections::HashSet::new());
        assert!(!RESTART_BACKOFF.lock().unwrap().contains_key(name));
    }
}

/// Score a node for scheduling (lower = better)
fn node_score(node: &crate::agent::Node) -> f32 {
    let m = match &node.metrics {
        Some(m) => m,
        None => return f32::MAX,
    };
    // Weighted score: CPU 40%, Memory 40%, Disk 20%
    let cpu = m.cpu_usage_percent;
    let mem = m.memory_percent;
    let disk = m.disks.iter()
        .map(|d| d.usage_percent)
        .fold(0.0_f32, f32::max);
    cpu * 0.4 + mem * 0.4 + disk * 0.2
}

/// Pick the best node for a new container, given the service constraints
pub fn schedule(
    cluster: &ClusterState,
    service: &WolfRunService,
) -> Option<String> {
    let nodes = cluster.get_all_nodes();

    // Filter eligible nodes
    let eligible: Vec<_> = nodes.iter().filter(|n| {
        // Must be online
        if !n.online {

            return false;
        }
        // Must have the required runtime
        // For self node: detect directly (flags may not be set yet after restart)
        let node_has_lxc = n.has_lxc || (n.is_self && std::path::Path::new("/usr/bin/lxc-ls").exists());
        let node_has_docker = n.has_docker || (n.is_self && std::path::Path::new("/usr/bin/docker").exists());
        match service.runtime {
            Runtime::Docker => { if !node_has_docker {

                return false;
            } }
            Runtime::Lxc => { if !node_has_lxc {

                return false;
            } }
        }
        // Must be in the same cluster
        let node_cluster = n.cluster_name.as_deref().unwrap_or("WolfStack");
        if node_cluster != service.cluster_name {

            return false;
        }
        // Must be in the allowed nodes list (if specified)
        if !service.allowed_nodes.is_empty() && !service.allowed_nodes.iter().any(|a| node_matches_id(n, a)) {

            return false;
        }
        // Check placement constraints
        match &service.placement {
            Placement::RequireNode(nid) => node_matches_id(n, nid),
            _ => true,
        }
    }).collect();

    if eligible.is_empty() {
        // Show WHY no nodes matched
        let reasons: Vec<String> = nodes.iter().map(|n| {
            if !n.online { return format!("{}: offline", n.hostname); }
            match service.runtime {
                Runtime::Docker => { if !n.has_docker { return format!("{}: no Docker", n.hostname); } }
                Runtime::Lxc => { if !n.has_lxc { return format!("{}: no LXC (has_lxc=false)", n.hostname); } }
            }
            let nc = n.cluster_name.as_deref().unwrap_or("WolfStack");
            let nc_source = if n.cluster_name.is_some() { "" } else { " (default)" };
            if nc != service.cluster_name { return format!("{}: cluster '{}'{} != '{}'", n.hostname, nc, nc_source, service.cluster_name); }
            format!("{}: unknown", n.hostname)
        }).collect();
        warn!("WolfRun: no eligible nodes for service {} in cluster {} — reasons: {:?}", service.name, service.cluster_name, reasons);
        return None;
    }

    // Prefer preferred node if specified
    if let Placement::PreferNode(preferred) = &service.placement
        && let Some(n) = eligible.iter().find(|n| node_matches_id(n, preferred))
            && n.online {
                return Some(n.id.clone());
            }

    // Spread: penalise nodes that already run instances of this service
    let instance_counts: HashMap<String, usize> = {
        let mut counts = HashMap::new();
        for inst in &service.instances {
            if inst.status == "running" || inst.status == "pending" {
                *counts.entry(inst.node_id.clone()).or_insert(0) += 1;
            }
        }
        counts
    };

    // Score and pick the best node
    eligible.iter()
        .min_by(|a, b| {
            let a_count = *instance_counts.get(&a.id).unwrap_or(&0) as f32 * 100.0;
            let b_count = *instance_counts.get(&b.id).unwrap_or(&0) as f32 * 100.0;
            let a_score = node_score(a) + a_count;
            let b_score = node_score(b) + b_count;
            a_score.partial_cmp(&b_score).unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|n| n.id.clone())
}

// ─── Reconciliation Loop ───

/// Get the container list API path for the given runtime
fn container_list_path(runtime: &Runtime) -> &'static str {
    match runtime {
        Runtime::Docker => "/api/containers/docker?all=true",
        Runtime::Lxc => "/api/containers/lxc",
    }
}

/// Get the container action API path for the given runtime
fn container_action_path(runtime: &Runtime, name: &str) -> String {
    match runtime {
        Runtime::Docker => format!("/api/containers/docker/{}/action", name),
        Runtime::Lxc => format!("/api/containers/lxc/{}/action", name),
    }
}

/// Run one reconciliation cycle for all services
pub async fn reconcile(
    wolfrun: &WolfRunState,
    cluster: &ClusterState,
    cluster_secret: &str,
) {
    // Prevent concurrent reconcile runs (race condition causes duplicate creates then scale-down)
    static RECONCILING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if RECONCILING.compare_exchange(false, true, std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst).is_err() {

        return;
    }
    // Ensure we release the lock on exit
    struct ReconcileGuard;
    impl Drop for ReconcileGuard {
        fn drop(&mut self) {
            RECONCILING.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let _guard = ReconcileGuard;

    // Only reconcile services belonging to this node's cluster — other clusters
    // manage their own services via their own leader.  Without this filter the
    // local reconcile marks cross-cluster instances as "offline" because it
    // cannot reach their host nodes.
    let self_cluster = {
        let nodes = cluster.get_all_nodes();
        nodes.iter().find(|n| n.is_self)
            .and_then(|n| n.cluster_name.clone())
            .unwrap_or_else(|| "WolfStack".to_string())
    };
    let services = wolfrun.list(Some(&self_cluster));
    if services.is_empty() {
        // No services left to manage — drop every restart record rather
        // than stranding them for the process lifetime.
        prune_restart_backoff(&std::collections::HashSet::new());
        return;
    }

    // Forget restart history for containers no longer in any service
    // (deleted, scaled down, un-managed), so the map tracks live work only.
    prune_restart_backoff(
        &services.iter()
            .flat_map(|s| s.instances.iter().map(|i| i.container_name.clone()))
            .collect(),
    );

    // Shared long-timeout client — see RPC_CLIENT_LONG docs at top of
    // file. Building a new client here every 15s was leaking connection
    // pools; we now use one for the lifetime of the process.
    let client = &*RPC_CLIENT_LONG;

    // A container list is a per-NODE fact, not a per-instance one, but
    // this loop fetched it INSIDE the per-instance loop: a service with
    // N instances on a node enumerated that node's containers N times,
    // every tick, forever. Locally that is N full docker/lxc
    // enumerations (the `_cached` helpers exist precisely to "avoid
    // spawning dozens of subprocesses per API request" and were being
    // bypassed); remotely it is N HTTP round-trips fetching the same
    // list. It is quadratic in (instances × containers), so klas's node
    // — ~100 instances from the crash-loop runaway, 100+ containers —
    // burned 4h48m of CPU in 40 minutes of wall clock with a 10 GB
    // memory peak, mostly system time (2026-08-12).
    //
    // Fetched at most once per node per pass now. A pass is also the
    // right consistency boundary: every instance on a node is judged
    // against ONE snapshot, so a flaky node can't report a container
    // present for one instance and missing for the next.
    let mut local_lists: HashMap<&'static str, Vec<crate::containers::ContainerInfo>> = HashMap::new();
    let mut remote_lists: HashMap<(String, &'static str), Option<Vec<serde_json::Value>>> = HashMap::new();

    // VIPs that currently carry at least one WolfRun DNAT rule in nat
    // PREROUTING. The LB_CACHE below only rebuilds when the BACKEND SET
    // changes, so a ruleset wiped underneath us (firewall reload, an
    // `iptables -t nat -F`, a rules restore) was never repaired: the VIP
    // kept answering ping — it is a local route on lo — while every TCP
    // connect to it died. One listing per tick, off the runtime. `None`
    // when the listing itself failed, which must NOT read as "all
    // missing" or a host without iptables would rebuild every tick.
    let lb_rules_present = tokio::task::spawn_blocking(vips_with_lb_rules)
        .await
        .ok()
        .flatten();

    for service in &services {
        // 1. Check actual state — query each instance's node for its container status
        let mut live_instances: Vec<ServiceInstance> = Vec::new();
        let all_nodes = cluster.get_all_nodes();
        let rt_key: &'static str = match service.runtime {
            Runtime::Docker => "docker",
            Runtime::Lxc => "lxc",
        };

        for inst in &service.instances {
            let node = all_nodes.iter().find(|n| node_matches_id(n, &inst.node_id));
            match node {
                Some(n) if n.online && n.is_self => {
                    // Check if the required runtime is actually installed on this node
                    let runtime_available = match service.runtime {
                        Runtime::Docker => n.has_docker || std::path::Path::new("/usr/bin/docker").exists(),
                        Runtime::Lxc => n.has_lxc || std::path::Path::new("/usr/bin/lxc-ls").exists(),
                    };
                    if !runtime_available {
                        // Runtime not installed locally — treat like offline remote node
                        // so instances aren't marked "lost" and don't trigger replacement clones
                        if inst.status == "pending" {
                            live_instances.push(inst.clone());
                        } else {
                            let mut offline = inst.clone();
                            offline.status = "offline".to_string();
                            live_instances.push(offline);
                        }
                        continue;
                    }
                    // Local node — query containers directly (avoids HTTP self-call
                    // issues). Once per pass, not once per instance, and on the
                    // blocking pool: the enumeration shells out to docker/lxc.
                    if !local_lists.contains_key(rt_key) {
                        let rt = service.runtime.clone();
                        let fetched = tokio::task::spawn_blocking(move || match rt {
                            Runtime::Docker => crate::containers::docker_list_all(),
                            Runtime::Lxc => crate::containers::lxc_list_all(),
                        }).await.unwrap_or_default();
                        local_lists.insert(rt_key, fetched);
                    }
                    let containers = &local_lists[rt_key];
                    let found = containers.iter().find(|c| c.name == inst.container_name);
                    if let Some(c) = found {
                        // Extract wolfnet IP from ip_address field (format: "x.x.x.5 (wolfnet)" or "192.168.1.1, x.x.x.5 (wolfnet)")
                        let wn_prefix = crate::containers::wolfnet_subnet_prefix().map(|p| format!("{}.", p));
                        let wolfnet_ip = c.ip_address.split(',')
                            .map(|s| s.trim())
                            .find(|s| s.contains("wolfnet") || wn_prefix.as_ref().map(|p| s.starts_with(p.as_str())).unwrap_or(false))
                            .map(|s| s.replace(" (wolfnet)", "").trim().to_string())
                            .filter(|s| !s.is_empty());
                        // Fallback: use bridge IP (10.0.3.x) if no wolfnet IP
                        let ip = wolfnet_ip.or_else(|| {
                            c.ip_address.split(',')
                                .map(|s| s.trim().to_string())
                                .find(|s| s.starts_with("10.0.3.") || s.starts_with("10.0.4.") || s.starts_with("192.168."))
                        });
                        live_instances.push(ServiceInstance {
                            node_id: inst.node_id.clone(),
                            container_name: inst.container_name.clone(),
                            wolfnet_ip: ip,
                            status: c.state.to_lowercase(),
                            last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                            standby: inst.standby,
                        });
                    } else if inst.status == "pending" {
                        // Pending (clone in progress) — preserve
                        live_instances.push(inst.clone());
                    } else {
                        live_instances.push(ServiceInstance {
                            node_id: inst.node_id.clone(),
                            container_name: inst.container_name.clone(),
                            wolfnet_ip: None,
                            status: "lost".to_string(),
                            last_seen: inst.last_seen,
                            standby: inst.standby,
                        });
                    }
                }
                Some(n) if n.online => {
                    // One fetch per (node, runtime) per pass — see the
                    // cache note above the service loop.
                    let cache_key = (n.id.clone(), rt_key);
                    if !remote_lists.contains_key(&cache_key) {
                        let urls = crate::api::build_node_urls(
                            &n.address, n.port,
                            container_list_path(&service.runtime),
                        );
                        let mut fetched: Option<Vec<serde_json::Value>> = None;
                        for url in &urls {
                            match client.get(url)
                                .peer_auth(cluster_secret)
                                .send().await
                            {
                                Ok(resp) => {
                                    if !resp.status().is_success() {
                                        // HTTP error (401, 403, 500, etc.) — can't verify
                                        // container state. Drain the body before breaking so
                                        // reqwest can return the socket to the pool; dropping
                                        // the Response unconsumed was a CLOSE_WAIT leak.
                                        let _ = resp.bytes().await;
                                        break;
                                    }
                                    if let Ok(list) = resp.json::<Vec<serde_json::Value>>().await {
                                        fetched = Some(list);
                                    }
                                    break;
                                }
                                Err(_) => continue,
                            }
                        }
                        remote_lists.insert(cache_key.clone(), fetched);
                    }
                    let listing = remote_lists.get(&cache_key).and_then(|o| o.as_ref());
                    // true if we successfully fetched & parsed the list
                    let got_container_list = listing.is_some();
                    let mut found = false;
                    if let Some(containers) = listing {
                                    for c in containers {
                                        let name = c["name"].as_str().unwrap_or("");
                                        if name == inst.container_name {
                                            let state = c["state"].as_str()
                                                .or_else(|| c["status"].as_str())
                                                .unwrap_or("unknown");
                                            // Extract wolfnet IP from ip_address field (same as local path)
                                            let ip_addr = c["ip_address"].as_str().unwrap_or("");
                                            let wn_pfx = crate::containers::wolfnet_subnet_prefix().map(|p| format!("{}.", p));
                                            let wolfnet_ip = ip_addr.split(',')
                                                .map(|s| s.trim())
                                                .find(|s| s.contains("wolfnet") || wn_pfx.as_ref().map(|p| s.starts_with(p.as_str())).unwrap_or(false))
                                                .map(|s| s.replace(" (wolfnet)", "").trim().to_string())
                                                .filter(|s| !s.is_empty())
                                                .or_else(|| {
                                                    // Fallback: try wolfnet_ip field if present
                                                    c["wolfnet_ip"].as_str().map(|s| s.to_string())
                                                });
                                            live_instances.push(ServiceInstance {
                                                node_id: inst.node_id.clone(),
                                                container_name: inst.container_name.clone(),
                                                wolfnet_ip,
                                                status: state.to_lowercase(),
                                                last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                                                standby: inst.standby,
                                            });
                                            found = true;
                                            break;
                                        }
                                    }
                    }
                    if !found {
                        if inst.status == "pending" {
                            live_instances.push(inst.clone());
                        } else if got_container_list {
                            // We successfully fetched the container list but the container
                            // wasn't in it — it's genuinely gone. Mark as "lost".
                            live_instances.push(ServiceInstance {
                                node_id: inst.node_id.clone(),
                                container_name: inst.container_name.clone(),
                                wolfnet_ip: None,
                                status: "lost".to_string(),
                                last_seen: inst.last_seen,
                                standby: inst.standby,
                            });
                        } else {
                            // Couldn't reach the node or got HTTP/auth error — container
                            // may still be running fine. Keep as "offline" to preserve it
                            // and avoid triggering replacement clones.
                            live_instances.push(ServiceInstance {
                                node_id: inst.node_id.clone(),
                                container_name: inst.container_name.clone(),
                                wolfnet_ip: inst.wolfnet_ip.clone(),
                                status: "offline".to_string(),
                                last_seen: inst.last_seen,
                                standby: inst.standby,
                            });
                        }
                    }
                }
                _ => {
                    // Node offline or unknown — keep instance as "offline" (not "lost")
                    // so it's still counted as existing and doesn't trigger replacement clones.
                    // This prevents duplicate containers on WolfStack restart when remote
                    // nodes haven't re-joined gossip yet.
                    if inst.status == "pending" {
                        live_instances.push(inst.clone());
                    } else {
                        let mut offline = inst.clone();
                        offline.status = "offline".to_string();
                        live_instances.push(offline);
                    }
                }
            }
        }

        // Update instances with live state
        wolfrun.update_instances(&service.id, live_instances.clone());

        // Rebuild load balancer rules for this service's VIP (only if backends changed)
        if let Some(ref vip) = service.service_ip {
            // SORTED. The cache below compares this Vec to the previous
            // pass's, and a Vec comparison is order-sensitive — so any
            // reordering of `instances` (a peer's copy arriving via
            // merge_from_peer, an add/remove shuffling the vec) read as
            // "backends changed" and triggered a full iptables rebuild
            // even though the same containers were serving. Sorting makes
            // the comparison set-wise, which is what was always meant.
            let mut backend_ips: Vec<String> = live_instances.iter()
                .filter(|i| i.status == "running" && !i.standby)
                .filter_map(|i| i.wolfnet_ip.clone())
                .collect();
            backend_ips.sort();
            backend_ips.dedup();

            // Skip rebuild if backends haven't changed since last cycle
            use std::sync::Mutex;
            static LB_CACHE: std::sync::LazyLock<Mutex<std::collections::HashMap<String, Vec<String>>>> =
                std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

            let changed = {
                let mut cache = LB_CACHE.lock().unwrap();
                let prev = cache.get(vip);
                if prev == Some(&backend_ips) {
                    false
                } else {
                    cache.insert(vip.clone(), backend_ips.clone());
                    true
                }
            };

            let rules_missing = !backend_ips.is_empty()
                && lb_rules_present
                    .as_ref()
                    .map(|present| !present.contains(vip.as_str()))
                    .unwrap_or(false);
            if changed || rules_missing {
                // OFF THE ASYNC RUNTIME. A rebuild is dozens-to-hundreds of
                // iptables invocations, each taking the global netfilter
                // lock; running it inline blocked a tokio worker for the
                // whole rebuild and starved actix.
                let vip_owned = vip.clone();
                let backends = backend_ips.clone();
                let ports = service.ports.clone();
                let policy = service.lb_policy.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    rebuild_lb_rules(&vip_owned, &backends, &ports, &policy);
                }).await;
            }
        }

        // 2. Count instances for scaling decisions
        // Exclude standby instances — they don't count toward active replicas.
        //
        // DENYLIST, not allowlist: count every known instance that still
        // exists in ANY state; only "lost" (container vanished from an
        // ONLINE node) means it's really gone and needs replacing. The old
        // allowlist named six states and silently omitted the rest —
        // Docker alone also has `restarting`, `paused`, `removing` and
        // `dead`, and LXC adds STARTING/STOPPING/FREEZING/ABORTING. An
        // omitted state reads as "missing", so the reconciler cloned
        // ANOTHER instance every tick while never counting the ones it
        // made: a crash-looping image sits in `restarting` forever, and
        // one service became ~100 containers on a single node
        // (klas, 2026-08-12). Erring toward "it exists" can only ever
        // under-create, which is visible and safe; the reverse fills a
        // disk.
        let existing = live_instances.iter()
            .filter(|i| !i.standby && i.status != "lost")
            .count() as u32;
        let desired = service.replicas;

        // 3. Scale up if under-provisioned (based on EXISTING count, not running)
        if existing < desired {
            // Two independent brakes, so no future counting bug can ever
            // run away like this again:
            //  * the service's own max_replicas ceiling is absolute — the
            //    reconciler may never create past it, whatever the
            //    arithmetic says;
            //  * at most MAX_CREATES_PER_TICK per pass, so even a stuck
            //    count converges in a few visible ticks instead of
            //    spawning a container every cycle forever. A deliberate
            //    scale to 10 still completes in well under two minutes.
            const MAX_CREATES_PER_TICK: u32 = 2;
            let ceiling = service.max_replicas.max(desired);
            let room = ceiling.saturating_sub(existing);
            let needed = (desired - existing).min(room).min(MAX_CREATES_PER_TICK);
            if room == 0 {
                warn!(
                    "WolfRun: service '{}' wants {} replicas but already has {} instances \
                     (ceiling {}) — not creating more. Check for instances stuck in a \
                     restart loop.",
                    service.name, desired, existing, ceiling
                );
            }

            for i in 0..needed {
                let current = wolfrun.get(&service.id).unwrap_or(service.clone());
                let node_id = match schedule(cluster, &current) {
                    Some(id) => id,
                    None => {
                        warn!("WolfRun: no available node for service {}", service.name);
                        break;
                    }
                };

                let _instance_num = current.instances.len() + 1 + i as usize;
                let node = match cluster.get_node(&node_id) {
                    Some(n) => n,
                    None => continue,
                };

                // Pick best clone source: prefer a running instance, fall back to any instance
                let source_instance = live_instances.iter()
                    .find(|i| i.status == "running")
                    .or_else(|| live_instances.first())
                    .or_else(|| service.instances.first());

                let template_name = source_instance
                    .map(|i| i.container_name.clone())
                    .unwrap_or_else(|| service.name.clone());

                // Find which node the template lives on
                let template_node_id = source_instance
                    .map(|i| i.node_id.clone());

                match service.runtime {
                    Runtime::Docker => {
                        let short_id = &uuid::Uuid::new_v4().to_string()[..8];
                        let container_name = format!("{}-wolfrun-{}", service.name.to_lowercase().replace(' ', "-"), short_id);


                        let mut env = service.env.clone();
                        env.push(format!("WOLFRUN_SERVICE={}", service.id));
                        env.push(format!("WOLFRUN_SERVICE_NAME={}", service.name));

                        deploy_docker(client, cluster_secret, &node, &container_name, service, &env, wolfrun, &node_id).await;
                    }
                    Runtime::Lxc => {
                        // LXC: clone from template, deploy to scheduler's target node
                        let source_node_id = template_node_id.clone().unwrap_or(node_id.clone());
                        let short_id = &uuid::Uuid::new_v4().to_string()[..8];
                        let clone_name = format!("{}-wolfrun-{}", template_name, short_id);
                        let target_node_id_final = node_id.clone();



                        let source_node = cluster.get_node(&source_node_id);
                        // Compare the RESOLVED source node's registry key to the
                        // target — not the raw stored ids, which may be different
                        // forms (node-… vs ws-…) for the same physical node and
                        // would wrongly take the cross-node migration path
                        // (review, 2026-06-28).
                        let same_node = source_node.as_ref()
                            .map(|sn| sn.id == target_node_id_final)
                            .unwrap_or(false);

                        let cloned = if same_node {
                            // Same node: simple local or remote clone
                            if node.is_self {
                                // Both source and target are this node. A full
                                // rootfs clone runs for minutes and the retry
                                // path sleeps 2s — all of it goes on the
                                // blocking pool, never the async runtime.
                                let tmpl = template_name.clone();
                                let clone = clone_name.clone();
                                tokio::task::spawn_blocking(move || {
                                    let _ = crate::containers::lxc_stop(&tmpl);
                                    let result = crate::containers::lxc_clone(&tmpl, &clone);
                                    let _ = crate::containers::lxc_start(&tmpl);
                                    match result {
                                        Ok(_msg) => {
                                            // lxc_clone_local already called lxc_clone_fixup_ip
                                            // (unique bridge IP + MAC + wolfnet marker removal)
                                            // Start the clone
                                            if let Err(ref e) = crate::containers::lxc_start(&clone) {
                                                warn!("WolfRun: lxc_start failed for {}: {}", clone, e);
                                                // Retry once after delay
                                                std::thread::sleep(std::time::Duration::from_secs(2));
                                                if let Err(e2) = crate::containers::lxc_start(&clone) {
                                                    warn!("WolfRun: lxc_start retry also failed for {}: {}", clone, e2);
                                                }
                                            }
                                            // Allocate a fresh wolfnet IP for the clone
                                            if let Some(ip) = crate::containers::next_available_wolfnet_ip() {
                                                let _ = crate::containers::lxc_attach_wolfnet(&clone, &ip);
                                            }
                                            true
                                        }
                                        Err(e) => {
                                            warn!("WolfRun: local clone failed: {}", e);
                                            false
                                        }
                                    }
                                }).await.unwrap_or(false)
                            } else if let Some(ref sn) = source_node {
                                // Both source and target on same remote node
                                let clone_path = format!("/api/containers/lxc/{}/clone", template_name);
                                let urls = crate::api::build_node_urls(&sn.address, sn.port, &clone_path);
                                let clone_client = &*RPC_CLIENT_LONG;
                                let mut ok = false;
                                for url in &urls {
                                    if let Ok(resp) = clone_client.post(url)
                                        .peer_auth(cluster_secret)
                                        .json(&serde_json::json!({ "new_name": clone_name }))
                                        .send().await
                                    {
                                        if resp.status().is_success() {
                                            let _ = resp.bytes().await;
                                            // Start the clone
                                            let sp = format!("/api/containers/lxc/{}/start", clone_name);
                                            let su = crate::api::build_node_urls(&sn.address, sn.port, &sp);
                                            for u in &su {
                                                if send_and_drain(
                                                    clone_client.post(u).peer_auth(cluster_secret)
                                                ).await.is_some() { break; }
                                            }
                                            ok = true;
                                        } else {
                                            let _ = resp.bytes().await;
                                        }
                                        break;
                                    }
                                }
                                ok
                            } else { false }
                        } else {
                            // ── Cross-node clone-and-migrate ──
                            // Register instance as PENDING first to prevent duplicates
                            let _src_hostname = source_node.as_ref().map(|n| n.hostname.as_str()).unwrap_or("unknown");


                            // Register PENDING instance NOW — before clone starts.
                            // This prevents the next reconcile from creating another.
                            // Pre-allocate wolfnet IP on the orchestrator (has global view
                            // via services.json + local state) to avoid cross-node conflicts.
                            let pre_alloc_ip = crate::containers::next_available_wolfnet_ip();
                            wolfrun.add_instance(&service.id, ServiceInstance {
                                node_id: node_id.clone(),
                                container_name: clone_name.clone(),
                                wolfnet_ip: pre_alloc_ip.clone(),
                                status: "pending".to_string(),
                                last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                                standby: false,
                            });

                            let mut clone_payload = serde_json::json!({
                                "new_name": clone_name,
                                "target_node": node_id,
                            });
                            // Pass the pre-allocated IP to the target node
                            if let Some(ref ip) = pre_alloc_ip {
                                clone_payload["wolfnet_ip"] = serde_json::json!(ip);
                            }

                            let mut ok = false;
                            if let Some(ref sn) = source_node {
                                let clone_path = format!("/api/containers/lxc/{}/clone", template_name);
                                let urls = if sn.is_self {
                                    vec![format!("https://127.0.0.1:{}{}", sn.port, clone_path)]
                                } else {
                                    crate::api::build_node_urls(&sn.address, sn.port, &clone_path)
                                };

                                let migrate_client = &*RPC_CLIENT_MIGRATE;

                                for url in &urls {
                                    match migrate_client.post(url)
                                        .peer_auth(cluster_secret)
                                        .json(&clone_payload)
                                        .send().await
                                    {
                                        Ok(resp) if resp.status().is_success() => {

                                            ok = true;
                                            break;
                                        }
                                        Ok(resp) => {
                                            let err = resp.text().await.unwrap_or_default();
                                            warn!("WolfRun: ❌ Clone-migrate failed: {}", err);
                                            break;
                                        }
                                        Err(e) => {
                                            warn!("WolfRun: connection error: {}", e);
                                            continue;
                                        }
                                    }
                                }
                            }

                            if !ok {
                                // Clone failed — remove the pending instance
                                warn!("WolfRun: removing pending instance '{}' (clone failed)", clone_name);
                                wolfrun.remove_instance(&service.id, &clone_name);
                            }
                            // If ok: leave the pending instance. Next reconcile will
                            // update its status to running/stopped from live state.
                            continue;
                        };

                        if cloned {
                            wolfrun.add_instance(&service.id, ServiceInstance {
                                node_id: target_node_id_final,
                                container_name: clone_name,
                                wolfnet_ip: None,
                                status: "running".to_string(),
                                last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                                standby: false,
                            });
                        } else {
                            warn!("WolfRun: failed to clone '{}' for service {}", template_name, service.name);
                        }
                    }
                }
            }
        }

        // 4. Scale down if over-provisioned
        //
        // Measured on EXISTING, not just running — the old check only ever
        // saw `running`, so instances stuck in another state (the
        // `restarting` crash-loop above) were invisible here too: never
        // counted, therefore never cleaned up, and the service list grew
        // without bound (klas, 2026-08-12). Non-running instances are
        // released FIRST: they're the junk, and un-managing a healthy
        // serving container while a crash-looping one stays on the books
        // would be exactly backwards.
        if existing > desired {
            let excess = existing - desired;

            let mut instance_counts: HashMap<String, usize> = HashMap::new();
            for inst in &live_instances {
                if !inst.standby && inst.status != "lost" {
                    *instance_counts.entry(inst.node_id.clone()).or_insert(0) += 1;
                }
            }

            let mut candidates: Vec<_> = live_instances.iter()
                .filter(|i| !i.standby && i.status != "lost")
                .collect();
            candidates.sort_by(|a, b| {
                // Non-running before running; then the most crowded node
                // first, so releasing rebalances instead of concentrating.
                let a_running = a.status == "running";
                let b_running = b.status == "running";
                a_running.cmp(&b_running).then_with(|| {
                    let a_count = instance_counts.get(&a.node_id).unwrap_or(&0);
                    let b_count = instance_counts.get(&b.node_id).unwrap_or(&0);
                    b_count.cmp(a_count)
                })
            });

            for inst in candidates.iter().take(excess as usize) {
                // Just un-manage — don't destroy the container. User can always stop it manually.

                wolfrun.remove_instance(&service.id, &inst.container_name);
            }
        }

        // 5. Handle stopped containers that should be running (restart policy)
        // Skip standby instances — they are intentionally stopped
        if matches!(service.restart_policy, RestartPolicy::Always) {
            for inst in &live_instances {
                if inst.standby { continue; }
                // A container we can see running has recovered — forget its
                // failure history so a later genuine stop restarts instantly.
                if inst.status == "running" {
                    clear_restart_backoff(&inst.container_name);
                    continue;
                }
                if inst.status == "exited" || inst.status == "dead" || inst.status == "stopped" || inst.status == "created" {
                    let node = match cluster.get_node(&inst.node_id) {
                        Some(n) => n,
                        None => continue,
                    };

                    // Back off on a container that keeps dying. Without this
                    // the reconciler force-started EVERY non-running instance
                    // on EVERY tick, forever: ~100 crash-looping containers
                    // meant ~100 `docker start` per 15s pass, each of which
                    // can sleep a second re-attaching WolfNet *and* calls
                    // invalidate_docker_list_cache() — so the 5s list cache
                    // never survived and every other poller (notify,
                    // predictive, exposure, router…) re-enumerated every
                    // time. The restarts also fight Docker's own
                    // exponential restart backoff instead of letting it
                    // settle. That compounding loop is what kept klas's node
                    // pegged even after the v25.11.26/.28 fixes (2026-08-12).
                    if !should_attempt_restart(&inst.container_name) {
                        continue;
                    }

                    if node.is_self {
                        let name = inst.container_name.clone();
                        let rt = service.runtime.clone();
                        // Subprocess + a possible 1s WolfNet re-attach sleep —
                        // never on the async runtime.
                        let _ = tokio::task::spawn_blocking(move || match rt {
                            Runtime::Docker => { let _ = crate::containers::docker_start(&name); }
                            Runtime::Lxc => { let _ = crate::containers::lxc_start(&name); }
                        }).await;
                    } else {
                        let urls = crate::api::build_node_urls(
                            &node.address, node.port,
                            &container_action_path(&service.runtime, &inst.container_name),
                        );
                        let payload = serde_json::json!({ "action": "start" });
                        for url in &urls {
                            if send_and_drain(
                                client.post(url)
                                    .peer_auth(cluster_secret)
                                    .header("Content-Type", "application/json")
                                    .body(payload.to_string())
                            ).await.is_some() {
                                break;
                            }
                        }
                    }
                }
            }
        }

        // 6. Clean up lost instances — if a node stays lost for >5 minutes, reschedule
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let lost: Vec<_> = live_instances.iter()
            .filter(|i| i.status == "lost" && now - i.last_seen > 300)
            .cloned()
            .collect();
        for inst in &lost {

            wolfrun.remove_instance(&service.id, &inst.container_name);
            // The next reconciliation cycle will detect under-provisioning and schedule a replacement
        }

        // 7. Clean up orphaned standby instances when failover is disabled
        if !service.failover {
            let orphaned_standby: Vec<_> = live_instances.iter()
                .filter(|i| i.standby)
                .cloned()
                .collect();
            for inst in &orphaned_standby {
                // Stop and destroy the standby container
                let node = all_nodes.iter().find(|n| node_matches_id(n, &inst.node_id));
                if let Some(n) = node {
                    if n.is_self {
                        let name = inst.container_name.clone();
                        let rt = service.runtime.clone();
                        // Subprocess teardown — off the async runtime.
                        let _ = tokio::task::spawn_blocking(move || match rt {
                            Runtime::Docker => {
                                let _ = crate::containers::docker_stop(&name);
                                let _ = crate::containers::docker_remove_permanent(&name);
                            }
                            Runtime::Lxc => {
                                let _ = crate::containers::lxc_stop(&name);
                                let _ = crate::containers::lxc_destroy(&name);
                            }
                        }).await;
                    } else if n.online {
                        let action_path = container_action_path(&service.runtime, &inst.container_name);
                        let urls = crate::api::build_node_urls(&n.address, n.port, &action_path);
                        let stop_payload = serde_json::json!({ "action": "stop" });
                        for url in &urls {
                            if send_and_drain(
                                client.post(url)
                                    .peer_auth(cluster_secret)
                                    .json(&stop_payload)
                            ).await.is_some() { break; }
                        }
                        let rm_action = match service.runtime {
                            Runtime::Docker => "remove",
                            Runtime::Lxc => "destroy",
                        };
                        // force: WolfRun destroying its own standby — must not
                        // be bounced by the peer's managed-container guard.
                        let rm_payload = serde_json::json!({ "action": rm_action, "force": true });
                        for url in &urls {
                            if send_and_drain(
                                client.post(url)
                                    .peer_auth(cluster_secret)
                                    .json(&rm_payload)
                            ).await.is_some() { break; }
                        }
                    }
                }
                wolfrun.remove_instance(&service.id, &inst.container_name);
            }
        }
    }
}

// ─── Deployment Helpers ───

/// Deploy a Docker container on a node
async fn deploy_docker(
    client: &reqwest::Client,
    cluster_secret: &str,
    node: &crate::agent::Node,
    container_name: &str,
    service: &WolfRunService,
    env: &[String],
    wolfrun: &WolfRunState,
    node_id: &str,
) {
    let mut payload = serde_json::json!({
        "name": container_name,
        "image": service.image,
        "ports": service.ports,
        "env": env,
        "volumes": service.volumes,
    });

    if node.is_self {
        // Image pull + create + start are subprocess work that can run for
        // minutes — never on the async runtime.
        let name = container_name.to_string();
        let image = service.image.clone();
        let ports = service.ports.clone();
        let volumes = service.volumes.clone();
        let env_owned = env.to_vec();
        let (wolfnet_ip, created) = tokio::task::spawn_blocking(move || {
            let wolfnet_ip = crate::containers::next_available_wolfnet_ip();
            let created = crate::containers::docker_create(
                &name, &image, &ports, &env_owned,
                wolfnet_ip.as_deref(), None, None, None, &volumes,
            );
            if created.is_ok() {
                let _ = crate::containers::docker_start(&name);
            }
            (wolfnet_ip, created)
        }).await.unwrap_or_else(|e| (None, Err(format!("deploy task panicked: {}", e))));

        match created {
            Ok(_) => {
                wolfrun.add_instance(&service.id, ServiceInstance {
                    node_id: node_id.to_string(),
                    container_name: container_name.to_string(),
                    wolfnet_ip,
                    status: "running".to_string(),
                    last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    standby: false,
                });
            }
            Err(e) => warn!("WolfRun: failed to deploy {} locally: {}", container_name, e),
        }
    } else {
        // Allocate a WolfNet IP for the remote container, mirroring the
        // node.is_self branch above and the LXC cross-node path. The
        // orchestrator has the global view (services.json + local state via
        // wolfnet_used_ip_set), and add_instance persists each allocation to
        // services.json before the next replica's deploy_docker runs, so
        // sequential replicas never collide. Without this the VIP
        // load-balancer's backend list (built from instance.wolfnet_ip) stays
        // empty for any service scheduled off the orchestrator and the VIP
        // routes to nothing (AstroMando, 2026-06-27).
        let wolfnet_ip = crate::containers::next_available_wolfnet_ip();
        if let Some(ref ip) = wolfnet_ip {
            payload["wolfnet_ip"] = serde_json::json!(ip);
        }

        // Pull image on remote node
        let pull_urls = crate::api::build_node_urls(&node.address, node.port, "/api/containers/docker/pull");
        let pull_payload = serde_json::json!({ "image": service.image });
        let mut pulled = false;
        for url in &pull_urls {
            // send_and_drain reads the body so the socket is pooled.
            if matches!(send_and_drain(
                client.post(url)
                    .peer_auth(cluster_secret)
                    .json(&pull_payload)
            ).await, Some(true)) { pulled = true; break; }
        }
        if !pulled {
            warn!("WolfRun: failed to pull image {} on {}", service.image, node.hostname);
            return;
        }

        // Create container on remote node
        let create_urls = crate::api::build_node_urls(&node.address, node.port, "/api/containers/docker/create");
        let mut created = false;
        for url in &create_urls {
            if let Ok(resp) = client.post(url)
                .peer_auth(cluster_secret)
                .json(&payload)
                .send().await
            {
                if resp.status().is_success() {
                    // Drain body to pool the connection.
                    let _ = resp.bytes().await;
                    created = true;
                    break;
                }
                let body = resp.text().await.unwrap_or_default();
                warn!("WolfRun: create failed on {}: {}", node.hostname, body);
                break;
            }
        }
        if !created {
            warn!("WolfRun: failed to create container {} on {}", container_name, node.hostname);
            return;
        }

        // Start container
        let start_urls = crate::api::build_node_urls(&node.address, node.port,
            &container_action_path(&Runtime::Docker, container_name));
        let start_payload = serde_json::json!({ "action": "start" });
        for url in &start_urls {
            if matches!(send_and_drain(
                client.post(url)
                    .peer_auth(cluster_secret)
                    .json(&start_payload)
            ).await, Some(true)) { break; }
        }

        wolfrun.add_instance(&service.id, ServiceInstance {
            node_id: node_id.to_string(),
            container_name: container_name.to_string(),
            wolfnet_ip,
            status: "running".to_string(),
            last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            standby: false,
        });
    }
}

/// Deploy an LXC container on a node
#[allow(dead_code)]
async fn deploy_lxc(
    client: &reqwest::Client,
    cluster_secret: &str,
    node: &crate::agent::Node,
    container_name: &str,
    service: &WolfRunService,
    wolfrun: &WolfRunState,
    node_id: &str,
) {
    let lxc = service.lxc_config.clone().unwrap_or_default();

    if node.is_self {
        // Template download + rootfs create can run for minutes — off the
        // async runtime, like the Docker deploy path.
        let name = container_name.to_string();
        let (distro, release, arch) =
            (lxc.distribution.clone(), lxc.release.clone(), lxc.architecture.clone());
        let created = tokio::task::spawn_blocking(move || {
            let created = crate::containers::lxc_create(
                &name, &distro, &release, &arch, None, None,
            );
            if created.is_ok() {
                let _ = crate::containers::lxc_start(&name);
            }
            created
        }).await.unwrap_or_else(|e| Err(format!("deploy task panicked: {}", e)));

        match created {
            Ok(_) => {
                wolfrun.add_instance(&service.id, ServiceInstance {
                    node_id: node_id.to_string(),
                    container_name: container_name.to_string(),
                    wolfnet_ip: None,
                    status: "running".to_string(),
                    last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    standby: false,
                });
            }
            Err(e) => warn!("WolfRun: failed to deploy LXC {} locally: {}", container_name, e),
        }
    } else {
        let create_urls = crate::api::build_node_urls(&node.address, node.port, "/api/containers/lxc/create");
        let payload = serde_json::json!({
            "name": container_name,
            "distribution": lxc.distribution,
            "release": lxc.release,
            "architecture": lxc.architecture,
        });
        let mut created = false;
        for url in &create_urls {
            if let Ok(resp) = client.post(url)
                .peer_auth(cluster_secret)
                .json(&payload)
                .send().await
            {
                if resp.status().is_success() {
                    let _ = resp.bytes().await;
                    created = true;
                    break;
                }
                let body = resp.text().await.unwrap_or_default();
                warn!("WolfRun: LXC create failed on {}: {}", node.hostname, body);
                break;
            }
        }
        if !created {
            warn!("WolfRun: failed to create LXC {} on {}", container_name, node.hostname);
            return;
        }

        // Start the LXC container
        let start_urls = crate::api::build_node_urls(&node.address, node.port,
            &container_action_path(&Runtime::Lxc, container_name));
        let start_payload = serde_json::json!({ "action": "start" });
        for url in &start_urls {
            if matches!(send_and_drain(
                client.post(url)
                    .peer_auth(cluster_secret)
                    .json(&start_payload)
            ).await, Some(true)) { break; }
        }

        wolfrun.add_instance(&service.id, ServiceInstance {
            node_id: node_id.to_string(),
            container_name: container_name.to_string(),
            wolfnet_ip: None,
            status: "running".to_string(),
            last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            standby: false,
        });
    }
}

/// Stop and remove a container (Docker or LXC). Returns true when the
/// remove/destroy step reported success.
async fn stop_and_remove(
    client: &reqwest::Client,
    cluster_secret: &str,
    node: &crate::agent::Node,
    container_name: &str,
    runtime: &Runtime,
) -> bool {
    if node.is_self {
        // Subprocess-backed container commands are blocking — keep them
        // off the async runtime (this runs from both API handlers and
        // the reconcile loop).
        let name = container_name.to_string();
        let rt = runtime.clone();
        tokio::task::spawn_blocking(move || {
            match rt {
                Runtime::Docker => {
                    let _ = crate::containers::docker_stop(&name);
                    // Permanent teardown — release any vSwitch allocation too, matching
                    // the live orphan-cleanup path (do NOT use plain docker_remove here).
                    crate::containers::docker_remove_permanent(&name).is_ok()
                }
                Runtime::Lxc => {
                    let _ = crate::containers::lxc_stop(&name);
                    crate::containers::lxc_destroy(&name).is_ok()
                }
            }
        }).await.unwrap_or(false)
    } else {
        let urls = crate::api::build_node_urls(
            &node.address, node.port,
            &container_action_path(runtime, container_name),
        );
        let stop_payload = serde_json::json!({ "action": "stop" });
        for url in &urls {
            if send_and_drain(
                client.post(url)
                    .peer_auth(cluster_secret)
                    .json(&stop_payload)
            ).await.is_some() {
                break;
            }
        }
        let rm_action = match runtime {
            Runtime::Docker => "remove",
            Runtime::Lxc => "destroy",
        };
        // force: this removal is WolfRun tearing down its OWN instance —
        // the managed-container guard on the peer's action endpoint must
        // not bounce it back with "managed by WolfRun".
        let rm_payload = serde_json::json!({ "action": rm_action, "force": true });
        for url in &urls {
            match send_and_drain(
                client.post(url)
                    .peer_auth(cluster_secret)
                    .json(&rm_payload)
            ).await {
                Some(ok) => return ok,
                None => continue,
            }
        }
        false
    }
}

// ─── Failover ───

/// Manage standby containers for services with failover enabled.
/// Creates stopped clones on nodes that don't already have a running or standby instance.
pub async fn manage_standby(
    wolfrun: &WolfRunState,
    cluster: &ClusterState,
    cluster_secret: &str,
) {
    let self_cluster = {
        let nodes = cluster.get_all_nodes();
        nodes.iter().find(|n| n.is_self)
            .and_then(|n| n.cluster_name.clone())
            .unwrap_or_else(|| "WolfStack".to_string())
    };

    let services = wolfrun.list(Some(&self_cluster));
    // Zero-service fast path — matches the guard in reconcile() and
    // the one added to broadcast_to_cluster(). Without this the
    // function still read the full node list and pulled in the RPC
    // pool every 15s on clusters with no WolfRun services.
    if services.is_empty() {
        return;
    }
    let all_nodes = cluster.get_all_nodes();

    // Shared long-timeout client — same pool used everywhere else in
    // this module. Previously built per-call = leaked connection pools.
    let client = &*RPC_CLIENT_LONG;

    for service in &services {
        if !service.failover { continue; }

        // Find nodes that already have an instance (running or standby)
        let occupied_nodes: std::collections::HashSet<String> = service.instances.iter()
            .filter(|i| i.status != "lost")
            .map(|i| i.node_id.clone())
            .collect();

        // Find eligible nodes that DON'T have an instance yet
        let eligible_nodes: Vec<_> = all_nodes.iter().filter(|n| {
            if !n.online { return false; }
            let nc = n.cluster_name.as_deref().unwrap_or("WolfStack");
            if nc != service.cluster_name { return false; }
            if !service.allowed_nodes.is_empty() && !service.allowed_nodes.iter().any(|a| node_matches_id(n, a)) { return false; }
            // Must have the required runtime
            let has_runtime = match service.runtime {
                Runtime::Docker => n.has_docker || (n.is_self && std::path::Path::new("/usr/bin/docker").exists()),
                Runtime::Lxc => n.has_lxc || (n.is_self && std::path::Path::new("/usr/bin/lxc-ls").exists()),
            };
            if !has_runtime { return false; }
            // Skip nodes that already have an instance
            !occupied_nodes.contains(&n.id)
        }).collect();

        if eligible_nodes.is_empty() { continue; }

        // Find a running instance to use as clone source
        let source = service.instances.iter()
            .find(|i| i.status == "running" && !i.standby)
            .or_else(|| service.instances.iter().find(|i| i.status == "running"));

        let source = match source {
            Some(s) => s,
            None => continue, // No running instance to clone from
        };

        for target_node in &eligible_nodes {
            let short_id = &uuid::Uuid::new_v4().to_string()[..8];
            let standby_name = format!("{}-standby-{}", source.container_name
                .split("-wolfrun-").next().unwrap_or(&service.name.to_lowercase().replace(' ', "-")), short_id);

            // Pre-allocate wolfnet IP for the standby (same subnet, unique)
            let standby_ip = crate::containers::next_available_wolfnet_ip();

            tracing::info!("WolfRun failover: creating standby '{}' on {} for service {}",
                standby_name, target_node.hostname, service.name);

            // Register as standby immediately to prevent duplicates
            wolfrun.add_instance(&service.id, ServiceInstance {
                node_id: target_node.id.clone(),
                container_name: standby_name.clone(),
                wolfnet_ip: standby_ip.clone(),
                status: "standby".to_string(),
                last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                standby: true,
            });

            match service.runtime {
                Runtime::Docker => {
                    // For Docker: pull the image and create the container stopped
                    let created = if target_node.is_self {
                        match crate::containers::docker_create(
                            &standby_name, &service.image, &service.ports, &service.env,
                            standby_ip.as_deref(), None, None, None, &service.volumes,
                        ) {
                            Ok(_) => true,
                            Err(e) => {
                                warn!("WolfRun failover: failed to create standby Docker '{}': {}", standby_name, e);
                                false
                            }
                        }
                    } else {
                        // Pull + create on remote node (don't start)
                        let pull_urls = crate::api::build_node_urls(&target_node.address, target_node.port, "/api/containers/docker/pull");
                        let pull_payload = serde_json::json!({ "image": service.image });
                        let mut pulled = false;
                        for url in &pull_urls {
                            if matches!(send_and_drain(
                                client.post(url).peer_auth(cluster_secret).json(&pull_payload)
                            ).await, Some(true)) { pulled = true; break; }
                        }
                        if pulled {
                            let create_urls = crate::api::build_node_urls(&target_node.address, target_node.port, "/api/containers/docker/create");
                            let payload = serde_json::json!({
                                "name": standby_name,
                                "image": service.image,
                                "ports": service.ports,
                                "env": service.env,
                                "volumes": service.volumes,
                            });
                            let mut ok = false;
                            for url in &create_urls {
                                match send_and_drain(
                                    client.post(url).peer_auth(cluster_secret).json(&payload)
                                ).await {
                                    Some(true) => { ok = true; break; }
                                    Some(false) => break,  // HTTP error — don't retry next URL
                                    None => continue,       // Network error — try next URL
                                }
                            }
                            ok
                        } else { false }
                    };
                    if !created {
                        wolfrun.remove_instance(&service.id, &standby_name);
                    }
                }
                Runtime::Lxc => {
                    // For LXC: clone from source (stopped) — cross-node or same-node
                    let source_node = all_nodes.iter().find(|n| node_matches_id(n, &source.node_id));
                    let source_node = match source_node {
                        Some(n) => n,
                        None => {
                            wolfrun.remove_instance(&service.id, &standby_name);
                            continue;
                        }
                    };

                    let mut clone_payload = serde_json::json!({
                        "new_name": standby_name,
                    });
                    if source_node.id != target_node.id {
                        clone_payload["target_node"] = serde_json::json!(target_node.id);
                    }
                    if let Some(ref ip) = standby_ip {
                        clone_payload["wolfnet_ip"] = serde_json::json!(ip);
                    }

                    let clone_path = format!("/api/containers/lxc/{}/clone", source.container_name);
                    let urls = if source_node.is_self {
                        vec![format!("https://127.0.0.1:{}{}", source_node.port, clone_path)]
                    } else {
                        crate::api::build_node_urls(&source_node.address, source_node.port, &clone_path)
                    };

                    let clone_client = &*RPC_CLIENT_MIGRATE;

                    let mut ok = false;
                    for url in &urls {
                        match send_and_drain(
                            clone_client.post(url)
                                .peer_auth(cluster_secret)
                                .json(&clone_payload)
                        ).await {
                            Some(true) => { ok = true; break; }
                            Some(false) => break,
                            None => continue,
                        }
                    }

                    if !ok {
                        warn!("WolfRun failover: failed to clone standby '{}' for service {}", standby_name, service.name);
                        wolfrun.remove_instance(&service.id, &standby_name);
                    }
                    // Note: standby LXC stays stopped — don't start it
                }
            }
        }
    }
}

/// Check for failover — detect offline nodes with running instances and promote standby containers.
/// Called by the leader during reconciliation.
pub async fn check_failover(
    wolfrun: &WolfRunState,
    cluster: &ClusterState,
    cluster_secret: &str,
) {
    let self_cluster = {
        let nodes = cluster.get_all_nodes();
        nodes.iter().find(|n| n.is_self)
            .and_then(|n| n.cluster_name.clone())
            .unwrap_or_else(|| "WolfStack".to_string())
    };

    let services = wolfrun.list(Some(&self_cluster));
    // Zero-service fast path — identical to the other three WolfRun
    // loop functions. Keeps an idle cluster quiet.
    if services.is_empty() {
        return;
    }
    let all_nodes = cluster.get_all_nodes();

    // Shared pool — see RPC_CLIENT_LONG docs at top of file.
    let client = &*RPC_CLIENT_LONG;

    for service in &services {
        if !service.failover { continue; }

        // Find instances on offline nodes (not standby — those are expected to be stopped)
        let failed_instances: Vec<_> = service.instances.iter()
            .filter(|i| !i.standby && (i.status == "offline" || i.status == "lost"))
            .filter(|i| {
                // Verify the node is actually offline
                all_nodes.iter().find(|n| node_matches_id(n, &i.node_id))
                    .map(|n| !n.online)
                    .unwrap_or(true) // Unknown node = offline
            })
            .collect();

        if failed_instances.is_empty() { continue; }

        // Find standby instances to promote (mutable — consumed as used)
        let mut standby_instances: Vec<_> = service.instances.iter()
            .filter(|i| i.standby && i.status != "lost")
            .cloned()
            .collect();

        for failed in &failed_instances {
            // Pick a standby to promote (prefer one on an online node), removing it from candidates
            let standby_idx = standby_instances.iter().position(|s| {
                all_nodes.iter().find(|n| node_matches_id(n, &s.node_id))
                    .map(|n| n.online)
                    .unwrap_or(false)
            });

            let standby = match standby_idx {
                Some(idx) => standby_instances.remove(idx),
                None => {
                    warn!("WolfRun failover: no standby available for failed instance '{}' on offline node",
                        failed.container_name);
                    continue;
                }
            };

            let standby_node = match all_nodes.iter().find(|n| node_matches_id(n, &standby.node_id)) {
                Some(n) => n,
                None => continue,
            };

            tracing::info!("WolfRun failover: promoting standby '{}' on {} (replacing '{}' on offline node)",
                standby.container_name, standby_node.hostname, failed.container_name);

            // Start the standby container
            let started = if standby_node.is_self {
                let name = standby.container_name.clone();
                let rt = service.runtime.clone();
                let wn_ip = standby.wolfnet_ip.clone();
                // Subprocess + WolfNet attach — off the async runtime.
                tokio::task::spawn_blocking(move || match rt {
                    Runtime::Docker => crate::containers::docker_start(&name).is_ok(),
                    Runtime::Lxc => {
                        // Attach wolfnet with the pre-allocated IP before starting
                        if let Some(ref ip) = wn_ip {
                            let _ = crate::containers::lxc_attach_wolfnet(&name, ip);
                        }
                        crate::containers::lxc_start(&name).is_ok()
                    }
                }).await.unwrap_or(false)
            } else {
                let action_path = container_action_path(&service.runtime, &standby.container_name);
                let urls = crate::api::build_node_urls(&standby_node.address, standby_node.port, &action_path);
                let payload = serde_json::json!({ "action": "start" });
                let mut ok = false;
                for url in &urls {
                    match send_and_drain(
                        client.post(url)
                            .peer_auth(cluster_secret)
                            .json(&payload)
                    ).await {
                        Some(true) => { ok = true; break; }
                        Some(false) => break,
                        None => continue,
                    }
                }
                ok
            };

            if started {
                // Update the standby instance — mark as active (not standby)
                let mut svcs = wolfrun.services.write().unwrap();
                if let Some(svc) = svcs.iter_mut().find(|s| s.id == service.id) {
                    if let Some(inst) = svc.instances.iter_mut().find(|i| i.container_name == standby.container_name) {
                        inst.standby = false;
                        inst.status = "running".to_string();
                        inst.last_seen = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    }
                    // Remove the failed instance
                    svc.instances.retain(|i| i.container_name != failed.container_name);
                }
                drop(svcs);
                wolfrun.save();

                // Record failover event
                let failed_hostname = all_nodes.iter()
                    .find(|n| node_matches_id(n, &failed.node_id))
                    .map(|n| n.hostname.clone())
                    .unwrap_or_else(|| failed.node_id.clone());

                let failover_event = FailoverEvent {
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    service_id: service.id.clone(),
                    service_name: service.name.clone(),
                    from_node: failed_hostname,
                    to_node: standby_node.hostname.clone(),
                    container_name: standby.container_name.clone(),
                    detail: format!("Standby '{}' promoted — replacing failed '{}'",
                        standby.container_name, failed.container_name),
                };
                // WolfFunctions container_failover trigger. force_local:
                // failover runs on exactly one node (the leader), so the
                // observation already happens once per cluster.
                crate::wolffunctions::fire_event_global(
                    crate::wolffunctions::TriggerEvent::ContainerFailover,
                    serde_json::to_value(&failover_event).unwrap_or_default(),
                    true,
                );
                wolfrun.add_failover_event(failover_event);

                tracing::info!("WolfRun failover: successfully promoted '{}' on {}",
                    standby.container_name, standby_node.hostname);
            } else {
                warn!("WolfRun failover: failed to start standby '{}' on {}",
                    standby.container_name, standby_node.hostname);
            }
        }
    }
}

// ─── Load Balancer (iptables round-robin DNAT) ───

/// Rebuild iptables DNAT rules for a service VIP.
/// Supports "round_robin" (nth statistic) and "ip_hash" (source-IP based sticky sessions).
pub fn rebuild_lb_rules(vip: &str, backend_ips: &[String], ports: &[String], lb_policy: &str) {
    // First remove any existing rules for this VIP
    remove_lb_rules_for_vip(vip);

    if backend_ips.is_empty() {

        return;
    }

    // Make the VIP locally routable so iptables PREROUTING DNAT can intercept it.
    // We use `ip route replace local` (not `ip addr add` on wolfnet0) because
    // adding addresses to the TUN device interferes with WolfNet packet processing.
    let cidr = format!("{}/32", vip);
    // Remove any stale interface address (if left from a previous version)
    let _ = std::process::Command::new("ip")
        .args(["addr", "del", &cidr, "dev", "wolfnet0"])
        .output();
    // Add as local route (idempotent — replace if exists)
    let _ = std::process::Command::new("ip")
        .args(["route", "replace", "local", &cidr, "dev", "lo"])
        .output();

    // One-time setup: ip_forward + rp_filter + FORWARD chain rules
    use std::sync::atomic::{AtomicBool, Ordering};
    static VIP_INFRA_READY: AtomicBool = AtomicBool::new(false);
    if !VIP_INFRA_READY.load(Ordering::Relaxed) {
        let _ = std::process::Command::new("sysctl")
            .args(["-w", "net.ipv4.conf.wolfnet0.forwarding=1"])
            .output();
        let _ = std::process::Command::new("sysctl")
            .args(["-w", "net.ipv4.conf.docker0.forwarding=1"])
            .output();
        let _ = std::process::Command::new("sysctl")
            .args(["-w", "net.ipv4.conf.lxcbr0.forwarding=1"])
            .output();
        // Disable reverse path filtering on wolfnet0 — required because after DNAT
        // the source IP is a remote WolfNet peer but the reply goes via a different path
        let _ = std::process::Command::new("sysctl")
            .args(["-w", "net.ipv4.conf.wolfnet0.rp_filter=0"])
            .output();
        let _ = std::process::Command::new("sysctl")
            .args(["-w", "net.ipv4.conf.all.rp_filter=0"])
            .output();
        // FORWARD rules: wolfnet0 ↔ container bridges AND wolfnet0 ↔ wolfnet0 (hairpin for remote backends)
        for iface_pair in &[
            ("wolfnet0", "docker0"),
            ("wolfnet0", "lxcbr0"),
            ("wolfnet0", "wolfnet0"),  // hairpin: backend on remote node
        ] {
            let check = std::process::Command::new("iptables")
                .args(["-C", "FORWARD", "-i", iface_pair.0, "-o", iface_pair.1, "-j", "ACCEPT"])
                .output();
            if check.map(|o| !o.status.success()).unwrap_or(true) {
                let _ = std::process::Command::new("iptables")
                    .args(["-I", "FORWARD", "-i", iface_pair.0, "-o", iface_pair.1, "-j", "ACCEPT"])
                    .output();
                if iface_pair.0 != iface_pair.1 {
                    let _ = std::process::Command::new("iptables")
                        .args(["-I", "FORWARD", "-i", iface_pair.1, "-o", iface_pair.0, "-j", "ACCEPT"])
                        .output();
                }
            }
        }
        VIP_INFRA_READY.store(true, Ordering::Relaxed);

    }

    // Send gratuitous ARP in background (don't block the reconcile loop)
    let vip_owned = vip.to_string();
    std::thread::spawn(move || {
        let _ = std::process::Command::new("arping")
            .args(["-U", "-c", "1", "-I", "wolfnet0", &vip_owned])
            .output();
    });

    // Push VIP into local WolfNet routes (cached host IP to avoid spawning a process every cycle)
    use std::sync::OnceLock;
    static HOST_WOLFNET_IP: OnceLock<Option<String>> = OnceLock::new();
    let host_ip = HOST_WOLFNET_IP.get_or_init(|| {
        std::process::Command::new("ip")
            .args(["addr", "show", "wolfnet0"])
            .output()
            .ok()
            .and_then(|o| {
                let text = String::from_utf8_lossy(&o.stdout).to_string();
                text.lines()
                    .find(|l| l.contains("inet "))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|s| s.split('/').next())
                    .map(|s| s.to_string())
            })
    });
    if let Some(host_ip) = host_ip {
        let mut routes = std::collections::HashMap::new();
        routes.insert(vip.to_string(), host_ip.clone());
        crate::containers::update_wolfnet_routes(&routes);

    }

    let n = backend_ips.len();

    // Parse service ports to get the container-side ports for LB rules
    // Port format is "host_port:container_port" or just "port"
    let lb_ports: Vec<String> = ports.iter().map(|p| {
        if let Some((_host, container)) = p.split_once(':') {
            container.to_string()
        } else {
            p.clone()
        }
    }).collect();

    // Create DNAT rules for both PREROUTING (external) and OUTPUT (local)
    for chain in &["PREROUTING", "OUTPUT"] {
        for (i, backend) in backend_ips.iter().enumerate() {
            let remaining = n - i;

            let mut args: Vec<String> = vec![
                "-t".into(), "nat".into(), "-A".into(), chain.to_string(),
                "-d".into(), vip.to_string(),
            ];

            // Add port matching if service has ports
            if !lb_ports.is_empty() {
                args.extend_from_slice(&["-p".into(), "tcp".into()]);
                if lb_ports.len() == 1 {
                    args.extend_from_slice(&["--dport".into(), lb_ports[0].clone()]);
                } else {
                    args.extend_from_slice(&["-m".into(), "multiport".into(), "--dports".into(), lb_ports.join(",")]);
                }
            }

            // Distribution mode
            if lb_policy == "ip_hash" {
                // ip_hash: use `statistic --mode random` for distribution.
                // conntrack ensures all packets in a connection go to the same
                // backend, giving session stickiness.
                if remaining > 1 {
                    let prob = 1.0 / remaining as f64;
                    args.extend_from_slice(&[
                        "-m".into(), "statistic".into(),
                        "--mode".into(), "random".into(),
                        "--probability".into(), format!("{:.6}", prob),
                    ]);
                }
            } else {
                // round_robin: nth-based distribution
                if remaining > 1 {
                    args.extend_from_slice(&[
                        "-m".into(), "statistic".into(),
                        "--mode".into(), "nth".into(),
                        "--every".into(), remaining.to_string(),
                        "--packet".into(), "0".into(),
                    ]);
                }
            }

            // Add DNAT target
            let dest = if !lb_ports.is_empty() {
                format!("{}:{}", backend, lb_ports[0])
            } else {
                backend.clone()
            };
            args.extend_from_slice(&["-j".into(), "DNAT".into(), "--to-destination".into(), dest]);
            args.extend_from_slice(&["-m".into(), "comment".into(), "--comment".into(), format!("wolfrun-lb-{}", vip)]);

            let output = std::process::Command::new("iptables")
                .args(args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
                .output();

            match output {
                Ok(o) if o.status.success() => {},
                Ok(o) => warn!("WolfRun LB: iptables rule failed for {} → {}: {}",
                    vip, backend, String::from_utf8_lossy(&o.stderr)),
                Err(e) => warn!("WolfRun LB: failed to run iptables: {}", e),
            }
        }
    }

    // MASQUERADE for return traffic (per-backend)
    for backend in backend_ips {
        let _ = std::process::Command::new("iptables")
            .args(["-t", "nat", "-A", "POSTROUTING", "-d", backend,
                "-m", "comment", "--comment", &format!("wolfrun-lb-{}", vip),
                "-j", "MASQUERADE"])
            .output();
    }


}

/// Pure: every VIP tagged by a `wolfrun-lb-<vip>` comment in an
/// `iptables -S` listing. Token-exact, so 10.10.10.5 never matches the
/// rules of 10.10.10.50.
fn vips_tagged_in_listing(listing: &str) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    for line in listing.lines() {
        let mut toks = line.split_whitespace();
        while let Some(t) = toks.next() {
            if t != "--comment" { continue; }
            if let Some(c) = toks.next()
                && let Some(vip) = c.trim_matches('"').strip_prefix("wolfrun-lb-")
                && !vip.is_empty()
            {
                set.insert(vip.to_string());
            }
        }
    }
    set
}

/// VIPs whose LB DNAT rules are actually present in nat PREROUTING right
/// now. `rebuild_lb_rules` always writes at least one PREROUTING rule per
/// backend, so "no tagged rule" for a VIP with backends means the ruleset
/// was lost. `None` if the listing could not be taken.
fn vips_with_lb_rules() -> Option<std::collections::HashSet<String>> {
    let out = std::process::Command::new("iptables")
        .args(["-t", "nat", "-S", "PREROUTING"])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    Some(vips_tagged_in_listing(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(test)]
mod lb_rule_presence_tests {
    use super::vips_tagged_in_listing;

    #[test]
    fn finds_each_tagged_vip_once_and_is_token_exact() {
        let listing = "\
-P PREROUTING ACCEPT
-A PREROUTING -d 10.10.10.50/32 -p tcp -m tcp --dport 80 -m statistic --mode nth --every 2 --packet 0 -j DNAT --to-destination 10.10.10.101:80 -m comment --comment wolfrun-lb-10.10.10.50
-A PREROUTING -d 10.10.10.50/32 -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.10.10.102:80 -m comment --comment wolfrun-lb-10.10.10.50
-A PREROUTING -d 10.10.10.7/32 -m comment --comment \"wolfrun-lb-10.10.10.7\" -j DNAT --to-destination 10.10.10.103
-A PREROUTING -d 10.10.10.105/32 -m comment --comment wolfstack-wolfnet-container -j DNAT --to-destination 172.18.0.5
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
";
        let set = vips_tagged_in_listing(listing);
        assert!(set.contains("10.10.10.50"));
        assert!(set.contains("10.10.10.7"));
        assert!(!set.contains("10.10.10.5"), "prefix of .50 must not count as present");
        assert!(!set.contains("10.10.10.105"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn empty_listing_has_no_vips() {
        assert!(vips_tagged_in_listing("-P PREROUTING ACCEPT\n").is_empty());
    }
}

/// Remove all iptables rules tagged with a WolfRun LB comment for a given VIP
pub fn remove_lb_rules_for_vip(vip: &str) {
    let comment = format!("wolfrun-lb-{}", vip);

    // Remove from nat PREROUTING, POSTROUTING and OUTPUT.
    //
    // ONE listing per chain, then delete by descending line number.
    //
    // This loop used to re-run `iptables -L <chain>` before EVERY single
    // delete, because deleting a rule renumbers the ones after it. That
    // made removal 2N subprocesses per chain, N of them full nat-table
    // listings that take the global netfilter lock — and a rebuild calls
    // this first, so it ran on every reconcile tick whose backends had
    // changed. On a node running WolfRun with flapping backends that was
    // a large share of the 61% system time klas measured at 354% CPU
    // (2026-08-12).
    //
    // Deleting in DESCENDING order removes the need to re-list at all:
    // removing a higher-numbered rule never shifts a lower-numbered one,
    // so every number collected from the single listing stays valid.
    for chain in &["PREROUTING", "POSTROUTING", "OUTPUT"] {
        let output = std::process::Command::new("iptables")
            .args(["-t", "nat", "-L", chain, "--line-numbers", "-n"])
            .output();

        let lines = match output {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => continue,
        };

        let mut nums: Vec<u32> = lines
            .lines()
            .filter(|l| l.contains(&comment))
            .filter_map(|l| l.split_whitespace().next())
            .filter_map(|n| n.parse::<u32>().ok())
            .collect();
        nums.sort_unstable();

        for num in nums.into_iter().rev() {
            let _ = std::process::Command::new("iptables")
                .args(["-t", "nat", "-D", chain, &num.to_string()])
                .output();
        }
    }

    // Remove the VIP local route and any stale interface address (best-effort)
    let cidr = format!("{}/32", vip);
    let _ = std::process::Command::new("ip")
        .args(["route", "del", "local", &cidr, "dev", "lo"])
        .output();
    let _ = std::process::Command::new("ip")
        .args(["addr", "del", &cidr, "dev", "wolfnet0"])
        .output();
}

#[cfg(test)]
mod node_id_match_tests {
    use super::node_matches_id;

    fn node(id: &str, self_id: Option<&str>) -> crate::agent::Node {
        let mut base = serde_json::json!({
            "id": id, "hostname": "h", "address": "10.0.0.9", "port": 8553,
            "last_seen": 0, "metrics": null, "components": [], "online": true, "is_self": false
        });
        if let Some(s) = self_id { base["self_id"] = serde_json::json!(s); }
        serde_json::from_value(base).unwrap()
    }

    #[test]
    fn matches_either_local_key_or_self_id() {
        // Online entry keyed by node-… with a ws-… self_id (AstroMando's case):
        // an instance recorded under EITHER form must resolve to it.
        let n = node("node-abc", Some("ws-xyz"));
        assert!(node_matches_id(&n, "node-abc"));   // local key form
        assert!(node_matches_id(&n, "ws-xyz"));     // self_id form — the fix
        assert!(!node_matches_id(&n, "ws-OLD"));    // a genuinely-gone id never matches
        assert!(!node_matches_id(&n, "node-other"));

        // Self node: registry key IS the ws-… self_id, self_id field empty.
        let s = node("ws-self", None);
        assert!(node_matches_id(&s, "ws-self"));
        assert!(!node_matches_id(&s, "node-self"));
    }
}

#[cfg(test)]
mod replica_count_tests {
    use super::ServiceInstance;

    fn inst(name: &str, status: &str, standby: bool) -> ServiceInstance {
        ServiceInstance {
            node_id: "node-549".into(),
            container_name: name.into(),
            wolfnet_ip: None,
            status: status.into(),
            last_seen: 0,
            standby,
        }
    }

    /// Mirror of the reconciler's `existing` predicate. Kept in lockstep
    /// with the filter in `reconcile()` — the whole bug was that this
    /// count disagreed with reality.
    fn existing_count(instances: &[ServiceInstance]) -> u32 {
        instances.iter().filter(|i| !i.standby && i.status != "lost").count() as u32
    }

    #[test]
    fn a_crash_looping_instance_still_counts_as_existing() {
        // THE klas BUG (2026-08-12): a Docker container whose image
        // crash-loops sits in `restarting` forever. The old allowlist
        // (running/stopped/pending/offline/created/exited) did not name
        // that state, so the reconciler saw zero instances, cloned
        // another one every tick, and never counted what it made —
        // ~100 containers of one service on one node.
        let live = vec![inst("pocket-id-wolfrun-1a2b", "restarting", false)];
        assert_eq!(existing_count(&live), 1, "a restarting container exists — do not clone another");
    }

    #[test]
    fn every_runtime_state_except_lost_counts_as_existing() {
        // Docker: created/restarting/running/removing/paused/exited/dead.
        // LXC: starting/running/stopping/stopped/freezing/frozen/aborting.
        // Any state the runtimes add later must default to "exists" too —
        // that direction under-creates (visible, safe); the other fills a disk.
        for state in ["created", "restarting", "running", "removing", "paused",
                      "exited", "dead", "starting", "stopping", "stopped",
                      "freezing", "frozen", "aborting", "pending", "offline",
                      "some-future-state"] {
            let live = vec![inst("c", state, false)];
            assert_eq!(existing_count(&live), 1, "state {:?} must count as existing", state);
        }
        // Only a container that vanished from an ONLINE node is replaceable.
        assert_eq!(existing_count(&[inst("c", "lost", false)]), 0);
        // Standby instances never count toward active replicas.
        assert_eq!(existing_count(&[inst("c", "running", true)]), 0);
    }

    #[test]
    fn creation_is_bounded_by_ceiling_and_per_tick_cap() {
        // Mirror of the scale-up arithmetic: whatever the counting says,
        // max_replicas is absolute and a single tick creates at most 2.
        const MAX_CREATES_PER_TICK: u32 = 2;
        let plan = |desired: u32, existing: u32, max_replicas: u32| -> u32 {
            if existing >= desired { return 0; }
            let ceiling = max_replicas.max(desired);
            let room = ceiling.saturating_sub(existing);
            (desired - existing).min(room).min(MAX_CREATES_PER_TICK)
        };
        // Normal scale-up: paced, not instant.
        assert_eq!(plan(10, 0, 10), 2);
        assert_eq!(plan(3, 2, 10), 1);
        // Already at or over the ceiling: never create, even if a bug
        // claims more are needed.
        assert_eq!(plan(10, 10, 10), 0);
        assert_eq!(plan(10, 99, 10), 0, "over-ceiling must never create — this is the runaway brake");
        // Ceiling below desired (mis-set config) still honours desired.
        assert_eq!(plan(5, 4, 1), 1);
    }
}

#[cfg(test)]
mod reconcile_list_fetch_tests {
    use std::collections::HashMap;

    /// Mirrors the reconcile pass's list-fetch policy: a container list
    /// is fetched at most once per (node, runtime) per pass, however
    /// many instances live on that node. The old code fetched inside
    /// the per-instance loop, which is quadratic in
    /// (instances × containers) — 4h48m of CPU in 40 minutes of wall
    /// clock on a node with ~100 instances (klas, 2026-08-12).
    fn fetches_for(instances_per_node: &[(&str, usize)]) -> usize {
        let mut cache: HashMap<(String, &'static str), usize> = HashMap::new();
        let mut fetches = 0;
        for (node, count) in instances_per_node {
            for _inst in 0..*count {
                let key = (node.to_string(), "docker");
                cache.entry(key).or_insert_with(|| {
                    fetches += 1; // the expensive part: enumerate the node
                    1
                });
            }
        }
        fetches
    }

    #[test]
    fn one_list_fetch_per_node_regardless_of_instance_count() {
        // klas's shape: ~100 instances across two nodes.
        assert_eq!(fetches_for(&[("node-549", 99), ("node-473", 1)]), 2,
            "two nodes must cost two fetches — this was 100 before");
        // Degenerate and ordinary shapes.
        assert_eq!(fetches_for(&[("node-549", 1)]), 1);
        assert_eq!(fetches_for(&[]), 0);
        // Growth in instances must NOT grow fetches.
        assert_eq!(fetches_for(&[("a", 1000)]), 1,
            "instance count must not drive enumeration count");
    }
}
