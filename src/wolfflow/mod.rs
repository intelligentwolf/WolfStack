// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! WolfFlow — Workflow Automation Engine for WolfStack
//!
//! Provides server management workflow automation:
//! - Define multi-step workflows (update packages, restart services, prune Docker, etc.)
//! - Target local, all nodes, specific cluster, or named nodes
//! - Cron-based scheduling with a minimal built-in matcher (no external crate)
//! - Sequential step execution with configurable failure policies
//! - Remote execution via inter-node API calls

use serde::{Serialize, Deserialize};
use std::sync::{Arc, RwLock};
use chrono::Utc;
use tracing::{info, warn, error};

use crate::agent::ClusterState;
use crate::node_identity::PeerAuth;

/// Shared HTTP clients for WolfFlow action execution. Two flavors
/// because the `HttpRequest` action exposes a `verify_tls` toggle to
/// the user — we honour it by dispatching to the appropriate pool.
/// Per-call `crate::api::ipv4_only_client_builder()` was leaking one connection
/// pool per workflow step; on a scheduled workflow with many HTTP
/// actions, that compounded per run.
///
/// `_INSECURE` is also used for cluster-internal calls (remote step
/// execution, Unifi sessions) because WolfStack commonly talks to
/// self-signed peers and the existing behaviour was
/// `danger_accept_invalid_certs(true)`.
static WOLFFLOW_CLIENT_STRICT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });
static WOLFFLOW_CLIENT_INSECURE: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

// ─── Constants ───

fn wolfflow_dir() -> String { crate::paths::get().wolfflow_dir }
fn workflows_file() -> String { crate::paths::get().wolfflow_workflows }
fn runs_file() -> String { crate::paths::get().wolfflow_runs }

/// Maximum number of runs to keep in history
const MAX_RUNS: usize = 500;

// ─── Default helpers ───

fn default_channel() -> String { "master".to_string() }
fn default_timeout() -> u64 { 300 }
fn default_true() -> bool { true }
fn default_eq() -> String { "eq".to_string() }
fn default_http_method() -> String { "GET".to_string() }
fn default_target_all() -> String { "all".to_string() }
fn default_ai_max_tokens() -> u32 { 1024 }

// ═══════════════════════════════════════════════
// ─── Data Types ───
// ═══════════════════════════════════════════════

/// Structured output from a step execution, enabling data passing between nodes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StepOutput {
    /// Human-readable output text (equivalent to prior Ok(String))
    pub text: String,
    /// Structured key-value data that downstream steps can reference via `{{step_name.key}}`
    #[serde(default)]
    pub data: serde_json::Map<String, serde_json::Value>,
}

/// Execution context passed through a workflow run, carrying outputs from previous steps.
#[derive(Debug, Clone, Default)]
pub struct WorkflowContext {
    pub step_outputs: std::collections::HashMap<String, StepOutput>,
}

/// HTTP header for the HttpRequest action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

/// Authentication configuration for the HttpRequest action
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HttpAuth {
    Bearer { token: String },
    Basic { username: String, password: String },
    ApiKey { header_name: String, key: String },
}

/// Webhook trigger configuration for a workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Unique webhook path token (auto-generated UUID)
    pub token: String,
    /// Optional secret for HMAC validation of incoming payloads
    #[serde(default)]
    pub secret: Option<String>,
    /// Whether the webhook is active
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// An action to perform in a workflow step
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ActionType {
    /// Run the system package manager update + upgrade
    UpdatePackages,
    /// Pull and run the WolfStack installer for a given channel
    UpdateWolfstack {
        #[serde(default = "default_channel")]
        channel: String,
    },
    /// Restart a systemd service by name
    RestartService {
        service_name: String,
    },
    /// Run an arbitrary shell command with a timeout
    RunCommand {
        command: String,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
    },
    /// Vacuum systemd journal logs
    CleanLogs {
        #[serde(default)]
        max_size_mb: Option<u32>,
    },
    /// Check disk space on specified mount point (defaults to all)
    CheckDiskSpace {
        #[serde(default)]
        warn_threshold_pct: Option<u32>,
        /// Mount point to check e.g. "/" or "/var" or "all" (default: all)
        #[serde(default)]
        mount_point: Option<String>,
    },
    /// Restart a Docker or LXC container
    RestartContainer {
        runtime: String,
        name: String,
    },
    /// Prune all unused Docker resources
    DockerPrune,

    // ─── Docker Update Nodes ───

    /// Check if a Docker image has a newer version available on the registry
    DockerCheckUpdate {
        /// Container name or image reference (e.g., "nginx:latest", "myapp")
        container_or_image: String,
    },

    /// Update a Docker container to the latest image version
    DockerUpdate {
        container_name: String,
        /// Create a backup before updating (default: true)
        #[serde(default = "default_true")]
        backup_first: bool,
    },

    // ─── Docker Multi-container Update Nodes ───
    //
    // Bulk variants that drive WolfStack's image-watcher pipeline (full
    // recreate-from-inspect + optional backup + health-check + optional
    // rollback) instead of the simpler docker-restart used by
    // `DockerUpdate`. Honours per-container policy from
    // `/etc/wolfstack/image-watcher.json` — pinned/ignored containers
    // are skipped automatically, no foot-guns.

    /// Check ALL running Docker containers on the local node (or a
    /// selected subset) for available image updates. Same code path as
    /// the background watcher uses; result is the per-container
    /// `update_available` boolean + remote/local digests.
    DockerCheckUpdateMany {
        /// Targeting mode: `"all"` walks every running container; any
        /// other value treats `container_names` as the explicit list.
        #[serde(default = "default_target_all")]
        target: String,
        /// Containers to check when `target != "all"`. Ignored
        /// otherwise.
        #[serde(default)]
        container_names: Vec<String>,
    },

    /// Update ALL running Docker containers (or a selected subset) to
    /// the latest image version, using the full image-watcher pipeline.
    /// Honours `max_parallel_updates` from the image-watcher config so
    /// the host doesn't get crushed by N concurrent pulls.
    DockerUpdateMany {
        #[serde(default = "default_target_all")]
        target: String,
        #[serde(default)]
        container_names: Vec<String>,
    },

    // ─── Backup ───

    /// Run a WolfStack backup schedule (on the node executing the step) and
    /// wait for it to finish. Backups go through the normal pipeline, so
    /// they appear in the Backups section for management and restore, honour
    /// the schedule's retention, and run its pre/post commands (wabil
    /// 2026-07-02). The step fails if any backup in the run fails.
    /// HOST-scoped: container/VM step targeting doesn't apply — schedules
    /// live on the node, and `execute_action_in_container` falls back to
    /// local execution for this variant.
    RunBackupSchedule {
        schedule_id: String,
    },

    // ─── Generic HTTP Request ───

    /// Make an HTTP request to any external API
    HttpRequest {
        #[serde(default = "default_http_method")]
        method: String,
        url: String,
        #[serde(default)]
        headers: Vec<HttpHeader>,
        #[serde(default)]
        body: Option<String>,
        #[serde(default)]
        auth: Option<HttpAuth>,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
        /// If true, fail the step on non-2xx status codes
        #[serde(default = "default_true")]
        fail_on_error: bool,
        /// If false, skip TLS certificate verification (default: false for homelab compat)
        #[serde(default)]
        verify_tls: bool,
    },

    // ─── Conditional / Branch ───

    /// Evaluate a condition and choose execution path.
    /// Supports template variables: `{{step_name.key}}`
    Condition {
        /// Value or expression to evaluate
        expression: String,
        /// Value to compare against
        compare_to: String,
        /// Operator: eq, neq, gt, lt, gte, lte, contains, matches, truthy
        #[serde(default = "default_eq")]
        operator: String,
    },

    // ─── Service-Specific Nodes ───

    /// NetBird VPN management API action
    NetBirdAction {
        /// NetBird management URL (default: https://api.netbird.io)
        api_url: String,
        /// Bearer token for NetBird API
        api_token: String,
        /// API endpoint path (e.g., "/api/peers")
        endpoint: String,
        #[serde(default = "default_http_method")]
        method: String,
        #[serde(default)]
        body: Option<String>,
    },

    /// TrueNAS Scale API action
    TrueNasAction {
        api_url: String,
        api_key: String,
        endpoint: String,
        #[serde(default = "default_http_method")]
        method: String,
        #[serde(default)]
        body: Option<String>,
    },

    /// Unifi Network Controller API action
    UnifiAction {
        api_url: String,
        username: String,
        password: String,
        endpoint: String,
        #[serde(default = "default_http_method")]
        method: String,
        #[serde(default)]
        body: Option<String>,
    },

    /// Execute an action on a configured external integration instance
    IntegrationAction {
        /// Integration instance ID
        instance_id: String,
        /// Operation name (from connector capabilities)
        operation: String,
        /// Operation parameters
        #[serde(default)]
        params: serde_json::Value,
    },

    // ─── AI / Agent Nodes ───

    /// Invoke the configured AI model with a prompt and capture the
    /// response. Lets workflows branch on AI judgment ("is this a real
    /// alert?", "summarise this disk-full report"). The prompt body
    /// supports `{{step_name.key}}` template substitution like other
    /// action types so prior steps can feed into the question. The
    /// response text lands in the step's stdout for downstream steps
    /// (typically a Condition) to act on.
    ///
    /// Uses the global AI config — no per-agent context. For a
    /// per-agent persistent conversation, use `AgentChat` (which
    /// pulls the agent's memory + tool allowlist from WolfAgents).
    AiInvoke {
        /// User-side prompt — what to ask the model. Templated.
        prompt: String,
        /// Optional system prompt override — defaults to a generic
        /// "you are an ops assistant" if omitted.
        #[serde(default)]
        system_prompt: Option<String>,
        /// Override the configured AI model (e.g. swap to a smaller
        /// faster one for routine summaries). Defaults to AiConfig.model.
        #[serde(default)]
        model: Option<String>,
        /// Override the configured provider. Defaults to AiConfig.provider.
        #[serde(default)]
        provider: Option<String>,
        /// Cap response length so a runaway model can't fill the
        /// step's stdout buffer. Tokens, not characters.
        #[serde(default = "default_ai_max_tokens")]
        max_tokens: u32,
    },

    /// Send a message to a named WolfAgent and wait for its response.
    /// Unlike AiInvoke this uses the agent's persistent memory + tool
    /// allowlist, so the agent can take actions during the turn (e.g.
    /// restart a container, fetch metrics) and remember the
    /// conversation for next time.
    AgentChat {
        /// Agent ID from /api/agents.
        agent_id: String,
        /// Message to send. Templated.
        message: String,
        /// Seconds to wait for the agent to finish its turn. Agent
        /// tool-use loops can take a while so this defaults higher
        /// than the generic action timeout.
        #[serde(default = "default_agent_chat_timeout")]
        timeout_secs: u64,
    },

    /// Run a SQL query against a configured connection and expose the
    /// result as `{columns, rows, row_count, rows_csv, rows_markdown}`
    /// for downstream steps. `permission` picks the classifier tier —
    /// `read` only accepts SELECT/SHOW, `update` also accepts
    /// INSERT/UPDATE, `delete` additionally accepts DELETE/TRUNCATE.
    /// DDL is never allowed from the workflow surface.
    ///
    /// Pairs with `SendEmail` for the "run a query every 2h and email
    /// the result" use case operators asked for.
    SqlQuery {
        /// Connection id from Settings → SQL Connections.
        connection_id: String,
        /// SQL text. Templated (`{{step.x.…}}` etc. resolved first).
        query: String,
        /// Tier the query is expected to fall under. Sqlparser rejects
        /// anything above this at execution time.
        #[serde(default = "default_sql_permission")]
        permission: SqlStepPermission,
        /// Wall-clock timeout for the query. Default 30s.
        #[serde(default = "default_sql_timeout")]
        timeout_secs: u64,
        /// Fail the step if the query returned zero rows. Useful when
        /// the workflow is supposed to trigger downstream only when a
        /// condition is present in the DB.
        #[serde(default)]
        fail_on_empty: bool,
    },

    /// Send an email via the SMTP config in Settings → Alerting.
    /// Used as the tail of "query → email" workflows. Body supports
    /// templating so `{{step.qry.rows_markdown}}` drops in the
    /// formatted result from an upstream SqlQuery.
    SendEmail {
        /// One or more addresses. Templated.
        to: Vec<String>,
        /// Subject line. Templated.
        subject: String,
        /// Plain-text body. Templated.
        body: String,
        /// If true, body is treated as HTML and sent with a
        /// text/html Content-Type. Otherwise plain text.
        #[serde(default)]
        html: bool,
    },
}

/// Mirror of `sql_connections::SqlPermission` that lives in this
/// module for serde round-tripping without adding a cross-module
/// serde dependency loop.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SqlStepPermission { Read, Update, Delete }

fn default_sql_permission() -> SqlStepPermission { SqlStepPermission::Read }
fn default_sql_timeout() -> u64 { 30 }

impl From<SqlStepPermission> for crate::sql_connections::SqlPermission {
    fn from(s: SqlStepPermission) -> Self {
        match s {
            SqlStepPermission::Read => crate::sql_connections::SqlPermission::Read,
            SqlStepPermission::Update => crate::sql_connections::SqlPermission::Update,
            SqlStepPermission::Delete => crate::sql_connections::SqlPermission::Delete,
        }
    }
}

fn default_agent_chat_timeout() -> u64 { 180 }

/// What to do when a step fails
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum OnFailure {
    /// Continue to the next step
    Continue,
    /// Abort the entire workflow
    #[default]
    Abort,
    /// Log an alert and continue
    Alert,
    /// Send notification via alerting system and abort
    NotifyAndAbort,
    /// Send notification via alerting system and continue
    NotifyAndContinue,
}


/// Target scope for workflow execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum Target {
    /// Execute only on the local node
    Local,
    /// Execute on all online nodes in the cluster
    AllNodes,
    /// Execute on all nodes in a named cluster
    Cluster {
        cluster_name: String,
    },
    /// Execute on specific nodes by ID
    Nodes {
        node_ids: Vec<String>,
    },
    /// Execute on specific containers/VMs/LXCs
    /// Each entry is "node_id:runtime:name" e.g. "node-abc:docker:nginx"
    Containers {
        #[serde(default)]
        targets: Vec<ContainerTarget>,
    },
    /// Execute on ALL nodes AND inside all their containers/VMs
    Everything,
}

/// A specific container/VM/LXC target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerTarget {
    pub node_id: String,
    pub runtime: String, // "docker", "lxc", "vm"
    pub name: String,
}

/// A single step within a workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub name: String,
    pub action: ActionType,
    #[serde(default)]
    pub on_failure: OnFailure,
    #[serde(default)]
    pub target_override: Option<Target>,
    /// For Condition nodes: step index to jump to on true (0-based)
    #[serde(default)]
    pub on_true_step: Option<usize>,
    /// For Condition nodes: step index to jump to on false (0-based)
    #[serde(default)]
    pub on_false_step: Option<usize>,
    /// Maximum retry count before marking as failed (0 = no retry)
    #[serde(default)]
    pub retry_count: u32,
    /// Delay between retries in seconds
    #[serde(default)]
    pub retry_delay_secs: u64,
}

/// A complete workflow definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub cluster: String,
    pub steps: Vec<WorkflowStep>,
    pub target: Target,
    /// Optional cron expression (5-field: min hour dom month dow)
    #[serde(default)]
    pub schedule: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub last_run: Option<String>,
    /// Email address to send results to (optional — uses SMTP settings from alerting config)
    #[serde(default)]
    pub email_results: Option<String>,
    /// Webhook trigger — when configured, this workflow can be triggered by an incoming POST
    #[serde(default)]
    pub webhook: Option<WebhookConfig>,
    /// Maximum total runtime in seconds (0 = unlimited)
    #[serde(default)]
    pub max_runtime_secs: u64,
}

/// Status of a workflow run or individual step
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Completed,
    Failed,
    PartialFailure,
}

/// Result of executing a single step on a single node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_name: String,
    pub node_id: String,
    pub node_hostname: String,
    pub status: RunStatus,
    pub output: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
}

/// A complete workflow execution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRun {
    pub id: String,
    pub workflow_id: String,
    pub workflow_name: String,
    pub status: RunStatus,
    pub trigger: String,
    pub steps: Vec<StepResult>,
    pub started_at: String,
    #[serde(default)]
    pub finished_at: Option<String>,
    pub duration_ms: u64,
    /// Email delivery status (shown in task log)
    #[serde(default)]
    pub email_status: Option<String>,
}

// ═══════════════════════════════════════════════
// ─── State Management ───
// ═══════════════════════════════════════════════

pub struct WolfFlowState {
    workflows: RwLock<Vec<Workflow>>,
    runs: RwLock<Vec<WorkflowRun>>,
}

impl WolfFlowState {
    pub fn new() -> Self {
        let state = Self {
            workflows: RwLock::new(Vec::new()),
            runs: RwLock::new(Vec::new()),
        };
        state.load_workflows();
        state.load_runs();
        state
    }

    // ─── Persistence ───

    fn load_workflows(&self) {
        if let Ok(data) = std::fs::read_to_string(workflows_file())
            && let Ok(wfs) = serde_json::from_str::<Vec<Workflow>>(&data) {
                let mut workflows = self.workflows.write().unwrap();
                *workflows = wfs;
            }
    }

    fn save_workflows(&self) {
        let wfs = self.workflows.read().unwrap();
        if let Ok(json) = serde_json::to_string_pretty(&*wfs) {
            let _ = std::fs::create_dir_all(wolfflow_dir());
            if let Err(e) = std::fs::write(workflows_file(), json) {
                warn!("WolfFlow: failed to save workflows: {}", e);
            }
        }
    }

    fn load_runs(&self) {
        if let Ok(data) = std::fs::read_to_string(runs_file())
            && let Ok(runs) = serde_json::from_str::<Vec<WorkflowRun>>(&data) {
                let mut r = self.runs.write().unwrap();
                *r = runs;
            }
    }

    fn save_runs(&self) {
        let runs = self.runs.read().unwrap();
        if let Ok(json) = serde_json::to_string_pretty(&*runs) {
            let _ = std::fs::create_dir_all(wolfflow_dir());
            if let Err(e) = std::fs::write(runs_file(), json) {
                warn!("WolfFlow: failed to save runs: {}", e);
            }
        }
    }

    // ─── Workflow CRUD ───

    pub fn list_workflows(&self, cluster: Option<&str>) -> Vec<Workflow> {
        let wfs = self.workflows.read().unwrap();
        match cluster {
            Some(c) => wfs.iter().filter(|w| w.cluster == c).cloned().collect(),
            None => wfs.clone(),
        }
    }

    pub fn get_workflow(&self, id: &str) -> Option<Workflow> {
        let wfs = self.workflows.read().unwrap();
        wfs.iter().find(|w| w.id == id).cloned()
    }

    pub fn create_workflow(&self, workflow: Workflow) -> Workflow {
        let mut wfs = self.workflows.write().unwrap();
        wfs.push(workflow.clone());
        drop(wfs);
        self.save_workflows();
        workflow
    }

    pub fn update_workflow(&self, id: &str, mut updated: Workflow) -> Option<Workflow> {
        let mut wfs = self.workflows.write().unwrap();
        if let Some(existing) = wfs.iter_mut().find(|w| w.id == id) {
            updated.id = id.to_string();
            updated.created_at = existing.created_at.clone();
            updated.updated_at = Utc::now().to_rfc3339();
            *existing = updated.clone();
            drop(wfs);
            self.save_workflows();
            Some(updated)
        } else {
            None
        }
    }

    pub fn delete_workflow(&self, id: &str) -> Option<Workflow> {
        let mut wfs = self.workflows.write().unwrap();
        let idx = wfs.iter().position(|w| w.id == id);
        let removed = idx.map(|i| wfs.remove(i));
        drop(wfs);
        if removed.is_some() {
            self.save_workflows();
        }
        removed
    }

    /// Mark a workflow's last_run timestamp
    pub fn mark_last_run(&self, id: &str) {
        let mut wfs = self.workflows.write().unwrap();
        if let Some(wf) = wfs.iter_mut().find(|w| w.id == id) {
            wf.last_run = Some(Utc::now().to_rfc3339());
        }
        drop(wfs);
        self.save_workflows();
    }

    // ─── Run management ───

    pub fn list_runs(&self, workflow_id: Option<&str>) -> Vec<WorkflowRun> {
        let runs = self.runs.read().unwrap();
        match workflow_id {
            Some(wid) => runs.iter().filter(|r| r.workflow_id == wid).cloned().collect(),
            None => runs.clone(),
        }
    }

    pub fn add_run(&self, run: WorkflowRun) {
        let mut runs = self.runs.write().unwrap();
        runs.push(run);
        // Trim to keep only the most recent runs
        if runs.len() > MAX_RUNS {
            let drain = runs.len() - MAX_RUNS;
            runs.drain(..drain);
        }
        drop(runs);
        self.save_runs();
    }

    pub fn update_run(&self, run_id: &str, updated: WorkflowRun) {
        let mut runs = self.runs.write().unwrap();
        if let Some(existing) = runs.iter_mut().find(|r| r.id == run_id) {
            *existing = updated;
        }
        drop(runs);
        self.save_runs();
    }

    /// Get workflows that are due to run based on their cron schedule.
    /// Compares the cron expression against the current UTC time.
    pub fn get_due_workflows(&self) -> Vec<Workflow> {
        let now = Utc::now().naive_utc();
        let now_minute = now.format("%Y-%m-%d %H:%M").to_string();
        let wfs = self.workflows.read().unwrap();
        let runs = self.runs.read().unwrap();
        wfs.iter()
            .filter(|w| {
                if !w.enabled || w.schedule.is_none() { return false; }
                if !cron_matches(w.schedule.as_deref().unwrap(), &now) { return false; }
                // Skip if already ran in this same minute (prevent duplicate execution)
                let already_ran = runs.iter().any(|r| {
                    r.workflow_id == w.id
                        && r.trigger == "scheduled"
                        && r.started_at.starts_with(&now_minute)
                });
                !already_ran
            })
            .cloned()
            .collect()
    }

    /// Rename all cluster references from old_name to new_name.
    #[allow(dead_code)]
    pub fn rename_cluster(&self, old_name: &str, new_name: &str) -> usize {
        let mut wfs = self.workflows.write().unwrap();
        let mut count = 0;
        for wf in wfs.iter_mut() {
            if wf.cluster == old_name {
                wf.cluster = new_name.to_string();
                count += 1;
            }
        }
        drop(wfs);
        if count > 0 {
            self.save_workflows();
        }
        count
    }
}

// ═══════════════════════════════════════════════
// ─── Cron Matcher ───
// ═══════════════════════════════════════════════

/// Minimal 5-field cron expression matcher.
///
/// Format: `minute hour day-of-month month day-of-week`
///
/// Supports:
/// - `*` (any value)
/// - Single values: `5`
/// - Comma-separated: `1,15,30`
/// - Ranges: `1-5`
/// - Steps: `*/15`, `1-30/5`
pub fn cron_matches(expr: &str, now: &chrono::NaiveDateTime) -> bool {
    use chrono::{Datelike, Timelike};

    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 {
        return false;
    }

    let minute = now.minute();
    let hour = now.hour();
    let dom = now.day();
    let month = now.month();
    // chrono: Monday=0 .. Sunday=6 — cron uses Sunday=0, Monday=1 .. Saturday=6
    let dow_chrono = now.weekday().num_days_from_sunday(); // Sunday=0

    field_matches(fields[0], minute, 0, 59)
        && field_matches(fields[1], hour, 0, 23)
        && field_matches(fields[2], dom, 1, 31)
        && field_matches(fields[3], month, 1, 12)
        && field_matches(fields[4], dow_chrono, 0, 7) // 0 and 7 both mean Sunday
}

/// Check if a single cron field matches a given value.
/// Handles `*`, single values, comma-separated lists, ranges, and step values.
fn field_matches(field: &str, value: u32, min: u32, max: u32) -> bool {
    // Comma-separated entries: "1,15,30"
    for part in field.split(',') {
        if single_field_matches(part.trim(), value, min, max) {
            return true;
        }
    }
    false
}

/// Match a single cron field segment (no commas).
fn single_field_matches(part: &str, value: u32, min: u32, max: u32) -> bool {
    // Step: "*/15" or "1-30/5"
    if let Some((range_part, step_str)) = part.split_once('/') {
        let step: u32 = match step_str.parse() {
            Ok(s) if s > 0 => s,
            _ => return false,
        };
        let (range_min, range_max) = if range_part == "*" {
            (min, max)
        } else if let Some((lo, hi)) = range_part.split_once('-') {
            match (lo.parse::<u32>(), hi.parse::<u32>()) {
                (Ok(lo), Ok(hi)) => (lo, hi),
                _ => return false,
            }
        } else {
            return false;
        };
        // Value must be in range and on a step boundary from range_min
        if value < range_min || value > range_max {
            return false;
        }
        return (value - range_min).is_multiple_of(step);
    }

    // Wildcard
    if part == "*" {
        return true;
    }

    // Range: "1-5"
    if let Some((lo_str, hi_str)) = part.split_once('-') {
        if let (Ok(lo), Ok(hi)) = (lo_str.parse::<u32>(), hi_str.parse::<u32>()) {
            return value >= lo && value <= hi;
        }
        return false;
    }

    // Single value
    if let Ok(v) = part.parse::<u32>() {
        // For day-of-week, treat 7 as Sunday (same as 0)
        if min == 0 && max == 7 {
            let normalised_value = if value == 7 { 0 } else { value };
            let normalised_v = if v == 7 { 0 } else { v };
            return normalised_value == normalised_v;
        }
        return value == v;
    }

    false
}

// ═══════════════════════════════════════════════
// ─── Action Execution (Local) ───
// ═══════════════════════════════════════════════

/// Detect the system package manager
fn detect_package_manager() -> &'static str {
    if std::path::Path::new("/usr/bin/apt").exists()
        || std::path::Path::new("/usr/bin/apt-get").exists()
    {
        "apt"
    } else if std::path::Path::new("/usr/bin/dnf").exists() {
        "dnf"
    } else if std::path::Path::new("/usr/bin/pacman").exists() {
        "pacman"
    } else if std::path::Path::new("/usr/bin/zypper").exists() {
        "zypper"
    } else {
        "apt" // fallback
    }
}

/// Resolve `{{step_name.key}}` template variables from the workflow context.
/// Limited to 64 replacements to prevent infinite loops if a replacement value
/// itself contains `{{...}}` patterns.
pub fn resolve_templates(input: &str, context: &WorkflowContext) -> String {
    let mut result = input.to_string();
    let mut iterations = 0;
    // Match {{step_name.key}} patterns
    while let Some(start) = result.find("{{") {
        iterations += 1;
        if iterations > 64 { break; } // safety limit
        if let Some(end) = result[start..].find("}}") {
            let end = start + end + 2;
            let inner = &result[start + 2..end - 2].trim();
            let replacement = if let Some((step, key)) = inner.split_once('.') {
                context.step_outputs
                    .get(step.trim())
                    .and_then(|out| out.data.get(key.trim()))
                    .map(|v| match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .unwrap_or_default()
            } else {
                // Not a valid template ref — skip past it to avoid re-matching
                result = format!("{}[invalid-ref:{}]{}", &result[..start], inner, &result[end..]);
                continue;
            };
            result = format!("{}{}{}", &result[..start], replacement, &result[end..]);
        } else {
            break;
        }
    }
    result
}

/// Evaluate a condition expression
fn evaluate_condition(expression: &str, compare_to: &str, operator: &str, context: &WorkflowContext) -> bool {
    let resolved = resolve_templates(expression, context);
    let resolved = resolved.trim();
    let compare = compare_to.trim();

    match operator {
        "eq" => resolved == compare,
        "neq" => resolved != compare,
        "gt" => resolved.parse::<f64>().unwrap_or(0.0) > compare.parse::<f64>().unwrap_or(0.0),
        "lt" => resolved.parse::<f64>().unwrap_or(0.0) < compare.parse::<f64>().unwrap_or(0.0),
        "gte" => resolved.parse::<f64>().unwrap_or(0.0) >= compare.parse::<f64>().unwrap_or(0.0),
        "lte" => resolved.parse::<f64>().unwrap_or(0.0) <= compare.parse::<f64>().unwrap_or(0.0),
        "contains" => resolved.contains(compare),
        "matches" => {
            // Simple glob-style matching: * matches any substring
            if compare.contains('*') {
                let parts: Vec<&str> = compare.split('*').collect();
                let mut pos = 0;
                let mut ok = true;
                for (i, part) in parts.iter().enumerate() {
                    if part.is_empty() { continue; }
                    if let Some(found) = resolved[pos..].find(part) {
                        if i == 0 && found != 0 { ok = false; break; }
                        pos += found + part.len();
                    } else {
                        ok = false; break;
                    }
                }
                if ok && !parts.last().unwrap_or(&"").is_empty() && pos != resolved.len() { ok = false; }
                ok
            } else {
                resolved == compare
            }
        }
        "truthy" => !resolved.is_empty() && resolved != "false" && resolved != "0" && resolved != "null",
        _ => resolved == compare,
    }
}

/// Helper: wrap a plain string result into a StepOutput with no structured data.
fn plain_output(text: String) -> StepOutput {
    StepOutput { text, data: serde_json::Map::new() }
}

/// Helper: build a StepOutput with structured data.
fn structured_output(text: String, data: serde_json::Map<String, serde_json::Value>) -> StepOutput {
    StepOutput { text, data }
}

/// Execute a single action on the local machine.
/// Returns Ok(StepOutput) with structured data on success, Err(error_message) on failure.
pub async fn execute_action_local(action: &ActionType) -> Result<StepOutput, String> {
    match action {
        ActionType::UpdatePackages => {
            let pm = detect_package_manager();
            let (cmd, args): (&str, Vec<&str>) = match pm {
                "apt" => ("bash", vec!["-c", "apt-get update -y && apt-get upgrade -y"]),
                "dnf" => ("bash", vec!["-c", "dnf upgrade -y"]),
                "pacman" => ("bash", vec!["-c", "pacman -Syu --noconfirm"]),
                "zypper" => ("bash", vec!["-c", "zypper refresh && zypper update -y"]),
                _ => ("bash", vec!["-c", "apt-get update -y && apt-get upgrade -y"]),
            };
            run_command(cmd, &args, 600).await.map(plain_output)
        }

        ActionType::UpdateWolfstack { channel } => {
            let script = format!(
                "curl -sSL https://raw.githubusercontent.com/intelligentwolf/WolfStack/{}/setup.sh | bash",
                channel
            );
            run_command("bash", &["-c", &script], 600).await.map(plain_output)
        }

        ActionType::RestartService { service_name } => {
            validate_service_name(service_name)?;
            run_command("systemctl", &["restart", service_name], 60).await.map(plain_output)
        }

        ActionType::RunCommand { command, timeout_secs } => {
            run_command("bash", &["-c", command], *timeout_secs).await.map(plain_output)
        }

        ActionType::CleanLogs { max_size_mb } => {
            let size = max_size_mb.unwrap_or(500);
            let arg = format!("--vacuum-size={}M", size);
            run_command("journalctl", &[&arg], 120).await.map(plain_output)
        }

        ActionType::CheckDiskSpace { warn_threshold_pct, mount_point } => {
            let threshold = warn_threshold_pct.unwrap_or(90);
            let mp = mount_point.as_deref().unwrap_or("all");

            // Use df -BG for parseable gigabyte values + df -h for human-readable display
            let human_output = run_command("df", &["-h", "-x", "nfs", "-x", "nfs4", "-x", "cifs", "-x", "sshfs", "-x", "fuse.sshfs"], 10).await?;
            let gb_output = if mp == "all" || mp.is_empty() {
                run_command("df", &["-BG", "-x", "nfs", "-x", "nfs4", "-x", "cifs", "-x", "sshfs", "-x", "fuse.sshfs"], 10).await?
            } else {
                run_command("df", &["-BG", mp], 10).await?
            };

            // Parse structured data from df -BG output
            // Format: Filesystem  1G-blocks  Used  Available  Use%  Mounted
            let mut data = serde_json::Map::new();
            let mut over = Vec::new();
            let mut root_avail: u64 = 0;
            let mut root_total: u64 = 0;
            let mut root_pct: u32 = 0;

            for line in gb_output.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 6 { continue; }
                let mount = fields[5];
                let total: u64 = fields[1].trim_end_matches('G').parse().unwrap_or(0);
                let avail: u64 = fields[3].trim_end_matches('G').parse().unwrap_or(0);
                let pct: u32 = fields[4].trim_end_matches('%').parse().unwrap_or(0);

                // Track the target mount (or "/" for "all" mode)
                let is_target = if mp == "all" || mp.is_empty() {
                    mount == "/"
                } else {
                    mount == mp
                };
                if is_target {
                    root_avail = avail;
                    root_total = total;
                    root_pct = pct;
                }
                if pct > threshold {
                    over.push(format!("{} at {}%", mount, pct));
                }
            }

            data.insert("available_gb".to_string(), serde_json::json!(root_avail));
            data.insert("total_gb".to_string(), serde_json::json!(root_total));
            data.insert("usage_pct".to_string(), serde_json::json!(root_pct));
            data.insert("mount_point".to_string(), serde_json::json!(if mp == "all" || mp.is_empty() { "/" } else { mp }));
            data.insert("over_threshold".to_string(), serde_json::json!(!over.is_empty()));

            if over.is_empty() {
                Ok(structured_output(human_output, data))
            } else {
                // Still return structured data even on failure so conditions can use it
                Err(format!("Over {}%: {}\n\n{}", threshold, over.join(", "), human_output))
            }
        }

        ActionType::RestartContainer { runtime, name } => {
            // Validate name
            if name.contains(';') || name.contains('&') || name.contains('|') || name.contains('`') {
                return Err("Invalid container name".to_string());
            }
            match runtime.to_lowercase().as_str() {
                "docker" => {
                    run_command("docker", &["restart", name], 120).await.map(plain_output)
                }
                "lxc" => {
                    let stop_result = run_command("lxc-stop", &["-n", name], 60).await;
                    if let Err(e) = &stop_result
                        && !e.contains("not running") {
                            warn!("WolfFlow: lxc-stop failed for {}: {}", name, e);
                        }
                    run_command("lxc-start", &["-n", name], 60).await.map(plain_output)
                }
                _ => Err(format!("Unknown runtime: {}", runtime)),
            }
        }

        ActionType::DockerPrune => {
            run_command("docker", &["system", "prune", "-af"], 300).await.map(plain_output)
        }

        // ─── Docker Update Check ───
        ActionType::DockerCheckUpdate { container_or_image } => {
            if container_or_image.contains(';') || container_or_image.contains('&') || container_or_image.contains('|') || container_or_image.contains('`') {
                return Err("Invalid container/image name".to_string());
            }
            // Get the image reference from the container
            let image = {
                let inspect = run_command("docker", &["inspect", "--format", "{{.Config.Image}}", container_or_image], 10).await;
                match inspect {
                    Ok(img) => img.trim().to_string(),
                    Err(_) => container_or_image.clone(), // Assume it's an image reference
                }
            };
            let local = run_command("docker", &["image", "inspect", "--format", "{{index .RepoDigests 0}}", &image], 10).await
                .unwrap_or_default().trim().to_string();
            if local.is_empty() {
                return Err(format!("Image '{}' has no repo digest — locally built images cannot be checked", image));
            }
            // Parse local digest
            let local_digest = local.split('@').nth(1).unwrap_or(&local).to_string();
            let mut data = serde_json::Map::new();
            data.insert("image".to_string(), serde_json::json!(image));
            data.insert("local_digest".to_string(), serde_json::json!(local_digest));
            data.insert("update_available".to_string(), serde_json::json!(false));
            data.insert("container".to_string(), serde_json::json!(container_or_image));
            Ok(structured_output(
                format!("Local digest for {}: {}", image, local_digest),
                data,
            ))
        }

        // ─── Docker Update ───
        ActionType::DockerUpdate { container_name, backup_first } => {
            if container_name.contains(';') || container_name.contains('&') || container_name.contains('|') {
                return Err("Invalid container name".to_string());
            }
            // Get current image
            let image = run_command("docker", &["inspect", "--format", "{{.Config.Image}}", container_name], 10).await
                .map_err(|e| format!("Container '{}' not found: {}", container_name, e))?
                .trim().to_string();

            if *backup_first {
                info!("WolfFlow: backing up container '{}' before update", container_name);
                let _ = run_command("docker", &["commit", container_name, &format!("{}_backup", container_name)], 120).await;
            }

            // Pull latest
            run_command("docker", &["pull", &image], 600).await
                .map_err(|e| format!("Pull failed: {}", e))?;

            // Restart to pick up new image (simple approach — full recreate is in image_watcher)
            run_command("docker", &["restart", container_name], 120).await
                .map_err(|e| format!("Restart failed after pull: {}", e))?;

            let mut data = serde_json::Map::new();
            data.insert("success".to_string(), serde_json::json!(true));
            data.insert("container".to_string(), serde_json::json!(container_name));
            data.insert("image".to_string(), serde_json::json!(image));
            Ok(structured_output(
                format!("Updated container '{}' with latest image '{}'", container_name, image),
                data,
            ))
        }

        // ─── Docker Multi-container Update Check ───
        //
        // Drives the full image_watcher check pipeline (registry HEAD
        // + digest compare) for every running container or a selected
        // subset. Containers with passive policies (Ignore / Pinned)
        // are skipped inside `check_all_containers`.
        ActionType::DockerCheckUpdateMany { target, container_names } => {
            use crate::containers::image_watcher as iw;
            let config = iw::ImageWatcherConfig::load();
            let results = if target == "all" {
                iw::check_all_containers(&config).await
            } else {
                let mut out = Vec::new();
                for name in container_names {
                    if name.is_empty() { continue; }
                    if name.contains(';') || name.contains('&') || name.contains('|') || name.contains('`') {
                        return Err(format!("Invalid container name: {}", name));
                    }
                    // Honour passive policies the same way the bulk
                    // path does — skip with no remote query.
                    if config.policy_for(name).is_passive() { continue; }
                    match iw::check_container_update(name).await {
                        Ok(r) => out.push(r),
                        Err(e) => out.push(iw::ImageCheckResult {
                            container_name: name.clone(),
                            image: String::new(),
                            local_digest: String::new(),
                            remote_digest: None,
                            update_available: false,
                            last_checked: chrono::Utc::now().to_rfc3339(),
                            error: Some(e),
                        }),
                    }
                }
                out
            };
            let updates_available = results.iter().filter(|r| r.update_available).count();
            let mut data = serde_json::Map::new();
            data.insert("results".to_string(), serde_json::to_value(&results).unwrap_or(serde_json::Value::Null));
            data.insert("checked".to_string(), serde_json::json!(results.len()));
            data.insert("updates_available".to_string(), serde_json::json!(updates_available));
            Ok(structured_output(
                format!("Checked {} container(s); {} update(s) available", results.len(), updates_available),
                data,
            ))
        }

        // ─── Docker Multi-container Update ───
        //
        // Operator-triggered bulk update via the image_watcher pipeline
        // (full recreate-from-inspect, optional pre-backup, health-check,
        // optional rollback). Honours `max_parallel_updates` from the
        // watcher config so a host with many containers doesn't get
        // crushed by N concurrent docker pulls. Each container's
        // policy is consulted: passive (Ignore / Pinned) is skipped
        // with an explicit "skipped" event so the run log shows why.
        ActionType::DockerUpdateMany { target, container_names } => {
            use crate::containers::image_watcher as iw;
            let config = iw::ImageWatcherConfig::load();
            // Resolve target list.
            let names: Vec<String> = if target == "all" {
                let out = run_command("docker", &["ps", "--format", "{{.Names}}"], 30).await
                    .map_err(|e| format!("docker ps failed: {}", e))?;
                out.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
            } else {
                for name in container_names.iter() {
                    if name.contains(';') || name.contains('&') || name.contains('|') || name.contains('`') {
                        return Err(format!("Invalid container name: {}", name));
                    }
                }
                container_names.clone()
            };
            let max_parallel = config.max_parallel_updates.max(1);
            let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(max_parallel));
            let mut handles = Vec::new();
            for name in names {
                let policy = config.policy_for(&name);
                if policy.is_passive() {
                    let name_for_skip = name.clone();
                    let policy_str = format!("{:?}", policy.policy);
                    handles.push(tokio::spawn(async move {
                        Ok(iw::ImageUpdateEvent {
                            id: format!("evt-skip-{}", uuid::Uuid::new_v4().simple()),
                            container_name: name_for_skip,
                            image: String::new(),
                            old_digest: String::new(),
                            new_digest: String::new(),
                            backup_id: None,
                            status: iw::ImageUpdateStatus::Failed,
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            error: Some(format!("policy is {} — skipped", policy_str)),
                        })
                    }));
                    continue;
                }
                let sem = sem.clone();
                let cfg = config.clone();
                // Preserve the container name in the outer scope so a
                // join failure can be recorded against the right
                // container in the audit history.
                let fallback_name = name.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = sem.acquire_owned().await.expect("semaphore closed");
                    // Err(name) = that container is already being updated
                    // (operator "Update now" or the auto-apply loop). Not a
                    // failure and not history: reported in the run output.
                    tokio::task::spawn_blocking(move || {
                        iw::perform_update_blocking(&name, &cfg).ok_or(name)
                    }).await.unwrap_or_else(|join_err| Ok(iw::ImageUpdateEvent {
                        id: format!("evt-join-{}", chrono::Utc::now().timestamp()),
                        container_name: fallback_name,
                        image: String::new(),
                        old_digest: String::new(),
                        new_digest: String::new(),
                        backup_id: None,
                        status: iw::ImageUpdateStatus::Failed,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        error: Some(format!("worker join failed: {}", join_err)),
                    }))
                }));
            }
            let mut events: Vec<iw::ImageUpdateEvent> = Vec::with_capacity(handles.len());
            let mut already_updating: Vec<String> = Vec::new();
            for h in handles {
                match h.await {
                    Ok(Ok(ev)) => events.push(ev),
                    Ok(Err(name)) => already_updating.push(name),
                    Err(_) => {}
                }
            }
            // Persist to audit history.
            if let Err(e) = iw::append_history(events.clone()) {
                tracing::warn!("wolfflow: failed to persist image update history: {}", e);
            }
            let success_count = events.iter()
                .filter(|e| matches!(e.status, iw::ImageUpdateStatus::Completed))
                .count();
            let mut data = serde_json::Map::new();
            data.insert("events".to_string(), serde_json::to_value(&events).unwrap_or(serde_json::Value::Null));
            data.insert("total".to_string(), serde_json::json!(events.len()));
            data.insert("succeeded".to_string(), serde_json::json!(success_count));
            data.insert("failed".to_string(), serde_json::json!(events.len() - success_count));
            let mut summary = format!("Updated {}/{} container(s) successfully", success_count, events.len());
            if !already_updating.is_empty() {
                summary.push_str(&format!(
                    "; skipped {} already being updated: {}",
                    already_updating.len(), already_updating.join(", "),
                ));
            }
            data.insert("already_updating".to_string(), serde_json::json!(already_updating));
            Ok(structured_output(summary, data))
        }

        // ─── Backup ───
        ActionType::RunBackupSchedule { schedule_id } => {
            let id = schedule_id.trim().to_string();
            if id.is_empty() {
                return Err("No backup schedule selected".to_string());
            }
            // run_schedule_now_summary is fully blocking (tars containers,
            // uploads to storage) — never run it on the async runtime.
            let summary = tokio::task::spawn_blocking(move || {
                crate::backup::run_schedule_now_summary(&id)
            })
            .await
            .map_err(|e| format!("backup schedule worker failed: {}", e))??;

            let mut data = serde_json::Map::new();
            data.insert("schedule".to_string(), serde_json::json!(summary.name));
            data.insert("total".to_string(), serde_json::json!(summary.total));
            data.insert("completed".to_string(), serde_json::json!(summary.completed));
            data.insert("failed".to_string(), serde_json::json!(summary.failed));
            if summary.failed > 0 {
                // Strict: a flow gated on "backup first" must not proceed to
                // its update/destructive steps on a partial backup.
                return Err(format!(
                    "{} — {} of {} backup(s) failed",
                    summary.message, summary.failed, summary.total
                ));
            }
            Ok(structured_output(summary.message, data))
        }

        // ─── Generic HTTP Request ───
        ActionType::HttpRequest { method, url, headers, body, auth, timeout_secs, fail_on_error, verify_tls } => {
            // Route to the right shared pool based on the user's
            // `verify_tls` toggle. Timeout goes on the RequestBuilder
            // below so both pools can serve every timeout value.
            let client: &reqwest::Client = if *verify_tls {
                &WOLFFLOW_CLIENT_STRICT
            } else {
                &WOLFFLOW_CLIENT_INSECURE
            };

            let req_method = match method.to_uppercase().as_str() {
                "GET" => reqwest::Method::GET,
                "POST" => reqwest::Method::POST,
                "PUT" => reqwest::Method::PUT,
                "DELETE" => reqwest::Method::DELETE,
                "PATCH" => reqwest::Method::PATCH,
                "HEAD" => reqwest::Method::HEAD,
                _ => return Err(format!("Unsupported HTTP method: {}", method)),
            };

            let mut req = client.request(req_method, url)
                .timeout(std::time::Duration::from_secs(*timeout_secs));

            // Apply auth
            if let Some(a) = auth {
                req = match a {
                    HttpAuth::Bearer { token } => req.header("Authorization", format!("Bearer {}", token)),
                    HttpAuth::Basic { username, password } => req.basic_auth(username, Some(password)),
                    HttpAuth::ApiKey { header_name, key } => req.header(header_name.as_str(), key.as_str()),
                };
            }

            // Apply custom headers
            for h in headers {
                req = req.header(h.name.as_str(), h.value.as_str());
            }

            // Apply body
            if let Some(b) = body {
                req = req.header("Content-Type", "application/json").body(b.clone());
            }

            let resp = req.send().await.map_err(|e| format!("HTTP request failed: {}", e))?;
            let status = resp.status().as_u16();
            let resp_body = resp.text().await.unwrap_or_default();

            if *fail_on_error && status >= 400 {
                return Err(format!("HTTP {} — {}", status, resp_body.chars().take(2000).collect::<String>()));
            }

            let mut data = serde_json::Map::new();
            data.insert("status_code".to_string(), serde_json::json!(status));
            data.insert("response_body".to_string(), serde_json::json!(resp_body.chars().take(5000).collect::<String>()));
            // Try to parse response as JSON for structured access
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&resp_body) {
                data.insert("json".to_string(), parsed);
            }
            Ok(structured_output(
                format!("HTTP {} — {} bytes", status, resp_body.len()),
                data,
            ))
        }

        // ─── Condition — returns structured result for branching ───
        ActionType::Condition { expression, compare_to, operator } => {
            // When called standalone (not from execute_workflow), context is empty.
            // The real evaluation with context happens in the execution engine.
            let mut data = serde_json::Map::new();
            data.insert("result".to_string(), serde_json::json!(false));
            data.insert("expression".to_string(), serde_json::json!(expression));
            data.insert("operator".to_string(), serde_json::json!(operator));
            data.insert("compare_to".to_string(), serde_json::json!(compare_to));
            Ok(structured_output(
                format!("Condition: '{}' {} '{}' (context required for evaluation)", expression, operator, compare_to),
                data,
            ))
        }

        // ─── Service-Specific HTTP wrappers ───
        ActionType::NetBirdAction { api_url, api_token, endpoint, method, body } => {
            let url = format!("{}{}", api_url.trim_end_matches('/'), endpoint);
            // NetBird uses "Token <key>" not "Bearer <key>" in the Authorization header
            let wrapped = ActionType::HttpRequest {
                method: method.clone(),
                url,
                headers: vec![HttpHeader { name: "Authorization".to_string(), value: format!("Token {}", api_token) }],
                body: body.clone(),
                auth: None,
                timeout_secs: 30,
                fail_on_error: true,
                verify_tls: false,
            };
            // Use Box::pin to avoid recursion-without-boxing error
            Box::pin(execute_action_local(&wrapped)).await
        }

        ActionType::TrueNasAction { api_url, api_key, endpoint, method, body } => {
            let url = format!("{}{}", api_url.trim_end_matches('/'), endpoint);
            let wrapped = ActionType::HttpRequest {
                method: method.clone(),
                url,
                headers: vec![],
                body: body.clone(),
                auth: Some(HttpAuth::Bearer { token: api_key.clone() }),
                timeout_secs: 30,
                fail_on_error: true,
                verify_tls: false,
            };
            Box::pin(execute_action_local(&wrapped)).await
        }

        ActionType::UnifiAction { api_url, username, password, endpoint, method, body: body_str } => {
            // Unifi requires cookie-based login. We use a jar to manage session cookies.
            let jar = std::sync::Arc::new(reqwest::cookie::Jar::default());
            let client = crate::api::ipv4_only_client_builder()
                .timeout(std::time::Duration::from_secs(30))
                .danger_accept_invalid_certs(true)
                .cookie_provider(jar)
                .build()
                .map_err(|e| format!("HTTP client error: {}", e))?;

            // Login to get session cookie
            let login_url = format!("{}/api/login", api_url.trim_end_matches('/'));
            let login_body = serde_json::json!({ "username": username, "password": password });
            let login_resp = client.post(&login_url)
                .json(&login_body)
                .send().await
                .map_err(|e| format!("Unifi login failed: {}", e))?;
            let login_status = login_resp.status();
            // Drain the login response body so the socket returns to
            // the keep-alive pool — cookies were already parsed into
            // the jar during send(), so we don't need to inspect the
            // body content itself.
            let _ = login_resp.bytes().await;
            if !login_status.is_success() {
                return Err(format!("Unifi login failed: HTTP {}", login_status));
            }

            // Execute the actual request (session cookies are sent automatically)
            let url = format!("{}{}", api_url.trim_end_matches('/'), endpoint);
            let req_method = match method.to_uppercase().as_str() {
                "POST" => reqwest::Method::POST,
                "PUT" => reqwest::Method::PUT,
                "DELETE" => reqwest::Method::DELETE,
                _ => reqwest::Method::GET,
            };
            let mut req = client.request(req_method, &url);
            if let Some(b) = body_str {
                req = req.header("Content-Type", "application/json").body(b.clone());
            }
            let resp = req.send().await.map_err(|e| format!("Unifi request failed: {}", e))?;
            let status = resp.status().as_u16();
            let resp_body = resp.text().await.unwrap_or_default();

            if status >= 400 {
                return Err(format!("Unifi HTTP {} — {}", status, resp_body.chars().take(2000).collect::<String>()));
            }
            let mut data = serde_json::Map::new();
            data.insert("status_code".to_string(), serde_json::json!(status));
            data.insert("response_body".to_string(), serde_json::json!(resp_body.chars().take(5000).collect::<String>()));
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&resp_body) {
                data.insert("json".to_string(), parsed);
            }
            Ok(structured_output(format!("Unifi HTTP {}", status), data))
        }

        // ─── Integration Framework action ───
        ActionType::IntegrationAction { instance_id, operation, params: _params } => {
            let mut data = serde_json::Map::new();
            data.insert("instance_id".to_string(), serde_json::json!(instance_id));
            data.insert("operation".to_string(), serde_json::json!(operation));
            Ok(structured_output(
                format!("Integration action: instance={}, operation={}", instance_id, operation),
                data,
            ))
        }

        // ─── AI invocation (no per-agent context, no tools) ───
        ActionType::AiInvoke { prompt, system_prompt, model, provider, max_tokens: _max_tokens } => {
            // Clone and override provider/model on the effective config
            // so workflows can ask a cheaper/faster model for routine
            // summaries without editing global AI settings.
            let mut cfg = crate::ai::AiConfig::load();
            if let Some(p) = provider { cfg.provider = p.clone(); }
            if let Some(m) = model { cfg.model = m.clone(); }
            let sys = system_prompt.clone().unwrap_or_else(|| {
                "You are an operations assistant inside a WolfFlow workflow. Answer concisely. \
                 Output plain text — no JSON, no markdown formatting unless explicitly asked. \
                 If the answer is yes/no, start with 'YES' or 'NO' on its own line so a downstream \
                 Condition step can branch on it.".to_string()
            });
            // `max_tokens` is captured here for future use when
            // simple_chat gains a token cap; Claude/Gemini currently
            // cap at 4096 internally. Kept in the schema so workflows
            // authored now keep working when we wire it through.
            match crate::ai::simple_chat(&cfg, &sys, &[], prompt).await {
                Ok(reply) => {
                    let mut data = serde_json::Map::new();
                    data.insert("response".to_string(), serde_json::json!(reply));
                    data.insert("model".to_string(), serde_json::json!(cfg.model));
                    data.insert("provider".to_string(), serde_json::json!(cfg.provider));
                    Ok(structured_output(reply, data))
                }
                Err(e) => Err(format!("AiInvoke failed: {}", e)),
            }
        }

        // ─── Per-agent persistent chat ───
        ActionType::AgentChat { agent_id, message, timeout_secs } => {
            let deadline = std::time::Duration::from_secs(*timeout_secs);
            let agent_id_c = agent_id.clone();
            let message_c = message.clone();
            match tokio::time::timeout(deadline,
                crate::wolfagents::chat_with_agent(&agent_id_c, &message_c)
            ).await {
                Ok(Ok(reply)) => {
                    let mut data = serde_json::Map::new();
                    data.insert("agent_id".to_string(), serde_json::json!(agent_id));
                    data.insert("response".to_string(), serde_json::json!(reply));
                    Ok(structured_output(reply, data))
                }
                Ok(Err(e)) => Err(format!("AgentChat failed: {}", e)),
                Err(_) => Err(format!("AgentChat timed out after {}s", timeout_secs)),
            }
        }

        // ─── SQL query + email ─────────────────────────────
        ActionType::SqlQuery { connection_id, query, permission, timeout_secs, fail_on_empty } => {
            // Cluster secret is needed to decrypt the stored password
            // when the pool is (re)built. We look it up from the
            // running state — same source the API handlers use.
            let cluster_secret = crate::auth::load_cluster_secret();
            let perm: crate::sql_connections::SqlPermission = (*permission).into();
            let workflow_id = "workflow".to_string();  // execute_action_local doesn't
                                                      // have workflow context; callers
                                                      // that need full audit path use
                                                      // execute_workflow which threads
                                                      // the id through the spawned task.
            let res = crate::sql_connections::execute(
                connection_id, query, perm,
                crate::sql_connections::Caller::Workflow {
                    workflow_id, step: "sql_query".into(),
                },
                &cluster_secret,
                Some(std::time::Duration::from_secs(*timeout_secs)),
                // execute_action_local has no ClusterState handle; remote-node
                // profiles will refuse with a clear error. Workflows that
                // need cross-node SQL should pin node_id = self and let
                // execute() short-circuit to local.
                None,
            ).await;
            match res {
                Ok(r) => {
                    if *fail_on_empty && r.row_count == 0 && r.affected_rows.unwrap_or(0) == 0 {
                        return Err("SqlQuery returned no rows and fail_on_empty is set".into());
                    }
                    let mut data = serde_json::Map::new();
                    data.insert("columns".into(), serde_json::json!(r.columns));
                    data.insert("rows".into(), serde_json::json!(r.rows));
                    data.insert("row_count".into(), serde_json::json!(r.row_count));
                    data.insert("affected_rows".into(), serde_json::json!(r.affected_rows));
                    data.insert("elapsed_ms".into(), serde_json::json!(r.elapsed_ms));
                    data.insert("truncated".into(), serde_json::json!(r.truncated));
                    // Pre-formatted renderings for downstream email / logs —
                    // saves every template author from writing their own
                    // loop over rows.
                    data.insert("rows_csv".into(), serde_json::json!(render_rows_csv(&r.columns, &r.rows)));
                    data.insert("rows_markdown".into(), serde_json::json!(render_rows_markdown(&r.columns, &r.rows)));
                    let summary = format!(
                        "{:?} on '{}': {} rows{}{}",
                        permission, connection_id, r.row_count,
                        r.affected_rows.map(|a| format!(" (affected {})", a)).unwrap_or_default(),
                        if r.truncated { " (truncated)" } else { "" },
                    );
                    Ok(structured_output(summary, data))
                }
                Err(e) => Err(format!("SqlQuery failed: {}", e)),
            }
        }

        ActionType::SendEmail { to, subject, body, html } => {
            let cfg = crate::ai::AiConfig::load();
            if cfg.smtp_host.is_empty() {
                return Err("SendEmail: SMTP not configured — Settings → AI Agent → Email".into());
            }
            if to.is_empty() {
                return Err("SendEmail: `to` is empty".into());
            }
            match crate::wolfagents::dispatch::send_email_generic(
                &cfg, to, subject, body, *html,
            ) {
                Ok(()) => {
                    let mut data = serde_json::Map::new();
                    data.insert("to".into(), serde_json::json!(to));
                    data.insert("subject".into(), serde_json::json!(subject));
                    Ok(structured_output(
                        format!("Emailed {} recipient(s): {}", to.len(), subject),
                        data,
                    ))
                }
                Err(e) => Err(format!("SendEmail failed: {}", e)),
            }
        }
    }
}

/// Turn `{columns, rows}` into a CSV string. Quoting follows RFC 4180:
/// values containing commas, quotes, or newlines get wrapped in
/// double-quotes with internal quotes doubled. Null = empty field.
fn render_rows_csv(columns: &[String], rows: &[Vec<serde_json::Value>]) -> String {
    fn esc(s: &str) -> String {
        if s.contains(',') || s.contains('"') || s.contains('\n') {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }
    let mut out = String::new();
    out.push_str(&columns.iter().map(|c| esc(c)).collect::<Vec<_>>().join(","));
    out.push('\n');
    for row in rows {
        let cells: Vec<String> = row.iter().map(|v| {
            match v {
                serde_json::Value::Null => String::new(),
                serde_json::Value::String(s) => esc(s),
                other => esc(&other.to_string()),
            }
        }).collect();
        out.push_str(&cells.join(","));
        out.push('\n');
    }
    out
}

/// Turn `{columns, rows}` into a GitHub-flavoured Markdown table.
/// First ~50 rows only so a huge result doesn't bloat an email body —
/// CSV rendering at full fidelity is available alongside.
fn render_rows_markdown(columns: &[String], rows: &[Vec<serde_json::Value>]) -> String {
    let mut out = String::new();
    out.push('|');
    for c in columns { out.push_str(&format!(" {} |", c)); }
    out.push('\n');
    out.push('|');
    for _ in columns { out.push_str(" --- |"); }
    out.push('\n');
    for row in rows.iter().take(50) {
        out.push('|');
        for v in row {
            let s = match v {
                serde_json::Value::Null => String::new(),
                serde_json::Value::String(s) => s.replace('|', "\\|").replace('\n', " "),
                other => other.to_string(),
            };
            out.push_str(&format!(" {} |", s));
        }
        out.push('\n');
    }
    if rows.len() > 50 {
        out.push_str(&format!("_…{} more rows (CSV attachment has the full set)_\n", rows.len() - 50));
    }
    out
}

/// Run a command with a timeout, capturing stdout+stderr
async fn run_command(cmd: &str, args: &[&str], timeout_secs: u64) -> Result<String, String> {
    use tokio::process::Command;

    // Use timeout wrapper — kill_on_drop ensures process is cleaned up
    let child = Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("Failed to spawn '{}': {}", cmd, e))?;

    let result = match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        child.wait_with_output(),
    ).await {
        Ok(r) => r,
        Err(_) => return Err(format!("Command '{}' timed out after {}s", cmd, timeout_secs)),
    };

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() {
                stdout
            } else if stdout.is_empty() {
                stderr
            } else {
                format!("{}\n{}", stdout, stderr)
            };

            if output.status.success() {
                Ok(combined)
            } else {
                Err(format!(
                    "Command exited with code {}: {}",
                    output.status.code().unwrap_or(-1),
                    combined.chars().take(2000).collect::<String>()
                ))
            }
        }
        Err(e) => Err(format!("Failed to execute command: {}", e)),
    }
}

// ─── Container/VM Command Execution ───

/// Execute a command inside a Docker container
pub async fn exec_in_docker(container_name: &str, command: &str, timeout_secs: u64) -> Result<String, String> {
    run_command("docker", &["exec", container_name, "sh", "-c", command], timeout_secs).await
}

/// Execute a command inside an LXC container
pub async fn exec_in_lxc(container_name: &str, command: &str, timeout_secs: u64) -> Result<String, String> {
    run_command("lxc-attach", &["-n", container_name, "--", "sh", "-c", command], timeout_secs).await
}

/// Execute a command inside a VM via SSH (best-effort).
/// VMs are reached via their WolfNet IP or MAC-derived IP.
pub async fn exec_in_vm(vm_name: &str, command: &str, timeout_secs: u64) -> Result<String, String> {
    // Try to find the VM's IP from the local VM manager
    let vms = crate::vms::manager::VmManager::new().list_vms();
    let vm = vms.iter().find(|v| v.name == vm_name);

    // Try WolfNet IP first, then fall back to MAC-based ARP lookup
    let ip = vm.and_then(|v| v.wolfnet_ip.clone()).filter(|ip| !ip.is_empty());

    let ip = match ip {
        Some(ip) => ip,
        None => {
            // Try to find IP via ARP table using MAC address
            if let Some(mac) = vm.and_then(|v| v.mac_address.clone()) {
                // Validate MAC format to prevent injection (must be XX:XX:XX:XX:XX:XX)
                if !mac.chars().all(|c| c.is_ascii_hexdigit() || c == ':') || mac.len() != 17 {
                    return Err(format!("Cannot execute in VM '{}': invalid MAC address format.", vm_name));
                }
                let arp_output = run_command("grep", &["-i", &mac, "/proc/net/arp"], 5).await;
                match arp_output {
                    Ok(line) if !line.trim().is_empty() => {
                        // ARP table format: IP HWtype Flags HWaddress Mask Iface
                        let ip_str = line.split_whitespace().next().unwrap_or("");
                        // Validate as IPv4
                        if ip_str.parse::<std::net::Ipv4Addr>().is_ok() {
                            ip_str.to_string()
                        } else {
                            return Err(format!("Cannot execute in VM '{}': ARP lookup returned invalid IP.", vm_name));
                        }
                    }
                    _ => return Err(format!("Cannot execute in VM '{}': no IP address found. Ensure the VM has a network connection.", vm_name)),
                }
            } else {
                return Err(format!("Cannot execute in VM '{}': no MAC or IP address found.", vm_name));
            }
        }
    };

    // Validate IP before using in SSH command
    if ip.parse::<std::net::Ipv4Addr>().is_err() && ip.parse::<std::net::Ipv6Addr>().is_err() {
        return Err(format!("Cannot execute in VM '{}': invalid IP address '{}'", vm_name, ip));
    }

    // SSH with common options: no host key check, short timeout, try root first
    run_command("ssh", &[
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=5",
        "-o", "BatchMode=yes",
        &format!("root@{}", ip),
        "sh", "-c", command,
    ], timeout_secs).await
}

/// Shell-quote a string for safe embedding in an SSH command
#[allow(dead_code)]
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Validate a service name against shell metacharacters
fn validate_service_name(name: &str) -> Result<(), String> {
    if name.contains(';') || name.contains('&') || name.contains('|')
        || name.contains('`') || name.contains('$') || name.contains(' ')
    {
        Err("Invalid service name".to_string())
    } else {
        Ok(())
    }
}

/// Execute an action inside a specific container/VM on the local node.
/// Wraps RunCommand to execute inside the target; other actions run on the host.
pub async fn execute_action_in_container(
    action: &ActionType,
    ct: &ContainerTarget,
) -> Result<StepOutput, String> {
    // For RunCommand, execute inside the container
    if let ActionType::RunCommand { command, timeout_secs } = action {
        let result = match ct.runtime.as_str() {
            "docker" => exec_in_docker(&ct.name, command, *timeout_secs).await,
            "lxc" => exec_in_lxc(&ct.name, command, *timeout_secs).await,
            "vm" => exec_in_vm(&ct.name, command, *timeout_secs).await,
            _ => Err(format!("Unknown runtime: {}", ct.runtime)),
        };
        return result.map(plain_output);
    }

    // For RestartContainer targeting a specific container, just restart it
    if let ActionType::RestartContainer { .. } = action {
        let restart_action = ActionType::RestartContainer {
            runtime: ct.runtime.clone(),
            name: ct.name.clone(),
        };
        return execute_action_local(&restart_action).await;
    }

    // For DockerPrune targeting a docker container — run docker system prune in context
    if let ActionType::DockerPrune = action
        && ct.runtime == "docker" {
            // Prune unused resources on the host (not inside the container)
            return execute_action_local(action).await;
        }

    // For other actions that don't make sense inside a container, run on the host
    // (UpdatePackages inside a container, CleanLogs, etc.)
    match ct.runtime.as_str() {
        "docker" => {
            // Wrap package updates etc. to run inside docker
            let cmd = match action {
                ActionType::UpdatePackages => Some("apt-get update -y && apt-get upgrade -y 2>/dev/null || dnf upgrade -y 2>/dev/null || true".to_string()),
                ActionType::CleanLogs { .. } => Some("find /var/log -type f -name '*.log' -mtime +7 -delete 2>/dev/null; echo 'Logs cleaned'".to_string()),
                ActionType::CheckDiskSpace { .. } => Some("df -h".to_string()),
                _ => None,
            };
            if let Some(cmd) = cmd {
                return exec_in_docker(&ct.name, &cmd, 300).await.map(plain_output);
            }
        }
        "lxc" => {
            let cmd = match action {
                ActionType::UpdatePackages => Some("apt-get update -y && apt-get upgrade -y 2>/dev/null || dnf upgrade -y 2>/dev/null || true".to_string()),
                ActionType::CleanLogs { max_size_mb } => {
                    let size = max_size_mb.unwrap_or(500);
                    Some(format!("journalctl --vacuum-size={}M 2>/dev/null || find /var/log -type f -name '*.log' -mtime +7 -delete; echo 'Logs cleaned'", size))
                }
                ActionType::CheckDiskSpace { .. } => Some("df -h".to_string()),
                ActionType::RestartService { service_name } => {
                    validate_service_name(service_name)?;
                    Some(format!("systemctl restart {}", service_name))
                }
                _ => None,
            };
            if let Some(cmd) = cmd {
                return exec_in_lxc(&ct.name, &cmd, 300).await.map(plain_output);
            }
        }
        "vm" => {
            let cmd = match action {
                ActionType::UpdatePackages => Some("apt-get update -y && apt-get upgrade -y 2>/dev/null || dnf upgrade -y 2>/dev/null || true".to_string()),
                ActionType::CleanLogs { max_size_mb } => {
                    let size = max_size_mb.unwrap_or(500);
                    Some(format!("journalctl --vacuum-size={}M 2>/dev/null || echo 'no journalctl'", size))
                }
                ActionType::CheckDiskSpace { .. } => Some("df -h".to_string()),
                ActionType::RestartService { service_name } => {
                    validate_service_name(service_name)?;
                    Some(format!("systemctl restart {}", service_name))
                }
                _ => None,
            };
            if let Some(cmd) = cmd {
                return exec_in_vm(&ct.name, &cmd, 300).await.map(plain_output);
            }
        }
        _ => {}
    }

    // Fallback: action doesn't apply to containers — run on host
    execute_action_local(action).await
}

// ═══════════════════════════════════════════════
// ─── Workflow Execution ───
// ═══════════════════════════════════════════════

/// Resolve target nodes for execution.
/// Returns Vec<(node_id, node_hostname, node_address, node_port, is_self)>.
fn resolve_targets(
    cluster: &ClusterState,
    target: &Target,
) -> Vec<(String, String, String, u16, bool)> {
    let nodes = cluster.get_all_nodes();

    match target {
        Target::Local => {
            // Only the self node
            nodes.iter()
                .filter(|n| n.is_self)
                .map(|n| (n.id.clone(), n.hostname.clone(), n.address.clone(), n.port, true))
                .collect()
        }
        Target::AllNodes => {
            nodes.iter()
                .filter(|n| n.online && n.node_type == "wolfstack")
                .map(|n| (n.id.clone(), n.hostname.clone(), n.address.clone(), n.port, n.is_self))
                .collect()
        }
        Target::Cluster { cluster_name } => {
            nodes.iter()
                .filter(|n| {
                    n.online
                        && n.node_type == "wolfstack"
                        && n.cluster_name.as_deref().unwrap_or("WolfStack") == cluster_name.as_str()
                })
                .map(|n| (n.id.clone(), n.hostname.clone(), n.address.clone(), n.port, n.is_self))
                .collect()
        }
        Target::Nodes { node_ids } => {
            nodes.iter()
                .filter(|n| n.online && node_ids.contains(&n.id))
                .map(|n| (n.id.clone(), n.hostname.clone(), n.address.clone(), n.port, n.is_self))
                .collect()
        }
        Target::Containers { targets } => {
            // For container targets, resolve to the nodes that host them
            // The container-specific execution is handled in execute_workflow
            let mut result = Vec::new();
            let mut seen_nodes = std::collections::HashSet::new();
            for ct in targets {
                if seen_nodes.contains(&ct.node_id) { continue; }
                if let Some(n) = nodes.iter().find(|n| n.id == ct.node_id && n.online) {
                    result.push((n.id.clone(), n.hostname.clone(), n.address.clone(), n.port, n.is_self));
                    seen_nodes.insert(ct.node_id.clone());
                }
            }
            result
        }
        Target::Everything => {
            // All online WolfStack nodes — container execution is handled in the workflow runner
            nodes.iter()
                .filter(|n| n.online && n.node_type == "wolfstack")
                .map(|n| (n.id.clone(), n.hostname.clone(), n.address.clone(), n.port, n.is_self))
                .collect()
        }
    }
}

/// Execute a workflow across target nodes.
///
/// Steps are executed sequentially. For each step, all target nodes are
/// executed (in parallel per node), then results are collected before
/// moving to the next step.
pub async fn execute_workflow(
    state: &Arc<WolfFlowState>,
    cluster: &Arc<ClusterState>,
    cluster_secret: &str,
    // Who this run acts for — the operator who pressed Run, or a fixed
    // "wolfflow-scheduler" / "wolfagent" label for unattended triggers.
    // Sent to peer nodes as `X-WolfStack-Actor` so their exec endpoints
    // (`require_operator_auth`) accept the step; must never be "cluster-node".
    actor: &str,
    workflow: &Workflow,
    trigger: &str,
    ai_config: Option<crate::ai::AiConfig>,
) -> WorkflowRun {
    let run_id = format!("run-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let started_at = Utc::now().to_rfc3339();

    let mut run = WorkflowRun {
        id: run_id.clone(),
        workflow_id: workflow.id.clone(),
        workflow_name: workflow.name.clone(),
        status: RunStatus::Running,
        trigger: trigger.to_string(),
        steps: Vec::new(),
        started_at: started_at.clone(),
        finished_at: None,
        duration_ms: 0,
        email_status: None,
    };

    // Persist initial run state
    state.add_run(run.clone());

    info!("WolfFlow: starting workflow '{}' ({}), trigger: {}", workflow.name, workflow.id, trigger);

    let run_start = std::time::Instant::now();
    let mut had_failure = false;
    let mut aborted = false;

    // Shared pool for remote step execution — see
    // WOLFFLOW_CLIENT_INSECURE. Per-workflow-run Client construction
    // was leaking a pool every time a scheduled workflow fired. We
    // wrap in Some() so the downstream `.clone()` sites keep their
    // existing shape.
    let http_client: Option<reqwest::Client> = Some(reqwest::Client::clone(&WOLFFLOW_CLIENT_INSECURE));

    // Index-based execution loop with branching, context passing, and retry
    let mut step_idx: usize = 0;
    let mut context = WorkflowContext::default();
    let max_runtime = if workflow.max_runtime_secs > 0 { Some(std::time::Duration::from_secs(workflow.max_runtime_secs)) } else { None };

    while step_idx < workflow.steps.len() && !aborted {
        // Check max runtime
        if let Some(max) = max_runtime
            && run_start.elapsed() > max {
                error!("WolfFlow: workflow '{}' exceeded max runtime of {}s — aborting", workflow.name, workflow.max_runtime_secs);
                aborted = true;
                break;
            }

        let step = &workflow.steps[step_idx];

        // For Condition actions, evaluate with context and branch
        if let ActionType::Condition { ref expression, ref compare_to, ref operator } = step.action {
            let result = evaluate_condition(expression, compare_to, operator, &context);
            let mut data = serde_json::Map::new();
            data.insert("result".to_string(), serde_json::json!(result));
            data.insert("expression_resolved".to_string(), serde_json::json!(resolve_templates(expression, &context)));
            context.step_outputs.insert(step.name.clone(), StepOutput {
                text: format!("Condition: {} → {}", expression, result),
                data,
            });
            run.steps.push(StepResult {
                step_name: step.name.clone(),
                node_id: "local".to_string(),
                node_hostname: "local".to_string(),
                status: RunStatus::Completed,
                output: format!("Condition '{}' {} '{}' → {}", resolve_templates(expression, &context), operator, compare_to, result),
                started_at: Utc::now().to_rfc3339(),
                finished_at: Utc::now().to_rfc3339(),
                duration_ms: 0,
            });
            // Branch based on result
            step_idx = if result {
                step.on_true_step.unwrap_or(step_idx + 1)
            } else {
                step.on_false_step.unwrap_or(step_idx + 1)
            };
            run.duration_ms = run_start.elapsed().as_millis() as u64;
            state.update_run(&run_id, run.clone());
            continue;
        }

        // Determine target: step override or workflow default
        let target = step.target_override.as_ref().unwrap_or(&workflow.target);
        let targets = resolve_targets(cluster, target);

        if targets.is_empty() {
            warn!("WolfFlow: step '{}' has no target nodes — skipping", step.name);
            run.steps.push(StepResult {
                step_name: step.name.clone(),
                node_id: "none".to_string(),
                node_hostname: "none".to_string(),
                status: RunStatus::Failed,
                output: "No target nodes found".to_string(),
                started_at: Utc::now().to_rfc3339(),
                finished_at: Utc::now().to_rfc3339(),
                duration_ms: 0,
            });
            had_failure = true;
            match step.on_failure {
                OnFailure::Abort | OnFailure::NotifyAndAbort => { aborted = true; }
                OnFailure::Alert | OnFailure::NotifyAndContinue => {
                    error!("WolfFlow: ALERT — step '{}' failed: no target nodes", step.name);
                }
                OnFailure::Continue => {}
            }
            step_idx += 1;
            continue;
        }

        // Retry loop
        let max_attempts = (step.retry_count + 1) as usize;
        let mut _step_succeeded = false;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                info!("WolfFlow: retrying step '{}' (attempt {}/{})", step.name, attempt + 1, max_attempts);
                if step.retry_delay_secs > 0 {
                    tokio::time::sleep(std::time::Duration::from_secs(step.retry_delay_secs)).await;
                }
            }

            // Determine if this step targets containers
            let is_container_target = matches!(target, Target::Containers { .. });
            let is_everything = matches!(target, Target::Everything);

            // Execute on each target node in parallel (skip for pure container targets)
            let mut step_futures: Vec<tokio::task::JoinHandle<(StepResult, Option<StepOutput>)>> = Vec::new();

            if !is_container_target {
                for (node_id, node_hostname, node_address, node_port, is_self) in &targets {
                    let action = step.action.clone();
                    let step_name = step.name.clone();
                    let node_id = node_id.clone();
                    let node_hostname = node_hostname.clone();
                    let node_address = node_address.clone();
                    let node_port = *node_port;
                    let is_self = *is_self;
                    let secret = cluster_secret.to_string();
                    let actor = actor.to_string();
                    let client = http_client.clone();

                    step_futures.push(tokio::spawn(async move {
                        let step_start = std::time::Instant::now();
                        let started = Utc::now().to_rfc3339();

                        let result = if is_self {
                            execute_action_local(&action).await
                        } else {
                            execute_action_remote(&client, &node_address, node_port, &secret, &actor, &action).await
                        };

                        let elapsed = step_start.elapsed().as_millis() as u64;
                        let finished = Utc::now().to_rfc3339();

                        match result {
                            Ok(output) => (StepResult {
                                step_name,
                                node_id,
                                node_hostname,
                                status: RunStatus::Completed,
                                output: output.text.chars().take(5000).collect(),
                                started_at: started,
                                finished_at: finished,
                                duration_ms: elapsed,
                            }, Some(output)),
                            Err(err) => (StepResult {
                                step_name,
                                node_id,
                                node_hostname,
                                status: RunStatus::Failed,
                                output: err.chars().take(5000).collect(),
                                started_at: started,
                                finished_at: finished,
                                duration_ms: elapsed,
                            }, None),
                        }
                    }));
                }
            }

            // Container-targeted execution: run inside specific containers/VMs
            if is_container_target || is_everything {
                let container_targets = if is_container_target {
                    // Explicit container list from the target
                    match target {
                        Target::Containers { targets: cts } => cts.clone(),
                        _ => Vec::new(),
                    }
                } else {
                    // Everything: we need to discover all containers on all target nodes
                    // This is done by the remote nodes via the container-exec proxy
                    Vec::new()
                };

                if is_container_target && !container_targets.is_empty() {
                    // Execute inside each specific container
                    for ct in &container_targets {
                        let action = step.action.clone();
                        let step_name = step.name.clone();
                        let ct = ct.clone();
                        let secret = cluster_secret.to_string();
                        let actor = actor.to_string();
                        let client = http_client.clone();

                        // Find the node for this container
                        let node = targets.iter().find(|(id, _, _, _, _)| *id == ct.node_id).cloned();
                        let (node_id, node_hostname, node_address, node_port, is_self) = match node {
                            Some(n) => n,
                            None => {
                                // Try to find the node from cluster state
                                let nodes = cluster.get_all_nodes();
                                match nodes.iter().find(|n| n.id == ct.node_id && n.online) {
                                    Some(n) => (n.id.clone(), n.hostname.clone(), n.address.clone(), n.port, n.is_self),
                                    None => {
                                        step_futures.push(tokio::spawn(async move {
                                            (StepResult {
                                                step_name,
                                                node_id: ct.node_id.clone(),
                                                node_hostname: format!("{}:{}", ct.runtime, ct.name),
                                                status: RunStatus::Failed,
                                                output: format!("Host node '{}' not found or offline", ct.node_id),
                                                started_at: Utc::now().to_rfc3339(),
                                                finished_at: Utc::now().to_rfc3339(),
                                                duration_ms: 0,
                                            }, None)
                                        }));
                                        continue;
                                    }
                                }
                            }
                        };

                        let display_name = format!("{}:{} on {}", ct.runtime, ct.name, node_hostname);

                        step_futures.push(tokio::spawn(async move {
                            let step_start = std::time::Instant::now();
                            let started = Utc::now().to_rfc3339();

                            let result = if is_self {
                                execute_action_in_container(&action, &ct).await
                            } else {
                                // Remote: call the container-exec proxy
                                execute_container_remote(&client, &node_address, node_port, &secret, &actor, &action, &ct).await
                            };

                            let elapsed = step_start.elapsed().as_millis() as u64;
                            let finished = Utc::now().to_rfc3339();

                            match result {
                                Ok(output) => (StepResult {
                                    step_name,
                                    node_id,
                                    node_hostname: display_name,
                                    status: RunStatus::Completed,
                                    output: output.text.chars().take(5000).collect(),
                                    started_at: started,
                                    finished_at: finished,
                                    duration_ms: elapsed,
                                }, Some(output)),
                                Err(err) => (StepResult {
                                    step_name,
                                    node_id,
                                    node_hostname: display_name,
                                    status: RunStatus::Failed,
                                    output: err.chars().take(5000).collect(),
                                    started_at: started,
                                    finished_at: finished,
                                    duration_ms: elapsed,
                                }, None),
                            }
                        }));
                    }
                } else if is_everything {
                    // For "Everything": additionally execute inside all containers on each node
                    // Run via remote proxy which discovers + executes in all containers
                    for (node_id, node_hostname, node_address, node_port, is_self) in &targets {
                        let action = step.action.clone();
                        let step_name = step.name.clone();
                        let node_id = node_id.clone();
                        let node_hostname = node_hostname.clone();
                        let node_address = node_address.clone();
                        let node_port = *node_port;
                        let is_self = *is_self;
                        let secret = cluster_secret.to_string();
                        let actor = actor.to_string();
                        let client = http_client.clone();

                        step_futures.push(tokio::spawn(async move {
                            let step_start = std::time::Instant::now();
                            let started = Utc::now().to_rfc3339();

                            let result = if is_self {
                                execute_in_all_local_containers(&action).await
                            } else {
                                execute_all_containers_remote(&client, &node_address, node_port, &secret, &actor, &action).await
                            };

                            let elapsed = step_start.elapsed().as_millis() as u64;
                            let finished = Utc::now().to_rfc3339();

                            match result {
                                Ok(output) => (StepResult {
                                    step_name,
                                    node_id,
                                    node_hostname: format!("{} (containers)", node_hostname),
                                    status: RunStatus::Completed,
                                    output: output.text.chars().take(5000).collect(),
                                    started_at: started,
                                    finished_at: finished,
                                    duration_ms: elapsed,
                                }, Some(output)),
                                Err(err) => (StepResult {
                                    step_name,
                                    node_id,
                                    node_hostname: format!("{} (containers)", node_hostname),
                                    status: RunStatus::Failed,
                                    output: err.chars().take(5000).collect(),
                                    started_at: started,
                                    finished_at: finished,
                                    duration_ms: elapsed,
                                }, None),
                            }
                        }));
                    }
                }
            }

            // Collect results
            let mut step_had_failure = false;
            let mut last_output: Option<StepOutput> = None;
            // Clear previous attempt's results for this step
            if attempt > 0 {
                run.steps.retain(|r| r.step_name != step.name);
            }

            for future in step_futures {
                match future.await {
                    Ok((result, output)) => {
                        if result.status == RunStatus::Failed {
                            step_had_failure = true;
                        }
                        if let Some(o) = output {
                            last_output = Some(o);
                        }
                        run.steps.push(result);
                    }
                    Err(e) => {
                        step_had_failure = true;
                        run.steps.push(StepResult {
                            step_name: step.name.clone(),
                            node_id: "unknown".to_string(),
                            node_hostname: "unknown".to_string(),
                            status: RunStatus::Failed,
                            output: format!("Task error: {}", e),
                            started_at: Utc::now().to_rfc3339(),
                            finished_at: Utc::now().to_rfc3339(),
                            duration_ms: 0,
                        });
                    }
                }
            }

            if !step_had_failure {
                _step_succeeded = true;
                // Store output in context for downstream template references
                if let Some(output) = last_output {
                    context.step_outputs.insert(step.name.clone(), output);
                }
                break; // Success — no more retries needed
            }

            // Last attempt failed — don't retry
            if attempt == max_attempts - 1 {
                had_failure = true;
                match step.on_failure {
                    OnFailure::Abort => {
                        error!("WolfFlow: step '{}' failed — aborting workflow '{}'", step.name, workflow.name);
                        aborted = true;
                    }
                    OnFailure::Alert => {
                        error!("WolfFlow: ALERT — step '{}' failed in workflow '{}'", step.name, workflow.name);
                    }
                    OnFailure::Continue => {
                        warn!("WolfFlow: step '{}' failed — continuing workflow '{}'", step.name, workflow.name);
                    }
                    OnFailure::NotifyAndAbort => {
                        error!("WolfFlow: step '{}' failed — notifying and aborting workflow '{}'", step.name, workflow.name);
                        aborted = true;
                    }
                    OnFailure::NotifyAndContinue => {
                        warn!("WolfFlow: step '{}' failed — notifying and continuing workflow '{}'", step.name, workflow.name);
                    }
                }
            }
        }

        // Update run in-progress
        run.duration_ms = run_start.elapsed().as_millis() as u64;
        state.update_run(&run_id, run.clone());
        step_idx += 1;
    }

    // Determine final status
    run.status = if aborted {
        RunStatus::Failed
    } else if had_failure {
        RunStatus::PartialFailure
    } else {
        RunStatus::Completed
    };
    run.finished_at = Some(Utc::now().to_rfc3339());
    run.duration_ms = run_start.elapsed().as_millis() as u64;

    info!(
        "WolfFlow: workflow '{}' finished — status: {:?}, duration: {}ms, steps: {}",
        workflow.name, run.status, run.duration_ms, run.steps.len()
    );

    // Send email with results BEFORE persisting final status — the frontend stops
    // polling as soon as it sees a non-running status, so email_status must already
    // be set by the time the run is saved as completed/failed.
    if let Some(ref email) = workflow.email_results
        && !email.is_empty() {
            info!("WolfFlow: sending email results to {}", email);
            let subject = format!("[WolfFlow] {} — {:?}", workflow.name, run.status);
            let mut config = ai_config.clone().unwrap_or_else(crate::ai::AiConfig::load);
            config.email_to = email.clone();
            if config.smtp_host.is_empty() {
                run.email_status = Some("Failed: SMTP not configured in Settings → AI Agent".to_string());
            } else {
                let html_body = format!(
                    "<html><body style='font-family:sans-serif;'>\
                    <h2>[WolfFlow] {} &mdash; {:?}</h2>\
                    <p>Trigger: {} | Duration: {}ms | Steps: {}</p>\
                    <table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse;font-size:13px;'>\
                    <tr><th>Step</th><th>Node</th><th>Status</th><th>Duration</th><th>Output</th></tr>{}</table>\
                    </body></html>",
                    workflow.name, run.status, trigger, run.duration_ms, run.steps.len(),
                    run.steps.iter().map(|s| format!(
                        "<tr><td>{}</td><td>{}</td><td>{:?}</td><td>{}ms</td><td><pre>{}</pre></td></tr>",
                        s.step_name, s.node_hostname, s.status, s.duration_ms,
                        if s.output.len() > 500 { format!("{}...", &s.output[..500]) } else { s.output.clone() }
                    )).collect::<Vec<_>>().join("")
                );
                match crate::ai::send_html_email(&config, &subject, &html_body) {
                    Ok(_) => {
                        info!("WolfFlow: email sent to {}", config.email_to);
                        run.email_status = Some(format!("Sent to {}", config.email_to));
                    }
                    Err(e) => {
                        warn!("WolfFlow: email failed: {}", e);
                        run.email_status = Some(format!("Failed: {}", e));
                    }
                }
            }
        }

    // Persist final run state (with email_status already set)
    state.update_run(&run_id, run.clone());
    state.mark_last_run(&workflow.id);

    run
}

/// Execute an action on a remote node via the WolfFlow exec API endpoint.
/// Execute an action inside all Docker/LXC containers and VMs on the local node.
/// Returns a combined output summary.
pub async fn execute_in_all_local_containers(action: &ActionType) -> Result<StepOutput, String> {
    let mut outputs = Vec::new();

    // Docker containers
    let docker_containers = crate::containers::docker_list_all();
    for c in &docker_containers {
        let name = &c.name;
        let ct = ContainerTarget { node_id: String::new(), runtime: "docker".to_string(), name: name.clone() };
        match execute_action_in_container(action, &ct).await {
            Ok(o) => outputs.push(format!("[docker:{}] {}", name, o.text)),
            Err(e) => outputs.push(format!("[docker:{}] ERROR: {}", name, e)),
        }
    }

    // LXC containers
    let lxc_containers = crate::containers::lxc_list_all();
    for c in &lxc_containers {
        let name = &c.name;
        let ct = ContainerTarget { node_id: String::new(), runtime: "lxc".to_string(), name: name.clone() };
        match execute_action_in_container(action, &ct).await {
            Ok(o) => outputs.push(format!("[lxc:{}] {}", name, o.text)),
            Err(e) => outputs.push(format!("[lxc:{}] ERROR: {}", name, e)),
        }
    }

    // VMs
    let vms = crate::vms::manager::VmManager::new().list_vms();
    for v in &vms {
        if !v.running { continue; } // Only running VMs
        let ct = ContainerTarget { node_id: String::new(), runtime: "vm".to_string(), name: v.name.clone() };
        match execute_action_in_container(action, &ct).await {
            Ok(o) => outputs.push(format!("[vm:{}] {}", v.name, o.text)),
            Err(e) => outputs.push(format!("[vm:{}] ERROR: {}", v.name, e)),
        }
    }

    if outputs.is_empty() {
        Ok(plain_output("No containers or VMs found on this node".to_string()))
    } else {
        Ok(plain_output(outputs.join("\n")))
    }
}

/// Execute an action inside a specific container on a remote node
async fn execute_container_remote(
    client: &Option<reqwest::Client>,
    address: &str,
    port: u16,
    secret: &str,
    actor: &str,
    action: &ActionType,
    ct: &ContainerTarget,
) -> Result<StepOutput, String> {
    let client = client.as_ref().ok_or_else(|| "HTTP client not available".to_string())?;
    let urls = crate::api::build_node_urls(address, port, "/api/wolfflow/container-exec");

    let body = serde_json::json!({
        "action": serde_json::to_value(action).map_err(|e| e.to_string())?,
        "container": {
            "node_id": ct.node_id,
            "runtime": ct.runtime,
            "name": ct.name,
        }
    });

    for url in &urls {
        match client.post(url)
            .peer_auth(secret)
            // Operator attribution demanded by the remote exec gate.
            .header("X-WolfStack-Proxied", "1")
            .header("X-WolfStack-Actor", actor)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let result = resp.json::<serde_json::Value>().await
                    .map_err(|e| format!("Parse error: {}", e))?;
                if let Some(error) = result.get("error").and_then(|e| e.as_str()) {
                    return Err(error.to_string());
                }
                let text = result.get("output").and_then(|o| o.as_str()).unwrap_or("OK").to_string();
                return Ok(StepOutput { text, data: Default::default() });
            }
            Ok(resp) => {
                let status = resp.status();
                let body_text = resp.text().await.unwrap_or_default();
                return Err(format!("Remote {} returned {}: {}", url, status, body_text));
            }
            Err(_) => continue,
        }
    }
    Err(format!("Failed to reach node {}:{}", address, port))
}

/// Execute an action inside all containers on a remote node
async fn execute_all_containers_remote(
    client: &Option<reqwest::Client>,
    address: &str,
    port: u16,
    secret: &str,
    actor: &str,
    action: &ActionType,
) -> Result<StepOutput, String> {
    let client = client.as_ref().ok_or_else(|| "HTTP client not available".to_string())?;
    let urls = crate::api::build_node_urls(address, port, "/api/wolfflow/all-containers-exec");

    let body = serde_json::to_value(action).map_err(|e| e.to_string())?;

    for url in &urls {
        match client.post(url)
            .peer_auth(secret)
            // Operator attribution demanded by the remote exec gate.
            .header("X-WolfStack-Proxied", "1")
            .header("X-WolfStack-Actor", actor)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let result = resp.json::<serde_json::Value>().await
                    .map_err(|e| format!("Parse error: {}", e))?;
                if let Some(error) = result.get("error").and_then(|e| e.as_str()) {
                    return Err(error.to_string());
                }
                let text = result.get("output").and_then(|o| o.as_str()).unwrap_or("OK").to_string();
                return Ok(StepOutput { text, data: Default::default() });
            }
            Ok(resp) => {
                let status = resp.status();
                let body_text = resp.text().await.unwrap_or_default();
                return Err(format!("Remote {} returned {}: {}", url, status, body_text));
            }
            Err(_) => continue,
        }
    }
    Err(format!("Failed to reach node {}:{}", address, port))
}

async fn execute_action_remote(
    client: &Option<reqwest::Client>,
    address: &str,
    port: u16,
    secret: &str,
    actor: &str,
    action: &ActionType,
) -> Result<StepOutput, String> {
    let client = client.as_ref().ok_or_else(|| "HTTP client not available".to_string())?;

    let urls = crate::api::build_node_urls(address, port, "/api/wolfflow/exec");

    let body = serde_json::to_value(action).map_err(|e| format!("Serialization error: {}", e))?;

    for url in &urls {
        match client
            .post(url)
            .peer_auth(secret)
            // Operator attribution demanded by the remote exec gate.
            .header("X-WolfStack-Proxied", "1")
            .header("X-WolfStack-Actor", actor)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    let result = resp
                        .json::<serde_json::Value>()
                        .await
                        .map_err(|e| format!("Failed to parse response: {}", e))?;

                    if let Some(error) = result.get("error").and_then(|e| e.as_str()) {
                        return Err(error.to_string());
                    }
                    let text = result
                        .get("output")
                        .and_then(|o| o.as_str())
                        .unwrap_or("OK")
                        .to_string();
                    // Parse structured data if present in the response
                    let data = result.get("data")
                        .and_then(|d| d.as_object())
                        .cloned()
                        .unwrap_or_default();
                    return Ok(StepOutput { text, data });
                } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(format!("Remote node returned {}: {}", status, body));
                }
            }
            Err(_) => continue,
        }
    }

    Err(format!("Could not reach node at {}:{}", address, port))
}

// ═══════════════════════════════════════════════
// ─── Toolbox ───
// ═══════════════════════════════════════════════

/// Returns a JSON array describing each action type's form fields
/// for the frontend workflow builder UI.
pub fn toolbox_actions() -> serde_json::Value {
    // Sorted alphabetically by label for the frontend toolbox sidebar
    serde_json::json!([
        {
            "action": "check_disk_space",
            "label": "Check Disk Space",
            "description": "Check disk usage and return available_gb, total_gb, usage_pct for use in conditions",
            "icon": "fa-hard-drive",
            "category": "system",
            "fields": [
                { "name": "warn_threshold_pct", "label": "Threshold (%)", "type": "number", "default": 90, "placeholder": "90" },
                { "name": "mount_point", "label": "Mount Point", "type": "text", "placeholder": "/ or /var or all (default: all)" }
            ],
            "outputs": ["available_gb", "total_gb", "usage_pct", "mount_point", "over_threshold"]
        },
        {
            "action": "clean_logs",
            "label": "Clean Journal Logs",
            "description": "Vacuum systemd journal logs to a maximum size",
            "icon": "fa-broom",
            "category": "system",
            "fields": [
                { "name": "max_size_mb", "label": "Max Size (MB)", "type": "number", "default": 500, "placeholder": "500" }
            ]
        },
        {
            "action": "condition",
            "label": "Condition (If/Else)",
            "description": "Branch workflow based on a condition — use {{step_name.key}} to reference previous step outputs",
            "icon": "fa-code-branch",
            "category": "logic",
            "fields": [
                { "name": "expression", "label": "Value / Expression", "type": "text", "required": true, "placeholder": "{{Check Disk.available_gb}}" },
                { "name": "operator", "label": "Operator", "type": "select", "options": ["eq","neq","gt","lt","gte","lte","contains","matches","truthy"], "default": "eq" },
                { "name": "compare_to", "label": "Compare To", "type": "text", "placeholder": "500" }
            ],
            "outputs": ["result"]
        },
        {
            "action": "docker_update",
            "label": "Docker Container Update",
            "description": "Pull the latest image and restart a Docker container",
            "icon": "fa-arrow-rotate-right",
            "category": "docker",
            "fields": [
                { "name": "container_name", "label": "Container Name", "type": "text", "required": true },
                { "name": "backup_first", "label": "Backup Before Update", "type": "checkbox", "default": true }
            ],
            "outputs": ["success", "container", "image"]
        },
        {
            "action": "docker_update_many",
            "label": "Docker Update (Bulk)",
            "description": "Update all running Docker containers — or a chosen subset — in one step. Uses the full image-watcher pipeline (recreate-from-inspect + backup + health-check). Honours per-container Pinned/Ignored policy and max_parallel_updates from image-watcher.json.",
            "icon": "fa-arrows-rotate",
            "category": "docker",
            "fields": [
                { "name": "target", "label": "Target", "type": "select",
                  "options": ["all", "specific"], "default": "all" },
                { "name": "container_names", "label": "Container Names (when Target = specific)",
                  "type": "string_list",
                  "placeholder": "one per line, or comma-separated — e.g.\nplex\nnextcloud, mariadb" }
            ],
            "outputs": ["total", "succeeded", "failed", "events"]
        },
        {
            "action": "docker_prune",
            "label": "Docker Prune",
            "description": "Remove all unused Docker images, containers, volumes, and networks",
            "icon": "fa-trash-can",
            "category": "docker",
            "fields": []
        },
        {
            "action": "docker_check_update",
            "label": "Docker Update Check",
            "description": "Check if a Docker image has a newer version available",
            "icon": "fa-magnifying-glass",
            "category": "docker",
            "fields": [
                { "name": "container_or_image", "label": "Container / Image", "type": "text", "required": true, "placeholder": "nginx or myapp:latest" }
            ],
            "outputs": ["image", "local_digest", "update_available", "container"]
        },
        {
            "action": "docker_check_update_many",
            "label": "Docker Update Check (Bulk)",
            "description": "Check all running Docker containers — or a chosen subset — for available image updates in one step. Same code path as the background watcher. Pinned/Ignored containers are skipped automatically.",
            "icon": "fa-magnifying-glass-plus",
            "category": "docker",
            "fields": [
                { "name": "target", "label": "Target", "type": "select",
                  "options": ["all", "specific"], "default": "all" },
                { "name": "container_names", "label": "Container Names (when Target = specific)",
                  "type": "string_list",
                  "placeholder": "one per line, or comma-separated — e.g.\nplex\nnextcloud, mariadb" }
            ],
            "outputs": ["checked", "updates_available", "results"]
        },
        {
            "action": "http_request",
            "label": "HTTP Request",
            "description": "Send an HTTP request to any external API",
            "icon": "fa-globe",
            "category": "integration",
            "fields": [
                { "name": "method", "label": "Method", "type": "select", "options": ["GET","POST","PUT","DELETE","PATCH"], "default": "GET" },
                { "name": "url", "label": "URL", "type": "text", "required": true, "placeholder": "https://api.example.com/endpoint" },
                { "name": "headers", "label": "Headers (JSON array)", "type": "textarea", "placeholder": "[{\"name\":\"X-Key\",\"value\":\"abc\"}]" },
                { "name": "body", "label": "Request Body", "type": "textarea", "placeholder": "{\"key\": \"value\"}" },
                { "name": "timeout_secs", "label": "Timeout (seconds)", "type": "number", "default": 300 },
                { "name": "fail_on_error", "label": "Fail on HTTP Error", "type": "checkbox", "default": true }
            ],
            "outputs": ["status_code", "response_body", "json"]
        },
        {
            "action": "integration_action",
            "label": "Integration Action",
            "description": "Execute an action on a configured external integration",
            "icon": "fa-plug",
            "category": "integration",
            "fields": [
                { "name": "instance_id", "label": "Integration Instance", "type": "text", "required": true, "placeholder": "Instance ID" },
                { "name": "operation", "label": "Operation", "type": "text", "required": true, "placeholder": "list_peers" },
                { "name": "params", "label": "Parameters (JSON)", "type": "textarea", "placeholder": "{}" }
            ],
            "outputs": ["instance_id", "operation"]
        },
        {
            "action": "netbird_action",
            "label": "NetBird API",
            "description": "Interact with NetBird VPN management API",
            "icon": "fa-network-wired",
            "category": "services",
            "fields": [
                { "name": "api_url", "label": "Management URL", "type": "text", "default": "https://api.netbird.io", "placeholder": "https://api.netbird.io" },
                { "name": "api_token", "label": "API Token", "type": "text", "required": true },
                { "name": "endpoint", "label": "Endpoint", "type": "select", "options": ["/api/peers","/api/routes","/api/groups","/api/users","/api/dns/nameservers"], "default": "/api/peers" },
                { "name": "method", "label": "Method", "type": "select", "options": ["GET","POST","PUT","DELETE"], "default": "GET" },
                { "name": "body", "label": "Request Body", "type": "textarea" }
            ],
            "outputs": ["status_code", "response_body", "json"]
        },
        {
            "action": "restart_container",
            "label": "Restart Container",
            "description": "Restart a Docker or LXC container by name",
            "icon": "fa-cube",
            "category": "system",
            "fields": [
                { "name": "runtime", "label": "Runtime", "type": "select", "options": ["docker", "lxc"], "required": true },
                { "name": "name", "label": "Container Name", "type": "text", "required": true }
            ]
        },
        {
            "action": "restart_service",
            "label": "Restart Systemd Service",
            "description": "Restart a systemd service by name",
            "icon": "fa-rotate",
            "category": "system",
            "fields": [
                { "name": "service_name", "label": "Service Name", "type": "text", "required": true, "placeholder": "nginx" }
            ]
        },
        {
            "action": "run_backup_schedule",
            "label": "Run Backup Schedule",
            "description": "Run a WolfStack backup schedule and wait for it to finish — backups appear in the Backups section for management and restore, honour retention, and run the schedule's pre/post commands. Fails if any backup in the run fails. Runs on the node executing the workflow (not inside containers).",
            "icon": "fa-box-archive",
            "category": "system",
            "fields": [
                { "name": "schedule_id", "label": "Backup Schedule", "type": "text", "required": true, "placeholder": "Schedule ID (see Backups → Scheduled)" }
            ],
            "outputs": ["schedule", "total", "completed", "failed"]
        },
        {
            "action": "run_command",
            "label": "Run Shell Command",
            "description": "Execute an arbitrary shell command with a timeout",
            "icon": "fa-terminal",
            "category": "system",
            "fields": [
                { "name": "command", "label": "Command", "type": "textarea", "required": true, "placeholder": "echo hello" },
                { "name": "timeout_secs", "label": "Timeout (seconds)", "type": "number", "default": 300 }
            ]
        },
        {
            "action": "truenas_action",
            "label": "TrueNAS API",
            "description": "Interact with TrueNAS Scale REST API",
            "icon": "fa-database",
            "category": "services",
            "fields": [
                { "name": "api_url", "label": "TrueNAS URL", "type": "text", "required": true, "placeholder": "https://truenas.local" },
                { "name": "api_key", "label": "API Key", "type": "text", "required": true },
                { "name": "endpoint", "label": "Endpoint", "type": "select", "options": ["/api/v2.0/pool","/api/v2.0/pool/dataset","/api/v2.0/sharing/smb","/api/v2.0/sharing/nfs","/api/v2.0/system/info","/api/v2.0/system/alert/list"], "default": "/api/v2.0/pool" },
                { "name": "method", "label": "Method", "type": "select", "options": ["GET","POST","PUT","DELETE"], "default": "GET" },
                { "name": "body", "label": "Request Body", "type": "textarea" }
            ],
            "outputs": ["status_code", "response_body", "json"]
        },
        {
            "action": "unifi_action",
            "label": "Unifi Controller",
            "description": "Interact with Unifi Network Controller API",
            "icon": "fa-wifi",
            "category": "services",
            "fields": [
                { "name": "api_url", "label": "Controller URL", "type": "text", "required": true, "placeholder": "https://unifi.local:8443" },
                { "name": "username", "label": "Username", "type": "text", "required": true },
                { "name": "password", "label": "Password", "type": "text", "required": true },
                { "name": "endpoint", "label": "Endpoint", "type": "select", "options": ["/api/s/default/stat/device","/api/s/default/stat/sta","/api/s/default/stat/health","/api/s/default/rest/wlanconf","/api/s/default/cmd/devmgr"], "default": "/api/s/default/stat/device" },
                { "name": "method", "label": "Method", "type": "select", "options": ["GET","POST","PUT","DELETE"], "default": "GET" },
                { "name": "body", "label": "Request Body", "type": "textarea" }
            ],
            "outputs": ["status_code", "response_body", "json"]
        },
        {
            "action": "update_packages",
            "label": "Update System Packages",
            "description": "Run the system package manager to update and upgrade all packages",
            "icon": "fa-arrow-up",
            "category": "system",
            "fields": []
        },
        {
            "action": "update_wolfstack",
            "label": "Update WolfStack",
            "description": "Pull and install the latest WolfStack build from a given channel",
            "icon": "fa-download",
            "category": "system",
            "fields": [
                { "name": "channel", "label": "Channel", "type": "text", "default": "master", "placeholder": "master" }
            ]
        },
        {
            "action": "ai_invoke",
            "label": "AI Invoke",
            "description": "Ask the configured AI model a question and capture its response. Stateless — no memory between runs. Use {{step_name.key}} templates in the prompt. For yes/no decisions the system prompt tells the model to start with YES or NO so a Condition step can branch.",
            "icon": "fa-robot",
            "category": "ai",
            "fields": [
                { "name": "prompt", "label": "Prompt", "type": "textarea", "required": true, "placeholder": "Is the following disk-full alert a real problem or routine log-file growth?\n\n{{Check Disk.detail}}" },
                { "name": "system_prompt", "label": "System Prompt (optional)", "type": "textarea", "placeholder": "Leave blank to use the default ops-assistant system prompt" },
                { "name": "model", "label": "Model Override (optional)", "type": "text", "placeholder": "e.g. claude-haiku-4-5 for routine questions" },
                { "name": "provider", "label": "Provider Override (optional)", "type": "select", "options": ["", "claude", "gemini", "openrouter", "local"], "default": "" },
                { "name": "max_tokens", "label": "Max Response Tokens", "type": "number", "default": 1024, "placeholder": "1024" }
            ],
            "outputs": ["response", "model", "provider"]
        },
        {
            "action": "agent_chat",
            "label": "Agent Chat",
            "description": "Send a message to a named WolfAgent. The agent has persistent memory across turns and its own tool allowlist, so it can act during the conversation. Use for stateful ops assistants (e.g. an agent that watches a specific cluster).",
            "icon": "fa-comments",
            "category": "ai",
            "fields": [
                { "name": "agent_id", "label": "Agent ID", "type": "text", "required": true, "placeholder": "from /api/agents" },
                { "name": "message", "label": "Message", "type": "textarea", "required": true, "placeholder": "Can be templated with {{step_name.key}}" },
                { "name": "timeout_secs", "label": "Timeout (s)", "type": "number", "default": 180 }
            ],
            "outputs": ["response", "agent_id"]
        }
    ])
}

// ═══════════════════════════════════════════════
// ─── Tests ───
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDateTime;

    fn make_dt(year: i32, month: u32, day: u32, hour: u32, min: u32) -> NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(year, month, day)
            .unwrap()
            .and_hms_opt(hour, min, 0)
            .unwrap()
    }

    #[test]
    fn cron_wildcard() {
        let dt = make_dt(2026, 3, 19, 14, 30);
        assert!(cron_matches("* * * * *", &dt));
    }

    #[test]
    fn cron_exact_match() {
        let dt = make_dt(2026, 3, 19, 14, 30);
        assert!(cron_matches("30 14 19 3 *", &dt));
        assert!(!cron_matches("31 14 19 3 *", &dt));
    }

    #[test]
    fn cron_step() {
        let dt = make_dt(2026, 1, 1, 0, 15);
        assert!(cron_matches("*/15 * * * *", &dt));
        let dt2 = make_dt(2026, 1, 1, 0, 7);
        assert!(!cron_matches("*/15 * * * *", &dt2));
    }

    #[test]
    fn cron_range() {
        let dt = make_dt(2026, 1, 1, 9, 0);
        assert!(cron_matches("0 9-17 * * *", &dt));
        let dt2 = make_dt(2026, 1, 1, 8, 0);
        assert!(!cron_matches("0 9-17 * * *", &dt2));
    }

    #[test]
    fn cron_comma_list() {
        let dt = make_dt(2026, 1, 1, 0, 0);
        assert!(cron_matches("0,15,30,45 * * * *", &dt));
        let dt2 = make_dt(2026, 1, 1, 0, 10);
        assert!(!cron_matches("0,15,30,45 * * * *", &dt2));
    }

    #[test]
    fn cron_day_of_week() {
        // 2026-03-19 is a Thursday = 4 in cron (Sunday=0)
        let dt = make_dt(2026, 3, 19, 12, 0);
        assert!(cron_matches("0 12 * * 4", &dt));
        assert!(!cron_matches("0 12 * * 1", &dt));
    }

    #[test]
    fn cron_sunday_7() {
        // 2026-03-22 is a Sunday
        let dt = make_dt(2026, 3, 22, 0, 0);
        assert!(cron_matches("0 0 * * 0", &dt));
        assert!(cron_matches("0 0 * * 7", &dt)); // 7 is also Sunday
    }

    #[test]
    fn cron_invalid_fields() {
        let dt = make_dt(2026, 1, 1, 0, 0);
        assert!(!cron_matches("* * *", &dt)); // Too few fields
        assert!(!cron_matches("* * * * * *", &dt)); // Too many fields
    }

    #[test]
    fn cron_range_with_step() {
        let dt0 = make_dt(2026, 1, 1, 1, 0);
        let dt5 = make_dt(2026, 1, 1, 1, 5);
        let dt3 = make_dt(2026, 1, 1, 1, 3);
        assert!(cron_matches("0-30/5 * * * *", &dt0));
        assert!(cron_matches("0-30/5 * * * *", &dt5));
        assert!(!cron_matches("0-30/5 * * * *", &dt3));
    }

    #[test]
    fn action_serde_round_trip() {
        let action = ActionType::RunCommand {
            command: "echo hello".to_string(),
            timeout_secs: 60,
        };
        let json = serde_json::to_string(&action).unwrap();
        let parsed: ActionType = serde_json::from_str(&json).unwrap();
        match parsed {
            ActionType::RunCommand { command, timeout_secs } => {
                assert_eq!(command, "echo hello");
                assert_eq!(timeout_secs, 60);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn action_serde_defaults() {
        // UpdateWolfstack with no channel should default to "master"
        let json = r#"{"action":"update_wolfstack"}"#;
        let parsed: ActionType = serde_json::from_str(json).unwrap();
        match parsed {
            ActionType::UpdateWolfstack { channel } => {
                assert_eq!(channel, "master");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn on_failure_default_is_abort() {
        let default: OnFailure = Default::default();
        assert_eq!(default, OnFailure::Abort);
    }

    #[test]
    fn http_request_serde_round_trip() {
        let action = ActionType::HttpRequest {
            method: "POST".to_string(),
            url: "https://api.example.com/test".to_string(),
            headers: vec![HttpHeader { name: "X-Key".to_string(), value: "abc".to_string() }],
            body: Some(r#"{"key":"value"}"#.to_string()),
            auth: Some(HttpAuth::Bearer { token: "tok123".to_string() }),
            timeout_secs: 30,
            fail_on_error: true,
            verify_tls: false,
        };
        let json = serde_json::to_string(&action).unwrap();
        let parsed: ActionType = serde_json::from_str(&json).unwrap();
        match parsed {
            ActionType::HttpRequest { method, url, headers, .. } => {
                assert_eq!(method, "POST");
                assert_eq!(url, "https://api.example.com/test");
                assert_eq!(headers.len(), 1);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn condition_serde_defaults() {
        let json = r#"{"action":"condition","expression":"true","compare_to":"true"}"#;
        let parsed: ActionType = serde_json::from_str(json).unwrap();
        match parsed {
            ActionType::Condition { operator, .. } => {
                assert_eq!(operator, "eq");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn template_resolution() {
        let mut ctx = WorkflowContext::default();
        let mut data = serde_json::Map::new();
        data.insert("update_available".to_string(), serde_json::Value::Bool(true));
        data.insert("count".to_string(), serde_json::json!(42));
        ctx.step_outputs.insert("Check".to_string(), StepOutput {
            text: "ok".to_string(),
            data,
        });
        assert_eq!(resolve_templates("{{Check.update_available}}", &ctx), "true");
        assert_eq!(resolve_templates("{{Check.count}}", &ctx), "42");
        assert_eq!(resolve_templates("{{Missing.key}}", &ctx), "");
        assert_eq!(resolve_templates("no templates here", &ctx), "no templates here");
    }

    #[test]
    fn condition_evaluation() {
        let ctx = WorkflowContext::default();
        assert!(evaluate_condition("hello", "hello", "eq", &ctx));
        assert!(!evaluate_condition("hello", "world", "eq", &ctx));
        assert!(evaluate_condition("hello", "world", "neq", &ctx));
        assert!(evaluate_condition("10", "5", "gt", &ctx));
        assert!(evaluate_condition("5", "10", "lt", &ctx));
        assert!(evaluate_condition("hello world", "world", "contains", &ctx));
        assert!(evaluate_condition("true", "", "truthy", &ctx));
        assert!(!evaluate_condition("false", "", "truthy", &ctx));
        assert!(!evaluate_condition("0", "", "truthy", &ctx));
        assert!(!evaluate_condition("", "", "truthy", &ctx));
    }

    #[test]
    fn webhook_config_serde() {
        let wh = WebhookConfig {
            token: "abc-123".to_string(),
            secret: Some("mysecret".to_string()),
            enabled: true,
        };
        let json = serde_json::to_string(&wh).unwrap();
        let parsed: WebhookConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.token, "abc-123");
        assert_eq!(parsed.secret.as_deref(), Some("mysecret"));
    }

    #[test]
    fn step_output_default() {
        let out = StepOutput::default();
        assert!(out.text.is_empty());
        assert!(out.data.is_empty());
    }

    #[test]
    fn target_serde_round_trip() {
        let target = Target::Nodes {
            node_ids: vec!["node-1".to_string(), "node-2".to_string()],
        };
        let json = serde_json::to_string(&target).unwrap();
        let parsed: Target = serde_json::from_str(&json).unwrap();
        match parsed {
            Target::Nodes { node_ids } => {
                assert_eq!(node_ids.len(), 2);
                assert_eq!(node_ids[0], "node-1");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn toolbox_returns_all_actions() {
        let actions = toolbox_actions();
        let arr = actions.as_array().unwrap();
        // 16 base actions + AiInvoke + AgentChat added in v18.1
        // + docker_update_many + docker_check_update_many added in
        // v24.7.16 (sponsor request — bulk Docker container update so
        // operators don't have to chain one step per image)
        // + run_backup_schedule (wabil 2026-07-02 — flows that snapshot/
        // quiesce, back up through the normal pipeline, then update).
        // Bump this when you add a new toolbox entry — the frontend's
        // editor relies on one card per action, so `len` IS the right
        // assertion even if it reads like a fragile hardcode.
        assert_eq!(arr.len(), 21);
        // Check that each action has required fields
        for a in arr {
            assert!(a.get("action").is_some());
            assert!(a.get("label").is_some());
            assert!(a.get("description").is_some());
            assert!(a.get("fields").is_some());
        }
        // The two AI actions should be present by name so refactors
        // don't accidentally drop them.
        let names: Vec<&str> = arr.iter()
            .filter_map(|a| a.get("action").and_then(|n| n.as_str()))
            .collect();
        assert!(names.contains(&"ai_invoke"), "toolbox missing ai_invoke");
        assert!(names.contains(&"agent_chat"), "toolbox missing agent_chat");
        // The bulk Docker actions exposed in v24.7.16 — the backend
        // already supported them; without these catalog entries the UI
        // palette never offered them, forcing one-step-per-image flows.
        assert!(names.contains(&"docker_update_many"),
            "toolbox missing docker_update_many");
        assert!(names.contains(&"docker_check_update_many"),
            "toolbox missing docker_check_update_many");
        assert!(names.contains(&"run_backup_schedule"),
            "toolbox missing run_backup_schedule");
    }

    #[test]
    fn run_backup_schedule_action_parses() {
        // The catalog's "run_backup_schedule" + a schedule_id field must
        // deserialize into the enum variant the executor matches on.
        let json = r#"{"action":"run_backup_schedule","schedule_id":"abc-123"}"#;
        let action: ActionType = serde_json::from_str(json).unwrap();
        match action {
            ActionType::RunBackupSchedule { schedule_id } => assert_eq!(schedule_id, "abc-123"),
            _ => panic!("Wrong variant"),
        }
    }
}
