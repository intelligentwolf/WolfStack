// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! SQL connection pool + guarded query execution.
//!
//! Shared between AI agents (`src/wolfagents/dispatch.rs`) and
//! WolfFlow steps (`src/wolfflow/mod.rs::ActionType::SqlQuery`). Both
//! surfaces execute arbitrary SQL against operator-configured database
//! profiles (MariaDB / MySQL / Postgres), but every execution passes
//! through `execute()` here which:
//!
//! 1. **Classifies the statement(s)** via `sqlparser` and rejects
//!    anything above the caller's declared permission tier
//!    (Read | Update | Delete). An `UPDATE` cannot masquerade as a
//!    `SELECT` — the parser sees through whitespace, comments, and
//!    CTEs. Stacked statements are rejected outright (one query per
//!    call) because per-statement approval is an invitation to typo
//!    your way to a DELETE.
//!
//! 2. **Enforces connect + execution timeouts** (5s connect, default
//!    30s exec) so a hung database can't starve the actix workers
//!    that are answering agent / workflow requests.
//!
//! 3. **Caps result size** at 10,000 rows and 10 MB total — prevents
//!    "SELECT * FROM events" from eating the node's memory or the
//!    agent's LLM context.
//!
//! 4. **Audit-logs** every execution with caller, connection id,
//!    query, outcome, row count, and elapsed ms. Logs append to
//!    `/var/log/wolfstack/sql-audit.log` so operators have a trail
//!    of what agents and workflows did, even if the frontend history
//!    is gone.
//!
//! Passwords are AES-256-GCM encrypted at rest using the cluster
//! secret (same key-derivation scheme as OIDC client secrets — see
//! `auth::oidc::encrypt_secret`). The plaintext password never leaves
//! memory except when sent to the DB driver.

use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock, Mutex};
use std::collections::HashMap;
use std::time::Duration;
use crate::node_identity::PeerAuth;

/// Which DB engine. Determines both the driver and the `sqlparser`
/// dialect used to classify the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SqlKind {
    Mariadb,
    Mysql,
    Postgres,
}

impl SqlKind {
    #[allow(dead_code)]
    fn default_port(&self) -> u16 {
        match self { SqlKind::Mariadb | SqlKind::Mysql => 3306, SqlKind::Postgres => 5432 }
    }
}

/// SSL / TLS behaviour for the connection. Postgres understands all
/// three; mysql_async maps Prefer/Require to its own ssl_opts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SslMode {
    #[default]
    Disable,
    Prefer,
    Require,
}

/// One operator-configured database connection. Scoped to a specific
/// WolfStack node (`node_id`) so the routing layer knows which peer
/// can actually reach the database — a DB running on a container on
/// `wolfstack-1` can't be dialled directly from `wolfstack-2`'s
/// network, so we proxy the query through the owning node instead.
///
/// `password` is ALWAYS stored encrypted on disk. In-memory after load
/// it still carries the `encrypted:aes256:…` prefix; decryption
/// happens lazily inside `get_or_build_pool` just before handing the
/// plaintext to the driver.
///
/// `allowed_users` is the enterprise per-user ACL. Empty = all users
/// (backward-compatible default, and the only behaviour on the free
/// tier). On enterprise (`compat::platform_ready`), non-empty =
/// allowlist; everyone else is denied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlConnection {
    pub id: String,
    pub label: String,
    pub kind: SqlKind,
    /// Cluster-label grouping — purely cosmetic / for filtering in
    /// the UI. Defaults to the operator's current cluster name when
    /// a profile is created from the editor.
    #[serde(default)]
    pub cluster: String,
    /// The WolfStack node that can reach this database. Empty or
    /// matching `self_node_id` = local execution; any other value
    /// routes the query through that peer's `/api/sql-connections/
    /// {id}/query-proxy` endpoint. Missing = legacy profile, treated
    /// as local (current behaviour preserved).
    #[serde(default)]
    pub node_id: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub ssl_mode: SslMode,
    /// Enterprise-only per-user allowlist. Empty = all users. See
    /// module-level docs on the enforcement model.
    #[serde(default)]
    pub allowed_users: Vec<String>,
}

impl SqlConnection {
    /// Return a sanitised view for API responses — password replaced
    /// with a boolean "is_set" so the wire never carries the
    /// ciphertext (let alone plaintext) back to the browser.
    pub fn to_safe_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "label": self.label,
            "kind": self.kind,
            "cluster": self.cluster,
            "node_id": self.node_id,
            "host": self.host,
            "port": self.port,
            "database": self.database,
            "username": self.username,
            "has_password": !self.password.is_empty(),
            "ssl_mode": self.ssl_mode,
            "allowed_users": self.allowed_users,
        })
    }

    /// Return true if `username` is allowed to see/use this profile.
    /// Free tier (platform not licensed) always returns true — the
    /// ACL is an enterprise feature.
    ///
    /// Passes the current platform_ready state in rather than calling
    /// it inline so tests can exercise both modes without a global
    /// license-state fixture.
    pub fn user_permitted(&self, username: &str, enterprise: bool) -> bool {
        if !enterprise { return true; }
        if self.allowed_users.is_empty() { return true; }
        self.allowed_users.iter().any(|u| u.eq_ignore_ascii_case(username))
    }
}

/// Top-level on-disk config. Wrapped so we can add more global fields
/// (default row cap override, audit-log rotation policy, etc.) later
/// without a schema migration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SqlConnectionsConfig {
    #[serde(default)]
    pub connections: Vec<SqlConnection>,
}

fn config_path() -> String { crate::paths::get().sql_connections_config }
fn audit_path() -> String { crate::paths::get().sql_audit_log }

// ═══════════════════════════════════════════════════
// ─── Saved queries & per-user history ───
// ═══════════════════════════════════════════════════

/// One saved query OR one history entry. When `name` is empty the
/// entry is a history line (auto-appended on execution); otherwise
/// it's a named saved query the operator pinned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedQueryEntry {
    pub user: String,
    pub connection_id: String,
    #[serde(default)]
    pub name: String,          // empty = history entry
    pub sql: String,
    #[serde(default)]
    pub created_at: i64,       // unix seconds
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SavedQueriesFile {
    #[serde(default)]
    pub saved: Vec<SavedQueryEntry>,
    #[serde(default)]
    pub history: Vec<SavedQueryEntry>,
}

fn saved_queries_path() -> String {
    // Lives alongside the other sql_connections state. Contains no
    // credentials so 0o644 is fine, but we still write with 0o600 to
    // keep its neighbours' perms consistent.
    "/etc/wolfstack/sql-saved-queries.json".to_string()
}

pub fn load_saved_queries() -> SavedQueriesFile {
    match std::fs::read_to_string(saved_queries_path()) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
            tracing::warn!("sql_connections: saved-queries parse failed ({}) — starting empty", e);
            SavedQueriesFile::default()
        }),
        Err(_) => SavedQueriesFile::default(),
    }
}

fn save_saved_queries(f: &SavedQueriesFile) -> Result<(), String> {
    let path = saved_queries_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(f)
        .map_err(|e| format!("serialize saved-queries: {}", e))?;
    std::fs::write(&path, json).map_err(|e| format!("write saved-queries: {}", e))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

/// Saved queries the given user has pinned on the given connection,
/// sorted alphabetically by name. Does not include history entries.
pub fn list_saved(user: &str, connection_id: &str) -> Vec<SavedQueryEntry> {
    let mut out: Vec<_> = load_saved_queries().saved.into_iter()
        .filter(|e| e.user == user && e.connection_id == connection_id && !e.name.is_empty())
        .collect();
    out.sort_by_key(|a| a.name.to_lowercase());
    out
}

/// Upsert a named saved query for this user+connection. Saving twice
/// with the same name overwrites the previous SQL.
pub fn upsert_saved(user: &str, connection_id: &str, name: &str, sql: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("saved query name is required".into());
    }
    if sql.trim().is_empty() {
        return Err("saved query body is required".into());
    }
    let mut f = load_saved_queries();
    // Remove any existing entry with the same user+conn+name.
    f.saved.retain(|e| !(e.user == user && e.connection_id == connection_id && e.name == name));
    f.saved.push(SavedQueryEntry {
        user: user.to_string(),
        connection_id: connection_id.to_string(),
        name: name.to_string(),
        sql: sql.to_string(),
        created_at: chrono::Utc::now().timestamp(),
    });
    save_saved_queries(&f)
}

/// Remove a saved query by name. Returns Ok(true) if something was
/// removed, Ok(false) if not found.
pub fn delete_saved(user: &str, connection_id: &str, name: &str) -> Result<bool, String> {
    let mut f = load_saved_queries();
    let before = f.saved.len();
    f.saved.retain(|e| !(e.user == user && e.connection_id == connection_id && e.name == name));
    if f.saved.len() == before { return Ok(false); }
    save_saved_queries(&f)?;
    Ok(true)
}

/// Most-recent-first history for this user+connection, capped at 20.
pub fn list_history(user: &str, connection_id: &str) -> Vec<SavedQueryEntry> {
    let mut out: Vec<_> = load_saved_queries().history.into_iter()
        .filter(|e| e.user == user && e.connection_id == connection_id)
        .collect();
    out.sort_by_key(|b| std::cmp::Reverse(b.created_at));
    out.truncate(20);
    out
}

/// Append to history (deduped against the most recent entry).
pub fn push_history(user: &str, connection_id: &str, sql: &str) -> Result<(), String> {
    if sql.trim().is_empty() { return Ok(()); }
    let mut f = load_saved_queries();
    // Skip if identical to the most recent entry for this user+conn.
    let dup = f.history.iter()
        .filter(|e| e.user == user && e.connection_id == connection_id)
        .max_by_key(|e| e.created_at)
        .map(|e| e.sql.as_str() == sql)
        .unwrap_or(false);
    if dup { return Ok(()); }
    f.history.push(SavedQueryEntry {
        user: user.to_string(),
        connection_id: connection_id.to_string(),
        name: String::new(),
        sql: sql.to_string(),
        created_at: chrono::Utc::now().timestamp(),
    });
    // Trim: keep the last 20 per (user, connection_id) tuple. Simpler
    // to rebuild the vec than track per-key counts.
    use std::collections::HashMap;
    let mut by_key: HashMap<(String, String), Vec<SavedQueryEntry>> = HashMap::new();
    for e in f.history.drain(..) {
        by_key.entry((e.user.clone(), e.connection_id.clone())).or_default().push(e);
    }
    for v in by_key.values_mut() {
        v.sort_by_key(|b| std::cmp::Reverse(b.created_at));
        v.truncate(20);
    }
    f.history = by_key.into_values().flatten().collect();
    save_saved_queries(&f)
}

/// Load config from disk. Missing file = empty config; corrupt file
/// is logged and treated as empty so a malformed edit doesn't brick
/// the server.
pub fn load() -> SqlConnectionsConfig {
    match std::fs::read_to_string(config_path()) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
            tracing::warn!("sql_connections: config parse failed ({}) — using empty config", e);
            SqlConnectionsConfig::default()
        }),
        Err(_) => SqlConnectionsConfig::default(),
    }
}

/// Persist config with 0o600 permissions (contains encrypted
/// passwords — still treat the file as sensitive).
pub fn save(cfg: &SqlConnectionsConfig) -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(cfg)
        .map_err(|e| format!("serialize sql-connections: {}", e))?;
    // Atomic write: a truncate-then-write (std::fs::write) can leave a
    // zero-byte / partial file if the process dies mid-write, losing EVERY
    // connection. Write to a temp file then rename (atomic on the same fs).
    use std::os::unix::fs::PermissionsExt;
    let tmp = format!("{}.tmp", path);
    std::fs::write(&tmp, &json).map_err(|e| format!("write sql-connections: {}", e))?;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename sql-connections: {}", e))?;
    // Editing the config invalidates any cached pools; drop them so
    // the next call rebuilds with fresh credentials.
    POOLS.lock().unwrap().clear();
    Ok(())
}

/// Permission tier declared by the caller. sqlparser-gated:
///   - `Read`    → SELECT, SHOW, EXPLAIN, DESCRIBE, WITH (read-only CTE)
///   - `Update`  → everything in Read, plus INSERT, UPDATE
///   - `Delete`  → everything in Update, plus DELETE, TRUNCATE
///
/// DDL (CREATE / ALTER / DROP / GRANT / REVOKE) is refused at every
/// tier — there's no agent scenario where letting the LLM drop a
/// table is the right call. Operators who need schema changes run
/// them via the MySQL editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SqlPermission {
    Read,
    Update,
    Delete,
    /// DDL — ALTER / CREATE / DROP / RENAME / TRUNCATE (structural).
    /// Never granted to AI agents by default (requires an explicit
    /// `sql_schema` flag on the per-agent config). The Database
    /// Manager UI's Structure tab uses this tier when an operator
    /// issues an ALTER TABLE / CREATE INDEX / ADD CONSTRAINT.
    Schema,
}

/// Result shape returned to callers — mirrors what the MySQL editor
/// already produces so the frontend and prompt formatting can be
/// shared across surfaces. `Deserialize` is required so
/// `execute_proxied` can decode the `SqlResult` from a peer's
/// `/query-proxy` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub row_count: usize,
    pub affected_rows: Option<u64>,
    pub elapsed_ms: u64,
    pub truncated: bool,
}

const MAX_ROWS: usize = 10_000;
const MAX_TOTAL_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Parse + classify a single statement. Returns the minimum permission
/// tier the query requires, or an error if the query is malformed or
/// contains disallowed constructs (DDL, multi-statement, etc).
pub fn classify(query: &str, kind: SqlKind) -> Result<SqlPermission, String> {
    use sqlparser::dialect::{Dialect, GenericDialect, MySqlDialect, PostgreSqlDialect};
    use sqlparser::parser::Parser;
    

    // Empty / comment-only input is a misuse — we refuse instead of
    // silently succeeding, since "execute nothing" is never what an
    // agent or workflow actually wants to run.
    if query.trim().is_empty() {
        return Err("query is empty".into());
    }

    // Fast path for MySQL/MariaDB SHOW variants that sqlparser doesn't
    // fully cover (SHOW FULL PROCESSLIST, SHOW FULL TABLES, SHOW ENGINE
    // INNODB STATUS, SHOW GRANTS, SHOW CREATE *, etc.). These are all
    // read-only introspection and the UI's Server / Structure tabs
    // need them to work. Same for DESCRIBE and USE. Short-circuit to
    // Read before sqlparser gets a chance to reject them.
    let trimmed = query.trim_start().to_ascii_lowercase();
    if trimmed.starts_with("show ")
        || trimmed == "show"
        || trimmed.starts_with("describe ")
        || trimmed.starts_with("desc ")
        || trimmed.starts_with("use ")
    {
        // Single-statement check: refuse if a second statement sneaks in
        // after the SHOW (we split on a semicolon that isn't followed
        // only by whitespace/end).
        let body = query.trim_end_matches(';').trim();
        if body.contains(';') {
            return Err(
                "multi-statement queries are not allowed (one statement per call)".into()
            );
        }
        return Ok(SqlPermission::Read);
    }

    let dialect: Box<dyn Dialect> = match kind {
        SqlKind::Mariadb | SqlKind::Mysql => Box::new(MySqlDialect {}),
        SqlKind::Postgres => Box::new(PostgreSqlDialect {}),
    };

    let statements = Parser::parse_sql(&*dialect, query)
        .or_else(|_| Parser::parse_sql(&GenericDialect {}, query))
        .map_err(|e| format!("SQL parse error: {}", e))?;

    if statements.is_empty() {
        return Err("no executable statement in query".into());
    }
    if statements.len() > 1 {
        // One statement per call. Stacked statements are a classic
        // vector for smuggling a destructive tail after an innocuous
        // SELECT — we refuse rather than trying to classify the
        // conjunction.
        return Err(format!(
            "multi-statement queries are not allowed ({} statements found — run them one at a time)",
            statements.len()
        ));
    }

    // Single statement — pick its tier.
    let mut required = SqlPermission::Read;
    for stmt in &statements {
        let tier = statement_tier(stmt)?;
        // Max of required tiers — Delete > Update > Read.
        required = max_perm(required, tier);
    }
    Ok(required)
}

fn max_perm(a: SqlPermission, b: SqlPermission) -> SqlPermission {
    use SqlPermission::*;
    match (a, b) {
        (Schema, _) | (_, Schema) => Schema,
        (Delete, _) | (_, Delete) => Delete,
        (Update, _) | (_, Update) => Update,
        _ => Read,
    }
}

fn statement_tier(stmt: &sqlparser::ast::Statement) -> Result<SqlPermission, String> {
    use sqlparser::ast::Statement::*;
    // We allow-list the specific variants; every other statement
    // kind (CREATE, ALTER, DROP, GRANT, SET, transactions, CALL,
    // USE, LOCK, …) is refused outright. The agent/workflow surface
    // is for data operations, not schema or session management.
    match stmt {
        Query(_) | ExplainTable { .. } | Explain { .. } | Analyze { .. }
            => Ok(SqlPermission::Read),

        Insert { .. } | Update { .. } | Merge { .. }
            => Ok(SqlPermission::Update),

        Delete { .. } | Truncate { .. }
            => Ok(SqlPermission::Delete),

        other => {
            // The Debug repr starts with the variant name — "Drop {",
            // "AlterTable {", etc. Grab the first token so the error
            // message tells the operator which kind of statement was
            // rejected without hard-coding the ever-growing variant
            // list from sqlparser.
            let dbg = format!("{:?}", other);
            let kind = dbg.split(|c: char| !c.is_alphanumeric()).next().unwrap_or("unknown");
            let lower = kind.to_lowercase();
            // Read-only introspection: SHOW*, DESCRIBE, USE (schema switch
            // is harmless — the connection pool is per-profile anyway).
            // These don't have dedicated variants we match on directly
            // across all sqlparser minor versions, so gate by name prefix.
            if lower.starts_with("show") || lower == "describe" || lower == "use" {
                return Ok(SqlPermission::Read);
            }
            // DDL — gated at Schema tier. The UI's Structure tab uses
            // this; AI agents need an explicit sql_schema flag that's
            // off by default. Covers ALTER/CREATE/DROP across their
            // many sqlparser variants (AlterTable, CreateTable,
            // CreateIndex, DropFunction, RenameTable, …).
            if lower.starts_with("alter")
                || lower.starts_with("create")
                || lower.starts_with("drop")
                || lower.starts_with("rename")
            {
                return Ok(SqlPermission::Schema);
            }
            Err(format!(
                "statement kind not permitted via this interface: {}",
                lower
            ))
        }
    }
}

// ═══════════════════════════════════════════════════
// ─── Pool registry ───
// ═══════════════════════════════════════════════════

/// Lazy-initialised per-connection pools. Keyed by connection `id`.
/// `save()` clears this map so credential edits take effect on the
/// next query.
static POOLS: LazyLock<Mutex<HashMap<String, PoolHandle>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Internal enum holding the concrete pool for each backend. Kept
/// behind a Mutex<HashMap> so the dispatcher can swap in a fresh
/// pool after a credential change.
#[derive(Clone)]
enum PoolHandle {
    Mysql(mysql_async::Pool),
    Postgres(deadpool_postgres::Pool),
}

fn get_or_build_pool(conn: &SqlConnection, cluster_secret: &str) -> Result<PoolHandle, String> {
    {
        let pools = POOLS.lock().unwrap();
        if let Some(p) = pools.get(&conn.id) { return Ok(p.clone()); }
    }

    // Resolve the plaintext password only here, at pool-build time.
    // Once hyper/tokio-postgres has copied it into the connection,
    // the plaintext goes out of scope immediately.
    let password = if conn.password.is_empty() {
        String::new()
    } else {
        crate::auth::oidc::decrypt_secret(&conn.password, cluster_secret)
            .map_err(|_| password_decrypt_error(&conn.id))?
    };

    let handle = match conn.kind {
        SqlKind::Mariadb | SqlKind::Mysql => {
            // For MariaDB/MySQL the default-schema is optional. If the
            // operator leaves it blank the connection opens with no
            // current DB and the Database Manager / agent just issues
            // fully-qualified `db.table` references (or `USE db` via
            // the SHOW-tree's "use" action).
            let mut builder = mysql_async::OptsBuilder::default()
                .ip_or_hostname(conn.host.clone())
                .tcp_port(conn.port)
                .user(Some(conn.username.clone()))
                .pass(Some(password));
            if !conn.database.trim().is_empty() {
                builder = builder.db_name(Some(conn.database.clone()));
            }
            if !matches!(conn.ssl_mode, SslMode::Disable) {
                // mysql_async's SslOpts are fine with defaults for
                // Prefer/Require; we don't pin a CA here since the
                // operator may be hitting a private CA — the explicit
                // opt-in is enough.
                builder = builder.ssl_opts(mysql_async::SslOpts::default());
            }
            // Connect timeout lives on the pool constraints in
            // mysql_async 0.34 — see PoolConstraints::new. The
            // defaults (min=10, max=100, inactive_connection_ttl=0)
            // are fine for our usage; we enforce a wall-clock
            // timeout around get_conn() in the query path instead.
            let opts: mysql_async::Opts = builder.into();
            let pool = mysql_async::Pool::new(opts);
            PoolHandle::Mysql(pool)
        }
        SqlKind::Postgres => {
            let mut cfg = deadpool_postgres::Config::new();
            cfg.host = Some(conn.host.clone());
            cfg.port = Some(conn.port);
            cfg.user = Some(conn.username.clone());
            cfg.password = Some(password);
            cfg.dbname = Some(conn.database.clone());
            cfg.connect_timeout = Some(CONNECT_TIMEOUT);
            cfg.ssl_mode = Some(match conn.ssl_mode {
                SslMode::Disable => deadpool_postgres::SslMode::Disable,
                SslMode::Prefer => deadpool_postgres::SslMode::Prefer,
                SslMode::Require => deadpool_postgres::SslMode::Require,
            });
            let pool = cfg.create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            ).map_err(|e| format!("create postgres pool: {}", e))?;
            PoolHandle::Postgres(pool)
        }
    };

    POOLS.lock().unwrap().insert(conn.id.clone(), handle.clone());
    Ok(handle)
}

/// Identifies who called `execute` — used by the audit log. Either
/// an AI agent id, or a WolfFlow workflow+step combo.
#[derive(Debug, Clone)]
pub enum Caller {
    Agent(String),
    Workflow { workflow_id: String, step: String },
    Ui(String),  // logged-in user (manual via the Test button, etc.)
}

impl Caller {
    fn as_tag(&self) -> String {
        match self {
            Caller::Agent(id) => format!("agent:{}", id),
            Caller::Workflow { workflow_id, step } => format!("workflow:{}:{}", workflow_id, step),
            Caller::Ui(user) => format!("ui:{}", user),
        }
    }
}

/// Execute `query` on `connection_id` with the declared permission
/// tier. Returns a bounded `SqlResult` or an error. Audit-logs the
/// outcome regardless.
///
/// Routing:
///   - If the profile's `node_id` is empty or matches this node's
///     `self_node_id`, the query runs LOCALLY — direct driver
///     connection to `host:port`. This is the common case and
///     preserves the behaviour of older profiles that predate the
///     node_id field.
///   - Otherwise the query is proxied: a cluster-secret-authenticated
///     POST to the target node's `/api/sql-connections/{id}/query-proxy`
///     endpoint. That peer re-enters `execute` locally and returns
///     the `SqlResult` verbatim. The audit log on BOTH nodes records
///     the call, with the originator also noting `via_node=<target>`.
pub async fn execute(
    connection_id: &str,
    query: &str,
    requested: SqlPermission,
    caller: Caller,
    cluster_secret: &str,
    exec_timeout: Option<Duration>,
    // ClusterState is `Option` because a few deep wolfflow paths
    // (`execute_action_local`) don't carry full runtime state. With
    // `None`, remote-node profiles refuse with a clear error instead
    // of silently failing or calling a dead address.
    cluster: Option<&crate::agent::ClusterState>,
) -> Result<SqlResult, String> {
    execute_with_schema(connection_id, query, requested, caller, cluster_secret, ExecutionOptions { exec_timeout, cluster, schema: None }).await
}

pub struct ExecutionOptions<'a> {
    pub exec_timeout: Option<Duration>,
    pub cluster: Option<&'a crate::agent::ClusterState>,
    pub schema: Option<&'a str>,
}

/// Same as `execute` but with an optional schema override that the
/// UI passes when the operator has picked a specific DB in the tree.
/// For MySQL/MariaDB this issues `USE <schema>` on the pooled
/// connection before running; for Postgres it issues
/// `SET search_path TO <schema>, public`.
pub async fn execute_with_schema(
    connection_id: &str,
    query: &str,
    requested: SqlPermission,
    caller: Caller,
    cluster_secret: &str,
    options: ExecutionOptions<'_>,
) -> Result<SqlResult, String> {
    let ExecutionOptions { exec_timeout, cluster, schema } = options;
    let cfg = load();
    let conn = cfg.connections.iter()
        .find(|c| c.id == connection_id)
        .cloned()
        .ok_or_else(|| format!("unknown sql connection '{}'", connection_id))?;

    // Classify first — tier must be ≤ requested. This is the main
    // authorization gate and applies regardless of routing.
    let tier = classify(query, conn.kind)?;
    if !tier_within(tier, requested) {
        let outcome = format!(
            "query requires {:?} permission but caller holds {:?}",
            tier, requested
        );
        write_audit(&caller, &conn.id, query, false, 0, 0, &outcome);
        return Err(outcome);
    }

    // Routing decision. `node_id` empty or equal to self → local.
    // Use the ClusterState's authoritative self_id if provided,
    // otherwise fall back to the on-disk node-id file — fine for
    // local-only checks, only proxying truly needs live cluster data.
    let self_id = cluster
        .map(|c| c.self_id.clone())
        .unwrap_or_else(crate::agent::self_node_id);
    let is_local = conn.node_id.is_empty() || conn.node_id == self_id;

    if is_local {
        execute_local(&conn, query, &caller, cluster_secret, exec_timeout, schema).await
    } else {
        let cluster = match cluster {
            Some(c) => c,
            None => {
                let msg = format!(
                    "sql connection '{}' targets node '{}' but caller has no cluster state — \
                     routing is only available from handler/agent contexts, not \
                     execute_action_local. Configure this connection on its owning node \
                     instead, or call from a context that provides state.",
                    conn.id, conn.node_id
                );
                write_audit(&caller, &conn.id, query, false, 0, 0, &msg);
                return Err(msg);
            }
        };
        execute_proxied(&conn, query, requested, &caller, cluster_secret, cluster, QueryOptions { exec_timeout, schema }).await
    }
}

/// Force LOCAL execution of a connection, regardless of its `node_id`.
/// Used by the `/query-proxy` handler: the originator has already
/// routed to us, so re-running the routing logic is harmful (the
/// receiver's `self_id` may not match the stored `node_id` verbatim
/// even though the originator's cluster snapshot resolved this node
/// as the target — e.g. gossip id drift, stale node-id file, or the
/// originator simply picked this node because it is the owning node's
/// nearest reachable peer). Classify the SQL, then execute locally.
pub async fn execute_as_target(
    connection_id: &str,
    query: &str,
    requested: SqlPermission,
    caller: Caller,
    cluster_secret: &str,
    exec_timeout: Option<Duration>,
    schema: Option<&str>,
) -> Result<SqlResult, String> {
    let cfg = load();
    let conn = cfg.connections.iter()
        .find(|c| c.id == connection_id)
        .cloned()
        .ok_or_else(|| format!("unknown sql connection '{}'", connection_id))?;

    let tier = classify(query, conn.kind)?;
    if !tier_within(tier, requested) {
        let outcome = format!(
            "query requires {:?} permission but caller holds {:?}",
            tier, requested
        );
        write_audit(&caller, &conn.id, query, false, 0, 0, &outcome);
        return Err(outcome);
    }

    execute_local(&conn, query, &caller, cluster_secret, exec_timeout, schema).await
}

/// Local execution — open a driver pool to `conn.host:conn.port` and
/// run the query in-process. Bounded by `exec_timeout` (default 30s)
/// and the module-level row / byte caps.
async fn execute_local(
    conn: &SqlConnection,
    query: &str,
    caller: &Caller,
    cluster_secret: &str,
    exec_timeout: Option<Duration>,
    schema: Option<&str>,
) -> Result<SqlResult, String> {
    let pool = get_or_build_pool(conn, cluster_secret)?;
    let timeout = exec_timeout.unwrap_or(DEFAULT_EXEC_TIMEOUT);

    let start = std::time::Instant::now();
    let query_owned = query.to_string();
    let schema_owned = schema.map(|s| s.to_string());
    let fut = async move {
        match pool {
            PoolHandle::Mysql(p) => run_mysql(p, &query_owned, schema_owned.as_deref()).await,
            PoolHandle::Postgres(p) => run_postgres(p, &query_owned, schema_owned.as_deref()).await,
        }
    };
    let result = tokio::time::timeout(timeout, fut).await;

    let elapsed_ms = start.elapsed().as_millis() as u64;
    match result {
        Ok(Ok(mut r)) => {
            r.elapsed_ms = elapsed_ms;
            write_audit(caller, &conn.id, query, true, r.row_count, elapsed_ms, "ok");
            Ok(r)
        }
        Ok(Err(e)) => {
            write_audit(caller, &conn.id, query, false, 0, elapsed_ms, &e);
            Err(e)
        }
        Err(_) => {
            let msg = format!("query exceeded {}s timeout", timeout.as_secs());
            write_audit(caller, &conn.id, query, false, 0, elapsed_ms, &msg);
            Err(msg)
        }
    }
}

struct QueryOptions<'a> {
    exec_timeout: Option<Duration>,
    schema: Option<&'a str>,
}

/// Proxied execution — POST the query to the target node's
/// `/api/sql-connections/{id}/query-proxy` endpoint with cluster-secret
/// auth. That peer runs `execute_local` on our behalf and returns the
/// same `SqlResult` shape.
///
/// We re-validate the SQL on BOTH sides: the classifier already ran
/// before we got here (so we know the caller is authorized), and the
/// target node's handler will classify again before executing (so a
/// compromised originator can't smuggle disallowed SQL through this
/// path by faking the `requested` tier).
async fn execute_proxied(
    conn: &SqlConnection,
    query: &str,
    requested: SqlPermission,
    caller: &Caller,
    cluster_secret: &str,
    cluster: &crate::agent::ClusterState,
    options: QueryOptions<'_>,
) -> Result<SqlResult, String> {
    let QueryOptions { exec_timeout, schema } = options;
    // Resolve the target peer's address from cluster state. We rely on
    // the agent module's snapshot rather than re-reading nodes.json so
    // the address reflects the currently-observed reachable value
    // (pinned IP, last heartbeat, etc.).
    let node_info = match cluster.get_node(&conn.node_id) {
        Some(n) => n,
        None => {
            let msg = format!(
                "sql connection '{}' targets node '{}' but that node is not in the cluster state",
                conn.id, conn.node_id
            );
            write_audit(caller, &conn.id, query, false, 0, 0, &msg);
            return Err(msg);
        }
    };
    if !node_info.online {
        let msg = format!(
            "sql connection '{}' targets node '{}' which is offline — try again when the peer is up",
            conn.id, node_info.hostname
        );
        write_audit(caller, &conn.id, query, false, 0, 0, &msg);
        return Err(msg);
    }

    let start = std::time::Instant::now();
    let urls = crate::api::build_node_urls(
        &node_info.address, node_info.port,
        &format!("/api/sql-connections/{}/query-proxy", conn.id),
    );
    let body = serde_json::json!({
        "query": query,
        "permission": match requested {
            SqlPermission::Read => "read",
            SqlPermission::Update => "update",
            SqlPermission::Delete => "delete",
            SqlPermission::Schema => "schema",
        },
        "timeout_secs": exec_timeout.map(|d| d.as_secs()),
        "origin_caller": caller.as_tag(),
        "schema": schema,
    });

    let client = &*crate::api::API_HTTP_CLIENT;
    let total_timeout = exec_timeout.unwrap_or(DEFAULT_EXEC_TIMEOUT) + Duration::from_secs(10);

    let mut last_err = String::new();
    for url in &urls {
        let resp = client.post(url)
            .peer_auth(cluster_secret)
            .timeout(total_timeout)
            .json(&body)
            .send().await;
        match resp {
            Ok(r) if r.status().is_success() => {
                let elapsed_ms = start.elapsed().as_millis() as u64;
                match r.json::<SqlResult>().await {
                    Ok(result) => {
                        write_audit(
                            caller, &conn.id, query, true, result.row_count, elapsed_ms,
                            &format!("ok (via {})", node_info.hostname),
                        );
                        return Ok(result);
                    }
                    Err(e) => {
                        last_err = format!("decode proxy response: {}", e);
                        break;
                    }
                }
            }
            Ok(r) => {
                let status = r.status();
                let body_text = r.text().await.unwrap_or_default();
                
                // If the target node cleanly rejected the query (e.g. timeout, syntax error,
                // connection refused), it returns {"error": "..."}. We unwrap this and
                // return it directly so the caller gets the actual database error, rather
                // than a confusing "proxy to X failed: HTTP 400..." message that makes it
                // look like the proxy infrastructure is broken.
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_text)
                    && let Some(err_msg) = json.get("error").and_then(|v| v.as_str()) {
                        let clean_err = err_msg.to_string();
                        let elapsed_ms = start.elapsed().as_millis() as u64;
                        write_audit(
                            caller, &conn.id, query, false, 0, elapsed_ms,
                            &format!("{} (via {})", clean_err, node_info.hostname),
                        );
                        return Err(clean_err);
                    }
                
                last_err = format!("HTTP {} from {}: {}", status, url, body_text);
                // Authentic HTTP errors don't retry with different
                // URL schemes — a 403 on https is going to be 403 on
                // http too (same handler). Only retry on network errors.
                break;
            }
            Err(e) => {
                // Transport error — try the next URL in the fallback chain.
                last_err = format!("{} ({})", e, url);
            }
        }
    }

    let elapsed_ms = start.elapsed().as_millis() as u64;
    let msg = format!("proxy to '{}' failed: {}", node_info.hostname, last_err);
    write_audit(caller, &conn.id, query, false, 0, elapsed_ms, &msg);
    Err(msg)
}

fn tier_within(required: SqlPermission, granted: SqlPermission) -> bool {
    use SqlPermission::*;
    match (required, granted) {
        (Read, _) => true,                                   // Read fits under any tier
        (Update, Update) | (Update, Delete) | (Update, Schema) => true,
        (Delete, Delete) | (Delete, Schema) => true,
        (Schema, Schema) => true,
        _ => false,
    }
}

/// Try to connect to the database and issue a cheap health check.
/// Used by the "Test Connection" button in the Settings UI.
///
/// Routes through `execute()` so remote-node profiles are proxied to
/// their owning peer — a DB on a container that's only reachable from
/// `wolfstack-2` must be tested from `wolfstack-2`, not from the node
/// the operator happens to be logged into. We classify the probe as
/// Read and bound the wall-clock to 8 seconds so a black-holed port
/// fails fast instead of hanging the UI.
pub async fn test(
    conn: &SqlConnection,
    cluster_secret: &str,
    cluster: Option<&crate::agent::ClusterState>,
) -> Result<String, String> {
    let probe = match conn.kind {
        SqlKind::Mariadb | SqlKind::Mysql => "SELECT VERSION()",
        SqlKind::Postgres => "SELECT version()",
    };
    let result = execute(
        &conn.id,
        probe,
        SqlPermission::Read,
        Caller::Ui("test-connection".into()),
        cluster_secret,
        Some(Duration::from_secs(8)),
        cluster,
    ).await?;
    // First row, first column is the version string; otherwise fall
    // back to a generic "ok" so operators still get a success toast.
    let version = result.rows.first()
        .and_then(|r| r.first())
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "connected".into());
    Ok(version)
}

// ═══════════════════════════════════════════════════
// ─── Driver-specific execution ───
// ═══════════════════════════════════════════════════

async fn run_mysql(pool: mysql_async::Pool, query: &str, schema: Option<&str>) -> Result<SqlResult, String> {
    use mysql_async::prelude::Queryable;
    let mut conn = pool.get_conn().await.map_err(|e| format!("mysql connect: {}", e))?;
    // Per-request schema override — the UI passes the currently-
    // selected tree schema so queries target the DB the operator is
    // looking at, not just the connection's default. USE doesn't
    // accept bind parameters; we defend against backtick injection
    // by escaping any backticks in the schema name.
    if let Some(s) = schema.filter(|s| !s.is_empty()) {
        let escaped = s.replace('`', "``");
        conn.query_drop(format!("USE `{}`", escaped)).await
            .map_err(|e| format!("mysql USE {}: {}", s, e))?;
    }

    // `query::<Row, _>` buffers into a Vec<Row>. MAX_ROWS defence
    // happens after — mysql_async 0.34 doesn't expose a good
    // per-row streaming API without pinning boxing through its
    // QueryResult, and the MAX_ROWS cap makes worst-case buffering
    // bounded anyway (10k rows × a few hundred bytes each).
    //
    // For DML we still use `query_iter` so we get affected_rows()
    // without also paying to materialise a rowset.
    let trimmed = query.trim_start().to_ascii_lowercase();
    let is_read = trimmed.starts_with("select")
        || trimmed.starts_with("show")
        || trimmed.starts_with("describe")
        || trimmed.starts_with("desc ")
        || trimmed.starts_with("explain")
        || trimmed.starts_with("analyze")
        || trimmed.starts_with("with");

    let mut columns: Vec<String> = Vec::new();
    let mut rows_out: Vec<Vec<serde_json::Value>> = Vec::new();
    let mut total_bytes = 0usize;
    let mut truncated = false;
    let mut affected: Option<u64> = None;

    if is_read {
        let rows: Vec<mysql_async::Row> = conn.query(query).await
            .map_err(|e| format!("mysql exec: {}", e))?;
        if let Some(first) = rows.first() {
            columns = first.columns_ref().iter().map(|c| c.name_str().to_string()).collect();
        }
        for row in rows.iter() {
            if rows_out.len() >= MAX_ROWS { truncated = true; break; }
            let values: Vec<serde_json::Value> = (0..row.len())
                .map(|i| mysql_row_index_to_json(row, i))
                .collect();
            if let Ok(s) = serde_json::to_vec(&values) { total_bytes += s.len(); }
            if total_bytes > MAX_TOTAL_BYTES { truncated = true; break; }
            rows_out.push(values);
        }
    } else {
        // DML path — affected rows, no rowset.
        let result = conn.query_iter(query).await
            .map_err(|e| format!("mysql exec: {}", e))?;
        let aff = result.affected_rows();
        if aff > 0 { affected = Some(aff); }
        drop(result);
    }

    let _ = conn.disconnect().await;

    Ok(SqlResult {
        row_count: rows_out.len(),
        columns,
        rows: rows_out,
        affected_rows: affected,
        elapsed_ms: 0, // filled in by caller
        truncated,
    })
}

/// Convert one column of a mysql_async Row to JSON. `Row::take` moves
/// the value out; we use `get_opt` + `as_sql` so we don't mutate the
/// row (multiple columns need independent reads).
fn mysql_row_index_to_json(row: &mysql_async::Row, i: usize) -> serde_json::Value {
    
    match row.as_ref(i) {
        Some(v) => mysql_value_to_json(v),
        None => serde_json::Value::Null,
    }
}

fn mysql_value_to_json(v: &mysql_async::Value) -> serde_json::Value {
    use mysql_async::Value;
    match v {
        Value::NULL => serde_json::Value::Null,
        Value::Bytes(b) => match std::str::from_utf8(b) {
            Ok(s) => serde_json::Value::String(s.to_string()),
            Err(_) => serde_json::Value::String(format!("<binary:{} bytes>", b.len())),
        },
        Value::Int(i) => serde_json::json!(i),
        Value::UInt(u) => serde_json::json!(u),
        Value::Float(f) => serde_json::json!(f),
        Value::Double(d) => serde_json::json!(d),
        Value::Date(y, m, d, h, mi, s, _) => serde_json::Value::String(
            format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, m, d, h, mi, s)
        ),
        Value::Time(neg, days, h, m, s, _) => serde_json::Value::String(
            format!("{}{}:{:02}:{:02}:{:02}", if *neg { "-" } else { "" },
                    (*days as i64) * 24 + *h as i64, m, s, 0)
        ),
    }
}

async fn run_postgres(pool: deadpool_postgres::Pool, query: &str, schema: Option<&str>) -> Result<SqlResult, String> {
    let client = pool.get().await.map_err(|e| format!("postgres connect: {}", e))?;
    // Per-request search_path override — mirrors the UI's schema
    // selector. Postgres doesn't support "USE db" (connections are
    // pinned to one database at connect time), so we set
    // search_path on the pooled session instead. Escape embedded
    // double-quotes; public is kept as a fallback so built-ins
    // resolve without further qualification.
    if let Some(s) = schema.filter(|s| !s.is_empty()) {
        let escaped = s.replace('"', "\"\"");
        client.simple_query(&format!("SET search_path TO \"{}\", public", escaped)).await
            .map_err(|e| format!("postgres SET search_path {}: {}", s, e))?;
    }

    // Is this a result-producing query or a DML? simple_query returns
    // a stream of messages that tell us the difference — use it so
    // one code path handles SELECT, INSERT, UPDATE, DELETE alike.
    let messages = client.simple_query(query).await
        .map_err(|e| format!("postgres exec: {}", e))?;

    let mut columns: Vec<String> = Vec::new();
    let mut rows: Vec<Vec<serde_json::Value>> = Vec::new();
    let mut total_bytes = 0usize;
    let mut truncated = false;
    let mut affected: Option<u64> = None;

    for msg in messages {
        use tokio_postgres::SimpleQueryMessage::*;
        match msg {
            RowDescription(cols) => {
                columns = cols.iter().map(|c| c.name().to_string()).collect();
            }
            Row(row) => {
                if rows.len() >= MAX_ROWS { truncated = true; break; }
                let values: Vec<serde_json::Value> = (0..row.len())
                    .map(|i| row.get(i).map(|s| serde_json::Value::String(s.to_string()))
                        .unwrap_or(serde_json::Value::Null))
                    .collect();
                if let Ok(s) = serde_json::to_vec(&values) { total_bytes += s.len(); }
                if total_bytes > MAX_TOTAL_BYTES { truncated = true; break; }
                rows.push(values);
            }
            CommandComplete(n) => { affected = Some(n); }
            _ => {}
        }
    }

    Ok(SqlResult {
        row_count: rows.len(),
        columns,
        rows,
        affected_rows: affected,
        elapsed_ms: 0,
        truncated,
    })
}

// ═══════════════════════════════════════════════════
// ─── Audit log ───
// ═══════════════════════════════════════════════════

/// Append one JSON line per execution to the audit log. Errors are
/// logged but not propagated — an audit-log failure shouldn't block
/// a legitimate query.
fn write_audit(caller: &Caller, connection_id: &str, query: &str,
               success: bool, row_count: usize, elapsed_ms: u64, outcome: &str)
{
    let ts = chrono::Utc::now().to_rfc3339();
    let entry = serde_json::json!({
        "ts": ts,
        "caller": caller.as_tag(),
        "connection_id": connection_id,
        "query": query.chars().take(4000).collect::<String>(),
        "success": success,
        "row_count": row_count,
        "elapsed_ms": elapsed_ms,
        "outcome": outcome,
    });
    let line = match serde_json::to_string(&entry) {
        Ok(s) => s + "\n",
        Err(_) => return,
    };
    let path = audit_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Read the last `n` lines of the audit log for UI display. Capped
/// at 1000 for safety. Returns oldest-first.
pub fn read_audit_tail(n: usize) -> Vec<serde_json::Value> {
    let n = n.min(1000);
    let path = audit_path();
    let content = match std::fs::read_to_string(&path) { Ok(s) => s, Err(_) => return Vec::new() };
    let lines: Vec<&str> = content.lines().rev().take(n).collect();
    lines.into_iter().rev()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect()
}

// ═══════════════════════════════════════════════════
// ─── Save/encrypt helpers exposed to the API layer ───
// ═══════════════════════════════════════════════════

/// Take an incoming (user-edited) connection and encrypt its
/// password field against the cluster secret before it's persisted.
/// If the incoming password is empty, preserves the existing
/// encrypted value (edit-without-changing-password path).
pub fn prepare_for_save(
    incoming: &mut SqlConnection,
    existing: Option<&SqlConnection>,
    cluster_secret: &str,
) -> Result<(), String> {
    if incoming.password.is_empty() {
        if let Some(prev) = existing {
            incoming.password = prev.password.clone();
        }
        return Ok(());
    }
    // Already encrypted? (e.g. a round-tripped backup restore.)
    if incoming.password.starts_with("encrypted:") {
        return Ok(());
    }
    incoming.password = crate::auth::oidc::encrypt_secret(&incoming.password, cluster_secret)?;
    Ok(())
}

/// Marker prefix on the error returned when a stored SQL password cannot be
/// decrypted with the current cluster secret — almost always because the
/// secret was rotated since the password was saved. The API layer keys off
/// this token to tell the UI to re-prompt for the password and re-save it
/// under the current key (see `set_connection_password`).
pub const PASSWORD_DECRYPT_FAILED: &str = "password_decrypt_failed";

/// Build the user-facing decrypt-failure error for connection `id`.
pub fn password_decrypt_error(id: &str) -> String {
    format!(
        "{}: the saved password for '{}' can't be decrypted — the cluster secret was \
         changed since it was saved. Re-enter the password to fix this connection.",
        PASSWORD_DECRYPT_FAILED, id
    )
}

/// True if an error string is the "password can't be decrypted" marker.
pub fn is_password_decrypt_error(e: &str) -> bool {
    e.starts_with(PASSWORD_DECRYPT_FAILED)
}

/// Recovery path: re-encrypt ONLY the password of an existing connection under
/// the current cluster secret. Used after a secret rotation orphaned the old
/// ciphertext. `save()` drops all pools, so the next query rebuilds with the
/// freshly-encrypted password. The caller is responsible for cluster
/// replication (the API handler calls replicate_sql_connections_to_cluster).
pub fn set_connection_password(id: &str, new_password: &str, cluster_secret: &str) -> Result<(), String> {
    if new_password.is_empty() {
        return Err("password is required".to_string());
    }
    let mut cfg = load();
    let idx = cfg
        .connections
        .iter()
        .position(|c| c.id == id)
        .ok_or_else(|| format!("connection '{}' not found", id))?;
    // Guard against double-encryption: if the caller pasted an already-
    // encrypted blob (e.g. from a backup), store it verbatim rather than
    // wrapping ciphertext in another layer (mirrors prepare_for_save).
    cfg.connections[idx].password = if new_password.starts_with("encrypted:") {
        new_password.to_string()
    } else {
        crate::auth::oidc::encrypt_secret(new_password, cluster_secret)?
    };
    save(&cfg)
}

/// Convenience: invalidate the pool for `id` after a mutating
/// operation (update / delete). Next query rebuilds from scratch.
#[allow(dead_code)]
pub fn invalidate_pool(id: &str) {
    POOLS.lock().unwrap().remove(id);
}

/// Generate a kebab-slug id from a human label, with a short random
/// suffix so two connections called "prod" don't collide.
pub fn gen_id(label: &str) -> String {
    let slug: String = label.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let slug = if slug.is_empty() { "sql".into() } else { slug };
    let suffix: String = (0..4)
        .map(|_| {
            let x = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default()
                .subsec_nanos() as usize).wrapping_add(slug.len() * 31);
            b"abcdefghijklmnopqrstuvwxyz0123456789"[x % 36] as char
        })
        .collect();
    format!("{}-{}", slug, suffix)
}

/// Drop all pools — used when the cluster secret rotates (rare) or
/// on test cleanup. Every subsequent query re-encrypts with the new
/// secret and reopens connections.
pub fn invalidate_all_pools() {
    POOLS.lock().unwrap().clear();
}

/// Re-encrypt every stored SQL connection password from the OLD cluster
/// secret to the NEW one, as an integral step of a cluster-secret
/// rotation. Returns the number of passwords actually re-keyed.
///
/// Safety contract (loss-free, idempotent):
///   • An empty password is left untouched (nothing to re-key).
///   • A plaintext password (no `encrypted:` prefix — e.g. a legacy or
///     hand-edited profile) is left untouched: it isn't keyed to any
///     secret, so re-keying would be a no-op at best and a corruption
///     risk at worst.
///   • A password that FAILS to decrypt under `old` is left untouched
///     and logged as skipped. Decrypt-failure means it wasn't sealed
///     with `old` (already rotated, restored from a different-secret
///     backup, or corrupt) — never overwrite a secret we couldn't read.
///   • `old == new` short-circuits to a no-op (caller also guards this).
///
/// After re-keying, all pools are dropped so the next query rebuilds
/// using the new-key password.
pub fn reencrypt_at_rest(old: &str, new: &str) -> Result<usize, String> {
    if old == new {
        return Ok(0);
    }
    let mut cfg = load();
    let (rekeyed, skipped) = reencrypt_connections(&mut cfg.connections, old, new)?;
    if rekeyed > 0 {
        save(&cfg)?;
        // Drop cached pools so the next query rebuilds with the re-keyed
        // password instead of a pool built from the old plaintext.
        invalidate_all_pools();
    }
    if skipped > 0 {
        tracing::warn!(target: "secret_rotation",
            "sql_connections: re-keyed {} password(s), skipped {} (empty/plaintext/undecryptable — re-enter via the editor if a connection stops working)",
            rekeyed, skipped);
    }
    Ok(rekeyed)
}

/// Pure in-memory re-key of a connection list — separated from disk I/O
/// so the safety behaviour is unit-testable without writing to
/// /etc/wolfstack/. Returns (rekeyed, skipped). Mutates `connections`
/// in place; a skipped field is left BYTE-IDENTICAL.
fn reencrypt_connections(
    connections: &mut [SqlConnection],
    old: &str,
    new: &str,
) -> Result<(usize, usize), String> {
    let mut rekeyed = 0usize;
    let mut skipped = 0usize;
    for conn in connections.iter_mut() {
        if conn.password.is_empty() {
            continue;
        }
        // Only cluster-secret-keyed ciphertext is in scope. A plaintext
        // value (no encrypted: prefix) is not keyed to any secret.
        if !conn.password.starts_with("encrypted:") {
            skipped += 1;
            continue;
        }
        let plaintext = match crate::auth::oidc::decrypt_secret(&conn.password, old) {
            Ok(p) => p,
            Err(_) => {
                // Couldn't decrypt with the old key — leave it exactly as
                // it is. Re-keying a blob we can't read would destroy it.
                tracing::warn!(target: "secret_rotation",
                    "sql_connections: password for '{}' did not decrypt with the old \
                     cluster secret during rotation — left unchanged (re-enter it via \
                     the editor if this connection stops working)", conn.id);
                skipped += 1;
                continue;
            }
        };
        // Defensive: decrypt_secret returns the input unchanged for a
        // value that lacked the encrypted:aes256: prefix. We already
        // filtered those out above, but if a future format slips
        // through and round-trips to the same string, skip rather than
        // re-wrap plaintext.
        if plaintext == conn.password {
            skipped += 1;
            continue;
        }
        let reenc = crate::auth::oidc::encrypt_secret(&plaintext, new)
            .map_err(|e| format!("re-encrypt sql password for '{}': {}", conn.id, e))?;
        conn.password = reenc;
        rekeyed += 1;
    }
    Ok((rekeyed, skipped))
}

/// Marker to keep the unused-import linter happy when this file is
/// compiled without the API/agent surfaces wired in yet.
#[allow(dead_code)]
fn _link() -> Arc<()> { Arc::new(()) }

#[cfg(test)]
mod reencrypt_tests {
    use super::*;

    fn conn(id: &str, password: String) -> SqlConnection {
        SqlConnection {
            id: id.to_string(),
            label: id.to_string(),
            kind: SqlKind::Mysql,
            cluster: String::new(),
            node_id: String::new(),
            host: "localhost".into(),
            port: 3306,
            database: "db".into(),
            username: "u".into(),
            password,
            ssl_mode: SslMode::Disable,
            allowed_users: Vec::new(),
        }
    }

    const SECRET_A: &str = "wsk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECRET_B: &str = "wsk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SECRET_C: &str = "wsk_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    #[test]
    fn reencrypt_round_trip_a_to_b() {
        // Encrypt with A, re-key A→B, decrypt with B succeeds and yields
        // the original plaintext.
        let plain = "hunter2-prod-db";
        let enc_a = crate::auth::oidc::encrypt_secret(plain, SECRET_A).expect("enc A");
        let mut conns = vec![conn("c1", enc_a)];
        let (rekeyed, skipped) =
            reencrypt_connections(&mut conns, SECRET_A, SECRET_B).expect("reencrypt");
        assert_eq!(rekeyed, 1);
        assert_eq!(skipped, 0);
        let dec_b = crate::auth::oidc::decrypt_secret(&conns[0].password, SECRET_B).expect("dec B");
        assert_eq!(dec_b, plain);
        // And it no longer decrypts under the OLD secret.
        assert!(crate::auth::oidc::decrypt_secret(&conns[0].password, SECRET_A).is_err());
    }

    #[test]
    fn reencrypt_leaves_plaintext_and_empty_untouched() {
        let mut conns = vec![
            conn("empty", String::new()),
            conn("plain", "raw-not-encrypted".into()),
        ];
        let before: Vec<String> = conns.iter().map(|c| c.password.clone()).collect();
        let (rekeyed, skipped) =
            reencrypt_connections(&mut conns, SECRET_A, SECRET_B).expect("reencrypt");
        assert_eq!(rekeyed, 0);
        // empty is silently skipped (not counted); plaintext is counted skipped.
        assert_eq!(skipped, 1);
        let after: Vec<String> = conns.iter().map(|c| c.password.clone()).collect();
        assert_eq!(before, after, "plaintext + empty passwords must be byte-identical after re-key");
    }

    #[test]
    fn reencrypt_skips_field_encrypted_with_different_secret() {
        // A password sealed under secret C must NOT be destroyed when we
        // rotate A→B — it can't be decrypted with A, so it's skipped and
        // left exactly as-is.
        let enc_c = crate::auth::oidc::encrypt_secret("other-key-pw", SECRET_C).expect("enc C");
        let mut conns = vec![conn("foreign", enc_c.clone())];
        let (rekeyed, skipped) =
            reencrypt_connections(&mut conns, SECRET_A, SECRET_B).expect("reencrypt");
        assert_eq!(rekeyed, 0);
        assert_eq!(skipped, 1);
        assert_eq!(conns[0].password, enc_c, "undecryptable field must be left unchanged, never dropped");
        // It still decrypts under its real secret C — proof we didn't corrupt it.
        assert_eq!(
            crate::auth::oidc::decrypt_secret(&conns[0].password, SECRET_C).expect("dec C"),
            "other-key-pw"
        );
    }

    #[test]
    fn reencrypt_is_idempotent_on_equal_secrets() {
        let enc_a = crate::auth::oidc::encrypt_secret("pw", SECRET_A).expect("enc A");
        let mut conns = vec![conn("c1", enc_a.clone())];
        // old == new at the inner helper means it still attempts decrypt
        // with old and re-encrypt with new (same secret) — but the public
        // reencrypt_at_rest short-circuits. Here we test that a same-secret
        // re-key doesn't corrupt: decrypt(A)→encrypt(A) yields a value that
        // still decrypts to the original under A.
        let (rekeyed, _skipped) =
            reencrypt_connections(&mut conns, SECRET_A, SECRET_A).expect("reencrypt");
        assert_eq!(rekeyed, 1);
        assert_eq!(
            crate::auth::oidc::decrypt_secret(&conns[0].password, SECRET_A).expect("dec A"),
            "pw"
        );
    }
}
