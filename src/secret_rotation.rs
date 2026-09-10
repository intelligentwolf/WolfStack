// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Stage 3 of the cluster-secret migration: operator-initiated,
//! coordinated rotation of the cluster secret across every peer in
//! the local cluster.
//!
//! The protocol is split into five operator-controllable steps so that
//! a failed peer never leaves the cluster in a half-rotated state:
//!
//!   1. **Preflight** — initiator pings every peer (using the CURRENT
//!      cluster secret to authenticate) and confirms each one is
//!      reachable AND on a build that understands the protocol.
//!      Returns a per-peer reachability report. NOTHING IS WRITTEN.
//!
//!   2. **Propose** — initiator generates a fresh per-install secret
//!      (32 bytes from /dev/urandom). Returns the value to the operator
//!      UI for display + copy-to-clipboard, and stashes it in a pending
//!      file on the initiator. NOTHING IS PUSHED TO PEERS.
//!
//!   3. **Receive** — initiator pushes the pending secret to every
//!      peer's `/api/cluster/secret/rotate-receive`, authenticating
//!      with the CURRENT secret (still valid on every peer). Each
//!      peer writes the new secret to a `.pending` sibling of its
//!      active secret file. Each peer returns an ACK with the SHA-256
//!      fingerprint so the initiator can confirm bit-for-bit transfer.
//!
//!   4. **Commit** — if every peer ACK'd Receive, initiator broadcasts
//!      `/rotate-commit`. Each peer atomically promotes its .pending
//!      to the active path, backing up the prior active file to a
//!      timestamped `.bak.<ts>` first. The peer's in-memory cluster
//!      secret is NOT live-swapped (would race with concurrent
//!      requests). Both the old in-memory value AND the new on-disk
//!      value remain accepted by `require_auth` until the next restart,
//!      so the cluster works in "mixed" mode during the rolling
//!      restart that follows.
//!
//!   5. **Rollback** — if any peer fails at any step, initiator
//!      broadcasts `/rotate-rollback`. Each peer either deletes its
//!      .pending (if not yet committed) or restores from its .bak
//!      (if committed). The .bak file is the recovery anchor; we
//!      never overwrite or delete it during normal flow.
//!
//! Every step appends a structured line to
//! `/var/log/wolfstack/secret-rotation.log` (mode 0600). The log is
//! the forensic trail for "why did rotation N go weird".
//!
//! ## Why no live in-memory swap
//!
//! `state.cluster_secret` is read by 50+ outbound call sites and 3+
//! auth check sites. Hot-swapping it under an RwLock would (a) require
//! changing the type from `String` to `Arc<RwLock<String>>` everywhere
//! and (b) introduce a race window where some calls are signed with
//! the new secret before all peers have it accepted. The restart-
//! required model is operationally identical to other infrastructure
//! tools (Consul, etcd: SIGHUP-or-restart; Vault: rekey requires
//! restart of standby nodes) and reuses an existing safety net:
//! `api::require_auth` already accepts BOTH the in-memory secret AND
//! `auth::load_cluster_secret()` (re-reads disk on every call). So
//! the post-commit / pre-restart window is auth-tolerant by design.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::node_identity::PeerAuth;

const PROTOCOL_VERSION: u32 = 1;
const PENDING_SUFFIX: &str = ".pending";
const BACKUP_SUFFIX_PREFIX: &str = ".bak.";
const AUDIT_LOG_PATH: &str = "/var/log/wolfstack/secret-rotation.log";

/// H4 — keep the N most-recent backup files alongside the active
/// secret; prune the rest. The backups are forensic / recovery
/// material only; older than this is unlikely to be useful and just
/// expands the blast radius of a directory-listing attack on
/// /etc/wolfstack/.
const BACKUP_RETENTION_COUNT: usize = 5;

/// H3 — coordinator-side rotation lock. Stage 3 orchestrations are
/// long-running (preflight + receive + commit across N peers). Two
/// simultaneous clicks would generate two distinct secrets and race
/// each other through the protocol, leaving peers with a mix of
/// committed values that no audit log can disentangle. AtomicBool
/// gate refuses the second call cleanly with a 409.
static ROTATION_IN_PROGRESS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

struct RotationGuard;
impl Drop for RotationGuard {
    fn drop(&mut self) {
        ROTATION_IN_PROGRESS.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}
/// Try to acquire the rotation lock. Returns `None` if another
/// rotation is currently in flight on this node. The returned guard
/// releases the lock on drop (panic-safe).
fn try_acquire_rotation_lock() -> Option<RotationGuard> {
    let already = ROTATION_IN_PROGRESS
        .compare_exchange(false, true,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst)
        .is_err();
    if already { None } else { Some(RotationGuard) }
}

// ─── Wire types ─────────────────────────────────────────────────

/// Peer-to-peer ping; verifies version compatibility AND that the
/// presenting node holds the current cluster secret (the `require_auth`
/// at the endpoint enforces the latter). Includes the protocol version
/// so an initiator can refuse to rotate a cluster that mixes builds.
#[derive(Debug, Serialize, Deserialize)]
pub struct PreflightAck {
    pub ok: bool,
    pub protocol_version: u32,
    pub node_id: String,
    pub hostname: String,
}

#[derive(Debug, Deserialize)]
pub struct ReceiveRequest {
    /// New candidate secret. Validated for shape on receipt — must
    /// start with `wsk_` and be 64 lowercase hex characters after the
    /// prefix. Refused otherwise so a malformed body can't poison the
    /// .pending file.
    pub new_secret: String,
    /// SHA-256 of the secret bytes as lowercase hex. The peer
    /// re-computes locally and refuses the request if the digest
    /// doesn't match the secret. Catches in-flight truncation /
    /// proxy mangling.
    pub fingerprint: String,
    /// Initiator's own node id — captured into the audit log so
    /// operators can trace which node fired which rotation.
    pub initiated_by: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiveAck {
    pub ok: bool,
    pub fingerprint: String,
    pub pending_path: String,
}

#[derive(Debug, Deserialize)]
pub struct CommitRequest {
    /// Expected fingerprint of the secret to commit. Peer verifies the
    /// .pending file's content matches before promoting — otherwise
    /// a Receive that was overwritten by a stale Receive could commit
    /// the wrong secret.
    pub fingerprint: String,
    pub initiated_by: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommitAck {
    pub ok: bool,
    pub backup_path: String,
    pub active_path: String,
    pub restart_required: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct RollbackRequest {
    pub initiated_by: String,
    /// `"pending"` = delete .pending only (rotation aborted before commit).
    /// `"committed"` = restore from the most recent .bak (rotation aborted after commit).
    pub stage: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RollbackAck {
    pub ok: bool,
    pub action: String,
    pub restored_from: Option<String>,
}

// ─── Helpers ───────────────────────────────────────────────────

fn now_ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn now_compact() -> String {
    let n = now_ts();
    // Simple compact timestamp — yyyymmddHHMMSS — readable in filenames.
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(n as i64, 0)
        .unwrap_or_else(chrono::Utc::now);
    dt.format("%Y%m%d%H%M%S").to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use ring::digest;
    let d = digest::digest(&digest::SHA256, bytes);
    let mut out = String::with_capacity(64);
    for b in d.as_ref() {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", b);
    }
    out
}

/// `wsk_` + 64 lowercase hex. Anything else is refused at the wire.
fn valid_secret_shape(s: &str) -> bool {
    if !s.starts_with("wsk_") { return false; }
    let rest = &s[4..];
    rest.len() == 64 && rest.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn pending_path() -> String {
    format!("{}{}", crate::paths::get().cluster_secret, PENDING_SUFFIX)
}

fn audit(line: &str) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    // Best-effort logging — a write failure must never break a
    // rotation step. Ensure the directory exists first so a fresh
    // install doesn't lose every audit line until /var/log/wolfstack
    // is created elsewhere.
    let _ = std::fs::create_dir_all("/var/log/wolfstack");
    let formatted = format!(
        "[{}] {}\n",
        chrono::Utc::now().to_rfc3339(),
        line
    );
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true).append(true).mode(0o600).open(AUDIT_LOG_PATH)
    {
        let _ = f.write_all(formatted.as_bytes());
    }
}

// ─── At-rest re-encryption on rotation ──────────────────────────

/// Per-store outcome of a rotation re-encrypt pass. `count` is the
/// number of secret fields actually re-keyed in that store; `error` is
/// `Some` if that store's pass failed (the other stores still run — one
/// store's failure must never abort the whole rotation re-key).
#[derive(Debug, Default, Serialize)]
pub struct ReencryptReport {
    pub sql_passwords: usize,
    pub oidc_secrets: usize,
    pub integration_credentials: usize,
    pub dns_providers: usize,
    pub cloud_providers: usize,
    pub xo_tokens: usize,
    /// Human-readable per-store errors, e.g. "oidc: parse failed". Empty
    /// on a fully-clean pass. A non-empty list is NOT fatal: rotation
    /// already committed the new secret; the affected store's blobs are
    /// left intact (their plaintext re-enter prompts still work) and the
    /// operator can re-run the migration after restart.
    pub errors: Vec<String>,
}

impl ReencryptReport {
    fn new() -> Self {
        Self {
            sql_passwords: 0,
            oidc_secrets: 0,
            integration_credentials: 0,
            dns_providers: 0,
            cloud_providers: 0,
            xo_tokens: 0,
            errors: Vec::new(),
        }
    }

    /// Total secret fields re-keyed across every store.
    pub fn total(&self) -> usize {
        self.sql_passwords
            + self.oidc_secrets
            + self.integration_credentials
            + self.dns_providers
            + self.cloud_providers
            + self.xo_tokens
    }
}

/// Re-encrypt EVERY at-rest secret store on THIS node from the OLD
/// cluster secret to the NEW one, as an integral step of a cluster
/// secret rotation. Each store is independent: a failure in one is
/// recorded in the report and the rest still run. Never panics.
///
/// ORDERING CONTRACT (caller's responsibility): the NEW secret must
/// already be persisted to disk before this is called, and `old` must
/// be the secret that was active when these blobs were written. A crash
/// between writing the new secret and finishing this re-key leaves the
/// node in the SAME recoverable state as today (some blobs orphaned;
/// recoverable via the per-store "re-enter the credential" prompts) —
/// never worse, because every store skips (rather than destroys) any
/// field it can't decrypt with `old`.
///
/// No-op when `old == new` (each store also guards this).
pub fn reencrypt_all_at_rest(old: &str, new: &str) -> ReencryptReport {
    let mut report = ReencryptReport::new();
    if old == new {
        return report;
    }

    // SQL connection passwords (oidc::encrypt_secret scheme). Also drops
    // the live SQL pools so the next query rebuilds with the new-key
    // password.
    match crate::sql_connections::reencrypt_at_rest(old, new) {
        Ok(n) => report.sql_passwords = n,
        Err(e) => report.errors.push(format!("sql-connections: {}", e)),
    }

    // OIDC client secrets (oidc.json).
    match crate::auth::oidc::reencrypt_at_rest(old, new) {
        Ok(n) => report.oidc_secrets = n,
        Err(e) => report.errors.push(format!("oidc: {}", e)),
    }

    // Integration credential vault.
    match crate::integrations::reencrypt_at_rest(old, new) {
        Ok(n) => report.integration_credentials = n,
        Err(e) => report.errors.push(format!("integrations: {}", e)),
    }

    // at_rest_crypto v2 stores: dns / cloud / xo.
    {
        let mut store = crate::dns_providers::DnsProviderStore::load();
        match store.reencrypt_at_rest(old, new) {
            Ok(n) => report.dns_providers = n,
            Err(e) => report.errors.push(format!("dns-providers: {}", e)),
        }
    }
    {
        let mut store = crate::edge::CloudProviderStore::load();
        match store.reencrypt_at_rest(old, new) {
            Ok(n) => report.cloud_providers = n,
            Err(e) => report.errors.push(format!("cloud-providers: {}", e)),
        }
    }
    {
        let mut store = crate::xo::XoStore::load();
        match store.reencrypt_at_rest(old, new) {
            Ok(n) => report.xo_tokens = n,
            Err(e) => report.errors.push(format!("xo-tokens: {}", e)),
        }
    }

    if report.errors.is_empty() {
        tracing::info!(target: "secret_rotation",
            "at-rest re-encrypt complete: re-keyed {} SQL password(s), {} OIDC secret(s), \
             {} integration credential(s), {} DNS provider(s), {} cloud provider(s), \
             {} XO token(s) — total {}",
            report.sql_passwords, report.oidc_secrets, report.integration_credentials,
            report.dns_providers, report.cloud_providers, report.xo_tokens, report.total());
    } else {
        // A partial failure is non-fatal but must be loud — the operator
        // may need to re-enter a credential for the failed store(s).
        tracing::warn!(target: "secret_rotation",
            "at-rest re-encrypt finished with {} store error(s): {}. \
             Re-keyed total {} field(s); affected store(s) left intact \
             (re-enter their credentials after restart if they stop working).",
            report.errors.len(), report.errors.join("; "), report.total());
    }

    report
}

// ─── Server-side endpoint handlers (peer-facing) ────────────────

/// POST /api/cluster/secret/rotate-preflight — peer-side ping.
/// Auth: cluster secret (require_auth at the route). Returns this
/// node's protocol version and identity so an initiator can build
/// a per-peer compatibility matrix before generating anything.
pub async fn api_rotate_preflight(
    req: HttpRequest,
    state: web::Data<crate::api::AppState>,
) -> HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".into());
    HttpResponse::Ok().json(PreflightAck {
        ok: true,
        protocol_version: PROTOCOL_VERSION,
        node_id: crate::agent::self_node_id(),
        hostname,
    })
}

/// POST /api/cluster/secret/rotate-propose — initiator-side ONLY.
/// Generates a fresh per-install secret with the system CSPRNG and
/// returns it to the operator UI. The operator copies it to a
/// password manager BEFORE pushing it to peers (so a propagation
/// failure mid-rotation leaves them with a known-good recovery copy).
///
/// Auth: session cookie (operator). Refuses cluster-secret auth —
/// proposing a new secret is an operator decision, not a peer-driven
/// one.
pub async fn api_rotate_propose(
    req: HttpRequest,
    state: web::Data<crate::api::AppState>,
) -> HttpResponse {
    // Require session auth (operator); reject pure-cluster-secret callers.
    // validate_info, not validate: these gates read the cookie directly
    // instead of going through api::require_auth, so they must apply the
    // read-only (viewer) refusal themselves.
    let cookie_user = match req.cookie("wolfstack_session")
        .and_then(|c| state.sessions.validate_info(c.value()))
    {
        Some(s) if s.read_only => return crate::api::read_only_forbidden("rotating the cluster secret"),
        Some(s) => s.username,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "secret rotation must be initiated by an operator session"
            }));
        }
    };
    let new_secret = crate::auth::generate_cluster_secret();
    let fingerprint = sha256_hex(new_secret.as_bytes());
    // Write the candidate to the initiator's .pending file. If a
    // previous half-rotation left one behind, overwrite it — the
    // operator is explicitly starting a new flow.
    if let Err(e) = crate::paths::write_secure(&pending_path(), &new_secret) {
        audit(&format!("PROPOSE_FAIL operator={} err={}", cookie_user, e));
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("could not stash pending secret: {}", e)
        }));
    }
    audit(&format!("PROPOSE_OK operator={} fingerprint={}", cookie_user, fingerprint));
    HttpResponse::Ok().json(serde_json::json!({
        "new_secret": new_secret,
        "fingerprint": fingerprint,
        "pending_path": pending_path(),
        "protocol_version": PROTOCOL_VERSION,
        "warning": "Copy this secret to a password manager NOW. \
                    If propagation to a peer fails, this is your \
                    recovery copy. The value will not be displayed again.",
    }))
}

/// POST /api/cluster/secret/rotate-receive — peer-side write of
/// the candidate to .pending. Auth: cluster secret.
pub async fn api_rotate_receive(
    req: HttpRequest,
    state: web::Data<crate::api::AppState>,
    body: web::Json<ReceiveRequest>,
) -> HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }
    if !valid_secret_shape(&body.new_secret) {
        audit(&format!("RECEIVE_REJECT_SHAPE initiator={}", body.initiated_by));
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "new_secret has invalid shape (expect wsk_ + 64 lowercase hex)"
        }));
    }
    let local_fp = sha256_hex(body.new_secret.as_bytes());
    if local_fp != body.fingerprint {
        audit(&format!("RECEIVE_REJECT_FP initiator={}", body.initiated_by));
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "fingerprint mismatch — request body may be corrupt",
            "expected": body.fingerprint,
            "computed": local_fp,
        }));
    }
    let pending = pending_path();
    if let Err(e) = crate::paths::write_secure(&pending, &body.new_secret) {
        audit(&format!("RECEIVE_WRITE_FAIL initiator={} err={}",
                       body.initiated_by, e));
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("could not write pending file: {}", e)
        }));
    }
    audit(&format!("RECEIVE_OK initiator={} fingerprint={} pending={}",
                   body.initiated_by, local_fp, pending));
    HttpResponse::Ok().json(ReceiveAck {
        ok: true,
        fingerprint: local_fp,
        pending_path: pending,
    })
}

/// POST /api/cluster/secret/rotate-commit — peer-side promotion of
/// .pending to active, after backing up the prior active. Auth:
/// cluster secret.
pub async fn api_rotate_commit(
    req: HttpRequest,
    state: web::Data<crate::api::AppState>,
    body: web::Json<CommitRequest>,
) -> HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }

    let active = crate::paths::get().cluster_secret;
    let pending = pending_path();

    // Capture the OLD active secret BEFORE the rename so we can re-key
    // this peer's own at-rest stores from old→new once the commit lands.
    // load_cluster_secret() falls back to the built-in default when the
    // file is absent, so this is always a usable "old" value.
    let old_secret_for_reencrypt = crate::auth::load_cluster_secret();

    let pending_bytes = match std::fs::read(&pending) {
        Ok(b) => b,
        Err(e) => {
            audit(&format!("COMMIT_NO_PENDING initiator={} err={}",
                           body.initiated_by, e));
            return HttpResponse::Conflict().json(serde_json::json!({
                "error": format!("no pending secret at {}: {}", pending, e),
                "hint": "rotate-receive must succeed before rotate-commit"
            }));
        }
    };
    // Trim trailing newline that write_secure may or may not add.
    let pending_trimmed: Vec<u8> = pending_bytes.iter()
        .copied().take_while(|b| *b != b'\n' && *b != b'\r')
        .collect();
    let pending_fp = sha256_hex(&pending_trimmed);
    if pending_fp != body.fingerprint {
        audit(&format!("COMMIT_FP_MISMATCH initiator={} expected={} got={}",
                       body.initiated_by, body.fingerprint, pending_fp));
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": "pending file fingerprint does not match commit request",
            "expected": body.fingerprint,
            "on_disk": pending_fp,
            "hint": "another rotation may have overwritten the pending file; preflight + receive again"
        }));
    }

    // Back up current active (if it exists). This is the recovery
    // anchor — rollback restores from here. Never delete .bak files
    // during normal flow; operators can prune by hand.
    let backup = format!("{}{}{}", active, BACKUP_SUFFIX_PREFIX, now_compact());
    if Path::new(&active).exists() {
        if let Err(e) = std::fs::copy(&active, &backup) {
            audit(&format!("COMMIT_BACKUP_FAIL initiator={} backup={} err={}",
                           body.initiated_by, backup, e));
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("could not back up active secret: {}", e),
                "hint": "commit aborted — pending file untouched, original still active"
            }));
        }
        // Match permissions on backup (write_secure does 0600, but copy
        // preserves source perms which should already be 0600; defensive
        // chmod in case the source file was tightened by paths::write_secure
        // but the copy landed before the tighten).
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&backup,
            std::fs::Permissions::from_mode(0o600));
    }

    // Atomic rename of .pending → active. fs::rename on the same
    // filesystem is atomic per POSIX.
    if let Err(e) = std::fs::rename(&pending, &active) {
        audit(&format!("COMMIT_RENAME_FAIL initiator={} err={}",
                       body.initiated_by, e));
        // Try to put the backup back in case rename left active broken.
        if Path::new(&backup).exists() && !Path::new(&active).exists() {
            let _ = std::fs::copy(&backup, &active);
        }
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("could not promote pending to active: {}", e),
            "backup_at": backup,
        }));
    }
    // H5: re-align /etc/wolfusb/wolfusb.env so the external wolfusb
    // daemon picks up the same secret on its next restart. Use the
    // already-validated in-memory pending bytes rather than re-reading
    // the active file from disk — re-reading could fail on a full
    // filesystem in the narrow window after rename, and the realign
    // helper silently skips on empty input (so wolfusb would silently
    // stay misaligned).
    let new_secret_str = std::str::from_utf8(&pending_trimmed).unwrap_or("");
    crate::auth::realign_wolfusb_env_after_rotation(new_secret_str);
    // Re-key this peer's own at-rest secrets from old→new. The secret is
    // the at-rest encryption key; without this the peer's local SQL /
    // OIDC / integration / DNS / cloud / XO credentials would be
    // undecryptable after its restart. No-op if the value is unchanged.
    // Best-effort: a re-key failure is logged inside the orchestrator and
    // does NOT fail the commit (rotation already landed on disk; the
    // affected store's plaintext re-enter prompts still recover it).
    if !new_secret_str.is_empty() {
        // Re-key off the actix worker — this does multi-file blocking I/O.
        let old = old_secret_for_reencrypt.clone();
        let news = new_secret_str.to_string();
        let report = web::block(move || reencrypt_all_at_rest(&old, &news))
            .await
            .unwrap_or_default();
        audit(&format!("COMMIT_REENCRYPT initiator={} rekeyed_total={} store_errors={}",
                       body.initiated_by, report.total(), report.errors.len()));
    }
    // H4: prune .bak files beyond BACKUP_RETENTION_COUNT.
    let _ = prune_old_backups(&active);
    audit(&format!("COMMIT_OK initiator={} fingerprint={} backup={}",
                   body.initiated_by, pending_fp, backup));
    HttpResponse::Ok().json(CommitAck {
        ok: true,
        backup_path: backup,
        active_path: active,
        restart_required: true,
        message: "Cluster secret committed. The in-memory secret will \
                  update on the next restart of wolfstack on this node. \
                  Until then, both the old and new secret are accepted \
                  (require_auth checks both in-memory and on-disk values).".into(),
    })
}

/// H4 — keep `BACKUP_RETENTION_COUNT` most-recent `.bak.<ts>` files
/// alongside the active secret; delete the rest. Filenames embed a
/// yyyymmddHHMMSS timestamp so lexicographic sort = chronological.
fn prune_old_backups(active: &str) -> std::io::Result<()> {
    let dir = Path::new(active).parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| Path::new("/etc/wolfstack").to_path_buf());
    let base = Path::new(active).file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("custom-cluster-secret");
    let prefix = format!("{}{}", base, BACKUP_SUFFIX_PREFIX);
    let mut backups: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with(&prefix))
            .unwrap_or(false))
        .collect();
    if backups.len() <= BACKUP_RETENTION_COUNT { return Ok(()); }
    backups.sort();
    // The oldest entries are at the start; keep the last N.
    let to_delete = backups.len() - BACKUP_RETENTION_COUNT;
    for p in backups.into_iter().take(to_delete) {
        // Best-effort: a stuck file shouldn't block rotation.
        let _ = std::fs::remove_file(&p);
    }
    Ok(())
}

/// POST /api/cluster/secret/rotate-rollback — peer-side undo, either
/// removing the .pending (pre-commit abort) or restoring from the
/// most recent .bak (post-commit abort).
pub async fn api_rotate_rollback(
    req: HttpRequest,
    state: web::Data<crate::api::AppState>,
    body: web::Json<RollbackRequest>,
) -> HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }
    let active = crate::paths::get().cluster_secret;
    let pending = pending_path();

    match body.stage.as_str() {
        "pending" => {
            let action = if Path::new(&pending).exists() {
                match std::fs::remove_file(&pending) {
                    Ok(()) => "deleted-pending",
                    Err(e) => {
                        audit(&format!("ROLLBACK_PENDING_FAIL initiator={} err={}",
                                       body.initiated_by, e));
                        return HttpResponse::InternalServerError().json(serde_json::json!({
                            "error": format!("could not remove pending file: {}", e)
                        }));
                    }
                }
            } else { "no-pending-found" };
            audit(&format!("ROLLBACK_PENDING_OK initiator={} action={}",
                           body.initiated_by, action));
            HttpResponse::Ok().json(RollbackAck {
                ok: true, action: action.into(), restored_from: None,
            })
        }
        "committed" => {
            // Find the newest .bak file alongside the active secret.
            let dir = Path::new(&active).parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| Path::new("/etc/wolfstack").to_path_buf());
            let base = Path::new(&active).file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("custom-cluster-secret");
            let bak_prefix = format!("{}{}", base, BACKUP_SUFFIX_PREFIX);
            let mut candidates: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
                .map(|rd| rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with(&bak_prefix))
                        .unwrap_or(false))
                    .collect())
                .unwrap_or_default();
            // Sort lexicographically; backups use yyyymmddHHMMSS so
            // string order matches chronological order.
            candidates.sort();
            let newest = match candidates.last() {
                Some(p) => p.clone(),
                None => {
                    audit(&format!("ROLLBACK_NO_BACKUP initiator={}", body.initiated_by));
                    return HttpResponse::Conflict().json(serde_json::json!({
                        "error": "no .bak file found to restore from",
                        "hint": "manual recovery required — restore /etc/wolfstack/custom-cluster-secret from your backup"
                    }));
                }
            };
            let newest_str = newest.to_string_lossy().to_string();
            if let Err(e) = std::fs::copy(&newest, &active) {
                audit(&format!("ROLLBACK_RESTORE_FAIL initiator={} from={} err={}",
                               body.initiated_by, newest_str, e));
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("could not restore from backup: {}", e),
                    "backup": newest_str,
                }));
            }
            audit(&format!("ROLLBACK_RESTORED initiator={} from={}",
                           body.initiated_by, newest_str));
            HttpResponse::Ok().json(RollbackAck {
                ok: true,
                action: "restored-from-backup".into(),
                restored_from: Some(newest_str),
            })
        }
        other => {
            HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("invalid stage '{}' — expected 'pending' or 'committed'", other)
            }))
        }
    }
}

// ─── Coordinator (operator-facing) ──────────────────────────────

/// POST /api/cluster/secret/coordinated-rotate — single-call
/// orchestration of the full Stage 3 rotation protocol, suitable for
/// calling from the dashboard UI. Runs every safety step in order
/// and returns a per-peer report; partial failures auto-rollback.
///
/// Auth: operator session ONLY (no peer-driven rotations). Even an
/// attacker with the cluster secret cannot trigger this — it requires
/// a logged-in user. Distinct from the older fleet-wide rotation
/// at /api/fleet/security/rotate-cluster-secret which is one-shot
/// without the preflight / ACK / rollback safety net.
pub async fn api_coordinated_rotate(
    req: HttpRequest,
    state: web::Data<crate::api::AppState>,
) -> HttpResponse {
    let operator = match req.cookie("wolfstack_session")
        .and_then(|c| state.sessions.validate_info(c.value()))
    {
        Some(s) if s.read_only => return crate::api::read_only_forbidden("rotating the cluster secret"),
        Some(s) => s.username,
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "coordinated rotation must be initiated by an operator session"
            }));
        }
    };

    // H3: refuse if another rotation is already in flight on this
    // node. The guard releases on drop (panic-safe).
    let _rotation_guard = match try_acquire_rotation_lock() {
        Some(g) => g,
        None => {
            audit(&format!("ORCHESTRATE_BUSY operator={}", operator));
            return HttpResponse::Conflict().json(serde_json::json!({
                "error": "another rotation is already in progress on this node — \
                          wait for it to complete (check Settings → Security status), \
                          then retry"
            }));
        }
    };

    // C2: refuse if the coordinator's in-memory secret no longer
    // matches the on-disk secret. That means a previous rotation
    // committed but this node was never restarted, so its outbound
    // calls are signed with the OLD secret while restarted peers
    // expect the NEW secret. A second rotation from this stale
    // coordinator would fail all peer auth. The operator must
    // restart wolfstack on this node first.
    let on_disk = crate::auth::load_cluster_secret();
    if on_disk != state.cluster_secret {
        audit(&format!("ORCHESTRATE_STALE_COORDINATOR operator={}", operator));
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": "this coordinator node has a pending committed secret \
                      that needs a restart to take effect. Restart wolfstack \
                      on THIS node first (the new secret is already on disk), \
                      then retry rotation from the restarted coordinator.",
            "hint": "Stage 3 protocol commits new secrets to disk but never \
                    live-swaps the in-memory value; a coordinator must be \
                    restarted between rotations so its outbound calls are \
                    signed with the latest secret."
        }));
    }

    let self_id = state.cluster.self_id.clone();
    let peers: Vec<crate::agent::Node> = {
        let n = state.cluster.nodes_read();
        n.values()
            .filter(|p| p.id != self_id && p.node_type == "wolfstack")
            .cloned()
            .collect()
    };
    let old_secret = state.cluster_secret.clone();

    // Reuse the existing reqwest client builder pattern; short timeouts
    // so a hung peer doesn't stall the whole rotation.
    let client = match reqwest::Client::builder()
        // Bound the CONNECT, not just the request: a SYN to an
        // unroutable host holds a descriptor for the kernel's full
        // retry window (~130s). Enforced by tests/resource_safety.rs
        // after the 2026-08-05 fd-exhaustion outage.
        .connect_timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("client build: {}", e),
        })),
    };

    // Step 1: PREFLIGHT every peer. If any peer is unreachable or on
    // a version that doesn't understand the protocol, abort before
    // touching any state.
    let mut preflight_results = Vec::new();
    for node in &peers {
        let urls = crate::api::build_node_urls(&node.address, node.port,
            "/api/cluster/secret/rotate-preflight");
        let mut ok = false;
        let mut detail = String::new();
        let mut got_version: Option<u32> = None;
        for url in &urls {
            let r = client.post(url)
                .peer_auth(&old_secret)
                .send().await;
            match r {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(ack) = resp.json::<PreflightAck>().await {
                        got_version = Some(ack.protocol_version);
                        ok = ack.protocol_version == PROTOCOL_VERSION;
                        if !ok {
                            detail = format!("peer protocol v{} != coordinator v{}",
                                             ack.protocol_version, PROTOCOL_VERSION);
                        }
                    }
                    break;
                }
                Ok(resp) => { detail = format!("HTTP {}", resp.status()); }
                Err(e) => { detail = format!("transport: {}", e); }
            }
        }
        preflight_results.push(serde_json::json!({
            "node_id": node.id,
            "hostname": node.hostname,
            "address": node.address,
            "ok": ok,
            "protocol_version": got_version,
            "detail": detail,
        }));
    }
    let preflight_failed = preflight_results.iter()
        .filter(|r| r["ok"].as_bool() != Some(true)).count();
    if preflight_failed > 0 {
        audit(&format!("ORCHESTRATE_PREFLIGHT_ABORT operator={} failed={}/{}",
                       operator, preflight_failed, preflight_results.len()));
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": format!("{} of {} peer(s) failed preflight — rotation aborted, no changes made",
                             preflight_failed, preflight_results.len()),
            "preflight": preflight_results,
            "stage": "preflight",
        }));
    }

    // Step 2: GENERATE new secret. Locally only — peers don't know yet.
    let new_secret = crate::auth::generate_cluster_secret();
    let fingerprint = sha256_hex(new_secret.as_bytes());

    // Step 3: RECEIVE — push to every peer. If any fail, rollback all
    // that succeeded (delete their .pending) before returning.
    let mut receive_ok = Vec::new();
    let mut receive_fail = Vec::new();
    for node in &peers {
        let urls = crate::api::build_node_urls(&node.address, node.port,
            "/api/cluster/secret/rotate-receive");
        let body = serde_json::json!({
            "new_secret": new_secret,
            "fingerprint": fingerprint,
            "initiated_by": self_id,
        });
        let mut ok = false;
        let mut detail = String::new();
        for url in &urls {
            let r = client.post(url)
                .peer_auth(&old_secret)
                .json(&body)
                .send().await;
            match r {
                Ok(resp) if resp.status().is_success() => { ok = true; break; }
                Ok(resp) => { detail = format!("HTTP {}", resp.status()); }
                Err(e) => { detail = format!("transport: {}", e); }
            }
        }
        if ok {
            receive_ok.push(node.clone());
        } else {
            receive_fail.push(serde_json::json!({
                "node_id": node.id, "hostname": node.hostname,
                "address": node.address, "detail": detail,
            }));
        }
    }
    if !receive_fail.is_empty() {
        // Roll back the .pending file on every peer that DID accept.
        for node in &receive_ok {
            let urls = crate::api::build_node_urls(&node.address, node.port,
                "/api/cluster/secret/rotate-rollback");
            let body = serde_json::json!({
                "initiated_by": self_id, "stage": "pending",
            });
            for url in &urls {
                if client.post(url)
                    .peer_auth(&old_secret)
                    .json(&body).send().await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false)
                { break; }
            }
        }
        // And on self.
        let _ = std::fs::remove_file(pending_path());
        audit(&format!("ORCHESTRATE_RECEIVE_ABORT operator={} fail_count={} \
                        rolled_back_pending={}",
                       operator, receive_fail.len(), receive_ok.len()));
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": format!("{} of {} peer(s) failed to receive the new secret — \
                              rotation rolled back, no secrets committed",
                             receive_fail.len(), peers.len()),
            "failures": receive_fail,
            "stage": "receive",
        }));
    }

    // Step 3b: write the .pending on self as well. We do this AFTER
    // the peer fan-out so a local fs failure doesn't leave peers with
    // a .pending that won't get committed.
    if let Err(e) = crate::paths::write_secure(&pending_path(), &new_secret) {
        // Roll back peers.
        for node in &receive_ok {
            let urls = crate::api::build_node_urls(&node.address, node.port,
                "/api/cluster/secret/rotate-rollback");
            let body = serde_json::json!({
                "initiated_by": self_id, "stage": "pending",
            });
            for url in &urls {
                if client.post(url)
                    .peer_auth(&old_secret)
                    .json(&body).send().await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false)
                { break; }
            }
        }
        audit(&format!("ORCHESTRATE_SELF_PENDING_FAIL operator={} err={}",
                       operator, e));
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("could not write self .pending: {} — peers rolled back", e),
            "stage": "receive-self",
        }));
    }

    // Step 4: COMMIT every peer + self. If any peer commit fails,
    // attempt rollback on those that succeeded.
    let mut commit_ok = Vec::new();
    let mut commit_fail = Vec::new();
    let commit_body = serde_json::json!({
        "fingerprint": fingerprint,
        "initiated_by": self_id,
    });
    for node in &peers {
        let urls = crate::api::build_node_urls(&node.address, node.port,
            "/api/cluster/secret/rotate-commit");
        let mut ok = false;
        let mut detail = String::new();
        for url in &urls {
            let r = client.post(url)
                .peer_auth(&old_secret)
                .json(&commit_body)
                .send().await;
            match r {
                Ok(resp) if resp.status().is_success() => { ok = true; break; }
                Ok(resp) => { detail = format!("HTTP {}", resp.status()); }
                Err(e) => { detail = format!("transport: {}", e); }
            }
        }
        if ok { commit_ok.push(node.clone()); }
        else {
            commit_fail.push(serde_json::json!({
                "node_id": node.id, "hostname": node.hostname,
                "address": node.address, "detail": detail,
            }));
        }
    }
    if !commit_fail.is_empty() {
        // Best-effort: try to roll back peers that DID commit. They
        // now have new on-disk; the rollback restores from .bak.
        for node in &commit_ok {
            let urls = crate::api::build_node_urls(&node.address, node.port,
                "/api/cluster/secret/rotate-rollback");
            let body = serde_json::json!({
                "initiated_by": self_id, "stage": "committed",
            });
            for url in &urls {
                if client.post(url)
                    .peer_auth(&old_secret)
                    .json(&body).send().await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false)
                { break; }
            }
        }
        // Re-review MEDIUM: clean up the coordinator's own .pending
        // file too. Self-commit hasn't run yet (it's below this block),
        // so the .pending written in step 3b is still on disk. Without
        // this, a subsequent api_rotate_propose silently overwrites it
        // but leaves forensic ambiguity ("was this stale or fresh?").
        // Mirrors the receive-abort cleanup at the top of step 3.
        let _ = std::fs::remove_file(pending_path());
        audit(&format!("ORCHESTRATE_COMMIT_ABORT operator={} fail_count={} \
                        attempted_rollback_committed={} self_pending_cleaned",
                       operator, commit_fail.len(), commit_ok.len()));
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": format!("{} of {} peer commit(s) failed — attempted rollback \
                              on the {} that succeeded. Verify per-peer state \
                              before assuming recovery is complete.",
                             commit_fail.len(), peers.len(), commit_ok.len()),
            "failures": commit_fail,
            "rolled_back_attempts": commit_ok.iter().map(|n| n.id.clone()).collect::<Vec<_>>(),
            "stage": "commit",
        }));
    }
    // Self commit — last, after every peer succeeded.
    let active = crate::paths::get().cluster_secret;
    let pending = pending_path();
    let backup = format!("{}{}{}", active, BACKUP_SUFFIX_PREFIX, now_compact());
    if Path::new(&active).exists()
        && let Err(e) = std::fs::copy(&active, &backup) {
            // M2 fix: include the pending-file path in both the audit
            // log and the operator response. The .pending file is
            // intentionally LEFT on disk in this branch — it's the
            // operator's recovery anchor: they can manually
            // `cp <pending> <active>` to complete the rotation. Don't
            // delete it.
            audit(&format!("ORCHESTRATE_SELF_BACKUP_FAIL operator={} err={} \
                            pending_left_on_disk={}",
                           operator, e, pending));
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("self backup failed: {}. Peers have committed; \
                                  self is still on the old secret. \
                                  Recovery: `sudo cp {} {}` on this node \
                                  (the pending file is the new secret), then \
                                  restart wolfstack.",
                                 e, pending, active),
                "pending_file": pending,
                "stage": "commit-self-backup",
            }));
        }
    if let Err(e) = std::fs::rename(&pending, &active) {
        audit(&format!("ORCHESTRATE_SELF_RENAME_FAIL operator={} err={} \
                        pending_left_on_disk={}",
                       operator, e, pending));
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("self rename failed: {}. Peers have committed; \
                              self is still on the old secret. \
                              Recovery: `sudo mv {} {}` on this node, then \
                              restart wolfstack.", e, pending, active),
            "pending_file": pending,
            "stage": "commit-self-rename",
        }));
    }
    // H5 + H4 — keep the external wolfusb daemon aligned and prune
    // backups beyond the retention cap on the coordinator too.
    crate::auth::realign_wolfusb_env_after_rotation(&new_secret);
    let _ = prune_old_backups(&active);

    // Re-key the coordinator's own at-rest secrets from old→new (the
    // secret is the at-rest encryption key). Best-effort: a failure is
    // logged inside the orchestrator and does NOT fail the rotation —
    // the new secret has already committed on every node, and any store
    // that failed is left intact with its plaintext re-enter prompt.
    // No-op if old == new.
    let reencrypt_report = {
        // Re-key off the actix worker — multi-file blocking I/O.
        let old = old_secret.clone();
        let news = new_secret.clone();
        web::block(move || reencrypt_all_at_rest(&old, &news))
            .await
            .unwrap_or_default()
    };
    audit(&format!("ORCHESTRATE_REENCRYPT operator={} rekeyed_total={} store_errors={}",
                   operator, reencrypt_report.total(), reencrypt_report.errors.len()));

    audit(&format!("ORCHESTRATE_OK operator={} fingerprint={} peer_count={}",
                   operator, fingerprint, peers.len()));
    // Re-review LOW: only report a self_backup path if one actually
    // exists on disk. On a first-ever rotation (where the active file
    // was created by the rename, not pre-existing) no backup was made,
    // and the variable holds a path that points to nothing. Returning
    // an empty string here lets the UI show "(none)" rather than a
    // fake recovery path that would mislead an operator under pressure.
    let backup_reported = if Path::new(&backup).exists() {
        backup
    } else {
        String::new()
    };
    HttpResponse::Ok().json(serde_json::json!({
        "ok": true,
        "fingerprint": fingerprint,
        "new_secret": new_secret,
        "peer_count": peers.len(),
        "self_backup": backup_reported,
        "at_rest_reencrypt": reencrypt_report,
        "restart_required": true,
        "important": "Coordinated rotation complete. Copy the new_secret to a \
                      password manager NOW — this is the only time it will be \
                      shown. Restart wolfstack on every node when convenient. \
                      Until restart, BOTH the old and new secret are accepted \
                      (require_auth checks both in-memory and on-disk values), \
                      so cluster operations continue uninterrupted.",
    }))
}

// ─── At-rest credential migration (v1 XOR → v2 AES-256-GCM) ──────

/// Log helper shared by the startup migration sweep — only emits when something
/// actually changed or errored, so a fully-migrated install stays quiet.
fn log_startup_migrate(store: &str, result: Result<(usize, usize, usize), String>) {
    match result {
        Ok((migrated, _already, errored)) => {
            if errored > 0 {
                // An entry that failed to migrate stays XOR-obfuscated and the
                // High "legacy XOR" finding won't clear for it — surface at warn
                // so it isn't buried in info. Retry via the manual migrate button.
                tracing::warn!(target: "secret_rotation",
                    "startup at-rest migrate {}: migrated={} errored={} — the errored \
                     entr{} still uses legacy obfuscation; retry via 'Migrate at-rest \
                     credentials to AES'",
                    store, migrated, errored, if errored == 1 { "y" } else { "ies" });
            } else if migrated > 0 {
                tracing::info!(target: "secret_rotation",
                    "startup at-rest migrate {}: migrated={}", store, migrated);
            }
        }
        Err(e) => tracing::warn!(target: "secret_rotation",
            "startup at-rest migrate {} failed: {}", store, e),
    }
}

/// Migrate every at-rest credential store from legacy v1 (XOR, static baked-in
/// key) to v2 (AES-256-GCM keyed off the per-install cluster secret) at process
/// startup. This is what actually closes the High "legacy XOR" audit findings on
/// upgraded installs — the crypto and the per-store `migrate_to_v2` already
/// existed, but nothing ran them, so credentials stayed XOR-obfuscated until an
/// operator happened to press the manual migrate button. Running it at boot
/// (like the other legacy migrations in main.rs) fixes it for EVERYONE.
///
/// Safe on every boot: each `migrate_to_v2` is idempotent (skips entries already
/// v2), writes a one-time `<path>.bak.<ts>` before rewriting a file that still
/// holds v1 entries, and only saves when it migrated something. Both v1 and v2
/// decrypt forever, so a partial failure never breaks credential lookups. A
/// no-op on fresh installs (no v1 entries) and on already-migrated installs.
///
/// MUST be called after `at_rest_crypto::init` — otherwise `encrypt` falls back
/// to v1 and nothing is upgraded.
pub fn run_startup_at_rest_migration() {
    log_startup_migrate("dns-providers",
        crate::dns_providers::DnsProviderStore::load().migrate_to_v2());
    log_startup_migrate("cloud-providers",
        crate::edge::CloudProviderStore::load().migrate_to_v2());
    log_startup_migrate("xo-pools",
        crate::xo::XoStore::load().migrate_to_v2());
}

/// POST /api/security/migrate-at-rest-credentials — operator-triggered
/// one-shot that re-encrypts every v1-XOR-format stored credential
/// (DNS providers, cloud providers, XO tokens) to v2 AES-256-GCM
/// keyed off the per-install cluster secret.
///
/// **Safe by design.** Each store backs up its file to
/// `<path>.bak.<ts>` BEFORE saving. If a single store fails to migrate,
/// the other stores aren't touched. The read paths in every store
/// permanently support both v1 and v2, so a partial migration leaves
/// the system fully functional — operators can re-run the migration
/// after fixing whatever caused the failure.
///
/// Startup auto-migration (`run_startup_at_rest_migration`) now handles the
/// common case on every boot, so this endpoint is primarily the manual RETRY
/// path for entries that failed to migrate automatically (and an on-demand
/// re-run). Auth: operator session ONLY (not cluster-secret) — a peer node must
/// never be able to rewrite this node's local credential files; that rationale
/// still holds for the API even though the local boot-time migration does not
/// go through it.
pub async fn api_migrate_at_rest_credentials(
    req: HttpRequest,
    state: web::Data<crate::api::AppState>,
) -> HttpResponse {
    let operator = match req.cookie("wolfstack_session")
        .and_then(|c| state.sessions.validate_info(c.value()))
    {
        Some(s) if s.read_only => return crate::api::read_only_forbidden("migrating at-rest credentials"),
        Some(s) => s.username,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "at-rest credential migration must be initiated by an operator session"
        })),
    };

    // Each migration is independent — a failure in one store must not
    // prevent the others from being migrated. We surface per-store
    // results in the response so the operator can see exactly what
    // succeeded and what didn't.
    let mut results: Vec<serde_json::Value> = Vec::new();

    // C2/C3 — every store's `load → migrate_to_v2 → save` chain is a
    // sequence of std::fs operations on /etc/wolfstack/. Run them
    // inside web::block so a slow filesystem (NFS / degraded disk)
    // doesn't park an actix worker thread on the disk read for the
    // duration of the migration. Per-store isolation: a slow or
    // failed migration in one store doesn't queue behind the others.
    let dns_op = web::block(|| {
        let mut store = crate::dns_providers::DnsProviderStore::load();
        store.migrate_to_v2()
    }).await;
    let dns_result = match dns_op {
        Ok(Ok((migrated, already, errored))) => {
            audit(&format!("MIGRATE_DNS operator={} migrated={} already={} errored={}",
                           operator, migrated, already, errored));
            serde_json::json!({
                "store": "dns-providers",
                "ok": errored == 0,
                "migrated": migrated,
                "already_v2": already,
                "errored": errored,
            })
        }
        Ok(Err(e)) => {
            audit(&format!("MIGRATE_DNS_FAIL operator={} err={}", operator, e));
            serde_json::json!({ "store": "dns-providers", "ok": false, "error": e })
        }
        Err(e) => {
            audit(&format!("MIGRATE_DNS_BLOCKING_ERR operator={} err={}", operator, e));
            serde_json::json!({
                "store": "dns-providers", "ok": false,
                "error": format!("blocking pool error: {}", e)
            })
        }
    };
    results.push(dns_result);

    let cloud_op = web::block(|| {
        let mut store = crate::edge::CloudProviderStore::load();
        store.migrate_to_v2()
    }).await;
    let cloud_result = match cloud_op {
        Ok(Ok((migrated, already, errored))) => {
            audit(&format!("MIGRATE_CLOUD operator={} migrated={} already={} errored={}",
                           operator, migrated, already, errored));
            serde_json::json!({
                "store": "cloud-providers",
                "ok": errored == 0,
                "migrated": migrated,
                "already_v2": already,
                "errored": errored,
            })
        }
        Ok(Err(e)) => {
            audit(&format!("MIGRATE_CLOUD_FAIL operator={} err={}", operator, e));
            serde_json::json!({ "store": "cloud-providers", "ok": false, "error": e })
        }
        Err(e) => {
            audit(&format!("MIGRATE_CLOUD_BLOCKING_ERR operator={} err={}", operator, e));
            serde_json::json!({
                "store": "cloud-providers", "ok": false,
                "error": format!("blocking pool error: {}", e)
            })
        }
    };
    results.push(cloud_result);

    let xo_op = web::block(|| {
        let mut store = crate::xo::XoStore::load();
        store.migrate_to_v2()
    }).await;
    let xo_result = match xo_op {
        Ok(Ok((migrated, already, errored))) => {
            audit(&format!("MIGRATE_XO operator={} migrated={} already={} errored={}",
                           operator, migrated, already, errored));
            serde_json::json!({
                "store": "xo-pools",
                "ok": errored == 0,
                "migrated": migrated,
                "already_v2": already,
                "errored": errored,
            })
        }
        Ok(Err(e)) => {
            audit(&format!("MIGRATE_XO_FAIL operator={} err={}", operator, e));
            serde_json::json!({ "store": "xo-pools", "ok": false, "error": e })
        }
        Err(e) => {
            audit(&format!("MIGRATE_XO_BLOCKING_ERR operator={} err={}", operator, e));
            serde_json::json!({
                "store": "xo-pools", "ok": false,
                "error": format!("blocking pool error: {}", e)
            })
        }
    };
    results.push(xo_result);

    let any_fail = results.iter().any(|r| r["ok"].as_bool() == Some(false));
    let total_migrated: u64 = results.iter()
        .filter_map(|r| r["migrated"].as_u64()).sum();
    // W4 fix: HTTP 207 Multi-Status on partial failure so scripted
    // callers (curl, monitoring) see the failure in the status line.
    // The body still carries per-store detail for the UI to render.
    let body = serde_json::json!({
        "ok": !any_fail,
        "total_migrated": total_migrated,
        "stores": results,
        "note": "Per-store backups written to <path>.bak.<ts> on this node. \
                 v1 and v2 formats are both readable forever, so a partial \
                 failure does not break credential lookups — you can re-run \
                 this migration after fixing whatever failed.",
    });
    if any_fail {
        HttpResponse::MultiStatus().json(body)
    } else {
        HttpResponse::Ok().json(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A freshly-generated cluster secret — exactly `wsk_` + 64 lowercase
    /// hex chars (the shape `auth::generate_cluster_secret()` produces:
    /// 32 random bytes → 64 hex). The pre-existing built-in default at
    /// `auth::CLUSTER_SECRET` is mis-typed (only 62 hex) but is never
    /// sent through the rotation protocol — only newly-generated values
    /// flow through `valid_secret_shape`, so the validator's strict
    /// 64-hex check is correct.
    const CANONICAL: &str =
        "wsk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn valid_secret_shape_accepts_canonical() {
        // sanity: this string has exactly the shape generate_cluster_secret() emits
        assert_eq!(CANONICAL.len(), 4 + 64);
        assert!(valid_secret_shape(CANONICAL));
    }

    #[test]
    fn valid_secret_shape_rejects_uppercase() {
        // Lowercase-only by convention — keeps generated values byte-
        // identical across nodes regardless of who hex-printed them.
        let upper = format!("wsk_{}", CANONICAL[4..].to_uppercase());
        assert!(!valid_secret_shape(&upper));
    }

    #[test]
    fn valid_secret_shape_rejects_wrong_prefix_or_length() {
        assert!(!valid_secret_shape("ws_abcdef"));
        assert!(!valid_secret_shape("wsk_short"));
        assert!(!valid_secret_shape(""));
        assert!(!valid_secret_shape("wsk_ZZZZ"));
        // 62 hex chars (the count of the built-in default) — rejected
        // because the generator outputs 64. Catches drift between the
        // default constant and what generate_cluster_secret() produces.
        assert!(!valid_secret_shape("wsk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"));
    }

    #[test]
    fn fingerprint_matches_generator_output() {
        let fp = sha256_hex(CANONICAL.as_bytes());
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn generator_produces_validatable_shape() {
        // The single most important invariant: anything `auth::generate_cluster_secret`
        // produces must pass `valid_secret_shape`. If this ever fails, the
        // rotation protocol bricks itself — coordinator generates a secret
        // and then refuses to push it.
        for _ in 0..16 {
            let s = crate::auth::generate_cluster_secret();
            assert!(valid_secret_shape(&s),
                "generate_cluster_secret() produced an invalid shape: {:?}", s);
        }
    }

    #[test]
    fn pending_path_distinct_from_active() {
        let active = crate::paths::get().cluster_secret;
        let pending = pending_path();
        assert_ne!(active, pending);
        assert!(pending.ends_with(PENDING_SUFFIX));
    }
}
