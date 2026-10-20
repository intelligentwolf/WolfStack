// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! OAuth 2.1 authorization server for the MCP endpoint.
//!
//! WolfStack is both the authorization server and the resource server, so
//! tokens are opaque random strings looked up here — never JWTs another
//! service could mint or accept. Only SHA-256 hashes of codes and tokens are
//! held, in memory and on disk, so a leaked state file or memory dump yields
//! nothing usable.
//!
//! Lifetimes (MCP authorization spec, "Token Theft": short-lived access
//! tokens; refresh tokens rotated for public clients):
//! * authorization code — 60 s, single use, bound to client, redirect URI,
//!   PKCE S256 challenge and resource; replaying a used code revokes the
//!   grant it produced (OAuth 2.1 §4.1.3);
//! * access token — 15 min, in memory only (a restart forces a refresh);
//! * refresh token — 30 days sliding, never past 90 days from approval,
//!   rotated on every use; presenting a retired one is treated as theft and
//!   revokes the whole grant (except within a few seconds of its rotation,
//!   which is an honest client retrying a request whose answer it lost).
//!
//! Every change to persisted state is made on a copy, written to disk, and
//! only then made live — a failed write can never leave a revocation that
//! the next restart silently undoes. The user lookup (file reads) always
//! happens outside the store lock.
//!
//! Client registration is RFC 7591 dynamic registration only. Client ID
//! Metadata Documents are deliberately NOT supported: they make the server
//! fetch an attacker-chosen URL (SSRF), and the spec makes them a SHOULD.
//! A registered client can do nothing until a WolfStack user signs in and
//! approves it on the consent page.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Scopes a token can carry. Names match the API-key scopes so one
/// vocabulary covers both. `read` is the minimal set advertised in the
/// protected-resource metadata; the others are requested by step-up.
/// `logs` is separate from `read` because container logs can hold
/// secrets and attacker-written text, and they go to a third-party model.
pub const ALL_SCOPES: [&str; 5] = ["read", "logs", "containers", "vms", "backup"];
/// What a read-only account may grant: reading, never acting.
pub const READ_ONLY_SCOPES: [&str; 2] = ["read", "logs"];

pub const CODE_TTL_SECS: i64 = 60;
pub const ACCESS_TTL_SECS: i64 = 15 * 60;
pub const REFRESH_TTL_SECS: i64 = 30 * 24 * 3600;
/// However often it is refreshed, a grant ends this long after approval.
pub const GRANT_MAX_LIFETIME_SECS: i64 = 90 * 24 * 3600;
/// A consent page left open longer than this must be restarted.
pub const PENDING_TTL_SECS: i64 = 10 * 60;
/// A registered client nobody ever approved is garbage after a day.
pub const UNUSED_CLIENT_TTL_SECS: i64 = 24 * 3600;
/// A retired refresh token presented this soon after its rotation is a
/// client retrying a request whose response it lost — refused, but the
/// grant is not revoked.
const REFRESH_RETRY_GRACE_SECS: i64 = 10;
/// Used authorization codes are remembered this long to catch replays.
const USED_CODE_MEMORY_SECS: i64 = 10 * 60;

const MAX_CLIENTS: usize = 200;
const MAX_GRANTS: usize = 1000;
const MAX_PENDING: usize = 500;
const MAX_PENDING_PER_CLIENT: usize = 10;
/// Per requester (rate-limit key): registering many clients from one
/// address doesn't buy more of the shared pool.
const MAX_PENDING_PER_SOURCE: usize = 20;
const MAX_CODES: usize = 500;
const MAX_ACCESS_TOKENS: usize = 5000;
const MAX_REDIRECT_URIS: usize = 5;
const MAX_REDIRECT_URI_LEN: usize = 512;
const MAX_CLIENT_NAME_LEN: usize = 80;
const MAX_STATE_LEN: usize = 512;
/// Retired refresh hashes kept per grant for reuse (theft) detection.
const RETIRED_REFRESH_KEEP: usize = 20;

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// 256 bits from the OS CSPRNG, base64url without padding, with a prefix
/// naming what it is (so a token pasted into the wrong field is obvious
/// and secret scanners can recognise it).
pub fn random_token(prefix: &str) -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("{}{}", prefix, base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Storage key for a secret. Domain-separated so a code hash can never be
/// confused with a token hash even if the raw values collided.
fn secret_hash(kind: &str, secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"wolfstack-mcp-oauth\0");
    h.update(kind.as_bytes());
    h.update(b"\0");
    h.update(secret.as_bytes());
    hex::encode(h.finalize())
}

/// RFC 7636 §4.1: 43-128 chars from the unreserved set.
fn valid_code_verifier(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// S256: BASE64URL(SHA256(ASCII(code_verifier))) == code_challenge,
/// compared in constant time.
pub fn pkce_s256_matches(verifier: &str, challenge: &str) -> bool {
    if !valid_code_verifier(verifier) {
        return false;
    }
    let digest = Sha256::digest(verifier.as_bytes());
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    computed.as_bytes().ct_eq(challenge.as_bytes()).into()
}

/// A code_challenge from the client must look like an S256 output
/// (43 base64url chars) — anything else can never verify.
pub fn valid_code_challenge(c: &str) -> bool {
    c.len() == 43 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// MCP "Communication Security": every redirect URI is HTTPS or loopback.
/// Exact-match only later, so this is the registration-time shape check.
pub fn validate_redirect_uri(raw: &str) -> Result<(), String> {
    if raw.is_empty() || raw.len() > MAX_REDIRECT_URI_LEN {
        return Err("redirect_uri must be 1-512 characters".into());
    }
    if raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("redirect_uri must not contain whitespace or control characters".into());
    }
    let url = url::Url::parse(raw).map_err(|e| format!("redirect_uri is not a valid URL: {}", e))?;
    if url.fragment().is_some() {
        return Err("redirect_uri must not contain a fragment".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("redirect_uri must not contain credentials".into());
    }
    let host = url.host_str().unwrap_or("");
    if host.is_empty() {
        return Err("redirect_uri must have a host".into());
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(host) => Ok(()),
        "http" => Err("http redirect URIs are only allowed for localhost / 127.0.0.1 / [::1]".into()),
        other => Err(format!("redirect URI scheme '{}' is not allowed (https or loopback http only)", other)),
    }
}

pub fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

/// Invisible / direction-changing characters that let a name render as
/// something other than what it is (e.g. U+202E RIGHT-TO-LEFT OVERRIDE).
fn is_spoofing_char(c: char) -> bool {
    matches!(c,
        '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

/// Client-supplied display name: printable, single line, bounded, no
/// direction overrides or invisible characters. It is shown on the
/// consent page as UNVERIFIED — a client can call itself anything, so the
/// redirect address is what the user is told to check.
pub fn sanitize_client_name(raw: Option<&str>) -> String {
    let cleaned: String = raw.unwrap_or("")
        .chars()
        .filter(|c| !is_spoofing_char(*c))
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let truncated: String = cleaned.chars().take(MAX_CLIENT_NAME_LEN).collect();
    if truncated.is_empty() { "Unnamed client".to_string() } else { truncated }
}

/// Parse a space-delimited scope string. Unknown scopes are an error
/// (invalid_scope) rather than silently dropped, so a client never
/// believes it holds something it does not. Empty → `read`.
pub fn parse_scopes(raw: Option<&str>) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for s in raw.unwrap_or("").split(' ').filter(|s| !s.is_empty()) {
        if !ALL_SCOPES.contains(&s) {
            return Err(format!("unknown scope '{}'", s));
        }
        if !out.iter().any(|o| o == s) {
            out.push(s.to_string());
        }
    }
    if out.is_empty() {
        out.push("read".to_string());
    }
    Ok(normalize_scopes(out))
}

/// Canonical order (ALL_SCOPES order) so stored and compared scope lists
/// are stable.
pub fn normalize_scopes(scopes: Vec<String>) -> Vec<String> {
    ALL_SCOPES.iter()
        .filter(|s| scopes.iter().any(|x| x == *s))
        .map(|s| s.to_string())
        .collect()
}

pub fn scopes_string(scopes: &[String]) -> String {
    scopes.join(" ")
}

/// Which account store proved the user's identity. Authority is always
/// re-read from the SAME store, so a Linux login can never pick up the
/// rights of a WolfStack user who happens to share its name (or vice
/// versa).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthSource {
    WolfStack,
    Linux,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub created_at: i64,
    /// Set the first time a user approves this client. Unapproved
    /// clients are pruned after UNUSED_CLIENT_TTL_SECS.
    #[serde(default)]
    pub approved_at: Option<i64>,
    #[serde(default)]
    pub registered_from: String,
}

/// A user's standing approval for one client: what the refresh token
/// renews. Persisted (hashes only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    pub username: String,
    pub source: AuthSource,
    /// What the user approved. A narrowed refresh narrows the token, not
    /// this, so a later refresh can still use everything approved.
    pub scopes: Vec<String>,
    pub resource: String,
    pub created_at: i64,
    pub last_used_at: i64,
    refresh_hash: String,
    refresh_expires_at: i64,
    #[serde(default)]
    retired_refresh_hashes: Vec<String>,
    #[serde(default)]
    last_rotated_at: i64,
    /// UserAuthority::credential_fp when the grant was made.
    credential_fp: String,
}

/// Public, secret-free view of a grant for the settings UI.
#[derive(Debug, Clone, Serialize)]
pub struct GrantView {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    pub username: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub last_used_at: i64,
    pub expires_at: i64,
}

/// Everything the consent page validated, held server-side so the form
/// POST cannot alter it. The id is the only thing the browser carries
/// and doubles as the CSRF token (256-bit, single use, short-lived).
#[derive(Debug, Clone)]
pub struct PendingAuth {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub code_challenge: String,
    pub scopes: Vec<String>,
    pub resource: String,
    pub created_at: i64,
    /// Rate-limit key of whoever opened the consent page.
    pub from: String,
}

#[derive(Debug, Clone)]
struct AuthCode {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    scopes: Vec<String>,
    resource: String,
    username: String,
    source: AuthSource,
    expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct AccessInfo {
    pub credential_fp: String,
    pub grant_id: String,
    pub client_id: String,
    pub username: String,
    pub source: AuthSource,
    pub scopes: Vec<String>,
    pub resource: String,
    pub expires_at: i64,
}

/// What a successful token request returns.
#[derive(Debug, Clone, Serialize)]
pub struct TokenSet {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub refresh_token: String,
    pub scope: String,
}

/// RFC 6749 §5.2 error codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    InvalidRequest(String),
    InvalidClient(String),
    InvalidGrant(String),
    InvalidScope(String),
    InvalidTarget(String),
    ServerError(String),
}

/// A failed state write surfaces as a server error.
impl From<String> for TokenError {
    fn from(e: String) -> Self {
        TokenError::ServerError(e)
    }
}

impl TokenError {
    pub fn code(&self) -> &'static str {
        match self {
            TokenError::InvalidRequest(_) => "invalid_request",
            TokenError::InvalidClient(_) => "invalid_client",
            TokenError::InvalidGrant(_) => "invalid_grant",
            TokenError::InvalidScope(_) => "invalid_scope",
            TokenError::InvalidTarget(_) => "invalid_target",
            TokenError::ServerError(_) => "server_error",
        }
    }
    pub fn description(&self) -> &str {
        match self {
            TokenError::InvalidRequest(s) | TokenError::InvalidClient(s)
            | TokenError::InvalidGrant(s) | TokenError::InvalidScope(s)
            | TokenError::InvalidTarget(s) | TokenError::ServerError(s) => s,
        }
    }
}

/// The current authority of a user, re-read on every refresh and (via
/// `mcp::http`) every request, so a deleted or demoted account loses
/// access immediately.
#[derive(Debug, Clone)]
pub struct UserAuthority {
    /// Scopes this user may hold right now.
    pub allowed_scopes: Vec<String>,
    /// Digest of the account's current credentials (password hash + TOTP
    /// secret, or the Linux shadow hash). Grants record it; a mismatch
    /// means the password or 2FA changed — on ANY node, since users
    /// replicate — and the grant is dead.
    pub credential_fp: String,
}

#[derive(Default, Serialize, Deserialize)]
struct Persisted {
    #[serde(default)]
    clients: Vec<Client>,
    #[serde(default)]
    grants: Vec<Grant>,
}

#[derive(Default, Clone)]
struct Inner {
    clients: HashMap<String, Client>,
    grants: HashMap<String, Grant>,
    /// refresh-token hash → grant id (current tokens only)
    refresh_index: HashMap<String, String>,
    /// retired refresh hash → grant id (theft detection)
    retired_index: HashMap<String, String>,
    codes: HashMap<String, AuthCode>,
    /// used code hash → (grant id it produced, forget-after time)
    used_codes: HashMap<String, (String, i64)>,
    access: HashMap<String, AccessInfo>,
    pending: HashMap<String, PendingAuth>,
}

impl Inner {
    fn rebuild_indexes(&mut self) {
        self.refresh_index.clear();
        self.retired_index.clear();
        for g in self.grants.values() {
            self.refresh_index.insert(g.refresh_hash.clone(), g.id.clone());
            for r in &g.retired_refresh_hashes {
                self.retired_index.insert(r.clone(), g.id.clone());
            }
        }
    }

    fn remove_grant(&mut self, grant_id: &str) -> Option<Grant> {
        let g = self.grants.remove(grant_id)?;
        self.refresh_index.remove(&g.refresh_hash);
        for r in &g.retired_refresh_hashes {
            self.retired_index.remove(r);
        }
        self.access.retain(|_, a| a.grant_id != grant_id);
        Some(g)
    }

    fn prune(&mut self, t: i64) {
        self.codes.retain(|_, c| c.expires_at > t);
        self.used_codes.retain(|_, (_, until)| *until > t);
        self.access.retain(|_, a| a.expires_at > t);
        self.pending.retain(|_, p| p.created_at + PENDING_TTL_SECS > t);
        let expired: Vec<String> = self.grants.values()
            .filter(|g| g.refresh_expires_at <= t)
            .map(|g| g.id.clone())
            .collect();
        for id in expired {
            self.remove_grant(&id);
        }
        let in_use: std::collections::HashSet<&String> =
            self.grants.values().map(|g| &g.client_id).collect();
        let stale: Vec<String> = self.clients.values()
            .filter(|c| c.approved_at.is_none()
                && c.created_at + UNUSED_CLIENT_TTL_SECS <= t
                && !in_use.contains(&c.client_id))
            .map(|c| c.client_id.clone())
            .collect();
        for id in stale {
            self.clients.remove(&id);
        }
    }

    fn snapshot(&self) -> Persisted {
        let mut clients: Vec<Client> = self.clients.values().cloned().collect();
        clients.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.client_id.cmp(&b.client_id)));
        let mut grants: Vec<Grant> = self.grants.values().cloned().collect();
        grants.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        Persisted { clients, grants }
    }

    fn issue_access(&mut self, grant: &Grant, scopes: &[String], t: i64) -> (String, i64) {
        let token = random_token("wsat_");
        self.access.insert(secret_hash("access", &token), AccessInfo {
            credential_fp: grant.credential_fp.clone(),
            grant_id: grant.id.clone(),
            client_id: grant.client_id.clone(),
            username: grant.username.clone(),
            source: grant.source,
            scopes: scopes.to_vec(),
            resource: grant.resource.clone(),
            expires_at: t + ACCESS_TTL_SECS,
        });
        (token, ACCESS_TTL_SECS)
    }

    /// Make room for one more client: drop the oldest never-approved
    /// client without grants. False when every slot is genuinely in use.
    fn evict_unapproved_client(&mut self) -> bool {
        let in_use: std::collections::HashSet<String> =
            self.grants.values().map(|g| g.client_id.clone()).collect();
        let victim = self.clients.values()
            .filter(|c| c.approved_at.is_none() && !in_use.contains(&c.client_id))
            .min_by_key(|c| c.created_at)
            .map(|c| c.client_id.clone());
        match victim {
            Some(id) => { self.clients.remove(&id); true }
            None => false,
        }
    }
}

pub struct OAuthStore {
    inner: Mutex<Inner>,
    /// None = in-memory only (tests).
    path: Option<String>,
}

impl OAuthStore {
    pub fn load(path: &str) -> Self {
        let persisted: Persisted = match std::fs::read_to_string(path) {
            Ok(s) => match serde_json::from_str(&s) {
                Ok(p) => p,
                Err(e) => {
                    // Keep the evidence instead of overwriting it with an
                    // empty store on the next write.
                    let aside = format!("{}.corrupt-{}", path, now());
                    tracing::error!("mcp oauth: {} is unreadable ({}); moved to {} — all MCP approvals must be redone", path, e, aside);
                    let _ = std::fs::rename(path, &aside);
                    Persisted::default()
                }
            },
            Err(_) => Persisted::default(),
        };
        let mut inner = Inner::default();
        for c in persisted.clients {
            inner.clients.insert(c.client_id.clone(), c);
        }
        for g in persisted.grants {
            inner.grants.insert(g.id.clone(), g);
        }
        inner.rebuild_indexes();
        OAuthStore { inner: Mutex::new(inner), path: Some(path.to_string()) }
    }

    #[cfg(test)]
    pub fn in_memory() -> Self {
        OAuthStore { inner: Mutex::new(Inner::default()), path: None }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Write clients + grants (hashes only) atomically, mode 0600.
    fn persist(&self, inner: &Inner) -> Result<(), String> {
        let Some(path) = &self.path else { return Ok(()) };
        let json = serde_json::to_string_pretty(&inner.snapshot()).map_err(|e| e.to_string())?;
        let tmp = format!("{}.tmp", path);
        crate::paths::write_secure(&tmp, json).map_err(|e| format!("write {}: {}", tmp, e))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("rename {}: {}", path, e))
    }

    /// Apply `f` to a copy of the state, persist the copy, and only then
    /// make it live. If `f` or the write fails, nothing changes.
    fn commit<R, E: From<String>>(
        &self, inner: &mut Inner, f: impl FnOnce(&mut Inner) -> Result<R, E>,
    ) -> Result<R, E> {
        let mut draft = inner.clone();
        let r = f(&mut draft)?;
        self.persist(&draft).map_err(E::from)?;
        *inner = draft;
        Ok(r)
    }

    /// RFC 7591 registration. Public clients only (no client secret):
    /// every MCP client is a native/desktop app that couldn't keep one.
    pub fn register_client(
        &self, client_name: Option<&str>, redirect_uris: &[String], from: &str,
    ) -> Result<Client, String> {
        if redirect_uris.is_empty() {
            return Err("redirect_uris is required".into());
        }
        if redirect_uris.len() > MAX_REDIRECT_URIS {
            return Err(format!("at most {} redirect_uris", MAX_REDIRECT_URIS));
        }
        for u in redirect_uris {
            validate_redirect_uri(u)?;
        }
        let t = now();
        let mut inner = self.lock();
        inner.prune(t);
        let client = Client {
            client_id: random_token("wsc_"),
            client_name: sanitize_client_name(client_name),
            redirect_uris: redirect_uris.to_vec(),
            created_at: t,
            approved_at: None,
            registered_from: from.chars().take(64).collect(),
        };
        self.commit(&mut inner, |d| {
            if d.clients.len() >= MAX_CLIENTS && !d.evict_unapproved_client() {
                return Err("too many registered clients — remove unused ones in Settings → AI Agents (MCP)".to_string());
            }
            d.clients.insert(client.client_id.clone(), client.clone());
            Ok(())
        })?;
        Ok(client)
    }

    pub fn get_client(&self, client_id: &str) -> Option<Client> {
        self.lock().clients.get(client_id).cloned()
    }

    pub fn list_clients(&self) -> Vec<Client> {
        let mut inner = self.lock();
        inner.prune(now());
        inner.snapshot().clients
    }

    /// Remove a client and every grant it holds.
    pub fn delete_client(&self, client_id: &str) -> Result<bool, String> {
        let mut inner = self.lock();
        self.commit(&mut inner, |d| {
            let existed = d.clients.remove(client_id).is_some();
            let grant_ids: Vec<String> = d.grants.values()
                .filter(|g| g.client_id == client_id).map(|g| g.id.clone()).collect();
            for id in &grant_ids {
                d.remove_grant(id);
            }
            Ok::<_, String>(existed || !grant_ids.is_empty())
        })
    }

    /// Store a validated authorization request; returns its id.
    pub fn begin_pending(&self, p: PendingAuth) -> Result<String, String> {
        if p.state.as_deref().is_some_and(|s| s.len() > MAX_STATE_LEN) {
            return Err("state is too long".into());
        }
        let mut inner = self.lock();
        inner.prune(now());
        if inner.pending.len() >= MAX_PENDING {
            return Err("too many authorizations in progress — try again shortly".into());
        }
        // One client, or one requester, can't fill the global pool and
        // lock everyone else out.
        if inner.pending.values().filter(|x| x.client_id == p.client_id).count() >= MAX_PENDING_PER_CLIENT {
            return Err("too many authorizations in progress for this app — try again shortly".into());
        }
        if inner.pending.values().filter(|x| x.from == p.from).count() >= MAX_PENDING_PER_SOURCE {
            return Err("too many authorizations in progress from your address — try again shortly".into());
        }
        let id = random_token("wsp_");
        inner.pending.insert(id.clone(), p);
        Ok(id)
    }

    pub fn peek_pending(&self, id: &str) -> Option<PendingAuth> {
        let mut inner = self.lock();
        inner.prune(now());
        inner.pending.get(id).cloned()
    }

    /// Consume a pending authorization (single use, whatever the outcome).
    pub fn take_pending(&self, id: &str) -> Option<PendingAuth> {
        let mut inner = self.lock();
        inner.prune(now());
        inner.pending.remove(id)
    }

    /// Mint a 60 s single-use code after the user approved `granted`
    /// (already intersected with what the user may hold).
    pub fn issue_code(&self, p: &PendingAuth, username: &str, source: AuthSource, granted: Vec<String>) -> Result<String, String> {
        let t = now();
        let mut inner = self.lock();
        inner.prune(t);
        if inner.codes.len() >= MAX_CODES {
            return Err("too many authorizations in progress — try again shortly".into());
        }
        let code = random_token("wsa_");
        let ac = AuthCode {
            client_id: p.client_id.clone(),
            redirect_uri: p.redirect_uri.clone(),
            code_challenge: p.code_challenge.clone(),
            scopes: normalize_scopes(granted),
            resource: p.resource.clone(),
            username: username.to_string(),
            source,
            expires_at: t + CODE_TTL_SECS,
        };
        let code_hash = secret_hash("code", &code);
        self.commit(&mut inner, |d| {
            if let Some(c) = d.clients.get_mut(&p.client_id) {
                c.approved_at.get_or_insert(t);
            }
            d.codes.insert(code_hash, ac);
            Ok::<_, String>(())
        })?;
        Ok(code)
    }

    /// authorization_code grant. The code is removed on the FIRST
    /// presentation, valid or not, so it can't be brute-forced; a replay
    /// of a used code revokes the grant it produced.
    pub fn exchange_code(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        code_verifier: &str,
        resource: Option<&str>,
        authority: impl Fn(&str, AuthSource) -> Option<UserAuthority>,
    ) -> Result<TokenSet, TokenError> {
        let t = now();
        let code_hash = secret_hash("code", code);
        // Phase 1 (locked): consume and check the code.
        let ac = {
            let mut inner = self.lock();
            inner.prune(t);
            let Some(ac) = inner.codes.remove(&code_hash) else {
                if let Some((grant_id, _)) = inner.used_codes.get(&code_hash).cloned() {
                    let revoked = self.commit(&mut inner, |d| Ok::<_, String>(d.remove_grant(&grant_id)));
                    tracing::warn!("mcp oauth: authorization code replayed — grant {} revoked ({:?})",
                        grant_id, revoked.as_ref().map(|g| g.is_some()));
                }
                return Err(TokenError::InvalidGrant("authorization code is invalid, expired or already used".into()));
            };
            if ac.client_id != client_id {
                return Err(TokenError::InvalidGrant("code was issued to a different client".into()));
            }
            if ac.redirect_uri != redirect_uri {
                return Err(TokenError::InvalidGrant("redirect_uri does not match the authorization request".into()));
            }
            if !pkce_s256_matches(code_verifier, &ac.code_challenge) {
                return Err(TokenError::InvalidGrant("PKCE verification failed".into()));
            }
            if let Some(r) = resource
                && r != ac.resource {
                    return Err(TokenError::InvalidTarget("resource does not match the authorization request".into()));
                }
            ac
        };
        // Phase 2 (unlocked): who is this user now? (file reads)
        let Some(auth) = authority(&ac.username, ac.source) else {
            return Err(TokenError::InvalidGrant("the approving user no longer exists or may not use MCP".into()));
        };
        let scopes: Vec<String> = ac.scopes.iter()
            .filter(|s| auth.allowed_scopes.contains(s)).cloned().collect();
        if scopes.is_empty() {
            return Err(TokenError::InvalidScope("the approving user may no longer hold any of the granted scopes".into()));
        }
        // Phase 3 (locked): create the grant.
        let mut inner = self.lock();
        let client_name = inner.clients.get(client_id).map(|c| c.client_name.clone())
            .ok_or_else(|| TokenError::InvalidClient("client is no longer registered".into()))?;
        if inner.grants.len() >= MAX_GRANTS {
            return Err(TokenError::ServerError("too many active MCP grants — revoke unused ones in Settings → AI Agents (MCP)".into()));
        }
        if inner.access.len() >= MAX_ACCESS_TOKENS {
            return Err(TokenError::ServerError("too many active access tokens".into()));
        }
        let refresh = random_token("wsrt_");
        let grant = Grant {
            id: random_token("wsg_"),
            client_id: client_id.to_string(),
            client_name,
            username: ac.username.clone(),
            source: ac.source,
            scopes: normalize_scopes(scopes),
            resource: ac.resource.clone(),
            created_at: t,
            last_used_at: t,
            refresh_hash: secret_hash("refresh", &refresh),
            refresh_expires_at: t + REFRESH_TTL_SECS,
            retired_refresh_hashes: Vec::new(),
            last_rotated_at: t,
            credential_fp: auth.credential_fp.clone(),
        };
        let scope = scopes_string(&grant.scopes);
        let access = self.commit(&mut inner, |d| {
            let (access, _) = d.issue_access(&grant, &grant.scopes, t);
            d.refresh_index.insert(grant.refresh_hash.clone(), grant.id.clone());
            d.used_codes.insert(code_hash.clone(), (grant.id.clone(), t + USED_CODE_MEMORY_SECS));
            d.grants.insert(grant.id.clone(), grant.clone());
            Ok::<_, TokenError>(access)
        })?;
        Ok(TokenSet { access_token: access, token_type: "Bearer", expires_in: ACCESS_TTL_SECS, refresh_token: refresh, scope })
    }

    /// refresh_token grant with rotation. A retired refresh token is a
    /// stolen one (OAuth 2.1 §4.3.1): the whole grant is revoked — unless
    /// it was rotated seconds ago, which is the honest client retrying.
    pub fn refresh(
        &self,
        refresh_token: &str,
        client_id: &str,
        resource: Option<&str>,
        requested_scopes: Option<Vec<String>>,
        authority: impl Fn(&str, AuthSource) -> Option<UserAuthority>,
    ) -> Result<TokenSet, TokenError> {
        let t = now();
        let h = secret_hash("refresh", refresh_token);
        // Phase 1 (locked): find the grant, handle replays.
        let grant = {
            let mut inner = self.lock();
            inner.prune(t);
            let grant = if let Some(grant_id) = inner.retired_index.get(&h).cloned() {
                // The token rotated away seconds ago is the client retrying a
                // refresh whose response it lost: let it rotate again from
                // the successor it never received. Anything older is theft.
                let retry_of = inner.grants.get(&grant_id).filter(|g| {
                    g.retired_refresh_hashes.last() == Some(&h)
                        && t - g.last_rotated_at <= REFRESH_RETRY_GRACE_SECS
                }).cloned();
                match retry_of {
                    Some(g) => g,
                    None => {
                        if let Some(g) = self.commit(&mut inner, |d| Ok::<_, TokenError>(d.remove_grant(&grant_id)))? {
                            tracing::warn!(
                                "mcp oauth: retired refresh token replayed for grant {} (user '{}', client '{}') — grant revoked",
                                g.id, g.username, g.client_name
                            );
                        }
                        return Err(TokenError::InvalidGrant("refresh token was already used; the grant has been revoked".into()));
                    }
                }
            } else {
                let Some(g) = inner.refresh_index.get(&h).and_then(|id| inner.grants.get(id)).cloned() else {
                    return Err(TokenError::InvalidGrant("refresh token is invalid or expired".into()));
                };
                g
            };
            if grant.client_id != client_id {
                return Err(TokenError::InvalidGrant("refresh token was issued to a different client".into()));
            }
            if let Some(r) = resource
                && r != grant.resource {
                    return Err(TokenError::InvalidTarget("resource does not match the grant".into()));
                }
            grant
        };
        // Phase 2 (unlocked): re-check the user (file reads).
        let auth = authority(&grant.username, grant.source);
        // Phase 3 (locked): rotate — but only if nobody rotated meanwhile
        // (the grant's current refresh hash is the one we looked at).
        let mut inner = self.lock();
        if inner.refresh_index.get(&grant.refresh_hash) != Some(&grant.id) {
            return Err(TokenError::InvalidGrant("refresh token was already used".into()));
        }
        let auth = match auth {
            Some(a) if a.credential_fp == grant.credential_fp => a,
            Some(_) => {
                // Positively changed credentials: the grant is dead.
                self.commit(&mut inner, |d| Ok::<_, TokenError>(d.remove_grant(&grant.id)))?;
                return Err(TokenError::InvalidGrant(
                    "the user's password or two-factor setup changed; the grant has been revoked".into()));
            }
            // Not found — or the account files couldn't be read just now.
            // Refuse without revoking: a transient read failure must not
            // destroy a grant. A deleted user's grants are revoked when the
            // user is deleted, and every request is refused meanwhile.
            None => return Err(TokenError::InvalidGrant(
                "the user cannot be confirmed (no longer exists, or may not use MCP)".into())),
        };
        let base: Vec<String> = match requested_scopes {
            Some(req) => {
                if req.iter().any(|s| !grant.scopes.contains(s)) {
                    return Err(TokenError::InvalidScope("a refresh cannot add scopes the user did not approve".into()));
                }
                req
            }
            None => grant.scopes.clone(),
        };
        let scopes = normalize_scopes(base.into_iter()
            .filter(|s| auth.allowed_scopes.contains(s)).collect());
        if scopes.is_empty() {
            return Err(TokenError::InvalidScope("the user may no longer hold any of the granted scopes".into()));
        }
        if inner.access.len() >= MAX_ACCESS_TOKENS {
            return Err(TokenError::ServerError("too many active access tokens".into()));
        }
        let new_refresh = random_token("wsrt_");
        let new_hash = secret_hash("refresh", &new_refresh);
        let access = self.commit(&mut inner, |d| {
            let g = d.grants.get_mut(&grant.id)
                .ok_or_else(|| TokenError::InvalidGrant("refresh token is invalid or expired".into()))?;
            g.retired_refresh_hashes.push(std::mem::replace(&mut g.refresh_hash, new_hash));
            if g.retired_refresh_hashes.len() > RETIRED_REFRESH_KEEP {
                let drop = g.retired_refresh_hashes.len() - RETIRED_REFRESH_KEEP;
                g.retired_refresh_hashes.drain(0..drop);
            }
            g.last_rotated_at = t;
            g.refresh_expires_at = (t + REFRESH_TTL_SECS).min(g.created_at + GRANT_MAX_LIFETIME_SECS);
            g.last_used_at = t;
            let g = g.clone();
            d.rebuild_indexes();
            let (access, _) = d.issue_access(&g, &scopes, t);
            Ok::<_, TokenError>(access)
        })?;
        Ok(TokenSet {
            access_token: access,
            token_type: "Bearer",
            expires_in: ACCESS_TTL_SECS,
            refresh_token: new_refresh,
            scope: scopes_string(&scopes),
        })
    }

    /// Resource-server check: the token exists, is unexpired and was
    /// issued for exactly this resource (RFC 8707 audience binding).
    pub fn validate_access(&self, token: &str, resource: &str) -> Option<AccessInfo> {
        let t = now();
        let mut inner = self.lock();
        let h = secret_hash("access", token);
        let info = inner.access.get(&h)?.clone();
        if info.expires_at <= t {
            inner.access.remove(&h);
            return None;
        }
        if info.resource != resource || !inner.grants.contains_key(&info.grant_id) {
            return None;
        }
        // In memory only; persisted with the next real change.
        if let Some(g) = inner.grants.get_mut(&info.grant_id) {
            g.last_used_at = t;
        }
        Some(info)
    }

    /// RFC 7009. Revoking either token of a grant revokes the grant.
    /// Unknown tokens are not an error (§2.2).
    pub fn revoke_token(&self, token: &str, client_id: Option<&str>) -> Result<(), String> {
        let mut inner = self.lock();
        let grant_id = inner.access.get(&secret_hash("access", token)).map(|a| a.grant_id.clone())
            .or_else(|| inner.refresh_index.get(&secret_hash("refresh", token)).cloned());
        let Some(grant_id) = grant_id else { return Ok(()) };
        if let Some(cid) = client_id
            && inner.grants.get(&grant_id).is_some_and(|g| g.client_id != cid) {
                return Ok(()); // a client may only revoke its own tokens
            }
        self.commit(&mut inner, |d| { d.remove_grant(&grant_id); Ok::<_, String>(()) })
    }

    pub fn revoke_grant(&self, grant_id: &str) -> Result<bool, String> {
        let mut inner = self.lock();
        if !inner.grants.contains_key(grant_id) {
            return Ok(false);
        }
        self.commit(&mut inner, |d| Ok::<_, String>(d.remove_grant(grant_id).is_some()))
    }

    /// Drop every grant a user holds (account deleted, password changed,
    /// or an admin cutting them off).
    pub fn revoke_user(&self, username: &str) -> Result<usize, String> {
        let mut inner = self.lock();
        let ids: Vec<String> = inner.grants.values()
            .filter(|g| g.username == username).map(|g| g.id.clone()).collect();
        if ids.is_empty() {
            return Ok(0);
        }
        self.commit(&mut inner, |d| {
            for id in &ids {
                d.remove_grant(id);
            }
            Ok::<_, String>(ids.len())
        })
    }

    /// End every grant (the public URL changed, so every token's audience
    /// is now wrong). One write.
    pub fn revoke_all(&self) -> Result<usize, String> {
        let mut inner = self.lock();
        let ids: Vec<String> = inner.grants.keys().cloned().collect();
        if ids.is_empty() {
            return Ok(0);
        }
        self.commit(&mut inner, |d| {
            for id in &ids {
                d.remove_grant(id);
            }
            Ok::<_, String>(ids.len())
        })
    }

    pub fn list_grants(&self) -> Vec<GrantView> {
        let mut inner = self.lock();
        inner.prune(now());
        inner.snapshot().grants.into_iter().map(|g| GrantView {
            id: g.id, client_id: g.client_id, client_name: g.client_name,
            username: g.username, scopes: g.scopes, created_at: g.created_at,
            last_used_at: g.last_used_at, expires_at: g.refresh_expires_at,
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RES: &str = "https://ws.example.com:8553/mcp";

    fn verifier() -> String { "a".repeat(43) + "-._~" }
    fn challenge(v: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()))
    }
    fn admin(_: &str, _: AuthSource) -> Option<UserAuthority> {
        Some(UserAuthority { allowed_scopes: ALL_SCOPES.iter().map(|s| s.to_string()).collect(), credential_fp: "fp1".into() })
    }
    fn viewer(_: &str, _: AuthSource) -> Option<UserAuthority> {
        Some(UserAuthority { allowed_scopes: vec!["read".into()], credential_fp: "fp1".into() })
    }
    fn password_changed(_: &str, _: AuthSource) -> Option<UserAuthority> {
        Some(UserAuthority { allowed_scopes: ALL_SCOPES.iter().map(|s| s.to_string()).collect(), credential_fp: "fp2".into() })
    }
    fn gone(_: &str, _: AuthSource) -> Option<UserAuthority> { None }

    fn setup(store: &OAuthStore, scopes: &[&str]) -> (Client, String, String) {
        let client = store.register_client(Some("Test"), &["http://127.0.0.1:33418/callback".into()], "127.0.0.1").unwrap();
        let v = verifier();
        let p = PendingAuth {
            client_id: client.client_id.clone(), client_name: client.client_name.clone(),
            redirect_uri: client.redirect_uris[0].clone(), state: Some("s".into()),
            code_challenge: challenge(&v), scopes: scopes.iter().map(|s| s.to_string()).collect(),
            resource: RES.into(), created_at: now(), from: "127.0.0.1".into(),
        };
        let code = store.issue_code(&p, "paul", AuthSource::WolfStack, p.scopes.clone()).unwrap();
        (client, code, v)
    }

    fn rewind_rotation(s: &OAuthStore, secs: i64) {
        for g in s.lock().grants.values_mut() {
            g.last_rotated_at -= secs;
        }
    }

    #[test]
    fn pkce_rfc7636_appendix_b_vector() {
        // RFC 7636 Appendix B.
        assert!(pkce_s256_matches(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assert!(!pkce_s256_matches(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXX",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assert!(!pkce_s256_matches("short", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assert!(valid_code_challenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assert!(!valid_code_challenge("plain-text-challenge"));
    }

    #[test]
    fn redirect_uris_must_be_https_or_loopback() {
        assert!(validate_redirect_uri("https://app.example.com/cb").is_ok());
        assert!(validate_redirect_uri("http://127.0.0.1:5000/cb").is_ok());
        assert!(validate_redirect_uri("http://localhost:5000/cb").is_ok());
        assert!(validate_redirect_uri("http://[::1]:5000/cb").is_ok());
        assert!(validate_redirect_uri("http://evil.example.com/cb").is_err());
        assert!(validate_redirect_uri("javascript:alert(1)").is_err());
        assert!(validate_redirect_uri("data:text/html,x").is_err());
        assert!(validate_redirect_uri("https://a.example.com/cb#frag").is_err());
        assert!(validate_redirect_uri("https://user:pw@a.example.com/cb").is_err());
        assert!(validate_redirect_uri("myapp://cb").is_err());
        assert!(validate_redirect_uri("https://a.example.com/c b").is_err());
    }

    #[test]
    fn scopes_parse_strictly() {
        assert_eq!(parse_scopes(None).unwrap(), vec!["read"]);
        assert_eq!(parse_scopes(Some("vms read vms")).unwrap(), vec!["read", "vms"]);
        assert_eq!(parse_scopes(Some("logs read")).unwrap(), vec!["read", "logs"]);
        assert!(parse_scopes(Some("read admin")).is_err());
        assert!(parse_scopes(Some("*")).is_err());
    }

    #[test]
    fn client_name_is_sanitised() {
        assert_eq!(sanitize_client_name(Some("  Claude\n\tCode\u{0007} ")), "Claude Code");
        assert_eq!(sanitize_client_name(None), "Unnamed client");
        assert_eq!(sanitize_client_name(Some(&"x".repeat(500))).len(), MAX_CLIENT_NAME_LEN);
        // Bidi override / zero-width characters can't disguise a name.
        assert_eq!(sanitize_client_name(Some("Claude\u{202E}edoC\u{200B}")), "ClaudeedoC");
    }

    #[test]
    fn code_flow_issues_audience_bound_tokens() {
        let s = OAuthStore::in_memory();
        let (client, code, v) = setup(&s, &["read", "containers"]);
        let t = s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), admin).unwrap();
        assert_eq!(t.scope, "read containers");
        let info = s.validate_access(&t.access_token, RES).unwrap();
        assert_eq!(info.username, "paul");
        assert_eq!(info.source, AuthSource::WolfStack);
        // Audience binding: the same token is useless for any other resource.
        assert!(s.validate_access(&t.access_token, "https://other.example.com/mcp").is_none());
        assert!(s.validate_access("wsat_forged", RES).is_none());
    }

    #[test]
    fn code_is_single_use_even_after_a_failed_attempt() {
        let s = OAuthStore::in_memory();
        let (client, code, v) = setup(&s, &["read"]);
        let bad = s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &"b".repeat(43), Some(RES), admin);
        assert_eq!(bad.unwrap_err().code(), "invalid_grant");
        // The right verifier no longer helps: the code was consumed.
        let again = s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), admin);
        assert_eq!(again.unwrap_err().code(), "invalid_grant");
    }

    #[test]
    fn replaying_a_used_code_revokes_its_grant() {
        let s = OAuthStore::in_memory();
        let (client, code, v) = setup(&s, &["read"]);
        let t = s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), admin).unwrap();
        assert!(s.validate_access(&t.access_token, RES).is_some());
        // An attacker who intercepted the code tries it again.
        assert!(s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), admin).is_err());
        assert!(s.validate_access(&t.access_token, RES).is_none());
        assert!(s.list_grants().is_empty());
    }

    #[test]
    fn code_is_bound_to_client_redirect_and_resource() {
        let s = OAuthStore::in_memory();
        let (client, code, v) = setup(&s, &["read"]);
        assert!(s.exchange_code(&code, "wsc_other", &client.redirect_uris[0], &v, Some(RES), admin).is_err());
        let (client, code, v) = setup(&s, &["read"]);
        assert!(s.exchange_code(&code, &client.client_id, "http://127.0.0.1:1/x", &v, Some(RES), admin).is_err());
        let (client, code, v) = setup(&s, &["read"]);
        assert_eq!(s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v,
            Some("https://evil.example.com/mcp"), admin).unwrap_err().code(), "invalid_target");
    }

    #[test]
    fn viewer_never_gets_more_than_read() {
        let s = OAuthStore::in_memory();
        let (client, code, v) = setup(&s, &["read", "vms"]);
        let t = s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), viewer).unwrap();
        assert_eq!(t.scope, "read");
    }

    #[test]
    fn deleted_user_cannot_exchange_or_refresh() {
        let s = OAuthStore::in_memory();
        let (client, code, v) = setup(&s, &["read"]);
        assert!(s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), gone).is_err());
        let (client, code, v) = setup(&s, &["read"]);
        let t = s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), admin).unwrap();
        assert!(s.refresh(&t.refresh_token, &client.client_id, Some(RES), None, gone).is_err());
        // Unconfirmable is refused but not revoked (a transient read error
        // must not destroy the grant)...
        assert_eq!(s.list_grants().len(), 1);
        // ...and once the user resolves again, refresh works.
        assert!(s.refresh(&t.refresh_token, &client.client_id, Some(RES), None, admin).is_ok());
        // Deleting the user revokes outright.
        assert_eq!(s.revoke_user("paul").unwrap(), 1);
        assert!(s.list_grants().is_empty());
    }

    #[test]
    fn credential_change_revokes_the_grant_at_refresh() {
        let s = OAuthStore::in_memory();
        let (client, code, v) = setup(&s, &["read"]);
        let t = s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), admin).unwrap();
        assert_eq!(s.validate_access(&t.access_token, RES).unwrap().credential_fp, "fp1");
        assert!(s.refresh(&t.refresh_token, &client.client_id, Some(RES), None, password_changed).is_err());
        assert!(s.list_grants().is_empty());
    }

    #[test]
    fn refresh_rotates_and_replay_revokes_the_grant() {
        let s = OAuthStore::in_memory();
        let (client, code, v) = setup(&s, &["read", "vms"]);
        let t1 = s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), admin).unwrap();
        let t2 = s.refresh(&t1.refresh_token, &client.client_id, Some(RES), None, admin).unwrap();
        assert_ne!(t1.refresh_token, t2.refresh_token);
        assert!(s.validate_access(&t2.access_token, RES).is_some());
        // An attacker replays the stolen first refresh token later on...
        rewind_rotation(&s, REFRESH_RETRY_GRACE_SECS + 1);
        let replay = s.refresh(&t1.refresh_token, &client.client_id, Some(RES), None, admin);
        assert_eq!(replay.unwrap_err().code(), "invalid_grant");
        // ...which kills the legitimate holder's tokens too: the grant is gone.
        assert!(s.validate_access(&t2.access_token, RES).is_none());
        assert!(s.refresh(&t2.refresh_token, &client.client_id, Some(RES), None, admin).is_err());
        assert!(s.list_grants().is_empty());
    }

    #[test]
    fn an_immediate_retry_of_a_rotated_token_recovers_the_session() {
        let s = OAuthStore::in_memory();
        let (client, code, v) = setup(&s, &["read"]);
        let t1 = s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), admin).unwrap();
        let lost = s.refresh(&t1.refresh_token, &client.client_id, Some(RES), None, admin).unwrap();
        // The client never received `lost` and retries at once: it gets a
        // fresh pair, and the pair it never saw is retired.
        let t3 = s.refresh(&t1.refresh_token, &client.client_id, Some(RES), None, admin).unwrap();
        assert!(s.validate_access(&t3.access_token, RES).is_some());
        assert!(s.refresh(&t3.refresh_token, &client.client_id, Some(RES), None, admin).is_ok());
        assert_ne!(lost.refresh_token, t3.refresh_token);
    }

    #[test]
    fn refresh_can_narrow_but_never_widen_scopes() {
        let s = OAuthStore::in_memory();
        let (client, code, v) = setup(&s, &["read", "vms"]);
        let t1 = s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), admin).unwrap();
        let wider = s.refresh(&t1.refresh_token, &client.client_id, Some(RES), Some(vec!["read".into(), "backup".into()]), admin);
        assert_eq!(wider.unwrap_err().code(), "invalid_scope");
        let t2 = s.refresh(&t1.refresh_token, &client.client_id, Some(RES), Some(vec!["read".into()]), admin).unwrap();
        assert_eq!(t2.scope, "read");
        // Narrowing a token does not shrink what the user approved.
        let t3 = s.refresh(&t2.refresh_token, &client.client_id, Some(RES), None, admin).unwrap();
        assert_eq!(t3.scope, "read vms");
        // A demotion is applied at refresh: viewer → read only.
        assert_eq!(s.refresh(&t3.refresh_token, &client.client_id, Some(RES), None, viewer).unwrap().scope, "read");
    }

    #[test]
    fn grant_lifetime_is_capped() {
        let s = OAuthStore::in_memory();
        let (client, code, v) = setup(&s, &["read"]);
        let t = s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), admin).unwrap();
        for g in s.lock().grants.values_mut() {
            g.created_at -= GRANT_MAX_LIFETIME_SECS - 60;
        }
        s.refresh(&t.refresh_token, &client.client_id, Some(RES), None, admin).unwrap();
        let exp = s.list_grants()[0].expires_at;
        assert!(exp <= now() + 60, "refresh may not extend past the absolute lifetime");
    }

    #[test]
    fn refresh_is_bound_to_its_client() {
        let s = OAuthStore::in_memory();
        let (client, code, v) = setup(&s, &["read"]);
        let t = s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), admin).unwrap();
        assert!(s.refresh(&t.refresh_token, "wsc_thief", Some(RES), None, admin).is_err());
        // The legitimate client still works (a wrong-client attempt isn't a replay).
        assert!(s.refresh(&t.refresh_token, &client.client_id, Some(RES), None, admin).is_ok());
    }

    #[test]
    fn revocation_kills_both_tokens() {
        let s = OAuthStore::in_memory();
        let (client, code, v) = setup(&s, &["read"]);
        let t = s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), admin).unwrap();
        // Another client cannot revoke someone else's token.
        s.revoke_token(&t.access_token, Some("wsc_other")).unwrap();
        assert!(s.validate_access(&t.access_token, RES).is_some());
        s.revoke_token(&t.access_token, Some(&client.client_id)).unwrap();
        assert!(s.validate_access(&t.access_token, RES).is_none());
        assert!(s.refresh(&t.refresh_token, &client.client_id, Some(RES), None, admin).is_err());
    }

    #[test]
    fn pending_is_single_use_and_capped_per_client() {
        let s = OAuthStore::in_memory();
        let p = PendingAuth {
            client_id: "c".into(), client_name: "n".into(), redirect_uri: "https://a/cb".into(),
            state: None, code_challenge: "x".repeat(43), scopes: vec!["read".into()],
            resource: RES.into(), created_at: now(), from: "198.51.100.1".into(),
        };
        let id = s.begin_pending(p.clone()).unwrap();
        assert!(s.peek_pending(&id).is_some());
        assert!(s.take_pending(&id).is_some());
        assert!(s.take_pending(&id).is_none());
        for _ in 0..MAX_PENDING_PER_CLIENT {
            s.begin_pending(p.clone()).unwrap();
        }
        assert!(s.begin_pending(p.clone()).is_err(), "one client cannot exhaust the pool");
        let mut other = p.clone();
        other.client_id = "d".into();
        assert!(s.begin_pending(other).is_ok());
        // One requester can't hold the pool across many registered clients.
        for i in 0..(MAX_PENDING_PER_SOURCE - MAX_PENDING_PER_CLIENT - 1) {
            let mut q = p.clone();
            q.client_id = format!("e{}", i);
            s.begin_pending(q).unwrap();
        }
        let mut q = p;
        q.client_id = "last".into();
        assert!(s.begin_pending(q).is_err());
    }

    #[test]
    fn full_client_table_evicts_the_oldest_unapproved_client() {
        let s = OAuthStore::in_memory();
        let first = s.register_client(Some("first"), &["https://a.example.com/cb".into()], "x").unwrap();
        // Registered in the same second as the fillers: make it the oldest.
        s.lock().clients.get_mut(&first.client_id).unwrap().created_at -= 100;
        for _ in 1..MAX_CLIENTS {
            s.register_client(Some("filler"), &["https://a.example.com/cb".into()], "x").unwrap();
        }
        assert!(s.register_client(Some("new"), &["https://a.example.com/cb".into()], "x").is_ok());
        assert!(s.get_client(&first.client_id).is_none());
    }

    #[test]
    fn persisted_state_never_contains_raw_secrets_and_survives_restart() {
        let dir = std::env::temp_dir().join(format!("wsmcp-{}", random_token("t")));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oauth.json");
        let s = OAuthStore::load(path.to_str().unwrap());
        let (client, code, v) = setup(&s, &["read"]);
        let t = s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), admin).unwrap();
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains(&t.refresh_token));
        assert!(!on_disk.contains(&t.access_token));
        assert!(!on_disk.contains(&code));
        // Survives a restart: the refresh token still works, access tokens don't.
        let reloaded = OAuthStore::load(path.to_str().unwrap());
        assert!(reloaded.validate_access(&t.access_token, RES).is_none());
        assert!(reloaded.refresh(&t.refresh_token, &client.client_id, Some(RES), None, admin).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_state_file_is_kept_aside_not_overwritten() {
        let dir = std::env::temp_dir().join(format!("wsmcp-{}", random_token("t")));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oauth.json");
        std::fs::write(&path, "{ not json").unwrap();
        let s = OAuthStore::load(path.to_str().unwrap());
        assert!(s.list_grants().is_empty());
        let kept = std::fs::read_dir(&dir).unwrap().flatten()
            .any(|e| e.file_name().to_string_lossy().contains(".corrupt-"));
        assert!(kept, "the unreadable file must be preserved");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_persist_changes_nothing() {
        // A store whose file can't be written: revocation must not take
        // effect in memory only (a restart would undo it).
        let dir = std::env::temp_dir().join(format!("wsmcp-{}", random_token("t")));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oauth.json");
        let s = OAuthStore::load(path.to_str().unwrap());
        let (client, code, v) = setup(&s, &["read"]);
        let t = s.exchange_code(&code, &client.client_id, &client.redirect_uris[0], &v, Some(RES), admin).unwrap();
        let grant_id = s.list_grants()[0].id.clone();
        // Replace the file with a directory so the rename fails.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir_all(path.join("blocker")).unwrap();
        assert!(s.revoke_grant(&grant_id).is_err());
        assert!(s.validate_access(&t.access_token, RES).is_some(), "state unchanged after a failed write");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
