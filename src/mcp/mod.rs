// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! MCP (Model Context Protocol) server: lets Claude and other agent
//! harnesses read this node's state and run a small set of reversible
//! actions, at `POST /mcp`.
//!
//! Security model — every layer is independent, so one mistake does not
//! open the door:
//! * OFF by default, per node; a disabled node answers 404 on every MCP
//!   and OAuth path, so it has no new attack surface.
//! * An admin fixes the public URL. The OAuth issuer and the token
//!   audience come from it, never from the request's Host header.
//! * HTTPS only, judged by the listener actually being TLS
//!   (`AppConfig::secure`) — never by a forgeable X-Forwarded-Proto —
//!   except for loopback callers (a reverse proxy on the same host).
//! * Users authenticate through OAuth 2.1 (`oauth`, `http`): a fresh
//!   sign-in with password + TOTP on every approval (never a browser
//!   session) and an explicit consent; authority is always re-read from
//!   the account store that signed the user in. Session cookies and the
//!   cluster secret are never accepted at `/mcp`.
//! * API keys work only if an admin separately enables them for MCP AND
//!   the key carries the `mcp` scope.
//! * Every request re-reads the user: deleted → refused; demoted to
//!   viewer → read only; lost access to this node's cluster → refused.
//! * Tools are read-only plus start/stop/restart and "run backup"; no
//!   exec, files, delete, network or settings (`tools`).
//! * Rate limits on registration, the consent page, token, sign-in and
//!   tool calls; every grant, refusal and tool call is logged.

pub mod http;
pub mod oauth;
pub mod protocol;
pub mod tools;

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ─── Configuration ───

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpConfig {
    #[serde(default)]
    pub enabled: bool,
    /// `https://host[:port]` this node is reached at — the OAuth issuer.
    #[serde(default)]
    pub public_url: String,
    /// Accept `wsk_` API keys (with the `mcp` scope) as well as OAuth.
    #[serde(default)]
    pub allow_api_keys: bool,
}

fn config_path() -> String {
    format!("{}/mcp.json", crate::paths::get().config_dir)
}

fn oauth_store_path() -> String {
    format!("{}/mcp-oauth.json", crate::paths::get().config_dir)
}

static CONFIG: LazyLock<RwLock<McpConfig>> = LazyLock::new(|| {
    let cfg = std::fs::read_to_string(config_path())
        .ok()
        .and_then(|s| serde_json::from_str::<McpConfig>(&s).ok())
        .unwrap_or_default();
    RwLock::new(cfg)
});

pub fn config() -> McpConfig {
    CONFIG.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Validate and persist (mode 0600), then make it live.
pub fn save_config(mut cfg: McpConfig) -> Result<McpConfig, String> {
    if !cfg.public_url.trim().is_empty() {
        cfg.public_url = normalize_public_url(&cfg.public_url)?;
    } else {
        cfg.public_url.clear();
    }
    if cfg.enabled && cfg.public_url.is_empty() {
        return Err("Set the public HTTPS URL this node is reached at before enabling MCP.".into());
    }
    let json = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?;
    let path = config_path();
    let tmp = format!("{}.tmp", path);
    crate::paths::write_secure(&tmp, json).map_err(|e| format!("write {}: {}", tmp, e))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename {}: {}", path, e))?;
    *CONFIG.write().unwrap_or_else(|e| e.into_inner()) = cfg.clone();
    Ok(cfg)
}

/// `https://host[:port]` only — no path, query, fragment or credentials.
/// Returned in canonical origin form (lowercase host, default port elided)
/// so the issuer and resource strings are byte-stable.
pub fn normalize_public_url(raw: &str) -> Result<String, String> {
    let url = url::Url::parse(raw.trim()).map_err(|e| format!("Public URL is not a valid URL: {}", e))?;
    if url.scheme() != "https" {
        return Err("Public URL must start with https:// — tokens must never travel in clear text.".into());
    }
    if url.host_str().is_none_or(|h| h.is_empty()) {
        return Err("Public URL must include a host name.".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Public URL must not contain credentials.".into());
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err("Public URL must be just scheme, host and port (no path) — e.g. https://ws1.example.com:8553".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("Public URL must not contain a query or fragment.".into());
    }
    Ok(url.origin().ascii_serialization())
}

impl McpConfig {
    /// OAuth issuer; `None` when MCP is not usable.
    pub fn issuer(&self) -> Option<String> {
        (self.enabled && !self.public_url.is_empty()).then(|| self.public_url.clone())
    }
    /// Canonical MCP resource URI (RFC 8707 audience).
    pub fn resource(&self) -> Option<String> {
        self.issuer().map(|i| format!("{}/mcp", i))
    }
}

pub static OAUTH: LazyLock<oauth::OAuthStore> = LazyLock::new(|| oauth::OAuthStore::load(&oauth_store_path()));

// ─── Who is calling ───

#[derive(Debug, Clone)]
pub enum PrincipalKind {
    User { username: String, client_id: String, client_name: String },
    ApiKey { name: String, id: String },
}

#[derive(Debug, Clone)]
pub struct Principal {
    pub kind: PrincipalKind,
    /// Effective scopes: what the token carries ∩ what the account may
    /// hold right now.
    pub scopes: Vec<String>,
}

impl Principal {
    pub fn label(&self) -> String {
        match &self.kind {
            PrincipalKind::User { username, client_name, .. } => format!("user '{}' via '{}'", username, client_name),
            PrincipalKind::ApiKey { name, .. } => format!("API key '{}'", name),
        }
    }
    /// The caller string `api::filter_nodes_for_caller` expects — the same
    /// one the REST API derives for this identity.
    pub fn cluster_filter_caller(&self) -> String {
        match &self.kind {
            PrincipalKind::User { username, .. } => username.clone(),
            PrincipalKind::ApiKey { name, .. } => format!("apikey:{}", name),
        }
    }
    pub fn rate_key(&self) -> String {
        match &self.kind {
            PrincipalKind::User { username, client_id, .. } => format!("u:{}:{}", username, client_id),
            PrincipalKind::ApiKey { id, .. } => format!("k:{}", id),
        }
    }
}

/// Name shown for this node on the consent page and in metadata.
pub fn self_hostname(cluster: &crate::agent::ClusterState) -> String {
    cluster.get_all_nodes().into_iter().find(|n| n.is_self)
        .map(|n| n.display_name.filter(|d| !d.trim().is_empty()).unwrap_or(n.hostname))
        .unwrap_or_else(|| "this node".to_string())
}

/// This node's cluster name, for the per-user cluster allowlist.
pub fn self_cluster_name(cluster: &crate::agent::ClusterState) -> Option<String> {
    cluster.get_all_nodes().into_iter().find(|n| n.is_self).and_then(|n| n.cluster_name)
}

/// A Linux account's shadow password hash while the account exists with a
/// usable password (not locked `!…` / disabled `*`); `None` otherwise.
/// Mirrors what `auth::authenticate_user` reads.
fn linux_shadow_hash(username: &str) -> Option<String> {
    if username.is_empty() || username.contains(':') || username.contains('/') || username.contains('\0') {
        return None;
    }
    let shadow = std::fs::read_to_string("/etc/shadow").ok()?;
    shadow.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        if parts.next() != Some(username) { return None; }
        parts.next().filter(|h| !h.is_empty() && !h.starts_with('!') && !h.starts_with('*')).map(|h| h.to_string())
    })
}

/// Digest binding a grant to the credentials it was approved with.
fn credential_fingerprint(parts: &[&str]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"wolfstack-mcp-credential\0");
    for p in parts {
        h.update(p.as_bytes());
        h.update(b"\0");
    }
    hex::encode(h.finalize())
}

/// What `username` may hold on this node right now, or `None` when the
/// account may not use MCP at all. Read on every request and refresh, so
/// revoking or demoting a user in WolfStack takes effect immediately.
///
/// Authority comes ONLY from the store that authenticated the user
/// (`source`): a Linux login never inherits the role of a WolfStack user
/// who shares its name, and a WolfStack login never inherits root's Linux
/// privileges. The store must also still be enabled by the auth mode.
pub fn user_authority(username: &str, source: oauth::AuthSource, self_cluster: Option<&str>) -> Option<oauth::UserAuthority> {
    let cfg = crate::auth::users::AuthConfig::load();
    let mode = cfg.auth_mode.as_str();
    if source == oauth::AuthSource::WolfStack {
        if mode != "wolfstack" && mode != "both" {
            return None;
        }
        let store = crate::auth::users::UserStore::load();
        let user = store.find(username)?;
        if !user.can_access_cluster(self_cluster) {
            return None;
        }
        let scopes: &[&str] = if crate::auth::role_is_read_only(&user.role) {
            &oauth::READ_ONLY_SCOPES
        } else {
            &oauth::ALL_SCOPES
        };
        return Some(oauth::UserAuthority {
            allowed_scopes: scopes.iter().map(|s| s.to_string()).collect(),
            credential_fp: credential_fingerprint(&[
                "wolfstack", &user.password_hash, &user.totp_secret,
                if user.totp_enabled { "2fa-on" } else { "2fa-off" },
            ]),
        });
    }
    if mode != "linux" && mode != "both" {
        return None;
    }
    let shadow_hash = linux_shadow_hash(username)?;
    // A Linux account has no WolfStack role. The dashboard gives every
    // Linux login full access; MCP is stricter and only lets root and
    // sudo/wheel members act — the set WolfStack already treats as
    // admins (`auth::session_user_is_admin`). Others may only read.
    let scopes: &[&str] = if crate::auth::linux_user_is_privileged(username) {
        &oauth::ALL_SCOPES
    } else {
        &oauth::READ_ONLY_SCOPES
    };
    Some(oauth::UserAuthority {
        allowed_scopes: scopes.iter().map(|s| s.to_string()).collect(),
        credential_fp: credential_fingerprint(&["linux", &shadow_hash]),
    })
}

// ─── Rate limiting ───

/// Fixed-window counter per key. Small and bounded: the map is cleared of
/// expired windows when it grows, and capped so a flood of distinct keys
/// can't exhaust memory (at the cap, unknown keys are refused).
pub struct RateLimiter {
    window: Duration,
    max: u32,
    hits: Mutex<HashMap<String, (Instant, u32)>>,
}

const RATE_MAP_CAP: usize = 20_000;

impl RateLimiter {
    pub fn new(window: Duration, max: u32) -> Self {
        RateLimiter { window, max, hits: Mutex::new(HashMap::new()) }
    }

    /// True when `key` has used its whole window — checked BEFORE validating
    /// a credential, so an IP over its failure budget gets no oracle, not
    /// even for a correct guess.
    pub fn exhausted(&self, key: &str) -> bool {
        let now = Instant::now();
        let hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        hits.get(key).is_some_and(|(start, count)| now.duration_since(*start) < self.window && *count >= self.max)
    }

    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        if hits.len() > RATE_MAP_CAP / 2 {
            hits.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        if let Some((start, count)) = hits.get_mut(key) {
            if now.duration_since(*start) >= self.window {
                *start = now;
                *count = 1;
                return true;
            }
            if *count >= self.max {
                return false;
            }
            *count += 1;
            return true;
        }
        if hits.len() >= RATE_MAP_CAP {
            // Full of live windows (a flood of distinct keys): evict the
            // oldest rather than refuse newcomers, so a flood can't lock
            // legitimate callers out.
            if let Some(oldest) = hits.iter().min_by_key(|(_, (start, _))| *start).map(|(k, _)| k.clone()) {
                hits.remove(&oldest);
            }
        }
        hits.insert(key.to_string(), (now, 1));
        true
    }
}

/// Rate-limit key for a client address: IPv4 as-is, IPv6 by its /64 —
/// one host is routinely handed a whole /64, so per-address keys would
/// give an attacker unlimited buckets.
pub fn limiter_key(ip: std::net::IpAddr) -> String {
    match ip.to_canonical() {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

/// Consent page views per IP (each one holds a pending authorization).
pub static AUTHORIZE_LIMIT: LazyLock<RateLimiter> = LazyLock::new(|| RateLimiter::new(Duration::from_secs(600), 30));
/// Dynamic client registrations per IP.
pub static REGISTER_LIMIT: LazyLock<RateLimiter> = LazyLock::new(|| RateLimiter::new(Duration::from_secs(3600), 10));
/// Token endpoint calls per IP.
pub static TOKEN_LIMIT: LazyLock<RateLimiter> = LazyLock::new(|| RateLimiter::new(Duration::from_secs(60), 30));
/// Consent submissions per IP (on top of the login lockout).
pub static CONSENT_LIMIT: LazyLock<RateLimiter> = LazyLock::new(|| RateLimiter::new(Duration::from_secs(600), 20));
/// Failed bearer authentications at /mcp per IP.
pub static AUTH_FAIL_LIMIT: LazyLock<RateLimiter> = LazyLock::new(|| RateLimiter::new(Duration::from_secs(60), 30));
/// Requests per caller.
pub static REQUEST_LIMIT: LazyLock<RateLimiter> = LazyLock::new(|| RateLimiter::new(Duration::from_secs(60), 120));
/// State-changing tool calls per caller.
pub static ACTION_LIMIT: LazyLock<RateLimiter> = LazyLock::new(|| RateLimiter::new(Duration::from_secs(60), 10));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_url_is_https_origin_only() {
        assert_eq!(normalize_public_url("https://WS1.Example.com:8553/").unwrap(), "https://ws1.example.com:8553");
        assert_eq!(normalize_public_url("https://ws1.example.com:443").unwrap(), "https://ws1.example.com");
        assert!(normalize_public_url("http://ws1.example.com").is_err());
        assert!(normalize_public_url("https://ws1.example.com/mcp").is_err());
        assert!(normalize_public_url("https://u:p@ws1.example.com").is_err());
        assert!(normalize_public_url("https://ws1.example.com/?x=1").is_err());
        assert!(normalize_public_url("ws1.example.com").is_err());
    }

    #[test]
    fn issuer_requires_enabled_and_url() {
        let mut c = McpConfig { enabled: false, public_url: "https://a.example.com".into(), allow_api_keys: false };
        assert!(c.issuer().is_none());
        c.enabled = true;
        assert_eq!(c.resource().as_deref(), Some("https://a.example.com/mcp"));
    }

    #[test]
    fn rate_limiter_enforces_window() {
        let rl = RateLimiter::new(Duration::from_secs(60), 2);
        assert!(rl.allow("a"));
        assert!(rl.allow("a"));
        assert!(!rl.allow("a"));
        assert!(rl.allow("b"));
    }

    #[test]
    fn ipv6_is_limited_per_64() {
        let a: std::net::IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: std::net::IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let c: std::net::IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(limiter_key(a), limiter_key(b));
        assert_ne!(limiter_key(a), limiter_key(c));
        let mapped: std::net::IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(limiter_key(mapped), "192.0.2.7");
    }

    #[test]
    fn linux_check_rejects_unsafe_names() {
        assert!(linux_shadow_hash("root:x").is_none());
        assert!(linux_shadow_hash("../etc").is_none());
        assert!(linux_shadow_hash("").is_none());
    }

    #[test]
    fn credential_fingerprint_changes_with_any_part() {
        let a = credential_fingerprint(&["wolfstack", "$6$hash", ""]);
        assert_eq!(a, credential_fingerprint(&["wolfstack", "$6$hash", ""]));
        assert_ne!(a, credential_fingerprint(&["wolfstack", "$6$other", ""]));
        assert_ne!(a, credential_fingerprint(&["wolfstack", "$6$hash", "TOTPSECRET"]));
        // Field boundaries are unambiguous.
        assert_ne!(credential_fingerprint(&["ab", "c"]), credential_fingerprint(&["a", "bc"]));
    }
}
