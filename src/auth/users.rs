// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! WolfStack user management with optional TOTP two-factor authentication.
//!
//! Users are stored in /etc/wolfstack/users.json. Each user has a username,
//! a password hash (using the system crypt() function), an optional TOTP
//! secret for 2FA, and a role.

use serde::{Deserialize, Serialize};

fn users_config_path() -> String {
    let cfg = crate::paths::get().config_dir;
    format!("{}/users.json", cfg)
}

fn auth_config_path() -> String {
    let cfg = crate::paths::get().config_dir;
    format!("{}/auth-config.json", cfg)
}

/// Wall-clock milliseconds since the epoch — the logical version stamp for
/// control-plane replication. Last-write-wins compares these across nodes, so
/// nodes should run NTP (they do in any real cluster). Monotonic enough for a
/// human-paced admin action (create/delete/change user).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ─── Auth Config ───

/// Controls which authentication backends are active
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// "linux" = system users only, "wolfstack" = WolfStack users only,
    /// "both" = either works (default). "both" is the default because it's
    /// non-breaking — with no WolfStack users it behaves exactly like "linux"
    /// (system logins only), but the moment an operator creates a WolfStack
    /// user it works on every node of every cluster (replicated) with zero
    /// extra setup.
    #[serde(default = "default_auth_mode")]
    pub auth_mode: String,
    /// Whether to require 2FA for WolfStack users that have it enabled
    #[serde(default = "default_true")]
    pub require_2fa_when_configured: bool,
    /// Logical version (epoch-ms of last change) for control-plane
    /// replication. Newer wins. Defaults to 0 on configs written before
    /// replication existed, so any explicit save supersedes them.
    #[serde(default)]
    pub version: u64,
}

fn default_auth_mode() -> String { "both".into() }
fn default_true() -> bool { true }

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            auth_mode: default_auth_mode(),
            require_2fa_when_configured: true,
            version: 0,
        }
    }
}

impl AuthConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(auth_config_path()) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = auth_config_path();
        // Stamp a fresh version on every save so the change wins control-plane
        // replication (see UserStore::save for the rationale).
        let mut stamped = self.clone();
        stamped.version = now_ms();
        let json = serde_json::to_string_pretty(&stamped).map_err(|e| e.to_string())?;
        // 0600 — config tunes auth behaviour and can carry secrets.
        crate::paths::write_secure(&path, json)
            .map_err(|e| format!("Failed to write auth config: {}", e))
    }
}

// ─── User Model ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfUser {
    pub username: String,
    /// Password hash (system crypt() format — same as /etc/shadow)
    pub password_hash: String,
    /// TOTP secret (base32-encoded, empty = 2FA not enabled)
    #[serde(default)]
    pub totp_secret: String,
    /// Whether 2FA is enabled for this user
    #[serde(default)]
    pub totp_enabled: bool,
    /// User role: "admin" or "viewer"
    #[serde(default = "default_role")]
    pub role: String,
    /// Display name (optional)
    #[serde(default)]
    pub display_name: String,
    /// Email address (used for password reset)
    #[serde(default)]
    pub email: String,
    /// When the user was created
    #[serde(default)]
    pub created_at: String,
    /// Cluster names this user is allowed to see / act on. Empty =
    /// all clusters (backward-compatible default for existing users).
    /// Admin-role users always pass the access check regardless of
    /// this list so an operator can't lock themselves out.
    #[serde(default)]
    pub allowed_clusters: Vec<String>,
}

impl WolfUser {
    /// Can this user see nodes / containers / metrics / etc. that live
    /// inside the given cluster? Admins bypass the allowlist, empty
    /// allowlist = all clusters, otherwise exact cluster-name match.
    /// Pass None for `cluster_name` (unassigned / proxmox edge case)
    /// to mean "visible to everyone" — those nodes haven't been
    /// grouped yet so we default to showing them rather than hiding.
    pub fn can_access_cluster(&self, cluster_name: Option<&str>) -> bool {
        if self.role == "admin" { return true; }
        if self.allowed_clusters.is_empty() { return true; }
        match cluster_name {
            Some(c) => self.allowed_clusters.iter().any(|x| x == c),
            None => true,
        }
    }
}

fn default_role() -> String { "admin".into() }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserStore {
    pub users: Vec<WolfUser>,
    /// Logical version (epoch-ms of last mutation) for control-plane
    /// replication. Bumped by every add/remove/edit; newer wins across the
    /// fleet. Defaults to 0 for pre-replication stores.
    #[serde(default)]
    pub version: u64,
}

impl UserStore {
    pub fn load() -> Self {
        match std::fs::read_to_string(users_config_path()) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = users_config_path();
        // Stamp a fresh logical version on EVERY save so any mutation wins
        // control-plane replication and no handler can forget to bump it.
        // (Replication ADOPTION writes the file directly via write_secure, not
        // through save(), so it preserves the originating peer's version.)
        let mut stamped = self.clone();
        stamped.version = now_ms();
        let json = serde_json::to_string_pretty(&stamped).map_err(|e| e.to_string())?;
        // 0600 — this file contains password hashes. Pre-v18.7.30 it
        // was world-readable, giving any local user the hashes to
        // offline-crack.
        crate::paths::write_secure(&path, json)
            .map_err(|e| format!("Failed to write users config: {}", e))
    }

    pub fn find(&self, username: &str) -> Option<&WolfUser> {
        self.users.iter().find(|u| u.username == username)
    }

    pub fn find_mut(&mut self, username: &str) -> Option<&mut WolfUser> {
        self.users.iter_mut().find(|u| u.username == username)
    }

    pub fn add(&mut self, user: WolfUser) -> Result<(), String> {
        if self.find(&user.username).is_some() {
            return Err(format!("User '{}' already exists", user.username));
        }
        self.users.push(user);
        self.save() // save() stamps a fresh version for replication
    }

    pub fn remove(&mut self, username: &str) -> Result<(), String> {
        let before = self.users.len();
        self.users.retain(|u| u.username != username);
        if self.users.len() == before {
            return Err(format!("User '{}' not found", username));
        }
        self.save() // save() stamps a fresh version for replication
    }
}

// ─── Control-plane replication (users + auth config) ───

/// Snapshot the replicable control-plane state for a sync push:
/// `(users_json, users_version, auth_json, auth_version)`. The JSON is the
/// raw on-disk form (version field included) so a receiver can write it
/// verbatim.
pub fn control_plane_snapshot() -> (String, u64, String, u64) {
    let users = UserStore::load();
    // Pretty-print to match what save() writes, so the replicated file is
    // byte-identical to a locally-saved one (clean audits / diffs).
    let users_json = serde_json::to_string_pretty(&users).unwrap_or_default();
    let auth = AuthConfig::load();
    let auth_json = serde_json::to_string_pretty(&auth).unwrap_or_default();
    (users_json, users.version, auth_json, auth.version)
}

/// Serialises concurrent control-plane applies (two peers pushing at the same
/// instant) so the load-version → check → write window can't race.
static CONTROL_PLANE_APPLY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Apply replicated control-plane state from a peer, last-write-wins by
/// version. Each blob is written ONLY when its incoming version is strictly
/// newer than the local one AND it parses cleanly (so a malformed or empty
/// payload can never clobber a good local file). Returns
/// `(users_updated, auth_updated)`.
pub fn control_plane_apply(
    users_json: &str,
    users_version: u64,
    auth_json: &str,
    auth_version: u64,
) -> (bool, bool) {
    // Hold the apply lock across the whole check-then-write so two peers
    // applying concurrently can't both pass the version check and double-write.
    let _guard = CONTROL_PLANE_APPLY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut users_updated = false;
    let mut auth_updated = false;

    if users_version > UserStore::load().version
        && !users_json.trim().is_empty()
        && serde_json::from_str::<UserStore>(users_json).is_ok()
        && crate::paths::write_secure(&users_config_path(), users_json).is_ok() {
            users_updated = true;
        }

    if auth_version > AuthConfig::load().version
        && !auth_json.trim().is_empty()
        && serde_json::from_str::<AuthConfig>(auth_json).is_ok()
        && crate::paths::write_secure(&auth_config_path(), auth_json).is_ok() {
            auth_updated = true;
        }

    (users_updated, auth_updated)
}

pub fn hash_password(password: &str) -> Result<String, String> {
    let params = sha_crypt::Sha512Params::new(5000)
        .map_err(|e| format!("SHA-512 params error: {:?}", e))?;
    sha_crypt::sha512_simple(password, &params)
        .map_err(|e| format!("SHA-512 hash error: {:?}", e))
}

/// Verify a password against a stored hash
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    super::verify_password(password, stored_hash)
}

// ─── TOTP (RFC 6238) ───

/// Generate a new random TOTP secret (base32-encoded, 20 bytes)
pub fn generate_totp_secret() -> String {
    let mut bytes = [0u8; 20];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut bytes);
    }
    data_encoding::BASE32_NOPAD.encode(&bytes)
}

/// Generate a TOTP code for the current time
#[allow(dead_code)]
pub fn generate_totp(secret_b32: &str, time_step: u64) -> Result<String, String> {
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_b32.to_uppercase().as_bytes())
        .map_err(|e| format!("Invalid TOTP secret: {}", e))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("System time error: {}", e))?;

    let counter = now.as_secs() / time_step;
    Ok(hotp(&secret, counter))
}

/// Verify a TOTP code (allows ±1 time step for clock skew)
pub fn verify_totp(secret_b32: &str, code: &str) -> bool {
    let secret = match data_encoding::BASE32_NOPAD.decode(secret_b32.to_uppercase().as_bytes()) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return false,
    };

    let time_step = 30u64;

    // Check current time step and ±1 for clock skew
    for offset in [0i64, -1, 1] {
        let counter = ((now as i64 / time_step as i64) + offset) as u64;
        let expected = hotp(&secret, counter);
        if constant_time_eq(code.as_bytes(), expected.as_bytes()) {
            return true;
        }
    }
    false
}

/// HOTP (RFC 4226) — HMAC-based one-time password
fn hotp(secret: &[u8], counter: u64) -> String {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    // TOTP uses HMAC-SHA1 per RFC 6238
    type HmacSha1 = Hmac<Sha1>;

    let counter_bytes = counter.to_be_bytes();
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 section 5.4)
    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let code = ((result[offset] as u32 & 0x7f) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);
    let otp = code % 1_000_000;
    format!("{:06}", otp)
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Generate an otpauth:// URI for QR code generation
pub fn totp_uri(secret_b32: &str, username: &str) -> String {
    let issuer = "WolfStack";
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        urlencoding::encode(issuer),
        urlencoding::encode(username),
        secret_b32,
        urlencoding::encode(issuer),
    )
}

/// Render an otpauth:// URI as an SVG QR code on this host. The URI carries
/// the TOTP secret, so it must never be handed to a third-party QR service.
pub fn totp_qr_svg(uri: &str) -> Result<String, String> {
    let code = qrcode::QrCode::new(uri.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod totp_qr_tests {
    #[test]
    fn qr_is_a_self_contained_svg() {
        let secret = super::generate_totp_secret();
        let svg = super::totp_qr_svg(&super::totp_uri(&secret, "admin")).expect("render");
        assert!(svg.contains("<svg") && svg.ends_with("</svg>"));
        // The only URL is the SVG namespace: nothing is fetched from anywhere,
        // and neither the URI nor the secret appears as text.
        assert_eq!(svg.matches("http").count(), 1);
        assert!(svg.contains(r#"xmlns="http://www.w3.org/2000/svg""#));
        assert!(!svg.contains("otpauth") && !svg.contains(&secret));
    }
}

/// Authenticate a WolfStack user (password check, no 2FA)
pub fn authenticate_wolfstack_user(username: &str, password: &str) -> Option<WolfUser> {
    let store = UserStore::load();
    let user = store.find(username)?;
    if verify_password(password, &user.password_hash) {
        Some(user.clone())
    } else {
        None
    }
}

// ─── Password Hashing (pure Rust, no libcrypt dependency) ───

/// Hash a password using SHA-512 crypt (same as Linux /etc/shadow)
#[cfg(test)]
mod password_roundtrip_tests {
    /// The password-reset flow writes hash_password() output into the
    /// UserStore and login verifies it via verify_password() (native
    /// libc crypt() when available, pure-Rust sha512_check otherwise).
    /// If those two ever disagree on hash format, reset "succeeds" and
    /// every subsequent login fails — lock the contract.
    #[test]
    fn hash_then_verify_roundtrip() {
        let h = super::hash_password("test-password-123").expect("hash");
        assert!(h.starts_with("$6$"), "expected sha512-crypt format, got {}", &h[..h.len().min(12)]);
        assert!(super::verify_password("test-password-123", &h), "fresh hash must verify");
        assert!(!super::verify_password("wrong-password", &h), "wrong password must fail");
    }
}
