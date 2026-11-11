// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! WebAuthn (Passkeys / FIDO2) — registration + authentication via the
//! `webauthn-rs` crate. Storage lives in /etc/wolfstack/webauthn.json.
//!
//! Two ceremonies, each two-step:
//! - Registration: existing logged-in user adds a passkey to their account.
//!   `start_registration` returns a challenge + an opaque `ceremony_id` the
//!   client must echo back; `finish_registration` consumes the response
//!   and persists the credential.
//! - Authentication: anonymous client logs in using a passkey.
//!   `start_authentication` issues a discoverable-credential challenge
//!   when no username is given, or a challenge listing that user's
//!   credentials when one is; `finish_authentication` verifies the
//!   assertion, identifies which stored credential signed it, and returns
//!   the username for session creation upstream.
//!
//! Registration asks for a *discoverable* (resident) credential so the
//! username-less login works. Credentials registered before that change
//! were requested as non-discoverable — a security key holding one has
//! nothing to offer an empty allow-list — so those still log in through
//! the username-scoped path.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::{Instant, Duration};

use webauthn_rs::prelude::*;

/// In-flight ceremonies expire after 5 minutes — plenty of time for the
/// user to interact with their authenticator, but short enough that
/// abandoned ceremonies don't accumulate.
const CEREMONY_TTL: Duration = Duration::from_secs(300);

fn webauthn_config_path() -> String {
    let cfg = crate::paths::get().config_dir;
    format!("{}/webauthn.json", cfg)
}

// ═══════════════════════════════════════════════
// ─── Data Types ───
// ═══════════════════════════════════════════════

/// Top-level WebAuthn configuration, persisted to /etc/wolfstack/webauthn.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Whether passkey/WebAuthn login is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Relying Party ID — typically the hostname (e.g. "wolfstack.example.com").
    /// Captured at first registration; subsequent registrations must match
    /// otherwise WebAuthn will reject the assertion.
    #[serde(default)]
    pub rp_id: String,
    /// Relying Party display name shown in authenticator prompts
    #[serde(default = "default_rp_name")]
    pub rp_name: String,
    /// Origin URL for the RP (e.g. "https://wolfstack.example.com:8553")
    #[serde(default)]
    pub origin: String,
    /// Stored credentials per user
    #[serde(default)]
    pub credentials: Vec<StoredCredential>,
}

fn default_rp_name() -> String {
    "WolfStack".to_string()
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rp_id: String::new(),
            rp_name: default_rp_name(),
            origin: String::new(),
            credentials: Vec::new(),
        }
    }
}

impl WebAuthnConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(webauthn_config_path()) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save with mode 0600 — credentials don't contain shared secrets but
    /// the file does map credential IDs to usernames, which is enough to
    /// fingerprint who has registered passkeys on the box.
    pub fn save(&self) -> Result<(), String> {
        let path = webauthn_config_path();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::paths::write_secure(&path, &json)
            .map_err(|e| format!("Failed to write WebAuthn config: {}", e))
    }
}

/// A stored WebAuthn credential — represents a registered passkey/security key.
/// `passkey_data` is the JSON-serialised webauthn-rs `Passkey`, which is the
/// authoritative cryptographic state. The legacy fields (credential_id,
/// public_key, sign_count, aaguid) are kept for display and pre-existing
/// JSON compatibility but are not used to verify assertions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// Unique credential ID (base64url-encoded, from the authenticator) — display only
    pub credential_id: String,
    /// Username this credential belongs to
    pub username: String,
    /// Human-readable label (e.g. "YubiKey 5", "MacBook Touch ID")
    #[serde(default)]
    pub label: String,
    /// COSE public key (base64url-encoded) — display only; webauthn-rs verifies via `passkey_data`
    #[serde(default)]
    pub public_key: String,
    /// Signature counter — display only; live counter lives inside `passkey_data`
    #[serde(default)]
    pub sign_count: u32,
    /// When this credential was registered (ISO 8601)
    #[serde(default)]
    pub registered_at: String,
    /// When this credential was last used (ISO 8601), empty if never
    #[serde(default)]
    pub last_used_at: String,
    /// Authenticator Attestation GUID — identifies the make/model
    #[serde(default)]
    pub aaguid: String,
    /// JSON-serialised webauthn-rs `Passkey` — the cryptographic state used
    /// for assertion verification. Empty for credentials migrated from
    /// pre-webauthn-rs scaffolding (those cannot be used to authenticate).
    #[serde(default)]
    pub passkey_data: String,
}

// ═══════════════════════════════════════════════
// ─── Credential Management ───
// ═══════════════════════════════════════════════

/// List all stored credentials for a given username.
pub fn list_credentials(config: &WebAuthnConfig, username: &str) -> Vec<StoredCredential> {
    config
        .credentials
        .iter()
        .filter(|c| c.username == username)
        .cloned()
        .collect()
}

/// Remove a credential by its credential_id. Returns Ok(true) if found and removed,
/// Ok(false) if not found.
pub fn remove_credential(config: &mut WebAuthnConfig, credential_id: &str) -> Result<bool, String> {
    let before = config.credentials.len();
    config
        .credentials
        .retain(|c| c.credential_id != credential_id);
    let removed = config.credentials.len() < before;
    if removed {
        config.save()?;
    }
    Ok(removed)
}

// ═══════════════════════════════════════════════
// ─── Ceremony state — in-memory, TTL'd ───
// ═══════════════════════════════════════════════

struct StoredState<T> {
    data: T,
    created: Instant,
    /// For registration ceremonies, the username this challenge was issued to.
    /// For authentication ceremonies, this is empty (discoverable login).
    username: String,
}

fn registrations() -> &'static RwLock<HashMap<String, StoredState<PasskeyRegistration>>> {
    static R: OnceLock<RwLock<HashMap<String, StoredState<PasskeyRegistration>>>> = OnceLock::new();
    R.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Which kind of authentication challenge a ceremony was issued as —
/// decides which webauthn-rs finish call verifies the assertion.
enum AuthCeremony {
    /// Empty allow-list; the authenticator picks a resident credential.
    Discoverable(DiscoverableAuthentication),
    /// Allow-list of one user's credentials (works for non-resident ones).
    Scoped(PasskeyAuthentication),
}

fn authentications() -> &'static RwLock<HashMap<String, StoredState<AuthCeremony>>> {
    static A: OnceLock<RwLock<HashMap<String, StoredState<AuthCeremony>>>> = OnceLock::new();
    A.get_or_init(|| RwLock::new(HashMap::new()))
}

fn purge_expired<T>(map: &mut HashMap<String, StoredState<T>>) {
    map.retain(|_, s| s.created.elapsed() < CEREMONY_TTL);
}

// ═══════════════════════════════════════════════
// ─── Webauthn instance ───
// ═══════════════════════════════════════════════

/// Build a `Webauthn` instance for the given RP ID + origin. Returns a
/// human-readable error if the inputs are malformed (most commonly:
/// the origin is an IP address, which browsers reject for WebAuthn).
fn build_webauthn(rp_id: &str, origin: &str) -> Result<Webauthn, String> {
    if rp_id.is_empty() {
        return Err("WebAuthn RP ID is empty — pass a hostname (not an IP)".to_string());
    }
    // Reject pure IP addresses up front — browsers will not allow WebAuthn
    // on a bare IP, and the resulting failure is opaque if we let it through.
    if rp_id.parse::<std::net::IpAddr>().is_ok() {
        return Err(format!(
            "WebAuthn requires a hostname, but the request came in as the IP '{}'. \
             Access WolfStack via a hostname (or add a /etc/hosts entry) to use passkeys.",
            rp_id
        ));
    }
    let origin_url = Url::parse(origin)
        .map_err(|e| format!("Invalid origin URL '{}': {}", origin, e))?;
    let rp_name = default_rp_name();
    let builder = WebauthnBuilder::new(rp_id, &origin_url)
        .map_err(|e| format!("WebauthnBuilder::new failed: {}", e))?
        .rp_name(&rp_name);
    builder.build().map_err(|e| format!("Webauthn build failed: {}", e))
}

// ═══════════════════════════════════════════════
// ─── Registration ceremony ───
// ═══════════════════════════════════════════════

/// Begin the registration ceremony. The caller (the API endpoint) must
/// already have authenticated `username` via the existing PAM/WolfStack
/// session — this function does not authorise, it just issues a challenge.
///
/// Returns `(challenge_json, ceremony_id)`. The challenge is what the
/// browser feeds to `navigator.credentials.create()`. The ceremony_id is
/// opaque — the client echoes it back to `finish_registration`.
pub fn start_registration(
    config: &WebAuthnConfig,
    rp_id: &str,
    origin: &str,
    username: &str,
    display_name: &str,
) -> Result<(serde_json::Value, String), String> {
    let webauthn = build_webauthn(rp_id, origin)?;

    // Exclude credentials this user already has, so the browser refuses
    // to re-register the same authenticator twice.
    let exclude: Vec<CredentialID> = usable_passkeys(config, username)
        .into_iter()
        .map(|(_, p)| p.cred_id().clone())
        .collect();

    // Stable per-user UUID derived from the username — webauthn-rs uses it
    // as the WebAuthn `user.id`. We deterministically hash the username so
    // re-registering on the same account ties to the same user handle.
    let user_uuid = username_to_uuid(username);

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(user_uuid, username, display_name, Some(exclude))
        .map_err(|e| format!("start_passkey_registration: {}", e))?;

    let ceremony_id = uuid::Uuid::new_v4().to_string();
    {
        let mut map = registrations().write().unwrap();
        purge_expired(&mut map);
        map.insert(
            ceremony_id.clone(),
            StoredState {
                data: reg_state,
                created: Instant::now(),
                username: username.to_string(),
            },
        );
    }

    let mut json = serde_json::to_value(&ccr)
        .map_err(|e| format!("serialise CreationChallengeResponse: {}", e))?;
    require_discoverable(&mut json)?;
    Ok((json, ceremony_id))
}

/// Complete the registration ceremony. Verifies the authenticator's
/// attestation against the stored challenge, then persists the new
/// credential to disk.
///
/// The `username` parameter is checked against the username the ceremony
/// was issued for — this prevents a logged-in user from registering a
/// credential under a different account by tampering with the request body.
pub fn finish_registration(
    config: &mut WebAuthnConfig,
    rp_id: &str,
    origin: &str,
    ceremony_id: &str,
    username: &str,
    label: &str,
    response: &serde_json::Value,
) -> Result<StoredCredential, String> {
    let webauthn = build_webauthn(rp_id, origin)?;

    let reg_state = {
        let mut map = registrations().write().unwrap();
        purge_expired(&mut map);
        let entry = map.remove(ceremony_id)
            .ok_or_else(|| "No matching registration ceremony — it may have expired".to_string())?;
        if entry.username != username {
            return Err("Registration ceremony belongs to a different user".to_string());
        }
        entry.data
    };

    let reg_response: RegisterPublicKeyCredential = serde_json::from_value(response.clone())
        .map_err(|e| format!("Invalid registration response payload: {}", e))?;

    let passkey = webauthn
        .finish_passkey_registration(&reg_response, &reg_state)
        .map_err(|e| format!("finish_passkey_registration: {}", e))?;

    // Pin the RP/origin for this config the first time anything is
    // registered. Subsequent registrations under the same RP are normal;
    // a different RP is rejected because cross-RP credentials wouldn't
    // verify against the existing ones anyway.
    if config.rp_id.is_empty() {
        config.rp_id = rp_id.to_string();
        config.origin = origin.to_string();
    } else if config.rp_id != rp_id {
        return Err(format!(
            "WebAuthn is bound to RP '{}' on this server. Access WolfStack via that hostname to register passkeys.",
            config.rp_id
        ));
    }
    config.enabled = true;

    let cred_id_b64 = base64_url(passkey.cred_id().as_ref());
    let now = chrono::Utc::now().to_rfc3339();
    let passkey_json = serde_json::to_string(&passkey)
        .map_err(|e| format!("serialise Passkey: {}", e))?;

    let stored = StoredCredential {
        credential_id: cred_id_b64,
        username: username.to_string(),
        label: label.to_string(),
        public_key: String::new(),
        sign_count: 0,
        registered_at: now,
        last_used_at: String::new(),
        aaguid: String::new(),
        passkey_data: passkey_json,
    };

    config.credentials.push(stored.clone());
    config.save()?;
    Ok(stored)
}

// ═══════════════════════════════════════════════
// ─── Authentication ceremony (discoverable) ───
// ═══════════════════════════════════════════════

/// Begin the authentication ceremony.
///
/// With no `username` (or one that has no usable passkeys) this is the
/// *discoverable* challenge — the browser lets the user pick any resident
/// credential without us knowing who they are. With a username that has
/// passkeys, the challenge lists that user's credential IDs, which is the
/// only way an authenticator can use a non-resident credential (every
/// passkey registered before registration required resident keys).
///
/// Listing credential IDs for a typed username does reveal that the
/// account has passkeys; that is inherent to non-discoverable WebAuthn
/// and the endpoint sits behind the login rate limiter.
pub fn start_authentication(
    config: &WebAuthnConfig,
    rp_id: &str,
    origin: &str,
    username: Option<&str>,
) -> Result<(serde_json::Value, String), String> {
    let webauthn = build_webauthn(rp_id, origin)?;

    let user_passkeys: Vec<Passkey> = match username {
        Some(u) => usable_passkeys(config, u).into_iter().map(|(_, pk)| pk).collect(),
        None => Vec::new(),
    };

    let (rcr, auth_state) = if user_passkeys.is_empty() {
        let (rcr, st) = webauthn
            .start_discoverable_authentication()
            .map_err(|e| format!("start_discoverable_authentication: {}", e))?;
        (rcr, AuthCeremony::Discoverable(st))
    } else {
        let (rcr, st) = webauthn
            .start_passkey_authentication(&user_passkeys)
            .map_err(|e| format!("start_passkey_authentication: {}", e))?;
        (rcr, AuthCeremony::Scoped(st))
    };
    let ceremony_username = if user_passkeys.is_empty() {
        String::new()
    } else {
        username.unwrap_or_default().to_string()
    };

    let ceremony_id = uuid::Uuid::new_v4().to_string();
    {
        let mut map = authentications().write().unwrap();
        purge_expired(&mut map);
        map.insert(
            ceremony_id.clone(),
            StoredState {
                data: auth_state,
                created: Instant::now(),
                username: ceremony_username,
            },
        );
    }

    let json = serde_json::to_value(&rcr)
        .map_err(|e| format!("serialise RequestChallengeResponse: {}", e))?;
    Ok((json, ceremony_id))
}

/// Complete the authentication ceremony. Returns the username of the
/// authenticated user on success. The caller is responsible for creating
/// the session/cookie.
pub fn finish_authentication(
    config: &mut WebAuthnConfig,
    rp_id: &str,
    origin: &str,
    ceremony_id: &str,
    response: &serde_json::Value,
) -> Result<String, String> {
    let webauthn = build_webauthn(rp_id, origin)?;

    let (auth_state, ceremony_username) = {
        let mut map = authentications().write().unwrap();
        purge_expired(&mut map);
        let entry = map.remove(ceremony_id)
            .ok_or_else(|| "No matching authentication ceremony — it may have expired".to_string())?;
        (entry.data, entry.username)
    };

    let auth_response: PublicKeyCredential = serde_json::from_value(response.clone())
        .map_err(|e| format!("Invalid authentication response payload: {}", e))?;

    let unknown = || "Unknown credential — passkey not registered on this server".to_string();

    let (idx, passkey, result) = match auth_state {
        AuthCeremony::Discoverable(st) => {
            // Identify which credential the assertion came from so we can
            // look up the matching Passkey and the user it belongs to.
            let (_user_uuid, cred_id) = webauthn
                .identify_discoverable_authentication(&auth_response)
                .map_err(|e| format!("identify_discoverable_authentication: {}", e))?;
            let (idx, passkey) = find_passkey(config, &base64_url(cred_id), None)
                .ok_or_else(unknown)?;
            let discoverable: DiscoverableKey = (&passkey).into();
            let result = webauthn
                .finish_discoverable_authentication(&auth_response, st, &[discoverable])
                .map_err(|e| format!("finish_discoverable_authentication: {}", e))?;
            (idx, passkey, result)
        }
        AuthCeremony::Scoped(st) => {
            // webauthn-rs-core `authenticate_credential` already rejects a
            // credential ID outside the challenge's allow-list
            // (CredentialNotFound); the username filter makes our own
            // lookup state the same restriction.
            let cred_id_b64 = base64_url(auth_response.get_credential_id());
            let (idx, passkey) = find_passkey(config, &cred_id_b64, Some(&ceremony_username))
                .ok_or_else(unknown)?;
            let result = webauthn
                .finish_passkey_authentication(&auth_response, &st)
                .map_err(|e| format!("finish_passkey_authentication: {}", e))?;
            (idx, passkey, result)
        }
    };

    // Update counter / state if webauthn-rs says so. The mutable Passkey
    // copy needs to be re-serialised back into storage.
    let mut updated_pk = passkey;
    let _ = updated_pk.update_credential(&result);
    if let Ok(json) = serde_json::to_string(&updated_pk) {
        config.credentials[idx].passkey_data = json;
    }
    config.credentials[idx].last_used_at = chrono::Utc::now().to_rfc3339();

    let username = config.credentials[idx].username.clone();
    config.save()?;

    // Pin RP if not already (defensive — registration normally does this)
    if config.rp_id.is_empty() {
        config.rp_id = rp_id.to_string();
        config.origin = origin.to_string();
        config.enabled = true;
        let _ = config.save();
    }

    Ok(username)
}

// ═══════════════════════════════════════════════
// ─── Helpers ───
// ═══════════════════════════════════════════════

/// webauthn-rs 0.5 `start_passkey_registration` hard-codes
/// `require_resident_key(false)`, which sends `residentKey: "discouraged"`
/// (webauthn-rs-core core.rs `generate_challenge_register`). A security key
/// then stores no credential on-device, so the discoverable login (empty
/// allow-list) has nothing to offer. Ask for a resident credential instead.
/// This only changes the options sent to the browser: `register_credential`
/// ignores the state's `require_resident_key`, so verification is unchanged.
///
/// Edited on the serialised JSON because the prelude does not re-export
/// `ResidentKeyRequirement`. Key names are webauthn-rs-proto's camelCase
/// serde names (attest.rs `CreationChallengeResponse.public_key`,
/// `PublicKeyCredentialCreationOptions.authenticator_selection`, options.rs
/// `AuthenticatorSelectionCriteria`) and match the WebAuthn spec.
fn require_discoverable(ccr: &mut serde_json::Value) -> Result<(), String> {
    let sel = ccr
        .get_mut("publicKey")
        .and_then(|pk| pk.get_mut("authenticatorSelection"))
        .and_then(|s| s.as_object_mut())
        .ok_or_else(|| "registration challenge has no authenticatorSelection".to_string())?;
    sel.insert("residentKey".into(), serde_json::Value::from("required"));
    sel.insert("requireResidentKey".into(), serde_json::Value::from(true));
    Ok(())
}

/// Every stored credential of `username` that carries webauthn-rs state.
fn usable_passkeys(config: &WebAuthnConfig, username: &str) -> Vec<(usize, Passkey)> {
    config
        .credentials
        .iter()
        .enumerate()
        .filter(|(_, c)| c.username == username && !c.passkey_data.is_empty())
        .filter_map(|(i, c)| serde_json::from_str::<Passkey>(&c.passkey_data).ok().map(|pk| (i, pk)))
        .collect()
}

/// Find the stored credential with this base64url ID, optionally
/// restricted to one user.
fn find_passkey(config: &WebAuthnConfig, cred_id_b64: &str, username: Option<&str>) -> Option<(usize, Passkey)> {
    config.credentials.iter().enumerate().find_map(|(i, c)| {
        if c.credential_id != cred_id_b64 || c.passkey_data.is_empty() {
            return None;
        }
        if username.is_some_and(|u| u != c.username) {
            return None;
        }
        serde_json::from_str::<Passkey>(&c.passkey_data).ok().map(|pk| (i, pk))
    })
}

/// Deterministic UUID v5 derived from the username. WebAuthn requires a
/// stable user.id across registrations; using a derived UUID means we
/// don't need to maintain a separate username→uuid mapping.
fn username_to_uuid(username: &str) -> uuid::Uuid {
    // Namespace UUID — arbitrary but constant for WolfStack. Never change
    // this value; doing so would orphan every existing passkey.
    const WOLFSTACK_NAMESPACE: uuid::Uuid =
        uuid::Uuid::from_bytes([0x57, 0x4f, 0x4c, 0x46, 0x53, 0x54, 0x41, 0x43,
                                0x4b, 0x57, 0x45, 0x42, 0x41, 0x55, 0x54, 0x4e]);
    uuid::Uuid::new_v5(&WOLFSTACK_NAMESPACE, username.as_bytes())
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(bytes)
}

// ═══════════════════════════════════════════════
// ─── Tests ───
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config_with_credentials() -> WebAuthnConfig {
        WebAuthnConfig {
            enabled: true,
            rp_id: "example.com".to_string(),
            rp_name: "WolfStack".to_string(),
            origin: "https://example.com:8553".to_string(),
            credentials: vec![
                StoredCredential {
                    credential_id: "cred-aaa".to_string(),
                    username: "alice".to_string(),
                    label: "YubiKey".to_string(),
                    public_key: "pk-aaa".to_string(),
                    sign_count: 5,
                    registered_at: "2025-01-01T00:00:00Z".to_string(),
                    last_used_at: "2025-06-15T12:00:00Z".to_string(),
                    aaguid: "".to_string(),
                    passkey_data: String::new(),
                },
                StoredCredential {
                    credential_id: "cred-bbb".to_string(),
                    username: "bob".to_string(),
                    label: "Touch ID".to_string(),
                    public_key: "pk-bbb".to_string(),
                    sign_count: 12,
                    registered_at: "2025-02-01T00:00:00Z".to_string(),
                    last_used_at: "".to_string(),
                    aaguid: "".to_string(),
                    passkey_data: String::new(),
                },
                StoredCredential {
                    credential_id: "cred-ccc".to_string(),
                    username: "alice".to_string(),
                    label: "Windows Hello".to_string(),
                    public_key: "pk-ccc".to_string(),
                    sign_count: 0,
                    registered_at: "2025-03-01T00:00:00Z".to_string(),
                    last_used_at: "".to_string(),
                    aaguid: "".to_string(),
                    passkey_data: String::new(),
                },
            ],
        }
    }

    #[test]
    fn test_list_credentials_filters_by_username() {
        let config = test_config_with_credentials();
        let alice_creds = list_credentials(&config, "alice");
        assert_eq!(alice_creds.len(), 2);
        assert!(alice_creds.iter().all(|c| c.username == "alice"));
    }

    #[test]
    fn test_list_credentials_empty_for_unknown_user() {
        let config = test_config_with_credentials();
        let creds = list_credentials(&config, "nobody");
        assert!(creds.is_empty());
    }

    #[test]
    fn test_default_config() {
        let config = WebAuthnConfig::default();
        assert!(!config.enabled);
        assert!(config.rp_id.is_empty());
        assert_eq!(config.rp_name, "WolfStack");
        assert!(config.credentials.is_empty());
    }

    #[test]
    fn test_username_to_uuid_is_stable() {
        let a = username_to_uuid("alice");
        let b = username_to_uuid("alice");
        let c = username_to_uuid("bob");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_build_webauthn_rejects_ip() {
        let r = build_webauthn("10.0.0.1", "https://10.0.0.1:8553");
        assert!(r.is_err());
        let msg = format!("{:?}", r);
        assert!(msg.contains("hostname"));
    }

    #[test]
    fn test_build_webauthn_rejects_empty_rp() {
        assert!(build_webauthn("", "https://example.com:8553").is_err());
    }

    #[test]
    fn test_build_webauthn_accepts_hostname() {
        let r = build_webauthn("wolfstack.example.com", "https://wolfstack.example.com:8553");
        assert!(r.is_ok(), "expected Ok, got {:?}", r);
    }

    #[test]
    fn test_registration_requests_discoverable_credential() {
        let config = WebAuthnConfig::default();
        let (json, _id) = start_registration(
            &config, "wolfstack.example.com", "https://wolfstack.example.com:8553", "alice", "alice",
        ).expect("start_registration");
        let sel = &json["publicKey"]["authenticatorSelection"];
        assert_eq!(sel["residentKey"], "required", "got {}", sel);
        assert_eq!(sel["requireResidentKey"], true, "got {}", sel);
    }

    #[test]
    fn test_authentication_without_passkeys_is_discoverable() {
        // Legacy credentials carry no passkey_data, so a typed username
        // with nothing usable must still get the discoverable challenge.
        let config = test_config_with_credentials();
        let (json, _id) = start_authentication(
            &config, "wolfstack.example.com", "https://wolfstack.example.com:8553", Some("alice"),
        ).expect("start_authentication");
        let allow = &json["publicKey"]["allowCredentials"];
        assert!(allow.as_array().is_none_or(|a| a.is_empty()), "got {}", allow);
    }

    #[test]
    fn test_find_passkey_respects_username() {
        let config = test_config_with_credentials();
        // No passkey_data on fixtures → never usable, whatever the filter.
        assert!(find_passkey(&config, "cred-aaa", None).is_none());
        assert!(find_passkey(&config, "cred-aaa", Some("alice")).is_none());
        assert!(usable_passkeys(&config, "alice").is_empty());
    }

    #[test]
    fn test_serialization_round_trip() {
        let config = test_config_with_credentials();
        let json = serde_json::to_string_pretty(&config).expect("serialize");
        let loaded: WebAuthnConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(loaded.credentials.len(), 3);
        assert_eq!(loaded.rp_id, "example.com");
        assert!(loaded.enabled);
    }
}
