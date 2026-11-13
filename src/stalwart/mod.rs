// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com
//
//! Stalwart Mail Manager — a Stalwart v1 mail cluster spread across WolfStack
//! nodes, sharing one Galera database, coordinated by Stalwart Keep (or Redis
//! Sentinel on hosts whose kernel is too old for Keep).
//!
//! Layers:
//!   * model + persistence (`/etc/wolfstack/stalwart.json`, secrets sealed
//!     with at_rest_crypto)              — this file
//!   * node-local checks                  — `preflight`
//!   * node-local container deploys       — `deploy`
//!   * Stalwart's JMAP management API     — `jmap`
//!   * the cross-node install job         — `install`
//!   * domain / mailbox management        — `manage`
//!   * HTTP handlers                      — `api`
//!
//! Every Stalwart behaviour this module relies on is cited at the point of
//! use against Stalwart v1.1.0 (github.com/stalwartlabs/stalwart tag v1.1.0)
//! or its documentation source (github.com/stalwartlabs/website,
//! `src/content/docs/docs/<path>.md`, published at stalw.art/docs/<path>).
//! v0.16 replaced the TOML config and the `/api` REST interface with JMAP
//! objects, so nothing here applies to Stalwart releases before v1.

pub mod api;
pub mod deploy;
pub mod install;
pub mod jmap;
pub mod manage;
pub mod preflight;

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

const CONFIG_PATH: &str = "/etc/wolfstack/stalwart.json";
/// at_rest_crypto purpose label. NEVER rename: the label is part of the key
/// derivation, so renaming it makes every stored secret undecryptable.
pub const SECRET_PURPOSE: &[u8] = b"stalwart-mail-cluster-v1";

/// Serialises read-modify-write of stalwart.json. Held only across sync file
/// IO, never across an `.await`.
static CONFIG_LOCK: Mutex<()> = Mutex::new(());

/// Which shared in-memory store + coordinator the cluster uses.
/// Source: docs cluster/configuration/coordination.md — a cluster needs a
/// shared InMemoryStore (Keep or Redis) and a Coordinator; a single node uses
/// the local default store with no coordinator.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CoordinatorKind {
    /// Single mail node: InMemoryStore `Default`, Coordinator `Disabled`.
    #[default]
    None,
    Keep,
    Redis,
}

/// One server running a Stalwart container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailNode {
    /// WolfStack node id (the peer's stable self_id).
    pub node_id: String,
    /// Display name of the WolfStack node, for the UI.
    #[serde(default)]
    pub label: String,
    /// `STALWART_HOSTNAME` — must be unique per node, because Stalwart leases
    /// node ids by hostname (docs cluster/configuration/node-id.md).
    pub stalwart_hostname: String,
    /// The node's WolfNet address. Stalwart's management listener (8080) is
    /// published on this address only, and the coordinator binds to it.
    pub wolfnet_ip: String,
    /// Public address mail is delivered to (shown in DNS guidance).
    #[serde(default)]
    pub public_ip: String,
}

/// One coordinator member (a Keep server, or a Valkey + Sentinel pair).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordMember {
    pub node_id: String,
    #[serde(default)]
    pub label: String,
    pub wolfnet_ip: String,
    /// Keep `--node` id. Unused for Redis.
    #[serde(default)]
    pub member_id: u32,
}

/// A managed Stalwart mail cluster. Lives in the owner node's stalwart.json —
/// the node the Galera cluster it uses is defined on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailCluster {
    /// Short lowercase id, used in container and database names.
    pub id: String,
    pub name: String,
    /// WolfStack cluster this belongs to (scopes the UI).
    #[serde(default)]
    pub cluster: String,
    /// self_id of the node that owns this record.
    #[serde(default)]
    pub owner_node: String,
    /// `SystemSettings.defaultHostname` — the one public name every node
    /// answers to (docs cluster/configuration/load-balancing.md).
    pub public_hostname: String,
    pub default_domain: String,

    pub galera_cluster_id: String,
    pub db_host: String,
    pub db_port: u16,
    pub db_name: String,
    pub db_user: String,
    #[serde(default)]
    pub db_password_enc: String,

    #[serde(default)]
    pub coordinator: CoordinatorKind,
    #[serde(default)]
    pub coordinator_members: Vec<CoordMember>,
    /// Keep cluster secret (shared with clients) and peer secret (servers only).
    #[serde(default)]
    pub keep_secret_enc: String,
    #[serde(default)]
    pub keep_peer_secret_enc: String,
    /// Valkey `requirepass` and Sentinel `requirepass`.
    #[serde(default)]
    pub redis_password_enc: String,
    #[serde(default)]
    pub sentinel_password_enc: String,

    #[serde(default)]
    pub mail_nodes: Vec<MailNode>,

    /// Stalwart's own administrator account (`admin@<default_domain>`), created
    /// by the Bootstrap step. Kept so the operator can sign in to Stalwart's
    /// web admin; WolfStack itself uses the API key below.
    #[serde(default)]
    pub admin_user: String,
    #[serde(default)]
    pub admin_password_enc: String,
    /// API key of the admin account (`API_…`). Bearer credentials are not
    /// subject to the account's two-factor setting, so WolfStack keeps working
    /// if the admin enrols TOTP (docs auth/authentication/api-key.md, 2fa.md).
    #[serde(default)]
    pub api_key_enc: String,

    #[serde(default)]
    pub created_at: String,
    /// "installing", "ready" or "failed". A record is saved as soon as an
    /// install starts so a failed install can still be removed from the UI.
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub last_error: String,
    /// What the install was asked for, so a failed install can be retried
    /// with the same settings.
    #[serde(default)]
    pub request_tls_certificate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MailConfig {
    #[serde(default)]
    pub clusters: Vec<MailCluster>,
}

// ── Secrets ──────────────────────────────────────────────────────────

/// Seal a secret for storage. Refuses (rather than storing an empty string)
/// when at_rest_crypto can't encrypt, so a stale key never silently loses a
/// credential the cluster can't be managed without.
pub fn seal(plain: &str) -> Result<String, String> {
    if plain.is_empty() {
        return Ok(String::new());
    }
    crate::at_rest_crypto::encrypt(plain.as_bytes(), SECRET_PURPOSE)
}

pub fn unseal(stored: &str) -> String {
    if stored.is_empty() {
        return String::new();
    }
    crate::at_rest_crypto::decrypt_or_legacy(stored, SECRET_PURPOSE, |_| String::new())
}

/// Random alphanumeric secret of `len` characters from the OS RNG.
pub fn random_secret(len: usize) -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rngs::OsRng;
    (0..len).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

/// 32 hexadecimal digits — the format Keep requires for both its cluster
/// secret and its peer secret (keep README "Settings": `--secret-file` /
/// `--peer-secret-file`, "32 hex digits").
pub fn random_hex32() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

// ── Persistence ──────────────────────────────────────────────────────

pub fn load_config() -> MailConfig {
    match std::fs::read_to_string(CONFIG_PATH) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => MailConfig::default(),
    }
}

fn save_config(cfg: &MailConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    crate::paths::write_secure(CONFIG_PATH, json).map_err(|e| format!("write {}: {}", CONFIG_PATH, e))
}

pub fn get_cluster(id: &str) -> Option<MailCluster> {
    load_config().clusters.into_iter().find(|c| c.id == id)
}

pub fn upsert_cluster(cluster: MailCluster) -> Result<(), String> {
    let _g = CONFIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut cfg = load_config();
    cfg.clusters.retain(|c| c.id != cluster.id);
    cfg.clusters.push(cluster);
    save_config(&cfg)
}

pub fn remove_cluster(id: &str) -> Result<(), String> {
    let _g = CONFIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut cfg = load_config();
    let before = cfg.clusters.len();
    cfg.clusters.retain(|c| c.id != id);
    if cfg.clusters.len() == before {
        return Err(format!("mail cluster '{}' not found", id));
    }
    save_config(&cfg)
}

/// Re-key every sealed field after a cluster-secret rotation. Fields that
/// don't decrypt with `old` are left untouched (never destroyed). Called from
/// `secret_rotation::reencrypt_all_at_rest`.
pub fn reencrypt_at_rest(old: &str, new: &str) -> Result<usize, String> {
    use crate::at_rest_crypto::{reencrypt_v2_field, ReencryptOutcome};
    let _g = CONFIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut cfg = load_config();
    let mut n = 0usize;
    for c in cfg.clusters.iter_mut() {
        for field in [
            &mut c.db_password_enc, &mut c.keep_secret_enc, &mut c.keep_peer_secret_enc,
            &mut c.redis_password_enc, &mut c.sentinel_password_enc,
            &mut c.admin_password_enc, &mut c.api_key_enc,
        ] {
            if let ReencryptOutcome::Rekeyed(v) = reencrypt_v2_field(field, SECRET_PURPOSE, old, new) {
                *field = v;
                n += 1;
            }
        }
    }
    if n > 0 {
        save_config(&cfg)?;
    }
    Ok(n)
}

/// The cluster as the API returns it: every sealed field blanked.
pub fn redacted(c: &MailCluster) -> MailCluster {
    let mut r = c.clone();
    r.db_password_enc.clear();
    r.keep_secret_enc.clear();
    r.keep_peer_secret_enc.clear();
    r.redis_password_enc.clear();
    r.sentinel_password_enc.clear();
    r.admin_password_enc.clear();
    r.api_key_enc.clear();
    r
}

/// Names that reach `docker`, file paths and SQL identifiers. Lowercase
/// letters, digits and `-`, 1–24 chars, starting with a letter.
pub fn valid_cluster_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 24
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// A DNS name: labels of letters/digits/hyphens, at least two labels.
pub fn valid_domain(d: &str) -> bool {
    let d = d.trim_end_matches('.');
    if d.len() > 253 || !d.contains('.') {
        return false;
    }
    d.split('.').all(|l| {
        !l.is_empty() && l.len() <= 63
            && !l.starts_with('-') && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Container names, derived from the cluster id.
pub fn stalwart_container(id: &str) -> String { format!("wolfstack-mail-{}", id) }
pub fn keep_container(id: &str) -> String { format!("wolfstack-mail-{}-keep", id) }
pub fn valkey_container(id: &str) -> String { format!("wolfstack-mail-{}-valkey", id) }
pub fn sentinel_container(id: &str) -> String { format!("wolfstack-mail-{}-sentinel", id) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_ids() {
        assert!(valid_cluster_id("mail"));
        assert!(valid_cluster_id("mail-2"));
        assert!(!valid_cluster_id(""));
        assert!(!valid_cluster_id("2mail"));
        assert!(!valid_cluster_id("Mail"));
        assert!(!valid_cluster_id("mail;rm"));
        assert!(!valid_cluster_id("a234567890123456789012345"));
    }

    #[test]
    fn domains() {
        assert!(valid_domain("example.com"));
        assert!(valid_domain("mx.example.co.uk"));
        assert!(!valid_domain("localhost"));
        assert!(!valid_domain("-bad.com"));
        assert!(!valid_domain("bad..com"));
        assert!(!valid_domain("ex ample.com"));
    }

    #[test]
    fn hex_secret_is_32_hex_digits() {
        let s = random_hex32();
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn redaction_blanks_every_secret() {
        let c = MailCluster {
            id: "m".into(), name: "m".into(), cluster: String::new(), owner_node: String::new(),
            public_hostname: "mx.example.com".into(), default_domain: "example.com".into(),
            galera_cluster_id: "g".into(), db_host: "10.0.0.1".into(), db_port: 3306,
            db_name: "d".into(), db_user: "u".into(), db_password_enc: "x".into(),
            coordinator: CoordinatorKind::Keep, coordinator_members: vec![],
            keep_secret_enc: "x".into(), keep_peer_secret_enc: "x".into(),
            redis_password_enc: "x".into(), sentinel_password_enc: "x".into(),
            mail_nodes: vec![], admin_user: "admin@example.com".into(),
            admin_password_enc: "x".into(), api_key_enc: "x".into(), created_at: String::new(),
            status: "ready".into(), last_error: String::new(), request_tls_certificate: false,
        };
        let r = serde_json::to_string(&redacted(&c)).unwrap();
        assert!(!r.contains("\"x\""), "a sealed field leaked: {}", r);
    }
}
