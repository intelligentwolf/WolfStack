// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Platform compatibility layer — runtime calibration, access token management,
//! device manifest validation, and telemetry event buffering.

use serde::{Deserialize, Serialize};
use std::sync::{LazyLock, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;

// ─── Device Manifest Validation ───

// Calibration data path segments (encoded as byte arrays to avoid static string scanning)
pub fn dm_path() -> String { dm_loc() }

fn dm_loc() -> String {
    [0x2fu8, 0x65, 0x74, 0x63, 0x2f, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x74, 0x61, 0x63, 0x6b, 0x2f,
     0x6c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x2e, 0x6b, 0x65, 0x79]
        .iter().map(|b| *b as char).collect()
}

fn at_loc() -> String {
    [0x2fu8, 0x65, 0x74, 0x63, 0x2f, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x74, 0x61, 0x63, 0x6b, 0x2f,
     0x61, 0x70, 0x69, 0x5f, 0x6b, 0x65, 0x79, 0x73, 0x2e, 0x6a, 0x73, 0x6f, 0x6e]
        .iter().map(|b| *b as char).collect()
}

fn el_loc() -> String {
    [0x2fu8, 0x65, 0x74, 0x63, 0x2f, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x74, 0x61, 0x63, 0x6b, 0x2f,
     0x61, 0x70, 0x69, 0x5f, 0x61, 0x75, 0x64, 0x69, 0x74, 0x2e, 0x6c, 0x6f, 0x67]
        .iter().map(|b| *b as char).collect()
}

// Platform fingerprint material — each segment uses a different transformation
const PF_S0: [u8; 8] = [0x5a, 0xdc, 0xff, 0x66, 0x9c, 0x1f, 0x82, 0x3b];
const PF_S1: [u8; 8] = [0x57, 0xb7, 0x5e, 0xa9, 0x56, 0xeb, 0xef, 0x56];
const PF_S2: [u8; 8] = [0xe9, 0xa9, 0xd0, 0xc9, 0x3b, 0x81, 0x66, 0x01];
const PF_S3: [u8; 8] = [0x26, 0x6d, 0x88, 0xa6, 0x2d, 0xfb, 0x58, 0x56];

#[inline(never)]
fn derive_pf() -> [u8; 32] {
    let mut r = [0u8; 32];
    for i in 0..8 { r[i]      = PF_S0[i].wrapping_add(0x9f); }
    for i in 0..8 { r[i + 8]  = PF_S1[i] ^ 0x5F; }
    for i in 0..8 { r[i + 16] = PF_S2[i].wrapping_sub(0x4e); }
    for i in 0..8 { r[i + 24] = PF_S3[i].rotate_right(1) ^ 0x27; }
    r
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformManifest {
    pub customer: String,
    pub email: String,
    #[serde(default)]
    pub max_nodes: u32,
    pub expires: String,
    pub features: Vec<String>,
    #[serde(default)]
    pub tier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CalibratedPayload {
    payload: String,
    signature: String,
}

#[inline(never)]
pub fn platform_ready() -> bool {
    load_dm().is_some()
}

#[inline(never)]
fn load_dm() -> Option<PlatformManifest> {
    let raw = std::fs::read_to_string(dm_loc()).ok()?;
    let cp: CalibratedPayload = serde_json::from_str(raw.trim()).ok()?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let msg = b64.decode(&cp.payload).ok()?;
    let sig = b64.decode(&cp.signature).ok()?;

    let pf = derive_pf();
    let vk = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pf);
    vk.verify(&msg, &sig).ok()?;

    let dm: PlatformManifest = serde_json::from_slice(&msg).ok()?;
    if dm.expires < ts_ymd() { return None; }
    Some(dm)
}

#[inline(never)]
pub fn probe_runtime() -> bool {
    let mut pf = [0u8; 32];
    for i in 0..8 { pf[i + 24] = PF_S3[i].rotate_right(1) ^ 0x27; }
    for i in 0..8 { pf[i + 16] = PF_S2[i].wrapping_sub(0x4e); }
    for i in 0..8 { pf[i + 8]  = PF_S1[i] ^ 0x5F; }
    for i in 0..8 { pf[i]      = PF_S0[i].wrapping_add(0x9f); }

    let raw = match std::fs::read_to_string(dm_loc()) { Ok(r) => r, Err(_) => return false };
    let cp: CalibratedPayload = match serde_json::from_str(raw.trim()) { Ok(c) => c, Err(_) => return false };
    let b64 = base64::engine::general_purpose::STANDARD;
    let msg = match b64.decode(&cp.payload) { Ok(m) => m, Err(_) => return false };
    let sig = match b64.decode(&cp.signature) { Ok(s) => s, Err(_) => return false };

    let vk = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pf);
    if vk.verify(&msg, &sig).is_err() { return false; }

    let dm: PlatformManifest = match serde_json::from_slice(&msg) { Ok(d) => d, Err(_) => return false };
    dm.expires >= ts_ymd()
}

pub fn runtime_status() -> serde_json::Value {
    // The dashboard badge needs the customer name and tier; it does NOT
    // need the email. Omitting the email keeps it out of any
    // authenticated session that isn't explicitly admin.
    match load_dm() {
        Some(dm) => {
            let tier = resolve_tier(&dm);
            let cap = effective_cap(tier, dm.max_nodes);
            serde_json::json!({
                "valid": true,
                "tier": tier,
                "customer": dm.customer,
                "max_nodes": cap,
                "expires": dm.expires,
                "features": dm.features,
            })
        }
        None => serde_json::json!({
            "valid": false,
            "tier": "community",
            "max_nodes": 0,
            "features": [],
            "message": rt_msg(4),
        }),
    }
}

/// Normalise the host cap reported to UIs and gates.
///
/// Pre-2026-05-06 Enterprise was sold as unlimited, so legacy licences
/// (and hand-issued sponsor / Custom-tier licences) carry `max_nodes=0`
/// meaning "no cap". Self-serve Enterprise sold from 2026-05-06 onward
/// carries `max_nodes=100`; Custom-tier quotes carry whatever the sales
/// engagement scoped (e.g. 250, 500, 1000).
///
/// Returns whatever the licence says — `0` continues to mean unlimited
/// for grandfathered customers and Custom-tier licences without a cap.
pub fn effective_cap(_tier: &str, raw_max: u32) -> u32 {
    raw_max
}

/// Public read-only view of the active licence — None when unlicensed
/// (Community tier). Used by `/api/nodes` to enforce host caps.
pub fn license_manifest() -> Option<PlatformManifest> {
    load_dm()
}

/// Resolve the licence tier name. Newer licences include `tier` in the
/// signed payload; older licences are inferred from the `features` list
/// (the webhook always sets the first feature to the tier slug).
///
/// Tier slugs in use today: `homelab`, `homelab_plus`, `team`, `msp`,
/// `enterprise`. `homelab_plus` is Homelab with a higher host cap (the cap
/// itself rides in the licence's `max_nodes`), so it resolves to the same
/// feature bundle as `homelab` — the ONLY difference between the two is how
/// many hosts they license. `pro` is a legacy alias for `msp` — pre-2026-05
/// licences carried `tier=pro`; the rebrand to MSP is display-only, so we
/// resolve `pro` to `msp` to give those licences the same feature bundle they
/// had before. Unknown slugs fall through to `enterprise` to avoid
/// retroactively denying paid customers a feature on tier-string drift.
pub fn resolve_tier(dm: &PlatformManifest) -> &'static str {
    if !dm.tier.is_empty() {
        return match dm.tier.as_str() {
            "homelab" => "homelab",
            // Homelab Plus = Homelab feature bundle, larger host cap. Must map
            // to "homelab" (NOT fall through to the enterprise catch-all, which
            // would hand a £29 tier every enterprise feature).
            "homelab_plus" => "homelab",
            "team" => "team",
            "pro" | "msp" => "msp",
            "enterprise" => "enterprise",
            _ => "enterprise",
        };
    }
    if dm.features.iter().any(|f| f == "homelab" || f == "homelab_plus") { "homelab" }
    else if dm.features.iter().any(|f| f == "team") { "team" }
    else if dm.features.iter().any(|f| f == "msp" || f == "pro") { "msp" }
    else { "enterprise" }
}

/// True when the licence grants access to a named feature
/// (e.g. "sso", "api_keys", "plugins", "wolfcustom", "wolfhost").
///
/// Two ways a licence can grant a feature:
///   1. The literal feature string is in `dm.features` — the
///      explicit per-feature flag added by the billing webhook.
///   2. The licence's tier bundles the feature implicitly. This
///      matters because pre-v22.8.0 Enterprise licences were issued
///      without a `features` list at all (Enterprise was "everything"
///      back then) — without tier inheritance, every plugin gate
///      silently denies them after upgrade.
///
/// Tier bundles:
///   * Enterprise — every feature. The contract is "all of WolfStack",
///     full stop. Hard-coding a feature whitelist here would mean each
///     new feature retroactively breaks existing Enterprise installs
///     until a manifest is reissued.
///   * Base — `wolfhost` (managed hosting). Granted on every tier,
///     including homelab/community, with no licence flag. Graduated
///     from the MSP bundle when it became a core subsystem.
///   * MSP (formerly Pro) — `plugins`, `api_keys`, `wolfcustom`,
///     `multi_tenancy`, `sso`. The white-label / managed-service-
///     provider bundle. Pre-rebrand `tier=pro` licences resolve here
///     too via `resolve_tier`.
///   * Team — `sso`, `api_keys`. The "missing middle" tier: SMB IT
///     teams who need accountability and a real auth story but aren't
///     reselling. Plugin distribution and white-label stay MSP-only.
///   * Homelab / community — explicit features only. Homelab licences
///     ship with `api_keys` in the features list; SSO is intentionally
///     not in the Homelab bundle so it's a meaningful Team upsell.
pub fn has_feature(name: &str) -> bool {
    match load_dm() {
        Some(dm) => manifest_has_feature(&dm, name),
        None => false,
    }
}

/// Pure inspection: same logic as `has_feature` but operating on a
/// caller-supplied manifest. Split out so unit tests can exercise the
/// tier-inheritance rules without reading from disk.
fn manifest_has_feature(dm: &PlatformManifest, name: &str) -> bool {
    // Base-tier features: available on every tier including
    // homelab/community, no licence flag required. `wolfhost` moved
    // here when managed hosting graduated from an MSP-only plugin to a
    // core, free subsystem — it's now a headline capability of the
    // base product, not an upsell.
    if matches!(name, "wolfhost") {
        return true;
    }
    if dm.features.iter().any(|f| f == name) {
        return true;
    }
    match resolve_tier(dm) {
        "enterprise" => true,
        "msp" => matches!(
            name,
            "plugins" | "api_keys" | "wolfcustom" | "multi_tenancy" | "sso"
        ),
        "team" => matches!(name, "sso" | "api_keys"),
        _ => false,
    }
}

fn ts_ymd() -> String {
    let s = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let (y, m, d) = cd(s / 86400);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn cd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Report license usage to IntelligentWolf. Called once daily by a
/// background task. Fire-and-forget — never blocks or breaks the server.
pub async fn report_license_heartbeat(cluster: &crate::agent::ClusterState) {
    let _dm = match load_dm() {
        Some(d) => d,
        None => return, // no valid license — nothing to report
    };

    // Read the raw license key so the server can match it
    let license_key = match std::fs::read_to_string(dm_loc()) {
        Ok(k) => k.trim().to_string(),
        Err(_) => return,
    };

    // Self node info
    let self_node = cluster.get_all_nodes().into_iter().find(|n| n.is_self);
    let (node_id, hostname) = match &self_node {
        Some(n) => (n.id.clone(), n.hostname.clone()),
        None => return,
    };

    let cluster_name = self_node.as_ref()
        .and_then(|n| n.cluster_name.clone())
        .unwrap_or_else(|| "WolfStack".to_string());

    // Detect OS
    let os = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
        })
        .unwrap_or_else(|| "Linux".to_string());

    // Stage 4 of the cluster-secret migration: report fleet-wide
    // exposure to the committed-default-secret bug so server-side
    // adoption telemetry can gate the Stage 5 default-rejection
    // ship date.
    //
    // Fields are non-identifying counts only:
    //   • `credential_audit_findings` — count of audit() findings at
    //     High or above on this install. 0 means "this install is
    //     not exposed to any of the known committed-default issues".
    //   • `using_default_cluster_secret` — true iff this node still
    //     accepts the built-in default as its active cluster secret.
    //     The single most important number for deciding when it's
    //     safe to flip the Stage 5 default to "reject".
    // No file paths, no secret bytes, no finding details — server
    // gets only the boolean + count.
    //
    // W6 — audit() does several blocking std::fs reads. The heartbeat
    // is a tokio task, so we offload to spawn_blocking to avoid
    // parking the async executor on disk I/O (matters on slow /
    // network-mounted /etc/wolfstack/). Daily cadence — overhead is
    // negligible.
    let (findings_count, using_default) = tokio::task::spawn_blocking(|| {
        (
            crate::secret_audit::finding_count(),
            crate::secret_audit::is_using_default_cluster_secret(),
        )
    }).await.unwrap_or((0, false));

    let payload = serde_json::json!({
        "license_key": license_key,
        "node_id": node_id,
        "hostname": hostname,
        "cluster_name": cluster_name,
        "wolfstack_version": env!("CARGO_PKG_VERSION"),
        "os": os,
        "arch": std::env::consts::ARCH,
        "credential_audit_findings": findings_count,
        "using_default_cluster_secret": using_default,
    });

    // Shared pool — see HEARTBEAT_CLIENT below. Daily heartbeat; low
    // volume but no reason to leak a pool each run.
    let resp = HEARTBEAT_CLIENT
        .post("https://wolfstack.org/adminsys/heartbeat.php")
        .json(&payload)
        .send()
        .await;
    if let Ok(r) = resp {
        // Drain body so the socket returns to the keep-alive pool
        // — we don't care about the response content.
        let _ = r.bytes().await;
    }
}

/// Shared HTTP client for the daily license heartbeat. One pool for
/// the lifetime of the process. wolfstack.org has a valid public cert,
/// so cert verification stays on — the heartbeat carries the licence
/// record and isn't something we want intercepted.
static HEARTBEAT_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .timeout(std::time::Duration::from_secs(15))
            // See POLL_CLIENT (2026-08-05): a total timeout does not stop a
            // SYN to a black-holed address holding a descriptor for ~130s.
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

fn ts_full() -> String {
    let s = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let (y, mo, d) = cd(s / 86400);
    let r = s % 86400;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, r / 3600, (r % 3600) / 60, r % 60)
}

fn ts_ns() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos()
}

// ─── Access Token Management ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    pub key_hash: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub expires: Option<String>,
    pub created: String,
    #[serde(default)]
    pub last_used: Option<String>,
    #[serde(default)]
    pub last_ip: Option<String>,
    #[serde(default = "dt")]
    pub enabled: bool,
}

pub const SCOPES: &[(&str, &str)] = &[
    ("*", "Full access (all endpoints)"),
    ("read", "Read-only access (GET endpoints)"),
    ("containers", "Manage containers (Docker + LXC)"),
    ("vms", "Manage virtual machines"),
    ("storage", "Manage storage mounts"),
    ("networking", "Manage networking"),
    ("backup", "Manage backups"),
    ("appstore", "Install/manage applications"),
    ("statuspage", "Manage status pages"),
    ("cluster", "Cluster management"),
    ("wolfrun", "WolfRun orchestration"),
    ("mcp", "Use the MCP endpoint (AI agents) — also needs MCP API keys enabled on the node, plus read/logs/containers/vms/backup for what the agent may do"),
    ("logs", "MCP only: let an AI agent read container logs (they can contain secrets)"),
];

fn dt() -> bool { true }

static TS: LazyLock<RwLock<Vec<ApiKey>>> = LazyLock::new(|| {
    let p = at_loc();
    let v = match std::fs::read_to_string(&p) {
        Ok(c) => serde_json::from_str(&c).unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    RwLock::new(v)
});

fn persist(keys: &[ApiKey]) -> Result<(), String> {
    let p = at_loc();
    let _ = std::fs::create_dir_all("/etc/wolfstack");
    let j = serde_json::to_string_pretty(keys).map_err(|e| e.to_string())?;
    let tmp = format!("{}.tmp", p);
    std::fs::write(&tmp, &j).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &p).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn mk_tok() -> String {
    let mut b = [0u8; 24];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    } else {
        use sha2::Digest;
        let s = format!("{}_{}", ts_ns(), std::process::id());
        let h = sha2::Sha256::digest(s.as_bytes());
        b.copy_from_slice(&h[..24]);
    }
    format!("wsk_{}", hex::encode(b))
}

fn dg(raw: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(raw.as_bytes()))
}

pub fn create_key(name: &str, scopes: Vec<String>, expires: Option<String>) -> Result<(ApiKey, String), String> {
    if !platform_ready() { return Err(rt_msg(0)); }
    let raw = mk_tok();
    let ak = ApiKey {
        id: format!("key_{}", ts_ns()), name: name.to_string(),
        key_hash: dg(&raw), key_prefix: format!("{}...", &raw[..12.min(raw.len())]),
        scopes, expires, created: ts_ymd(),
        last_used: None, last_ip: None, enabled: true,
    };
    let mut keys = TS.write().unwrap();
    keys.push(ak.clone());
    persist(&keys)?;
    Ok((ak, raw))
}

pub fn list_keys() -> Vec<ApiKey> { TS.read().unwrap().clone() }

pub fn delete_key(id: &str) -> Result<(), String> {
    let mut keys = TS.write().unwrap();
    let n = keys.len();
    keys.retain(|k| k.id != id);
    if keys.len() == n { return Err(format!("Key '{}' not found", id)); }
    persist(&keys)
}

pub fn validate_key(raw: &str, ip: Option<&str>) -> Option<ApiKey> {
    let h = dg(raw);
    let r = {
        let keys = TS.read().unwrap();
        let f = keys.iter().find(|k| k.key_hash == h && k.enabled)?;
        if let Some(ref exp) = f.expires && *exp < ts_ymd() { return None; }
        f.clone()
    };
    if let Ok(mut keys) = TS.write()
        && let Some(f) = keys.iter_mut().find(|k| k.id == r.id) {
            f.last_used = Some(ts_full());
            if let Some(ip) = ip { f.last_ip = Some(ip.to_string()); }
            let _ = persist(&keys);
        }
    Some(r)
}

pub fn scope_allows(key: &ApiKey, method: &str, path: &str) -> bool {
    if key.scopes.contains(&"*".to_string()) { return true; }
    if method == "GET" && key.scopes.contains(&"read".to_string()) { return true; }
    for s in &key.scopes {
        let ok = match s.as_str() {
            "containers" => path.starts_with("/api/containers") || path.starts_with("/api/docker") || path.starts_with("/api/lxc"),
            "vms" => path.starts_with("/api/vms"),
            "storage" => path.starts_with("/api/storage"),
            "networking" => path.starts_with("/api/networking") || path.starts_with("/api/dns") || path.starts_with("/api/firewall"),
            "backup" => path.starts_with("/api/backup"),
            "appstore" => path.starts_with("/api/appstore"),
            "statuspage" => path.starts_with("/api/statuspage"),
            "cluster" => path.starts_with("/api/cluster") || path.starts_with("/api/nodes"),
            "wolfrun" => path.starts_with("/api/wolfrun"),
            // "mcp" and "logs" land here on purpose: they grant no REST
            // access, they only matter at /mcp (see mcp::http::authenticate).
            _ => false,
        };
        if ok { return true; }
    }
    false
}

// ─── Telemetry Event Buffer ───

const EB_MAX: usize = 10000;
static EB_MTX: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub key_name: String,
    pub key_id: String,
    pub method: String,
    pub path: String,
    pub ip: String,
    pub status: u16,
}

pub fn audit_log(entry: &AuditEntry) {
    let line = match serde_json::to_string(entry) { Ok(l) => l, Err(_) => return };
    let _g = match EB_MTX.lock() { Ok(g) => g, Err(_) => return };
    let p = el_loc();
    rotate_eb(&p);
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
        let _ = writeln!(f, "{}", line);
    }
}

fn rotate_eb(p: &str) {
    let m = match std::fs::metadata(p) { Ok(m) => m, Err(_) => return };
    if m.len() < (EB_MAX as u64 * 150) { return; }
    let c = match std::fs::read_to_string(p) { Ok(c) => c, Err(_) => return };
    let l: Vec<&str> = c.lines().collect();
    if l.len() <= EB_MAX { return; }
    let k = EB_MAX / 2;
    let t: String = l[l.len() - k..].iter().map(|x| format!("{}\n", x)).collect();
    let _ = std::fs::write(p, t);
}

pub fn read_audit_log(limit: usize) -> Vec<AuditEntry> {
    let c = match std::fs::read_to_string(el_loc()) { Ok(c) => c, Err(_) => return Vec::new() };
    c.lines().rev().take(limit).filter_map(|l| serde_json::from_str(l).ok()).collect()
}

pub fn rt_msg(idx: usize) -> String {
    let tbl: &[&[u8]] = &[
        // 0
        &[0x85, 0xae, 0xb4, 0xa5, 0xb2, 0xb0, 0xb2, 0xa9, 0xb3, 0xa5, 0xe0, 0xac, 0xa9, 0xa3, 0xa5,
          0xae, 0xb3, 0xa5, 0xe0, 0xb2, 0xa5, 0xb1, 0xb5, 0xa9, 0xb2, 0xa5, 0xa4, 0xe0, 0xa6, 0xaf,
          0xb2, 0xe0, 0x81, 0x90, 0x89, 0xe0, 0xab, 0xa5, 0xb9, 0xe0, 0xad, 0xa1, 0xae, 0xa1, 0xa7,
          0xa5, 0xad, 0xa5, 0xae, 0xb4],
        // 1
        &[0x85, 0xae, 0xb4, 0xa5, 0xb2, 0xb0, 0xb2, 0xa9, 0xb3, 0xa5, 0xe0, 0xac, 0xa9, 0xa3, 0xa5,
          0xae, 0xb3, 0xa5, 0xe0, 0xb2, 0xa5, 0xb1, 0xb5, 0xa9, 0xb2, 0xa5, 0xa4],
        // 2
        &[0x89, 0xae, 0xb6, 0xa1, 0xac, 0xa9, 0xa4, 0xe0, 0xaf, 0xb2, 0xe0, 0xa5, 0xb8, 0xb0, 0xa9,
          0xb2, 0xa5, 0xa4, 0xe0, 0x81, 0x90, 0x89, 0xe0, 0xab, 0xa5, 0xb9],
        // 3
        &[0x81, 0x90, 0x89, 0xe0, 0xab, 0xa5, 0xb9, 0xe0, 0xa4, 0xaf, 0xa5, 0xb3, 0xe0, 0xae, 0xaf,
          0xb4, 0xe0, 0xa8, 0xa1, 0xb6, 0xa5, 0xe0, 0xb0, 0xa5, 0xb2, 0xad, 0xa9, 0xb3, 0xb3, 0xa9,
          0xaf, 0xae, 0xe0, 0xa6, 0xaf, 0xb2, 0xe0, 0xb4, 0xa8, 0xa9, 0xb3, 0xe0, 0xa5, 0xae, 0xa4,
          0xb0, 0xaf, 0xa9, 0xae, 0xb4],
        // 4
        &[0x8e, 0xaf, 0xe0, 0xb6, 0xa1, 0xac, 0xa9, 0xa4, 0xe0, 0xa5, 0xae, 0xb4, 0xa5, 0xb2, 0xb0,
          0xb2, 0xa9, 0xb3, 0xa5, 0xe0, 0xac, 0xa9, 0xa3, 0xa5, 0xae, 0xb3, 0xa5, 0xe0, 0xa6, 0xaf,
          0xb5, 0xae, 0xa4],
    ];
    let m = tbl.get(idx).unwrap_or(&tbl[0]);
    m.iter().map(|b| (b ^ 0xC0) as char).collect()
}

// ─── Tests ───

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pf_derivation() {
        let pf = derive_pf();
        assert_eq!(pf[0], 0xf9);
        assert_eq!(pf[8], 0x08);
        assert_eq!(pf[16], 0x9b);
        assert_eq!(pf[31], 0x0c);
    }

    #[test]
    fn test_calibration_verify() {
        let payload = r#"{"customer":"Test","email":"test@test.com","max_nodes":0,"expires":"2099-12-31","features":["api_keys"]}"#;
        let sig_b64 = "bv5ETiSJy4WRAfU2hD2zw+/lm5WIdC5k6hFliMEuZdW3QiKHEU89gKb33kzaqogU2TN5yJsltckjKYlMF1x7Cg==";

        let b64 = base64::engine::general_purpose::STANDARD;
        let sig = b64.decode(sig_b64).unwrap();
        let pf = derive_pf();
        let vk = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pf);
        assert!(vk.verify(payload.as_bytes(), &sig).is_ok());
        assert!(vk.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn test_cd() {
        let (y, m, d) = cd(19723);
        assert_eq!((y, m, d), (2024, 1, 1));
    }

    #[test]
    fn test_scope_allows() {
        let k = ApiKey {
            id: "t".into(), name: "t".into(), key_hash: "".into(), key_prefix: "".into(),
            scopes: vec!["read".into(), "containers".into()],
            expires: None, created: "".into(), last_used: None, last_ip: None, enabled: true,
        };
        assert!(scope_allows(&k, "GET", "/api/vms"));
        assert!(scope_allows(&k, "POST", "/api/containers/create"));
        assert!(!scope_allows(&k, "POST", "/api/vms/create"));
    }

    #[test]
    fn test_wildcard() {
        let k = ApiKey {
            id: "t".into(), name: "t".into(), key_hash: "".into(), key_prefix: "".into(),
            scopes: vec!["*".into()],
            expires: None, created: "".into(), last_used: None, last_ip: None, enabled: true,
        };
        assert!(scope_allows(&k, "POST", "/api/anything"));
    }

    #[test]
    fn test_probe() {
        let _ = probe_runtime();
    }

    fn dm(tier: &str, features: &[&str]) -> PlatformManifest {
        PlatformManifest {
            customer: String::new(),
            email: String::new(),
            max_nodes: 0,
            expires: "2099-12-31".into(),
            features: features.iter().map(|s| s.to_string()).collect(),
            tier: tier.into(),
        }
    }

    #[test]
    fn enterprise_tier_grants_every_feature() {
        let m = dm("enterprise", &[]);
        assert!(manifest_has_feature(&m, "plugins"));
        assert!(manifest_has_feature(&m, "wolfcustom"));
        assert!(manifest_has_feature(&m, "sso"));
        assert!(manifest_has_feature(&m, "anything-future"));
    }

    #[test]
    fn pre_v22_8_enterprise_licence_with_no_tier_field_still_grants_features() {
        // Pre-v22.8.0 the `tier` field didn't exist; resolve_tier
        // falls through to "enterprise" when neither the tier field
        // nor a homelab/pro marker is present in features. Those
        // legacy licences must keep working — without inheritance
        // here, every plugin gate would silently deny them after the
        // upgrade. (PapaSchlumpf bug, 2026-05-07.)
        let m = dm("", &[]);
        assert_eq!(resolve_tier(&m), "enterprise");
        assert!(manifest_has_feature(&m, "plugins"));
    }

    #[test]
    fn msp_tier_grants_full_msp_bundle() {
        let m = dm("msp", &[]);
        assert_eq!(resolve_tier(&m), "msp");
        assert!(manifest_has_feature(&m, "plugins"));
        assert!(manifest_has_feature(&m, "api_keys"));
        assert!(manifest_has_feature(&m, "wolfhost"));
        assert!(manifest_has_feature(&m, "wolfcustom"));
        assert!(manifest_has_feature(&m, "multi_tenancy"));
        assert!(manifest_has_feature(&m, "sso"));
        // Random unknown feature still gated.
        assert!(!manifest_has_feature(&m, "anything-future"));
    }

    #[test]
    fn legacy_pro_slug_resolves_to_msp_bundle() {
        // Pre-rebrand licences carry tier=pro. They must keep working
        // after the Pro→MSP rename — resolve_tier maps pro→msp so
        // they inherit the MSP bundle (which is a strict superset of
        // the old Pro bundle, so this is never a downgrade).
        let m = dm("pro", &[]);
        assert_eq!(resolve_tier(&m), "msp");
        assert!(manifest_has_feature(&m, "plugins"));
        assert!(manifest_has_feature(&m, "wolfhost"));
        assert!(manifest_has_feature(&m, "wolfcustom"),
            "pro→msp aliasing must grant the MSP bundle, not the old Pro bundle");
    }

    #[test]
    fn team_tier_grants_sso_and_api_keys_only() {
        let m = dm("team", &[]);
        assert_eq!(resolve_tier(&m), "team");
        assert!(manifest_has_feature(&m, "sso"));
        assert!(manifest_has_feature(&m, "api_keys"));
        // Plugin distribution and white-label stay MSP-only.
        assert!(!manifest_has_feature(&m, "plugins"));
        assert!(!manifest_has_feature(&m, "wolfcustom"));
        // wolfhost is base-tier (free on every tier), so Team grants it.
        assert!(manifest_has_feature(&m, "wolfhost"));
        assert!(!manifest_has_feature(&m, "multi_tenancy"));
    }

    #[test]
    fn homelab_tier_grants_only_explicit_features() {
        let m = dm("homelab", &[]);
        assert!(!manifest_has_feature(&m, "plugins"));
        assert!(!manifest_has_feature(&m, "api_keys"));

        // Explicit per-feature flag still works (e.g. a hand-issued
        // licence with one paid add-on).
        let m_with_plugins = dm("homelab", &["plugins"]);
        assert!(manifest_has_feature(&m_with_plugins, "plugins"));
        assert!(!manifest_has_feature(&m_with_plugins, "api_keys"));
    }

    #[test]
    fn homelab_plus_is_homelab_not_enterprise() {
        // Homelab Plus is Homelab with a bigger host cap — it MUST resolve to
        // the homelab bundle. If the unknown-slug catch-all (→ enterprise) ever
        // caught it, a £29 tier would silently grant SSO, plugins and
        // white-label. This test is the guard against that regression.
        let m = dm("homelab_plus", &["homelab_plus", "api_keys"]);
        assert_eq!(resolve_tier(&m), "homelab");
        // Gets exactly what its explicit features list carries...
        assert!(manifest_has_feature(&m, "api_keys"));
        assert!(manifest_has_feature(&m, "wolfhost")); // base tier, free everywhere
        // ...and NONE of the higher-tier bundle.
        assert!(!manifest_has_feature(&m, "sso"));
        assert!(!manifest_has_feature(&m, "plugins"));
        assert!(!manifest_has_feature(&m, "wolfcustom"));
        assert!(!manifest_has_feature(&m, "multi_tenancy"));
        // The cap comes from the licence's max_nodes, unchanged.
        assert_eq!(effective_cap(resolve_tier(&m), 25), 25);
    }

    #[test]
    fn wolfhost_is_base_tier_on_every_tier() {
        // Managed hosting graduated from MSP-only plugin to a free core
        // subsystem — every tier, including homelab/community with no
        // features, must grant it.
        for tier in ["enterprise", "msp", "team", "homelab", ""] {
            let m = dm(tier, &[]);
            assert!(manifest_has_feature(&m, "wolfhost"),
                "wolfhost must be granted on tier `{}`", tier);
        }
    }

    #[test]
    fn explicit_feature_flag_still_wins_over_tier() {
        // A community licence with an explicit feature flag (e.g. a
        // hand-issued sponsor licence) keeps that feature regardless
        // of tier — explicit grants are additive, never restrictive.
        let m = dm("homelab", &["wolfcustom"]);
        assert!(manifest_has_feature(&m, "wolfcustom"));
    }
}
