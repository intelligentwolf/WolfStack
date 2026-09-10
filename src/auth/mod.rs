// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

// Authentication — Linux system user authentication via crypt(),
// with optional WolfStack user accounts and TOTP two-factor authentication.

pub mod users;
#[allow(dead_code)]
pub mod oidc;
#[allow(dead_code)]
pub mod webauthn;
pub mod log_monitor;

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::warn;
use crate::node_identity::PeerAuth;

/// Session token lifetime (8 hours)
const SESSION_LIFETIME: Duration = Duration::from_secs(8 * 3600);

// Old static MAX_LOGIN_ATTEMPTS / LOGIN_LOCKOUT_WINDOW constants were
// removed when the lockout system became operator-configurable.
// See `LoginLockoutConfig` for the per-policy fields.

/// Built-in cluster secret shared by all WolfStack installations.
const CLUSTER_SECRET: &str = "wsk_a7f3b9e2c1d4f6a8b0e3d5c7f9a1b3d5e7f9a1c3b5d7e9f0a2b4c6d8e0f1a3";

/// Get the built-in default cluster secret (always accepted as fallback)
pub fn default_cluster_secret() -> &'static str {
    CLUSTER_SECRET
}

/// Path for user-generated custom cluster secrets (via Settings → Security).
/// Note: /etc/wolfstack/cluster-secret may contain leftover per-installation
/// secrets from v11.26.3 — we deliberately use a different path to avoid loading those.
fn custom_secret_path() -> String { crate::paths::get().cluster_secret }

/// Load the active cluster secret — custom from file if present, otherwise the built-in default
pub fn load_cluster_secret() -> String {
    let path_str = custom_secret_path();
    let path = std::path::Path::new(&path_str);
    // Falling back to the built-in default is silent-but-fatal in a cluster:
    // the node comes up, polls, and reports ONLINE, while every proxied
    // per-node call is signed with the wrong X-WolfStack-Secret and rejected.
    // The operator sees "online, but none of the links work" and nothing in
    // the log says why. On Unraid /etc/wolfstack is a symlink into appdata, so
    // an array that is slow, unmounted or wedged when the agent starts makes
    // this read fail and silently downgrades the node's identity
    // (klas, 2026-07-31). Say so, loudly, every time it happens.
    match std::fs::read_to_string(path) {
        Ok(secret) => {
            let secret = secret.trim().to_string();
            if !secret.is_empty() {
                return secret;
            }
            tracing::error!(
                "cluster secret file {} is empty — falling back to the BUILT-IN DEFAULT secret. \
                 If any peer uses a custom secret it will reject this node with 401 on every \
                 proxied request.",
                path_str
            );
        }
        Err(e) => {
            tracing::warn!(
                "could not read cluster secret file {} ({}) — falling back to the BUILT-IN \
                 DEFAULT secret. On a fresh single node this is normal; in a cluster it means \
                 peers using a custom secret will reject this node with 401 on every proxied \
                 request, while it still shows as online.",
                path_str, e
            );
        }
    }
    CLUSTER_SECRET.to_string()
}

/// True when this node is authenticating with the public built-in default
/// cluster secret rather than one of its own. Harmless on a standalone node;
/// in a cluster it is the "online but every link 401s" failure.
pub fn using_default_cluster_secret() -> bool {
    !has_custom_cluster_secret()
}

/// True if this node has its OWN custom cluster secret configured (the
/// operator has migrated off the built-in default). Such a node never
/// needs to accept the public built-in default for inter-node auth, so
/// `default_secret_accepted` can safely refuse it. Un-migrated installs
/// (no custom secret file, or a file still holding the default) return
/// false so we don't sever their auth on upgrade.
fn has_custom_cluster_secret() -> bool {
    let path_str = custom_secret_path();
    match std::fs::read_to_string(std::path::Path::new(&path_str)) {
        Ok(s) => {
            let s = s.trim();
            !s.is_empty() && s != CLUSTER_SECRET
        }
        Err(_) => false,
    }
}

/// Generate a new random cluster secret (wsk_ prefix + 64 hex chars)
pub fn generate_cluster_secret() -> String {
    use std::fmt::Write;
    let mut secret = String::from("wsk_");
    let mut buf = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut buf);
    }
    for b in &buf {
        let _ = write!(secret, "{:02x}", b);
    }
    secret
}

/// Save a cluster secret to the custom secret file. Written with mode
/// 0600 — the secret is the cluster's inter-node auth token, so any
/// non-root reader can impersonate a cluster member. Pre-v18.7.27 this
/// used `std::fs::write` which inherited the process umask (usually
/// 022 → 0644) and made the secret world-readable.
pub fn save_cluster_secret(secret: &str) -> Result<(), String> {
    let path = custom_secret_path();
    crate::paths::write_secure(&path, secret)
        .map_err(|e| format!("Cannot write custom-cluster-secret: {}", e))
}

/// Verify that `username`+`password` identify an ADMIN/privileged user on
/// THIS node, using the exact same credential check the interactive login
/// path uses. This is the gate for the cluster-join handshake: a leaked
/// cluster secret or join token alone must NOT let an attacker graft this
/// server onto their fleet — they must additionally prove they control an
/// admin account on this specific machine.
///
/// "Admin" is resolved the same way the rest of the app distinguishes
/// privileged users:
///   • WolfStack-account auth (`authenticate_wolfstack_user`) — the user
///     must exist AND have `role == "admin"` (viewers are rejected).
///   • Linux system auth (`authenticate_user`, the /etc/shadow crypt()
///     check used by login) — the account must additionally be `root` or
///     a member of the `sudo` / `wheel` group, i.e. an account that can
///     already administer the box.
///
/// Returns `true` only when BOTH the password verifies AND the account is
/// privileged. Never logs the password. The two sources are tried in the
/// same order as the login handler so behaviour is identical.
pub fn verify_target_admin(username: &str, password: &str) -> bool {
    if username.is_empty() || password.is_empty() {
        return false;
    }
    // WolfStack accounts first (mirrors the login handler ordering). A
    // matching WolfStack account is authoritative — if the password is
    // right but the role isn't admin, reject (don't fall through to Linux
    // auth, which could accept a same-named system account and bypass the
    // role check).
    {
        let store = crate::auth::users::UserStore::load();
        if store.find(username).is_some() {
            return match crate::auth::users::authenticate_wolfstack_user(username, password) {
                Some(user) => user.role == "admin",
                None => false,
            };
        }
    }
    // Linux system account: verify the password via the same crypt() path
    // the login uses, then require the account be privileged (root or in
    // sudo/wheel). The login itself proves control of the box; the group
    // check enforces the "admin" requirement.
    if authenticate_user(username, password) {
        return linux_user_is_privileged(username);
    }
    false
}

/// Session-based admin resolution — the same rules as
/// `verify_target_admin` but WITHOUT a password (the session cookie
/// already proved identity at login):
///   • WolfStack account → must have `role == "admin"`. Authoritative:
///     a same-named system account must not bypass the role check.
///   • Otherwise (Linux session user) → root or sudo/wheel member.
/// Used by the per-user mutation endpoints (create/delete user,
/// password/email/2FA changes) so a viewer-role session can't repoint
/// another user's credentials, while Linux-admin sessions — the
/// bootstrap path that creates the first WolfStack users — keep
/// working.
pub fn session_user_is_admin(username: &str) -> bool {
    let store = users::UserStore::load();
    if let Some(u) = store.find(username) {
        return u.role == "admin";
    }
    linux_user_is_privileged(username)
}

/// True if a Linux account is `root` or belongs to the `sudo` / `wheel`
/// group — the conventional "can administer this host" set across Debian
/// (`sudo`) and RHEL/Arch (`wheel`). Reads /etc/group + /etc/passwd; if
/// they can't be read we fail closed (return false) rather than granting.
fn linux_user_is_privileged(username: &str) -> bool {
    if username == "root" {
        return true;
    }
    // Supplementary-group membership via /etc/group: a line is
    // `name:passwd:gid:member1,member2,...`. We match the `sudo`/`wheel`
    // groups' member lists.
    let primary_gid: Option<String> = std::fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|passwd| {
            passwd.lines().find_map(|line| {
                let parts: Vec<&str> = line.split(':').collect();
                // name:passwd:uid:gid:...
                if parts.len() >= 4 && parts[0] == username {
                    Some(parts[3].to_string())
                } else {
                    None
                }
            })
        });
    if let Ok(group) = std::fs::read_to_string("/etc/group") {
        for line in group.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 4 {
                continue;
            }
            let gname = parts[0];
            let gid = parts[2];
            let is_admin_group = gname == "sudo" || gname == "wheel";
            if !is_admin_group {
                continue;
            }
            // Primary group match (rare for sudo/wheel but possible).
            if primary_gid.as_deref() == Some(gid) {
                return true;
            }
            // Supplementary member list.
            if parts[3]
                .split(',')
                .any(|m| !m.is_empty() && m == username)
            {
                return true;
            }
        }
    }
    false
}

/// Stage 2 of the cluster-secret migration: on a FRESH install (no
/// custom-secret file AND no peers configured), generate a fresh
/// per-install secret instead of inheriting the built-in default
/// shared by every WolfStack on Earth.
///
/// SAFETY — this MUST be called only when both conditions hold:
///   1. `custom_secret_path()` does not exist
///   2. No peers are recorded in nodes.json (single-node install)
///
/// Either condition false → existing install → do nothing, never
/// rotate behind the operator's back. Stage 3 (operator-triggered
/// coordinated rotation) is the supported path for existing clusters.
///
/// Returns `Some(new_secret)` on a fresh-install generation,
/// `None` if conditions aren't met or generation/save failed.
/// On generation, emits a loud INFO log so the operator can copy
/// the value to a password manager.
pub fn auto_generate_for_fresh_install() -> Option<String> {
    let path = custom_secret_path();
    if std::path::Path::new(&path).exists() { return None; }

    // Check for peers in nodes.json — if any exist, this is NOT a
    // fresh install (someone is rejoining, restoring from backup, or
    // running on a host whose old custom-secret was deleted but the
    // peer list survived). Refuse to auto-generate.
    //
    // W1 fix: if nodes.json exists but is unreadable, corrupted, or
    // contains anything we can't recognise as "empty", treat it as
    // "existing install" and refuse — the safe direction. Log a
    // warning so operators with a corrupted file see why the auto-gen
    // didn't fire (otherwise they'd silently keep running on the
    // default secret).
    let nodes_path = crate::paths::get().nodes_config;
    if std::path::Path::new(&nodes_path).exists() {
        match std::fs::read_to_string(&nodes_path) {
            Ok(raw) => {
                let trimmed = raw.trim();
                if !trimmed.is_empty() && trimmed != "[]" && trimmed != "{}" {
                    return None;
                }
            }
            Err(e) => {
                tracing::warn!(target: "cluster_secret",
                    "fresh-install auto-gen skipped: cannot read {} ({}). \
                     If this is a fresh install, fix file perms and restart.",
                    nodes_path, e);
                return None;
            }
        }
    }

    let new_secret = generate_cluster_secret();
    if save_cluster_secret(&new_secret).is_err() {
        // Non-fatal: caller can still proceed with the built-in default.
        // We don't want a fresh-install failure here to break startup.
        return None;
    }
    // Keep /etc/wolfusb/wolfusb.env aligned. The install script writes
    // it with the hardcoded default BEFORE the daemon ever starts (so
    // it can't see our soon-to-be-generated per-install secret). If we
    // don't update it here, the external wolfusb daemon will run with
    // the default and our in-process wolfusb module will run with the
    // new per-install — they'll reject each other's auth headers.
    // Best-effort; failure here doesn't block startup.
    let _ = realign_wolfusb_env(&new_secret);
    // H1 fix: only log a fingerprint, never the secret bytes themselves.
    // journald is readable by anyone in the systemd-journal group on
    // most distros — a full secret in the log is an immediate exfil
    // path. Operators retrieve the full value from the 0600 file at
    // `path` or via Settings → Security in the UI.
    let masked = mask_secret_for_log(&new_secret);
    tracing::warn!(target: "cluster_secret",
        "Fresh-install cluster secret generated and saved to {} \
         (mode 0600). Fingerprint: {}. Retrieve the full value from \
         that file (sudo cat) before adding peer nodes — peers must \
         present the same secret to authenticate inter-node calls.",
        path, masked);
    Some(new_secret)
}

/// Print a short, log-safe fingerprint of a cluster secret: prefix +
/// first 6 chars after the `wsk_` + `…` + last 4. Enough for an
/// operator to confirm "is this the value I'm holding" without
/// committing the secret to journald.
fn mask_secret_for_log(s: &str) -> String {
    if s.len() < 14 { return "(too short to mask)".into(); }
    let head: String = s.chars().take(10).collect();   // "wsk_xxxxxx"
    let tail: String = s.chars().rev().take(4).collect::<Vec<_>>()
        .into_iter().rev().collect();
    format!("{}…{}", head, tail)
}

/// H5 — public wrapper used by Stage 3 coordinated rotation. After
/// any rotation that changes the on-disk cluster secret, the external
/// wolfusb daemon's WOLFUSB_KEY must be updated too — otherwise our
/// in-process wolfusb module (using the new cluster_secret) and the
/// external daemon (using the old env value) reject each other.
/// Best-effort; logs but does not fail on errors.
///
/// Also signals systemd to restart wolfusb.service so the daemon picks
/// up the new key without waiting for the next manual restart. Silent
/// no-op if systemctl / the service unit isn't present (e.g. fresh
/// install where setup.sh hasn't installed wolfusb yet).
pub fn realign_wolfusb_env_after_rotation(new_secret: &str) {
    if new_secret.is_empty() { return; }
    match realign_wolfusb_env(new_secret) {
        Ok(()) => {
            // C2 fix: dispatch the systemctl restart on a blocking
            // pool thread instead of synchronously on the caller —
            // this is called from actix request handlers and a
            // systemctl fork/exec under dbus pressure can block for
            // seconds. `--no-block` only stops systemd waiting on the
            // unit's startup; the spawn/exec itself is still
            // synchronous. tokio::spawn keeps the call off the actix
            // worker thread; the result is discarded (best-effort).
            // We also try to detect tokio runtime presence so the
            // helper stays callable from non-async contexts (init
            // paths, future CLI tools).
            let restart = || {
                let _ = std::process::Command::new("systemctl")
                    .args(["restart", "--no-block", "wolfusb.service"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            };
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => { handle.spawn_blocking(restart); }
                Err(_) => { std::thread::spawn(restart); }
            }
        }
        Err(e) => tracing::warn!(target: "cluster_secret",
            "failed to realign /etc/wolfusb/wolfusb.env after rotation ({}); \
             you may need to update WOLFUSB_KEY by hand and restart wolfusb.service",
            e),
    }
}

/// Update `/etc/wolfusb/wolfusb.env`'s `WOLFUSB_KEY=` line in place
/// without touching the rest of the file (preserves any operator
/// edits to bind / port). No-ops silently if the file isn't there.
fn realign_wolfusb_env(new_secret: &str) -> Result<(), std::io::Error> {
    let path = "/etc/wolfusb/wolfusb.env";
    if !std::path::Path::new(path).exists() { return Ok(()); }
    let body = std::fs::read_to_string(path)?;
    let mut out = String::with_capacity(body.len());
    let mut replaced = false;
    for line in body.lines() {
        if line.starts_with("WOLFUSB_KEY=") {
            out.push_str("WOLFUSB_KEY=");
            out.push_str(new_secret);
            out.push('\n');
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str("WOLFUSB_KEY=");
        out.push_str(new_secret);
        out.push('\n');
    }
    // Reuse the project's atomic 0600 writer so a partial write
    // can't leave the file truncated.
    crate::paths::write_secure(path, out)
        .map_err(std::io::Error::other)
}

/// Stage 5 of the cluster-secret migration: is the built-in default
/// secret currently accepted as a valid inter-node auth value?
///
/// Default (in this release): **YES, accept**. Shipping the binary
/// must not break any existing install. Operators opt INTO rejection
/// by setting `WOLFSTACK_REJECT_DEFAULT_SECRET=1` in the environment.
///
/// A future release flips the default to "reject" with an opt-OUT
/// flag (`WOLFSTACK_ACCEPT_DEFAULT_SECRET=1`) for any install that
/// hasn't migrated by then. The escape hatch is permanent so ops
/// support can recover a broken upgrade by setting the variable
/// without an emergency hotfix release.
pub fn default_secret_accepted() -> bool {
    // No peer address supplied → fail CLOSED. See
    // `default_secret_accepted_from` for why the peer is required.
    default_secret_accepted_from(None)
}

/// Peer-scoped form of [`default_secret_accepted`].
///
/// # Security (CVE pending — reported by Dostxodjayev Abdullox, 2026-08-01)
///
/// Before this, the built-in default was accepted from ANY source
/// address on a node that had not yet rotated. Since the constant is
/// published in this very file, that made every un-migrated,
/// network-reachable node a full authentication bypass: one HTTP
/// request with the public constant reached `require_auth`-gated
/// endpoints including `POST /api/containers/{runtime}/{id}/exec`,
/// i.e. unauthenticated root RCE inside any managed container.
///
/// The default is now honoured ONLY when the request arrives from an
/// address already recorded as a peer in `nodes.json`. Rationale:
///   * A single-node install has no peers, so nothing legitimate can
///     present the default — it is rejected outright.
///   * An existing multi-node cluster keeps working, because its
///     members are exactly the recorded peers. No upgrade breakage,
///     which is why this is safe to ship without a coordinated
///     rotation.
///   * An attacker on the internet is not a recorded peer.
///
/// `peer` MUST be the transport-level source address (actix
/// `HttpRequest::peer_addr`). NEVER pass a value derived from
/// `X-Forwarded-For` / `realip_remote_addr`: those are attacker-
/// controlled and would hand the bypass straight back.
///
/// Known, deliberate narrowing: a node still on the default whose
/// peers are recorded as hostnames is accepted only while those
/// hostnames resolve (60 s cache). Rotating the secret — which the
/// dashboard banner now demands — removes the dependency entirely.
pub fn default_secret_accepted_from(peer: Option<std::net::IpAddr>) -> bool {
    // Explicit reject takes priority — operators who set this WANT
    // the default rejected even if a future release flips the
    // overall default to "reject".
    if std::env::var("WOLFSTACK_REJECT_DEFAULT_SECRET")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return false;
    }
    // Permanent escape hatch: an operator recovering a half-migrated
    // cluster can force-accept the default without an emergency release.
    // Takes priority over every check below, including the peer gate.
    if std::env::var("WOLFSTACK_ACCEPT_DEFAULT_SECRET")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return true;
    }
    // Auto-lock: a node that has rotated to its OWN custom cluster secret
    // has migrated and never needs the public built-in default (which is a
    // constant published in the source repo). Reject the default for it —
    // this closes the "public default secret accepted everywhere" hole for
    // every cluster that has rotated, with zero operator action.
    if has_custom_cluster_secret() {
        return false;
    }
    // Un-migrated node: the default is still the working cluster
    // credential, but only between RECORDED PEERS.
    match peer {
        Some(ip) => peer_is_recorded(ip),
        None => false,
    }
}

/// Normalise an address for comparison: IPv4-mapped IPv6
/// (`::ffff:192.0.2.1`) is folded to its IPv4 form so a peer recorded
/// as `192.0.2.1` still matches a connection accepted on a
/// dual-stack listener.
fn canonical_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => std::net::IpAddr::V4(v4),
            None => std::net::IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Addresses recorded in `nodes.json`, resolved to IPs, cached for
/// 60 s. Only consulted on the built-in-default path (a migrated node
/// short-circuits above), so this never touches the hot auth path for
/// a healthy cluster.
fn peer_is_recorded(peer: std::net::IpAddr) -> bool {
    use std::collections::HashSet;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    use std::net::ToSocketAddrs;

    static CACHE: Mutex<Option<(Instant, HashSet<std::net::IpAddr>)>> = Mutex::new(None);
    const TTL: Duration = Duration::from_secs(60);

    let peer = canonical_ip(peer);
    // Poisoned lock must not become an auth bypass OR a cluster
    // outage — recompute locally instead of trusting/So poisoning.
    let mut guard = match CACHE.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some((at, set)) = guard.as_ref()
        && at.elapsed() < TTL
    {
        return set.contains(&peer);
    }

    let mut ips: HashSet<std::net::IpAddr> = HashSet::new();
    let path = crate::paths::get().nodes_config;
    if let Ok(raw) = std::fs::read_to_string(&path)
        && let Ok(nodes) = serde_json::from_str::<Vec<serde_json::Value>>(&raw)
    {
        for n in nodes {
            // `address` is the peer's configured address; `public_ip`
            // is what it reported about itself. A peer can legitimately
            // reach us from either, so both are allowed.
            for key in ["address", "public_ip"] {
                let Some(a) = n.get(key).and_then(|v| v.as_str()) else { continue };
                let a = a.trim();
                if a.is_empty() { continue; }
                // Strip a [v6]:port / host:port wrapper if present.
                let host = a.trim_start_matches('[').split(']').next().unwrap_or(a);
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    ips.insert(canonical_ip(ip));
                    continue;
                }
                // Hostname → resolve. Port 0 is fine; we only want IPs.
                if let Ok(addrs) = (host, 0u16).to_socket_addrs() {
                    for sa in addrs { ips.insert(canonical_ip(sa.ip())); }
                }
            }
        }
    }
    let hit = ips.contains(&peer);
    *guard = Some((Instant::now(), ips));
    hit
}

/// Authenticate a presented `X-WolfStack-Secret` header value against
/// every acceptance path used by inter-node auth:
///   1. The in-memory secret from process start (`state.cluster_secret`)
///   2. The current on-disk secret (re-read every call so a Stage 3
///      .pending → active commit is picked up without restart)
///   3. The hardcoded built-in default — ONLY if Stage 5 still allows it
///      (operators can opt out via `WOLFSTACK_REJECT_DEFAULT_SECRET=1`)
///
/// Use this from every endpoint that authenticates by cluster secret —
/// the alternative is bespoke three-line checks at every call site, which
/// is how the Stage 5 review found 13+ endpoints accepting the default
/// unconditionally even when the operator had opted out.
///
/// Constant-time per-comparison via `validate_cluster_secret`. The
/// overall function short-circuits on success (`||` chain), which is
/// fine: an attacker learns nothing useful from "which of the three
/// values matched" because the three valid values are equally
/// authoritative.
/// Use this from every HTTP handler, passing
/// `req.peer_addr().map(|a| a.ip())`. See
/// [`default_secret_accepted_from`] for the security rationale and
/// for why a forwarded header must never be substituted here.
pub fn validate_inter_node_secret_from(
    provided: &str,
    in_memory: &str,
    peer: Option<std::net::IpAddr>,
) -> bool {
    // CRITICAL ORDERING — do not "optimise" this by checking the
    // in-memory/on-disk slots first.
    //
    // On an un-migrated node BOTH of those slots literally CONTAIN the
    // built-in default: `load_cluster_secret()` falls back to
    // `CLUSTER_SECRET` whenever the custom-secret file is absent,
    // empty or unreadable, and `state.cluster_secret` was populated
    // from that same call at startup. So a "check our own slots first"
    // arrangement matches the published constant on the ordinary
    // comparison path and never consults the peer gate at all — which
    // is precisely the bypass being fixed here, and precisely the
    // reporter's PoC (an install whose /etc/wolfstack was unwritable).
    //
    // Therefore: if the presented value IS the published constant, the
    // peer gate is the ONLY thing that can accept it, no matter which
    // of our slots happens to hold the same bytes.
    if validate_cluster_secret(provided, default_cluster_secret()) {
        return default_secret_accepted_from(peer);
    }
    if validate_cluster_secret(provided, in_memory) { return true; }
    if validate_cluster_secret(provided, &load_cluster_secret()) { return true; }
    false
}

/// Validate a cluster secret from a request header.
///
/// True constant-time comparison: the pre-v18.7.30 implementation had
/// an early-exit on length mismatch which leaked the secret's length
/// via timing. Now we fold the length difference into the accumulator
/// so the running time depends only on the longer of the two inputs.
pub fn validate_cluster_secret(provided: &str, expected: &str) -> bool {
    if provided.is_empty() || expected.is_empty() {
        return false;
    }
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    // Mix the length difference into the accumulator by OR-ing every
    // byte of the XOR — this folds len-mismatch into the result
    // without a narrow u8 cast (which would alias 256-byte-apart
    // lengths to "equal"). Then walk both inputs in full by reading
    // zero for out-of-bounds indices.
    let len_diff_bytes = ((a.len() as u64) ^ (b.len() as u64)).to_le_bytes();
    let mut acc: u8 = len_diff_bytes.iter().fold(0u8, |x, b| x | *b);
    let max = a.len().max(b.len());
    for i in 0..max {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        acc |= x ^ y;
    }
    acc == 0
}

// Pure-Rust password hashing (replaces C libcrypt dependency)

/// Active session
struct Session {
    username: String,
    created: Instant,
    /// Read-only (viewer-role) session. Decided ONCE at login from the
    /// role the authenticating store reported — see `role_is_read_only`
    /// — and enforced centrally by `api::require_auth`, so a role change
    /// in users.json takes effect at the user's next login, never
    /// mid-session. (VolkSec report, 2026-09-09.)
    read_only: bool,
}

/// What `SessionManager::validate_info` hands back for a live session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub username: String,
    pub read_only: bool,
}

/// The ONE definition of which WolfStack user role is read-only.
///
/// `WolfUser::role` is documented as `"admin"` or `"viewer"` and the docs
/// promise viewer = read-only. Anything that is not literally `"admin"`
/// is treated as read-only so a mistyped or unknown role fails CLOSED —
/// the same rule `session_user_is_admin` applies.
pub fn role_is_read_only(role: &str) -> bool {
    role != "admin"
}

/// Session manager
pub struct SessionManager {
    sessions: RwLock<HashMap<String, Session>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new session for a user, returns the session token.
    ///
    /// `read_only` is the caller's verdict on the authenticated identity
    /// (`role_is_read_only(&user.role)` for a WolfStack-store or OIDC
    /// user; `false` for a Linux account, which has no role). It is
    /// deliberately a required argument rather than a defaulted builder
    /// so no login path can forget to decide it.
    pub fn create_session(&self, username: &str, read_only: bool) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(token.clone(), Session {
            username: username.to_string(),
            created: Instant::now(),
            read_only,
        });

        token
    }

    /// Validate a session token, returns the username if valid
    pub fn validate(&self, token: &str) -> Option<String> {
        self.validate_info(token).map(|s| s.username)
    }

    /// Validate a session token, returning the username AND whether the
    /// session is read-only. Every mutation gate that reads the cookie
    /// directly (instead of through `api::require_auth`) must use this
    /// and refuse `read_only` sessions.
    pub fn validate_info(&self, token: &str) -> Option<SessionInfo> {
        let sessions = self.sessions.read().unwrap();
        if let Some(session) = sessions.get(token)
            && session.created.elapsed() < SESSION_LIFETIME {
                return Some(SessionInfo {
                    username: session.username.clone(),
                    read_only: session.read_only,
                });
            }
        None
    }

    /// Destroy a session
    pub fn destroy(&self, token: &str) {
        let mut sessions = self.sessions.write().unwrap();
        if let Some(_session) = sessions.remove(token) {

        }
    }

    /// Destroy every active session. Used by the fleet-wide
    /// force-logout — operator wants to invalidate suspected stolen
    /// cookies. Every user has to re-authenticate after this.
    pub fn destroy_all(&self) {
        let mut sessions = self.sessions.write().unwrap();
        let n = sessions.len();
        sessions.clear();
        tracing::warn!("auth: destroyed {} active session(s) (force-logout)", n);
    }

    /// Clean up expired sessions
    pub fn cleanup(&self) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.retain(|_, s| s.created.elapsed() < SESSION_LIFETIME);
    }
}

#[cfg(test)]
mod read_only_session_tests {
    use super::{role_is_read_only, SessionInfo, SessionManager};

    #[test]
    fn only_the_literal_admin_role_is_not_read_only() {
        assert!(!role_is_read_only("admin"));
        assert!(role_is_read_only("viewer"));
        // Unknown / mistyped roles fail closed.
        assert!(role_is_read_only("Admin"));
        assert!(role_is_read_only("operator"));
        assert!(role_is_read_only(""));
    }

    #[test]
    fn session_carries_the_read_only_verdict_it_was_created_with() {
        let mgr = SessionManager::new();
        let admin = mgr.create_session("alice", false);
        let viewer = mgr.create_session("bob", true);
        assert_eq!(mgr.validate_info(&admin),
                   Some(SessionInfo { username: "alice".into(), read_only: false }));
        assert_eq!(mgr.validate_info(&viewer),
                   Some(SessionInfo { username: "bob".into(), read_only: true }));
        // The username-only accessor still works for read-side callers.
        assert_eq!(mgr.validate(&viewer).as_deref(), Some("bob"));
        assert_eq!(mgr.validate_info("no-such-token"), None);
    }
}

/// Authenticate a user against the Linux system (/etc/shadow)
pub fn authenticate_user(username: &str, password: &str) -> bool {
    // Validate inputs
    if username.is_empty() || password.is_empty() {
        return false;
    }

    // Prevent path traversal and injection
    if username.contains(':') || username.contains('/') || username.contains('\0') {
        warn!("Invalid username characters in login attempt");
        return false;
    }

    // Read /etc/shadow (requires root)
    let shadow = match std::fs::read_to_string("/etc/shadow") {
        Ok(s) => s,
        Err(e) => {
            warn!("Cannot read /etc/shadow: {} — WolfStack must run as root", e);
            return false;
        }
    };

    for line in shadow.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() < 2 {
            continue;
        }

        if parts[0] != username {
            continue;
        }

        let stored_hash = parts[1];

        // Skip locked/disabled accounts
        if stored_hash.is_empty() || stored_hash == "!" || stored_hash == "*"
            || stored_hash == "!!" || stored_hash.starts_with('!')
        {
            warn!("Login attempt for locked account '{}'", username);
            return false;
        }

        // Use crypt() to verify password
        match verify_password(password, stored_hash) {
            true => {

                return true;
            }
            false => {
                warn!("Failed login attempt for user '{}'", username);
                return false;
            }
        }
    }

    warn!("Login attempt for unknown user '{}'", username);
    false
}

/// Verify a password against a stored hash.
/// Uses native C crypt() via dlopen when available, with pure-Rust fallback
/// for yescrypt ($y$), SHA-512 ($6$), and SHA-256 ($5$).
fn verify_password(password: &str, stored_hash: &str) -> bool {
    // Try native C crypt() first — handles all formats
    if let Some(result) = native_crypt(password, stored_hash) {
        use subtle::ConstantTimeEq;
        return result.as_bytes().ct_eq(stored_hash.as_bytes()).into();
    }
    // Fallback: pure Rust (needed for statically-linked / musl builds)
    if stored_hash.starts_with("$y$") {
        use yescrypt::Yescrypt;
        use yescrypt::password_hash::PasswordVerifier;
        Yescrypt::default().verify_password(password.as_bytes(), stored_hash).is_ok()
    } else if stored_hash.starts_with("$6$") {
        sha_crypt::sha512_check(password, stored_hash).is_ok()
    } else if stored_hash.starts_with("$5$") {
        sha_crypt::sha256_check(password, stored_hash).is_ok()
    } else {
        false
    }
}

/// Try to call crypt() by dynamically loading libcrypt.so at runtime.
/// Returns None if libcrypt is not available (e.g. minimal Debian ISO).
fn native_crypt(password: &str, salt: &str) -> Option<String> {
    use std::ffi::{CStr, CString};
    let c_password = CString::new(password).ok()?;
    let c_salt = CString::new(salt).ok()?;
    unsafe {
        // Try libcrypt.so.2 (Arch/Fedora), then libcrypt.so.1 (Debian/Ubuntu)
        let lib = libc::dlopen(b"libcrypt.so.2\0".as_ptr() as *const _, libc::RTLD_NOW);
        let lib = if lib.is_null() {
            libc::dlopen(b"libcrypt.so.1\0".as_ptr() as *const _, libc::RTLD_NOW)
        } else {
            lib
        };
        if lib.is_null() {
            return None;
        }
        let sym = libc::dlsym(lib, b"crypt\0".as_ptr() as *const _);
        if sym.is_null() {
            libc::dlclose(lib);
            return None;
        }
        let crypt_fn: extern "C" fn(*const libc::c_char, *const libc::c_char) -> *mut libc::c_char =
            std::mem::transmute(sym);
        let result = crypt_fn(c_password.as_ptr(), c_salt.as_ptr());
        let ret = if result.is_null() {
            None
        } else {
            Some(CStr::from_ptr(result).to_string_lossy().to_string())
        };
        libc::dlclose(lib);
        ret
    }
}

/// Operator-tunable lockout policy. Defaults are aggressive — designed
/// for fleets that are exposed to the public internet. An attacker who
/// learns one root password can try at most `max_failures` times in any
/// `window_seconds` rolling window before being hard-blocked for
/// `lockout_seconds`. 10 attempts and 48-hour blocks make typical
/// password-spray attacks economically impossible.
///
/// The operator can adjust any of these via the Security settings UI
/// or by editing `/etc/wolfstack/auth-lockout.json` directly. Trusted
/// IPs / CIDRs bypass the lockout entirely so the operator can never
/// lock themselves out from their own networks.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoginLockoutConfig {
    /// How many failures within the detection window trigger a hard lockout.
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,
    /// Sliding window for counting failures (seconds).
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
    /// Hard lockout duration once `max_failures` is hit (seconds).
    /// Default: 48 hours. The operator chose this — appropriate when
    /// the threat model is "real attacker with leaked credentials".
    #[serde(default = "default_lockout_seconds")]
    pub lockout_seconds: u64,
    /// IPs or CIDRs that bypass the lockout entirely. Examples:
    /// `192.168.1.5`, `192.168.0.0/24`, `2a01:4f8:151:7225::/64`.
    /// IPv4 and IPv6 supported.
    #[serde(default)]
    pub trusted_ips: Vec<String>,
    /// Master switch. If false, no lockout is applied at all (useful
    /// for debugging — NOT recommended for production).
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

// 3 failures in 5 minutes from a single IP triggers a 48-hour kernel
// block. Aggressive default because in practice every brute-forcer
// hits one of:
//   - sshd:     Failed password / Invalid user
//   - pveproxy: authentication failure
//   - wolfstack: failed login on 8553
// and all three feed the same limiter (see log_monitor.rs). Three
// failures gives a legitimate fat-finger user one mistyped password
// + two retries before they're locked out; anything more rapid is
// automated scanning.
fn default_max_failures() -> u32 { 3 }
fn default_window_seconds() -> u64 { 300 }
fn default_lockout_seconds() -> u64 { 48 * 3600 }  // 48 hours
fn default_enabled() -> bool { true }

impl Default for LoginLockoutConfig {
    fn default() -> Self {
        Self {
            max_failures: default_max_failures(),
            window_seconds: default_window_seconds(),
            lockout_seconds: default_lockout_seconds(),
            trusted_ips: Vec::new(),
            enabled: default_enabled(),
        }
    }
}

impl LoginLockoutConfig {
    fn config_path() -> String {
        format!("{}/auth-lockout.json", crate::paths::get().config_dir)
    }
    pub fn load() -> Self {
        let mut cfg: Self = std::fs::read_to_string(Self::config_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        // One-time migration: pre-v23.12.13 default was max_failures=10.
        // v23.12.13 tightened to 3. If the saved value is the old
        // default exactly, treat it as "operator never tuned this" and
        // bring it down to the new default. An operator who actually
        // wants 10 can re-save the policy from the UI; their explicit
        // value is preserved on every subsequent load.
        if cfg.max_failures == 10 {
            tracing::info!(
                "auth-lockout: migrating max_failures 10 -> 3 (post-v23.12.13 default). \
                 To restore the older threshold, save the policy form with the value you want."
            );
            cfg.max_failures = 3;
            let _ = cfg.save();
        }
        cfg
    }
    pub fn save(&self) -> Result<(), String> {
        let path = Self::config_path();
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::paths::write_secure(&path, &json)
            .map_err(|e| format!("save lockout config: {}", e))
    }
    /// True if `ip` matches any trusted entry. Single-IP and CIDR forms
    /// supported; malformed entries are silently ignored (operator
    /// typos in the file shouldn't lock them out).
    pub fn is_trusted(&self, ip: &str) -> bool {
        let target: std::net::IpAddr = match ip.parse() {
            // to_canonical: an IPv4-mapped v6 form (::ffff:a.b.c.d, from a
            // dual-stack [::] listener) must match the operator's v4
            // trusted entries — ip_in_cidr is family-exact by design.
            Ok(a) => std::net::IpAddr::to_canonical(&a),
            Err(_) => return false,
        };
        for entry in &self.trusted_ips {
            // CIDR?
            if let Some((net_str, prefix_str)) = entry.split_once('/') {
                let net: std::net::IpAddr = match net_str.parse() { Ok(a) => a, Err(_) => continue };
                let prefix: u8 = match prefix_str.parse() { Ok(p) => p, Err(_) => continue };
                if ip_in_cidr(&target, &net, prefix) { return true; }
            } else if let Ok(parsed) = entry.parse::<std::net::IpAddr>()
                && parsed == target { return true; }
        }
        false
    }
}

// ─── Known admin client IPs + shared protected-IPs provider ───
//
// Threat-intel enforcement must never blackhole an address an operator
// authenticates from (klas 2026-07-05: a FireHOL feed update listed his
// browser's public IP; all three of his nodes kernel-DROPped it at once
// and only SSH from an internal address still worked). Every successful
// dashboard login records its source IP here; both threat-intel modules
// union this with the operator's trusted_ips before enforcing.
//
// Bounded: entries expire after 30 days without a successful login and
// the map is capped (oldest evicted) so a shared/roaming setup can't
// grow the file forever. Mode 0600 like every other auth artefact.

const KNOWN_ADMIN_IPS_MAX: usize = 64;
const KNOWN_ADMIN_IP_TTL_SECS: u64 = 30 * 24 * 3600;

fn known_admin_ips_path() -> String {
    format!("{}/known-admin-ips.json", crate::paths::get().config_dir)
}

fn load_known_admin_ips(now: u64) -> std::collections::BTreeMap<String, u64> {
    let mut map: std::collections::BTreeMap<String, u64> =
        std::fs::read_to_string(known_admin_ips_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
    map.retain(|_, ts| now.saturating_sub(*ts) < KNOWN_ADMIN_IP_TTL_SECS);
    map
}

/// Record a successful dashboard login's source IP. Called from every
/// login-success path (password, TOTP, passkey, OIDC). Loopback and
/// unspecified addresses are skipped — they never need feed protection.
pub fn record_admin_ip(ip: &str) {
    let parsed: std::net::IpAddr = match ip.trim().parse() {
        Ok(a) => std::net::IpAddr::to_canonical(&a),
        Err(_) => return,
    };
    if parsed.is_loopback() || parsed.is_unspecified() {
        return;
    }
    // Serialize the read-modify-write: two admins logging in at the same
    // moment must not clobber each other's entry (last-writer-wins on the
    // whole file would silently drop one IP's protection). Never held
    // across an await — this is a plain sync fn.
    static RECORD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = RECORD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut map = load_known_admin_ips(now);
    map.insert(parsed.to_string(), now);
    while map.len() > KNOWN_ADMIN_IPS_MAX {
        match map.iter().min_by_key(|(_, ts)| **ts).map(|(k, _)| k.clone()) {
            Some(oldest) => { map.remove(&oldest); }
            None => break,
        }
    }
    if let Ok(json) = serde_json::to_string_pretty(&map) {
        let _ = crate::paths::write_secure(&known_admin_ips_path(), &json);
    }
}

/// Every address enforcement features must never block: the operator's
/// trusted_ips entries (verbatim — single IPs or CIDRs) plus every IP
/// with a successful dashboard login in the last 30 days. Consumers do
/// their own family filtering / CIDR math.
pub fn protected_client_ips() -> Vec<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut out: Vec<String> = LoginLockoutConfig::load().trusted_ips.clone();
    out.extend(load_known_admin_ips(now).into_keys());
    out.sort();
    out.dedup();
    out
}

fn ip_in_cidr(target: &std::net::IpAddr, net: &std::net::IpAddr, prefix: u8) -> bool {
    match (target, net) {
        (std::net::IpAddr::V4(t), std::net::IpAddr::V4(n)) => {
            if prefix > 32 { return false; }
            let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
            (u32::from(*t) & mask) == (u32::from(*n) & mask)
        }
        (std::net::IpAddr::V6(t), std::net::IpAddr::V6(n)) => {
            if prefix > 128 { return false; }
            let mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
            (u128::from(*t) & mask) == (u128::from(*n) & mask)
        }
        _ => false,
    }
}

/// Per-IP record. `failures` is the sliding-window count; `locked_until`
/// is the hard-block expiry (only set once the threshold is hit). The
/// two are independent: a slow trickle of failures never hits the
/// threshold and gradually expires; a fast burst hits the threshold
/// and triggers the hard block.
#[derive(Debug, Default)]
struct AttemptRecord {
    failures: Vec<Instant>,
    locked_until: Option<Instant>,
    /// Username last seen — surfaced in the audit log so the operator
    /// can tell if it's an attacker spraying "admin", "root", "test" or
    /// somebody fat-fingering their own login.
    last_username: String,
}

/// One row in the audit log. Bounded buffer (newest 500 entries) so we
/// don't grow unbounded over time.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthLogEntry {
    /// Unix epoch seconds.
    pub timestamp: u64,
    pub ip: String,
    pub username: String,
    pub success: bool,
    /// Plain-English reason: "ok", "bad password", "locked out", "trusted ip skipped lockout", etc.
    pub reason: String,
    /// True when the attempt was blocked because the IP was already locked.
    pub was_locked: bool,
}

const AUDIT_LOG_MAX: usize = 500;

/// IP-based login rate limiter with hard lockouts, trusted-IP allowlist,
/// and an in-memory audit log. The operator-facing API is unchanged
/// (is_locked_out / record_failure / clear) so existing callers keep
/// working; new methods expose the audit log and the config.
/// Hook callbacks installed by the API/runtime layer so the limiter
/// can trigger fleet propagation without owning ClusterState directly.
/// Set once at startup; called by the limiter whenever a lock/unlock
/// happens regardless of the source surface (WolfStack UI, sshd, PVE).
pub type PropagateBlockHook = std::sync::Arc<dyn Fn(&str, u64) + Send + Sync>;
pub type PropagateUnblockHook = std::sync::Arc<dyn Fn(&str) + Send + Sync>;
/// (title, body) callback fired when a lockout newly triggers. main.rs
/// wires this to alerting::send_node_alert so the operator gets a
/// Discord / Slack / Telegram / email with the cluster + hostname.
pub type SecurityAlertHook = std::sync::Arc<dyn Fn(String, String) + Send + Sync>;

pub struct LoginRateLimiter {
    attempts: RwLock<HashMap<String, AttemptRecord>>,
    audit: RwLock<std::collections::VecDeque<AuthLogEntry>>,
    config: RwLock<LoginLockoutConfig>,
    propagate_block: RwLock<Option<PropagateBlockHook>>,
    propagate_unblock: RwLock<Option<PropagateUnblockHook>>,
    alert_hook: RwLock<Option<SecurityAlertHook>>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: RwLock::new(HashMap::new()),
            audit: RwLock::new(std::collections::VecDeque::with_capacity(AUDIT_LOG_MAX)),
            config: RwLock::new(LoginLockoutConfig::load()),
            propagate_block: RwLock::new(None),
            propagate_unblock: RwLock::new(None),
            alert_hook: RwLock::new(None),
        }
    }

    pub fn install_alert_hook(&self, hook: SecurityAlertHook) {
        *self.alert_hook.write().unwrap() = Some(hook);
    }

    /// Install hooks the limiter will call whenever a lock/unlock
    /// happens. The hooks own (or clone) the cluster state and fan
    /// out via the existing inter-node API. Set ONCE at startup.
    pub fn install_propagation_hooks(&self,
        on_block: PropagateBlockHook,
        on_unblock: PropagateUnblockHook,
    ) {
        *self.propagate_block.write().unwrap() = Some(on_block);
        *self.propagate_unblock.write().unwrap() = Some(on_unblock);
    }

    fn fire_block_hook(&self, ip: &str, seconds: u64) {
        let hook = self.propagate_block.read().unwrap().clone();
        if let Some(h) = hook {
            h(ip, seconds);
        }
    }

    fn fire_unblock_hook(&self, ip: &str) {
        let hook = self.propagate_unblock.read().unwrap().clone();
        if let Some(h) = hook {
            h(ip);
        }
    }

    /// Snapshot the current config.
    pub fn config(&self) -> LoginLockoutConfig {
        self.config.read().unwrap().clone()
    }

    /// Replace the config (and persist to disk). Returns the saved
    /// shape so the caller can echo it back to the operator.
    pub fn set_config(&self, new: LoginLockoutConfig) -> Result<LoginLockoutConfig, String> {
        new.save()?;
        *self.config.write().unwrap() = new.clone();
        Ok(new)
    }

    /// Append an audit row. Bounded — oldest entry dropped when full.
    fn audit_push(&self, entry: AuthLogEntry) {
        let mut log = self.audit.write().unwrap();
        if log.len() >= AUDIT_LOG_MAX {
            log.pop_front();
        }
        log.push_back(entry);
    }

    /// Read the audit log (newest first).
    pub fn audit_log(&self) -> Vec<AuthLogEntry> {
        let log = self.audit.read().unwrap();
        log.iter().rev().cloned().collect()
    }

    /// Currently-locked IPs (with remaining seconds). Useful for the UI.
    pub fn current_lockouts(&self) -> Vec<(String, u64, String)> {
        let attempts = self.attempts.read().unwrap();
        let now = Instant::now();
        attempts.iter()
            .filter_map(|(ip, rec)| {
                rec.locked_until.and_then(|until| {
                    if until > now {
                        Some((ip.clone(), until.duration_since(now).as_secs(), rec.last_username.clone()))
                    } else { None }
                })
            })
            .collect()
    }

    /// Manually clear a lockout for a specific IP. Operator escape hatch.
    pub fn unblock(&self, ip: &str) {
        let mut attempts = self.attempts.write().unwrap();
        attempts.remove(ip);
        drop(attempts);
        // Drop the kernel rule too — operator unblocking expects full recovery.
        kernel_unblock_ip(ip);
        self.persist_lockouts();
        self.fire_unblock_hook(ip);
        self.audit_push(AuthLogEntry {
            timestamp: now_secs(),
            ip: ip.to_string(),
            username: String::new(),
            success: false,
            reason: "manually unblocked by operator".into(),
            was_locked: false,
        });
    }

    /// Add a kernel block from a peer's propagation. Skips trusted IPs
    /// (each node has its own trusted list — the receiver always re-
    /// validates, so an attacker can't trick a peer into blocking your
    /// admin IP just because it's not trusted on their node). Records
    /// in the audit log so the operator sees fleet-wide propagation.
    pub fn add_propagated_lockout(&self, ip: &str, lockout_seconds: u64, source_node: &str) {
        let cfg = self.config.read().unwrap().clone();
        if cfg.is_trusted(ip) {
            tracing::info!(
                "auth: refused propagated lockout for {} (trusted on this node) — source: {}",
                ip, source_node
            );
            self.audit_push(AuthLogEntry {
                timestamp: now_secs(),
                ip: ip.to_string(),
                username: String::new(),
                success: false,
                reason: format!("propagated lockout from {} REFUSED — IP is trusted here", source_node),
                was_locked: false,
            });
            return;
        }
        let mut attempts = self.attempts.write().unwrap();
        let rec = attempts.entry(ip.to_string()).or_default();
        let new_until = Instant::now() + Duration::from_secs(lockout_seconds);
        // Extend if a longer lockout arrives, never shorten.
        rec.locked_until = Some(match rec.locked_until {
            Some(existing) if existing > new_until => existing,
            _ => new_until,
        });
        drop(attempts);
        kernel_block_ip(ip);
        self.persist_lockouts();
        tracing::warn!(
            "auth: kernel-blocked {} via fleet propagation from {} ({}s)",
            ip, source_node, lockout_seconds
        );
        self.audit_push(AuthLogEntry {
            timestamp: now_secs(),
            ip: ip.to_string(),
            username: String::new(),
            success: false,
            reason: format!("kernel-blocked via fleet propagation from {}", source_node),
            was_locked: false,
        });
    }

    /// Record a failed login attempt. Returns true if the IP just hit
    /// the threshold (was not previously locked, now is).
    pub fn record_failure(&self, ip: &str) -> bool {
        self.record_failure_with(ip, "")
    }

    /// Variant that records the username and audit reason for the row.
    pub fn record_failure_with(&self, ip: &str, username: &str) -> bool {
        let cfg = self.config.read().unwrap().clone();
        // Trusted IPs never accumulate failures.
        if cfg.is_trusted(ip) {
            self.audit_push(AuthLogEntry {
                timestamp: now_secs(),
                ip: ip.to_string(),
                username: username.to_string(),
                success: false,
                reason: "bad password (trusted IP — no lockout)".into(),
                was_locked: false,
            });
            tracing::info!("auth: failed login for {} from trusted IP {} (no lockout)", username, ip);
            return false;
        }
        if !cfg.enabled {
            self.audit_push(AuthLogEntry {
                timestamp: now_secs(),
                ip: ip.to_string(),
                username: username.to_string(),
                success: false,
                reason: "bad password (lockout disabled in config)".into(),
                was_locked: false,
            });
            return false;
        }
        let window = Duration::from_secs(cfg.window_seconds);
        let lockout = Duration::from_secs(cfg.lockout_seconds);
        let mut attempts = self.attempts.write().unwrap();
        let entry = attempts.entry(ip.to_string()).or_default();
        let now = Instant::now();
        entry.failures.retain(|t| now.duration_since(*t) < window);
        entry.failures.push(now);
        entry.last_username = username.to_string();
        let just_locked = entry.failures.len() >= cfg.max_failures as usize && entry.locked_until.is_none();
        if just_locked {
            entry.locked_until = Some(now + lockout);
            tracing::warn!(
                "auth: IP {} hit {} failed logins in {}s — locked out for {}s",
                ip, cfg.max_failures, cfg.window_seconds, cfg.lockout_seconds
            );
        }
        drop(attempts);
        // Apply the kernel-level block AFTER releasing the write lock
        // (Command::new can take a few ms and we don't want to hold
        // the attempts lock across it).
        if just_locked {
            kernel_block_ip(ip);
            self.persist_lockouts();
            self.fire_block_hook(ip, cfg.lockout_seconds);
            // Alert operator out-of-band (Discord/Slack/Telegram/email).
            // Title includes the source IP; body has the username
            // attempted, threshold, and lockout duration. Cluster +
            // hostname are stamped in by the alert hook itself.
            let hook = self.alert_hook.read().unwrap().clone();
            if let Some(h) = hook {
                let title = format!("🚨 IP {} blocked after {} failed logins", ip, cfg.max_failures);
                let body = format!(
                    "Source IP {} crossed the brute-force threshold and is now kernel-blocked.\n\n\
                     User attempted: {}\n\
                     Threshold: {} failed logins within {} seconds\n\
                     Lockout: {} seconds ({} hours)\n\n\
                     The block is enforced via iptables DROP and is propagating to every other WolfStack-managed node in the cluster.",
                    ip, if username.is_empty() { "(unknown)".to_string() } else { username.to_string() },
                    cfg.max_failures, cfg.window_seconds,
                    cfg.lockout_seconds, cfg.lockout_seconds / 3600,
                );
                h(title, body);
            }
        }
        self.audit_push(AuthLogEntry {
            timestamp: now_secs(),
            ip: ip.to_string(),
            username: username.to_string(),
            success: false,
            reason: if just_locked { "bad password — threshold hit, IP locked".into() } else { "bad password".into() },
            was_locked: false,
        });
        just_locked
    }

    /// Immediately lock out an IP without the threshold accumulation.
    /// Used for cases where a single hit is unambiguous evidence and
    /// the standard sliding-window count would just delay the same
    /// outcome. Returns `true` if newly locked (caller should
    /// propagate to the rest of the cluster); `false` if the IP was
    /// trusted, the limiter is disabled, or the IP was already locked.
    ///
    /// `source` and `detail` are caller-side context only — the
    /// operator-visible audit log uses a generic reason regardless.
    pub fn force_lockout(&self, ip: &str, source: &str, detail: &str) -> bool {
        let cfg = self.config.read().unwrap().clone();
        if cfg.is_trusted(ip) {
            tracing::info!("auth: force-lockout skipped for trusted IP {} ({})", ip, source);
            return false;
        }
        if !cfg.enabled {
            return false;
        }
        let lockout = Duration::from_secs(cfg.lockout_seconds);
        let mut attempts = self.attempts.write().unwrap();
        let entry = attempts.entry(ip.to_string()).or_default();
        let now = Instant::now();
        if let Some(until) = entry.locked_until
            && until > now {
                return false; // already locked, don't re-fire
            }
        entry.locked_until = Some(now + lockout);
        entry.last_username = source.to_string();
        drop(attempts);
        tracing::warn!("auth: auto-block {}", ip);
        kernel_block_ip(ip);
        self.persist_lockouts();
        self.fire_block_hook(ip, cfg.lockout_seconds);
        let hook = self.alert_hook.read().unwrap().clone();
        if let Some(h) = hook {
            let title = format!("🚨 IP {} auto-blocked", ip);
            let body = format!(
                "Source IP {} was blocked.\n\n\
                 Lockout: {} seconds ({} hours)\n\n\
                 The block is enforced via iptables DROP and is propagating to every other WolfStack-managed node in the cluster.",
                ip, cfg.lockout_seconds, cfg.lockout_seconds / 3600,
            );
            h(title, body);
        }
        // Audit reason is intentionally generic — callers pass their
        // own `detail` for context only at the limiter level; we don't
        // surface it in the operator-visible audit log.
        let _ = detail;
        let _ = source;
        self.audit_push(AuthLogEntry {
            timestamp: now_secs(),
            ip: ip.to_string(),
            username: String::new(),
            success: false,
            reason: "auto-block".to_string(),
            was_locked: true,
        });
        true
    }

    /// Currently locked out?
    pub fn is_locked_out(&self, ip: &str) -> bool {
        let cfg = self.config.read().unwrap();
        if cfg.is_trusted(ip) || !cfg.enabled { return false; }
        drop(cfg);
        let attempts = self.attempts.read().unwrap();
        match attempts.get(ip) {
            Some(rec) => match rec.locked_until {
                Some(until) => until > Instant::now(),
                None => false,
            },
            None => false,
        }
    }

    /// Remaining lockout seconds (0 if not locked).
    pub fn lockout_remaining(&self, ip: &str) -> u64 {
        let attempts = self.attempts.read().unwrap();
        match attempts.get(ip).and_then(|r| r.locked_until) {
            Some(until) => {
                let now = Instant::now();
                if until > now { until.duration_since(now).as_secs() } else { 0 }
            }
            None => 0,
        }
    }

    /// Successful login — clear failures, audit the success.
    pub fn clear(&self, ip: &str) {
        self.clear_with(ip, "")
    }

    pub fn clear_with(&self, ip: &str, username: &str) {
        let mut attempts = self.attempts.write().unwrap();
        attempts.remove(ip);
        drop(attempts);
        self.audit_push(AuthLogEntry {
            timestamp: now_secs(),
            ip: ip.to_string(),
            username: username.to_string(),
            success: true,
            reason: "ok".into(),
            was_locked: false,
        });
        tracing::info!("auth: successful login for {} from {}", username, ip);
    }

    /// Audit-only: record a "blocked because already locked" attempt.
    pub fn audit_blocked(&self, ip: &str, username: &str) {
        self.audit_push(AuthLogEntry {
            timestamp: now_secs(),
            ip: ip.to_string(),
            username: username.to_string(),
            success: false,
            reason: format!("rejected — IP locked for {}s more", self.lockout_remaining(ip)),
            was_locked: true,
        });
    }

    /// Periodic cleanup of expired entries (called from the background
    /// task). Removes kernel iptables rules for any lockouts that
    /// expired since the last tick — the rules persist across restarts,
    /// so without this they'd accumulate forever.
    pub fn cleanup(&self) {
        let cfg = self.config.read().unwrap().clone();
        let window = Duration::from_secs(cfg.window_seconds);
        let now = Instant::now();
        let mut to_unblock: Vec<String> = Vec::new();
        {
            let mut attempts = self.attempts.write().unwrap();
            attempts.retain(|ip, rec| {
                rec.failures.retain(|t| now.duration_since(*t) < window);
                let still_locked = matches!(rec.locked_until, Some(u) if u > now);
                let just_expired = matches!(rec.locked_until, Some(u) if u <= now);
                if just_expired {
                    to_unblock.push(ip.clone());
                }
                !rec.failures.is_empty() || still_locked
            });
        }
        for ip in to_unblock {
            kernel_unblock_ip(&ip);
            tracing::info!("auth: lockout for {} expired — kernel rule removed", ip);
        }
        if !to_unblock_was_empty(&self.attempts) {
            self.persist_lockouts();
        }
    }
}

fn to_unblock_was_empty(attempts: &RwLock<HashMap<String, AttemptRecord>>) -> bool {
    attempts.read().unwrap().is_empty()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════════
// Kernel-level IP blocking — "act like the server isn't there"
// ════════════════════════════════════════════════════════════════════
//
// When the rate limiter decides an IP has crossed the threshold, we
// install an iptables DROP rule for that source. New TCP packets get
// silently discarded by the kernel — no SYN-ACK, no RST, no HTTP
// response. From the attacker's side the server appears offline.
//
// Existing TCP connections from a blocked IP keep working briefly
// (they're already established) but they'll timeout on the next ACK
// the kernel can't deliver. New connections fail at SYN.
//
// Trusted IPs are NEVER kernel-blocked — the operator can always reach
// the box from their declared admin networks.
//
// State is persisted to /etc/wolfstack/auth-active-lockouts.json so
// WolfStack can restore iptables rules on restart (kernel rules persist
// across WolfStack restarts; the file just lets us track what we own).

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistedLockout {
    ip: String,
    locked_at: u64,         // unix secs
    lockout_seconds: u64,   // total duration
}

fn lockouts_file() -> String {
    format!("{}/auth-active-lockouts.json", crate::paths::get().config_dir)
}

/// Drop every entry for `ip` from a persisted lockout snapshot.
///
/// Returns `None` when nothing matched, so the caller can skip the rewrite
/// (and say nothing) rather than churn the file on every unblock.
///
/// Compares canonical forms: `kernel_block_ip` canonicalises before writing,
/// but a snapshot written by an older build may hold the IPv4-mapped spelling
/// (`::ffff:a.b.c.d`) that a dual-stack listener reports. Matching on the raw
/// string would silently miss those and leave the entry to be restored.
fn prune_lockout_snapshot(
    snapshot: Vec<PersistedLockout>,
    ip: &str,
) -> Option<Vec<PersistedLockout>> {
    let canon = |s: &str| {
        s.parse::<std::net::IpAddr>()
            .map(|a| a.to_canonical().to_string())
            .unwrap_or_else(|_| s.to_string())
    };
    let target = canon(ip);
    let before = snapshot.len();
    let kept: Vec<PersistedLockout> =
        snapshot.into_iter().filter(|e| canon(&e.ip) != target).collect();
    if kept.len() == before { None } else { Some(kept) }
}

/// Remove `ip` from the on-disk lockout snapshot. Returns true if an entry
/// was there and has been removed.
///
/// Without this an unblock is undone by the next restart:
/// `restore_persisted_lockouts` re-applies every non-expired entry it finds —
/// the kernel DROP *and* the in-memory record — so the operator's recovery
/// survives only until someone bounces the service.
pub fn cli_prune_persisted_lockout(ip: &str) -> bool {
    let path = lockouts_file();
    let json = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let snapshot: Vec<PersistedLockout> = match serde_json::from_str(&json) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let kept = match prune_lockout_snapshot(snapshot, ip) {
        Some(k) => k,
        None => return false,
    };
    match serde_json::to_string_pretty(&kept) {
        Ok(out) => crate::paths::write_secure(&path, &out).is_ok(),
        Err(_) => false,
    }
}

/// Ask the RUNNING daemon to drop its in-memory login lockout for `ip`.
///
/// `--unblock` is a separate, short-lived process. It can delete kernel rules
/// and rewrite files, but the lockout that actually refuses a login lives in
/// the daemon's memory (`LoginRateLimiter::attempts`, keyed on `Instant`, so it
/// is not reconstructable from disk). Clearing only the kernel rule leaves the
/// operator able to *reach* the login page and still be rejected on submit —
/// the exact dead end reported 2026-08-06, where the only real escape was a
/// `trusted_ips` entry.
///
/// So drive the same `/api/security/auth-unblock` endpoint the Security UI
/// uses, authenticating with this node's cluster secret — readable because
/// `--unblock` already requires root. HTTPS first (the default), then plain
/// HTTP for `--no-tls` installs. Self-signed certs are the norm here and the
/// peer is 127.0.0.1, so certificate validation buys nothing: anyone able to
/// intercept this connection already owns the box.
pub async fn cli_clear_daemon_lockout(ip: &str) -> Result<(), String> {
    let port = crate::ports::PortConfig::load().api;
    let secret = load_cluster_secret();
    let client = reqwest::Client::builder()
        // Bound CONNECT as well as the overall request — required by
        // tests/resource_safety.rs after the 2026-08-05 fd exhaustion, and a
        // wedged socket must never stall an operator's recovery command.
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("http client: {}", e))?;

    // propagate: true matches the Security UI's default — "unblock my IP"
    // is nearly always meant fleet-wide, and the threat-intel half of
    // --unblock already allowlists across the cluster.
    let body = serde_json::json!({ "ip": ip, "propagate": true });
    let mut last_err = String::from("no endpoint tried");
    for scheme in ["https", "http"] {
        let url = format!("{}://127.0.0.1:{}/api/security/auth-unblock", scheme, port);
        match client
            .post(&url)
            .peer_auth(&secret)
            .json(&body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => return Ok(()),
            Ok(r) => last_err = format!("{} returned HTTP {}", url, r.status()),
            Err(e) => last_err = format!("{}: {}", url, e),
        }
    }
    Err(last_err)
}

// ─── Cluster-node block protection ──────────────────────────────────────────
// klasSponsor 2026-06-08: WolfStack nodes were kernel-blocking / fail2ban-
// banning each OTHER's IPs (inter-node polling, a propagated block, or SSH
// between nodes tripping the 3-strike / scan auto-block), silently breaking
// cluster connectivity — "one node had banned another's ip". Every kernel
// block funnels through `kernel_block_ip`, so a single guard there protects
// all paths (brute-force, scan, AND propagated blocks). The set is refreshed
// from cluster state every ~10s by a background task in main.rs; a refused
// block is recorded so the Security UI can raise a red banner and an alert can
// fire. (fail2ban bans independently — its ignoreip is handled separately.)
static PROTECTED_NODE_IPS: std::sync::OnceLock<RwLock<std::collections::HashSet<String>>> =
    std::sync::OnceLock::new();
static PROTECTED_BLOCK_EVENTS: std::sync::OnceLock<RwLock<std::collections::VecDeque<ProtectedBlockEvent>>> =
    std::sync::OnceLock::new();
const MAX_PROTECTED_EVENTS: usize = 50;

/// A refused attempt to kernel-block a cluster-node IP. Drives the red banner.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ProtectedBlockEvent {
    /// Monotonic id so the UI / alerter can tell what's new.
    pub id: u64,
    pub ip: String,
    /// Unix seconds.
    pub at: u64,
}

fn protected_ips() -> &'static RwLock<std::collections::HashSet<String>> {
    PROTECTED_NODE_IPS.get_or_init(|| RwLock::new(std::collections::HashSet::new()))
}
fn protected_events() -> &'static RwLock<std::collections::VecDeque<ProtectedBlockEvent>> {
    PROTECTED_BLOCK_EVENTS.get_or_init(|| RwLock::new(std::collections::VecDeque::new()))
}

// ─── Sticky peer protection — persisted cluster-peer IPs ───
//
// The protected-node set is rebuilt every sync tick from LIVE cluster
// membership, so the moment a node fell out of its cluster the manager's
// IP lost ban protection — exactly when re-add auth churn (stale-secret
// polls, mistyped admin passwords) makes an auto-ban most likely, and a
// banned manager can't even reach the join handshake to recover
// (klasSponsor 2026-07-16: Unraid agent's startup log showed healed bans
// against both cluster LAN IPs). Persist every peer we've protected and
// keep protecting it for 30 days after it was last seen in the cluster.
// Same bounded-file pattern as known-admin-ips above.

const KNOWN_PEER_IPS_MAX: usize = 128;
const KNOWN_PEER_IP_TTL_SECS: u64 = 30 * 24 * 3600;
// Refresh a stored peer's last-seen stamp at most daily: the cluster sync
// loop calls set_protected_node_ips every 10s and must not rewrite
// flash-backed config storage on every tick.
const KNOWN_PEER_REFRESH_SECS: u64 = 24 * 3600;

fn known_peer_ips_path() -> String {
    format!("{}/known-peer-ips.json", crate::paths::get().config_dir)
}

/// An address worth protecting: parseable, not unspecified (would match
/// far too much and must never be whitelisted), not loopback (never needs
/// protection).
fn valid_protectable_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>()
        .map(|ip| !ip.is_unspecified() && !ip.is_loopback())
        .unwrap_or(false)
}

fn load_known_peer_ips(now: u64) -> std::collections::BTreeMap<String, u64> {
    let mut map: std::collections::BTreeMap<String, u64> =
        std::fs::read_to_string(known_peer_ips_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
    map.retain(|ip, ts| {
        now.saturating_sub(*ts) < KNOWN_PEER_IP_TTL_SECS && valid_protectable_ip(ip)
    });
    map
}

fn save_known_peer_ips(map: &std::collections::BTreeMap<String, u64>) {
    if let Ok(json) = serde_json::to_string_pretty(map) {
        let _ = crate::paths::write_secure(&known_peer_ips_path(), &json);
    }
}

fn evict_oldest_peers(map: &mut std::collections::BTreeMap<String, u64>) {
    while map.len() > KNOWN_PEER_IPS_MAX {
        match map.iter().min_by_key(|(_, ts)| **ts).map(|(k, _)| k.clone()) {
            Some(oldest) => { map.remove(&oldest); }
            None => break,
        }
    }
}

// Serializes read-modify-write of known-peer-ips.json between the cluster
// sync loop, the join-handshake path, and the operator forget path. Never
// held across an await — all users are plain sync fns.
static PEER_IPS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Record a PROVEN cluster manager's source IP as a sticky protected peer
/// and protect it in-memory immediately. Called from the join-handshake
/// success path — the caller has verified the join token AND this node's
/// admin credentials, so the source is operator-controlled by definition.
/// The caller heals any existing kernel ban (`kernel_unblock_ip`) off the
/// async executor.
pub fn record_known_peer_ip(ip: &str) {
    let canon = match ip.trim().parse::<std::net::IpAddr>() {
        Ok(a) => a.to_canonical().to_string(),
        Err(_) => return,
    };
    if !valid_protectable_ip(&canon) { return; }
    // Hold PEER_IPS_LOCK across BOTH the persist and the in-memory insert:
    // a concurrent set_protected_node_ips tick snapshots-then-overwrites
    // the in-memory set, and an insert landing between its snapshot and
    // its commit would be clobbered until the next tick — a 10s window of
    // lost protection at the exact moment a join is in flight. Lock order
    // is always PEER_IPS_LOCK → protected_ips().write(), never reversed.
    {
        let _guard = PEER_IPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let now = now_secs();
        let mut stored = load_known_peer_ips(now);
        stored.insert(canon.clone(), now);
        evict_oldest_peers(&mut stored);
        save_known_peer_ips(&stored);
        if let Ok(mut g) = protected_ips().write() {
            g.insert(canon.clone());
        }
    }
    tracing::info!(
        "auth: protecting joining manager IP {} from auto-bans (join handshake verified)",
        canon
    );
}

/// Drop an IP from the sticky peer store AND the in-memory protected set —
/// the operator explicitly wants this address blockable (e.g. a removed,
/// now-untrusted ex-peer). A LIVE cluster member re-enters the protected
/// set on the next sync tick, so this can never make nodes block each
/// other; it only lifts the 30-day stickiness. Callers must ensure the
/// request is operator-initiated, NOT propagated (a peer's bad ban must
/// not strip protection fleet-wide).
pub fn forget_known_peer_ip(ip: &str) {
    let canon = match ip.trim().parse::<std::net::IpAddr>() {
        Ok(a) => a.to_canonical().to_string(),
        Err(_) => return,
    };
    // Same lock scope as record_known_peer_ip — see the comment there.
    {
        let _guard = PEER_IPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let now = now_secs();
        let mut stored = load_known_peer_ips(now);
        if stored.remove(&canon).is_none() { return; }
        save_known_peer_ips(&stored);
        if let Ok(mut g) = protected_ips().write() {
            g.remove(&canon);
        }
    }
    tracing::info!(
        "auth: operator lifted sticky peer protection for {} (block will apply unless it is a live cluster member)",
        canon
    );
}

/// Replace the set of cluster-node IPs that must never be kernel-blocked.
/// Returns the IPs that are NEWLY protected since the last call, so the caller
/// can heal any pre-existing bad ban (a one-shot unblock per IP) without
/// shelling out to iptables every cycle. Unspecified / unparseable addresses
/// (e.g. a node still reporting 0.0.0.0) are dropped — they'd match far too
/// much and must never be whitelisted.
pub fn set_protected_node_ips(ips: Vec<String>) -> Vec<String> {
    let live: std::collections::HashSet<String> = ips.into_iter()
        .filter(|s| valid_protectable_ip(s))
        .collect();
    // Sticky protection: union live membership with every peer seen in the
    // last 30 days (see the known-peer section above) so a node that falls
    // out of its cluster keeps protecting its manager/peers while the
    // operator re-adds it. Live members refresh their stored last-seen at
    // most daily to bound file writes.
    let mut set = live.clone();
    let mut newly = Vec::new();
    // The in-memory commit stays INSIDE the PEER_IPS_LOCK scope so a
    // concurrent record/forget can't land between this snapshot and the
    // `*g = set` overwrite and get clobbered for a tick (lock order:
    // PEER_IPS_LOCK → protected_ips().write(), same everywhere).
    {
        let _guard = PEER_IPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let now = now_secs();
        let mut stored = load_known_peer_ips(now);
        let mut dirty = false;
        for ip in &live {
            let needs_refresh = stored.get(ip)
                .is_none_or(|ts| now.saturating_sub(*ts) >= KNOWN_PEER_REFRESH_SECS);
            if needs_refresh {
                stored.insert(ip.clone(), now);
                dirty = true;
            }
        }
        if stored.len() > KNOWN_PEER_IPS_MAX {
            evict_oldest_peers(&mut stored);
            dirty = true;
        }
        if dirty { save_known_peer_ips(&stored); }
        set.extend(stored.into_keys());
        if let Ok(mut g) = protected_ips().write() {
            for ip in &set {
                if !g.contains(ip) { newly.push(ip.clone()); }
            }
            *g = set;
        }
    }
    newly
}

/// True if `ip` is a known cluster-node address that must never be blocked.
pub fn is_protected_node_ip(ip: &str) -> bool {
    protected_ips().read().map(|g| g.contains(ip)).unwrap_or(false)
}

/// Record that a block was refused for a protected cluster-node IP. Coalesces
/// a rapid repeat for the same IP so a tight propagation loop can't flood the
/// ring (or re-alert) — it bumps the existing entry's timestamp instead.
/// `pub` so other block paths that don't go through `kernel_block_ip` (e.g. the
/// compromise-remediation C2 block) can surface their own refusals too.
pub fn record_protected_block(ip: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if let Ok(mut g) = protected_events().write() {
        if let Some(last) = g.back_mut()
            && last.ip == ip && now.saturating_sub(last.at) < 5
        {
            last.at = now;
            return;
        }
        let id = g.back().map(|e| e.id + 1).unwrap_or(1);
        g.push_back(ProtectedBlockEvent { id, ip: ip.to_string(), at: now });
        while g.len() > MAX_PROTECTED_EVENTS { g.pop_front(); }
    }
}

/// Recent refused blocks, oldest first. For the Security UI banner + alerter.
pub fn recent_protected_block_events() -> Vec<ProtectedBlockEvent> {
    protected_events().read().map(|g| g.iter().cloned().collect()).unwrap_or_default()
}

// ─── Local workload-subnet block protection ─────────────────────────────────
// klasSponsor 2026-06-08 (round 2): the same auto-block was also firewalling the
// host's OWN containers — a Docker/LXC service that hit an auth endpoint with bad
// creds tripped the 3-strike brute-force block, and kernel_block_ip's INPUT+FORWARD
// DROP on the container's IP killed its traffic ("wolfstack made iptables rules to
// drop traffic from those containers"). We exempt the locally-managed container
// bridges (docker0/br-*/lxcbr*/virbr*, from `collect_workload_subnets`) the same way
// cluster-node IPs are exempt. A genuinely-compromised container is stopped /
// quarantined, never blanket FORWARD-DROP'd (which is over-broad). CIDR-based
// because container IPs are dynamic; refreshed every ~10s in main.rs.
static PROTECTED_WORKLOAD_SUBNETS: std::sync::OnceLock<RwLock<Vec<(std::net::IpAddr, u8)>>> =
    std::sync::OnceLock::new();

fn protected_workload_subnets() -> &'static RwLock<Vec<(std::net::IpAddr, u8)>> {
    PROTECTED_WORKLOAD_SUBNETS.get_or_init(|| RwLock::new(Vec::new()))
}

/// Parse a CIDR (v4 "a.b.c.d/prefix" or v6 "fd00::/64") into (network,
/// prefix). None on garbage, a missing prefix, or a /0 in either family —
/// we must never whitelist the entire internet.
fn parse_workload_cidr(cidr: &str) -> Option<(std::net::IpAddr, u8)> {
    let (ip_s, pfx_s) = cidr.split_once('/')?;
    let ip: std::net::IpAddr = ip_s.trim().parse().ok()?;
    let prefix: u8 = pfx_s.trim().parse().ok()?;
    let max = match ip {
        std::net::IpAddr::V4(_) => 32,
        std::net::IpAddr::V6(_) => 128,
    };
    if prefix == 0 || prefix > max { return None; }
    Some((ip, prefix))
}

/// Replace the set of locally-managed container/workload subnets (Docker/LXC/
/// libvirt bridges) whose IPs must never be kernel-blocked. CIDR strings come
/// from `collect_workload_subnets()`. Returns true when the set CHANGED —
/// callers use that to trigger a one-shot `sweep_protected_drop_rules()` so
/// a bridge that appears after startup (Docker starting late, a new compose
/// network) heals any stale kernel rule for its subnet.
pub fn set_protected_workload_subnets(cidrs: Vec<String>) -> bool {
    let mut parsed: Vec<(std::net::IpAddr, u8)> =
        cidrs.iter().filter_map(|c| parse_workload_cidr(c)).collect();
    parsed.sort_unstable();
    if let Ok(mut g) = protected_workload_subnets().write() {
        if *g == parsed {
            return false;
        }
        *g = parsed;
        true
    } else {
        false
    }
}

/// True if `ip` falls inside a protected workload subnet. Family-matched:
/// a v4 address only matches v4 subnets and a v6 address only v6 subnets
/// (ip_in_cidr returns false on a family mismatch).
pub fn is_protected_workload_ip(ip: std::net::IpAddr) -> bool {
    let g = match protected_workload_subnets().read() {
        Ok(g) => g,
        Err(_) => return false,
    };
    g.iter().any(|(net, prefix)| ip_in_cidr(&ip, net, *prefix))
}

/// True if `ip` (string form) is a WolfStack-managed address that must never
/// be kernel-blocked: a cluster-node IP or an address (v4 or v6) inside a
/// local container/workload bridge subnet. Single predicate shared by every
/// block path (`kernel_block_ip`, the persisted-lockout restore, the C2
/// remediation) so the guards can't drift apart.
pub fn is_protected_address(ip: &str) -> bool {
    // canonical_ip_str: a mapped ::ffff:a.b.c.d spelling of a protected v4
    // address (cluster node or container) must hit the same guard — the
    // node-IP set stores plain v4 strings and the workload match is
    // family-exact.
    let ip = crate::netaddr::canonical_ip_str(ip);
    if is_protected_node_ip(&ip) {
        return true;
    }
    matches!(
        ip.parse::<std::net::IpAddr>(),
        Ok(addr) if is_protected_workload_ip(addr)
    )
}

/// Parse one `iptables -S <chain>` / `ip6tables -S <chain>` line of the
/// EXACT shape WolfStack's `insert_drop_rule` writes — `-A <chain> -s
/// <ip>/32 -j DROP` (v6: `<ip>/128`) — and return the bare IP. Anything
/// else (extra matches, a CIDR wider than a single host, a different
/// target) returns None so the sweep can never touch a rule the operator
/// wrote by hand with comments/ports/REJECT targets.
fn parse_wolfstack_drop_rule(line: &str, chain: &str) -> Option<String> {
    // Chained strip_prefix instead of a format!() so a sweep over a
    // thousands-entry chain doesn't allocate per line.
    let rest = line
        .strip_prefix("-A ")?
        .strip_prefix(chain)?
        .strip_prefix(" -s ")?;
    let (cidr, tail) = rest.split_once(' ')?;
    if tail.trim() != "-j DROP" {
        return None;
    }
    // iptables -S echoes a plain `-s 1.2.3.4` as `1.2.3.4/32` (ip6tables:
    // `<addr>/128`); accept the bare form defensively. Only a FULL-HOST
    // prefix for the address's own family passes — anything wider is an
    // operator rule the sweep must never touch.
    let (ip_part, pfx) = match cidr.split_once('/') {
        Some((i, p)) => (i, Some(p)),
        None => (cidr, None),
    };
    let ip: std::net::IpAddr = ip_part.parse().ok()?;
    match (ip, pfx) {
        (std::net::IpAddr::V4(_), None | Some("32")) => {}
        (std::net::IpAddr::V6(_), None | Some("128")) => {}
        _ => return None,
    }
    Some(ip.to_string())
}

/// Remove stale WolfStack-shaped kernel DROP rules (`-s <ip>/32 -j DROP`,
/// v6 `/128`, in INPUT/FORWARD) whose IP is now a protected address. Heals
/// rules written by versions before the protected-address guard existed
/// (klasSponsor's compose containers, 2026-06-08): kernel rules survive a
/// WolfStack restart, so the guard alone never cleaned them up. Sweeps
/// both iptables and ip6tables — a v6-enabled container that tripped the
/// auto-block needs the same healing as a v4 one. Sync subprocess calls —
/// run from spawn_blocking or startup.
pub fn sweep_protected_drop_rules() {
    for cmd in ["iptables", "ip6tables"] {
        for chain in ["INPUT", "FORWARD"] {
            let out = match std::process::Command::new(cmd).args(["-S", chain]).output() {
                Ok(o) if o.status.success() => o,
                _ => continue, // binary missing — nothing to heal in this table
            };
            let mut healed: Vec<String> = Vec::new();
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let Some(ip) = parse_wolfstack_drop_rule(line, chain) else { continue };
                if !is_protected_address(&ip) || healed.contains(&ip) {
                    continue;
                }
                // Loop-until-gone (duplicate inserts can accumulate across old
                // versions/restarts) — same approach kernel_unblock_ip uses.
                remove_drop_rule(cmd, chain, &ip);
                healed.push(ip);
            }
            for ip in &healed {
                tracing::warn!(
                    "auth: healed stale kernel-block of {} in {} ({}) — it is a \
                     WolfStack-managed address (cluster node or local container bridge)",
                    ip, chain, cmd
                );
            }
        }
    }
    // Also heal the ipsets: a source blocked before it became protected (e.g.
    // a node that joined the cluster later) must be released there too.
    if ipset_available() {
        for set in [BLOCK_SET_V4, BLOCK_SET_V6] {
            let out = match std::process::Command::new("ipset").args(["list", set]).output() {
                Ok(o) if o.status.success() => o,
                _ => continue,
            };
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                // Member lines are bare addresses/CIDRs; the header block
                // (Name:, Type:, References:, ...) won't parse as an IP.
                let member = line.trim();
                let ip = member.split('/').next().unwrap_or(member);
                if ip.parse::<std::net::IpAddr>().is_ok() && is_protected_address(ip) {
                    let _ = std::process::Command::new("ipset")
                        .args(["del", set, member])
                        .output();
                    tracing::warn!("auth: healed protected {} from ipset {}", member, set);
                }
            }
        }
    }
}

/// ipsets holding auto-blocked sources (brute-force, scan, fleet-propagated).
/// A SINGLE `-m set --match-set` rule per chain references each, so the kernel
/// does an O(1) hash lookup per packet regardless of how many IPs are blocked.
/// The old design inserted one `-s <ip> -j DROP` rule per IP into INPUT *and
/// FORWARD*; on a router/gateway the FORWARD walk ran for every forwarded
/// packet, so a large blocklist saturated ksoftirqd and collapsed throughput
/// (PapaSchlumpf, 2026-06-17, 200→8 Mbps). hash:net so CIDR blocks work too.
const BLOCK_SET_V4: &str = "wolfstack_block4";
const BLOCK_SET_V6: &str = "wolfstack_block6";

/// `ipset` usable on this host? Cached after first lookup. When false we fall
/// back to per-IP iptables rules so blocking still works (Golden Rule: never
/// make blocking worse), just without the O(1) win.
/// What actually happened to an `ipset del`.
///
/// Every unblock surface used to discard the exit status and print
/// "✓ removed from ipset" regardless, so an operator hunting a lockout got a
/// confident success line whether or not the address had ever been in the set.
/// That is worse than no message: it rules out a suspect that was never
/// eliminated. `ipset del` exits non-zero when the entry (or the set) isn't
/// there, so the truth was always available — it just wasn't read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsetDel {
    /// The entry was there and is now gone.
    Removed,
    /// `ipset` ran and declined — the entry, or the set itself, wasn't there.
    NotPresent,
    /// No `ipset` binary on this host, so there is no set to remove from.
    NoIpset,
}

impl IpsetDel {
    /// One operator-facing report line, so the three unblock surfaces describe
    /// the same outcome the same way. A tick means something actually changed.
    pub fn describe(self, label: &str, set: &str) -> String {
        match self {
            IpsetDel::Removed => format!("  ✓ {}: removed from ipset '{}'", label, set),
            IpsetDel::NotPresent => {
                format!("  · {}: was not in ipset '{}' — nothing to remove", label, set)
            }
            IpsetDel::NoIpset => format!("  · {}: ipset not installed on this host", label),
        }
    }
}

/// Delete `ip` from `set`, reporting what actually happened.
pub fn ipset_del(set: &str, ip: &str) -> IpsetDel {
    if !ipset_available() {
        return IpsetDel::NoIpset;
    }
    match std::process::Command::new("ipset")
        .args(["del", set, ip])
        .output()
    {
        Ok(o) if o.status.success() => IpsetDel::Removed,
        _ => IpsetDel::NotPresent,
    }
}

/// What `kernel_unblock_ip` actually removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelUnblock {
    pub ipset: IpsetDel,
    /// Per-IP DROP rules deleted across INPUT + FORWARD, both rule forms.
    pub rules_removed: usize,
}

impl KernelUnblock {
    /// One report line covering both halves of a kernel block. Only claims a
    /// removal when something was removed.
    pub fn describe(&self) -> String {
        let label = "login-lockout / NMAP-protection";
        match (self.ipset, self.rules_removed) {
            (IpsetDel::Removed, 0) => {
                format!("  ✓ {}: removed from ipset (no iptables rule present)", label)
            }
            (IpsetDel::Removed, n) => format!(
                "  ✓ {}: removed from ipset and {} iptables rule(s)",
                label, n
            ),
            (_, 0) => format!("  · {}: no kernel block was in place", label),
            (_, n) => format!(
                "  ✓ {}: removed {} iptables rule(s); was not in the ipset",
                label, n
            ),
        }
    }
}

fn ipset_available() -> bool {
    use std::sync::OnceLock;
    static AVAIL: OnceLock<bool> = OnceLock::new();
    *AVAIL.get_or_init(|| {
        // `which` honours $PATH, but the systemd unit's PATH frequently omits
        // /usr/sbin where ipset lives — so also probe the standard absolute
        // locations directly, otherwise the O(1) path silently never engages
        // on exactly the router nodes that need it most.
        let via_which = std::process::Command::new("which")
            .arg("ipset")
            .output()
            .map(|o| o.status.success() && !o.stdout.is_empty())
            .unwrap_or(false);
        via_which
            || ["/usr/sbin/ipset", "/sbin/ipset", "/usr/bin/ipset", "/bin/ipset"]
                .iter()
                .any(|p| std::path::Path::new(p).exists())
    })
}

/// Ensure the `ipset` userspace tool is installed so the O(1) match-set
/// blocklist path can engage. Many Debian 13 / nftables-default hosts ship
/// WITHOUT it, so `ipset_available()` is false and WolfStack silently falls
/// back to one `-s <ip> -j DROP` rule per blocked IP. On a router that per-packet
/// FORWARD walk saturates ksoftirqd and collapses throughput — PapaSchlumpf's
/// recurring issue, confirmed 2026-06-22 (546 legacy per-IP rules, no ipset,
/// NET_RX softirqs in the tens of millions). threat_intel already auto-installs
/// ipset; the brute-force/scan blocklist did not, which is why the v24.48 O(1)
/// fix never engaged on these hosts.
///
/// Best-effort + idempotent: a no-op when ipset is already present. MUST run
/// before the first `ipset_available()` call — that result is cached for the
/// process, so installing afterwards wouldn't be picked up until a restart.
pub fn ensure_ipset_installed() {
    // Same probe `ipset_available()` uses (systemd PATH often omits /usr/sbin).
    let present = std::process::Command::new("which")
        .arg("ipset")
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
        || ["/usr/sbin/ipset", "/sbin/ipset", "/usr/bin/ipset", "/bin/ipset"]
            .iter()
            .any(|p| std::path::Path::new(p).exists());
    if present {
        return;
    }
    match crate::installer::packages::install("ipset") {
        Ok(_) => tracing::warn!(
            "auth: ipset was missing — installed it so the O(1) blocklist match-set \
             engages instead of a per-IP DROP rule walk (relieves router ksoftirqd)"
        ),
        Err(e) => tracing::warn!(
            "auth: ipset missing and auto-install failed ({}); blocklist falls back to \
             per-IP iptables rules — a large blocklist can saturate ksoftirqd on a \
             router. Install manually: apt install ipset",
            e
        ),
    }
}

/// The blocklist DROP rule for one ipset.
///
/// `--ctstate NEW` is load-bearing, not decoration. A brute-force
/// lockout is a statement about INBOUND connection attempts — "new
/// connections fail at SYN", as the design note above says. Without
/// the conntrack match the rule drops *every* packet from that
/// address, including the SYN-ACK answering a connection THIS host
/// initiated. Blocking an abusive IP then silently destroys our
/// ability to reach it, which is the opposite of what a lockout means
/// and presents as a remote outage rather than a local firewall rule.
///
/// That is not hypothetical: WolfStack locked out 116.202.127.11 on
/// 2026-07-28, and every outbound HTTPS call from a region host to
/// that address returned nothing for the next 48 hours — the SYNs
/// left fine and our own INPUT rule dropped the replies.
///
/// `predictive::threat_intel::rule_spec` has always had this match on
/// INPUT; this is the same fix applied to the auth blocklist. The two
/// modules differ deliberately elsewhere: threat-intel also carries an
/// OUTPUT rule because severing traffic TO a listed C2 address is its
/// job. A lockout has no OUTPUT rule and should not behave as if it
/// did.
fn block_rule_spec(set: &str) -> Vec<&str> {
    vec!["-m", "conntrack", "--ctstate", "NEW",
         "-m", "set", "--match-set", set, "src", "-j", "DROP"]
}

/// Pre-v25.6.0 stateless form. Kept solely so existing installs can
/// have it removed — a deployed host already has this sitting at
/// position 1 of INPUT and FORWARD, and inserting the corrected rule
/// above it changes nothing while the old one still matches.
fn legacy_block_rule_spec(set: &str) -> Vec<&str> {
    vec!["-m", "set", "--match-set", set, "src", "-j", "DROP"]
}

/// Delete every copy of the stateless pre-v25.6.0 rule from `chain`.
///
/// Bounded loop because `-D` removes one match per call: a host that
/// somehow stacked copies gets all of them cleared, and the loop can't
/// spin if the delete starts succeeding forever.
fn remove_legacy_stateless_rule(cmd: &str, chain: &str, set: &str) {
    let legacy = legacy_block_rule_spec(set);
    for _ in 0..8 {
        let removed = std::process::Command::new(cmd)
            .arg("-D").arg(chain).args(&legacy)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !removed { break; }
        tracing::warn!(
            "auth: removed legacy stateless blocklist rule from {} {} — it was \
             dropping replies to connections this host initiated",
            cmd, chain,
        );
    }
}

/// Ensure the blocklist DROP rule exists at the top of `chain` for the
/// given iptables variant, and that the legacy stateless form is gone.
/// Idempotent (`-C` then `-I`). Returns true if the rule is present (or
/// the binary is simply absent — e.g. no ip6tables, which is not fatal
/// for the other family); false only if the rule genuinely could not be
/// installed (e.g. the `set` match module is missing).
///
/// Order matters: install the corrected rule BEFORE deleting the legacy
/// one, so there is never a window in which a locked-out address is
/// unblocked.
fn ensure_match_set_rule(cmd: &str, chain: &str, set: &str) -> bool {
    let rule = block_rule_spec(set);
    let present = std::process::Command::new(cmd)
        .arg("-C").arg(chain).args(&rule)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !present {
        match std::process::Command::new(cmd)
            .arg("-I").arg(chain).arg("1").args(&rule)
            .output()
        {
            Ok(o) if o.status.success() => {}
            Err(_) => return true, // variant binary missing — don't fail the other family
            Ok(_) => return false, // present but couldn't install (xt_set missing) → fall back
        }
    }
    remove_legacy_stateless_rule(cmd, chain, set);
    true
}

/// Idempotently create the auto-block ipset for ONE family (v4 or v6) and its
/// match-set DROP rules in INPUT+FORWARD. Returns true if the ipset path is
/// usable for that family. Tracked PER FAMILY so a host missing ip6tables /
/// xt_set for v6 still gets the O(1) ipset path for v4 (and vice versa) rather
/// than collapsing all the way back to per-IP rules. The create/-C/-I work runs
/// once per family per process (gated); Relaxed ordering is fine because every
/// underlying op is idempotent (`-exist`, `-C` before `-I`), so a thread race
/// during an attack burst at most repeats harmless setup.
fn ensure_block_family(v6: bool) -> bool {
    if !ipset_available() {
        return false;
    }
    static V4_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static V6_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let gate = if v6 { &V6_READY } else { &V4_READY };
    if gate.load(std::sync::atomic::Ordering::Relaxed) {
        return true;
    }
    let (set, family, cmd) = if v6 {
        (BLOCK_SET_V6, "inet6", "ip6tables")
    } else {
        (BLOCK_SET_V4, "inet", "iptables")
    };
    let _ = std::process::Command::new("ipset")
        .args(["create", set, "hash:net", "family", family, "hashsize", "4096", "maxelem", "1048576", "-exist"])
        .output();
    let mut ok = true;
    for chain in ["INPUT", "FORWARD"] {
        if !ensure_match_set_rule(cmd, chain, set) {
            ok = false;
        }
    }
    if ok {
        gate.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    ok
}

/// One-shot startup migration: lift any legacy per-IP WolfStack DROP rules out
/// of INPUT/FORWARD into the ipset, then delete the per-IP rules. Existing
/// installs accumulated one rule per blocked IP; on a router that per-packet
/// walk saturated ksoftirqd. Running this on startup gives those hosts the
/// O(1) behaviour immediately, not just for new blocks. No-op without ipset.
/// Protected addresses are released, never migrated into the set.
pub fn migrate_legacy_block_rules() {
    let mut migrated = 0usize;
    for (cmd, set, v6) in [
        ("iptables", BLOCK_SET_V4, false),
        ("ip6tables", BLOCK_SET_V6, true),
    ] {
        // Without this family's ipset we can't migrate it — leave its per-IP
        // rules untouched so blocking still works there.
        if !ensure_block_family(v6) {
            continue;
        }
        // Collect WolfStack per-IP DROP IPs across BOTH chains, deduped, so an
        // IP blocked in INPUT *and* FORWARD (the normal prior state) is
        // migrated and counted exactly once.
        let mut ips: Vec<String> = Vec::new();
        for chain in ["INPUT", "FORWARD"] {
            let out = match std::process::Command::new(cmd).args(["-S", chain]).output() {
                Ok(o) if o.status.success() => o,
                _ => continue,
            };
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if let Some(ip) = parse_wolfstack_drop_rule(line, chain)
                    && !ips.contains(&ip) {
                        ips.push(ip);
                    }
            }
        }
        for ip in &ips {
            if !is_protected_address(ip) {
                let _ = std::process::Command::new("ipset")
                    .args(["add", set, ip, "-exist"])
                    .output();
                migrated += 1;
            }
            // Remove the per-IP rule from BOTH chains either way (protected ones
            // are healed, never migrated into the set).
            remove_drop_rule(cmd, "INPUT", ip);
            remove_drop_rule(cmd, "FORWARD", ip);
        }
    }
    if migrated > 0 {
        tracing::warn!(
            "auth: migrated {} legacy per-IP kernel-block rules into ipset (O(1) match) \
             — relieves router ksoftirqd/throughput collapse from large blocklists",
            migrated
        );
    }
}

/// Block `ip` (v4 or v6) in the kernel. Prefers the ipset-backed match (O(1)
/// per packet) and falls back to a per-IP iptables rule only where ipset is
/// unavailable. Idempotent. Silent when the tooling is missing (the HTTP-level
/// Forbidden fallback still applies).
pub fn kernel_block_ip(ip: &str) {
    // to_canonical: an IPv4-mapped form (::ffff:a.b.c.d, reported by a
    // dual-stack [::] listener) is IPv4 ON THE WIRE — it must produce an
    // iptables rule for a.b.c.d. Routing it to ip6tables would write a
    // rule no packet ever matches and the attacker stays unblocked.
    let target: std::net::IpAddr = match ip.parse::<std::net::IpAddr>() {
        Ok(a) => a.to_canonical(),
        Err(_) => {
            tracing::warn!("auth: cannot kernel-block invalid IP '{}'", ip);
            return;
        }
    };
    let canon = target.to_string();
    let ip = canon.as_str();
    // Universal guard: never DROP a WolfStack-managed address. Every block path
    // (brute-force, scan, propagated) funnels through here, so this one check
    // covers them all — cluster-node IPs AND the host's own container/workload
    // bridges, so a container that trips auth detection can't get its own traffic
    // firewalled. Record the refusal so the Security UI shows a banner / alert.
    // (klasSponsor 2026-06-08.)
    if is_protected_address(ip) {
        record_protected_block(ip);
        tracing::error!(
            "auth: REFUSED kernel-block of {} — it is a WolfStack-managed address \
             (a cluster node or a local container bridge), auto-whitelisted. A \
             security trigger tried to firewall your own infrastructure; check the \
             Security page (a compromised container should be stopped, not blocked).",
            ip
        );
        return;
    }
    let v6 = matches!(target, std::net::IpAddr::V6(_));
    // Prefer the ipset-backed block (one match-set rule per chain, O(1) per
    // packet). The match-set rules sit in BOTH INPUT and FORWARD: INPUT
    // protects the host's own services (sshd, pveproxy:8006, wolfstack:8553);
    // FORWARD protects guests behind the host's bridges/vSwitches (only
    // effective with br_netfilter + net.bridge.bridge-nf-call-iptables=1,
    // which Proxmox enables by default — inert/harmless otherwise). Neither
    // can block traffic that bypasses host netfilter (SR-IOV/PCI passthrough,
    // a separate unfirewalled NIC) — push those to an upstream ACL.
    if ensure_block_family(v6) {
        let set = if v6 { BLOCK_SET_V6 } else { BLOCK_SET_V4 };
        match std::process::Command::new("ipset")
            .args(["add", set, ip, "-exist"])
            .output()
        {
            Ok(o) if o.status.success() => {
                tracing::warn!("auth: kernel-blocked {} (ipset {})", ip, set);
            }
            Ok(o) => tracing::error!(
                "auth: ipset add {} to {} failed: {}",
                ip,
                set,
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => tracing::error!("auth: could not run ipset to block {}: {}", ip, e),
        }
        // Mirror into any macvlan/ipvlan container the host FORWARD can't reach.
        trigger_macvlan_reconcile();
        return;
    }
    // Fallback: no usable ipset — per-IP rules in INPUT + FORWARD (the old
    // O(N) path, kept so blocking still works where ipset is absent).
    let cmd = if v6 { "ip6tables" } else { "iptables" };
    insert_drop_rule(cmd, "INPUT", ip);
    insert_drop_rule(cmd, "FORWARD", ip);
    // Mirror into any macvlan/ipvlan container the host FORWARD can't reach.
    trigger_macvlan_reconcile();
}

/// Per-IP DROP spec used when ipset isn't available. Carries the same
/// `--ctstate NEW` match as the ipset rule and for the same reason: a
/// lockout must drop the attacker's new connection attempts without
/// also dropping replies to connections this host made. See
/// `block_rule_spec`.
fn per_ip_rule_spec(ip: &str) -> Vec<&str> {
    vec!["-m", "conntrack", "--ctstate", "NEW", "-s", ip, "-j", "DROP"]
}

/// Pre-v25.6.0 stateless per-IP form, for removal only.
fn legacy_per_ip_rule_spec(ip: &str) -> Vec<&str> {
    vec!["-s", ip, "-j", "DROP"]
}

/// Idempotently insert the per-IP DROP at the top of `chain` for the
/// given iptables variant, and clear any stateless copy left by an
/// older WolfStack. No-op if the correct rule already exists.
fn insert_drop_rule(cmd: &str, chain: &str, ip: &str) {
    let rule = per_ip_rule_spec(ip);
    let check = std::process::Command::new(cmd)
        .arg("-C").arg(chain).args(&rule)
        .output();
    if let Ok(out) = check
        && out.status.success() {
            // Already correct — still sweep the legacy form, which an
            // upgrade from a pre-fix build leaves sitting below it.
            remove_legacy_per_ip_rule(cmd, chain, ip);
            return;
        }
    let r = std::process::Command::new(cmd)
        .arg("-I").arg(chain).arg("1").args(&rule)
        .output();
    match r {
        Ok(o) if o.status.success() => {
            tracing::warn!("auth: kernel-blocked {} in {}/{}", ip, cmd, chain);
            remove_legacy_per_ip_rule(cmd, chain, ip);
        }
        Ok(o) => {
            tracing::error!(
                "auth: kernel-block failed for {} in {}/{}: {}",
                ip, cmd, chain, String::from_utf8_lossy(&o.stderr).trim()
            );
        }
        Err(e) => {
            tracing::error!("auth: could not run {} to block {} in {}: {}", cmd, ip, chain, e);
        }
    }
}

/// Delete every stateless pre-v25.6.0 per-IP rule for `ip` from `chain`.
/// Only called once the corrected rule is in place, so the address is
/// never briefly unblocked.
fn remove_legacy_per_ip_rule(cmd: &str, chain: &str, ip: &str) {
    let legacy = legacy_per_ip_rule_spec(ip);
    for _ in 0..10 {
        let removed = std::process::Command::new(cmd)
            .arg("-D").arg(chain).args(&legacy)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !removed { break; }
        tracing::warn!(
            "auth: removed legacy stateless DROP for {} from {} {} — it was \
             dropping replies to connections this host initiated",
            ip, cmd, chain,
        );
    }
}

/// Remove the kernel DROP rules for `ip` from both INPUT and FORWARD
/// chains. Loops per chain while the rule exists (handles duplicate
/// INSERTs that can accumulate across restarts).
pub fn kernel_unblock_ip(ip: &str) -> KernelUnblock {
    // to_canonical: must mirror kernel_block_ip so a mapped spelling
    // removes the same iptables rule the block wrote.
    let target: std::net::IpAddr = match ip.parse::<std::net::IpAddr>() {
        Ok(a) => a.to_canonical(),
        Err(_) => return KernelUnblock { ipset: IpsetDel::NotPresent, rules_removed: 0 },
    };
    let canon = target.to_string();
    let ip = canon.as_str();
    let v6 = matches!(target, std::net::IpAddr::V6(_));
    // Remove from the ipset (new path) AND any legacy per-IP rule (blocks
    // written before the ipset migration, or on hosts without ipset).
    let set = if v6 { BLOCK_SET_V6 } else { BLOCK_SET_V4 };
    let ipset = ipset_del(set, ip);
    let cmd = if v6 { "ip6tables" } else { "iptables" };
    let rules_removed =
        remove_drop_rule(cmd, "INPUT", ip) + remove_drop_rule(cmd, "FORWARD", ip);
    tracing::info!(
        "auth: kernel-unblocked {} (ipset: {:?}, {} iptables rule(s))",
        ip, ipset, rules_removed
    );
    // Lift the mirrored block from any macvlan/ipvlan container too.
    trigger_macvlan_reconcile();
    KernelUnblock { ipset, rules_removed }
}

/// Remove every per-IP DROP for `ip` from `chain` — BOTH the current
/// conntrack form and the stateless pre-v25.6.0 one.
///
/// Both forms must be swept. A host upgraded mid-lockout has the new
/// rule, one that never restarted has the old, and one blocked before
/// the upgrade and unblocked after has both. Deleting only the form
/// this build happens to write would leave the other in place and the
/// address blocked forever with nothing in the UI to explain it.
/// Returns how many rules were actually deleted, so the CLI can report a real
/// outcome instead of claiming a removal that never happened.
fn remove_drop_rule(cmd: &str, chain: &str, ip: &str) -> usize {
    let mut removed = 0usize;
    for rule in [per_ip_rule_spec(ip), legacy_per_ip_rule_spec(ip)] {
        for _ in 0..10 {
            let r = std::process::Command::new(cmd)
                .arg("-D").arg(chain).args(&rule)
                .output();
            match r {
                Ok(o) if o.status.success() => { removed += 1; continue; }
                _ => break,
            }
        }
    }
    removed
}

// ─── macvlan / ipvlan block fan-in ───────────────────────────────────────────
//
// `kernel_block_ip` writes a DROP into the host INPUT + FORWARD chains. INPUT
// protects host services; FORWARD protects guests on standard Linux/OVS bridges
// (br_netfilter feeds bridged frames through iptables). But macvlan/ipvlan
// containers — and SR-IOV/passthrough VMs — bypass the host netfilter path BY
// DESIGN, so the host FORWARD DROP never sees their packets. For containers we
// CAN reach, mirror the block INSIDE the container's own network namespace.
//
// We enter the netns with `nsenter --net` and run the HOST's iptables binary, so
// this works even on minimal images that ship no iptables (the same reason the
// WolfNet connect path uses nsenter + the host `ip`). Every rule we add carries
// the `wolfstack-ns-block` comment so the reconcile can add/remove exactly our
// rules and never touch the operator's own in-container firewall.

/// iptables comment marking a DROP rule WolfStack injected into a container's
/// network namespace, so the reconcile owns exactly its own rules.
const NS_BLOCK_TAG: &str = "wolfstack-ns-block";

static MACVLAN_RECONCILE_RUNNING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static MACVLAN_RECONCILE_PENDING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Request a macvlan/ipvlan block reconcile. Single-flight + coalescing: any
/// number of concurrent blocks (e.g. a botnet brute-force storm) collapse to AT
/// MOST ONE worker thread, which re-runs once more if more requests arrived
/// while it worked. Called from every block/unblock and from the periodic
/// safety-net loop, so a host with no such containers spends nothing beyond one
/// cheap `docker network ls` per request. Detached so it never delays the
/// security-critical host block.
pub fn trigger_macvlan_reconcile() {
    use std::sync::atomic::Ordering;
    MACVLAN_RECONCILE_PENDING.store(true, Ordering::SeqCst);
    // If a worker is already running it will observe PENDING and loop again.
    if MACVLAN_RECONCILE_RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(|| {
        loop {
            MACVLAN_RECONCILE_PENDING.store(false, Ordering::SeqCst);
            reconcile_macvlan_blocks();
            // More work arrived during the reconcile — handle it without
            // releasing ownership.
            if MACVLAN_RECONCILE_PENDING.load(Ordering::SeqCst) {
                continue;
            }
            // Tentatively release. A trigger that fired between the load above
            // and this store would have seen RUNNING still true and returned
            // without spawning, so its PENDING=true could otherwise be lost.
            MACVLAN_RECONCILE_RUNNING.store(false, Ordering::SeqCst);
            if !MACVLAN_RECONCILE_PENDING.load(Ordering::SeqCst) {
                break; // nothing pending — clean exit
            }
            // Pending work appeared in that window. Try to re-acquire; if a
            // concurrent trigger already did, it owns the work and we exit.
            if MACVLAN_RECONCILE_RUNNING.swap(true, Ordering::SeqCst) {
                break;
            }
            // Re-acquired — loop to drain the pending request.
        }
    });
}

/// Reconcile the in-namespace DROP rules of every reachable macvlan/ipvlan
/// container to match the current host block set — adds new blocks, lifts ones
/// no longer blocked, and covers containers started since the last pass.
/// Idempotent and best-effort; runs only when such a container exists.
pub fn reconcile_macvlan_blocks() {
    let targets = crate::containers::macvlan_netns_targets();
    if targets.is_empty() {
        return;
    }
    let (v4, v6) = current_block_set();
    // Nothing to enforce AND nothing tagged to clean up is the common case once
    // a block is lifted — but we still pass empty sets through so any leftover
    // tagged rule from an earlier block gets removed.
    for t in &targets {
        reconcile_one_netns(t, "iptables", &v4);
        reconcile_one_netns(t, "ip6tables", &v6);
    }
}

/// The IPs WolfStack currently blocks at the host, split by family. Source of
/// truth is the ipset (the O(1) path); falls back to the legacy per-IP INPUT
/// DROP rules where ipset is absent — mirroring `kernel_block_ip`'s two paths.
fn current_block_set() -> (Vec<String>, Vec<String>) {
    let mut v4: Vec<String> = Vec::new();
    let mut v6: Vec<String> = Vec::new();
    if ipset_available() {
        for (set, dst) in [(BLOCK_SET_V4, &mut v4), (BLOCK_SET_V6, &mut v6)] {
            let out = match std::process::Command::new("ipset").args(["list", set]).output() {
                Ok(o) if o.status.success() => o,
                _ => continue,
            };
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                // Skip the header block (Name:, Type:, …); only members parse as
                // an address/CIDR. Normalise a /32 (/128) host to its bare form
                // so it compares equal to an in-namespace `-s 1.2.3.4/32` rule.
                let m = line.trim();
                let head = m.split('/').next().unwrap_or(m);
                if head.parse::<std::net::IpAddr>().is_ok() {
                    dst.push(normalise_host_cidr(m));
                }
            }
        }
    } else {
        for (cmd, dst) in [("iptables", &mut v4), ("ip6tables", &mut v6)] {
            let out = match std::process::Command::new(cmd).args(["-S", "INPUT"]).output() {
                Ok(o) if o.status.success() => o,
                _ => continue,
            };
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if let Some(ip) = parse_wolfstack_drop_rule(line, "INPUT") {
                    dst.push(ip); // already bare-normalised
                }
            }
        }
    }
    (v4, v6)
}

/// Strip a full-host `/32` or `/128` suffix so host entries compare equal across
/// ipset's bare form and iptables' `-S` (which always echoes the prefix). Real
/// CIDR blocks (e.g. `/24`) are left intact.
fn normalise_host_cidr(addr: &str) -> String {
    match addr.split_once('/') {
        Some((ip, "32")) | Some((ip, "128")) => ip.to_string(),
        _ => addr.to_string(),
    }
}

/// Reconcile ONE container netns's WolfStack-tagged DROP rules (for one iptables
/// variant) to exactly `want`. Touches only rules carrying `NS_BLOCK_TAG`.
fn reconcile_one_netns(t: &crate::containers::NetnsTarget, cmd: &str, want: &[String]) {
    let listed = match nsenter_ipt(t.pid, cmd, &["-S", "INPUT"]) {
        Some(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        // No ip6tables in the netns, or the namespace is gone — best-effort skip.
        _ => return,
    };
    let mut have: Vec<String> = Vec::new();
    for line in listed.lines() {
        if !line.contains(NS_BLOCK_TAG) {
            continue;
        }
        if let Some(ip) = parse_ns_tagged_drop(line) {
            have.push(ip);
        }
    }

    // Lift blocks no longer in the host set (loop-until-gone for any duplicate).
    for ip in &have {
        if want.iter().any(|w| w == ip) {
            continue;
        }
        // Sweep both the conntrack form and the stateless pre-v25.6.0
        // one — see remove_drop_rule for why both must go.
        for spec in [ns_block_spec(ip), legacy_ns_block_spec(ip)] {
            for _ in 0..10 {
                let mut args = vec!["-D", "INPUT"];
                args.extend(spec.iter().copied());
                let removed = nsenter_ipt(t.pid, cmd, &args)
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if !removed {
                    break;
                }
            }
        }
        tracing::info!("auth: lifted ns-block {} in {} ({})", ip, t.label, cmd);
    }

    // Add blocks present in the host set but missing from this namespace.
    for ip in want {
        if have.iter().any(|h| h == ip) {
            continue;
        }
        let spec = ns_block_spec(ip);
        let mut check = vec!["-C", "INPUT"];
        check.extend(spec.iter().copied());
        let exists = nsenter_ipt(t.pid, cmd, &check)
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !exists {
            let mut insert = vec!["-I", "INPUT", "1"];
            insert.extend(spec.iter().copied());
            let added = nsenter_ipt(t.pid, cmd, &insert)
                .map(|o| o.status.success())
                .unwrap_or(false);
            if added {
                tracing::warn!("auth: ns-blocked {} in {} ({})", ip, t.label, cmd);
            } else {
                continue; // couldn't install — leave any legacy rule doing its job
            }
        }
        // Correct rule is in place; clear the stateless form an older
        // WolfStack left in this namespace.
        let legacy = legacy_ns_block_spec(ip);
        for _ in 0..10 {
            let mut del = vec!["-D", "INPUT"];
            del.extend(legacy.iter().copied());
            let removed = nsenter_ipt(t.pid, cmd, &del)
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !removed { break; }
            tracing::warn!(
                "auth: removed legacy stateless ns-block for {} in {} ({})",
                ip, t.label, cmd,
            );
        }
    }
}

/// Tagged DROP spec mirrored into a container netns. Carries the same
/// `--ctstate NEW` match as the host rules — see `block_rule_spec`.
/// `parse_ns_tagged_drop` locates `-s` positionally, so the extra
/// leading match doesn't disturb detection of existing rules.
fn ns_block_spec(ip: &str) -> Vec<&str> {
    vec!["-m", "conntrack", "--ctstate", "NEW",
         "-s", ip, "-m", "comment", "--comment", NS_BLOCK_TAG, "-j", "DROP"]
}

/// Pre-v25.6.0 stateless namespace form, for removal only.
fn legacy_ns_block_spec(ip: &str) -> Vec<&str> {
    vec!["-s", ip, "-m", "comment", "--comment", NS_BLOCK_TAG, "-j", "DROP"]
}

/// Run the host iptables/ip6tables binary inside container PID's network
/// namespace via `nsenter --net`. Returns the process output, or None if
/// nsenter itself couldn't be launched.
fn nsenter_ipt(pid: i32, cmd: &str, args: &[&str]) -> Option<std::process::Output> {
    let mut full: Vec<String> = vec![
        "--target".into(),
        pid.to_string(),
        "--net".into(),
        cmd.into(),
    ];
    full.extend(args.iter().map(|s| s.to_string()));
    std::process::Command::new("nsenter").args(&full).output().ok()
}

/// Pull the source IP out of one of our tagged DROP lines, e.g.
/// `-A INPUT -s 1.2.3.4/32 -m comment --comment wolfstack-ns-block -j DROP`,
/// normalised to bare host form so it compares to `current_block_set`.
fn parse_ns_tagged_drop(line: &str) -> Option<String> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    let pos = toks.iter().position(|t| *t == "-s")?;
    let raw = toks.get(pos + 1)?;
    Some(normalise_host_cidr(raw))
}

impl LoginRateLimiter {
    /// Snapshot of currently-locked entries → persistence file. Called
    /// on every state change so reloads are consistent.
    fn persist_lockouts(&self) {
        let now = Instant::now();
        let now_unix = now_secs();
        let attempts = self.attempts.read().unwrap();
        let mut snapshot: Vec<PersistedLockout> = Vec::new();
        let cfg = self.config.read().unwrap().clone();
        for (ip, rec) in attempts.iter() {
            if let Some(until) = rec.locked_until
                && until > now {
                    let remaining = until.duration_since(now).as_secs();
                    // The lockout total isn't stored on the record (we
                    // only have an Instant); approximate from the config.
                    // This is good enough for cross-restart restoration.
                    let total = cfg.lockout_seconds;
                    snapshot.push(PersistedLockout {
                        ip: ip.clone(),
                        locked_at: now_unix.saturating_sub(total.saturating_sub(remaining)),
                        lockout_seconds: total,
                    });
                }
        }
        if let Ok(json) = serde_json::to_string_pretty(&snapshot) {
            let _ = crate::paths::write_secure(&lockouts_file(), &json);
        }
    }

    /// Restore kernel-block state from disk on startup. Call once after
    /// `LoginRateLimiter::new()`. For each non-expired entry: re-apply
    /// the iptables DROP rule and re-register the record in memory.
    /// Expired entries are dropped silently (caller-removed rules are
    /// fine — kernel_unblock is idempotent if they were never set).
    pub fn restore_persisted_lockouts(&self) {
        let json = match std::fs::read_to_string(lockouts_file()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let snapshot: Vec<PersistedLockout> = match serde_json::from_str(&json) {
            Ok(s) => s,
            Err(_) => return,
        };
        let now = now_secs();
        let cfg = self.config.read().unwrap().clone();
        for entry in snapshot {
            if cfg.is_trusted(&entry.ip) { continue; }
            let expires_at_unix = entry.locked_at.saturating_add(entry.lockout_seconds);
            if expires_at_unix <= now {
                // Already expired — nuke any leftover kernel rule.
                kernel_unblock_ip(&entry.ip);
                continue;
            }
            let remaining = expires_at_unix - now;
            if is_protected_address(&entry.ip) {
                // WolfStack-managed address (cluster node / local container
                // bridge). Keep the HTTP-level lockout below — a container
                // that brute-forced auth stays locked out of the API — but
                // never re-apply the kernel rule, and heal any leftover one
                // written by a version that predates the guard. Without this,
                // restore raced the 10s protection task in main.rs and
                // re-firewalled container IPs on every restart (klasSponsor
                // round 3, 2026-06-10).
                kernel_unblock_ip(&entry.ip);
                tracing::warn!(
                    "auth: restored HTTP-level lockout for {} ({}s remaining) and \
                     healed its kernel rule — WolfStack-managed address (cluster \
                     node or local container bridge), never kernel-blocked",
                    entry.ip, remaining
                );
            } else {
                kernel_block_ip(&entry.ip);
                tracing::warn!(
                    "auth: restored kernel-block for {} ({}s remaining)",
                    entry.ip, remaining
                );
            }
            let mut attempts = self.attempts.write().unwrap();
            let rec = attempts.entry(entry.ip.clone()).or_default();
            rec.locked_until = Some(Instant::now() + Duration::from_secs(remaining));
        }
    }
}

// ─── Password Reset Tokens ───

/// In-memory storage for password reset tokens (30-minute expiry)
pub struct PasswordResetTokens {
    tokens: RwLock<HashMap<String, ResetToken>>,
}

struct ResetToken {
    username: String,
    created: Instant,
}

const RESET_TOKEN_LIFETIME: Duration = Duration::from_secs(30 * 60); // 30 minutes

impl PasswordResetTokens {
    pub fn new() -> Self {
        Self { tokens: RwLock::new(HashMap::new()) }
    }

    /// Create a reset token for a user. Returns the token string.
    pub fn create(&self, username: &str) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        let mut tokens = self.tokens.write().unwrap();
        // Remove any existing tokens for this user
        tokens.retain(|_, t| t.username != username);
        tokens.insert(token.clone(), ResetToken {
            username: username.to_string(),
            created: Instant::now(),
        });
        token
    }

    /// Validate and consume a reset token. Returns the username if valid.
    pub fn validate_and_consume(&self, token: &str) -> Option<String> {
        let mut tokens = self.tokens.write().unwrap();
        if let Some(rt) = tokens.remove(token)
            && rt.created.elapsed() < RESET_TOKEN_LIFETIME {
                return Some(rt.username);
            }
        None
    }

    /// Clean up expired tokens
    pub fn cleanup(&self) {
        let mut tokens = self.tokens.write().unwrap();
        tokens.retain(|_, t| t.created.elapsed() < RESET_TOKEN_LIFETIME);
    }

    /// Drop any outstanding tokens for a user. Called when the user's
    /// email or password is changed by an operator — a code that went
    /// to the OLD address must not stay redeemable for its remaining
    /// lifetime.
    pub fn invalidate_user(&self, username: &str) {
        let mut tokens = self.tokens.write().unwrap();
        tokens.retain(|_, t| t.username != username);
    }
}

/// Validate a container/VM name — only allow safe characters (alphanumeric, dash, underscore, dot)
pub fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !name.contains("..")
}

#[cfg(test)]
mod secret_tests {
    use super::*;

    #[test]
    fn equal_content_equal_length_is_true() {
        assert!(validate_cluster_secret("wsk_abc123", "wsk_abc123"));
        assert!(validate_cluster_secret("x", "x"));
    }

    /// Stage 5 regression test: validate_inter_node_secret MUST accept
    /// the in-memory secret regardless of env-flag state. Pre-fix, the
    /// chain in `require_auth` was inlined at 7+ call sites; any future
    /// change must keep the in-memory path always-on. This test does
    /// NOT touch env vars (set_var is racy with parallel tests in
    /// edition 2024 — marked unsafe) — just exercises the trivial
    /// in-memory match.
    #[test]
    fn inter_node_accepts_in_memory_unconditionally() {
        assert!(validate_inter_node_secret_from(
            "wsk_in_mem_value_for_test", "wsk_in_mem_value_for_test", None));
    }

    /// Stage 5 regression test: the OR-chain in
    /// validate_inter_node_secret must reject an obviously-wrong value
    /// regardless of any env state. Sanity check that the helper isn't
    /// degenerate to "always true".
    #[test]
    fn inter_node_rejects_obviously_wrong_value() {
        assert!(!validate_inter_node_secret_from("not_a_real_secret_at_all_xyz",
                                                 "wsk_in_mem_value_for_test", None));
    }

    /// Security regression (CVE pending, reported 2026-08-01 by
    /// Dostxodjayev Abdullox): the built-in default must NEVER be
    /// accepted without a transport peer address. This assertion
    /// replaces the old `default_secret_acceptance_defaults_to_true`,
    /// which encoded exactly the posture that made every un-migrated,
    /// network-reachable node an unauthenticated-RCE bypass.
    ///
    /// Skipped when the operator escape hatch is set in the runner's
    /// environment — that flag legitimately forces acceptance.
    #[test]
    fn default_secret_rejected_without_peer_address() {
        if std::env::var("WOLFSTACK_ACCEPT_DEFAULT_SECRET").is_ok() { return; }
        assert!(!default_secret_accepted(),
                "the built-in default must be rejected when no peer address \
                 is available — fail closed");
        assert!(!default_secret_accepted_from(None),
                "explicit None peer must also be rejected");
    }

    /// An address that is not a recorded peer must never authenticate
    /// with the published constant. 203.0.113.0/24 is TEST-NET-3
    /// (RFC 5737) and cannot be a real peer.
    #[test]
    fn default_secret_rejected_from_unrecorded_peer() {
        if std::env::var("WOLFSTACK_ACCEPT_DEFAULT_SECRET").is_ok() { return; }
        let stranger: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        assert!(!default_secret_accepted_from(Some(stranger)),
                "an unrecorded source address must not be able to present \
                 the built-in default secret");
    }

    /// The end-to-end shape of the reported vulnerability: the exact
    /// published constant, presented by a stranger, against a node
    /// whose in-memory secret is something else, must NOT authenticate.
    #[test]
    fn published_constant_does_not_authenticate_a_stranger() {
        if std::env::var("WOLFSTACK_ACCEPT_DEFAULT_SECRET").is_ok() { return; }
        let stranger: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        assert!(!validate_inter_node_secret_from(
                    default_cluster_secret(), "wsk_some_other_in_memory_secret",
                    Some(stranger)),
                "PoC regression: the constant from src/auth/mod.rs must not \
                 grant inter-node auth from an unrecorded address");
        // Explicit "no peer information" must fail closed too.
        assert!(!validate_inter_node_secret_from(
                    default_cluster_secret(), "wsk_some_other_in_memory_secret", None),
                "a request with no resolvable peer must fail closed on the default");
    }

    /// The real credential still works — the fix must not break a
    /// legitimate peer presenting the node's actual secret.
    #[test]
    fn genuine_secret_still_authenticates_regardless_of_peer() {
        let real = "wsk_a_genuine_per_install_secret_value_for_test";
        assert!(validate_inter_node_secret_from(real, real, None));
        let stranger: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        assert!(validate_inter_node_secret_from(real, real, Some(stranger)));
    }

    /// A peer arriving over a dual-stack listener shows up as an
    /// IPv4-mapped IPv6 address; it must compare equal to the IPv4
    /// form recorded in nodes.json.
    #[test]
    fn ipv4_mapped_ipv6_is_canonicalised() {
        let mapped: std::net::IpAddr = "::ffff:192.0.2.10".parse().unwrap();
        let plain: std::net::IpAddr = "192.0.2.10".parse().unwrap();
        assert_eq!(canonical_ip(mapped), plain);
        // A genuine v6 address is left alone.
        let v6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(canonical_ip(v6), v6);
    }

    #[test]
    fn equal_length_different_content_is_false() {
        assert!(!validate_cluster_secret("wsk_abc123", "wsk_xyz999"));
        assert!(!validate_cluster_secret("aaaaa", "aaaab"));  // one byte off
    }

    #[test]
    fn different_length_is_false() {
        // The bug this test prevents: pre-v18.7.30 the function did an
        // early return on length mismatch, leaking expected length via
        // timing. Now len-mismatch is folded into the accumulator
        // alongside content bytes — still returns false, still const
        // time relative to the longer input.
        assert!(!validate_cluster_secret("short", "muchlongersecret"));
        assert!(!validate_cluster_secret("longerthanexpected", "short"));
        assert!(!validate_cluster_secret("a", "ab"));
        assert!(!validate_cluster_secret("", ""));  // both empty — explicit early exit
    }

    #[test]
    fn empty_inputs_rejected() {
        assert!(!validate_cluster_secret("", "real_secret"));
        assert!(!validate_cluster_secret("real_secret", ""));
    }

    #[test]
    fn long_secret_equality() {
        let s = "wsk_".to_string() + &"a".repeat(64);
        assert!(validate_cluster_secret(&s, &s));
        let mut tampered = s.clone();
        tampered.pop();
        tampered.push('b');  // flip last byte
        assert!(!validate_cluster_secret(&s, &tampered));
    }
}

#[cfg(test)]
mod sticky_peer_tests {
    use super::*;

    #[test]
    fn protectable_ip_filter_rejects_dangerous_addresses() {
        assert!(valid_protectable_ip("10.10.10.10"));
        assert!(valid_protectable_ip("2001:db8::1"));
        assert!(!valid_protectable_ip("0.0.0.0"), "unspecified must never be whitelisted");
        assert!(!valid_protectable_ip("::"), "unspecified v6 must never be whitelisted");
        assert!(!valid_protectable_ip("127.0.0.1"), "loopback never needs protection");
        assert!(!valid_protectable_ip("not-an-ip"));
        assert!(!valid_protectable_ip(""));
    }

    #[test]
    fn evict_oldest_peers_caps_and_keeps_newest() {
        let mut map = std::collections::BTreeMap::new();
        for i in 0..(KNOWN_PEER_IPS_MAX as u64 + 10) {
            map.insert(format!("10.0.{}.{}", i / 256, i % 256), 1000 + i);
        }
        evict_oldest_peers(&mut map);
        assert_eq!(map.len(), KNOWN_PEER_IPS_MAX);
        // The oldest 10 stamps (1000..1009) must be the ones evicted.
        assert!(map.values().all(|ts| *ts >= 1010));
    }
}

#[cfg(test)]
mod lockout_tests {
    use super::*;

    fn make_limiter(cfg: LoginLockoutConfig) -> LoginRateLimiter {
        let l = LoginRateLimiter::new();
        *l.config.write().unwrap() = cfg;
        l
    }

    fn locked(ip: &str) -> PersistedLockout {
        PersistedLockout { ip: ip.into(), locked_at: 1_000, lockout_seconds: 48 * 3600 }
    }

    #[test]
    fn only_a_real_removal_gets_a_tick() {
        // The whole point: an operator scanning this output for what actually
        // changed must be able to trust the tick. Previously every line got
        // one, so a set the address was never in looked like a cleared block.
        assert!(IpsetDel::Removed.describe("blocklist", "s").contains('✓'));
        assert!(!IpsetDel::NotPresent.describe("blocklist", "s").contains('✓'));
        assert!(!IpsetDel::NoIpset.describe("blocklist", "s").contains('✓'));
    }

    #[test]
    fn a_no_op_does_not_claim_a_removal() {
        let msg = IpsetDel::NotPresent.describe("blocklist", "wolfstack_blocklist");
        assert!(msg.contains("was not in"), "{}", msg);
        assert!(!msg.contains("removed from"), "{}", msg);
    }

    #[test]
    fn missing_ipset_says_so_rather_than_blaming_the_entry() {
        // "not in the set" would be misleading when there is no set at all.
        let msg = IpsetDel::NoIpset.describe("blocklist", "wolfstack_blocklist");
        assert!(msg.contains("ipset not installed"), "{}", msg);
    }

    #[test]
    fn kernel_unblock_describes_each_combination_honestly() {
        let both = KernelUnblock { ipset: IpsetDel::Removed, rules_removed: 2 };
        assert!(both.describe().contains('✓'));
        assert!(both.describe().contains("2 iptables rule(s)"), "{}", both.describe());

        let set_only = KernelUnblock { ipset: IpsetDel::Removed, rules_removed: 0 };
        assert!(set_only.describe().contains("no iptables rule present"));

        let rules_only = KernelUnblock { ipset: IpsetDel::NotPresent, rules_removed: 1 };
        assert!(rules_only.describe().contains("was not in the ipset"));
        assert!(rules_only.describe().contains('✓'), "a real rule removal is still a change");

        // Nothing there at all — the case that used to print a confident tick.
        let nothing = KernelUnblock { ipset: IpsetDel::NotPresent, rules_removed: 0 };
        assert!(!nothing.describe().contains('✓'), "{}", nothing.describe());
        assert!(nothing.describe().contains("no kernel block was in place"));
    }

    #[test]
    fn prune_removes_the_named_ip() {
        // The unblock case: the entry must go, or restore_persisted_lockouts
        // re-applies both the kernel rule and the in-memory lockout on the
        // next service start and undoes the operator's recovery.
        let snap = vec![locked("192.168.68.50"), locked("203.0.113.9")];
        let kept = prune_lockout_snapshot(snap, "192.168.68.50").expect("should change");
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].ip, "203.0.113.9");
    }

    #[test]
    fn prune_matches_an_ipv4_mapped_entry() {
        // A dual-stack [::] listener reports v4 clients as ::ffff:a.b.c.d, and
        // an older build could have persisted that spelling. Raw string
        // matching would miss it and leave the block to be restored.
        let snap = vec![locked("::ffff:192.168.68.50")];
        let kept = prune_lockout_snapshot(snap, "192.168.68.50").expect("should change");
        assert!(kept.is_empty());
    }

    #[test]
    fn prune_reports_no_change_when_the_ip_is_absent() {
        // Caller skips the rewrite and stays quiet — no file churn, and no
        // "removed" line for something that was never there.
        let snap = vec![locked("203.0.113.9")];
        assert!(prune_lockout_snapshot(snap, "192.168.68.50").is_none());
    }

    #[test]
    fn prune_leaves_an_unparseable_entry_alone() {
        // Garbage in the snapshot must not be silently swallowed by the
        // canonicalisation fallback, nor block pruning of valid neighbours.
        let snap = vec![locked("not-an-ip"), locked("192.168.68.50")];
        let kept = prune_lockout_snapshot(snap, "192.168.68.50").expect("should change");
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].ip, "not-an-ip");
    }

    #[test]
    fn default_threshold_is_three() {
        // v23.12.13 lowered the default to 3 so brute-force attempts
        // get blocked after a handful of tries instead of waiting for
        // 10 failures. Lock this in so a future config-edit doesn't
        // silently relax the default back.
        let cfg = LoginLockoutConfig::default();
        assert_eq!(cfg.max_failures, 3);
        assert_eq!(cfg.window_seconds, 300);
        assert_eq!(cfg.lockout_seconds, 48 * 3600);
        assert!(cfg.enabled);
    }

    #[test]
    fn lockout_triggers_after_threshold() {
        let cfg = LoginLockoutConfig {
            max_failures: 3, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec![], enabled: true,
        };
        let l = make_limiter(cfg);
        assert!(!l.is_locked_out("1.2.3.4"));
        assert!(!l.record_failure_with("1.2.3.4", "u"));
        assert!(!l.record_failure_with("1.2.3.4", "u"));
        // Third failure is the threshold — should trigger.
        assert!(l.record_failure_with("1.2.3.4", "u"), "third failure must trigger lockout");
        assert!(l.is_locked_out("1.2.3.4"));
        // Subsequent failures don't re-trigger (already locked).
        assert!(!l.record_failure_with("1.2.3.4", "u"));
        assert!(l.is_locked_out("1.2.3.4"));
    }

    #[test]
    fn trusted_single_ip_never_locks_out() {
        let cfg = LoginLockoutConfig {
            max_failures: 2, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec!["10.0.0.5".into()], enabled: true,
        };
        let l = make_limiter(cfg);
        for _ in 0..50 {
            assert!(!l.record_failure_with("10.0.0.5", "u"),
                "trusted IP must never trigger lockout");
        }
        assert!(!l.is_locked_out("10.0.0.5"));
    }

    #[test]
    fn trusted_cidr_v4_never_locks_out() {
        let cfg = LoginLockoutConfig {
            max_failures: 2, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec!["10.0.0.0/8".into()], enabled: true,
        };
        let l = make_limiter(cfg);
        for ip in ["10.1.2.3", "10.255.255.255", "10.0.0.1"] {
            for _ in 0..10 { l.record_failure_with(ip, "u"); }
            assert!(!l.is_locked_out(ip), "IP {} in trusted CIDR must not lock", ip);
        }
        // An IP outside the CIDR DOES lock.
        for _ in 0..2 { l.record_failure_with("11.0.0.1", "u"); }
        assert!(l.is_locked_out("11.0.0.1"));
    }

    #[test]
    fn trusted_cidr_v6_never_locks_out() {
        let cfg = LoginLockoutConfig {
            max_failures: 2, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec!["2a01:4f8:151:7225::/64".into()], enabled: true,
        };
        let l = make_limiter(cfg);
        for _ in 0..10 { l.record_failure_with("2a01:4f8:151:7225::5", "u"); }
        assert!(!l.is_locked_out("2a01:4f8:151:7225::5"));
        // Different /64 → not trusted → does lock.
        for _ in 0..2 { l.record_failure_with("2a01:4f8:151:7226::5", "u"); }
        assert!(l.is_locked_out("2a01:4f8:151:7226::5"));
    }

    #[test]
    fn disabled_config_skips_lockout_entirely() {
        let cfg = LoginLockoutConfig {
            max_failures: 1, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec![], enabled: false,
        };
        let l = make_limiter(cfg);
        for _ in 0..50 { l.record_failure_with("9.9.9.9", "u"); }
        assert!(!l.is_locked_out("9.9.9.9"), "disabled config must never lock");
    }

    #[test]
    fn unblock_clears_lockout() {
        let cfg = LoginLockoutConfig {
            max_failures: 1, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec![], enabled: true,
        };
        let l = make_limiter(cfg);
        l.record_failure_with("8.8.8.8", "u");
        assert!(l.is_locked_out("8.8.8.8"));
        l.unblock("8.8.8.8");
        assert!(!l.is_locked_out("8.8.8.8"));
    }

    #[test]
    fn audit_log_capped_at_500() {
        let cfg = LoginLockoutConfig::default();
        let l = make_limiter(cfg);
        // Force-feed 600 audit rows via clear_with (success path —
        // doesn't trigger lockout).
        for i in 0..600 {
            l.clear_with(&format!("1.2.3.{}", i % 250), "test");
        }
        let log = l.audit_log();
        assert!(log.len() <= 500, "audit log capped at 500, got {}", log.len());
    }

    #[test]
    fn block_hook_fires_on_threshold() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let calls_h = calls.clone();
        let cfg = LoginLockoutConfig {
            max_failures: 2, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec![], enabled: true,
        };
        let l = make_limiter(cfg);
        l.install_propagation_hooks(
            std::sync::Arc::new(move |_ip, _secs| { calls_h.fetch_add(1, Ordering::SeqCst); }),
            std::sync::Arc::new(|_ip| {}),
        );
        l.record_failure_with("7.7.7.7", "u");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "hook must not fire before threshold");
        l.record_failure_with("7.7.7.7", "u");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "hook fires exactly once at threshold");
        l.record_failure_with("7.7.7.7", "u");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "hook does not re-fire on subsequent failures");
    }

    #[test]
    fn force_lockout_blocks_on_first_hit() {
        // No threshold accumulation — one hit is enough.
        let cfg = LoginLockoutConfig {
            max_failures: 3, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec![], enabled: true,
        };
        let l = make_limiter(cfg);
        let locked = l.force_lockout("6.6.6.6", "auto", "ctx");
        assert!(locked, "force_lockout must return true on first hit");
        assert!(l.is_locked_out("6.6.6.6"));
    }

    #[test]
    fn force_lockout_respects_trusted_ips() {
        let cfg = LoginLockoutConfig {
            max_failures: 3, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec!["10.0.0.0/8".into()],
            enabled: true,
        };
        let l = make_limiter(cfg);
        let locked = l.force_lockout("10.5.5.5", "auto", "ctx");
        assert!(!locked, "trusted IPs must not be force-locked");
        assert!(!l.is_locked_out("10.5.5.5"));
    }

    #[test]
    fn force_lockout_idempotent_when_already_locked() {
        let cfg = LoginLockoutConfig {
            max_failures: 3, window_seconds: 60, lockout_seconds: 60,
            trusted_ips: vec![], enabled: true,
        };
        let l = make_limiter(cfg);
        assert!(l.force_lockout("5.5.5.5", "auto", "first"));
        assert!(!l.force_lockout("5.5.5.5", "auto", "second"),
            "second force_lockout while still locked must return false");
    }
}

#[cfg(test)]
mod protected_node_tests {
    use super::*;

    // These touch process-global statics, but no other test exercises them, so
    // the sequences below are deterministic within the test binary.

    #[test]
    fn protected_ip_set_filters_diffs_and_sticks() {
        // Point config at a writable temp dir so the sticky known-peer
        // store is exercised for real: the live default /etc/wolfstack is
        // root-owned on dev boxes, which would silently disable stickiness
        // and let the pre-sticky expectations pass by accident (and, run
        // as root, the test would write to the LIVE store).
        let root = std::env::temp_dir().join(format!("wspt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root); // stale store from a prior run
        std::fs::create_dir_all(&root).unwrap();
        let mut locs = crate::paths::get();
        locs.config_dir = root.to_string_lossy().to_string();
        crate::paths::set_for_test(locs);

        // Valid IPs are kept; loopback / unspecified / garbage are dropped —
        // protecting those would whitelist far too much.
        let newly = set_protected_node_ips(vec![
            "10.0.0.1".into(),
            "127.0.0.1".into(),   // loopback
            "0.0.0.0".into(),     // unspecified
            "not-an-ip".into(),   // garbage
            "192.168.1.5".into(),
        ]);
        assert!(is_protected_node_ip("10.0.0.1"));
        assert!(is_protected_node_ip("192.168.1.5"));
        assert!(!is_protected_node_ip("127.0.0.1"), "loopback must never be protected");
        assert!(!is_protected_node_ip("0.0.0.0"), "unspecified must never be protected");
        assert!(!is_protected_node_ip("8.8.8.8"));
        // First set → both valid IPs are newly protected (drives the one-shot heal).
        assert!(newly.contains(&"10.0.0.1".to_string()));
        assert!(newly.contains(&"192.168.1.5".to_string()));
        assert_eq!(newly.len(), 2);

        // Re-asserting the same set reports nothing new (no repeat heal churn).
        assert!(set_protected_node_ips(vec!["10.0.0.1".into(), "192.168.1.5".into()]).is_empty());

        // STICKY: dropping an IP from live membership must KEEP it
        // protected — a node falling out of its cluster must not expose
        // its manager to auto-bans during re-add (klasSponsor 2026-07-16).
        let _ = set_protected_node_ips(vec!["10.0.0.1".into()]);
        assert!(is_protected_node_ip("10.0.0.1"));
        assert!(is_protected_node_ip("192.168.1.5"),
                "ex-peer must STAY protected via the sticky 30-day store");

        // A verified join-handshake source is protected immediately and
        // survives subsequent membership ticks that don't list it.
        record_known_peer_ip("172.16.0.9");
        assert!(is_protected_node_ip("172.16.0.9"));
        let _ = set_protected_node_ips(vec!["10.0.0.1".into()]);
        assert!(is_protected_node_ip("172.16.0.9"),
                "handshake-recorded manager must survive the sync tick");

        // Operator forget lifts stickiness for a NON-member…
        forget_known_peer_ip("192.168.1.5");
        let _ = set_protected_node_ips(vec!["10.0.0.1".into()]);
        assert!(!is_protected_node_ip("192.168.1.5"),
                "operator forget must make an ex-peer blockable");
        // …but a LIVE member is re-protected on the next sync tick.
        forget_known_peer_ip("10.0.0.1");
        let _ = set_protected_node_ips(vec!["10.0.0.1".into()]);
        assert!(is_protected_node_ip("10.0.0.1"),
                "a live cluster member must always be re-protected");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protected_block_events_record_and_coalesce() {
        record_protected_block("10.9.9.1");
        record_protected_block("10.9.9.2");
        let ev = recent_protected_block_events();
        assert!(ev.iter().any(|e| e.ip == "10.9.9.1"));
        assert!(ev.iter().any(|e| e.ip == "10.9.9.2"));
        // Event ids are monotonic.
        let ids: Vec<u64> = ev.iter().map(|e| e.id).collect();
        for w in ids.windows(2) { assert!(w[1] > w[0], "event ids must be monotonic"); }
        // A rapid repeat of the most-recent IP coalesces — no new ring entry.
        let before = recent_protected_block_events().len();
        record_protected_block("10.9.9.2");
        assert_eq!(before, recent_protected_block_events().len(),
            "a rapid repeat of the same IP must coalesce, not append");
    }

    #[test]
    fn workload_subnet_protection_matches_only_container_ranges() {
        // CIDRs exactly as collect_workload_subnets() returns them.
        set_protected_workload_subnets(vec![
            "172.17.0.0/16".into(),       // docker0
            "10.0.3.0/24".into(),         // lxcbr0
            "fd00:dead:beef::/48".into(), // docker0 fixed-cidr-v6 ULA
            "garbage".into(),             // dropped (unparseable)
            "0.0.0.0/0".into(),           // dropped — must NEVER whitelist the whole internet
            "::/0".into(),                // dropped — v6 spelling of the same trap
        ]);
        // Container IPs inside the bridges are protected.
        assert!(is_protected_workload_ip("172.17.0.5".parse().unwrap()));
        assert!(is_protected_workload_ip("172.17.255.254".parse().unwrap()));
        assert!(is_protected_workload_ip("10.0.3.42".parse().unwrap()));
        assert!(is_protected_workload_ip("fd00:dead:beef::42".parse().unwrap()));
        // Everything outside is NOT — including the adjacent /24, an unrelated
        // LAN, and any public IP (the /0s were dropped, so these must be false).
        assert!(!is_protected_workload_ip("10.0.4.1".parse().unwrap()));
        assert!(!is_protected_workload_ip("192.168.1.1".parse().unwrap()));
        assert!(!is_protected_workload_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_protected_workload_ip("fd00:dead:beee::1".parse().unwrap())); // adjacent /48
        assert!(!is_protected_workload_ip("2001:db8::1".parse().unwrap()));       // public v6
        // Family-matched: a v4 address must never match a v6 subnet's range
        // representation or vice versa.
        assert!(is_protected_address("fd00:dead:beef::7"));
        assert!(!is_protected_address("2606:4700::1111"));
        // The mapped spelling of a protected v4 container IP hits the same
        // guard — dual-stack [::] listeners report v4 peers as ::ffff:….
        assert!(is_protected_address("::ffff:172.17.0.5"));
        assert!(!is_protected_address("::ffff:8.8.8.8"));
        // ── Change reporting (same test fn — the global is shared, and a
        // second parallel #[test] mutating it would race this one) ──
        // Reset, then: first real population is a change.
        set_protected_workload_subnets(vec![]);
        assert!(set_protected_workload_subnets(vec!["172.30.0.0/16".into()]));
        // Same content again — no change, no sweep trigger.
        assert!(!set_protected_workload_subnets(vec!["172.30.0.0/16".into()]));
        // Order must not matter: the set is sorted before comparison, so the
        // 10s loop can't spuriously re-sweep when `ip -j addr` reorders.
        assert!(set_protected_workload_subnets(vec![
            "172.30.0.0/16".into(), "10.0.9.0/24".into(),
        ]));
        assert!(!set_protected_workload_subnets(vec![
            "10.0.9.0/24".into(), "172.30.0.0/16".into(),
        ]));
        // A bridge disappearing is also a change.
        assert!(set_protected_workload_subnets(vec!["10.0.9.0/24".into()]));
        set_protected_workload_subnets(vec![]);
    }

    #[test]
    fn drop_rule_parser_matches_only_wolfstack_shape() {
        // The exact shape insert_drop_rule writes, as iptables -S echoes it.
        assert_eq!(
            parse_wolfstack_drop_rule("-A INPUT -s 172.18.0.5/32 -j DROP", "INPUT"),
            Some("172.18.0.5".to_string())
        );
        assert_eq!(
            parse_wolfstack_drop_rule("-A FORWARD -s 10.0.3.7/32 -j DROP", "FORWARD"),
            Some("10.0.3.7".to_string())
        );
        // Bare-IP form (no /32) — accepted defensively.
        assert_eq!(
            parse_wolfstack_drop_rule("-A INPUT -s 172.18.0.5 -j DROP", "INPUT"),
            Some("172.18.0.5".to_string())
        );
        // Wrong chain prefix.
        assert_eq!(parse_wolfstack_drop_rule("-A INPUT -s 172.18.0.5/32 -j DROP", "FORWARD"), None);
        // Operator-written rules the sweep must never touch: wider CIDRs,
        // extra matches, different targets.
        assert_eq!(parse_wolfstack_drop_rule("-A INPUT -s 10.0.0.0/8 -j DROP", "INPUT"), None);
        assert_eq!(
            parse_wolfstack_drop_rule(
                "-A INPUT -s 172.18.0.5/32 -p tcp --dport 22 -j DROP", "INPUT"
            ),
            None
        );
        assert_eq!(
            parse_wolfstack_drop_rule(
                "-A INPUT -s 172.18.0.5/32 -m comment --comment mine -j DROP", "INPUT"
            ),
            None
        );
        assert_eq!(parse_wolfstack_drop_rule("-A INPUT -s 172.18.0.5/32 -j REJECT", "INPUT"), None);
        // Non -s rules and chain policy lines.
        assert_eq!(parse_wolfstack_drop_rule("-P INPUT ACCEPT", "INPUT"), None);
        assert_eq!(parse_wolfstack_drop_rule("-A INPUT -d 172.18.0.5/32 -j DROP", "INPUT"), None);
        // IPv6 — the shape ip6tables -S echoes for insert_drop_rule's output.
        assert_eq!(
            parse_wolfstack_drop_rule("-A INPUT -s fd00::1/128 -j DROP", "INPUT"),
            Some("fd00::1".to_string())
        );
        assert_eq!(
            parse_wolfstack_drop_rule("-A FORWARD -s 2001:db8::5 -j DROP", "FORWARD"),
            Some("2001:db8::5".to_string())
        );
        // Cross-family prefixes and wider v6 CIDRs are operator rules.
        assert_eq!(parse_wolfstack_drop_rule("-A INPUT -s fd00::1/32 -j DROP", "INPUT"), None);
        assert_eq!(parse_wolfstack_drop_rule("-A INPUT -s fd00::/64 -j DROP", "INPUT"), None);
        assert_eq!(parse_wolfstack_drop_rule("-A INPUT -s 172.18.0.5/128 -j DROP", "INPUT"), None);
    }

    #[test]
    fn normalise_host_cidr_strips_only_full_host() {
        // /32 (v4) and /128 (v6) collapse to bare so ipset's bare form and
        // iptables' echoed prefix compare equal.
        assert_eq!(normalise_host_cidr("1.2.3.4/32"), "1.2.3.4");
        assert_eq!(normalise_host_cidr("fd00::1/128"), "fd00::1");
        assert_eq!(normalise_host_cidr("1.2.3.4"), "1.2.3.4");
        // Real CIDR blocks are preserved verbatim.
        assert_eq!(normalise_host_cidr("10.0.0.0/24"), "10.0.0.0/24");
        assert_eq!(normalise_host_cidr("fd00::/64"), "fd00::/64");
    }

    // ── Blocklist rule shape ─────────────────────────────────────
    //
    // A lockout must drop the attacker's NEW connections without
    // dropping replies to connections THIS host made. Before v25.6.0
    // every one of these rules was stateless, so locking out an
    // address also severed our outbound path to it — WolfStack blocked
    // 116.202.127.11 on 2026-07-28 and every outbound HTTPS call to it
    // silently returned nothing for 48 hours.

    /// Every rule form must carry the conntrack match, or the bug is
    /// back on whichever path lacks it. Checked as a set so a new
    /// blocking path can't be added without it.
    #[test]
    fn every_current_block_form_matches_new_connections_only() {
        for spec in [
            block_rule_spec("wolfstack_block4"),
            per_ip_rule_spec("1.2.3.4"),
            ns_block_spec("1.2.3.4"),
        ] {
            let joined = spec.join(" ");
            assert!(joined.contains("-m conntrack --ctstate NEW"),
                "stateless rule form would drop our own inbound replies: {}", joined);
            assert!(joined.ends_with("-j DROP"), "must still DROP: {}", joined);
        }
    }

    /// The legacy forms are exactly the current ones minus the
    /// conntrack match. If this drifts, the migration `-D` stops
    /// matching what older builds actually wrote and the broken rule
    /// survives the upgrade.
    #[test]
    fn legacy_forms_are_the_current_forms_without_conntrack() {
        let strip = |v: Vec<&str>| -> Vec<String> {
            let mut out: Vec<String> = Vec::new();
            let mut it = v.into_iter();
            while let Some(tok) = it.next() {
                if tok == "-m" {
                    // Drop only the conntrack match pair, keep others
                    // (the ns form legitimately carries -m comment).
                    let next = it.next().unwrap_or("");
                    if next == "conntrack" {
                        let _ = it.next(); // --ctstate
                        let _ = it.next(); // NEW
                        continue;
                    }
                    out.push(tok.to_string());
                    out.push(next.to_string());
                    continue;
                }
                out.push(tok.to_string());
            }
            out
        };
        assert_eq!(strip(block_rule_spec("s")),
            legacy_block_rule_spec("s").iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(strip(per_ip_rule_spec("1.2.3.4")),
            legacy_per_ip_rule_spec("1.2.3.4").iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(strip(ns_block_spec("1.2.3.4")),
            legacy_ns_block_spec("1.2.3.4").iter().map(|s| s.to_string()).collect::<Vec<_>>());
    }

    /// The legacy forms are what pre-v25.6.0 builds literally wrote.
    /// Pinned verbatim: these strings are what `iptables -D` has to
    /// match on an upgraded host, so they must never be "tidied".
    #[test]
    fn legacy_forms_match_what_older_builds_wrote() {
        assert_eq!(legacy_block_rule_spec("wolfstack_block4"),
            vec!["-m", "set", "--match-set", "wolfstack_block4", "src", "-j", "DROP"]);
        assert_eq!(legacy_per_ip_rule_spec("1.2.3.4"),
            vec!["-s", "1.2.3.4", "-j", "DROP"]);
        assert_eq!(legacy_ns_block_spec("1.2.3.4"),
            vec!["-s", "1.2.3.4", "-m", "comment", "--comment", NS_BLOCK_TAG, "-j", "DROP"]);
    }

    /// The netns reconciler finds existing rules by locating `-s`
    /// positionally, so prefixing the conntrack match must not hide
    /// them — otherwise every reconcile would re-add a rule that is
    /// already there.
    #[test]
    fn ns_rule_with_conntrack_is_still_detected() {
        assert_eq!(
            parse_ns_tagged_drop(
                "-A INPUT -m conntrack --ctstate NEW -s 1.2.3.4/32 -m comment --comment wolfstack-ns-block -j DROP"
            ),
            Some("1.2.3.4".to_string())
        );
    }

    #[test]
    fn parse_ns_tagged_drop_extracts_source() {
        // The exact shape `iptables -S` echoes for a rule we inserted.
        assert_eq!(
            parse_ns_tagged_drop(
                "-A INPUT -s 1.2.3.4/32 -m comment --comment wolfstack-ns-block -j DROP"
            ),
            Some("1.2.3.4".to_string())
        );
        // ip6tables variant, /128 normalised.
        assert_eq!(
            parse_ns_tagged_drop(
                "-A INPUT -s fd00::5/128 -m comment --comment wolfstack-ns-block -j DROP"
            ),
            Some("fd00::5".to_string())
        );
        // A CIDR block survives intact.
        assert_eq!(
            parse_ns_tagged_drop(
                "-A INPUT -s 10.8.0.0/24 -m comment --comment wolfstack-ns-block -j DROP"
            ),
            Some("10.8.0.0/24".to_string())
        );
        // No source → None (e.g. the chain-policy line).
        assert_eq!(parse_ns_tagged_drop("-P INPUT ACCEPT"), None);
    }
}
