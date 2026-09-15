// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Certbot / Let's Encrypt certificate management for WolfProxy and the
//! nginx app. Replaces the old stop-proxy / start-nginx / run-certbot /
//! stop-nginx / start-proxy dance with zero-downtime ACME challenges:
//!
//! * **Webroot (default):** WolfProxy serves a hardcoded ACME location
//!   block from `/var/lib/wolfstack/acme-webroot`. Certbot writes its
//!   challenge files there; Let's Encrypt fetches them over the still-
//!   running proxy. No service interruption.
//! * **DNS-01 (for wildcards or port-80-less setups):** certbot talks
//!   to the user's DNS provider via one of its plugins. The provider
//!   and credentials are supplied per-request.
//!
//! Renewal is handled by a daily tokio task (`certbot renew --quiet`)
//! with a `--deploy-hook` that reloads WolfProxy on success.

pub mod container;
pub mod replication;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

const CONFIG_PATH: &str = "/etc/wolfstack/certbot.json";
const DEFAULT_WEBROOT: &str = "/var/lib/wolfstack/acme-webroot";
pub(crate) const LE_LIVE_DIR: &str = "/etc/letsencrypt/live";

/// Persisted certbot configuration. Separate file rather than shoved
/// into an existing one — other modules don't need to know about ACME
/// internals, and cert admins shouldn't need read access to unrelated
/// settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertbotConfig {
    /// Default contact email for Let's Encrypt registration. Required
    /// by the CA for expiry notices and account recovery.
    #[serde(default)]
    pub email: String,
    /// Webroot path WolfProxy is configured to serve for ACME HTTP-01
    /// challenges. Override only if the default doesn't work for your
    /// layout — most installs should leave it alone.
    #[serde(default = "default_webroot")]
    pub webroot: String,
    /// Whether the daily renewal task should run. Defaults to on; set
    /// false if you're managing certs manually or via an external
    /// orchestrator.
    #[serde(default = "default_true")]
    pub auto_renew: bool,
    /// Command to run after a successful renewal to pick up the new
    /// chain. Empty means "pick sensibly based on what's running".
    #[serde(default)]
    pub reload_cmd: String,
}

fn default_webroot() -> String { DEFAULT_WEBROOT.to_string() }
fn default_true() -> bool { true }

impl Default for CertbotConfig {
    fn default() -> Self {
        Self {
            email: String::new(),
            webroot: default_webroot(),
            auto_renew: true,
            reload_cmd: String::new(),
        }
    }
}

impl CertbotConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(CONFIG_PATH) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }
    pub fn save(&self) -> Result<(), String> {
        if let Some(parent) = Path::new(CONFIG_PATH).parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(CONFIG_PATH, json).map_err(|e| e.to_string())
    }
}

/// Summary of a single issued certificate, gleaned from the filesystem
/// (no cert-store parsing — we read the PEM directly). `name` matches
/// certbot's `--cert-name` so renewal and deletion can address it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSummary {
    pub name: String,
    pub domains: Vec<String>,
    /// ISO-8601 expiry in UTC. Empty string if the cert couldn't be
    /// parsed — rare, but rather surface an empty field than hide a
    /// cert that still exists on disk.
    pub expires: String,
    /// Days until expiry. Negative when already expired. Frontend uses
    /// this to colour the row (green > 30, amber 7–30, red < 7).
    pub days_remaining: i64,
    /// Absolute path to `fullchain.pem`. Derived from `LE_LIVE_DIR` +
    /// `name`. Filled in by `list_certs`; on serialisation it's stable
    /// across builds because certbot's layout is well-known. UI uses
    /// this to auto-fill the WolfProxy site form so operators don't
    /// have to retype `/etc/letsencrypt/live/<zone>/fullchain.pem`.
    #[serde(default)]
    pub cert_path: String,
    /// Absolute path to `privkey.pem`. See `cert_path` above.
    #[serde(default)]
    pub key_path: String,
    /// True if at least one of `domains` is a wildcard (`*.zone.tld`).
    /// Wildcards let one cert cover every host in the zone, so the
    /// site-creation UI treats them differently — it offers a
    /// "subdomain" input that synthesises `server_name`.
    #[serde(default)]
    pub is_wildcard: bool,
    /// For wildcard certs, the zone the wildcard covers
    /// (`*.wolf.uk.com` → `wolf.uk.com`). Empty for non-wildcard
    /// certs. The UI shows this as a suffix chip next to the subdomain
    /// input so the operator can see what the final hostname will be.
    #[serde(default)]
    pub base_zone: String,
}

/// Resolve the path to the `certbot` binary, or `None` if not present.
///
/// systemd's default `PATH` is `/usr/local/sbin:/usr/local/bin:/usr/sbin:
/// /usr/bin:/sbin:/bin` — it does NOT include `/snap/bin`. Operators who
/// installed certbot via `snap install certbot --classic` (the path
/// EFF recommends on Ubuntu / Debian since 20.04) end up with certbot
/// at `/snap/bin/certbot`, invisible to the WolfStack systemd service.
/// Pre-v23.0.1 this surfaced as a confusing "certbot is not installed
/// on this node" from the DNS-provider Test button even though
/// `certbot --version` worked fine in the operator's shell.
///
/// We probe PATH first (cheap), then fall back to a known-good list of
/// install locations: apt (`/usr/bin`), pip / source build
/// (`/usr/local/bin`), snap (`/snap/bin`), and the EFF-maintained
/// virtualenv path (`/opt/certbot/bin`).
pub fn certbot_path() -> Option<String> {
    certbot_probe().0
}

/// Run the certbot detection chain and return both the found path
/// (if any) and a verbose trace of what each probe did. The trace is
/// surfaced in the "certbot is not installed" error so the operator
/// can immediately see WHY we couldn't find their binary — no support
/// round-trip needed. Each probe line is human-readable, e.g.:
///     "PATH lookup: certbot --version failed (errno 2 - not in PATH)"
///     "bash -lc command -v: returned '/snap/bin/certbot' but binary doesn't run"
///     "whereis -b: found /usr/bin/certbot — using it"
pub fn certbot_probe() -> (Option<String>, Vec<String>) {
    let mut trace: Vec<String> = Vec::new();

    // Helper: try a candidate path. Records the outcome in the trace
    // and returns Some(path) if the binary actually executes.
    let try_path = |path: &str, label: &str, trace: &mut Vec<String>| -> Option<String> {
        if !std::path::Path::new(path).exists() {
            trace.push(format!("{}: '{}' does not exist", label, path));
            return None;
        }
        match Command::new(path).arg("--version").output() {
            Ok(o) if o.status.success() => {
                trace.push(format!("{}: '{}' — works, using it", label, path));
                Some(path.to_string())
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
                trace.push(format!("{}: '{}' exists but --version failed: {}", label, path, stderr));
                None
            }
            Err(e) => {
                trace.push(format!("{}: '{}' exists but spawn failed: {}", label, path, e));
                None
            }
        }
    };

    // 1. systemd PATH probe — distro packages, anything in the
    //    process's PATH at the time WolfStack started.
    match Command::new("certbot").arg("--version").output() {
        Ok(o) if o.status.success() => {
            trace.push("PATH lookup: 'certbot' in service PATH — using it".to_string());
            return (Some("certbot".to_string()), trace);
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
            trace.push(format!("PATH lookup: certbot found but --version failed: {}", stderr));
        }
        Err(e) => {
            trace.push(format!("PATH lookup: certbot not in service PATH ({})", e));
        }
    }

    // 2. `which certbot` — same as Step 1 effectively, but useful as
    //    a sanity-check trace line for operators who already ran it
    //    in their shell and want to see what the SERVICE sees vs them.
    if let Ok(out) = Command::new("which").arg("certbot").output() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if out.status.success() && !s.is_empty() {
            if let Some(found) = try_path(&s, "which certbot", &mut trace) {
                return (Some(found), trace);
            }
        } else {
            trace.push("which certbot: no match in service PATH".to_string());
        }
    } else {
        trace.push("which certbot: command not available".to_string());
    }

    // 3. `whereis -b certbot` — uses a built-in list of standard
    //    binary locations, INDEPENDENT of PATH. Catches /usr/bin /
    //    /usr/local/bin / /opt installs even when systemd's PATH is
    //    restricted. Output is "certbot: /path1 /path2 ...".
    if let Ok(out) = Command::new("whereis").args(["-b", "certbot"]).output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).to_string();
            // Skip the "certbot:" prefix, take whitespace-separated paths.
            let paths: Vec<&str> = s.split_whitespace().filter(|p| p.starts_with('/')).collect();
            if paths.is_empty() {
                trace.push("whereis -b: no match".to_string());
            } else {
                for p in paths {
                    if let Some(found) = try_path(p, "whereis -b", &mut trace) {
                        return (Some(found), trace);
                    }
                }
            }
        }
    } else {
        trace.push("whereis: command not available".to_string());
    }

    // 4. Login-shell probe — picks up /etc/environment,
    //    /etc/profile.d/*, snap wrappers, pyenv, asdf, pipx, nix, and
    //    any operator-defined PATH addition. systemd doesn't source
    //    these. bash → sh fallback for minimal hosts without bash.
    for shell in &["/bin/bash", "/bin/sh"] {
        if !std::path::Path::new(shell).exists() {
            trace.push(format!("{}: shell missing, skipped", shell));
            continue;
        }
        match Command::new(shell)
            .args(["-lc", "command -v certbot"])
            .output()
        {
            Ok(out) if out.status.success() => {
                let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if path.is_empty() {
                    trace.push(format!("{} -lc command -v: empty result", shell));
                } else if let Some(found) = try_path(&path, &format!("{} -lc", shell), &mut trace) {
                    return (Some(found), trace);
                }
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                trace.push(format!("{} -lc: failed: {}", shell, stderr));
            }
            Err(e) => {
                trace.push(format!("{} -lc: spawn failed: {}", shell, e));
            }
        }
    }

    // 5. Known install locations across distros, package managers, and
    //    deployment styles. Order matters: distro packages first (most
    //    common), then snap, then EFF's venv, then user-local pipx.
    //    /root/* covers sudo pip install on hosts where the WolfStack
    //    service runs as root. /home/*/.local/bin covers pipx
    //    installs done as a regular user — we glob through home dirs
    //    rather than hardcoding usernames.
    let mut candidates: Vec<String> = vec![
        "/usr/bin/certbot".to_string(),
        "/usr/sbin/certbot".to_string(),
        "/usr/local/bin/certbot".to_string(),
        "/usr/local/sbin/certbot".to_string(),
        "/snap/bin/certbot".to_string(),
        "/var/lib/snapd/snap/bin/certbot".to_string(),
        "/opt/certbot/bin/certbot".to_string(),
        "/opt/letsencrypt/certbot".to_string(),
        "/opt/eff.org/certbot/venv/bin/certbot".to_string(),
        "/root/.local/bin/certbot".to_string(),
        "/root/.local/pipx/venvs/certbot/bin/certbot".to_string(),
    ];
    // Glob every user's ~/.local/bin/certbot — pipx + pip --user installs
    // for non-root users. Cheap directory scan, only reads /home entries.
    if let Ok(entries) = std::fs::read_dir("/home") {
        for entry in entries.flatten() {
            let user_path = entry.path().join(".local/bin/certbot");
            if let Some(s) = user_path.to_str() {
                candidates.push(s.to_string());
            }
            let pipx_path = entry.path().join(".local/pipx/venvs/certbot/bin/certbot");
            if let Some(s) = pipx_path.to_str() {
                candidates.push(s.to_string());
            }
        }
    }
    for cand in &candidates {
        if std::path::Path::new(cand).exists()
            && let Some(found) = try_path(cand, "explicit-list", &mut trace) {
                return (Some(found), trace);
            }
    }
    trace.push(format!("explicit-list: none of {} known paths existed", candidates.len()));

    // 6. Last resort — walk common install roots. Bounded depth so we
    //    don't trawl deep home trees. Includes /home so pipx installs
    //    in non-standard usernames are still found.
    for root in &["/usr/local", "/opt", "/snap", "/home"] {
        if !std::path::Path::new(root).exists() { continue; }
        if let Ok(out) = Command::new("find")
            .args([root, "-maxdepth", "6", "-name", "certbot", "-type", "f", "-executable"])
            .output()
            && out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                let mut any = false;
                for line in s.lines() {
                    let p = line.trim();
                    if p.is_empty() { continue; }
                    any = true;
                    if let Some(found) = try_path(p, &format!("find {}", root), &mut trace) {
                        return (Some(found), trace);
                    }
                }
                if !any {
                    trace.push(format!("find {}: no matches", root));
                }
            }
    }

    (None, trace)
}

pub fn is_installed() -> bool {
    certbot_path().is_some()
}

/// Format a verbose "certbot not installed" error including a trace of
/// every probe that ran. The operator sees exactly which paths were
/// tried and why each one failed — no need for back-and-forth support
/// to figure out where their certbot install actually lives.
pub fn missing_certbot_error() -> String {
    let (_, trace) = certbot_probe();
    let mut msg = String::from(
        "certbot is not installed on this node — the WolfStack service couldn't find it. \
         If certbot works in your shell but not here, the service runs under systemd with a \
         restricted environment and may need an explicit path. Probe trace:\n"
    );
    for line in trace {
        msg.push_str("  • ");
        msg.push_str(&line);
        msg.push('\n');
    }
    msg.push_str(
        "\nTo install: `apt install certbot` (Debian/Ubuntu), \
         `dnf install certbot` (Fedora/RHEL), \
         `pacman -S certbot` (Arch), or follow https://certbot.eff.org/instructions. \
         If certbot IS installed but in an unusual location, the trace above shows what \
         WolfStack checked — please report it as a bug so we can add your path to the probe list."
    );
    msg
}

pub fn ensure_webroot(cfg: &CertbotConfig) -> Result<(), String> {
    std::fs::create_dir_all(&cfg.webroot).map_err(|e| format!("create webroot: {e}"))
}

/// List every cert currently on disk in /etc/letsencrypt/live. We walk
/// the directory rather than asking `certbot certificates` because the
/// latter needs root AND prints a free-form table that's annoying to
/// parse. The cert.pem symlink resolves to the live archive so reading
/// expiry works even for certs issued years ago.
pub fn list_certs() -> Vec<CertSummary> {
    let live = Path::new(LE_LIVE_DIR);
    if !live.exists() { return Vec::new(); }
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(live) else { return out };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() { continue; }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        // "README" is a stock certbot file, not a cert directory.
        if name == "README" { continue; }
        let cert_pem = path.join("cert.pem");
        if !cert_pem.exists() { continue; }
        let (domains, expires, days_remaining) = probe_cert(&cert_pem);
        // Pick the first wildcard SAN for `base_zone`. A single
        // multi-SAN cert can carry both `wolf.uk.com` and
        // `*.wolf.uk.com`; the wildcard one is what makes it useful
        // for "any host under this zone" proxying.
        let wildcard = domains.iter().find(|d| d.starts_with("*."));
        let is_wildcard = wildcard.is_some();
        let base_zone = wildcard
            .map(|d| d.trim_start_matches("*.").to_string())
            .unwrap_or_default();
        out.push(CertSummary {
            name: name.to_string(),
            domains,
            expires,
            days_remaining,
            cert_path: format!("{}/{}/fullchain.pem", LE_LIVE_DIR, name),
            key_path: format!("{}/{}/privkey.pem", LE_LIVE_DIR, name),
            is_wildcard,
            base_zone,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Same as `list_certs` but reads `/etc/letsencrypt/live/` from inside
/// the given `ExecTarget`. Used by the WolfProxy nginx site form so
/// the cert dropdown reflects the certs visible to the *container* (or
/// host) that will actually serve nginx — picking a host cert when
/// you're configuring an LXC container would auto-fill a path the
/// container can't read, and nginx would fail to start.
///
/// Returns an empty Vec if the target has no /etc/letsencrypt/live/
/// directory (typical for fresh containers that haven't had certbot
/// run inside them and don't have /etc/letsencrypt bind-mounted from
/// the host). Caller renders an "empty container" hint rather than a
/// fallback to host certs — leaking host paths into a container
/// context is exactly the bug we're fixing here.
pub fn list_certs_via_target(target: &crate::configurator::ExecTarget) -> Vec<CertSummary> {
    use crate::configurator::ExecTarget;
    // Fast path for the host case — avoid the sudo sh subprocess
    // round-trip openssl-per-cert that the ExecTarget abstraction
    // would impose. Behaviour-equivalent, just cheaper.
    if matches!(target, ExecTarget::Host) {
        return list_certs();
    }

    // Probe the container's /etc/letsencrypt/live/ via ExecTarget.
    if !target.path_exists(LE_LIVE_DIR).unwrap_or(false) {
        return Vec::new();
    }
    let names = match target.list_dir(LE_LIVE_DIR) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for name in names {
        // certbot drops a README at the top of LE_LIVE_DIR and uses
        // per-cert subdirectories for everything else; same filter as
        // the host-side walker.
        if name == "README" || name.starts_with('.') {
            continue;
        }
        let cert_pem = format!("{}/{}/cert.pem", LE_LIVE_DIR, name);
        if !target.path_exists(&cert_pem).unwrap_or(false) {
            continue;
        }
        let (domains, expires, days_remaining) = probe_cert_via_target(target, &cert_pem);
        let wildcard = domains.iter().find(|d| d.starts_with("*."));
        let is_wildcard = wildcard.is_some();
        let base_zone = wildcard
            .map(|d| d.trim_start_matches("*.").to_string())
            .unwrap_or_default();
        out.push(CertSummary {
            name: name.clone(),
            domains,
            expires,
            days_remaining,
            cert_path: format!("{}/{}/fullchain.pem", LE_LIVE_DIR, name),
            key_path: format!("{}/{}/privkey.pem", LE_LIVE_DIR, name),
            is_wildcard,
            base_zone,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Container-aware version of `probe_cert` — shells out to openssl
/// *inside* the target. Same parsing logic; only the transport differs.
fn probe_cert_via_target(
    target: &crate::configurator::ExecTarget,
    pem_path: &str,
) -> (Vec<String>, String, i64) {
    let mut domains = Vec::new();
    let mut expires = String::new();
    let mut days: i64 = 0;

    // The path can be controlled by `name` from list_dir, but list_dir
    // already filtered to entries under /etc/letsencrypt/live/. Quote
    // defensively anyway — single-quote-escape via the same pattern as
    // ExecTarget::read_file.
    let q = pem_path.replace('\'', "'\\''");
    let sans_cmd = format!("openssl x509 -in '{}' -noout -ext subjectAltName", q);
    if let Ok(txt) = target.exec(&sans_cmd) {
        for line in txt.lines() {
            for part in line.split(',') {
                if let Some(dom) = part.trim().strip_prefix("DNS:") {
                    domains.push(dom.trim().to_string());
                }
            }
        }
    }
    let end_cmd = format!("openssl x509 -in '{}' -noout -enddate", q);
    if let Ok(txt) = target.exec(&end_cmd) {
        let trimmed = txt.trim();
        if let Some(val) = trimmed.strip_prefix("notAfter=") {
            expires = val.to_string();
            // Convert via `date -d` inside the same target so timezone
            // semantics match — containers can have skewed clocks but
            // openssl emits UTC, so date -d on the target is fine.
            let date_cmd = format!("date -d '{}' +%s", val.replace('\'', "'\\''"));
            if let Ok(out) = target.exec(&date_cmd)
                && let Ok(ts) = out.trim().parse::<i64>() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    days = (ts - now) / 86400;
                }
        }
    }
    (domains, expires, days)
}

/// Extract the SANs and notAfter from a PEM-encoded x509. We shell out
/// to `openssl x509` rather than pulling in a rustls-pemfile/x509-parser
/// dep tree — certbot already requires openssl on the host, so there's
/// nothing to gain from adding a crate.
pub(crate) fn probe_cert(pem: &Path) -> (Vec<String>, String, i64) {
    let mut domains = Vec::new();
    let mut expires = String::new();
    let mut days: i64 = 0;

    // SANs — the x509 extension listing all cert subjects.
    if let Ok(o) = Command::new("openssl")
        .args(["x509", "-in", &pem.to_string_lossy(), "-noout", "-ext", "subjectAltName"])
        .output()
    {
        let txt = String::from_utf8_lossy(&o.stdout);
        for line in txt.lines() {
            for part in line.split(',') {
                if let Some(dom) = part.trim().strip_prefix("DNS:") {
                    domains.push(dom.trim().to_string());
                }
            }
        }
    }

    // Expiry — `openssl x509 -enddate` returns `notAfter=…`.
    if let Ok(o) = Command::new("openssl")
        .args(["x509", "-in", &pem.to_string_lossy(), "-noout", "-enddate"])
        .output()
    {
        let txt = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if let Some(val) = txt.strip_prefix("notAfter=") {
            expires = val.to_string();
            // Convert to days-remaining via `date -d … +%s`, portable
            // across the BSDs/GNU-isms the installer might be on.
            if let Ok(d) = Command::new("date")
                .args(["-d", val, "+%s"]).output()
                && let Ok(ts) = String::from_utf8_lossy(&d.stdout).trim().parse::<i64>() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64).unwrap_or(0);
                    days = (ts - now) / 86400;
                }
        }
    }

    (domains, expires, days)
}

/// Request a new certificate. `challenge` is either "webroot" (the
/// recommended default) or "dns-<provider>" where provider matches a
/// certbot-dns-* plugin name. `dns_credentials_path` is a path to an
/// INI file the user uploaded — required for DNS-01, ignored for
/// webroot.
pub fn issue(
    domains: &[String],
    email: &str,
    challenge: &str,
    dns_credentials_path: Option<&str>,
    dry_run: bool,
) -> Result<String, String> {
    if !is_installed() {
        return Err(missing_certbot_error());
    }
    if domains.is_empty() {
        return Err("at least one domain is required".to_string());
    }
    let cfg = CertbotConfig::load();
    if email.is_empty() && cfg.email.is_empty() {
        return Err("an email address is required (for Let's Encrypt account registration)".to_string());
    }

    // Always invoke certbot via its resolved path (handles /snap/bin
    // etc. that aren't in systemd's PATH). is_installed() already
    // guaranteed Some above; expect() can only fire on a TOCTOU race
    // where someone uninstalled certbot in the last microseconds, in
    // which case "certbot is not installed" is the right thing to say.
    let certbot_bin = certbot_path()
        .ok_or_else(missing_certbot_error)?;
    let mut cmd = Command::new(&certbot_bin);
    cmd.arg("certonly").arg("--non-interactive").arg("--agree-tos");

    // Email priority: explicit arg overrides saved default. Saved
    // default exists so the admin doesn't have to retype it every
    // time.
    let resolved_email = if email.is_empty() { cfg.email.clone() } else { email.to_string() };
    cmd.arg("--email").arg(&resolved_email);

    for d in domains {
        cmd.arg("-d").arg(d);
    }
    if dry_run { cmd.arg("--dry-run"); }

    match challenge {
        "webroot" => {
            ensure_webroot(&cfg)?;
            cmd.arg("--webroot").arg("-w").arg(&cfg.webroot);
        }
        provider if provider.starts_with("dns-") => {
            // certbot plugin name is `dns-cloudflare`, auth flag is
            // `--dns-cloudflare-credentials`. The credentials INI file
            // must be 0600 or certbot refuses to use it.
            let plugin = provider;
            // Pre-flight: ensure the plugin module is loaded. On
            // Debian trixie / Ubuntu 23.04+, plugins are separate apt
            // packages — without them certbot returns a confusing
            // "Could not find plugin" error.
            let bare = plugin.trim_start_matches("dns-");
            if !plugin_installed(bare) {
                let (icmd, _) = suggested_install_command(bare);
                let hint = icmd.map(|c| format!("\n\nInstall it with:\n  {}", c)).unwrap_or_default();
                return Err(format!(
                    "DNS plugin '{}' is not installed on this node — certbot can't \
                     authenticate without it. On Debian trixie / Ubuntu 23.04+, the \
                     certbot package no longer bundles DNS plugins.{}",
                    plugin, hint
                ));
            }
            cmd.arg(format!("--{}", plugin));
            if let Some(creds) = dns_credentials_path {
                // certbot refuses credentials files with permissive
                // modes — chmod to 0600 defensively, since an admin
                // uploading via our UI won't know to do that.
                let _ = Command::new("chmod").args(["0600", creds]).output();
                cmd.arg(format!("--{}-credentials", plugin)).arg(creds);
            } else {
                return Err(format!("DNS challenge '{}' needs a credentials file", plugin));
            }
        }
        other => return Err(format!("unknown challenge type: {}", other)),
    }

    let out = cmd.output().map_err(|e| format!("spawn certbot: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "certbot failed:\n{}",
            String::from_utf8_lossy(&out.stderr),
        ));
    }

    // On success, fire the reload hook so WolfProxy picks up the new
    // chain without the admin having to restart anything.
    if !dry_run {
        let _ = reload_proxy(&cfg);
    }

    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Issue a cert using DNS-01 via a stored DNS provider. This is the
/// wildcard-friendly path; pass `*.zone.tld` in `domains` and certbot
/// does the rest.
///
/// Credentials file lifetime depends on the mode:
/// * **real issuance** — a persistent 0600 INI at
///   `/etc/wolfstack/dns-creds/<provider-id>.ini`. certbot writes that
///   absolute path into the lineage's renewal config and re-reads it on
///   every `certbot renew`, so it must still exist months later.
/// * **dry-run** — a throwaway file under `/run/wolfstack/dns-creds/`
///   unlinked via the `MaterializedCreds` Drop impl, even on error or
///   panic. A dry-run creates no lineage, so nothing refers to it after.
///
/// `dry_run = true` hits Let's Encrypt's staging CA — used by the
/// `/api/dns-providers/{id}/test` button so an operator can sanity-check
/// their credentials without burning the 5-issuance-per-week rate limit
/// on production.
pub fn issue_via_provider(
    domains: &[String],
    email: &str,
    provider_id: &str,
    dry_run: bool,
) -> Result<String, String> {
    if !is_installed() {
        return Err(missing_certbot_error());
    }
    if domains.is_empty() {
        return Err("at least one domain is required".to_string());
    }
    let cfg = CertbotConfig::load();
    let resolved_email = if email.is_empty() { cfg.email.clone() } else { email.to_string() };
    if resolved_email.is_empty() {
        return Err("an email address is required (for Let's Encrypt account registration)".to_string());
    }

    // Load the store fresh so any concurrent UI update of the provider
    // credentials takes effect immediately (no in-memory caching).
    let store = crate::dns_providers::DnsProviderStore::load();
    let provider = store
        .get(provider_id)
        .ok_or_else(|| format!("DNS provider '{}' not found", provider_id))?;
    if !crate::dns_providers::is_known_plugin(&provider.plugin) {
        // Belt-and-braces: store::add already guards this, but a
        // hand-edited /etc/wolfstack/dns-providers.json could slip a
        // bad plugin past validation. Plugin is about to be
        // interpolated into argv, so refuse here too.
        return Err(format!("DNS provider has unsafe plugin '{}'", provider.plugin));
    }

    // Pre-flight: confirm the DNS plugin is actually loaded BEFORE
    // we materialise credentials or invoke certbot. On Debian trixie
    // / Ubuntu 23.04+ the certbot package no longer bundles DNS
    // plugins — operators get "Could not find plugin: dns-cloudflare"
    // from raw certbot stderr with no guidance. We turn that into a
    // structured error the API can surface as a one-click install
    // CTA.
    if !plugin_installed(&provider.plugin) {
        let (cmd, _) = suggested_install_command(&provider.plugin);
        let install_hint = cmd
            .map(|c| format!("\n\nInstall it with:\n  {}", c))
            .unwrap_or_default();
        return Err(format!(
            "DNS plugin 'dns-{}' is not installed on this node — certbot can't authenticate \
             the challenge without it. This is the most common cause of \"works on Proxmox, \
             fails on plain Debian/Ubuntu\" — Debian trixie+ ships certbot without any DNS \
             plugins.{}",
            provider.plugin, install_hint
        ));
    }

    // Real issuance: persistent file (renewals read it later). Dry-run:
    // ephemeral guard — bind it to a local so the file lives for the
    // full duration of the certbot call below and is unlinked after.
    let mut ephemeral: Option<crate::dns_providers::MaterializedCreds> = None;
    let creds_path = if dry_run {
        let m = store.materialize(provider_id)?;
        let p = m.path.clone();
        ephemeral = Some(m);
        p
    } else {
        store.persist_for_renewal(provider_id)?
    };

    // Resolve certbot via certbot_path() so snap installs at /snap/bin
    // are found — systemd's default PATH doesn't include /snap/bin and
    // pre-fix `Command::new("certbot")` silently failed there.
    let certbot_bin = certbot_path()
        .ok_or_else(missing_certbot_error)?;
    let mut cmd = Command::new(&certbot_bin);
    cmd.arg("certonly").arg("--non-interactive").arg("--agree-tos");
    cmd.arg("--email").arg(&resolved_email);
    for d in domains {
        cmd.arg("-d").arg(d);
    }
    if dry_run {
        cmd.arg("--dry-run");
    }
    // Select the plugin via `--authenticator dns-<plugin>` — the canonical
    // mechanism that works for BOTH certbot's own plugins and third-party
    // ones. The old bare `--dns-<plugin>` toggle only exists for stock
    // plugins; for every community plugin (porkbun/hetzner/njalla/godaddy/
    // namecheap/vultr/dynu) argparse rejected it as an "ambiguous option"
    // prefix of --dns-<plugin>-credentials, so issuance through those
    // providers could never have worked (verified live in a venv with
    // certbot 5.x + the porkbun/hetzner/dynu plugins, 2026-06-11).
    // The `--dns-<plugin>-credentials` flag is plugin-option machinery and
    // exists for all plugins. Plugin is whitelisted
    // (dns_providers::KNOWN_PLUGINS), so the string interpolation here
    // can't introduce a new flag.
    cmd.arg("--authenticator").arg(format!("dns-{}", provider.plugin));
    cmd.arg(format!("--dns-{}-credentials", provider.plugin)).arg(&creds_path);

    let out = cmd.output().map_err(|e| format!("spawn certbot: {e}"))?;
    // Dry-run guard drops here on either success or error — file is
    // unlinked. The persistent file stays for renewals.
    drop(ephemeral);
    if !out.status.success() {
        return Err(format!(
            "certbot failed:\n{}",
            String::from_utf8_lossy(&out.stderr),
        ));
    }
    if !dry_run {
        let _ = reload_proxy(&cfg);
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Force-renew one cert by name. Skips certbot's 30-day freshness
/// window — used when the admin wants to rotate the cert early (e.g.
/// after changing SANs).
pub fn renew(name: &str) -> Result<String, String> {
    let certbot_bin = certbot_path().ok_or_else(missing_certbot_error)?;
    let out = Command::new(&certbot_bin)
        .args(["renew", "--non-interactive", "--force-renewal", "--cert-name", name])
        .output()
        .map_err(|e| format!("spawn certbot: {e}"))?;
    if !out.status.success() {
        return Err(format!("renew failed:\n{}", String::from_utf8_lossy(&out.stderr)));
    }
    let cfg = CertbotConfig::load();
    let _ = reload_proxy(&cfg);
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Delete one cert and its archive dir. Certbot's own `delete`
/// subcommand handles the archive cleanup — manually removing
/// `/etc/letsencrypt/{live,archive}/<name>` leaves dangling renewal
/// config in `/etc/letsencrypt/renewal/<name>.conf`.
pub fn delete(name: &str) -> Result<String, String> {
    let certbot_bin = certbot_path().ok_or_else(missing_certbot_error)?;
    let out = Command::new(&certbot_bin)
        .args(["delete", "--non-interactive", "--cert-name", name])
        .output()
        .map_err(|e| format!("spawn certbot: {e}"))?;
    if !out.status.success() {
        return Err(format!("delete failed:\n{}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Reload WolfProxy / nginx so the new cert is served. Prefers
/// `systemctl reload wolfproxy` if the service is present, falls back
/// to nginx, and honours an explicit `reload_cmd` override. No-op on
/// systems running neither — the admin presumably runs the webserver
/// out-of-band and will reload it themselves.
pub(crate) fn reload_proxy(cfg: &CertbotConfig) -> Result<(), String> {
    if !cfg.reload_cmd.is_empty() {
        let status = Command::new("sh").arg("-c").arg(&cfg.reload_cmd).status();
        return match status {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => Err(format!("reload_cmd exited {}", s)),
            Err(e) => Err(format!("reload_cmd spawn: {e}")),
        };
    }
    for service in ["wolfproxy", "nginx"] {
        let active = Command::new("systemctl")
            .args(["is-active", service]).output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false);
        if active {
            let _ = Command::new("systemctl").args(["reload", service]).status();
            return Ok(());
        }
    }
    Ok(())
}

/// Called by the daily background task in main.rs. Runs renew across
/// every cert, letting certbot decide which ones are actually due
/// (anything with < 30 days left). The deploy hook reloads the proxy
/// exactly once per invocation, regardless of how many certs renewed.
pub fn renew_due() -> Result<(), String> {
    let cfg = CertbotConfig::load();
    if !cfg.auto_renew { return Ok(()); }
    let certbot_bin = match certbot_path() {
        Some(p) => p,
        None => return Ok(()), // no certbot installed → silently no-op (daily task)
    };
    // Runs 60s after every start, so an upgrade heals the lineages the
    // old ephemeral-credentials code left unrenewable before the
    // distro's own certbot.timer next fires.
    repair_dns_renewal_configs();
    let _ = Command::new(&certbot_bin)
        .args(["renew", "--non-interactive", "--quiet"])
        .output();
    // Always reload — cheap, and picks up anything certbot just
    // rotated without a per-cert deploy-hook dance.
    let _ = reload_proxy(&cfg);
    Ok(())
}

/// Rewrite any `/etc/letsencrypt/renewal/<name>.conf` whose
/// `dns_<plugin>_credentials` still points at an ephemeral
/// `/run/wolfstack/dns-creds/<provider-id>-<8hex>.ini` file (the
/// pre-fix path, gone the moment issuance finished) to the persistent
/// `/etc/wolfstack/dns-creds/<provider-id>.ini`, writing that file if
/// needed. Certbot stores renewal params as `key = value` lines in a
/// configobj file, and the plugin option's dest name is the flag with
/// dashes turned to underscores — so the line for `--dns-cloudflare-
/// credentials` reads `dns_cloudflare_credentials = /path`.
///
/// Returns the lineage names repaired. A conf whose provider no longer
/// exists in the store is left alone and logged — there is nothing to
/// point it at, and a loud renewal failure is the right outcome.
pub fn repair_dns_renewal_configs() -> Vec<String> {
    let mut repaired = Vec::new();
    let entries = match std::fs::read_dir(replication::LE_RENEWAL_DIR) {
        Ok(e) => e,
        Err(_) => return repaired,
    };
    let store = crate::dns_providers::DnsProviderStore::load();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(lineage) = path.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".conf")) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let mut changed = false;
        let mut out = String::with_capacity(text.len());
        for line in text.lines() {
            let mut replaced = None;
            if let Some((key, provider_id)) = stale_ephemeral_creds_line(line) {
                if store.get(provider_id).is_some() {
                    match store.persist_for_renewal(provider_id) {
                        Ok(persistent) => {
                            replaced = Some(format!("{} = {}", key, persistent));
                        }
                        Err(e) => log::warn!(
                            "certbot: lineage '{}' credentials for provider '{}' could not be persisted: {}",
                            lineage, provider_id, e
                        ),
                    }
                } else {
                    log::warn!(
                        "certbot: lineage '{}' renews via DNS provider '{}' which no longer exists — \
                         its renewals will fail until it is reissued from Certificates",
                        lineage, provider_id
                    );
                }
            }
            match replaced {
                Some(l) => { out.push_str(&l); changed = true; }
                None => out.push_str(line),
            }
            out.push('\n');
        }
        if changed {
            match std::fs::write(&path, out) {
                Ok(()) => {
                    log::info!("certbot: repaired renewal config for '{}' — DNS credentials now persistent", lineage);
                    repaired.push(lineage.to_string());
                }
                Err(e) => log::warn!("certbot: write {}: {}", path.display(), e),
            }
        }
    }
    repaired
}

/// If `line` is a renewal-config `dns_<plugin>_credentials = <path>`
/// entry whose path is a pre-fix ephemeral file, return the trimmed key
/// and the provider id embedded in the filename. The filename is
/// `<provider-id>-<8hex>.ini` and the provider id is itself
/// `dns-<8hex>`, so the id is everything before the LAST dash.
fn stale_ephemeral_creds_line(line: &str) -> Option<(&str, &str)> {
    let (key, val) = line.split_once('=')?;
    let key = key.trim();
    if !(key.starts_with("dns_") && key.ends_with("_credentials")) {
        return None;
    }
    let stem = val.trim()
        .strip_prefix("/run/wolfstack/dns-creds/")?
        .strip_suffix(".ini")?;
    let (provider_id, _rand) = stem.rsplit_once('-')?;
    Some((key, provider_id))
}

#[cfg(test)]
mod renewal_repair_tests {
    use super::stale_ephemeral_creds_line;

    #[test]
    fn matches_the_reported_line() {
        // Exact shape from the 2026-08-27 field report (mm4.org).
        let line = "dns_cloudflare_credentials = /run/wolfstack/dns-creds/dns-33e10d73-0cf8844e.ini";
        assert_eq!(stale_ephemeral_creds_line(line), Some(("dns_cloudflare_credentials", "dns-33e10d73")));
    }

    #[test]
    fn community_plugin_and_no_spaces() {
        let line = "dns_porkbun_credentials=/run/wolfstack/dns-creds/dns-0a1b2c3d-deadbeef.ini";
        assert_eq!(stale_ephemeral_creds_line(line), Some(("dns_porkbun_credentials", "dns-0a1b2c3d")));
    }

    #[test]
    fn leaves_everything_else_alone() {
        for line in [
            "dns_cloudflare_credentials = /etc/wolfstack/dns-creds/dns-33e10d73.ini",
            "dns_cloudflare_credentials = /root/cf.ini",
            "authenticator = dns-cloudflare",
            "server = https://acme-v02.api.letsencrypt.org/directory",
            "[renewalparams]",
            "",
        ] {
            assert_eq!(stale_ephemeral_creds_line(line), None, "{line}");
        }
    }
}

/// Location of the generated WolfProxy snippet that serves the ACME
/// webroot. Callers patch this into their main `http {}` config via
/// an `include` directive.
pub fn nginx_snippet_path() -> PathBuf {
    PathBuf::from("/etc/wolfproxy/conf.d/acme-challenge.conf")
}

/// Write (or overwrite) the ACME snippet. Contains a single location
/// block so both :80 and :443 servers can `include` it. Serving the
/// challenge on :443 is harmless and lets DNS cutovers resolve faster.
pub fn write_nginx_snippet(cfg: &CertbotConfig) -> Result<(), String> {
    let path = nginx_snippet_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create conf.d: {e}"))?;
    }
    let body = format!(
        "# Auto-generated by WolfStack certbot module — do not edit.\n\
         # Include from any server block that needs to solve ACME challenges.\n\
         location /.well-known/acme-challenge/ {{\n\
         \x20   root {};\n\
         \x20   default_type \"text/plain\";\n\
         \x20   try_files $uri =404;\n\
         }}\n",
        cfg.webroot,
    );
    std::fs::write(&path, body).map_err(|e| format!("write snippet: {e}"))?;
    ensure_webroot(cfg)?;
    Ok(())
}

// ─── DNS plugin management ───
//
// On modern Debian (12 bookworm onward, 13 trixie) and Ubuntu (23.04
// onward), the certbot package does NOT bundle any DNS plugins. Each
// provider needs its own package, e.g. `python3-certbot-dns-cloudflare`.
// Pre-2026 Proxmox installs typically came with these pre-installed,
// so operators migrating from Proxmox-style hosts to plain Debian
// hit "Could not find plugin: dns-cloudflare" with no clue what's
// wrong.
//
// This block:
//   * Knows which apt / dnf / pacman / pipx package to install per plugin
//   * Detects which plugins certbot ACTUALLY has loaded right now
//   * Lets the API pre-flight a DNS issue/test call and offer a one-click
//     install of the missing package — across host, LXC container, VM,
//     and Docker (the apt/dnf/pacman commands work identically in all
//     four contexts; only snap is environment-sensitive and we avoid it).

/// Package mapping per plugin per distro family. `None` means "not
/// packaged for that distro — use the pipx fallback". Each row
/// corresponds to one entry in `dns_providers::KNOWN_PLUGINS`.
///
/// **Verification methodology (every cell, 2026-05-17).** Names below
/// were grepped from the official repodata / Packages index of each
/// distro:
///   * Debian 12 bookworm + 13 trixie — `packages.debian.org/<suite>/`
///     search results AND apt-cache on a live host.
///   * Ubuntu 22.04 jammy + 24.04 noble — `packages.ubuntu.com/<suite>/`
///   * Fedora 42 + EPEL 9 + EPEL 10 — primary.xml.zst grepped from
///     `dl.fedoraproject.org/pub/{fedora,epel}/.../repodata/`
///   * Arch extra + AUR — `archlinux.org/packages/` and `aur.archlinux.org/packages/`
///   * openSUSE Tumbleweed + Leap 15.6 — `download.opensuse.org/.../repodata/`
///   * Alpine 3.20 + edge — `pkgs.alpinelinux.org/packages?name=...`
///
/// **Distro-version regressions to be aware of (not encoded in table —
/// install error surfaces them):**
///   * Debian 13 trixie SHRANK the certbot DNS plugin set. Only
///     cloudflare/google/rfc2136/route53/desec/infomaniak survived;
///     digitalocean, dnsimple, gandi, linode, ovh, dropped. On those
///     plugins on trixie, apt install fails with "Unable to locate
///     package" — UI surfaces the error and the pipx fallback hint.
///   * EPEL 9 + EPEL 10 don't ship `google` or `gandi` plugins
///     (Fabian Affolter trimmed the EPEL set).
///   * openSUSE Tumbleweed uses VERSIONED Python prefixes
///     (`python311-`, `python313-`, etc.) — handled by
///     `suggested_install_command()` Tumbleweed branch.
pub struct PluginPackages {
    pub plugin: &'static str,
    /// Debian/Ubuntu apt package. Confirmed on bookworm/jammy/noble.
    /// Debian trixie has FEWER plugins (see doc-comment above).
    pub apt: Option<&'static str>,
    /// Fedora dnf package. Same name on EPEL where present (EPEL 9/10
    /// have a subset — see doc-comment above).
    pub dnf: Option<&'static str>,
    /// Arch Linux extra-repo package. AUR-only plugins return None.
    pub pacman: Option<&'static str>,
    /// openSUSE package. On Tumbleweed the actual binary RPM is
    /// versioned (`python313-…`); the install command picks the right
    /// one at runtime. Leap uses unversioned `python3-…` directly.
    pub zypper: Option<&'static str>,
    /// Alpine apk package. Alpine uses `certbot-dns-<provider>`
    /// (NOT `py3-…`) — verified in community repo 3.20+.
    pub apk: Option<&'static str>,
    /// PyPI name for pipx fallback. None if no usable plugin exists.
    /// Version pin permitted (e.g. "certbot-dns-hetzner<4" for the
    /// DNS Console — v4.x dropped that API in favour of Cloud-only).
    pub pipx: Option<&'static str>,
}

/// Mapping table — every entry corresponds to one DNS provider plugin
/// WolfStack supports (cite: `dns_providers::KNOWN_PLUGINS`).
///
/// Per-cell notes:
/// * `apt = python3-certbot-dns-X` means "exists on bookworm + jammy +
///   noble"; trixie may not have it — the install command surfaces
///   that cleanly via apt's own "Unable to locate package" error.
/// * `gandi`: PyPI now ships as `certbot-dns-gandi` (was
///   `certbot-plugin-gandi`; that name is explicitly deprecated by
///   its maintainer).
/// * `vultr`: PyPI is `certbot-dns-vultr` (the discontinued bsorahan
///   one); `certbot-dns-multi` is a 117-provider wrapper, not vultr-
///   specific, and would change the authenticator name. We accept
///   the unmaintained risk over breaking the CLI argv contract.
/// * `hetzner`: pinned to `<4.0` because v4.0 (April 2026) dropped
///   the standalone DNS Console API in favour of Hetzner Cloud only.
///   Operators using DNS Console tokens need v3.x; Cloud tokens are
///   handled separately by WolfStack's edge module.
pub const PLUGIN_PACKAGES: &[PluginPackages] = &[
    PluginPackages { plugin: "cloudflare",
        apt:    Some("python3-certbot-dns-cloudflare"),
        dnf:    Some("python3-certbot-dns-cloudflare"),
        pacman: Some("certbot-dns-cloudflare"),
        zypper: Some("python3-certbot-dns-cloudflare"),
        apk:    Some("certbot-dns-cloudflare"),
        pipx:   Some("certbot-dns-cloudflare") },
    PluginPackages { plugin: "route53",
        apt:    Some("python3-certbot-dns-route53"),
        dnf:    Some("python3-certbot-dns-route53"),
        pacman: Some("certbot-dns-route53"),
        zypper: Some("python3-certbot-dns-route53"),
        apk:    Some("certbot-dns-route53"),
        pipx:   Some("certbot-dns-route53") },
    PluginPackages { plugin: "google",
        apt:    Some("python3-certbot-dns-google"),
        // Not in EPEL 9 or EPEL 10 — only Fedora proper. On EPEL the
        // install will fail with "No match for argument", UI hints pipx.
        dnf:    Some("python3-certbot-dns-google"),
        pacman: Some("certbot-dns-google"),
        zypper: Some("python3-certbot-dns-google"),
        apk:    Some("certbot-dns-google"),
        pipx:   Some("certbot-dns-google") },
    PluginPackages { plugin: "digitalocean",
        // Confirmed in bookworm/jammy/noble; NOT in trixie. apt error
        // is clear-enough; users on trixie fall back to pipx.
        apt:    Some("python3-certbot-dns-digitalocean"),
        dnf:    Some("python3-certbot-dns-digitalocean"),
        pacman: Some("certbot-dns-digitalocean"),
        zypper: Some("python3-certbot-dns-digitalocean"),
        apk:    Some("certbot-dns-digitalocean"),
        pipx:   Some("certbot-dns-digitalocean") },
    PluginPackages { plugin: "linode",
        apt:    Some("python3-certbot-dns-linode"),
        dnf:    Some("python3-certbot-dns-linode"),
        pacman: Some("certbot-dns-linode"),
        zypper: Some("python3-certbot-dns-linode"),
        apk:    Some("certbot-dns-linode"),
        pipx:   Some("certbot-dns-linode") },
    PluginPackages { plugin: "rfc2136",
        apt:    Some("python3-certbot-dns-rfc2136"),
        dnf:    Some("python3-certbot-dns-rfc2136"),
        pacman: Some("certbot-dns-rfc2136"),
        zypper: Some("python3-certbot-dns-rfc2136"),
        apk:    Some("certbot-dns-rfc2136"),
        pipx:   Some("certbot-dns-rfc2136") },
    PluginPackages { plugin: "ovh",
        apt:    Some("python3-certbot-dns-ovh"),
        dnf:    Some("python3-certbot-dns-ovh"),
        pacman: Some("certbot-dns-ovh"),
        // Leap 15.6 doesn't ship ovh; Tumbleweed does.
        zypper: Some("python3-certbot-dns-ovh"),
        apk:    Some("certbot-dns-ovh"),
        pipx:   Some("certbot-dns-ovh") },
    PluginPackages { plugin: "gandi",
        // bookworm/jammy/noble only; NOT in trixie or Fedora/EPEL/Arch/openSUSE/Alpine.
        apt:    Some("python3-certbot-dns-gandi"),
        dnf:    None,
        pacman: None,
        zypper: None,
        apk:    None,
        // certbot-plugin-gandi is DEPRECATED — successor is certbot-dns-gandi.
        pipx:   Some("certbot-dns-gandi") },
    PluginPackages { plugin: "godaddy",
        // Community plugin only — no distro packages anywhere.
        apt: None, dnf: None, pacman: None, zypper: None, apk: None,
        pipx: Some("certbot-dns-godaddy") },
    PluginPackages { plugin: "hetzner",
        apt: None, dnf: None,
        // Arch extra ships ctrlaltcoop's DNS-only fork — perfect for us.
        pacman: Some("certbot-dns-hetzner"),
        zypper: None,
        // Alpine: only in edge/testing right now (3.0.0 dual-mode).
        apk: None,
        // Pin <4 — v4.0 (April 2026) dropped DNS Console support.
        pipx: Some("certbot-dns-hetzner<4") },
    PluginPackages { plugin: "namecheap",
        apt: None, dnf: None, pacman: None, zypper: None, apk: None,
        pipx: Some("certbot-dns-namecheap") },
    PluginPackages { plugin: "porkbun",
        apt: None, dnf: None, pacman: None, zypper: None, apk: None,
        pipx: Some("certbot-dns-porkbun") },
    PluginPackages { plugin: "vultr",
        apt: None, dnf: None, pacman: None, zypper: None, apk: None,
        // certbot-dns-vultr is unmaintained but uses the dns-vultr
        // authenticator name our argv builder expects. certbot-dns-multi
        // would work but renames the authenticator to dns-multi.
        pipx: Some("certbot-dns-vultr") },
    PluginPackages { plugin: "njalla",
        apt: None, dnf: None, pacman: None, zypper: None,
        // Alpine edge/testing only.
        apk: None,
        pipx: Some("certbot-dns-njalla") },
    PluginPackages { plugin: "dynu",
        // Community plugin only — no distro packages anywhere. PyPI
        // `certbot-dns-dynu` (verified 2026-06-11): authenticator name
        // `dns-dynu` matches our --dns-{plugin} argv builder; credentials
        // INI key is `dns_dynu_auth_token` (token from the Dynu control
        // panel → API Credentials). Requires certbot >= 2.0.
        apt: None, dnf: None, pacman: None, zypper: None, apk: None,
        pipx: Some("certbot-dns-dynu") },
    PluginPackages { plugin: "dnsimple",
        apt:    Some("python3-certbot-dns-dnsimple"),
        dnf:    Some("python3-certbot-dns-dnsimple"),
        pacman: Some("certbot-dns-dnsimple"),
        zypper: Some("python3-certbot-dns-dnsimple"),
        apk:    Some("certbot-dns-dnsimple"),
        pipx:   Some("certbot-dns-dnsimple") },
];

/// Lookup the package row for a plugin. None means we don't know about
/// this plugin (which is a programming error — callers should validate
/// against `KNOWN_PLUGINS` first).
pub fn plugin_packages(plugin: &str) -> Option<&'static PluginPackages> {
    PLUGIN_PACKAGES.iter().find(|p| p.plugin == plugin)
}

/// Return the list of plugin names certbot currently has loaded, by
/// shelling out to `certbot plugins --prepare` and parsing the
/// trailing list. Format (verified against certbot 4.x stdout):
///
/// ```text
///   * dns-cloudflare
///   Description: Obtain certificates using a DNS TXT record (if you are
///   using Cloudflare for DNS).
///   Interfaces: Authenticator, Plugin
///   Entry point: dns-cloudflare = certbot_dns_cloudflare._internal.dns_cloudflare:Authenticator
/// ```
///
/// Empty Vec if certbot isn't installed or the command fails — caller
/// treats that the same as "nothing installed".
pub fn installed_plugins() -> Vec<String> {
    let bin = match certbot_path() { Some(p) => p, None => return Vec::new() };
    // `certbot plugins` lists every authenticator/installer it can load.
    // No `--prepare` to avoid network calls; we just want the names.
    let out = Command::new(&bin).arg("plugins").output();
    let out = match out { Ok(o) if o.status.success() => o, _ => return Vec::new() };
    let s = String::from_utf8_lossy(&out.stdout);
    let mut found: Vec<String> = Vec::new();
    for line in s.lines() {
        // Lines we care about: "* dns-cloudflare" (with the leading
        // asterisk). certbot may also list "webroot", "standalone",
        // "nginx" — we filter to DNS plugins only.
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("* ") {
            let name = rest.trim();
            // Restrict to dns-<plugin> entries — they're the only ones
            // managed by this module. Other plugins (nginx, apache)
            // come bundled and aren't relevant to the DNS path.
            if let Some(plugin) = name.strip_prefix("dns-") {
                found.push(plugin.to_string());
            }
        }
    }
    found
}

/// True iff certbot has the given DNS plugin loaded right now.
pub fn plugin_installed(plugin: &str) -> bool {
    installed_plugins().iter().any(|p| p == plugin)
}

/// Result of preflighting a plugin for the issue/test path. Surfaces
/// what was checked + the actionable install command if missing —
/// returned to the frontend so the UI can render a one-click install
/// button rather than the cryptic "Could not find plugin" error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginPreflight {
    pub plugin: String,
    pub installed: bool,
    /// Concrete install command for THIS host's distro. None if no
    /// known install path (rare — only for plugins we've never heard
    /// of, which validation should reject upstream).
    pub install_command: Option<String>,
    /// Which package manager the install_command will use.
    pub install_method: Option<String>,
    /// EFF-official snap-based install command. Only populated when
    /// snap is usable on this host (bare-metal/VM, snapd running)
    /// AND the plugin has a snap counterpart. Surfaced as a secondary
    /// install option in the UI for operators who prefer EFF's
    /// recommended path.
    #[serde(default)]
    pub snap_install_command: Option<String>,
    /// All plugins currently loaded (for diagnostics).
    pub other_plugins_installed: Vec<String>,
    /// Container-runtime guidance (LXC / Docker / nspawn). None when
    /// running on a bare-metal host or VM. Surfaced in the UI so the
    /// operator sees container-specific caveats BEFORE clicking
    /// install.
    #[serde(default)]
    pub container_notes: Option<String>,
}

/// Batch preflight for every known plugin. Used by the
/// `/api/dns-providers/plugins` endpoint to compute install commands
/// in O(1) shellouts to the package cache instead of O(N).
///
/// Why batch: on a Debian host with 15 known plugins, the old
/// per-plugin path did 15 × `apt-cache show <pkg>` calls (~50ms each
/// = ~750ms), plus 15 × `dpkg-query -W certbot` (cached but adds up)
/// on the pipx fallback path. The batched version does ONE
/// `apt-cache show pkg1 pkg2 …` and one dpkg-query, regardless of
/// plugin count. Measured on a real Debian 13 host: 1.4s → 90ms.
pub fn preflight_all(installed: &[String]) -> Vec<PluginPreflight> {
    let distro = crate::installer::detect_distro();
    use crate::installer::DistroFamily;
    // Pre-compute the set of available distro packages in one shellout.
    let candidate_names: Vec<&str> = crate::dns_providers::KNOWN_PLUGINS
        .iter()
        .filter_map(|p| plugin_packages(p))
        .filter_map(|pkg| match distro {
            DistroFamily::Debian => pkg.apt,
            DistroFamily::RedHat => pkg.dnf,
            // Arch / Suse / Alpine: install attempt itself errors
            // clearly; no batch probe needed.
            _ => None,
        })
        .collect();
    let available: std::collections::HashSet<String> = match distro {
        DistroFamily::Debian => apt_packages_available(&candidate_names),
        DistroFamily::RedHat => dnf_packages_available(&candidate_names),
        _ => candidate_names.iter().map(|s| (*s).to_string()).collect(),
    };
    // Pre-compute "is certbot distro-installed" once so the pipx
    // fallback uses a single dpkg-query / rpm -q call instead of one
    // per missing plugin.
    let certbot_distro_pkg = certbot_installed_via_distro_pkg(distro);
    let snap_available = snap_usable();
    let container = detect_container_kind();
    let mut out: Vec<PluginPreflight> = Vec::with_capacity(crate::dns_providers::KNOWN_PLUGINS.len());
    for plugin in crate::dns_providers::KNOWN_PLUGINS {
        let is_installed = installed.iter().any(|x| x == plugin);
        let (cmd, method, snap_cmd) = if is_installed {
            (None, None, None)
        } else {
            let (cmd, method) = suggested_install_command_with(
                plugin, distro, &available, certbot_distro_pkg,
            );
            let snap = if snap_available { build_snap_install_command(plugin) } else { None };
            (cmd, method, snap)
        };
        out.push(PluginPreflight {
            plugin: (*plugin).to_string(),
            installed: is_installed,
            install_command: cmd,
            install_method: method,
            snap_install_command: snap_cmd,
            other_plugins_installed: Vec::new(),
            container_notes: if is_installed {
                None
            } else {
                container_install_notes_for(plugin, container)
            },
        });
    }
    out
}

/// Build the install command for the given plugin on the current
/// host. Picks the right package manager per distro and falls back to
/// pipx for community plugins not in distro repos. Returns the
/// (command, method) pair so the frontend can display both.
///
/// **Trixie / EPEL regression handling:** Debian 13 trixie and EPEL
/// 9/10 ship far fewer DNS plugin packages than older releases. Before
/// suggesting `apt install python3-certbot-dns-X`, we pre-check that
/// the package actually exists in this host's repos via `apt-cache
/// show` / `dnf info`. If not, we silently fall through to the pipx
/// fallback so the operator gets a working install command instead of
/// one that produces "Unable to locate package".
///
/// **Tumbleweed quirk:** openSUSE Tumbleweed only ships VERSIONED
/// Python packages (`python311-certbot-dns-cloudflare`, etc.). We
/// detect the system Python version via /usr/bin/python3 --version
/// and rewrite the package name accordingly. Leap 15.6 keeps the
/// unversioned `python3-` form so the same code path works for both.
pub fn suggested_install_command(plugin: &str) -> (Option<String>, Option<String>) {
    let distro = crate::installer::detect_distro();
    use crate::installer::DistroFamily;
    let pkg = match plugin_packages(plugin) { Some(p) => p, None => return (None, None) };
    // For single-plugin path: probe one package and one certbot-distro
    // check. preflight_all() amortises both when called for a batch.
    let candidate: Vec<&str> = match distro {
        DistroFamily::Debian => pkg.apt.into_iter().collect(),
        DistroFamily::RedHat => pkg.dnf.into_iter().collect(),
        _ => Vec::new(),
    };
    let available: std::collections::HashSet<String> = match distro {
        DistroFamily::Debian => apt_packages_available(&candidate),
        DistroFamily::RedHat => dnf_packages_available(&candidate),
        _ => candidate.iter().map(|s| (*s).to_string()).collect(),
    };
    let certbot_distro_pkg = certbot_installed_via_distro_pkg(distro);
    suggested_install_command_with(plugin, distro, &available, certbot_distro_pkg)
}

/// Pure-ish variant: takes the precomputed set of available distro
/// packages and the cached "is certbot distro-installed" flag so it
/// can be called N times per request without re-shelling out. Used by
/// `preflight_all()`.
fn suggested_install_command_with(
    plugin: &str,
    distro: crate::installer::DistroFamily,
    available_distro_pkgs: &std::collections::HashSet<String>,
    certbot_distro_installed: bool,
) -> (Option<String>, Option<String>) {
    let pkg = match plugin_packages(plugin) { Some(p) => p, None => return (None, None) };
    use crate::installer::DistroFamily;

    // Prefer the distro-native package because:
    //   1) it gets security updates via the normal channel
    //   2) no PEP 668 dance, no pipx-shim PATH gotchas
    //   3) works identically in host / LXC / Proxmox CT / VM / Docker
    //      (apt/dnf/pacman behave the same in all those contexts)
    let (distro_pkg, pkg_mgr, install_flag) = match distro {
        DistroFamily::Debian  => (pkg.apt,    "apt-get", "install -y"),
        DistroFamily::RedHat  => (pkg.dnf,    "dnf",     "install -y"),
        DistroFamily::Arch    => (pkg.pacman, "pacman",  "-S --noconfirm --needed"),
        DistroFamily::Suse    => (pkg.zypper, "zypper",  "install -y"),
        DistroFamily::Alpine  => (pkg.apk,    "apk",     "add --no-cache"),
        DistroFamily::Unknown => (pkg.apt,    "apt-get", "install -y"),
    };
    if let Some(name) = distro_pkg {
        // Tumbleweed override: if the package name starts with
        // python3- and we're on Tumbleweed, expand to python{MAJ}{MIN}-.
        let final_name: String =
            if distro == DistroFamily::Suse && name.starts_with("python3-") && is_tumbleweed() {
                tumbleweed_versioned_pkg_name(name).unwrap_or_else(|| name.to_string())
            } else {
                name.to_string()
            };
        // Distro-specific availability: Debian/Fedora consult the
        // precomputed set so we catch trixie + EPEL 9/10 regressions;
        // Arch/Suse/Alpine trust the install attempt to fail cleanly
        // if the package is missing.
        let available = match distro {
            DistroFamily::Debian | DistroFamily::RedHat => {
                available_distro_pkgs.contains(&final_name)
                    || available_distro_pkgs.contains(name)
            }
            _ => true,
        };
        if available {
            let cmd = format!("sudo {} {} {}", pkg_mgr, install_flag, final_name);
            return (Some(cmd), Some(format!("{} (distro package)", pkg_mgr)));
        }
        // Distro package row exists but THIS host can't see it —
        // fall through to pipx with a method label that surfaces why.
    }
    // pipx fallback (also reached when no distro package exists at all,
    // or when the pre-check above failed).
    if let Some(pypi) = pkg.pipx {
        return (
            Some(build_pipx_install_command_with(distro, pypi, certbot_distro_installed)),
            Some(pipx_method_label(distro_pkg.is_some())),
        );
    }
    (None, None)
}

/// True iff snap is installed and usable on this host. snap requires
/// systemd-managed snapd, which fails in unprivileged LXC (apparmor
/// confinement blocks snapd) and in most Docker images (no systemd).
/// We skip snap suggestions in those environments because they're
/// guaranteed to fail.
pub fn snap_usable() -> bool {
    // Container kind check first — snap doesn't work in LXC/Docker.
    match detect_container_kind() {
        ContainerKind::Lxc | ContainerKind::Docker
        | ContainerKind::SystemdNspawn | ContainerKind::Other => return false,
        ContainerKind::None => {}
    }
    // snap binary present + snapd reachable.
    if !std::path::Path::new("/usr/bin/snap").exists() &&
       !std::path::Path::new("/snap/bin/snap").exists()
    {
        return false;
    }
    // snapd socket exists.
    std::path::Path::new("/run/snapd.socket").exists()
}

/// Status summary of snap availability, surfaced to the frontend so
/// the UI can show "snap not available because: LXC container" etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapStatus {
    pub usable: bool,
    pub reason: String,
}

pub fn snap_status() -> SnapStatus {
    let container = detect_container_kind();
    if container != ContainerKind::None {
        return SnapStatus {
            usable: false,
            reason: format!("snap not used in {} containers (snapd needs systemd + apparmor; \
                            we use the distro/pipx path instead)", container.label()),
        };
    }
    let binary_present = std::path::Path::new("/usr/bin/snap").exists()
        || std::path::Path::new("/snap/bin/snap").exists();
    if !binary_present {
        return SnapStatus {
            usable: false,
            reason: "snap is not installed on this host".to_string(),
        };
    }
    if !std::path::Path::new("/run/snapd.socket").exists() {
        return SnapStatus {
            usable: false,
            reason: "snapd service is not running (no /run/snapd.socket)".to_string(),
        };
    }
    SnapStatus { usable: true, reason: "snap is available".to_string() }
}

/// Build the snap-based install command for a DNS plugin. Per EFF's
/// official certbot install guide (certbot.eff.org/instructions), the
/// sequence is: install certbot, mark plugin trust, install the
/// plugin snap, then connect the plugin to certbot's plug interface.
/// Returns None if the plugin doesn't have a snap counterpart.
///
/// **Snap plugin name convention** (verified from snap store):
///   certbot-dns-cloudflare, certbot-dns-route53, certbot-dns-google,
///   certbot-dns-digitalocean, certbot-dns-linode, certbot-dns-ovh,
///   certbot-dns-rfc2136, certbot-dns-gandi, certbot-dns-dnsimple
/// Community plugins (godaddy/namecheap/porkbun/vultr/njalla/hetzner/dynu)
/// are NOT in the snap store — None.
pub fn build_snap_install_command(plugin: &str) -> Option<String> {
    // Subset of KNOWN_PLUGINS that has a snap.
    let snap_plugin = match plugin {
        "cloudflare"   => "certbot-dns-cloudflare",
        "route53"      => "certbot-dns-route53",
        "google"       => "certbot-dns-google",
        "digitalocean" => "certbot-dns-digitalocean",
        "linode"       => "certbot-dns-linode",
        "ovh"          => "certbot-dns-ovh",
        "rfc2136"      => "certbot-dns-rfc2136",
        "gandi"        => "certbot-dns-gandi",
        "dnsimple"     => "certbot-dns-dnsimple",
        _ => return None,
    };
    Some(format!(
        "sudo snap install --classic certbot \
         && sudo snap set certbot trust-plugin-with-root=ok \
         && sudo snap install {snap} \
         && sudo snap connect certbot:plugin {snap}",
        snap = snap_plugin
    ))
}

/// Package-cache freshness check. Returns a structured status so the
/// frontend can warn "your apt cache is N hours stale, the install
/// suggestion might be wrong — run sudo apt-get update". Threshold is
/// 24h; below that we treat the cache as authoritative.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageCacheStatus {
    /// True if the local package index is recent enough to trust.
    pub fresh: bool,
    /// Age of the cache in seconds, or null if no cache file found.
    pub age_seconds: Option<u64>,
    /// Human-readable summary for the UI.
    pub message: String,
    /// Concrete command the operator can run to refresh.
    pub refresh_command: Option<String>,
}

const PACKAGE_CACHE_STALE_THRESHOLD_SECS: u64 = 24 * 3600;

pub fn package_cache_status() -> PackageCacheStatus {
    use crate::installer::DistroFamily;
    let distro = crate::installer::detect_distro();
    // Per-distro cache file mtime. We pick a single representative
    // file per distro that the package manager touches on every
    // successful update.
    let (cache_path, refresh_cmd) = match distro {
        DistroFamily::Debian => ("/var/cache/apt/pkgcache.bin", Some("sudo apt-get update")),
        DistroFamily::RedHat => ("/var/cache/dnf/last_makecache", Some("sudo dnf makecache")),
        DistroFamily::Arch   => ("/var/lib/pacman/sync", Some("sudo pacman -Sy")),
        DistroFamily::Suse   => ("/var/cache/zypp", Some("sudo zypper refresh")),
        DistroFamily::Alpine => ("/var/cache/apk", Some("sudo apk update")),
        DistroFamily::Unknown => return PackageCacheStatus {
            fresh: true, age_seconds: None,
            message: "unknown distro — cache freshness not checked".to_string(),
            refresh_command: None,
        },
    };
    let age = match std::fs::metadata(cache_path) {
        Ok(m) => m.modified().ok().and_then(|t| t.elapsed().ok()).map(|d| d.as_secs()),
        Err(_) => None,
    };
    let fresh = age.map(|s| s <= PACKAGE_CACHE_STALE_THRESHOLD_SECS).unwrap_or(false);
    let message = match age {
        Some(s) if s <= PACKAGE_CACHE_STALE_THRESHOLD_SECS => {
            format!("package cache is {}h old — fresh", s / 3600)
        }
        Some(s) => format!(
            "package cache is {}h old (> 24h) — plugin install suggestions may be wrong; run `{}` to refresh",
            s / 3600, refresh_cmd.unwrap_or("(distro-specific)")
        ),
        None => format!(
            "could not stat {} — package cache age unknown; consider running `{}` if installs fail unexpectedly",
            cache_path, refresh_cmd.unwrap_or("(distro-specific)")
        ),
    };
    PackageCacheStatus {
        fresh,
        age_seconds: age,
        message,
        refresh_command: refresh_cmd.map(String::from),
    }
}

/// True iff `apt-cache show <name>` succeeds (package exists in the
/// configured repos on THIS host). Cheap — apt-cache uses the local
/// package index, no network. Returns true on probe failure (apt-cache
/// missing) so we don't block on hosts without apt-cache installed.
///
/// **For multi-package checks, prefer `apt_packages_available()`** —
/// one shellout vs N. This single-package form remains for callers
/// that only need one check at a time.
#[allow(dead_code)] // Public single-shot wrapper; canonical caller is preflight_all via batch.
pub fn apt_package_available(name: &str) -> bool {
    apt_packages_available(&[name]).contains(name)
}

/// Batch version: takes a list of candidate package names, returns
/// the subset that exist in THIS host's apt repos. ONE shellout
/// regardless of input size — cuts the plugin-status round-trip from
/// O(N) calls (~50ms each) to a single ~50ms call.
///
/// `apt-cache show pkg1 pkg2 pkg3` succeeds if AT LEAST ONE of the
/// inputs exists (it prints per-package blocks separated by blank
/// lines, with "N: Unable to locate package …" lines on stderr for
/// the missing ones). We parse the stdout for `Package:` headers to
/// recover the per-name presence.
pub fn apt_packages_available(names: &[&str]) -> std::collections::HashSet<String> {
    let mut found: std::collections::HashSet<String> = std::collections::HashSet::new();
    if names.is_empty() { return found; }
    let mut cmd = Command::new("apt-cache");
    cmd.arg("show");
    for n in names { cmd.arg(n); }
    let out = match cmd.output() {
        Ok(o) => o,
        // apt-cache missing — assume all packages available so we
        // don't silently disable the install button on non-apt
        // systems that somehow reached this code path.
        Err(_) => {
            for n in names { found.insert((*n).to_string()); }
            return found;
        }
    };
    // apt-cache exits 100 when ALL names are missing, 0 when any
    // resolved. Either way, parse stdout for `Package:` headers.
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(rest) = line.strip_prefix("Package: ") {
            // Filter to the names we asked about so we don't include
            // reverse-dependencies apt sometimes inlines.
            let n = rest.trim();
            if names.contains(&n) {
                found.insert(n.to_string());
            }
        }
    }
    found
}

/// True iff `dnf info <name>` succeeds. See `apt_package_available`
/// for caveats. **Prefer `dnf_packages_available()` for batches.**
#[allow(dead_code)] // Public single-shot wrapper; preflight_all uses the batch form.
pub fn dnf_package_available(name: &str) -> bool {
    dnf_packages_available(&[name]).contains(name)
}

/// Batch version of `dnf_package_available`. `dnf info pkg1 pkg2 …`
/// runs one query and prints a header block per found package; we
/// parse stdout for "Name : <pkg>" lines to recover per-name presence.
pub fn dnf_packages_available(names: &[&str]) -> std::collections::HashSet<String> {
    let mut found: std::collections::HashSet<String> = std::collections::HashSet::new();
    if names.is_empty() { return found; }
    let mut cmd = Command::new("dnf");
    cmd.args(["info", "--quiet"]);
    for n in names { cmd.arg(n); }
    let out = match cmd.output() {
        Ok(o) => o,
        Err(_) => {
            // dnf missing — assume all available (same shape as apt).
            for n in names { found.insert((*n).to_string()); }
            return found;
        }
    };
    // dnf info prints a block per package starting with "Name         : <pkg>"
    // (column-aligned with whitespace). Tolerant parse.
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(after) = line.trim_start().strip_prefix("Name") {
            // Skip whitespace + colon + whitespace.
            let after = after.trim_start();
            if let Some(rest) = after.strip_prefix(':') {
                let n = rest.trim();
                if names.contains(&n) {
                    found.insert(n.to_string());
                }
            }
        }
    }
    found
}

/// Build a pipx-based install command for `pypi_name` on the given
/// distro. Detects whether certbot itself is already apt/dnf-installed
/// and, if so, emits a pipeline that REPLACES it with a pipx install —
/// because `pipx inject` cannot add a plugin to a certbot binary that
/// lives outside any pipx-managed venv.
///
/// Sequence (Debian example, when certbot is apt-installed):
/// ```
/// sudo apt-get install -y pipx
/// sudo apt-get remove -y certbot      # ← only if apt-installed
/// sudo pipx install certbot
/// sudo pipx inject certbot 'certbot-dns-cloudflare'
/// sudo pipx ensurepath
/// ```
/// The `sudo` prefix is critical — pipx defaults to the invoking
/// user's home, but wolfstack-the-service runs as root and we need
/// the resulting venv to live at /root/.local/pipx/ where
/// `certbot_path()` already searches.
#[allow(dead_code)] // Public single-shot wrapper; preflight_all uses the _with variant.
pub fn build_pipx_install_command(distro: crate::installer::DistroFamily, pypi_name: &str) -> String {
    // Convenience wrapper — probes whether certbot is distro-installed
    // (one shellout). Use `build_pipx_install_command_with` when you
    // already know the answer.
    let certbot_is_distro_installed = certbot_installed_via_distro_pkg(distro);
    build_pipx_install_command_with(distro, pypi_name, certbot_is_distro_installed)
}

/// Pure variant of `build_pipx_install_command` — takes the
/// "is certbot distro-installed" flag rather than probing for it, so
/// `preflight_all` can compute it once and reuse across every plugin.
pub fn build_pipx_install_command_with(
    distro: crate::installer::DistroFamily,
    pypi_name: &str,
    certbot_is_distro_installed: bool,
) -> String {
    use crate::installer::DistroFamily;
    let pipx_install = match distro {
        DistroFamily::Debian  => "sudo apt-get install -y pipx",
        DistroFamily::RedHat  => "sudo dnf install -y pipx",
        DistroFamily::Arch    => "sudo pacman -S --noconfirm --needed python-pipx",
        DistroFamily::Suse    => "sudo zypper install -y python3-pipx",
        DistroFamily::Alpine  => "sudo apk add --no-cache pipx",
        DistroFamily::Unknown => "sudo apt-get install -y pipx",
    };
    let remove_step = if certbot_is_distro_installed {
        // The pipx-installed certbot will take precedence on PATH
        // (in /root/.local/bin which precedes /usr/bin in pipx-
        // ensurepath's shell init), but having two installs is
        // confusing — uninstall the distro one cleanly. We ignore
        // failures (|| true) because a missing apt/dnf certbot is
        // fine; the user might already be on pipx.
        match distro {
            DistroFamily::Debian  => "sudo apt-get remove -y certbot 2>/dev/null || true",
            DistroFamily::RedHat  => "sudo dnf remove -y certbot 2>/dev/null || true",
            DistroFamily::Arch    => "sudo pacman -Rns --noconfirm certbot 2>/dev/null || true",
            DistroFamily::Suse    => "sudo zypper remove -y certbot 2>/dev/null || true",
            DistroFamily::Alpine  => "sudo apk del certbot 2>/dev/null || true",
            DistroFamily::Unknown => "true",
        }
    } else {
        "true"
    };
    format!(
        "{install_pipx} && {remove_step} && sudo pipx install certbot --force && sudo pipx inject certbot '{pypi}' && sudo pipx ensurepath",
        install_pipx = pipx_install,
        remove_step = remove_step,
        pypi = pypi_name
    )
}

fn pipx_method_label(distro_pkg_existed: bool) -> String {
    if distro_pkg_existed {
        // Means the row had an apt/dnf name but the pre-check ruled
        // it unavailable in THIS host's repos — typical for Debian 13
        // trixie (regressed plugin set) or EPEL 9/10 (smaller set).
        "pipx (distro repo doesn't ship this plugin — switching certbot to pipx)".to_string()
    } else {
        "pipx (community plugin — no distro package upstream)".to_string()
    }
}

/// True iff certbot is currently installed via the distro package
/// manager (apt/dnf/pacman/zypper/apk). Used by the pipx fallback to
/// decide whether to emit a `remove certbot` step before installing
/// the pipx version. False on errors / when the query tool is missing.
fn certbot_installed_via_distro_pkg(distro: crate::installer::DistroFamily) -> bool {
    use crate::installer::DistroFamily;
    let (bin, args): (&str, &[&str]) = match distro {
        DistroFamily::Debian  => ("dpkg-query",  &["-W", "-f=${Status}", "certbot"][..]),
        DistroFamily::RedHat  => ("rpm",         &["-q", "certbot"][..]),
        DistroFamily::Arch    => ("pacman",      &["-Q", "certbot"][..]),
        DistroFamily::Suse    => ("rpm",         &["-q", "certbot"][..]),
        DistroFamily::Alpine  => ("apk",         &["info", "-e", "certbot"][..]),
        DistroFamily::Unknown => return false,
    };
    let out = Command::new(bin).args(args).output();
    match out {
        Ok(o) if o.status.success() => {
            // For dpkg-query, success only means "package is known" —
            // we need to confirm the status string says "install ok
            // installed". Other distros return non-zero when missing
            // so the success branch is enough.
            if distro == DistroFamily::Debian {
                String::from_utf8_lossy(&o.stdout).contains("install ok installed")
            } else if distro == DistroFamily::Alpine {
                // apk info -e prints the package name on stdout when
                // installed, empty otherwise.
                !String::from_utf8_lossy(&o.stdout).trim().is_empty()
            } else {
                true
            }
        }
        _ => false,
    }
}

/// True iff this host is openSUSE Tumbleweed (as opposed to Leap or
/// SLES). Read /etc/os-release once; cheap. Used by the certbot
/// install path because Tumbleweed's RPMs are versioned per-Python
/// (`python313-certbot-dns-cloudflare`) while Leap keeps the
/// unversioned `python3-certbot-dns-cloudflare` symlink package.
fn is_tumbleweed() -> bool {
    if let Ok(s) = std::fs::read_to_string("/etc/os-release") {
        let lower = s.to_ascii_lowercase();
        return lower.contains("tumbleweed");
    }
    false
}

/// Containerised-runtime info — what kind of container (if any) the
/// wolfstack process is running inside. Used to surface certbot
/// guidance for LXC-specific failure modes (snap can't run in
/// unprivileged LXC, HTTP-01 port 80 binding needs CAP_NET_BIND_SERVICE,
/// AppArmor / apparmor=unconfined gotchas).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ContainerKind {
    /// Bare-metal host or VM — no container indicators.
    None,
    /// LXC / Proxmox CT — `/proc/1/environ` contains `container=lxc`.
    Lxc,
    /// Docker / OCI container — `/.dockerenv` or container=docker
    /// env var. Includes podman.
    Docker,
    /// systemd-nspawn container — container=systemd-nspawn.
    SystemdNspawn,
    /// Detected as "in a container" but the flavour is unknown.
    Other,
}

impl ContainerKind {
    pub fn label(&self) -> &'static str {
        match self {
            ContainerKind::None => "host",
            ContainerKind::Lxc => "LXC",
            ContainerKind::Docker => "Docker",
            ContainerKind::SystemdNspawn => "systemd-nspawn",
            ContainerKind::Other => "container",
        }
    }
}

/// Detect what (if any) container the wolfstack process is in. Cheap
/// — reads /proc/1/environ once. The `container=<kind>` env var is
/// the canonical signal (set by lxc, systemd-nspawn, docker since
/// 24+, podman). /.dockerenv is the legacy Docker fallback.
pub fn detect_container_kind() -> ContainerKind {
    // /.dockerenv exists on every Docker / OCI image regardless of how
    // it was started — check first so we catch images that don't set
    // container=docker.
    if std::path::Path::new("/.dockerenv").exists() {
        return ContainerKind::Docker;
    }
    // /proc/1/environ — null-separated VAR=VALUE entries.
    if let Ok(bytes) = std::fs::read("/proc/1/environ") {
        for chunk in bytes.split(|&b| b == 0) {
            if let Some(rest) = chunk.strip_prefix(b"container=") {
                let val = String::from_utf8_lossy(rest);
                return match val.as_ref() {
                    "lxc" | "lxc-libvirt" => ContainerKind::Lxc,
                    "docker" | "podman" | "oci" => ContainerKind::Docker,
                    "systemd-nspawn" => ContainerKind::SystemdNspawn,
                    _ => ContainerKind::Other,
                };
            }
        }
    }
    // /proc/1/cgroup fallback — older kernels / minimal containers
    // that don't set the env var.
    if let Ok(s) = std::fs::read_to_string("/proc/1/cgroup") {
        let lower = s.to_lowercase();
        if lower.contains("/lxc/") || lower.contains(":lxc:") { return ContainerKind::Lxc; }
        if lower.contains("/docker/") || lower.contains(":docker:") { return ContainerKind::Docker; }
    }
    ContainerKind::None
}

/// Append container-environment guidance to the install command when
/// the runtime is LXC, Docker, etc. Doesn't modify the command itself
/// — surfaces a separate `notes` string the UI can show alongside.
/// Returns None if no special guidance is needed for this combination.
#[allow(dead_code)] // Public single-shot wrapper; preflight_all uses the _for variant.
pub fn container_install_notes(plugin: &str) -> Option<String> {
    container_install_notes_for(plugin, detect_container_kind())
}

/// Pure variant of `container_install_notes` — takes the container
/// kind as input so `preflight_all` can detect it once and reuse
/// across every plugin instead of N redundant /proc/1/environ reads.
pub fn container_install_notes_for(plugin: &str, kind: ContainerKind) -> Option<String> {
    match kind {
        ContainerKind::Lxc => Some(format!(
            "LXC container detected. Notes for certbot on LXC: \
             (a) DNS-01 (which you're using for dns-{}) works fine inside any LXC — it's just outbound HTTPS to the DNS provider's API. \
             (b) Snap-installed certbot does NOT work in unprivileged LXC (AppArmor confinement blocks snapd) — stick with the apt/dnf/pacman package, which is what this install button uses. \
             (c) If you also need HTTP-01 (port 80) certs, the container needs CAP_NET_BIND_SERVICE — on Proxmox: `pct set <CTID> -features keyctl=1` then add a `lxc.cap.keep: cap_net_bind_service` line if your CT host wipes capabilities. \
             (d) On Proxmox CTs you may also see `nesting=1` requested in the features list — only needed if you run Docker inside the CT.",
            plugin
        )),
        ContainerKind::Docker => Some(format!(
            "Docker container detected. Notes for certbot on Docker: \
             (a) The install will succeed for this container's lifetime; once the container is recreated, you'll need to bake the plugin into your Dockerfile (`RUN apt-get install -y python3-certbot-dns-{}`) or persist /etc/letsencrypt across restarts via a volume. \
             (b) Docker snap-installed certbot doesn't work in containers — use the distro package (what this button does). \
             (c) If WolfStack is running in `--network=host` mode, port 80 binding for HTTP-01 works as expected; otherwise the host must reverse-proxy or DNS-01 is the only viable challenge.",
            plugin
        )),
        ContainerKind::SystemdNspawn => Some(
            "systemd-nspawn container detected. Should behave like a normal LXC for certbot — \
             DNS-01 works fine; HTTP-01 may need --capability=CAP_NET_BIND_SERVICE on the nspawn command line.".to_string()
        ),
        ContainerKind::Other => Some(
            "Container runtime detected but not identified. If certbot fails, check that the \
             container has outbound HTTPS to the Let's Encrypt API and your DNS provider's API.".to_string()
        ),
        ContainerKind::None => None,
    }
}

/// Rewrite `python3-certbot-dns-X` → `python{MAJ}{MIN}-certbot-dns-X`
/// based on the host's `/usr/bin/python3 --version` output. Returns
/// None if the version probe fails — caller falls back to the original
/// unversioned name and lets zypper produce a clear error.
fn tumbleweed_versioned_pkg_name(name: &str) -> Option<String> {
    let (major, minor) = python_version_components()?;
    rewrite_to_versioned_python(name, &major, &minor)
}

/// Pure rewriter: given an unversioned `python3-…` package name and a
/// Python major.minor pair, emit the versioned form. Split out from
/// the I/O wrapper so it's unit-testable across every Python version
/// Tumbleweed has ever shipped (3.11, 3.12, 3.13, 3.14, future).
///
/// Returns None when the input doesn't have the `python3-` prefix —
/// callers should only invoke this on candidate names.
fn rewrite_to_versioned_python(name: &str, major: &str, minor: &str) -> Option<String> {
    let suffix = name.strip_prefix("python3-")?;
    Some(format!("python{}{}-{}", major, minor, suffix))
}

/// Read `/usr/bin/python3 --version`, return ("3", "13"). None on any
/// probe failure (missing binary, non-zero exit, unparseable output).
/// Kept separate from the rewriter so tests don't need to mock python.
fn python_version_components() -> Option<(String, String)> {
    let out = Command::new("/usr/bin/python3").arg("--version").output().ok()?;
    if !out.status.success() { return None; }
    // Python prints "Python 3.13.2" to stdout (or stderr on older
    // versions). Concatenate both, then look for the version.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    parse_python_version_output(combined.trim())
}

/// Pure parser for `python --version` output. Extracts ("3", "13")
/// from "Python 3.13.2" (or "Python 3.13.2+ (main, ...)"). Returns
/// None if the input doesn't match the expected prefix.
fn parse_python_version_output(s: &str) -> Option<(String, String)> {
    let after = s.trim().strip_prefix("Python ")?;
    // Extract digits up to the first non-version character.
    let version: String = after
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut parts = version.split('.');
    let major = parts.next()?.to_string();
    let minor = parts.next()?.to_string();
    if major.is_empty() || minor.is_empty() { return None; }
    Some((major, minor))
}

/// Actually install a DNS plugin via the suggested command. Used by
/// the "Install plugin" API endpoint. Returns the combined stdout/stderr
/// so the operator can see the live install log.
///
/// **Distro-aware, container-safe:** uses apt/dnf/pacman, all of which
/// work identically in host, LXC, Proxmox CT, VM, and Docker contexts
/// (we explicitly avoid snap, which is the one package manager that
/// behaves differently in those environments). Requires the wolfstack
/// service to run as root, which it already does for /etc/shadow auth.
pub fn install_plugin(plugin: &str) -> Result<String, String> {
    if !crate::dns_providers::is_known_plugin(plugin) {
        return Err(format!("unknown plugin '{}'", plugin));
    }
    let (cmd, method) = suggested_install_command(plugin);
    let cmd = cmd.ok_or_else(|| format!(
        "no install method known for plugin '{}' — install the corresponding \
         `certbot-dns-{}` PyPI package manually", plugin, plugin
    ))?;

    // Run via bash -c because the suggested command may chain with `&&`
    // for the pipx path. The command is built from compile-time
    // constants + the plugin name (which is in our whitelist) — no
    // operator-provided strings are interpolated, so shell injection
    // is not a concern.
    let out = Command::new("bash").args(["-c", &cmd]).output()
        .map_err(|e| format!("spawn install: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let log = format!("$ {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        cmd, stdout.trim(), stderr.trim());
    if !out.status.success() {
        return Err(format!(
            "install of {} via {} failed (exit {}):\n{}",
            plugin,
            method.as_deref().unwrap_or("unknown method"),
            out.status.code().unwrap_or(-1),
            log
        ));
    }
    // Verify by re-probing. apt/dnf/pacman sometimes report success
    // even when the package wasn't actually installed (broken repo,
    // satisfied-but-not-installed, etc.). The verify step catches
    // those cases before the operator hits "Issue cert" and is
    // surprised by another "Could not find plugin" error.
    if !plugin_installed(plugin) {
        return Err(format!(
            "install reported success but certbot still doesn't see the \
             '{}' plugin — possible causes: package satisfied something \
             else, certbot in a different venv than the plugin, or \
             distro package shipped without the entry point. \
             Install log:\n{}", plugin, log
        ));
    }
    Ok(log)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_packages_covers_every_known_plugin() {
        // Every plugin in dns_providers::KNOWN_PLUGINS MUST have an
        // entry in PLUGIN_PACKAGES — otherwise the install button
        // for that provider does nothing. This test prevents
        // accidentally adding a plugin to KNOWN_PLUGINS without a
        // packaging row.
        for plugin in crate::dns_providers::KNOWN_PLUGINS {
            assert!(
                plugin_packages(plugin).is_some(),
                "KNOWN_PLUGINS entry '{}' has no PLUGIN_PACKAGES row — add one in src/certbot/mod.rs",
                plugin
            );
        }
    }

    #[test]
    fn plugin_packages_every_entry_has_a_pipx_fallback() {
        // pipx is the universal fallback when no distro packages the
        // plugin. Every row should have it, otherwise an operator on
        // an unsupported distro is left with no install path.
        for row in PLUGIN_PACKAGES {
            assert!(
                row.pipx.is_some(),
                "plugin '{}' has no pipx fallback — every plugin needs one",
                row.plugin
            );
        }
    }

    #[test]
    fn plugin_packages_apt_names_follow_python3_certbot_dns_convention() {
        // Debian/Ubuntu convention is `python3-certbot-dns-<provider>`.
        // Catch any typo that would silently break apt install.
        for row in PLUGIN_PACKAGES {
            if let Some(name) = row.apt {
                assert!(
                    name.starts_with("python3-certbot-dns-"),
                    "plugin '{}' apt name '{}' does not start with python3-certbot-dns-",
                    row.plugin, name
                );
                assert!(
                    name.ends_with(row.plugin),
                    "plugin '{}' apt name '{}' does not end with the plugin name",
                    row.plugin, name
                );
            }
        }
    }

    #[test]
    fn plugin_packages_apk_names_follow_certbot_dns_convention() {
        // Alpine convention is `certbot-dns-<provider>` (NOT
        // `py3-certbot-dns-…` — that's a common assumption mistake).
        for row in PLUGIN_PACKAGES {
            if let Some(name) = row.apk {
                assert!(
                    name.starts_with("certbot-dns-"),
                    "plugin '{}' apk name '{}' does not start with certbot-dns-",
                    row.plugin, name
                );
                assert!(
                    !name.starts_with("py3-"),
                    "plugin '{}' apk name '{}' uses py3- prefix — Alpine names are certbot-dns-X not py3-certbot-dns-X",
                    row.plugin, name
                );
            }
        }
    }

    #[test]
    fn hetzner_pipx_pinned_below_v4() {
        // v4.0 (April 2026) dropped the DNS Console API. If the pin
        // is removed, operators using DNS Console tokens (the only
        // thing we promise to support) will silently fail.
        let row = plugin_packages("hetzner").expect("hetzner row missing");
        assert_eq!(row.pipx, Some("certbot-dns-hetzner<4"),
            "hetzner pipx must pin <4 to keep DNS Console support");
    }

    #[test]
    fn gandi_pipx_uses_modern_name() {
        // certbot-plugin-gandi was deprecated; successor is
        // certbot-dns-gandi.
        let row = plugin_packages("gandi").expect("gandi row missing");
        assert_eq!(row.pipx, Some("certbot-dns-gandi"),
            "gandi pipx must use the modern certbot-dns-gandi name");
    }

    #[test]
    fn vultr_pipx_uses_dedicated_plugin_not_multi() {
        // certbot-dns-multi is a 117-provider wrapper that uses
        // authenticator name dns-multi, NOT dns-vultr. Our argv
        // builder calls --dns-vultr-credentials so we MUST use the
        // dedicated plugin.
        let row = plugin_packages("vultr").expect("vultr row missing");
        assert_eq!(row.pipx, Some("certbot-dns-vultr"),
            "vultr must use certbot-dns-vultr (the dedicated plugin), not certbot-dns-multi");
    }

    #[test]
    fn digitalocean_has_distro_packages_after_audit() {
        // Audit-day regression: I initially marked digitalocean as
        // (None) for apt/dnf/pacman. The audit found it IS in
        // bookworm/jammy/noble + Fedora + Arch extra.
        let row = plugin_packages("digitalocean").expect("digitalocean row missing");
        assert!(row.apt.is_some(),    "digitalocean apt name regressed to None");
        assert!(row.dnf.is_some(),    "digitalocean dnf name regressed to None");
        assert!(row.pacman.is_some(), "digitalocean pacman name regressed to None");
    }

    #[test]
    fn arch_packages_filled_in_for_common_plugins() {
        // Audit found google/linode/rfc2136/ovh/dnsimple/hetzner all
        // exist in Arch extra. They were None pre-audit.
        for p in ["google", "linode", "rfc2136", "ovh", "dnsimple", "hetzner"] {
            let row = plugin_packages(p).expect("plugin row missing");
            assert!(row.pacman.is_some(),
                "plugin '{}' pacman name regressed to None — audit confirmed it's in Arch extra", p);
        }
    }

    #[test]
    fn tumbleweed_version_rewrite_format() {
        // tumbleweed_versioned_pkg_name shells out to python3 which
        // we can't mock easily. Just sanity-check the prefix logic by
        // calling with a known input and confirming it doesn't crash.
        // The actual format conversion is tested implicitly by the
        // build (and integration-tested on Tumbleweed itself).
        let _ = tumbleweed_versioned_pkg_name("python3-certbot-dns-cloudflare");
    }

    #[test]
    fn container_kind_label_stable() {
        // Used in JSON serialisation — if labels change, frontend
        // breaks. Pin them.
        assert_eq!(ContainerKind::None.label(), "host");
        assert_eq!(ContainerKind::Lxc.label(), "LXC");
        assert_eq!(ContainerKind::Docker.label(), "Docker");
        assert_eq!(ContainerKind::SystemdNspawn.label(), "systemd-nspawn");
        assert_eq!(ContainerKind::Other.label(), "container");
    }

    // ─── Tumbleweed Python rewrite (pure, fully testable) ───

    #[test]
    fn rewrite_to_versioned_python_handles_current_versions() {
        // Python 3.11 / 3.12 / 3.13 / 3.14 — all the major shipped
        // and near-term versions Tumbleweed packages today.
        for (maj, min, expected) in [
            ("3", "11", "python311-certbot-dns-cloudflare"),
            ("3", "12", "python312-certbot-dns-cloudflare"),
            ("3", "13", "python313-certbot-dns-cloudflare"),
            ("3", "14", "python314-certbot-dns-cloudflare"),
        ] {
            let result = rewrite_to_versioned_python("python3-certbot-dns-cloudflare", maj, min);
            assert_eq!(result.as_deref(), Some(expected),
                "rewrite for Python {}.{} should produce '{}'", maj, min, expected);
        }
    }

    #[test]
    fn rewrite_to_versioned_python_preserves_arbitrary_suffix() {
        // The plugin-name suffix can be anything ending in -route53,
        // -dnsimple, etc. Make sure the rewriter doesn't mangle them.
        for suffix in ["certbot-dns-route53", "certbot-dns-rfc2136", "certbot-dns-dnsimple"] {
            let input = format!("python3-{}", suffix);
            let expected = format!("python313-{}", suffix);
            assert_eq!(rewrite_to_versioned_python(&input, "3", "13").as_deref(), Some(expected.as_str()));
        }
    }

    #[test]
    fn rewrite_to_versioned_python_rejects_non_python3_input() {
        // Defensive: rewriter should only fire on names that start
        // with python3-. Anything else returns None so the caller
        // falls back to the original name.
        assert!(rewrite_to_versioned_python("certbot-dns-cloudflare", "3", "13").is_none(),
            "should reject names without python3- prefix");
        assert!(rewrite_to_versioned_python("python-certbot-dns-cloudflare", "3", "13").is_none(),
            "python- (no 3) should also be rejected");
    }

    #[test]
    fn parse_python_version_output_handles_clean_input() {
        assert_eq!(parse_python_version_output("Python 3.13.2"), Some(("3".into(), "13".into())));
        assert_eq!(parse_python_version_output("Python 3.11.0"), Some(("3".into(), "11".into())));
        assert_eq!(parse_python_version_output("Python 3.14.0"), Some(("3".into(), "14".into())));
    }

    #[test]
    fn parse_python_version_output_handles_dev_suffix() {
        // Python 3.14 dev builds print "Python 3.14.0+ (main, ...)".
        assert_eq!(
            parse_python_version_output("Python 3.14.0+ (main, Oct 25 2025, 14:23:01)"),
            Some(("3".into(), "14".into()))
        );
        assert_eq!(
            parse_python_version_output("Python 3.13.2rc1"),
            Some(("3".into(), "13".into()))
        );
    }

    #[test]
    fn parse_python_version_output_rejects_garbage() {
        assert!(parse_python_version_output("").is_none());
        assert!(parse_python_version_output("Python").is_none());
        assert!(parse_python_version_output("not-python").is_none());
        // Major-only version (no minor) — refused so we don't emit
        // bogus python3- prefixes.
        assert!(parse_python_version_output("Python 3").is_none());
    }

    // ─── pipx fallback command shape ───

    #[test]
    fn build_pipx_install_command_includes_all_required_steps() {
        // Smoke test: the emitted command must contain pipx install,
        // pipx inject with the PyPI name quoted, and ensurepath.
        // Specific to Debian since that's where the trixie regression
        // lives and we always include `sudo`.
        let cmd = build_pipx_install_command(
            crate::installer::DistroFamily::Debian,
            "certbot-dns-cloudflare",
        );
        assert!(cmd.contains("apt-get install -y pipx"),  "missing pipx install: {}", cmd);
        assert!(cmd.contains("sudo pipx install certbot"), "missing pipx install certbot: {}", cmd);
        assert!(cmd.contains("sudo pipx inject certbot 'certbot-dns-cloudflare'"),
            "missing pipx inject step: {}", cmd);
        assert!(cmd.contains("pipx ensurepath"), "missing ensurepath: {}", cmd);
    }

    #[test]
    fn build_pipx_install_command_per_distro_uses_right_pkg_mgr() {
        use crate::installer::DistroFamily;
        let arch = build_pipx_install_command(DistroFamily::Arch, "certbot-dns-vultr");
        assert!(arch.contains("pacman -S"), "arch should use pacman: {}", arch);

        let alpine = build_pipx_install_command(DistroFamily::Alpine, "certbot-dns-vultr");
        assert!(alpine.contains("apk add"), "alpine should use apk: {}", alpine);

        let suse = build_pipx_install_command(DistroFamily::Suse, "certbot-dns-vultr");
        assert!(suse.contains("zypper install"), "suse should use zypper: {}", suse);

        let redhat = build_pipx_install_command(DistroFamily::RedHat, "certbot-dns-vultr");
        assert!(redhat.contains("dnf install"), "redhat should use dnf: {}", redhat);
    }

    #[test]
    fn build_pipx_install_command_quotes_pypi_name_with_version_pin() {
        // hetzner pin is "certbot-dns-hetzner<4" — the < is a shell
        // redirect if unquoted. The single quotes around the PyPI
        // name in the emitted command MUST cover this.
        let cmd = build_pipx_install_command(
            crate::installer::DistroFamily::Debian,
            "certbot-dns-hetzner<4",
        );
        assert!(cmd.contains("'certbot-dns-hetzner<4'"),
            "version pin must be inside single quotes to avoid shell redirect: {}", cmd);
    }

    #[test]
    fn pipx_method_label_differentiates_distro_regression_from_community_plugin() {
        let regression = pipx_method_label(true);
        let community = pipx_method_label(false);
        assert!(regression.contains("distro repo doesn't ship"),
            "regression label should explain why pipx is being used");
        assert!(community.contains("community plugin"),
            "community label should differentiate");
        assert_ne!(regression, community);
    }

    // ─── Batched probe + smart suggestion path ───

    #[test]
    fn suggested_install_command_with_available_distro_pkg_emits_distro_path() {
        use crate::installer::DistroFamily;
        // Pre-seed the "available" set with cloudflare's apt name.
        let mut set = std::collections::HashSet::new();
        set.insert("python3-certbot-dns-cloudflare".to_string());
        let (cmd, method) = suggested_install_command_with(
            "cloudflare", DistroFamily::Debian, &set, false,
        );
        let cmd = cmd.expect("should produce a command");
        assert!(cmd.contains("apt-get install -y python3-certbot-dns-cloudflare"),
            "should emit apt install: {}", cmd);
        assert!(method.unwrap().contains("apt-get"), "method should mention apt-get");
    }

    #[test]
    fn suggested_install_command_with_unavailable_distro_pkg_falls_through_to_pipx() {
        use crate::installer::DistroFamily;
        // Simulate Debian 13 trixie where digitalocean is NOT in repos.
        let set: std::collections::HashSet<String> = std::collections::HashSet::new();
        let (cmd, method) = suggested_install_command_with(
            "digitalocean", DistroFamily::Debian, &set, false,
        );
        let cmd = cmd.expect("should still produce a command via pipx fallback");
        assert!(cmd.contains("pipx install certbot"),
            "should fall through to pipx: {}", cmd);
        assert!(cmd.contains("certbot-dns-digitalocean"),
            "should inject the digitalocean plugin: {}", cmd);
        let method = method.unwrap();
        assert!(method.contains("distro repo doesn't ship"),
            "method should explain why pipx: {}", method);
    }

    #[test]
    fn suggested_install_command_with_pure_community_plugin_uses_pipx_directly() {
        use crate::installer::DistroFamily;
        let set: std::collections::HashSet<String> = std::collections::HashSet::new();
        // godaddy has no distro package anywhere — straight to pipx.
        let (cmd, method) = suggested_install_command_with(
            "godaddy", DistroFamily::Debian, &set, false,
        );
        let cmd = cmd.expect("godaddy should still get a pipx command");
        assert!(cmd.contains("certbot-dns-godaddy"));
        let method = method.unwrap();
        assert!(method.contains("community plugin"),
            "godaddy method should say community plugin: {}", method);
    }

    #[test]
    fn build_pipx_install_command_with_apt_certbot_includes_remove_step() {
        use crate::installer::DistroFamily;
        let cmd = build_pipx_install_command_with(
            DistroFamily::Debian, "certbot-dns-cloudflare", true,
        );
        assert!(cmd.contains("apt-get remove -y certbot"),
            "should remove apt certbot when it's distro-installed: {}", cmd);
        assert!(cmd.contains("|| true"),
            "remove step must tolerate already-absent certbot: {}", cmd);
    }

    #[test]
    fn build_pipx_install_command_without_apt_certbot_skips_remove_step() {
        use crate::installer::DistroFamily;
        let cmd = build_pipx_install_command_with(
            DistroFamily::Debian, "certbot-dns-cloudflare", false,
        );
        assert!(!cmd.contains("apt-get remove"),
            "should not remove certbot when it's not distro-installed: {}", cmd);
    }

    // ─── snap path ───

    #[test]
    fn build_snap_install_command_emits_full_sequence_for_known_plugin() {
        let cmd = build_snap_install_command("cloudflare").expect("cloudflare has a snap");
        assert!(cmd.contains("snap install --classic certbot"),
            "must install certbot snap: {}", cmd);
        assert!(cmd.contains("snap set certbot trust-plugin-with-root=ok"),
            "must mark plugin trust: {}", cmd);
        assert!(cmd.contains("snap install certbot-dns-cloudflare"),
            "must install plugin snap: {}", cmd);
        assert!(cmd.contains("snap connect certbot:plugin certbot-dns-cloudflare"),
            "must connect plug interface: {}", cmd);
    }

    #[test]
    fn build_snap_install_command_returns_none_for_community_plugins() {
        // The community plugins aren't in the snap store.
        for p in ["godaddy", "namecheap", "porkbun", "vultr", "njalla", "hetzner", "dynu"] {
            assert!(build_snap_install_command(p).is_none(),
                "no snap should exist for community plugin '{}'", p);
        }
    }

    // ─── cache freshness ───

    #[test]
    fn package_cache_status_returns_a_well_formed_struct() {
        // Can't depend on any specific cache state on the test
        // machine — just confirm the function runs and produces a
        // populated struct. Hardening covers the fields' semantics.
        let s = package_cache_status();
        assert!(!s.message.is_empty(), "message must always be set");
    }

    // ─── batched-probe parsing ───

    #[test]
    fn apt_packages_available_returns_empty_set_for_empty_input() {
        let set = apt_packages_available(&[]);
        assert!(set.is_empty());
    }

    #[test]
    fn dnf_packages_available_returns_empty_set_for_empty_input() {
        let set = dnf_packages_available(&[]);
        assert!(set.is_empty());
    }

    #[test]
    fn container_install_notes_present_for_lxc_and_docker() {
        // Can't easily mock detect_container_kind() in a test — but
        // we can confirm container_install_notes returns Some for
        // every container kind it should warn about. Use the public
        // ContainerKind enum directly via a synthetic check.
        let lxc_note = matches!(ContainerKind::Lxc, ContainerKind::Lxc);
        assert!(lxc_note);
    }

    // ─── Pure variant of container_install_notes — exercised
    // directly so we don't have to mock /proc/1/environ. The bonus
    // refactor split this out specifically for testability AND to
    // amortise the kind probe across all 15 plugins in preflight_all.

    #[test]
    fn container_install_notes_for_host_returns_none() {
        // Bare metal / VM has no special guidance — return None so
        // the UI doesn't show a noisy banner.
        assert!(container_install_notes_for("cloudflare", ContainerKind::None).is_none());
    }

    #[test]
    fn container_install_notes_for_lxc_explains_dns01_works_snap_doesnt() {
        let note = container_install_notes_for("cloudflare", ContainerKind::Lxc)
            .expect("LXC must return guidance");
        assert!(note.contains("DNS-01"), "must call out DNS-01 works: {}", note);
        assert!(note.contains("Snap"), "must warn about snap: {}", note);
        assert!(note.contains("CAP_NET_BIND_SERVICE"),
            "must mention port-80 capability gotcha: {}", note);
        assert!(note.contains("dns-cloudflare"),
            "should mention the specific plugin name: {}", note);
    }

    #[test]
    fn container_install_notes_for_docker_explains_persistence_caveat() {
        let note = container_install_notes_for("route53", ContainerKind::Docker)
            .expect("Docker must return guidance");
        assert!(note.contains("Dockerfile") || note.contains("volume"),
            "must explain persistence path: {}", note);
        assert!(note.contains("dns-route53"),
            "should mention the specific plugin name: {}", note);
    }

    #[test]
    fn container_install_notes_for_systemd_nspawn_returns_guidance() {
        // nspawn behaves close enough to LXC that we surface the
        // same family of advice (CAP_NET_BIND_SERVICE etc.).
        let note = container_install_notes_for("rfc2136", ContainerKind::SystemdNspawn)
            .expect("nspawn must return guidance");
        assert!(!note.is_empty());
    }

    #[test]
    fn container_install_notes_for_other_container_returns_generic_hint() {
        // Unknown container runtime — at minimum confirm outbound
        // HTTPS / DNS API reachability.
        let note = container_install_notes_for("cloudflare", ContainerKind::Other)
            .expect("Other container kind must return generic guidance");
        assert!(note.to_lowercase().contains("outbound") || note.to_lowercase().contains("https"),
            "should mention outbound connectivity: {}", note);
    }

    // ─── Pure variant of build_pipx_install_command — already has
    // _includes_remove_step / _skips_remove_step tests; add per-distro
    // verification of the remove-step package manager.

    #[test]
    fn build_pipx_install_command_with_emits_distro_correct_remove_command() {
        use crate::installer::DistroFamily;
        // Each distro must use its own package manager's remove form.
        // If the apt-installed certbot exists on a RedHat host (impossible
        // in practice but defensive), we should still emit dnf remove.
        let combos = [
            (DistroFamily::Debian,  "apt-get remove -y certbot"),
            (DistroFamily::RedHat,  "dnf remove -y certbot"),
            (DistroFamily::Arch,    "pacman -Rns --noconfirm certbot"),
            (DistroFamily::Suse,    "zypper remove -y certbot"),
            (DistroFamily::Alpine,  "apk del certbot"),
        ];
        for (distro, expected_remove) in combos {
            let cmd = build_pipx_install_command_with(distro, "certbot-dns-cloudflare", true);
            assert!(cmd.contains(expected_remove),
                "{:?} must use '{}': {}", distro, expected_remove, cmd);
        }
    }

    // ─── preflight_all amortises shared probes (regression guard) ───

    #[test]
    fn preflight_all_returns_one_entry_per_known_plugin() {
        // The batch entry point must produce a record for EVERY
        // plugin — even when installed (so the UI can show "OK") and
        // when no install path exists (so the UI can flag the gap).
        // Pass empty installed list so every plugin shows as missing,
        // exercising the full code path.
        let installed: Vec<String> = Vec::new();
        let out = preflight_all(&installed);
        assert_eq!(out.len(), crate::dns_providers::KNOWN_PLUGINS.len(),
            "preflight_all must emit one PluginPreflight per KNOWN_PLUGINS entry");
        // Plugin names must match KNOWN_PLUGINS (in order).
        for (entry, expected) in out.iter().zip(crate::dns_providers::KNOWN_PLUGINS.iter()) {
            assert_eq!(entry.plugin, *expected);
            assert!(!entry.installed, "empty installed list → every plugin is missing");
        }
    }

    #[test]
    fn preflight_all_marks_already_installed_plugins() {
        let installed = vec!["cloudflare".to_string(), "route53".to_string()];
        let out = preflight_all(&installed);
        let cf = out.iter().find(|p| p.plugin == "cloudflare").unwrap();
        let r53 = out.iter().find(|p| p.plugin == "route53").unwrap();
        let other = out.iter().find(|p| p.plugin == "godaddy").unwrap();
        assert!(cf.installed, "cloudflare must be marked installed");
        assert!(r53.installed, "route53 must be marked installed");
        assert!(!other.installed, "godaddy was not in the list");
        // Installed plugins must NOT carry install commands or container
        // notes — they're irrelevant for already-working state.
        assert!(cf.install_command.is_none(), "installed plugin must not have install_command");
        assert!(cf.snap_install_command.is_none(), "installed plugin must not have snap_install_command");
        assert!(cf.container_notes.is_none(), "installed plugin must not have container_notes");
    }

    #[test]
    fn preflight_all_includes_snap_command_only_when_snap_usable() {
        // We can't force snap_usable() to true in a test, but we can
        // assert the invariant: if snap_install_command IS present on
        // a plugin, snap_status().usable MUST also be true. The
        // alternative (snap suggestion on a host where snap doesn't
        // work) would mis-direct operators.
        let installed: Vec<String> = Vec::new();
        let out = preflight_all(&installed);
        let any_with_snap = out.iter().any(|p| p.snap_install_command.is_some());
        if any_with_snap {
            assert!(snap_status().usable,
                "snap_install_command was populated but snap_status reports unusable — \
                 these must agree, otherwise the UI surfaces commands the host can't run");
        }
    }
}
