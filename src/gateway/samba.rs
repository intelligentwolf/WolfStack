// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Samba (SMB) configuration emitter.
//!
//! WolfStack writes per-gateway include snippets into
//! `/etc/samba/wolfstack-gateways.d/<id>.conf` and a single global
//! aggregator at `/etc/samba/wolfstack-gateways.conf` that the host's
//! `smb.conf` includes once. This way we never own the operator's
//! `smb.conf` — we just append a single `include = …` line on first
//! use, and from there on we manage our own snippets.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::{AuthConfig, Gateway, GatewayOptions, Protocol, SmbEncrypt};

const HOST_SMB_CONF: &str = "/etc/samba/smb.conf";
const HOST_INCLUDE_LINE: &str = "include = /etc/samba/wolfstack-gateways.conf";
const AGGREGATOR_PATH: &str = "/etc/samba/wolfstack-gateways.conf";
const SNIPPETS_DIR: &str = "/etc/samba/wolfstack-gateways.d";

/// Errors surfaced to the API. Variants match the operator-actionable
/// failure modes — same shape as `SourceError`.
#[derive(Debug)]
#[allow(dead_code)]
pub enum SambaError {
    NotInstalled { install_command: String, install_package: String },
    WriteFailed(String),
    ReloadFailed(String),
    Io(std::io::Error),
}

impl std::fmt::Display for SambaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SambaError::NotInstalled { install_package, .. } => {
                write!(f, "samba is not installed (install package '{}')", install_package)
            }
            SambaError::WriteFailed(s) => write!(f, "config write failed: {}", s),
            SambaError::ReloadFailed(s) => write!(f, "samba reload failed: {}", s),
            SambaError::Io(e) => write!(f, "io error: {}", e),
        }
    }
}

impl From<std::io::Error> for SambaError {
    fn from(e: std::io::Error) -> Self { SambaError::Io(e) }
}

/// Confirm samba (smbd + smbpasswd + pdbedit) is installed. Returns
/// a structured error so the UI shows install instructions instead of
/// blowing up the operator with a stack trace.
pub fn require_samba() -> Result<(), SambaError> {
    if super::sources::which_helper("smbd").is_none() {
        return Err(SambaError::NotInstalled {
            install_command: "apt-get install -y samba".to_string(),
            install_package: "samba".to_string(),
        });
    }
    Ok(())
}

/// Write the snippet for a single gateway. Idempotent — overwriting
/// a snippet for an existing gateway is the normal path.
pub fn write_gateway_snippet(g: &Gateway, share_path: &Path) -> Result<(), SambaError> {
    if !g.protocols.contains(&Protocol::Smb) {
        // Operator may have flipped SMB off — remove any stale snippet
        // and we're done.
        let _ = std::fs::remove_file(snippet_path(&g.id));
        return Ok(());
    }
    require_samba()?;

    std::fs::create_dir_all(SNIPPETS_DIR)?;
    let snippet = render_snippet(g, share_path);
    let path = snippet_path(&g.id);
    std::fs::write(&path, snippet).map_err(|e| SambaError::WriteFailed(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
    }
    // Pass the in-memory gateway so the workgroup picker sees its
    // smb_workgroup even on the first apply (before gateways.json
    // persists). Otherwise the aggregator would render with the
    // pre-create state's workgroup until the next reload.
    rebuild_aggregator(Some(g))?;
    ensure_host_include()?;
    apply_users(&g.auth)?;
    reload_smbd()?;
    Ok(())
}

/// Drop a gateway's snippet and reload. Idempotent.
pub fn remove_gateway_snippet(gateway_id: &str) -> Result<(), SambaError> {
    let path = snippet_path(gateway_id);
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    rebuild_aggregator(None)?;
    // Don't fail loudly if smbd isn't installed/running — gateway
    // delete is "best effort cleanup".
    let _ = reload_smbd();
    Ok(())
}

// ─── Internals ───

fn snippet_path(gateway_id: &str) -> PathBuf {
    PathBuf::from(SNIPPETS_DIR).join(format!("{}.conf", sanitise(gateway_id)))
}

fn sanitise(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn render_snippet(g: &Gateway, share_path: &Path) -> String {
    let mut out = String::new();
    let opts: &GatewayOptions = &g.options;

    // Each snippet contributes one [share] section. The aggregator
    // writes a single [global] block with workgroup + encryption +
    // logging.
    out.push_str(&format!("# WolfStack gateway: {} ({})\n", g.name, g.id));
    out.push_str(&format!("[{}]\n", sanitise(&g.name)));
    out.push_str(&format!("    path = {}\n", share_path.display()));
    out.push_str(&format!("    comment = WolfStack share '{}'\n", g.name));
    out.push_str("    browseable = yes\n");
    out.push_str(&format!("    read only = {}\n", yesno(opts.readonly)));
    out.push_str(&format!("    guest ok = {}\n", yesno(opts.guest_ok)));

    // Auth-driven access controls.
    match &g.auth {
        AuthConfig::Anonymous { writable } => {
            out.push_str("    guest only = yes\n");
            out.push_str(&format!("    writable = {}\n", yesno(*writable && !opts.readonly)));
            out.push_str("    force user = nobody\n");
        }
        AuthConfig::Users { users, default_writable } => {
            let names: Vec<&str> = users.iter().map(|u| u.username.as_str()).collect();
            out.push_str(&format!("    valid users = {}\n", names.join(" ")));
            let writers: Vec<&str> = users.iter()
                .filter(|u| u.writable)
                .map(|u| u.username.as_str())
                .collect();
            if !writers.is_empty() {
                out.push_str(&format!("    write list = {}\n", writers.join(" ")));
            }
            out.push_str(&format!("    writable = {}\n", yesno(*default_writable && !opts.readonly)));
        }
        AuthConfig::Ad { .. } => {
            // Reserved for v1.2+; should never reach here because
            // validate() rejects AD on v1.0, but be safe.
            out.push_str("    valid users = @WOLFSTACK_AD_PLACEHOLDER\n");
        }
    }

    // Optional VFS modules.
    let mut vfs: Vec<&str> = Vec::new();
    if opts.recycle_bin { vfs.push("recycle"); }
    if opts.time_machine { vfs.extend(["catia", "fruit", "streams_xattr"]); }
    if !vfs.is_empty() {
        out.push_str(&format!("    vfs objects = {}\n", vfs.join(" ")));
    }
    if opts.recycle_bin {
        out.push_str("    recycle:repository = .recycle/%U\n");
        out.push_str("    recycle:keeptree = yes\n");
        out.push_str("    recycle:versions = yes\n");
    }
    if opts.time_machine {
        out.push_str("    fruit:time machine = yes\n");
        out.push_str("    fruit:metadata = stream\n");
    }

    // Allow / deny CIDR lists.
    if !opts.allow_hosts.is_empty() {
        out.push_str(&format!("    hosts allow = {}\n", opts.allow_hosts.join(" ")));
    }
    if !opts.deny_hosts.is_empty() {
        out.push_str(&format!("    hosts deny = {}\n", opts.deny_hosts.join(" ")));
    }

    // Symlinks that leave the share (ZFS pools that link across
    // datasets). Share-level half only — the required
    // `unix extensions = no` is global-only and lives in the
    // aggregator's [global] (see any_smb_wide_links).
    if opts.smb_wide_links {
        out.push_str("    follow symlinks = yes\n");
        out.push_str("    wide links = yes\n");
    }

    if let Some(maxc) = opts.max_connections {
        out.push_str(&format!("    max connections = {}\n", maxc));
    }
    if let Some(cs) = opts.case_sensitive {
        out.push_str(&format!("    case sensitive = {}\n", yesno(cs)));
    }

    if g.disabled {
        out.push_str("    available = no\n");
    }
    out.push('\n');
    out
}

fn render_aggregator(active: Option<&Gateway>) -> std::io::Result<String> {
    // Pick the workgroup. `active` (if any) is the gateway being
    // written right now — its in-memory smb_workgroup wins even
    // before it lands in gateways.json. Otherwise fall back to the
    // first SMB-enabled gateway in the persisted store.
    let workgroup = active
        .filter(|g| g.protocols.contains(&Protocol::Smb)
            && !g.options.smb_workgroup.trim().is_empty())
        .map(|g| g.options.smb_workgroup.trim().to_string())
        .or_else(|| {
            let store = super::GatewayStore::load();
            store.gateways.values()
                .find(|g| g.protocols.contains(&Protocol::Smb)
                    && !g.options.smb_workgroup.trim().is_empty())
                .map(|g| g.options.smb_workgroup.trim().to_string())
        })
        .unwrap_or_else(|| "WORKGROUP".to_string());
    let mut out = String::new();
    out.push_str("# Auto-generated by WolfStack — do not edit\n");
    out.push_str("# Per-gateway snippets live in /etc/samba/wolfstack-gateways.d/*.conf\n\n");
    out.push_str("[global]\n");
    // sanitise the workgroup before writing — operator-supplied
    // strings could otherwise inject arbitrary smb.conf directives
    // via embedded newlines or `=` characters.
    out.push_str(&format!("    workgroup = {}\n", sanitise(&workgroup)));
    out.push_str("    server string = WolfStack Gateway %h\n");
    out.push_str("    server role = standalone server\n");
    out.push_str("    log file = /var/log/samba/log.%m\n");
    out.push_str("    max log size = 1000\n");
    out.push_str("    map to guest = bad user\n");
    out.push_str("    passdb backend = tdbsam\n");
    out.push_str("    smb encrypt = auto\n");
    out.push_str("    server min protocol = SMB2_10\n");
    out.push_str("    client min protocol = SMB2_10\n");
    out.push_str("    panic action = /usr/share/samba/panic-action %d\n");
    out.push_str("    obey pam restrictions = no\n");
    out.push_str("    unix password sync = no\n");
    // `wide links` on any share is force-disabled by Samba while
    // `unix extensions` (global-only, default yes) is on — see
    // smb.conf(5) "wide links (S)" / "smb1 unix extensions (G)". So
    // whenever any SMB gateway asks for wide links, switch SMB1 unix
    // extensions off globally. Free: [global] above already pins
    // `server min protocol = SMB2_10`, so no SMB1 client connects.
    if any_smb_wide_links(active) {
        out.push_str("    unix extensions = no\n");
    }
    out.push('\n');

    // Pull in every snippet — alphabetical order so the rendered
    // smb.conf is stable across runs.
    if let Ok(entries) = std::fs::read_dir(SNIPPETS_DIR) {
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("conf"))
            .collect();
        paths.sort();
        for p in paths {
            if let Ok(s) = std::fs::read_to_string(&p) {
                out.push_str(&s);
                if !s.ends_with('\n') { out.push('\n'); }
            }
        }
    }
    Ok(out)
}

fn rebuild_aggregator(active: Option<&Gateway>) -> Result<(), SambaError> {
    // Some gateways may have been updated to apply `smb encrypt =
    // required`. Pick the strictest setting — Required wins, then
    // Auto, then Off — and bake it into [global].
    let body = render_aggregator(active)?;
    let body = with_global_smb_encrypt(body, max_smb_encrypt());
    std::fs::write(AGGREGATOR_PATH, body)?;
    Ok(())
}

fn with_global_smb_encrypt(body: String, encrypt: SmbEncrypt) -> String {
    let value = match encrypt {
        SmbEncrypt::Auto => "auto",
        SmbEncrypt::Required => "required",
        SmbEncrypt::Off => "off",
    };
    body.replace("    smb encrypt = auto\n", &format!("    smb encrypt = {}\n", value))
}

/// Read every snippet and return the strictest encryption mode any
/// gateway requested. Required > Auto > Off.
fn max_smb_encrypt() -> SmbEncrypt {
    // Cheap scan of the persisted gateways file rather than parsing
    // snippets back out — single source of truth.
    let store = super::GatewayStore::load();
    let mut best = SmbEncrypt::Off;
    for g in store.gateways.values() {
        if !g.protocols.contains(&Protocol::Smb) { continue; }
        match g.options.smb_encrypt {
            SmbEncrypt::Required => return SmbEncrypt::Required,
            SmbEncrypt::Auto => best = SmbEncrypt::Auto,
            SmbEncrypt::Off => {}
        }
    }
    best
}

/// True when any SMB gateway wants `wide links`. `active` is the
/// gateway being written right now — checked in-memory so the first
/// apply sees it before gateways.json persists (same reasoning as the
/// workgroup picker in render_aggregator).
fn any_smb_wide_links(active: Option<&Gateway>) -> bool {
    if active.is_some_and(gateway_wants_wide_links) {
        return true;
    }
    let store = super::GatewayStore::load();
    store.gateways.values().any(gateway_wants_wide_links)
}

fn gateway_wants_wide_links(g: &Gateway) -> bool {
    g.protocols.contains(&Protocol::Smb) && g.options.smb_wide_links
}

fn ensure_host_include() -> Result<(), SambaError> {
    // If the host smb.conf doesn't exist yet (samba just installed
    // and never started), create a minimal one with our include.
    if !Path::new(HOST_SMB_CONF).exists() {
        let stub = format!(
            "# Minimal smb.conf created by WolfStack\n[global]\n    log file = /var/log/samba/log.%m\n\n{}\n",
            HOST_INCLUDE_LINE
        );
        if let Some(parent) = Path::new(HOST_SMB_CONF).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(HOST_SMB_CONF, stub)?;
        return Ok(());
    }
    let content = std::fs::read_to_string(HOST_SMB_CONF)?;
    if content.contains(HOST_INCLUDE_LINE) {
        return Ok(());
    }
    // Append at end. We never edit existing lines.
    let mut new_content = content;
    if !new_content.ends_with('\n') { new_content.push('\n'); }
    new_content.push_str(&format!(
        "\n# Added by WolfStack — managed-share aggregator (do not remove unless you uninstall WolfStack gateways)\n{}\n",
        HOST_INCLUDE_LINE
    ));
    std::fs::write(HOST_SMB_CONF, new_content)?;
    Ok(())
}

fn reload_smbd() -> Result<(), SambaError> {
    // Two-phase reload:
    //   1. `smbcontrol smbd reload-config` — the canonical graceful
    //      reload that keeps existing connections. Only works when
    //      smbd is already running.
    //   2. systemctl reload-or-restart against whichever service unit
    //      this distro uses. Debian/Ubuntu ship `smbd.service`; Arch
    //      and openSUSE ship `smb.service`; Fedora ships both. We try
    //      smbd first, then smb, then samba — first one that succeeds
    //      wins.
    let in_place = Command::new("smbcontrol").args(["smbd", "reload-config"]).output();
    if matches!(&in_place, Ok(o) if o.status.success()) {
        return Ok(());
    }
    let in_place_err = match in_place {
        Ok(o) => String::from_utf8_lossy(&o.stderr).trim().to_string(),
        Err(e) => format!("smbcontrol invoke failed: {}", e),
    };
    let mut last_systemctl_err = String::new();
    for unit in ["smbd", "smb", "samba"] {
        let r = Command::new("systemctl").args(["reload-or-restart", unit]).output();
        match r {
            Ok(o) if o.status.success() => return Ok(()),
            Ok(o) => last_systemctl_err = format!(
                "{}: {}",
                unit,
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => last_systemctl_err = format!("{}: {}", unit, e),
        }
    }
    Err(SambaError::ReloadFailed(format!(
        "smbcontrol said: {}; systemctl tried smbd/smb/samba — last error: {}",
        in_place_err, last_systemctl_err
    )))
}

/// Ensure UNIX users exist for every SMB user named in the auth
/// config, AND record them as wolfstack-managed (so the post-persist
/// orphan prune knows they're ours to delete later when no gateway
/// still references them). Passwords are NOT set here — the operator
/// sets them via the dedicated /users/{name}/password endpoint.
fn apply_users(auth: &AuthConfig) -> Result<(), SambaError> {
    let users = match auth {
        AuthConfig::Users { users, .. } => users.clone(),
        _ => return Ok(()),
    };
    if super::sources::which_helper("smbpasswd").is_none() {
        return Err(SambaError::NotInstalled {
            install_command: "apt-get install -y samba".to_string(),
            install_package: "samba".to_string(),
        });
    }
    for u in &users {
        ensure_unix_user(&u.username)?;
        wolfstack_managed_users_record(&u.username);
    }
    Ok(())
}

/// Public reconciliation entry-point — called by the API layer
/// AFTER every gateway mutation has been persisted to disk. Reads
/// the on-disk gateway store to compute the active user set, then
/// removes any wolfstack-managed user that no gateway still
/// references. Operator's pre-existing Samba users (never recorded
/// in /var/lib/samba/wolfstack-managed-users) are left alone.
///
/// Called from api/mod.rs::apply_and_persist + the delete handler.
/// Errors are logged, not propagated — the gateway config is
/// persisted successfully, and a failed prune is a recoverable
/// cleanup miss, not a correctness failure.
pub fn reconcile_managed_users() {
    if super::sources::which_helper("pdbedit").is_none() {
        return; // can't prune without pdbedit.
    }
    let store = super::GatewayStore::load();
    let mut active: std::collections::HashSet<String> = std::collections::HashSet::new();
    for g in store.gateways.values() {
        if let AuthConfig::Users { users, .. } = &g.auth {
            for u in users {
                active.insert(u.username.clone());
            }
        }
    }
    for username in wolfstack_managed_users_load() {
        if active.contains(&username) { continue; }
        let _ = Command::new("pdbedit").args(["-x", "-u", &username]).status();
        // We DON'T call `userdel` — the UNIX account may legitimately
        // be in use elsewhere. Operator can clean it up if they want.
        wolfstack_managed_users_remove(&username);
    }
}

const MANAGED_USERS_PATH: &str = "/var/lib/samba/wolfstack-managed-users";

fn wolfstack_managed_users_load() -> Vec<String> {
    std::fs::read_to_string(MANAGED_USERS_PATH).ok()
        .map(|s| s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
        .unwrap_or_default()
}

fn wolfstack_managed_users_record(username: &str) {
    let mut set = wolfstack_managed_users_load();
    if !set.iter().any(|u| u == username) {
        set.push(username.to_string());
        if let Some(parent) = std::path::Path::new(MANAGED_USERS_PATH).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(MANAGED_USERS_PATH, set.join("\n"));
    }
}

fn wolfstack_managed_users_remove(username: &str) {
    let mut set = wolfstack_managed_users_load();
    set.retain(|u| u != username);
    let _ = std::fs::write(MANAGED_USERS_PATH, set.join("\n"));
}

/// Set a user's SMB password. Plaintext is piped directly into
/// `smbpasswd -s -a` and immediately discarded — never persisted by
/// WolfStack. The hashed copy lives in `/var/lib/samba/private/passdb.tdb`.
pub fn set_user_password(username: &str, plaintext: &str) -> Result<(), SambaError> {
    use std::io::Write;
    if super::sources::which_helper("smbpasswd").is_none() {
        return Err(SambaError::NotInstalled {
            install_command: "apt-get install -y samba".to_string(),
            install_package: "samba".to_string(),
        });
    }
    ensure_unix_user(username)?;
    // smbpasswd -s -a username  reads "password\npassword\n" on stdin
    // and adds the user. -s = silent (no terminal prompts), -a = add.
    let mut child = Command::new("smbpasswd")
        .args(["-s", "-a", username])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        let line = format!("{}\n{}\n", plaintext, plaintext);
        stdin.write_all(line.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    // smbpasswd returns 0 even when re-setting an existing user's
    // password, so success is just a clean exit.
    if !out.status.success() {
        return Err(SambaError::WriteFailed(format!(
            "smbpasswd -s -a {} failed: {}",
            username,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Remove a user from Samba's passdb. Does not delete the UNIX user
/// account (the account may be in use elsewhere; v1.0 leaves it
/// alone — operator can `userdel` manually if they want).
#[allow(dead_code)]
pub fn delete_smb_user(username: &str) -> Result<(), SambaError> {
    if super::sources::which_helper("smbpasswd").is_none() {
        return Ok(());
    }
    let _ = Command::new("smbpasswd").args(["-x", username]).status();
    Ok(())
}

/// Make sure a UNIX user exists for the SMB user. Samba's tdbsam
/// requires it (it maps the SMB username to a UID). Use a system
/// account with no shell — purely for storage namespace ownership.
///
/// Tries shell candidates in order so we work on minimal distros
/// where /usr/sbin/nologin is missing (some Alpine / busybox-based
/// systems use /sbin/nologin or /bin/false).
fn ensure_unix_user(username: &str) -> Result<(), SambaError> {
    let exists = Command::new("id").arg(username).output()
        .map(|o| o.status.success()).unwrap_or(false);
    if exists { return Ok(()); }
    let shell = ["/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/nologin", "/bin/false"]
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .copied()
        .unwrap_or("/bin/false");
    let out = Command::new("useradd")
        .args(["-r", "-M", "-s", shell, username])
        .output()?;
    if !out.status.success() {
        return Err(SambaError::WriteFailed(format!(
            "useradd '{}' failed: {}",
            username,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

fn yesno(b: bool) -> &'static str { if b { "yes" } else { "no" } }

// ─── Status helpers ───

#[derive(Default, Debug, Clone, serde::Serialize)]
pub struct SmbStatus {
    pub installed: bool,
    pub running: bool,
    pub version: Option<String>,
    pub sessions: u32,
}

pub fn status() -> SmbStatus {
    let mut st = SmbStatus {
        installed: super::sources::which_helper("smbd").is_some(),
        ..Default::default()
    };
    if st.installed {
        // Same multi-distro probe as reload — smbd / smb / samba.
        st.running = ["smbd", "smb", "samba"].iter().any(|u| {
            Command::new("systemctl")
                .args(["is-active", "--quiet", u])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        });
        if let Ok(out) = Command::new("smbd").arg("--version").output()
            && out.status.success() {
                st.version = Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
            }
        // smbstatus -j is JSON — count sessions.
        if let Ok(out) = Command::new("smbstatus").arg("-j").output()
            && out.status.success()
                && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout)
                    && let Some(sessions) = v.get("sessions").and_then(|s| s.as_object()) {
                        st.sessions = sessions.len() as u32;
                    }
    }
    st
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitise_strips_dangerous_chars() {
        // Section name + filename safety: only allow A-Z a-z 0-9 - _.
        // Anything else collapses to '_' so a bracket-injection or
        // command-injection attempt can't escape the smb.conf parser
        // or write outside snippets.d.
        assert_eq!(sanitise("ops"), "ops");
        assert_eq!(sanitise("ops-share"), "ops-share");
        assert_eq!(sanitise("ops_share"), "ops_share");
        assert_eq!(sanitise("ops share"), "ops_share");
        assert_eq!(sanitise("ops]bad"), "ops_bad");
        assert_eq!(sanitise("../escape"), "___escape");
        assert_eq!(sanitise("a\nb"), "a_b");
        assert_eq!(sanitise("$IPC$"), "_IPC_");
    }

    #[test]
    fn render_snippet_anonymous_no_writes_when_readonly() {
        let g = Gateway {
            id: "abc-123".into(),
            name: "ops".into(),
            cluster: String::new(),
            mode: super::super::GatewayMode::Single,
            protocols: vec![Protocol::Smb],
            sources: vec![],
            origin_node_id: "node-a".into(),
            serve_nodes: vec![],
            auth: AuthConfig::Anonymous { writable: true },
            policy: super::super::ModePolicy::Single,
            options: GatewayOptions { readonly: true, ..Default::default() },
            created_at: String::new(),
            updated_at: String::new(),
            disabled: false,
        };
        let snippet = render_snippet(&g, std::path::Path::new("/var/share"));
        assert!(snippet.contains("[ops]"));
        assert!(snippet.contains("guest only = yes"));
        // readonly=true must override anonymous-writable.
        assert!(snippet.contains("writable = no"));
    }

    #[test]
    fn render_snippet_users_emits_valid_users_and_write_list() {
        use super::super::UserGrant;
        let g = Gateway {
            id: "abc-123".into(),
            name: "ops".into(),
            cluster: String::new(),
            mode: super::super::GatewayMode::Single,
            protocols: vec![Protocol::Smb],
            sources: vec![],
            origin_node_id: "node-a".into(),
            serve_nodes: vec![],
            auth: AuthConfig::Users {
                users: vec![
                    UserGrant { username: "alice".into(), writable: true },
                    UserGrant { username: "bob".into(),   writable: false },
                ],
                default_writable: true,
            },
            policy: super::super::ModePolicy::Single,
            options: GatewayOptions::default(),
            created_at: String::new(),
            updated_at: String::new(),
            disabled: false,
        };
        let s = render_snippet(&g, std::path::Path::new("/var/share"));
        assert!(s.contains("valid users = alice bob"));
        assert!(s.contains("write list = alice"), "bob is read-only and must not be in write list — got:\n{}", s);
    }

    #[test]
    fn render_snippet_disabled_marks_unavailable() {
        let g = Gateway {
            id: "abc-123".into(),
            name: "ops".into(),
            cluster: String::new(),
            mode: super::super::GatewayMode::Single,
            protocols: vec![Protocol::Smb],
            sources: vec![],
            origin_node_id: "node-a".into(),
            serve_nodes: vec![],
            auth: AuthConfig::Anonymous { writable: false },
            policy: super::super::ModePolicy::Single,
            options: GatewayOptions::default(),
            created_at: String::new(),
            updated_at: String::new(),
            disabled: true,
        };
        let s = render_snippet(&g, std::path::Path::new("/var/share"));
        assert!(s.contains("available = no"));
    }

    fn wide_links_gateway(on: bool) -> Gateway {
        Gateway {
            id: "abc-123".into(),
            name: "tank".into(),
            cluster: String::new(),
            mode: super::super::GatewayMode::Single,
            protocols: vec![Protocol::Smb],
            sources: vec![],
            origin_node_id: "node-a".into(),
            serve_nodes: vec![],
            auth: AuthConfig::Anonymous { writable: false },
            policy: super::super::ModePolicy::Single,
            options: GatewayOptions { smb_wide_links: on, ..Default::default() },
            created_at: String::new(),
            updated_at: String::new(),
            disabled: false,
        }
    }

    #[test]
    fn render_snippet_wide_links_emits_share_level_pair_only() {
        let s = render_snippet(&wide_links_gateway(true), std::path::Path::new("/tank"));
        assert!(s.contains("follow symlinks = yes"));
        assert!(s.contains("wide links = yes"));
        // Global-only parameter — must NOT appear in the share section
        // (smbd ignores it there with a warning).
        assert!(!s.contains("unix extensions"));
    }

    #[test]
    fn render_snippet_default_has_no_symlink_options() {
        let s = render_snippet(&wide_links_gateway(false), std::path::Path::new("/tank"));
        assert!(!s.contains("follow symlinks"));
        assert!(!s.contains("wide links"));
    }

    #[test]
    fn aggregator_disables_unix_extensions_when_wide_links_requested() {
        // Active in-memory gateway short-circuits before the on-disk
        // store is consulted, so this is deterministic in any test env.
        let g = wide_links_gateway(true);
        let body = render_aggregator(Some(&g)).expect("render");
        assert!(body.contains("    unix extensions = no\n"),
            "wide links needs the global smb1-unix-extensions kill switch — got:\n{}", body);
    }
}
