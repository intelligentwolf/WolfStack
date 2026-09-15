// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Security posture scanner + active-attack detection.
//!
//! Runs alongside the System Check audit and emits findings in the
//! same `DependencyCheck` shape so the existing Settings → System
//! Check UI auto-renders them under a dedicated "Security" category.
//! No new endpoint, no new frontend — just more rows.
//!
//! Two flavours of checks:
//!
//! **Posture** — static things that should be true on a healthy host:
//!   • No risky services listening on 0.0.0.0 (Docker 2375, Redis, Mongo…)
//!   • /etc/wolfstack/ config files aren't world-readable
//!   • sshd hardened: no root login, no password auth
//!   • fail2ban / sshguard running when SSH is exposed
//!   • Cluster secret is long + high-entropy
//!
//! **Active attack** — things happening right now that warrant alerting:
//!   • SSH brute-force in progress (≥ N failed auths from one IP in 5 min)
//!   • Known-bad crypto miner processes running (xmrig, minerd, cpuminer…)
//!   • Recent executable files in /tmp or /dev/shm (malware staging)
//!   • Outbound connections to unusual ports (IRC C2, Tor nodes, etc.)
//!
//! Every check catches its own errors — a broken log file in one
//! place never blocks the others. Missing tools are reported as
//! `Unsupported` so they don't look like failures.
//!
//! Designed to run both on demand (from `/api/system-check`) and on
//! a timer from the main loop for active-attack detection with alerts.

use crate::systemcheck::{DependencyCheck, DepStatus};
use chrono::Datelike;
use std::os::unix::fs::{PermissionsExt, MetadataExt};
use std::path::Path;
use std::process::Command;

/// Cluster-wide security checks that need access to AppState (for
/// topology / cluster info). Called from the /api/system-check
/// endpoint alongside the stateless `run_security_checks()`.
///
/// Separated because the background security scanner in main.rs
/// doesn't have AppState — it only runs the stateless checks. The
/// cluster-scoped checks only run on-demand from the UI which is
/// fine because cross-node IP conflicts don't change on a 15-min
/// cadence (containers don't move by themselves).
pub fn run_cluster_checks(state: &crate::api::AppState) -> Vec<DependencyCheck> {
    let mut out = Vec::new();
    scan_cluster_ip_conflicts(state, &mut out);
    out
}

/// Detect duplicate WolfNet IPs across containers/VMs on DIFFERENT
/// nodes within the same cluster. The local `scan_ip_conflicts`
/// catches same-node duplicates from LXC config files; this catches
/// cross-node duplicates that only show up when the full cluster
/// topology is assembled.
///
/// Scoped to the current cluster: containers in cluster A and cluster
/// B CAN have the same WolfNet IP — they're on separate overlay
/// networks and never interfere.
fn scan_cluster_ip_conflicts(
    state: &crate::api::AppState,
    out: &mut Vec<DependencyCheck>,
) {
    // Build (ip → [(container_name, node_name)]) map from ALL nodes in
    // the cluster. Uses the cached topology snapshots from the last
    // agent poll (including the local node's). Does NOT call
    // compute_local() here — that shells out to ip/ss/curl and would
    // stall the request thread for seconds. The topology poll (every
    // 3s) already keeps these snapshots fresh.
    let mut ip_owners: std::collections::HashMap<String, Vec<(String, String)>> =
        std::collections::HashMap::new();

    // Remote nodes' cached topologies (includes containers + VMs with
    // their WolfNet IPs from the last successful poll).
    {
        let remotes = state.router.remote_topologies.read().unwrap();
        for topo in remotes.values() {
            collect_ips(topo, &mut ip_owners);
        }
    }

    // Local node's containers — read from LXC storage paths directly
    // (cheap filesystem read, no subprocess) so we don't miss the
    // local node's containers when remote_topologies doesn't include
    // self.
    {
        let self_name = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "this node".into());
        for base in crate::containers::lxc_storage_paths() {
            let entries = match std::fs::read_dir(&base) { Ok(e) => e, Err(_) => continue };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let ip_path = entry.path().join(".wolfnet").join("ip");
                if let Ok(ip) = std::fs::read_to_string(&ip_path) {
                    let ip = ip.trim().to_string();
                    if !ip.is_empty() {
                        ip_owners.entry(ip).or_default().push((name, self_name.clone()));
                    }
                }
            }
        }
    }

    // Flag any IP with >1 owner.
    for (ip, owners) in &ip_owners {
        if owners.len() < 2 { continue; }
        let detail = owners.iter()
            .map(|(cname, nname)| format!("  {} on {}", cname, nname))
            .collect::<Vec<_>>().join("\n");
        out.push(DependencyCheck {
            name: format!("Cluster-wide duplicate WolfNet IP: {}", ip),
            category: CATEGORY.into(),
            status: DepStatus::Missing,  // critical
            version: None,
            detail: format!(
                "Multiple containers/VMs across the cluster share the same WolfNet IP. WolfNet routes by IP — only one will be reachable; the other is silently unreachable until the conflict is resolved.\n\n{}",
                detail),
            install_hint: Some(
                "Open each container's Settings → Network → WolfNet and assign a unique IP. Use 🔍 Next Available to find a free one.".into()),
            ai_helpful: true,
            install_package: None,
        });
    }
}

fn collect_ips(
    topo: &crate::networking::router::topology::NodeTopology,
    map: &mut std::collections::HashMap<String, Vec<(String, String)>>,
) {
    let node = &topo.node_name;
    for c in topo.containers.iter().chain(topo.vms.iter()) {
        if let Some(ref ip) = c.ip {
            let ip = ip.trim().to_string();
            if !ip.is_empty() {
                map.entry(ip).or_default().push((c.name.clone(), node.clone()));
            }
        }
    }
}

const CATEGORY: &str = "Security";

/// Run every security check and return the findings. Cheap enough to
/// fold into `/api/system-check` — no check does more than a few
/// subprocess calls or a small log file read.
pub fn run_security_checks() -> Vec<DependencyCheck> {
    let mut out = Vec::new();
    scan_listening_services(&mut out);
    scan_config_permissions(&mut out);
    scan_cluster_secret(&mut out);
    scan_committed_default_secrets(&mut out);
    scan_sshd_config(&mut out);
    scan_fail2ban(&mut out);
    scan_broken_security_controls(&mut out);
    scan_ssh_bruteforce(&mut out);
    scan_crypto_miners(&mut out);
    scan_tmp_binaries(&mut out);
    scan_outbound_suspicious(&mut out);
    scan_ip_conflicts(&mut out);
    if out.is_empty() {
        out.push(ok("No active threats", "Every posture check passed and no active-attack signatures were detected in recent logs.", None));
    }
    out
}

// ─── Helpers for finding construction ───────────────────────────

fn ok(name: &str, detail: &str, version: Option<String>) -> DependencyCheck {
    DependencyCheck {
        name: name.into(),
        category: CATEGORY.into(),
        status: DepStatus::Ok,
        version,
        detail: detail.into(),
        install_hint: None,
        ai_helpful: false,
        install_package: None,
    }
}

fn warn(name: &str, detail: &str, fix: Option<String>) -> DependencyCheck {
    DependencyCheck {
        name: name.into(),
        category: CATEGORY.into(),
        status: DepStatus::Warning,
        version: None,
        detail: detail.into(),
        install_hint: fix,
        ai_helpful: true,
        install_package: None,
    }
}

/// Critical severity → use Missing so the red badge shows (the
/// existing UI only has 5 statuses; red is the hottest colour).
fn critical(name: &str, detail: &str, fix: Option<String>) -> DependencyCheck {
    DependencyCheck {
        name: name.into(),
        category: CATEGORY.into(),
        status: DepStatus::Missing,
        version: None,
        detail: detail.into(),
        install_hint: fix,
        ai_helpful: true,
        install_package: None,
    }
}

// ─── Listening services ─────────────────────────────────────────

/// Well-known services that are typically a mistake to expose off
/// loopback. Ordered roughly by blast radius (worst first).
const RISKY_PORTS: &[(u16, &str, &str, bool)] = &[
    // (port, service-name, reason, critical?)
    (2375, "docker-api-plain",   "Docker Engine HTTP API has no auth — anyone reaching this port has root via container escape. Should ONLY ever bind 127.0.0.1.", true),
    (2376, "docker-api-tls",     "Docker Engine HTTPS API. Cert-authed but still hands out container root to anyone with the client cert.", false),
    (6379, "redis",              "Redis by default has no auth and supports CONFIG REWRITE — classic RCE when exposed.", false),
    (27017,"mongodb",            "MongoDB historically shipped with auth disabled; exposed instances get mass-compromised.", false),
    (9200, "elasticsearch",      "Elasticsearch HTTP API — full cluster control if unauthenticated.", false),
    (3306, "mysql",              "MySQL on a non-loopback interface. Credential leak or wildcard-host user = attacker access.", false),
    (5432, "postgres",           "PostgreSQL exposed. Verify pg_hba.conf doesn't trust the network.", false),
    (11211,"memcached",          "memcached has no auth; UDP listener is a classic amplification vector.", false),
    (5601, "kibana",              "Kibana UI. If its Elasticsearch is open, attackers get a search interface too.", false),
    (111,  "rpcbind-portmap",    "rpcbind/portmapper answering off-loopback. On UDP this is a DDoS amplification vector (~7-28x, CERT TA14-017A): an attacker spoofs a victim's source address and your host floods them with the reply. On a host with no NFS server and no NFSv3 client, rpcbind registers nothing but itself and can simply be switched off — check with `rpcinfo -p 127.0.0.1` first.", false),
];

fn scan_listening_services(out: &mut Vec<DependencyCheck>) {
    let output = match Command::new("ss").args(["-tulnp"]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => {
            out.push(DependencyCheck {
                name: "Listening services scan".into(),
                category: CATEGORY.into(),
                status: DepStatus::Unsupported,
                version: None,
                detail: "ss not available — install iproute2 to scan listening sockets.".into(),
                install_hint: None,
                ai_helpful: false,
                install_package: None,
            });
            return;
        }
    };

    for line in output.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 { continue; }
        let netid = fields[0];
        let local = fields[4];
        if local.starts_with("127.") || local.starts_with("[::1]:") { continue; }
        let port: u16 = match local.rsplit(':').next().and_then(|p| p.parse().ok()) {
            Some(p) => p, None => continue,
        };
        let proto = if netid.starts_with("tcp") { "tcp" } else { "udp" };

        for (rp, service, reason, is_critical) in RISKY_PORTS {
            if *rp != port { continue; }
            let name = format!("{}/{} exposed — {}", proto, port, service);
            let detail = format!("{} Listening on {}.", reason, local);
            // The generic "bind it to 127.0.0.1" advice is a dead end here:
            // rpcbind's `-h` option (see /etc/default/rpcbind) restricts UDP
            // binds only — TCP/111 comes from `rpcbind.socket`'s ListenStream,
            // so narrowing -h leaves the TCP listener wide open. On a host with
            // no NFS rpcbind isn't needed at all, so mask BOTH units; the socket
            // unit is the one that actually holds port 111.
            let fix = Some(if port == 111 {
                "Check nothing uses RPC first:\n  rpcinfo -p 127.0.0.1\n  mount | grep 'type nfs'\nIf only 'portmapper' is registered and there are no NFS mounts, switch it off:\n  systemctl stop rpcbind.socket rpcbind.service\n  systemctl mask rpcbind.socket rpcbind.service\nIf you DO serve NFS, firewall 111 to your storage network instead."
                    .to_string()
            } else {
                format!(
                    "Bind the service to 127.0.0.1 in its config, OR block externally:\n  iptables -A INPUT -p {} --dport {} ! -s 127.0.0.1 -j DROP",
                    proto, port)
            });
            out.push(if *is_critical { critical(&name, &detail, fix) } else { warn(&name, &detail, fix) });
            break;
        }
    }
}

// ─── Config permissions ─────────────────────────────────────────

fn scan_config_permissions(out: &mut Vec<DependencyCheck>) {
    let cfg_dir = "/etc/wolfstack";
    if !Path::new(cfg_dir).exists() { return; }
    let entries = match std::fs::read_dir(cfg_dir) { Ok(e) => e, Err(_) => return };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        let looks_sensitive = name.contains("secret")
            || name.contains("credentials")
            || name.contains("chap")
            || name.contains("pap")
            || name == "ai.json"
            || name == "alerting.json"
            || name == "wolfhost.json";
        if !looks_sensitive { continue; }
        let perm_bits = match std::fs::metadata(&path) {
            Ok(m) => m.permissions().mode() & 0o777, Err(_) => continue,
        };
        let world_readable = perm_bits & 0o004 != 0;
        let group_readable = perm_bits & 0o040 != 0;
        if world_readable {
            out.push(critical(
                &format!("{} is world-readable", name),
                &format!("Mode {:o} on {} — any local user can read its contents (API keys, cluster secrets).", perm_bits, path.display()),
                Some(format!("chmod 600 {}", path.display())),
            ));
        } else if group_readable {
            out.push(warn(
                &format!("{} is group-readable", name),
                &format!("Mode {:o} on {} — non-admin group members can read credentials.", perm_bits, path.display()),
                Some(format!("chmod 600 {}", path.display())),
            ));
        }
    }
}

// ─── Cluster secret ─────────────────────────────────────────────

fn scan_cluster_secret(out: &mut Vec<DependencyCheck>) {
    // Read the SAME file the auth loader uses
    // (`crate::auth::custom_secret_path()` resolves to
    // `/etc/wolfstack/custom-cluster-secret`). The pre-secret-audit
    // version of this scanner checked `cluster_secret.txt` — a path
    // that has never matched the loader, so this finding silently
    // never fired on any install.
    let path = crate::paths::get().cluster_secret;
    let s = match std::fs::read_to_string(&path) {
        Ok(t) => t.trim().to_string(), Err(_) => return,
    };
    if s.is_empty() { return; }
    let unique = s.chars().collect::<std::collections::HashSet<_>>().len();
    if s.len() < 24 {
        out.push(warn(
            "Cluster secret is too short",
            &format!("{} is {} chars; inter-node messages are trivially spoofable at that length. Aim for ≥32 random bytes.", path, s.len()),
            Some(format!("head -c 32 /dev/urandom | base64 > {} && chmod 600 {}  (then propagate to every cluster node)", path, path)),
        ));
    } else if s.len() >= 8 && unique < 4 {
        out.push(warn(
            "Cluster secret has low entropy",
            &format!("Only {} unique characters across {} — looks like a placeholder or keyboard-walked value.", unique, s.len()),
            Some(format!("head -c 32 /dev/urandom | base64 > {} && chmod 600 {}", path, path)),
        ));
    }
}

/// Surface every finding from the central secret-audit module into
/// the System Check scanner UI. Reuses the existing severity colours
/// (Missing = red, Warning = yellow) to match the rest of Security.
/// The audit module is the single source of truth — the same Vec
/// also powers `/api/security/secret-audit` and the heartbeat counter.
fn scan_committed_default_secrets(out: &mut Vec<DependencyCheck>) {
    for f in crate::secret_audit::audit() {
        let check = match f.severity {
            crate::secret_audit::Severity::Compromise =>
                critical(&f.title, &f.detail, Some(f.remediation.clone())),
            crate::secret_audit::Severity::High =>
                warn(&f.title, &f.detail, Some(f.remediation.clone())),
            crate::secret_audit::Severity::Info =>
                ok(&f.title, &f.detail, None),
        };
        out.push(check);
    }
}

// ─── sshd hardening ─────────────────────────────────────────────

/// Effective value of an sshd setting. Prefers `sshd -T` (which honors drop-in
/// files under /etc/ssh/sshd_config.d/ and Match blocks); falls back to the
/// FIRST matching line of the raw config (sshd is first-match-wins) only if
/// `sshd -T` can't run. Lowercased value, or None if neither source has it.
///
/// This is what makes a `PermitRootLogin prohibit-password` drop-in clear the
/// finding even when the main /etc/ssh/sshd_config still says `yes` (e.g.
/// Proxmox re-asserting it) — the drop-in wins in the effective config.
pub fn sshd_effective(key: &str) -> Option<String> {
    if let Ok(out) = std::process::Command::new("sshd").arg("-T").output()
        && out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let mut parts = line.split_whitespace();
                if let (Some(k), Some(v)) = (parts.next(), parts.next())
                    && k.eq_ignore_ascii_case(key) { return Some(v.to_ascii_lowercase()); }
            }
        }
    // Fallback: raw file, first match (Includes are NOT expanded here — that's
    // exactly why sshd -T is preferred; this only runs if sshd -T is missing).
    let text = std::fs::read_to_string("/etc/ssh/sshd_config").ok()?;
    let want = key.to_ascii_lowercase();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() { continue; }
        let lower = line.to_ascii_lowercase();
        let mut parts = lower.split_whitespace();
        if let (Some(k), Some(v)) = (parts.next(), parts.next())
            && k == want { return Some(v.to_string()); }
    }
    None
}

fn scan_sshd_config(out: &mut Vec<DependencyCheck>) {
    // Effective config (sshd -T) so drop-ins / Match blocks are honored.
    let root_login_yes = sshd_effective("permitrootlogin").as_deref() == Some("yes");
    let password_auth_yes = sshd_effective("passwordauthentication").as_deref() == Some("yes");
    // Proxmox uses root SSH for cluster operations (pvecm/corosync) and
    // re-asserts PermitRootLogin on its own, so the finding is un-actionable
    // there — suppress it on Proxmox. Operators who want key-only root can drop
    // a /etc/ssh/sshd_config.d/*.conf with `PermitRootLogin prohibit-password`,
    // which `sshd_effective` honors and which survives the reset.
    if root_login_yes && !crate::containers::is_proxmox() {
        out.push(critical(
            "sshd allows root login",
            "/etc/ssh/sshd_config has PermitRootLogin yes — direct root-over-SSH is widely scanned for and trivially brute-forced. Disable it.",
            Some("Edit /etc/ssh/sshd_config: `PermitRootLogin no` then `systemctl restart sshd`. Create a regular user with sudo first if you don't have one.".into()),
        ));
    }
    if password_auth_yes {
        out.push(warn(
            "sshd accepts password authentication",
            "/etc/ssh/sshd_config has PasswordAuthentication yes. Key-only auth + fail2ban is dramatically safer against the constant scan traffic every public SSH endpoint sees.",
            Some("Set PasswordAuthentication no and PubkeyAuthentication yes in /etc/ssh/sshd_config (make sure your key works first!), then `systemctl restart sshd`.".into()),
        ));
    }
}

// ─── fail2ban presence ─────────────────────────────────────────

fn ssh_is_exposed() -> bool {
    // Use -tulnp (same shape as scan_listening_services) — with -t alone
    // ss drops the Netid column and field indices shift, which silently
    // broke this check in the first cut.
    let out = match Command::new("ss").args(["-tulnp"]).output() {
        Ok(o) if o.status.success() => o.stdout, _ => return false,
    };
    for line in String::from_utf8_lossy(&out).lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 { continue; }
        if !fields[0].starts_with("tcp") { continue; }  // SSH is TCP only
        let local = fields[4];
        if local.starts_with("127.") || local.starts_with("[::1]:") { continue; }
        if local.ends_with(":22") { return true; }
    }
    false
}

fn process_running(name: &str) -> bool {
    Command::new("pgrep").args(["-x", name]).output()
        .map(|o| o.status.success()).unwrap_or(false)
}

fn scan_fail2ban(out: &mut Vec<DependencyCheck>) {
    if !ssh_is_exposed() { return; }
    if process_running("fail2ban-server") || process_running("sshguard") { return; }
    out.push(warn(
        "SSH exposed without brute-force protection",
        "sshd is listening on a non-loopback address but neither fail2ban nor sshguard is running. Public SSH endpoints see constant dictionary attacks — even key-only auth benefits from fail2ban because it blocks scanners early and shrinks log noise.",
        Some("Install fail2ban:\n  Debian/Ubuntu:  sudo apt install fail2ban && sudo systemctl enable --now fail2ban\n  Fedora/RHEL:    sudo dnf install fail2ban && sudo systemctl enable --now fail2ban\n  Arch:           sudo pacman -S fail2ban && sudo systemctl enable --now fail2ban\nVerify:  sudo fail2ban-client status sshd".into()),
    ));
}

// ─── Broken security controls ───────────────────────────────────
//
// A security tool that is installed but cannot do its job is worse
// than one that's absent — the operator believes the control exists.
// wolf1 (2026-08-01): chkrootkit's nightly run exited 127 for weeks
// (config set MAILTO="root", the Debian wrapper mails via `mail`,
// and no mail/mailx binary was installed — only /usr/sbin/sendmail),
// AND it had no /var/log/chkrootkit/log.expected baseline, so every
// successful run would have mailed its entire output regardless of
// change. A rootkit scanner simultaneously crying wolf nightly and
// incapable of telling anyone — while WolfStack reported the node
// healthy. Three failure modes, each checked independently:
//
//   1. Unit in failed state (the scanner itself is dead)
//   2. Alert delivery impossible (runs fine, findings go nowhere —
//      checked even when the unit is green; this is the mode that
//      hid for weeks)
//   3. Baseline never initialised (runs, alerts, but the output is
//      all noise or the tool skips its core comparison)
//
// Everything here is Posture, not Compromise — per the AlertCategory
// doc (alerting.rs), Compromise means "actively on fire", and a
// misconfigured scanner is a recommendation-grade finding. The
// critical()-severity findings alert through the background security
// scan's default (non-prefixed) mapping, which is Posture.
//
// Deliberately NOT done here: parsing or relaying chkrootkit's own
// findings. All three of its wolf1 hits were false positives (a
// "BPFDoor" that was package-owned /usr/sbin/chronyd, a corosync
// libqb blackbox data file in /dev/shm, fail2ban's test fixtures).
// Reproducing a noisy scanner's output would reproduce its noise;
// we report on the scanner's health, never its verdicts.

/// systemd units (matched by substring) whose failure means a
/// security control is dead. "aide" also matches Debian's
/// dailyaidecheck.service; "clam" covers clamav-freshclam,
/// clamav-daemon and clamd variants.
const SECURITY_UNIT_FAMILIES: &[&str] = &[
    "chkrootkit", "rkhunter", "aide", "clam", "auditd", "fail2ban", "sshguard",
];

fn security_relevant_unit(unit: &str) -> bool {
    let lower = unit.to_lowercase();
    SECURITY_UNIT_FAMILIES.iter().any(|f| lower.contains(f))
}

/// First column of `systemctl list-units --plain --no-legend` lines.
/// Format verified live: "UNIT LOAD ACTIVE SUB DESCRIPTION",
/// whitespace-separated, no header, no bullet glyph with --plain.
fn parse_failed_unit_names(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Parse `systemctl show -p Result,ExecMainStatus <unit>` output
/// ("Result=exit-code\nExecMainStatus=127", verified live).
fn parse_unit_show(text: &str) -> (Option<String>, Option<i32>) {
    let mut result = None;
    let mut status = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Result=") {
            if !v.is_empty() { result = Some(v.to_string()); }
        } else if let Some(v) = line.strip_prefix("ExecMainStatus=") {
            status = v.trim().parse::<i32>().ok();
        }
    }
    (result, status)
}

/// Extract the last assignment of `key` from shell-syntax config
/// text (`KEY="value"`, `KEY='value'`, `KEY=value`). Comment lines
/// are skipped. Returns the raw value — callers must treat values
/// containing `$` or backticks as indeterminate (we do not evaluate
/// shell) rather than acting on them.
fn parse_shell_assignment(text: &str, key: &str) -> Option<String> {
    let mut found = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') { continue; }
        if let Some(rest) = trimmed.strip_prefix(key)
            && let Some(value) = rest.strip_prefix('=')
        {
            let value = value.trim();
            let value = value
                .strip_prefix('"').and_then(|v| v.strip_suffix('"'))
                .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                .unwrap_or(value);
            found = Some(value.to_string());
        }
    }
    found
}

/// A shell value we can safely act on: non-empty and free of shell
/// expansion we'd have to evaluate to understand.
fn actionable_value(v: &Option<String>) -> Option<&str> {
    match v {
        Some(s) if !s.is_empty() && !s.contains('$') && !s.contains('`') => Some(s.as_str()),
        _ => None,
    }
}

/// Look for a binary in the directories cron and systemd actually
/// use. `command -v` semantics without inheriting WolfStack's own
/// PATH (which may be richer than the nightly job's).
fn binary_on_path(name: &str) -> bool {
    ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]
        .iter()
        .any(|d| Path::new(d).join(name).exists())
}

fn scan_broken_security_controls(out: &mut Vec<DependencyCheck>) {
    scan_failed_security_units(out);
    scan_control_mail_delivery(out);
    scan_control_baselines(out);
}

/// Mode 1: the unit itself is dead. `systemctl --state=failed` only
/// lists units systemd has given up on, so anything here matching a
/// security family is a control that is not running at all.
fn scan_failed_security_units(out: &mut Vec<DependencyCheck>) {
    let text = match Command::new("systemctl")
        .args(["list-units", "--type=service,timer", "--state=failed",
               "--plain", "--no-legend", "--no-pager"])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return,  // non-systemd host (Unraid/Slackware): nothing to scan
    };
    for unit in parse_failed_unit_names(&text) {
        if !security_relevant_unit(&unit) { continue; }
        // Enrich with the real failure data — Result= and the main
        // process exit status — so the finding names the cause
        // instead of just "failed".
        let (result, exec_status) = match Command::new("systemctl")
            .args(["show", "-p", "Result,ExecMainStatus", &unit]).output()
        {
            Ok(o) if o.status.success() =>
                parse_unit_show(&String::from_utf8_lossy(&o.stdout)),
            _ => (None, None),
        };
        let mut cause = match (&result, exec_status) {
            (Some(r), Some(s)) => format!("Result={}, last exit status {}", r, s),
            (Some(r), None) => format!("Result={}", r),
            _ => "see `systemctl status` for the failure record".to_string(),
        };
        if exec_status == Some(127) {
            // Source: POSIX shell — 127 is "command not found". This
            // is the wolf1 signature: the unit's script calls a
            // binary (usually `mail`) that isn't installed.
            cause.push_str(
                " — exit 127 means 'command not found': the unit's script \
                 invokes a binary that is not installed (a missing `mail` \
                 command is the classic cause for scanner wrappers)");
        }
        out.push(critical(
            &format!("Security control failed: {}", unit),
            &format!(
                "{} is in systemd 'failed' state — this security control is not \
                 running, and has not been since the failure. A dead scanner \
                 provides zero protection while the host still appears covered. \
                 Cause: {}.",
                unit, cause),
            Some(format!(
                "Diagnose and restart it:\n  systemctl status {u}\n  journalctl -u {u} -n 50 --no-pager\n  # after fixing the cause:\n  sudo systemctl restart {u}",
                u = unit)),
        ));
    }
}

/// Mode 2: the control runs but its alerts cannot be delivered.
/// Checked INDEPENDENTLY of unit state — a green unit whose mail
/// pipe is broken is precisely the failure that hides longest.
///
/// Per-tool transport, each verified against the actual Debian
/// packaging (sources.debian.org):
///   chkrootkit — chkrootkit-daily sources /etc/chkrootkit/chkrootkit.conf
///     (then legacy /etc/chkrootkit.conf, which overrides), and mails
///     via `mail -s "$SUBJECT" "$MAILTO"`. Needs `mail`.
///   rkhunter — cron.daily sources /etc/default/rkhunter, gates on
///     CRON_DAILY_RUN, mails via /usr/sbin/sendmail "$REPORT_EMAIL".
///     Needs sendmail. Separately, /etc/rkhunter.conf MAIL-ON-WARNING
///     uses MAIL_CMD (upstream default: `mail -s ...`).
///   aide — dailyaidecheck sources /etc/default/aide, defaults
///     MAILTO to root, sends via s-nail if present else `mail`.
fn scan_control_mail_delivery(out: &mut Vec<DependencyCheck>) {
    // ── chkrootkit ──
    if binary_on_path("chkrootkit") {
        let mut conf = std::fs::read_to_string("/etc/chkrootkit/chkrootkit.conf")
            .unwrap_or_default();
        if let Ok(legacy) = std::fs::read_to_string("/etc/chkrootkit.conf") {
            // Sourced second by chkrootkit-daily → later assignments win.
            conf.push('\n');
            conf.push_str(&legacy);
        }
        let run_daily = parse_shell_assignment(&conf, "RUN_DAILY");
        let daily_disabled = matches!(run_daily.as_deref(), Some("false"));
        let mailto = parse_shell_assignment(&conf, "MAILTO");
        if !daily_disabled
            && let Some(addr) = actionable_value(&mailto)
                && !binary_on_path("mail") && !binary_on_path("mailx") {
                    out.push(critical(
                        "Security alerts undeliverable: chkrootkit has no mail command",
                        &format!(
                            "chkrootkit's daily job is configured to mail its report to \
                             '{}' (MAILTO in /etc/chkrootkit/chkrootkit.conf), but the \
                             `mail` command it invokes is not installed. Every nightly \
                             run dies with exit 127 — the scanner produces findings \
                             nobody will ever see, and has been failing this way since \
                             the mail command went missing. An MTA at /usr/sbin/sendmail \
                             alone is NOT enough: the wrapper calls `mail`, not sendmail.",
                            addr),
                        Some(
                            "Install a mail(1) provider that hands off to your MTA:\n  \
                             Debian/Proxmox:  sudo apt install bsd-mailx   (or mailutils)\n\
                             Then prove delivery end-to-end:\n  \
                             echo test | mail -s \"chkrootkit mail path test\" root".into()),
                    ));
                }
    }

    // ── rkhunter ──
    if binary_on_path("rkhunter") {
        if let Ok(defaults) = std::fs::read_to_string("/etc/default/rkhunter") {
            // Source: Debian rkhunter cron.daily — runs only when
            // CRON_DAILY_RUN matches [YyTt]*.
            let cron_on = actionable_value(&parse_shell_assignment(&defaults, "CRON_DAILY_RUN"))
                .map(|v| v.starts_with(['y', 'Y', 't', 'T']))
                .unwrap_or(false);
            let report = parse_shell_assignment(&defaults, "REPORT_EMAIL");
            if cron_on
                && let Some(addr) = actionable_value(&report)
                    && !Path::new("/usr/sbin/sendmail").exists() && !binary_on_path("sendmail") {
                        out.push(critical(
                            "Security alerts undeliverable: rkhunter has no sendmail",
                            &format!(
                                "rkhunter's daily cron job is configured to mail warnings to \
                                 '{}' (REPORT_EMAIL in /etc/default/rkhunter) via \
                                 /usr/sbin/sendmail, which is not installed. Scan warnings \
                                 are silently lost.", addr),
                            Some("Install an MTA that provides /usr/sbin/sendmail (e.g. \
                                  `sudo apt install postfix` — 'local only' is fine) and send \
                                  a test message.".into()),
                        ));
                    }
        }
        if let Ok(conf) = std::fs::read_to_string("/etc/rkhunter.conf") {
            let warn_addr = parse_shell_assignment(&conf, "MAIL-ON-WARNING");
            if let Some(addr) = actionable_value(&warn_addr) {
                // Upstream default MAIL_CMD invokes `mail`; a custom
                // MAIL_CMD's first token is the binary to check.
                let mail_cmd = parse_shell_assignment(&conf, "MAIL_CMD");
                let mail_bin = actionable_value(&mail_cmd)
                    .and_then(|c| c.split_whitespace().next())
                    .unwrap_or("mail")
                    .to_string();
                let bin_name = mail_bin.rsplit('/').next().unwrap_or(&mail_bin);
                let present = if mail_bin.starts_with('/') {
                    Path::new(&mail_bin).exists()
                } else {
                    binary_on_path(bin_name)
                };
                if !present {
                    out.push(critical(
                        "Security alerts undeliverable: rkhunter MAIL-ON-WARNING is broken",
                        &format!(
                            "/etc/rkhunter.conf sets MAIL-ON-WARNING='{}' but the configured \
                             mail command ('{}') is not installed — warnings found during \
                             checks are silently lost.", addr, mail_bin),
                        Some("Install the mail command (Debian: `sudo apt install bsd-mailx`) \
                              or point MAIL_CMD at a binary that exists, then run \
                              `rkhunter --check --sk` to confirm.".into()),
                    ));
                }
            }
        }
    }

    // ── aide ──
    let aide_daily = Path::new("/usr/share/aide/bin/dailyaidecheck").exists();
    if aide_daily || binary_on_path("aide") {
        // Source: Debian dailyaidecheck — MAILTO="${MAILTO:-root}"
        // after sourcing /etc/default/aide, so mail is intended even
        // with no defaults file. Delivery is s-nail, falling back to
        // `mail`.
        let mailto = std::fs::read_to_string("/etc/default/aide")
            .ok()
            .and_then(|t| parse_shell_assignment(&t, "MAILTO"))
            .unwrap_or_else(|| "root".to_string());
        let mailto_opt = Some(mailto);
        if let Some(addr) = actionable_value(&mailto_opt)
            && !binary_on_path("s-nail") && !binary_on_path("mail") {
                out.push(critical(
                    "Security alerts undeliverable: AIDE has no mail command",
                    &format!(
                        "AIDE's daily integrity check mails its report to '{}' via \
                         s-nail or mail(1), and neither is installed. Integrity \
                         violations would be detected and then silently discarded.",
                        addr),
                    Some("Install one: `sudo apt install s-nail` (or bsd-mailx), \
                          then run the check once by hand to confirm delivery: \
                          `systemctl start dailyaidecheck.service`.".into()),
                ));
            }
    }
}

/// Mode 3: the tool runs but its baseline was never created, so its
/// core comparison never happens.
fn scan_control_baselines(out: &mut Vec<DependencyCheck>) {
    // chkrootkit diff baseline. Source: chkrootkit-daily —
    // EXPECTED_OUTPUT="$LOG_DIR/log.expected", LOG_DIR=/var/log/chkrootkit,
    // DIFF_MODE default "true". Without the baseline, every nightly
    // mail contains the FULL output instead of a diff — permanent
    // alert fatigue that trains the operator to ignore the control.
    if binary_on_path("chkrootkit") {
        let mut conf = std::fs::read_to_string("/etc/chkrootkit/chkrootkit.conf")
            .unwrap_or_default();
        if let Ok(legacy) = std::fs::read_to_string("/etc/chkrootkit.conf") {
            conf.push('\n');
            conf.push_str(&legacy);
        }
        let daily_off = matches!(
            parse_shell_assignment(&conf, "RUN_DAILY").as_deref(), Some("false"));
        let diff_off = matches!(
            parse_shell_assignment(&conf, "DIFF_MODE").as_deref(), Some("false"));
        if !daily_off && !diff_off
            && !Path::new("/var/log/chkrootkit/log.expected").exists()
        {
            out.push(warn(
                "chkrootkit has no baseline — full output mailed every night",
                "DIFF_MODE is on (the default) but /var/log/chkrootkit/log.expected \
                 does not exist, so the daily job mails its ENTIRE output every \
                 night regardless of change. chkrootkit's raw output includes \
                 known false positives (package-owned daemons flagged as \
                 'suspicious', corosync's /dev/shm blackbox files, fail2ban test \
                 fixtures) — nightly identical noise guarantees real changes get \
                 ignored.",
                Some("Review the current output, then accept it as the baseline:\n  \
                      less /var/log/chkrootkit/log.today\n  \
                      sudo cp -a /var/log/chkrootkit/log.today /var/log/chkrootkit/log.expected\n\
                      From then on you're only mailed the DIFF when something changes.".into()),
            ));
        }
    }

    // AIDE database. Source: Debian aide.conf
    // (database_in=file:/var/lib/aide/aide.db) and dailyaidecheck,
    // which exits fatally when the database is absent — an AIDE
    // install with no database does literally nothing.
    if (Path::new("/usr/share/aide/bin/dailyaidecheck").exists() || binary_on_path("aide"))
        && !Path::new("/var/lib/aide/aide.db").exists()
    {
        out.push(critical(
            "AIDE is installed but has no database — integrity checking is inert",
            "/var/lib/aide/aide.db does not exist. AIDE's daily check exits with \
             a fatal error before comparing anything, so file-integrity \
             monitoring is not happening at all despite the tool being installed.",
            Some("Initialise it (takes a while on big filesystems):\n  \
                  sudo aideinit\n  # then verify the timer runs clean:\n  \
                  sudo systemctl start dailyaidecheck.service && systemctl status dailyaidecheck.service".into()),
        ));
    }

    // rkhunter file-properties database. Source: rkhunter.conf —
    // DBDIR=/var/lib/rkhunter/db; `rkhunter --propupd` creates
    // rkhunter.dat there. Without it the file-properties comparison
    // is blind (other checks still run, hence warn not critical).
    if binary_on_path("rkhunter")
        && !Path::new("/var/lib/rkhunter/db/rkhunter.dat").exists()
    {
        out.push(warn(
            "rkhunter has no file-properties baseline",
            "/var/lib/rkhunter/db/rkhunter.dat does not exist — `rkhunter \
             --propupd` has never been run, so file-properties checks (the \
             ones that catch replaced binaries) have no baseline to compare \
             against.",
            Some("Create it while the system is in a known-good state:\n  \
                  sudo rkhunter --propupd\nRe-run after every legitimate \
                  package upgrade (Debian's APT hook does this automatically \
                  when APT_AUTOGEN is enabled in /etc/default/rkhunter).".into()),
        ));
    }
}

// ─── Active attack: SSH brute force ─────────────────────────────

/// Count recent "Failed password" / "Invalid user" entries grouped by
/// source IP. Threshold = 10 in the last 5 minutes from one IP. Uses
/// journalctl if available (works on any systemd box regardless of
/// where auth actually logs) with a fallback to /var/log/auth.log.
fn scan_ssh_bruteforce(out: &mut Vec<DependencyCheck>) {
    // `journalctl --since "5 minutes ago"` is the right way. If it's
    // not available (non-systemd boxes), fall back to tailing the last
    // N lines of /var/log/auth.log via `tail -n 2000`. NEVER read the
    // full auth.log — on a server running for months it can be tens of
    // thousands of historical lines, which would make the "last 5
    // minutes" count meaningless and fire alerts for attackers that
    // stopped days ago.
    let text = Command::new("journalctl")
        .args(["--since", "5 minutes ago", "-u", "ssh", "-u", "sshd",
               "-u", "openssh-server", "--no-pager", "--output=cat"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .or_else(|| {
            // Tail the last 2000 lines — plenty for a real brute-force
            // window, bounded enough that noisy historical hosts don't
            // trigger false positives. Caller filters further by the
            // per-line timestamp below.
            Command::new("tail")
                .args(["-n", "2000", "/var/log/auth.log"])
                .output().ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        })
        .unwrap_or_default();
    if text.is_empty() { return; }

    // Count failures per IP. If the line has a classic syslog timestamp
    // ("Apr 16 21:30:45 host sshd..."), filter to the last 5 minutes —
    // journalctl already does this for us, but the auth.log fallback
    // returns the last 2000 lines which may cover days on a quiet box.
    let now = chrono::Utc::now();
    let window = chrono::Duration::minutes(5);
    let year = now.year();
    let mut counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for line in text.lines() {
        if !line.contains("Failed password") && !line.contains("Invalid user") { continue; }
        // Parse the leading syslog timestamp if present. Format is
        // "Mmm DD HH:MM:SS" (fixed-width-ish; DD can be "%e" with a
        // space or "%d"). Skip the filter silently if it doesn't parse
        // — journalctl lines have no leading timestamp with --output=cat
        // and we want to count those.
        let first_15 = line.chars().take(15).collect::<String>();
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(
            &format!("{} {}", year, first_15), "%Y %b %e %H:%M:%S")
            .or_else(|_| chrono::NaiveDateTime::parse_from_str(
                &format!("{} {}", year, first_15), "%Y %b %d %H:%M:%S"))
        {
            let t = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive, chrono::Utc);
            if now.signed_duration_since(t) > window { continue; }
        }
        // Extract "from X.X.X.X" IP. Dumb scan — no regex engine for a dep.
        if let Some(idx) = line.rfind(" from ") {
            let rest = &line[idx + 6..];
            let ip = rest.split_whitespace().next().unwrap_or("");
            if ip.is_empty() { continue; }
            let ip = ip.trim_start_matches('[').split(']').next().unwrap_or(ip);
            *counts.entry(ip.to_string()).or_insert(0) += 1;
        }
    }
    let mut attackers: Vec<(String, u32)> = counts.into_iter()
        .filter(|(_, n)| *n >= 10)
        .collect();
    attackers.sort_by_key(|attacker| std::cmp::Reverse(attacker.1));
    if attackers.is_empty() { return; }
    let top = attackers.iter().take(5)
        .map(|(ip, n)| format!("  {} — {} failed attempts", ip, n))
        .collect::<Vec<_>>().join("\n");
    let total: u32 = attackers.iter().map(|(_, n)| n).sum();
    out.push(critical(
        &format!("SSH brute-force in progress ({} IP{}, {} attempts/5min)",
            attackers.len(), if attackers.len() == 1 { "" } else { "s" }, total),
        &format!(
            "Multiple failed SSH authentication attempts in the last 5 minutes:\n\n{}\n\nThis is either active scanning, a targeted brute-force, or a misconfigured client hammering with wrong credentials.",
            top),
        Some("Install fail2ban to auto-block (see the related finding for install commands). For immediate manual block: `iptables -A INPUT -s <IP> -j DROP`. Consider moving sshd to a non-default port to shed scan traffic.".into()),
    ));
}

// ─── Active attack: crypto miners ───────────────────────────────

/// Known crypto-miner process names. If one of these shows up on a
/// host the operator didn't put there, it's almost certainly a
/// compromise — miners are the most common payload for exposed-Redis,
/// exposed-Docker-API, and weak-SSH attacks.
const MINER_PROCS: &[&str] = &[
    "xmrig", "xmr-stak", "minerd", "cpuminer", "ccminer",
    "ethminer", "nsfminer", "phoenixminer", "teamredminer",
    "nbminer", "lolminer", "bzminer", "t-rex", "gminer",
    "cgminer", "bfgminer", "minergate",
];

fn scan_crypto_miners(out: &mut Vec<DependencyCheck>) {
    // Read /proc/*/comm directly instead of spawning pgrep per miner
    // name. One walk of /proc, one read() per PID — no subprocess
    // forks. On a busy host this is ~50× cheaper than the 17-pgrep
    // loop the first cut used, which is the difference between the
    // security scan being a background hum and being a noticeable
    // blip in top.
    let mut hits: Vec<(String, String)> = Vec::new();
    let proc_entries = match std::fs::read_dir("/proc") { Ok(e) => e, Err(_) => return };
    for entry in proc_entries.flatten() {
        let name = entry.file_name();
        let name_s = name.to_string_lossy();
        // Only directories whose name is entirely digits are PIDs.
        if !name_s.chars().all(|c| c.is_ascii_digit()) { continue; }
        let comm_path = entry.path().join("comm");
        let comm = match std::fs::read_to_string(&comm_path) {
            Ok(s) => s.trim().to_string(), Err(_) => continue,
        };
        // comm is truncated to 15 chars in the kernel (TASK_COMM_LEN).
        // Our miner list names are all <=15 chars so equality works.
        if !MINER_PROCS.contains(&comm.as_str()) { continue; }
        // Pull the full cmdline for context (argv0\0argv1\0...).
        let cmdline = std::fs::read_to_string(entry.path().join("cmdline"))
            .unwrap_or_default()
            .replace('\0', " ").trim().to_string();
        let pid = name_s.to_string();
        hits.push((comm, format!("PID {}  {}", pid, if cmdline.is_empty() { "(no cmdline)".to_string() } else { cmdline })));
    }
    if hits.is_empty() { return; }
    let detail = hits.iter()
        .map(|(proc, line)| format!("  [{}]  {}", proc, line))
        .collect::<Vec<_>>().join("\n");
    out.push(critical(
        &format!("Crypto-miner process detected ({} match{})",
            hits.len(), if hits.len() == 1 { "" } else { "es" }),
        &format!(
            "Known crypto-miner binaries are running on this host. If you didn't install them, the box is compromised — miners are the #1 payload for exposed-Redis, exposed-Docker-API, and weak-SSH hacks.\n\n{}",
            detail),
        Some("1. Identify the parent: `ps -ef | grep <pid>` and check if it's a container (`docker ps -q | xargs docker inspect`). 2. Kill it: `kill -9 <pid>`. 3. Find the persistence mechanism (cron, systemd unit, ~/.bashrc, /etc/rc.local) and remove it. 4. Rotate every credential on this host. 5. Consider reimaging — miners rarely come alone.".into()),
    ));
}

// ─── Active attack: recent tmp binaries ────────────────────────

/// Malware drops its stage-2 in /tmp or /dev/shm because those are
/// world-writable. Flag any executable file in those dirs newer than
/// 24 hours old (excluding known-benign patterns like pip unpack dirs).
///
/// The executable-bit gate is load-bearing and must stay: plain DATA
/// files in these dirs are normal (corosync's libqb writes its
/// qb-*-blackbox ring buffers into /dev/shm mode 0600 — chkrootkit
/// flags those; we must not). Only something both fresh AND
/// executable is staging-shaped.
///
/// Per-file decision is pure (`tmp_file_flaggable`) so every branch
/// is unit-tested; the ownership suppression below it is the second
/// gate.
fn tmp_file_flaggable(name: &str, mode: u32, age_secs: i64) -> bool {
    if mode & 0o111 == 0 { return false; }
    // Files older than 24h aren't worth flagging (and negative age =
    // clock skew — don't trust it).
    if !(0..=86400).contains(&age_secs) { return false; }
    // Common benign droppers.
    !(name.starts_with("systemd-") || name.starts_with("tmp.")
        || name.starts_with(".systemd-") || name.starts_with("tmux-")
        || name.starts_with("pip-") || name.ends_with(".tmp"))
}

/// True when `path` is owned by an installed package AND the package
/// manager's digest check confirms the file is unmodified. Used to
/// suppress false positives the chkrootkit way of working produces
/// (wolf1: chronyd flagged as "BPFDoor" — dpkg -S owned, dpkg -V
/// clean; an hour wasted disproving it).
///
/// dpkg: `dpkg-query -S` resolves the owner (format "pkg1, pkg2:
/// path", dpkg-query(1)); `dpkg -V pkg` (rpm-format output) prints a
/// line ONLY for paths that fail a check, with '5' in the third
/// column for a digest mismatch (dpkg(1) --verify). No line for our
/// path = content verified. rpm: `rpm -qf` + `rpm -V` with the same
/// third-column '5' semantics.
fn file_package_verified_clean(path: &str) -> bool {
    if binary_on_path("dpkg-query") && binary_on_path("dpkg") {
        let owners = match Command::new("dpkg-query").args(["-S", path]).output() {
            Ok(o) if o.status.success() =>
                crate::predictive::boot_partition::parse_dpkg_search_owners(
                    &String::from_utf8_lossy(&o.stdout), path),
            _ => return false,
        };
        if owners.is_empty() { return false; }
        for pkg in owners {
            if let Ok(v) = Command::new("dpkg").args(["-V", &pkg]).output() {
                let text = String::from_utf8_lossy(&v.stdout).to_string();
                if verify_output_digest_ok(&text, path) { return true; }
            }
        }
        return false;
    }
    if binary_on_path("rpm") {
        let owned = matches!(
            Command::new("rpm").args(["-qf", path]).output(),
            Ok(o) if o.status.success());
        if !owned { return false; }
        if let Ok(v) = Command::new("rpm").args(["-Vf", path]).output() {
            let text = String::from_utf8_lossy(&v.stdout).to_string();
            return verify_output_digest_ok(&text, path);
        }
        return false;
    }
    false
}

/// Scan dpkg/rpm verify output (rpm format: 9-char flag string, then
/// optional attribute marker, then path; lines exist only for FAILED
/// paths). Returns true when no line reports a digest mismatch ('5'
/// in the third column, per dpkg(1) and rpm(8)) for `path`.
fn verify_output_digest_ok(verify_stdout: &str, path: &str) -> bool {
    for line in verify_stdout.lines() {
        if !line.ends_with(path) { continue; }
        if line.starts_with("missing") { return false; }
        let flags: Vec<char> = line.chars().take(9).collect();
        if flags.get(2) == Some(&'5') { return false; }
    }
    true
}

fn scan_tmp_binaries(out: &mut Vec<DependencyCheck>) {
    let mut suspicious = Vec::new();
    for dir in &["/tmp", "/dev/shm"] {
        let entries = match std::fs::read_dir(dir) { Ok(e) => e, Err(_) => continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = match entry.metadata() { Ok(m) => m, Err(_) => continue };
            if !meta.is_file() { continue; }
            let mode = meta.permissions().mode();
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
            let age = now - meta.mtime();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !tmp_file_flaggable(name, mode, age) { continue; }
            // Second gate: provably package-owned and digest-clean
            // files are never reported. dpkg doesn't ship files into
            // /tmp or /dev/shm, so this fires ~never — it exists so a
            // chronyd-class "package binary misread as malware" false
            // positive is structurally impossible here.
            let path_str = path.display().to_string();
            if file_package_verified_clean(&path_str) { continue; }
            suspicious.push(format!("  {} ({:o}, {} mins old)", path.display(), mode & 0o777, age / 60));
        }
    }
    if suspicious.is_empty() { return; }
    // Severity: critical. A freshly-dropped executable in /tmp or /dev/shm
    // is a classic compromise staging area — bumping from warn → critical
    // so this finding actually reaches the operator via the security-scan
    // alert path (which is `Missing`/critical-only by design). The user's
    // Simple-mode notification list explicitly includes "suspicious /tmp
    // binary" as one of the three always-fire categories.
    out.push(critical(
        &format!("Suspicious binary in /tmp or /dev/shm ({} found)", suspicious.len()),
        &format!(
            "Files that are world-writable AND executable AND freshly-dropped are classic malware-staging indicators. If you didn't put these there, investigate.\n\n{}",
            suspicious.join("\n")),
        Some("Check each file: `file <path>` (what is it?), `lsof <path>` (is a process using it?), `ps -ef | grep <name>`. If malicious: kill the process, remove the file, find the entry point. If benign (package install, CI artefact): delete or move it so it stops triggering.".into()),
    ));
}

// ─── Active attack: outbound suspicious ─────────────────────────

/// Outbound connections to ports commonly used by RATs, C2, and
/// crypto-miner pools. Not definitive — IRC (6667) and Tor entry
/// (9001) are the obvious bad-news ports, but xmr pools use 3333,
/// 4444, 14444, 5555, 7777, 9999 all the time.
const SUSPICIOUS_REMOTE_PORTS: &[(u16, &str)] = &[
    (1337, "leet — hacker/RAT meme port"),
    (3333, "crypto-mining pool (monero stratum)"),
    (4444, "Metasploit default, common RAT port, and some mining pools"),
    (5555, "RAT / mining pool"),
    (6666, "IRC (legacy), some RAT families"),
    (6667, "IRC — classic C2 channel"),
    (7777, "common mining pool"),
    (8443, "HTTPS-alt — legit but worth noting if no HTTPS service on your side"),
    (9001, "Tor relay port (suspicious for a server)"),
    (9999, "mining pool / RAT"),
    (14444,"xmrig monero pool"),
];

fn scan_outbound_suspicious(out: &mut Vec<DependencyCheck>) {
    let text = match Command::new("ss").args(["-tn", "state", "established"]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return,
    };
    // `ss -tn state established` output format (state column is
    // suppressed when a state filter is used):
    //   Recv-Q Send-Q Local-Address:Port Peer-Address:Port
    //   0      0      192.168.1.10:42842  1.2.3.4:443
    // So we have 4 fields, peer is fields[3].
    let mut hits: Vec<(String, u16, String)> = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 { continue; }
        let peer = fields[3];           // Peer Address:Port
        // Skip private + loopback peer ranges — we only care about outbound to the internet.
        if peer.starts_with("127.") || peer.starts_with("192.168.") ||
           peer.starts_with("10.") || peer.starts_with("172.")  ||  // very rough but covers RFC1918
           peer.starts_with("[::1]:") || peer.starts_with("[fe80")
        { continue; }
        let port_str = peer.rsplit(':').next().unwrap_or("");
        let port: u16 = match port_str.parse() { Ok(p) => p, Err(_) => continue };
        for (sp, reason) in SUSPICIOUS_REMOTE_PORTS {
            if *sp == port {
                hits.push((peer.to_string(), port, (*reason).into()));
                break;
            }
        }
    }
    if hits.is_empty() { return; }
    let detail = hits.iter().take(10)
        .map(|(peer, _, reason)| format!("  {} — {}", peer, reason))
        .collect::<Vec<_>>().join("\n");
    out.push(warn(
        &format!("Outbound connection(s) to suspicious ports ({} found)", hits.len()),
        &format!(
            "Established TCP sessions to ports commonly used by RATs, C2, or crypto-miner pools:\n\n{}\n\nFalse positives happen — devs running IRC clients or mining their own hardware will show up here too. Confirm each one against what you actually run.",
            detail),
        Some("For each connection: `lsof -i :<port>` identifies the local process. If legitimate (IRC client, personal mining), leave it. If not: kill the process, remove persistence, rotate creds.".into()),
    ));
}

// ─── IP / MAC conflict detection ────────────────────────────────

/// Detect containers sharing the same IP or MAC address. Uses the
/// existing `detect_network_conflicts()` from the containers module
/// which walks every LXC config file. Additionally scans WolfNet IP
/// marker files (`.wolfnet/ip`) which the LXC config scan misses
/// because WolfNet IPs are stored separately.
fn scan_ip_conflicts(out: &mut Vec<DependencyCheck>) {
    // Reuse the existing conflict detector for LXC net config.
    let conflicts = crate::containers::detect_network_conflicts();

    // Also scan WolfNet IPs for duplicates. The marker files live at
    // <lxc-base>/<container>/.wolfnet/ip with just the IP as content.
    let mut wolfnet_ips: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for base in crate::containers::lxc_storage_paths() {
        let entries = match std::fs::read_dir(&base) { Ok(e) => e, Err(_) => continue };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let ip_path = entry.path().join(".wolfnet").join("ip");
            if let Ok(ip) = std::fs::read_to_string(&ip_path) {
                let ip = ip.trim().to_string();
                if !ip.is_empty() {
                    wolfnet_ips.entry(ip).or_default().push(name);
                }
            }
        }
    }

    // Emit findings for LXC config conflicts (MAC + bridge IP).
    for c in &conflicts {
        if c.containers.len() < 2 { continue; }
        let names = c.containers.join(", ");
        if c.conflict_type == "mac" {
            out.push(critical(
                &format!("Duplicate MAC address: {}", c.value),
                &format!(
                    "Containers sharing the same MAC on the same bridge will cause ARP confusion — packets go to the wrong container, connections drop randomly, and both containers appear to flicker on/off.\n\nContainers: {}",
                    names),
                Some("Open each container's Settings → Network tab and generate a unique MAC for one of them (🎲 button). Then restart both containers.".to_string()),
            ));
        } else {
            out.push(critical(
                &format!("Duplicate IP address: {}", c.value),
                &format!(
                    "Multiple containers configured with the same IP address. Only one will actually hold the address at a time — the other silently fails to communicate, causing mysterious connectivity issues.\n\nContainers: {}",
                    names),
                Some("Open each container's Settings → Network tab and assign unique IPs. If using DHCP, remove the static IP from one of them.".to_string()),
            ));
        }
    }

    // Emit findings for WolfNet IP duplicates.
    for (ip, containers) in &wolfnet_ips {
        if containers.len() < 2 { continue; }
        let names = containers.join(", ");
        out.push(critical(
            &format!("Duplicate WolfNet IP: {}", ip),
            &format!(
                "Multiple containers assigned the same WolfNet overlay IP. WolfNet routes packets by IP — two containers on the same address means traffic goes to whichever one ARP'd last, and the other is unreachable.\n\nContainers: {}",
                names),
            Some("Open each container's Settings → Network → WolfNet and assign a unique IP. Use 🔍 Next Available to find a free one.".to_string()),
        ));
    }
}

// ════════════════════════════════════════════════════════════════════
// Emergency root-password rotation
// ════════════════════════════════════════════════════════════════════
//
// Designed for the moment an operator realises an attacker has SSH
// credentials and wants to lock them out everywhere at once. The fleet
// coordinator (any node the operator is logged into) fans out
// authenticated rotation requests via the existing X-WolfStack-Secret
// channel; each node generates its own password locally with the
// system CSPRNG, applies it via chpasswd, and returns it ONCE to the
// coordinator. The coordinator surfaces the per-node passwords in the
// API response — they're not stored in WolfStack state anywhere.
//
// Belt-and-braces: each node also appends its new password to
// /root/.wolfstack-emergency-passwords.txt (mode 0600) so the operator
// can recover if the UI display fails or the browser closes.

use std::io::Write as _IoWrite;
use std::process::Stdio;

/// Generate a 32-character random password using only characters that
/// are safe inside shell pipelines (alphanumeric — no `$`, `'`, `"`,
/// `\\`, space). 32 alphanumeric is ~190 bits of entropy.
pub fn generate_strong_password() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}

/// Set the given user's password by piping `user:password` to chpasswd
/// via stdin. The password NEVER appears in argv — so it doesn't show
/// up in `ps`, audit args, or shell history.
pub fn set_password(user: &str, password: &str) -> Result<(), String> {
    let mut child = Command::new("chpasswd")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn chpasswd: {}", e))?;
    {
        let stdin = child.stdin.as_mut()
            .ok_or_else(|| "chpasswd stdin unavailable".to_string())?;
        writeln!(stdin, "{}:{}", user, password)
            .map_err(|e| format!("write chpasswd stdin: {}", e))?;
    }
    let output = child.wait_with_output()
        .map_err(|e| format!("wait chpasswd: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "chpasswd failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// Append (timestamp, hostname, user, password) to the emergency backup
/// file. Mode 0600, append-only — preserves earlier rotations.
pub fn record_emergency_password(user: &str, password: &str) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = "/root/.wolfstack-emergency-passwords.txt";
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let when = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("open {}: {}", path, e))?;
    writeln!(f, "{}\t{}\t{}\t{}", when, hostname, user, password)
        .map_err(|e| format!("write {}: {}", path, e))?;
    Ok(())
}

/// Rotate root password locally: generate, apply, record, kick any
/// active root SSH sessions, return the new password.
pub fn rotate_local_root() -> Result<String, String> {
    let pw = generate_strong_password();
    set_password("root", &pw)?;
    if let Err(e) = record_emergency_password("root", &pw) {
        eprintln!("warning: emergency-password backup write failed: {}", e);
    }
    // Kill active root SSH sessions so the attacker drops at the same
    // moment as the password change. We target per-session sshd
    // children only (the listening daemon is unaffected because its
    // process title doesn't include "@"). The WolfStack process is
    // not an sshd child so this can't affect us — but the operator's
    // own SSH session WILL terminate, which is intended.
    let _ = Command::new("pkill")
        .args(["-KILL", "-f", "sshd: root@"])
        .output();
    Ok(pw)
}

#[cfg(test)]
mod control_tests {
    use super::*;

    // ── failed-unit list parsing (format verified live) ──

    #[test]
    fn parses_failed_unit_names() {
        let text = "chkrootkit.service      loaded failed failed Nightly rootkit scan\n\
                    dailyaidecheck.service  loaded failed failed daily AIDE check\n";
        assert_eq!(parse_failed_unit_names(text),
            vec!["chkrootkit.service".to_string(), "dailyaidecheck.service".to_string()]);
        assert!(parse_failed_unit_names("").is_empty());
    }

    #[test]
    fn security_unit_matching() {
        assert!(security_relevant_unit("chkrootkit.service"));
        assert!(security_relevant_unit("chkrootkit.timer"));
        // Debian's AIDE unit is named dailyaidecheck — matched via
        // the "aide" substring (daily-AIDE-check).
        assert!(security_relevant_unit("dailyaidecheck.service"));
        assert!(security_relevant_unit("clamav-freshclam.service"));
        assert!(security_relevant_unit("auditd.service"));
        assert!(security_relevant_unit("fail2ban.service"));
        assert!(security_relevant_unit("rkhunter.timer"));
        assert!(!security_relevant_unit("nginx.service"));
        assert!(!security_relevant_unit("wolfstack.service"));
    }

    #[test]
    fn parses_unit_show_output() {
        // Format verified live: `systemctl show -p Result,ExecMainStatus`.
        let (r, s) = parse_unit_show("Result=exit-code\nExecMainStatus=127\n");
        assert_eq!(r.as_deref(), Some("exit-code"));
        assert_eq!(s, Some(127));
        let (r, s) = parse_unit_show("Result=success\nExecMainStatus=0\n");
        assert_eq!(r.as_deref(), Some("success"));
        assert_eq!(s, Some(0));
        let (r, s) = parse_unit_show("");
        assert!(r.is_none() && s.is_none());
    }

    // ── shell config parsing ──

    #[test]
    fn parses_debian_chkrootkit_conf_values() {
        // Verbatim lines from Debian's shipped chkrootkit.conf
        // (sources.debian.org, chkrootkit 0.59-1).
        let conf = r#"
## Whether the daily cron job should run chkrootkit at all
# true/false, default: true
RUN_DAILY="true"
RUN_DAILY_OPTS=""
DIFF_MODE="true"
MAILTO="root"
"#;
        assert_eq!(parse_shell_assignment(conf, "RUN_DAILY").as_deref(), Some("true"));
        assert_eq!(parse_shell_assignment(conf, "DIFF_MODE").as_deref(), Some("true"));
        assert_eq!(parse_shell_assignment(conf, "MAILTO").as_deref(), Some("root"));
        // Empty value parses as empty (→ "no mail intended").
        assert_eq!(parse_shell_assignment(conf, "RUN_DAILY_OPTS").as_deref(), Some(""));
        // Absent key is None, not empty.
        assert!(parse_shell_assignment(conf, "NOT_THERE").is_none());
    }

    #[test]
    fn shell_parse_last_assignment_wins_and_comments_skipped() {
        let conf = "MAILTO=\"root\"\n# MAILTO=\"commented@out\"\nMAILTO='admin@example.com'\n";
        assert_eq!(parse_shell_assignment(conf, "MAILTO").as_deref(),
            Some("admin@example.com"));
        // Unquoted form.
        assert_eq!(parse_shell_assignment("CRON_DAILY_RUN=yes\n", "CRON_DAILY_RUN").as_deref(),
            Some("yes"));
    }

    #[test]
    fn dynamic_shell_values_are_not_actionable() {
        // We do not evaluate shell — a $-expansion must be treated as
        // indeterminate rather than reported on.
        let v = Some("$ADMIN_EMAIL".to_string());
        assert!(actionable_value(&v).is_none());
        let v = Some("`cat /etc/mailto`".to_string());
        assert!(actionable_value(&v).is_none());
        let v = Some("root".to_string());
        assert_eq!(actionable_value(&v), Some("root"));
        let v = Some(String::new());
        assert!(actionable_value(&v).is_none());
        assert!(actionable_value(&None).is_none());
    }

    // ── /tmp + /dev/shm flagging ──

    #[test]
    fn fresh_executable_is_flaggable() {
        assert!(tmp_file_flaggable("dropper", 0o100755, 300));
    }

    /// The corosync case from wolf1: libqb blackbox ring buffers are
    /// DATA files (mode 0600) in /dev/shm. chkrootkit flags them; we
    /// must not — the alarm keys on the executable bit and that gate
    /// is load-bearing.
    #[test]
    fn corosync_blackbox_data_file_never_flagged() {
        assert!(!tmp_file_flaggable(
            "qb-3110230-3110234-32-1aB7dX/qb-blackbox-data", 0o100600, 60));
        assert!(!tmp_file_flaggable("qb-blackbox-data", 0o100600, 60));
        // Even a brand-new plain-data file: not executable → never flagged.
        assert!(!tmp_file_flaggable("anything.bin", 0o100644, 1));
    }

    #[test]
    fn old_or_benign_executables_not_flagged() {
        assert!(!tmp_file_flaggable("dropper", 0o100755, 90_000));   // >24h
        assert!(!tmp_file_flaggable("dropper", 0o100755, -5));       // clock skew
        assert!(!tmp_file_flaggable("pip-build-tool", 0o100755, 60));
        assert!(!tmp_file_flaggable("systemd-private-x", 0o100755, 60));
        assert!(!tmp_file_flaggable("build.tmp", 0o100755, 60));
    }

    // ── package verify parsing ──

    /// The chronyd case from wolf1: dpkg owns the file and `dpkg -V`
    /// prints nothing for it (only FAILED paths get lines, dpkg(1))
    /// — the file must be treated as clean and suppressed.
    #[test]
    fn package_owned_clean_file_is_suppressed() {
        // Empty verify output = every check passed for every path.
        assert!(verify_output_digest_ok("", "/usr/sbin/chronyd"));
        // A failure for a DIFFERENT path in the same package doesn't
        // taint ours.
        assert!(verify_output_digest_ok(
            "??5?????? c /etc/chrony/chrony.conf\n", "/usr/sbin/chronyd"));
    }

    #[test]
    fn digest_mismatch_is_not_clean() {
        // Third column '5' = content changed (dpkg(1) --verify).
        assert!(!verify_output_digest_ok(
            "??5??????   /usr/sbin/chronyd\n", "/usr/sbin/chronyd"));
        // A missing file is not clean either.
        assert!(!verify_output_digest_ok(
            "missing   /usr/sbin/chronyd\n", "/usr/sbin/chronyd"));
        // Conffile marker variant.
        assert!(!verify_output_digest_ok(
            "??5?????? c /usr/sbin/chronyd\n", "/usr/sbin/chronyd"));
    }
}

#[cfg(test)]
mod rotation_tests {
    use super::*;

    #[test]
    fn generated_passwords_are_32_chars_and_alphanumeric() {
        for _ in 0..50 {
            let pw = generate_strong_password();
            assert_eq!(pw.len(), 32);
            assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()),
                "non-alphanumeric in password: {}", pw);
        }
    }

    #[test]
    fn generated_passwords_have_high_diversity() {
        let a = generate_strong_password();
        let b = generate_strong_password();
        assert_ne!(a, b, "two consecutive passwords matched — RNG broken");
    }
}
