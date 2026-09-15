// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Baseline-driven tamper detection for SSH hardening, sudo, and
//! brute-force protection — the surfaces attackers tamper with to
//! establish persistence after the initial break-in.
//!
//! Complements `compromise_indicators` (which catches the literal
//! IoCs of the BootingWorld attack chain): this module catches the
//! *generic* post-exploitation moves an attacker makes regardless
//! of which specific kit they're running.
//!
//! ## Indicators
//!
//! * `/etc/ssh/sshd_config` drift — typically the attacker re-enables
//!   `PermitRootLogin yes` and `PasswordAuthentication yes` so they
//!   can keep brute-forcing or reuse a stolen password.
//! * `/root/.ssh/authorized_keys` drift — the #1 SSH persistence
//!   vector: drop an attacker-controlled key, you're back in
//!   forever even after the operator changes the root password.
//! * `/etc/sudoers` and `/etc/sudoers.d/*` drift — attacker adds a
//!   non-root account with NOPASSWD ALL=(ALL) so they can re-escalate
//!   without needing the root password.
//! * `/etc/passwd` new UIDs with shell access that weren't in the
//!   baseline — backdoor accounts.
//! * `/etc/fail2ban/jail.local` and `/etc/fail2ban/jail.d/*` drift OR
//!   `fail2ban.service` is installed but stopped/masked — the
//!   defender's first move against persistent brute-forcers is the
//!   attacker's first move to disable.
//!
//! Auto-fixes are baseline-driven: when drift is detected the
//! current file is captured for forensics and the baseline content
//! is restored. The baseline itself was auto-seeded on first run
//! (so a fresh install doesn't false-positive) and can be re-seeded
//! via `/api/predictive/baselines/reseed/<name>` when the operator
//! makes an intentional change.
//!
//! ## When we DON'T auto-revert
//!
//! Reverting is destructive, so two rules bound it. Both exist
//! because the analyzer cannot tell an operator apart from an
//! attacker by file content alone, and a revert that fires every
//! 5-minute tick silently undoes legitimate work forever.
//!
//! 1. **One-shot per baseline anchor.** We revert a given file at
//!    most once; after that we detect and alert only, until the
//!    operator reseeds. See `baselines::autofix_already_applied`.
//!
//! 2. **Pure key additions to `authorized_keys` are never reverted.**
//!    Adding an SSH key is routine administration. Deleting the
//!    operator's newly-added key — repeatedly, with no visible
//!    cause — is a worse outcome than leaving an unreviewed key in
//!    place next to a Critical inbox card naming its fingerprint.
//!    Anything else in that file (a baselined key REMOVED or its
//!    blob changed, an options-carrying or malformed line added)
//!    is treated as tampering and reverted under rule 1. This
//!    mirrors the `/etc/passwd` safe-addition carve-out below,
//!    which exists for exactly the same reason.
//!
//! ## Why baselines, not "good values"
//!
//! We deliberately do NOT ship a "correct sshd_config". Operators
//! legitimately customize it (Port, AllowUsers, KexAlgorithms,
//! Ciphers, etc.) and overwriting with our opinion would break
//! their setup. Baselines capture what THIS host considers normal
//! and only flag departures from that.

use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::predictive::{
    Context,
    ack::AckStore,
    baselines::{self, Verdict},
    compromise_indicators::RemediationOutcome,
    proposal::{Evidence, Proposal, ProposalScope, RemediationPlan, Severity},
};

pub const FT_SSHD_CONFIG_TAMPER: &str = "tamper:sshd_config";
pub const FT_AUTHORIZED_KEYS_TAMPER: &str = "tamper:authorized_keys";
pub const FT_SUDOERS_TAMPER: &str = "tamper:sudoers";
pub const FT_PASSWD_TAMPER: &str = "tamper:passwd";
pub const FT_FAIL2BAN_TAMPER: &str = "tamper:fail2ban";

const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const ROOT_AUTHORIZED_KEYS: &str = "/root/.ssh/authorized_keys";
const SUDOERS: &str = "/etc/sudoers";
const PASSWD: &str = "/etc/passwd";
const FAIL2BAN_JAIL_LOCAL: &str = "/etc/fail2ban/jail.local";

/// All paths sudoers.d that we baseline individually. Built at
/// scan time by listing the directory — we don't hard-code the set
/// because operators may add their own files (which become part of
/// the baseline on first observation).
const SUDOERS_D_DIR: &str = "/etc/sudoers.d";
const FAIL2BAN_JAIL_D_DIR: &str = "/etc/fail2ban/jail.d";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TamperFacts {
    /// Each (path, verdict) pair we evaluated this tick. The
    /// analyzer translates non-Match verdicts into proposals.
    pub paths: Vec<TamperedPath>,
    /// True iff fail2ban is installed on this host (we have a unit
    /// file for it). Detect-only — we don't INSTALL fail2ban, only
    /// fix it when it's already there but tampered with.
    pub fail2ban_installed: bool,
    /// True iff fail2ban.service is masked at scan time. If true,
    /// `remediations` will contain an unmask attempt entry.
    pub fail2ban_masked: bool,
    /// True iff fail2ban.service is installed and currently inactive.
    pub fail2ban_inactive: bool,
    /// True iff the `[sshd]` jail is enabled in the loaded fail2ban
    /// config (parsed from jail.local + jail.d/*). Required for the
    /// brute-force protection to actually be doing anything for SSH.
    pub fail2ban_sshd_jail_enabled: bool,
    /// What we did about each detection. Each entry pairs with a
    /// proposal's evidence so the inbox card shows the action.
    pub remediations: Vec<RemediationOutcome>,
    /// Set false on hosts where /etc/ doesn't look like a Linux box
    /// (no /etc/passwd at all — shouldn't happen but be defensive).
    pub scanned: bool,
}

/// One baselined path's current state plus its verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperedPath {
    pub path: String,
    pub verdict_label: String,
    pub current_sha256: Option<String>,
    pub baseline_sha256: Option<String>,
    /// True iff the remediation pass actually rewrote this file back
    /// to its baseline this tick. Drives the proposal wording — a
    /// card that claims "WolfStack auto-restored this file" when it
    /// deliberately left the file alone sends the operator hunting
    /// for a change that never happened.
    #[serde(default)]
    pub restored: bool,
}

pub async fn sample_now_async(_timeout: Duration) -> TamperFacts {
    tokio::task::spawn_blocking(sample_blocking).await.unwrap_or_default()
}

fn sample_blocking() -> TamperFacts {
    if std::fs::metadata(PASSWD).is_err() {
        return TamperFacts::default();
    }

    let mut paths: Vec<TamperedPath> = Vec::new();

    for p in [SSHD_CONFIG, ROOT_AUTHORIZED_KEYS, SUDOERS, PASSWD] {
        if std::fs::metadata(p).is_err() && baselines::load(p).is_none() {
            continue; // file not present and no baseline — skip
        }
        paths.push(verdict_to_path(p));
    }

    // sudoers.d/* — every file there gets baselined.
    if let Ok(entries) = std::fs::read_dir(SUDOERS_D_DIR) {
        for e in entries.flatten() {
            let p = e.path();
            if !p.is_file() { continue; }
            let s = p.to_string_lossy().into_owned();
            paths.push(verdict_to_path(&s));
        }
    }

    // Detect any baseline'd sudoers.d file that has since been
    // deleted. We use the baselines directory listing to find
    // baselines whose underlying path is gone — i.e. the attacker
    // dropped a NOPASSWD file and we baselined it, then they
    // realized and rm'd it. We treat that as a missing-file verdict.
    if let Ok(dir) = std::fs::read_dir(baselines::baselines_dir()) {
        for entry in dir.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
            // Cheap: load the JSON and look at its `path` field.
            if let Ok(body) = std::fs::read_to_string(&p)
                && let Ok(b) = serde_json::from_str::<baselines::Baseline>(&body)
                    && b.path.starts_with(SUDOERS_D_DIR)
                        && !paths.iter().any(|tp| tp.path == b.path)
                        && std::fs::metadata(&b.path).is_err()
                    {
                        paths.push(verdict_to_path(&b.path));
                    }
        }
    }

    // fail2ban state.
    let fail2ban_installed = is_unit_known("fail2ban.service");
    let fail2ban_masked = fail2ban_installed && super::compromise_indicators::is_unit_masked("fail2ban.service");
    let fail2ban_inactive = fail2ban_installed && !is_unit_active("fail2ban.service");
    let fail2ban_sshd_jail_enabled = if fail2ban_installed {
        parse_fail2ban_sshd_enabled()
    } else {
        true // not installed → don't flag; the operator's choice
    };

    if fail2ban_installed {
        if std::fs::metadata(FAIL2BAN_JAIL_LOCAL).is_ok() || baselines::load(FAIL2BAN_JAIL_LOCAL).is_some() {
            paths.push(verdict_to_path(FAIL2BAN_JAIL_LOCAL));
        }
        if let Ok(entries) = std::fs::read_dir(FAIL2BAN_JAIL_D_DIR) {
            for e in entries.flatten() {
                let p = e.path();
                if !p.is_file() { continue; }
                let s = p.to_string_lossy().into_owned();
                paths.push(verdict_to_path(&s));
            }
        }
    }

    TamperFacts {
        paths,
        fail2ban_installed,
        fail2ban_masked,
        fail2ban_inactive,
        fail2ban_sshd_jail_enabled,
        remediations: Vec::new(),
        scanned: true,
    }
}

fn verdict_to_path(p: &str) -> TamperedPath {
    let v = baselines::check(p);
    let (label, cur, base) = match &v {
        Verdict::Match => ("match".to_string(), None, None),
        Verdict::NoBaseline => ("no_baseline".to_string(), None, None),
        Verdict::Drift { current_sha256, baseline_sha256 } => (
            "drift".to_string(),
            Some(current_sha256.clone()),
            Some(baseline_sha256.clone()),
        ),
        Verdict::FileMissing { baseline_sha256 } => (
            "file_missing".to_string(),
            None,
            Some(baseline_sha256.clone()),
        ),
        Verdict::ReadError(_) => ("read_error".to_string(), None, None),
    };
    TamperedPath {
        path: p.to_string(),
        verdict_label: label,
        current_sha256: cur,
        baseline_sha256: base,
        restored: false,
    }
}

fn is_unit_known(unit: &str) -> bool {
    // Unit file present in any of the standard locations means
    // systemd "knows" the unit, regardless of enabled/disabled.
    let candidates = [
        format!("/etc/systemd/system/{}", unit),
        format!("/usr/lib/systemd/system/{}", unit),
        format!("/lib/systemd/system/{}", unit),
        format!("/run/systemd/system/{}", unit),
    ];
    candidates.iter().any(|p| std::path::Path::new(p).exists())
}

fn is_unit_active(unit: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Read jail.local + jail.d/* and return true iff a `[sshd]` (or
/// `[ssh]`) stanza has `enabled = true` set. Not a full INI parser —
/// just the minimum we need to verify the jail is on.
fn parse_fail2ban_sshd_enabled() -> bool {
    let mut bodies = String::new();
    if let Ok(b) = std::fs::read_to_string(FAIL2BAN_JAIL_LOCAL) { bodies.push_str(&b); bodies.push('\n'); }
    if let Ok(entries) = std::fs::read_dir(FAIL2BAN_JAIL_D_DIR) {
        for e in entries.flatten() {
            if let Ok(b) = std::fs::read_to_string(e.path()) {
                bodies.push_str(&b);
                bodies.push('\n');
            }
        }
    }
    // Walk sections.
    let mut in_sshd = false;
    let mut sshd_enabled = false;
    for line in bodies.lines() {
        let t = line.trim();
        if t.starts_with('[') && t.ends_with(']') {
            let name = t[1..t.len()-1].to_ascii_lowercase();
            in_sshd = name == "sshd" || name == "ssh";
            continue;
        }
        if !in_sshd { continue; }
        // Match `enabled = true` (allowing extra whitespace + case).
        let lower = t.to_ascii_lowercase();
        if lower.starts_with("enabled")
            && let Some((_, rhs)) = lower.split_once('=')
                && (rhs.trim() == "true" || rhs.trim() == "1") {
                    sshd_enabled = true;
                }
    }
    sshd_enabled
}

/// Auto-remediation pass — runs after sample, gated by ack/proposal
/// suppression. Same architecture as compromise_indicators::
/// remediate_if_unacked: an operator who acked a tamper finding
/// (intentionally letting drift stand) won't see WolfStack revert
/// it on the next tick.
pub async fn remediate_if_unacked(
    facts: TamperFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
    ctx: &Context,
) -> TamperFacts {
    if !facts.scanned { return facts; }
    let acks = acks.clone();
    let proposals = proposals.clone();
    let scope = ProposalScope { node_id: ctx.node_id.clone(), resource_id: None };
    tokio::task::spawn_blocking(move || remediate_blocking(facts, &acks, &proposals, &scope))
        .await
        .unwrap_or_else(|_| TamperFacts::default())
}

fn remediate_blocking(
    mut facts: TamperFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
    scope: &ProposalScope,
) -> TamperFacts {
    let suppressed = |ft: &str| -> bool {
        acks.suppresses(ft, scope) || proposals.is_suppressed(ft, scope)
    };

    // Group by indicator class so a single ack on sshd_config
    // suppresses all sshd_config drift remediations etc.
    //
    // Indexed rather than iterating a clone: a successful restore has
    // to be recorded back onto `facts.paths[i].restored` so `analyze`
    // can describe what actually happened.
    for i in 0..facts.paths.len() {
        let tp = facts.paths[i].clone();
        if tp.verdict_label != "drift" && tp.verdict_label != "file_missing" {
            continue;
        }
        let ft = finding_type_for_path(&tp.path);
        if suppressed(&ft) { continue; }

        // /etc/passwd: auto-reseed when the only change is known-safe
        // service users being ADDED (e.g. clamav installed by apt).
        // Blindly restoring the baseline deletes those users, breaking
        // logrotate / freshclam and causing a persistent fight between
        // the tamper detector and self_heal_clamav_logrotate().
        // piranhaSponsor 2026-06-10.
        if tp.path == PASSWD && passwd_drift_is_safe_addition(&tp.path) {
            tracing::info!(
                "tamper_detection: /etc/passwd drift is only safe service-user additions — reseeding baseline"
            );
            let _ = baselines::reseed(&tp.path, "auto:safe-service-users",
                "only known-safe service accounts added (e.g. clamav)");
            facts.remediations.push(RemediationOutcome {
                action: format!("auto-reseed {} baseline", tp.path),
                ok: true,
                detail: format!(
                    "only known-safe service accounts were added to {}; baseline reseeded to accept them",
                    tp.path
                ),
            });
            continue;
        }

        // /root/.ssh/authorized_keys: adding a key is routine admin
        // work, and silently deleting the operator's new key every
        // tick is the worst possible response to it. Alert on the
        // addition — naming each new key — and leave the file alone.
        // Removals, blob changes and non-key lines fall through to
        // the restore path below. (See the module header.)
        let key_additions = if tp.path == ROOT_AUTHORIZED_KEYS && tp.verdict_label == "drift" {
            authorized_keys_added_only(&tp.path)
        } else {
            None
        };
        if let Some(added) = key_additions {
            tracing::warn!(
                "tamper_detection: {} gained {} new SSH key(s) and lost none — \
                 alerting WITHOUT reverting; reseed the baseline to accept them",
                tp.path, added.len(),
            );
            facts.remediations.push(RemediationOutcome {
                action: format!("alert-only (no revert): {}", tp.path),
                ok: true,
                detail: format!(
                    "{} new SSH key(s) were ADDED and no baselined key was removed or \
                     altered, so WolfStack did NOT modify the file. Added: {}. \
                     If you added these, reseed the baseline to stop the alert. If you \
                     did NOT, remove them now — this is live SSH access to root.",
                    added.len(),
                    added.join("; "),
                ),
            });
            continue;
        }

        // One-shot: we already reverted this file once since its
        // baseline was seeded. Reverting again every tick fights an
        // operator who meant it, and buys nothing against an attacker
        // who can simply re-apply. Detect and alert instead.
        if baselines::autofix_already_applied(&tp.path) {
            tracing::warn!(
                "tamper_detection: {} drifted again after an earlier auto-restore — \
                 NOT reverting; operator action needed",
                tp.path,
            );
            facts.remediations.push(RemediationOutcome {
                action: format!("auto-restore of {} withheld", tp.path),
                ok: false,
                detail: format!(
                    "WolfStack already auto-restored {} once since its baseline was seeded, \
                     and it has drifted again. Auto-restore is one-shot per baseline, so the \
                     file was left as-is this time. Reseed the baseline to accept the current \
                     contents (which re-arms auto-restore), or restore it yourself.",
                    tp.path,
                ),
            });
            continue;
        }

        let outcome = restore_from_baseline(&tp.path);
        if outcome.ok {
            facts.paths[i].restored = true;
            baselines::record_autofix(&tp.path);
        }
        facts.remediations.push(outcome);
    }

    if facts.fail2ban_installed && facts.fail2ban_masked && !suppressed(FT_FAIL2BAN_TAMPER) {
        facts.remediations.push(unmask_and_start("fail2ban.service"));
    } else if facts.fail2ban_installed && facts.fail2ban_inactive && !suppressed(FT_FAIL2BAN_TAMPER) {
        facts.remediations.push(start_unit("fail2ban.service"));
    }

    facts
}

fn finding_type_for_path(path: &str) -> String {
    if path == SSHD_CONFIG { FT_SSHD_CONFIG_TAMPER.into() }
    else if path == ROOT_AUTHORIZED_KEYS { FT_AUTHORIZED_KEYS_TAMPER.into() }
    else if path == SUDOERS || path.starts_with(SUDOERS_D_DIR) { FT_SUDOERS_TAMPER.into() }
    else if path == PASSWD { FT_PASSWD_TAMPER.into() }
    else if path == FAIL2BAN_JAIL_LOCAL || path.starts_with(FAIL2BAN_JAIL_D_DIR) { FT_FAIL2BAN_TAMPER.into() }
    else { "tamper:unknown".into() }
}

/// Restore a file to its baseline content. Strategy:
///   1. Capture the current (suspected-tampered) content to forensics.
///   2. Load the baseline-content snapshot from the forensics
///      pre-tamper capture (we keep the original bytes alongside
///      the SHA so we can actually revert, not just detect).
///   3. Replace the file atomically.
///
/// For files we DON'T have a content-snapshot of (because the
/// baseline was seeded before content-snapshotting was a thing),
/// we capture-only and leave the operator to restore from their
/// own backup — the proposal text says so explicitly.
fn restore_from_baseline(path: &str) -> RemediationOutcome {
    let action = format!("restore {} from baseline", path);
    // Capture current state first.
    let cur_capture = match baselines::capture_current(path, "tamper") {
        Ok(p) => p,
        Err(e) if e.starts_with("read ") => {
            // File was deleted entirely — that IS the tamper. Nothing
            // to capture; just record the verdict in the outcome.
            return RemediationOutcome {
                action,
                ok: false,
                detail: format!("file is missing; baseline expected content present. Operator restore needed: {}", e),
            };
        }
        Err(e) => return RemediationOutcome { action, ok: false, detail: e },
    };
    // Look for a content snapshot in /var/lib/wolfstack/baselines/
    // — we save one at first-seed (see baselines::auto_seed; the
    // companion `.content` file). If absent, this is a pre-23.2.0
    // baseline and we surface that to the operator instead of
    // silently failing.
    let content_path = baselines::baselines_dir()
        .join(format!("{}.content", baselines::slug_for(path)));
    if !content_path.exists() {
        return RemediationOutcome {
            action,
            ok: false,
            detail: format!(
                "no content snapshot for {} (legacy baseline). Current state captured to {}; restore from your own backup, then run `/api/predictive/baselines/reseed/{}` to re-anchor.",
                path, cur_capture, baselines::slug_for(path),
            ),
        };
    }
    let baseline_bytes = match std::fs::read(&content_path) {
        Ok(b) => b,
        Err(e) => return RemediationOutcome {
            action,
            ok: false,
            detail: format!("read baseline content {:?}: {}", content_path, e),
        },
    };
    // Atomic write of the restored content.
    let tmp = format!("{}.wolfstack.tmp", path);
    if let Err(e) = std::fs::write(&tmp, &baseline_bytes) {
        return RemediationOutcome { action, ok: false, detail: format!("write {}: {}", tmp, e) };
    }
    // Preserve sensible permissions on system files.
    use std::os::unix::fs::PermissionsExt;
    let mode = match path {
        ROOT_AUTHORIZED_KEYS => 0o600,
        SUDOERS => 0o440,
        PASSWD => 0o644,
        _ if path.starts_with(SUDOERS_D_DIR) => 0o440,
        _ => 0o644,
    };
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode));
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return RemediationOutcome { action, ok: false, detail: format!("rename: {}", e) };
    }
    // If we just restored sshd_config, reload sshd so the change
    // takes effect immediately.
    if path == SSHD_CONFIG {
        let _ = std::process::Command::new("systemctl")
            .args(["reload", "sshd"])
            .output();
        // Some distros use `ssh` instead of `sshd`.
        let _ = std::process::Command::new("systemctl")
            .args(["reload", "ssh"])
            .output();
    }
    tracing::warn!(
        "tamper_detection: restored {} from baseline; current captured to {}",
        path, cur_capture,
    );
    RemediationOutcome {
        action,
        ok: true,
        detail: format!("restored {} from baseline; suspected-tampered version captured to {}", path, cur_capture),
    }
}

fn unmask_and_start(unit: &str) -> RemediationOutcome {
    // Remove the /dev/null symlink in both /etc/systemd/system and
    // /run/systemd/system, then daemon-reload + start.
    for base in &["/etc/systemd/system", "/run/systemd/system"] {
        let p = format!("{}/{}", base, unit);
        if let Ok(meta) = std::fs::symlink_metadata(&p)
            && meta.file_type().is_symlink()
                && let Ok(target) = std::fs::read_link(&p)
                    && target.as_os_str() == "/dev/null" {
                        let _ = std::fs::remove_file(&p);
                    }
    }
    let _ = std::process::Command::new("systemctl").arg("daemon-reload").output();
    let out = std::process::Command::new("systemctl")
        .args(["start", unit])
        .output();
    let ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
    let detail = if ok {
        format!("unmasked + started {}", unit)
    } else {
        format!(
            "unmask attempted, start failed: {}",
            out.map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                .unwrap_or_else(|e| e.to_string())
        )
    };
    tracing::warn!("tamper_detection: {}", detail);
    RemediationOutcome {
        action: format!("unmask and start {}", unit),
        ok,
        detail,
    }
}

fn start_unit(unit: &str) -> RemediationOutcome {
    let out = std::process::Command::new("systemctl").args(["start", unit]).output();
    let ok = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
    let detail = if ok {
        format!("started {}", unit)
    } else {
        format!(
            "start failed: {}",
            out.map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                .unwrap_or_else(|e| e.to_string())
        )
    };
    tracing::warn!("tamper_detection: {}", detail);
    RemediationOutcome { action: format!("start {}", unit), ok, detail }
}

pub fn analyze(
    ctx: &Context,
    facts: &TamperFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    if !facts.scanned { return out; }
    let scope = ProposalScope { node_id: ctx.node_id.clone(), resource_id: None };

    // Group drift findings by indicator class. Each (finding_type)
    // gets one card listing every file in that class that's drifted.
    let mut by_class: std::collections::HashMap<String, Vec<&TamperedPath>> = Default::default();
    for tp in &facts.paths {
        if tp.verdict_label == "drift" || tp.verdict_label == "file_missing" {
            let ft = finding_type_for_path(&tp.path);
            by_class.entry(ft).or_default().push(tp);
        }
    }

    let find_rem = |label_substring: &str| -> Option<&RemediationOutcome> {
        facts.remediations.iter().find(|r| r.detail.contains(label_substring) || r.action.contains(label_substring))
    };

    for (ft, paths) in by_class {
        if acks.suppresses(&ft, &scope) || proposals.is_suppressed(&ft, &scope) { continue; }
        // Find the remediation whose action mentions one of these paths.
        let rem = paths.iter().find_map(|p| find_rem(&p.path));
        out.push(build_tamper_proposal(&ft, &paths, rem, &scope));
    }

    // fail2ban-specific findings (masked / inactive / sshd jail off).
    if facts.fail2ban_installed
        && (facts.fail2ban_masked || facts.fail2ban_inactive || !facts.fail2ban_sshd_jail_enabled)
        && !acks.suppresses(FT_FAIL2BAN_TAMPER, &scope)
        && !proposals.is_suppressed(FT_FAIL2BAN_TAMPER, &scope)
    {
        let rem = facts.remediations.iter()
            .find(|r| r.action.contains("fail2ban"));
        out.push(build_fail2ban_proposal(facts, rem, &scope));
    }

    out
}

pub fn covered_scopes(
    ctx: &Context,
    facts: &TamperFacts,
) -> Vec<(String, ProposalScope)> {
    if !facts.scanned { return Vec::new(); }
    let scope = ProposalScope { node_id: ctx.node_id.clone(), resource_id: None };
    let types: [&str; 5] = [
        FT_SSHD_CONFIG_TAMPER,
        FT_AUTHORIZED_KEYS_TAMPER,
        FT_SUDOERS_TAMPER,
        FT_PASSWD_TAMPER,
        FT_FAIL2BAN_TAMPER,
    ];
    types.iter().map(|t| ((*t).to_string(), scope.clone())).collect()
}

fn build_tamper_proposal(
    finding_type: &str,
    paths: &[&TamperedPath],
    rem: Option<&RemediationOutcome>,
    scope: &ProposalScope,
) -> Proposal {
    let path_list: HashSet<&str> = paths.iter().map(|p| p.path.as_str()).collect();
    let path_list: Vec<&&str> = path_list.iter().collect();
    let title = match finding_type {
        FT_SSHD_CONFIG_TAMPER => "SSH daemon config changed from its baseline",
        FT_AUTHORIZED_KEYS_TAMPER => "Root authorized_keys changed from its baseline",
        FT_SUDOERS_TAMPER => "sudoers configuration changed from its baseline",
        FT_PASSWD_TAMPER => "/etc/passwd changed from its baseline",
        _ => "Security-critical file changed from its baseline",
    };
    let why = format!(
        "WolfStack baselined this file's contents when it was first observed and the current contents \
         no longer match. This is either an intentional operator change (in which case reseed the \
         baseline via `/api/predictive/baselines/reseed/<slug>` so it stops alerting) OR an attacker \
         establishing persistence — adding their SSH key to authorized_keys, re-enabling password \
         login in sshd_config, or granting NOPASSWD sudo to a backdoor account.\n\nFiles flagged: {}",
        path_list.iter().map(|s| format!("`{}`", s)).collect::<Vec<_>>().join(", "),
    );
    let mut evidence: Vec<Evidence> = paths.iter().map(|tp| Evidence {
        label: tp.path.clone(),
        value: format!("verdict = {}", tp.verdict_label),
        detail: Some(match (&tp.current_sha256, &tp.baseline_sha256) {
            (Some(c), Some(b)) => format!("current sha256 = {}, baseline = {}", c, b),
            (None, Some(b)) => format!("file deleted; baseline sha256 was {}", b),
            _ => "current contents do not match the baseline snapshot".into(),
        }),
        links: Vec::new(),
    }).collect();
    if let Some(r) = rem { evidence.push(remediation_evidence_for(r)); }
    let manual_cmds: Vec<String> = paths.iter().map(|tp| {
        format!("# Inspect current vs baseline for {}:\ndiff <(cat {}) <(cat /var/lib/wolfstack/baselines/{}.content)", tp.path, tp.path, baselines::slug_for(&tp.path))
    }).collect();
    Proposal::new_rule(
        finding_type.to_string(),
        Severity::Critical,
        title.to_string(),
        why,
        evidence,
        RemediationPlan::Manual {
            // A class can cover several files (sudoers.d/*), and they
            // can land differently — one restored, one deliberately
            // left alone. Only claim a restore when EVERY flagged file
            // in this card actually got one; otherwise point the
            // operator at the per-file Auto-fix evidence.
            instructions: if paths.iter().all(|p| p.restored) {
                "WolfStack auto-restored each affected file from its baseline snapshot and captured the suspected-tampered version to /var/lib/wolfstack/forensics/tamper/. If the Auto-fix evidence above shows a failure (e.g. missing content snapshot for a pre-23.2.0 baseline), restore from your own backup and run /api/predictive/baselines/reseed/<slug> to re-anchor. Auto-restore is one-shot: if this file drifts again WolfStack will alert but NOT revert it, so the next change is yours to accept or undo.".to_string()
            } else {
                "WolfStack left some or all of these files UNCHANGED — the Auto-fix evidence above says which, and why, file by file. A file is deliberately not reverted when the change is a plain SSH-key addition (nothing removed or rewritten), or when it was already auto-restored once since its baseline was seeded (auto-restore is one-shot per baseline). If YOU made this change, run /api/predictive/baselines/reseed/<slug> to accept it and stop the alert. If you did NOT, this is live unauthorised access: remove the change now, check /var/lib/wolfstack/forensics/tamper/ for earlier captures, then reseed.".to_string()
            },
            commands: {
                let mut v = vec!["# Inspect what changed:".to_string()];
                v.extend(manual_cmds);
                v.push("ls -la /var/lib/wolfstack/forensics/tamper/   # captured tampered versions".to_string());
                // Reseed after an intentional change so WolfStack stops
                // reverting + alerting. HTTPS only (:8553 has been HTTPS since
                // v23.11 — the old `http://` printed here just connection-
                // refused), and the endpoint needs auth: run as root on the
                // host, where the node's cluster secret is readable, so the
                // operator doesn't have to mint an API key. `-k` accepts the
                // default self-signed cert. (piranhaSponsor 2026-06-03.)
                let secret_path = crate::paths::get().cluster_secret;
                v.push("# After a legitimate change, reseed the baseline (run as root on this host):".to_string());
                v.extend(paths.iter().map(|tp| format!(
                    "curl -sk -X POST https://localhost:8553/api/predictive/baselines/reseed/{} -H \"X-WolfStack-Secret: $(cat {})\"",
                    baselines::slug_for(&tp.path), secret_path
                )));
                v
            },
        },
        scope.clone(),
    )
}

fn build_fail2ban_proposal(facts: &TamperFacts, rem: Option<&RemediationOutcome>, scope: &ProposalScope) -> Proposal {
    let mut symptoms: Vec<&str> = Vec::new();
    if facts.fail2ban_masked { symptoms.push("masked"); }
    if facts.fail2ban_inactive { symptoms.push("inactive"); }
    if !facts.fail2ban_sshd_jail_enabled { symptoms.push("no [sshd] jail enabled"); }
    let mut evidence = vec![Evidence {
        label: "fail2ban state".into(),
        value: symptoms.join(", "),
        detail: Some("fail2ban is installed on this host but is not actively protecting SSH. The attacker's first move after a successful break-in is to disable the brute-force watcher so they (and the next botnet) can keep hammering.".into()),
        links: Vec::new(),
    }];
    if let Some(r) = rem { evidence.push(remediation_evidence_for(r)); }
    Proposal::new_rule(
        FT_FAIL2BAN_TAMPER,
        Severity::Critical,
        format!("fail2ban not protecting SSH on this node ({})", symptoms.join(", ")),
        "fail2ban is installed but inactive / masked / not running the [sshd] jail. WolfStack auto-attempts to unmask + start it. If the [sshd] jail is disabled in config, reseed your fail2ban baseline AFTER fixing the config so future ticks recognize the corrected state.".to_string(),
        evidence,
        RemediationPlan::Manual {
            instructions: "WolfStack auto-unmasks and starts fail2ban when it's installed but stopped/masked. Verifying that the [sshd] jail is enabled requires inspecting jail.local / jail.d/*.".into(),
            commands: vec![
                "systemctl is-active fail2ban   # should be 'active'".into(),
                "fail2ban-client status sshd   # should NOT say 'no such jail'".into(),
                "# To enable the sshd jail manually:".into(),
                "echo -e '[sshd]\\nenabled = true\\nmaxretry = 5\\nbantime = 1h' >> /etc/fail2ban/jail.local".into(),
                "systemctl restart fail2ban".into(),
            ],
        },
        scope.clone(),
    )
}

fn remediation_evidence_for(rem: &RemediationOutcome) -> Evidence {
    let prefix = if rem.ok { "Auto-fix \u{2713}" } else { "Auto-fix \u{2717}" };
    Evidence {
        label: format!("{} — {}", prefix, rem.action),
        value: rem.detail.clone(),
        detail: Some(if rem.ok {
            "WolfStack performed this action as soon as the indicator was detected. The card auto-resolves on the next 5-minute tick if the host is now clean.".into()
        } else {
            "WolfStack attempted this action but it did not complete. Run the manual commands below to finish recovery.".into()
        }),
        links: Vec::new(),
    }
}

/// Determine whether the /etc/passwd drift is ONLY safe service-user
/// additions — i.e. every baseline line is still present unchanged, and
/// every NEW line belongs to a known-safe service account with a no-login
/// shell. If so, the tamper detector should reseed the baseline rather
/// than restoring (which would delete the user and break the service that
/// created it — e.g. clamav/logrotate cycle reported by piranhaSponsor).
///
/// Rationale: the whole point of /etc/passwd tamper detection is catching
/// backdoor accounts with shell access. Service accounts with
/// /usr/sbin/nologin or /bin/false are not interactive — they can't be
/// used for SSH persistence — and they're routinely created by apt/dnf
/// package installations. Restoring the baseline to delete them causes
/// real operational breakage (logrotate failures, freshclam inability to
/// drop privileges).
fn passwd_drift_is_safe_addition(path: &str) -> bool {
    // Load the baseline content snapshot.
    let content_path = baselines::baselines_dir()
        .join(format!("{}.content", baselines::slug_for(path)));
    let baseline_bytes = match std::fs::read(&content_path) {
        Ok(b) => b,
        Err(_) => return false, // no content snapshot → can't compare → not safe
    };
    let baseline_text = String::from_utf8_lossy(&baseline_bytes);
    let current_text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let baseline_lines: HashSet<&str> = baseline_text.lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    let current_lines: HashSet<&str> = current_text.lines()
        .filter(|l| !l.trim().is_empty())
        .collect();

    // Any baseline line removed or modified → real tampering.
    for bl in &baseline_lines {
        if !current_lines.contains(bl) {
            return false;
        }
    }

    // Every NEW line must be a known-safe service account.
    let added: Vec<&&str> = current_lines.difference(&baseline_lines).collect();
    if added.is_empty() {
        return false; // no additions but still drifted → something else changed
    }

    for line in &added {
        if !is_safe_service_user_line(line) {
            return false;
        }
    }

    true
}

/// Check whether a /etc/passwd line represents a safe, non-interactive
/// service account. Criteria:
///   1. The username is in our known-safe list, OR
///   2. The shell is a no-login shell AND the UID is in the system range
///      (typically < 1000 on Linux, assigned by adduser --system).
fn is_safe_service_user_line(line: &str) -> bool {
    let fields: Vec<&str> = line.split(':').collect();
    if fields.len() < 7 { return false; }
    let username = fields[0];
    let uid: u32 = match fields[2].parse() { Ok(u) => u, Err(_) => return false };
    let shell = fields[6];

    // Known-safe service accounts that WolfStack or its dependencies install.
    const KNOWN_SAFE: &[&str] = &[
        "clamav", "freshclam", "_clamav",        // ClamAV
        "clamupdate", "clamscan",                  // ClamAV on RHEL/Fedora
        "vscan",                                   // ClamAV on SUSE
        "lxd", "_lxd",                             // LXD
        "docker",                                  // Docker (rare but possible)
        "systemd-coredump", "systemd-oom",         // systemd services
        "systemd-timesync", "systemd-resolve",
        "systemd-network",
        "_apt", "apt-cacher-ng",                   // APT
        "sshd",                                    // OpenSSH
        "mosquitto",                               // MQTT broker
        "redis", "postgres", "mysql", "mongodb",   // databases
        "prometheus", "grafana", "node_exporter",  // monitoring
        "wireguard",                               // VPN
        "tcpdump", "tss",                          // system utilities
    ];

    // Check 1: known username.
    if KNOWN_SAFE.iter().any(|s| s.eq_ignore_ascii_case(username)) {
        return true;
    }

    // Check 2: system-range UID + no-login shell.
    let no_login_shells: &[&str] = &[
        "/usr/sbin/nologin",
        "/sbin/nologin",
        "/bin/false",
        "/usr/bin/false",
        "/bin/nologin",
        "/dev/null",
    ];
    uid < 1000 && no_login_shells.contains(&shell)
}

// ─────────────────────────────────────────────────────────────────
// authorized_keys addition analysis
// ─────────────────────────────────────────────────────────────────

/// One parsed line of an authorized_keys file.
struct AuthKeyLine {
    /// Set-comparison identity. Two lines are the same key when the
    /// key type and base64 blob match — the trailing comment is a
    /// label, and re-labelling a key grants no new access, so it must
    /// not read as "a key was removed and another added". Lines that
    /// don't parse as a plain key keep their raw text as identity, so
    /// a new one can never be mistaken for a benign key addition.
    id: String,
    /// Operator-facing description used in the alert.
    summary: String,
    /// False for anything that isn't a bare `<type> <blob> [comment]`
    /// — an options prefix (`command="…" ssh-rsa …`), a malformed
    /// blob, or junk. Those are never treated as routine additions.
    is_plain_key: bool,
}

/// What counts as a key, and how it's fingerprinted, is defined once
/// in `crate::ssh_keys` and shared with the hosting portal and the
/// host-level Authorised Keys manager. Certificate types
/// (`ssh-rsa-cert-v01@openssh.com`), `cert-authority` and
/// options-carrying lines are outside that definition, so they land
/// here as non-key lines and are treated as tampering on first sight.
fn parse_authorized_keys(text: &str) -> Vec<AuthKeyLine> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        match crate::ssh_keys::parse_line(t) {
            Some(k) => out.push(AuthKeyLine {
                id: format!("key\u{1}{}\u{1}{}", k.key_type, k.blob),
                summary: format!(
                    "{} sha256:{} {}",
                    k.key_type,
                    crate::ssh_keys::short_fp(&k.fingerprint()),
                    if k.comment.is_empty() { "(no comment)" } else { k.comment.as_str() },
                ),
                is_plain_key: true,
            }),
            None => out.push(AuthKeyLine {
                id: format!("raw\u{1}{}", t),
                summary: format!("non-key line: {}", t),
                is_plain_key: false,
            }),
        }
    }
    out
}

/// Decide whether authorized_keys drift is purely operator-style key
/// ADDITION. `Some(summaries)` means every baselined line is still
/// present and everything new is a well-formed public key — safe to
/// alert without reverting. `None` means something was removed or
/// rewritten, or a non-key line appeared: treat as tampering.
///
/// Split from the file I/O so it is directly testable without
/// touching the on-disk baselines directory.
fn authorized_keys_added_only_in(
    baseline_text: &str,
    current_text: &str,
) -> Option<Vec<String>> {
    let baseline = parse_authorized_keys(baseline_text);
    let current = parse_authorized_keys(current_text);

    let baseline_ids: HashSet<&str> = baseline.iter().map(|l| l.id.as_str()).collect();
    let current_ids: HashSet<&str> = current.iter().map(|l| l.id.as_str()).collect();

    // A baselined line that is gone means a key was removed or its
    // blob rewritten — the lockout / key-substitution case. Revert.
    if baseline_ids.iter().any(|id| !current_ids.contains(id)) {
        return None;
    }

    let mut seen: HashSet<&str> = HashSet::new();
    let mut added: Vec<&AuthKeyLine> = Vec::new();
    for l in &current {
        if baseline_ids.contains(l.id.as_str()) { continue; }
        if seen.insert(l.id.as_str()) {
            added.push(l);
        }
    }

    // Drift with nothing added: whitespace, ordering, or a comment
    // rewrite. Not an addition, so it takes the normal path.
    if added.is_empty() { return None; }
    // An options prefix (`command=…`, `environment=…`) or a malformed
    // line is not routine key management.
    if added.iter().any(|l| !l.is_plain_key) { return None; }

    Some(added.iter().map(|l| l.summary.clone()).collect())
}

/// File-reading wrapper around `authorized_keys_added_only_in`.
/// Returns None when there's no baseline content snapshot — without
/// the original bytes we can't tell an addition from a rewrite, and
/// the safe reading of an unknown change is "tampering".
fn authorized_keys_added_only(path: &str) -> Option<Vec<String>> {
    let content_path = baselines::baselines_dir()
        .join(format!("{}.content", baselines::slug_for(path)));
    let baseline_bytes = std::fs::read(&content_path).ok()?;
    let baseline_text = String::from_utf8_lossy(&baseline_bytes);
    let current_text = std::fs::read_to_string(path).ok()?;
    authorized_keys_added_only_in(&baseline_text, &current_text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_type_mapping() {
        assert_eq!(finding_type_for_path(SSHD_CONFIG), FT_SSHD_CONFIG_TAMPER);
        assert_eq!(finding_type_for_path(ROOT_AUTHORIZED_KEYS), FT_AUTHORIZED_KEYS_TAMPER);
        assert_eq!(finding_type_for_path(SUDOERS), FT_SUDOERS_TAMPER);
        assert_eq!(finding_type_for_path("/etc/sudoers.d/01-cluster"), FT_SUDOERS_TAMPER);
        assert_eq!(finding_type_for_path(PASSWD), FT_PASSWD_TAMPER);
        assert_eq!(finding_type_for_path(FAIL2BAN_JAIL_LOCAL), FT_FAIL2BAN_TAMPER);
        assert_eq!(finding_type_for_path("/etc/fail2ban/jail.d/sshd.local"), FT_FAIL2BAN_TAMPER);
    }

    #[test]
    fn parse_fail2ban_recognizes_enabled_sshd() {
        // Direct test of the body-parser via a stub function.
        let body = "[sshd]\nenabled = true\nmaxretry = 5\n";
        assert!(parse_fail2ban_body(body));
    }

    #[test]
    fn parse_fail2ban_recognizes_disabled_sshd() {
        let body = "[sshd]\nenabled = false\n";
        assert!(!parse_fail2ban_body(body));
    }

    #[test]
    fn parse_fail2ban_recognizes_no_sshd_section() {
        let body = "[ssh-iptables]\nenabled = true\n";
        // ssh-iptables is not our trigger word; sshd / ssh are.
        assert!(!parse_fail2ban_body(body));
    }

    #[test]
    fn parse_fail2ban_recognizes_legacy_ssh_section() {
        let body = "[ssh]\nenabled = true\n";
        assert!(parse_fail2ban_body(body));
    }

    // ── authorized_keys addition analysis ────────────────────────
    //
    // These drive the rule that stops WolfStack deleting an SSH key
    // the operator just added. `authorized_keys_added_only_in` takes
    // both texts as arguments precisely so these run without touching
    // the real /var/lib/wolfstack/baselines directory.

    /// Real base64 so `key_blob_fingerprint` decodes it — a blob that
    /// fails to decode is deliberately NOT treated as a plain key.
    fn blob(seed: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(seed.as_bytes())
    }

    #[test]
    fn authorized_keys_pure_addition_is_not_reverted() {
        let base = format!("ssh-ed25519 {} paul@wolf\n", blob("key-a"));
        let cur = format!(
            "ssh-ed25519 {} paul@wolf\nssh-rsa {} deploy@ci\n",
            blob("key-a"), blob("key-b"),
        );
        let added = authorized_keys_added_only_in(&base, &cur)
            .expect("adding a key while keeping the baselined one is an addition");
        assert_eq!(added.len(), 1);
        assert!(added[0].starts_with("ssh-rsa "), "got {}", added[0]);
        assert!(added[0].contains("deploy@ci"), "got {}", added[0]);
    }

    #[test]
    fn authorized_keys_multiple_additions_all_reported() {
        let base = format!("ssh-ed25519 {} paul@wolf\n", blob("key-a"));
        let cur = format!(
            "ssh-ed25519 {} paul@wolf\nssh-rsa {} a\nssh-rsa {} b\n",
            blob("key-a"), blob("key-b"), blob("key-c"),
        );
        let added = authorized_keys_added_only_in(&base, &cur).expect("two additions");
        assert_eq!(added.len(), 2);
    }

    #[test]
    fn authorized_keys_removal_is_tampering() {
        let base = format!(
            "ssh-ed25519 {} paul@wolf\nssh-rsa {} deploy@ci\n",
            blob("key-a"), blob("key-b"),
        );
        let cur = format!("ssh-ed25519 {} paul@wolf\n", blob("key-a"));
        assert!(
            authorized_keys_added_only_in(&base, &cur).is_none(),
            "removing a baselined key is the lockout case — must still revert",
        );
    }

    #[test]
    fn authorized_keys_blob_substitution_is_tampering() {
        // Same comment, different blob: the classic "swap the
        // operator's key for mine" move. The comment must not make
        // this look like the same key.
        let base = format!("ssh-ed25519 {} paul@wolf\n", blob("key-a"));
        let cur = format!("ssh-ed25519 {} paul@wolf\n", blob("attacker"));
        assert!(authorized_keys_added_only_in(&base, &cur).is_none());
    }

    #[test]
    fn authorized_keys_options_prefixed_addition_is_tampering() {
        let base = format!("ssh-ed25519 {} paul@wolf\n", blob("key-a"));
        let cur = format!(
            "ssh-ed25519 {} paul@wolf\ncommand=\"/bin/sh\" ssh-rsa {} x\n",
            blob("key-a"), blob("key-b"),
        );
        assert!(
            authorized_keys_added_only_in(&base, &cur).is_none(),
            "an options-carrying line is not routine key management",
        );
    }

    #[test]
    fn authorized_keys_malformed_addition_is_tampering() {
        let base = format!("ssh-ed25519 {} paul@wolf\n", blob("key-a"));
        let cur = format!(
            "ssh-ed25519 {} paul@wolf\nssh-rsa !!!not-base64!!! x\n",
            blob("key-a"),
        );
        assert!(authorized_keys_added_only_in(&base, &cur).is_none());
    }

    #[test]
    fn authorized_keys_relabel_is_not_an_addition() {
        // Only the trailing comment changed. Nothing was added, so
        // this is not the addition case and takes the normal path
        // (revert once, then alert-only).
        let base = format!("ssh-ed25519 {} old-label\n", blob("key-a"));
        let cur = format!("ssh-ed25519 {} new-label\n", blob("key-a"));
        assert!(authorized_keys_added_only_in(&base, &cur).is_none());
    }

    #[test]
    fn authorized_keys_comments_and_blanks_ignored() {
        let base = format!("# managed by wolfstack\n\nssh-ed25519 {} paul@wolf\n", blob("key-a"));
        let cur = format!(
            "ssh-ed25519 {} paul@wolf\n\n# a note\nssh-rsa {} deploy@ci\n",
            blob("key-a"), blob("key-b"),
        );
        let added = authorized_keys_added_only_in(&base, &cur)
            .expect("comment and blank lines are not keys");
        assert_eq!(added.len(), 1);
    }

    #[test]
    fn authorized_keys_reordering_alone_is_not_an_addition() {
        let base = format!(
            "ssh-ed25519 {} a\nssh-rsa {} b\n", blob("key-a"), blob("key-b"),
        );
        let cur = format!(
            "ssh-rsa {} b\nssh-ed25519 {} a\n", blob("key-b"), blob("key-a"),
        );
        assert!(authorized_keys_added_only_in(&base, &cur).is_none());
    }

    /// Helper exposed for testing the parser without needing
    /// real fail2ban config files on disk.
    fn parse_fail2ban_body(body: &str) -> bool {
        let mut in_sshd = false;
        let mut sshd_enabled = false;
        for line in body.lines() {
            let t = line.trim();
            if t.starts_with('[') && t.ends_with(']') {
                let name = t[1..t.len()-1].to_ascii_lowercase();
                in_sshd = name == "sshd" || name == "ssh";
                continue;
            }
            if !in_sshd { continue; }
            let lower = t.to_ascii_lowercase();
            if lower.starts_with("enabled")
                && let Some((_, rhs)) = lower.split_once('=')
                    && (rhs.trim() == "true" || rhs.trim() == "1") {
                        sshd_enabled = true;
                    }
        }
        sshd_enabled
    }
}
