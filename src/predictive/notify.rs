// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! First-appearance notification dispatch — convergence B.
//!
//! When a `Critical` or `High` proposal first lands in the inbox,
//! fire the existing notification channels (Discord / Slack /
//! Telegram / email). "First appearance" means the (finding_type,
//! scope) was NOT already in the proposal store before this tick —
//! a refresh of an existing pending proposal does NOT re-notify.
//!
//! ## What this replaces
//!
//! - The 2 s `cached_status_bg` loop in `main.rs` was calling
//!   `alerting::check_thresholds(...)` and dispatching directly,
//!   with a 30-min cooldown HashMap. Convergence B retires that
//!   call site — `alerting.rs`'s send-to-channel functions stay
//!   (they're still correct), but the *trigger* is now the
//!   predictive pipeline's findings. Cooldown becomes proposal
//!   dedup: same `(finding_type, scope)` won't re-notify until the
//!   proposal is auto-resolved or operator-acted-on.
//!
//! ## Severity gate
//!
//! - `Critical` and `High` → notify
//! - `Warn` and `Info` → inbox only (operator pulls when ready)
//!
//! A pending finding that ESCALATES to a higher tier than it was last
//! notified at notifies again (see [`find_alerts_to_dispatch`]), and a
//! capacity finding that was notified gets a recovery message when it
//! clears (see [`find_capacity_recoveries`]).
//!
//! ## Async-fire-and-forget
//!
//! Notification I/O can be slow (Discord webhooks, SMTP). We don't
//! want to block the tick body. Each dispatch is `tokio::spawn`'d
//! so the orchestrator returns to its 5-min sleep promptly.

use crate::predictive::Proposal;
use crate::predictive::proposal::{ProposalScope, Severity};

/// Finding types that describe a filesystem running out of space.
/// They dispatch as [`crate::alerting::AlertCategory::Capacity`] (which
/// fires under Simple verbosity) instead of `Threshold`, and get a
/// recovery notification when they clear.
pub const CAPACITY_FINDINGS: &[&str] = &[
    crate::predictive::threshold::FINDING_HOST_DISK_FREE,
    crate::predictive::disk_fill::FINDING_TYPE,
    "docker_storage_fill_eta",
    "lxc_storage_fill_eta",
    crate::predictive::vm_disk::FINDING_TYPE,
    crate::predictive::boot_partition::FINDING_BOOT_SPACE,
];

pub fn is_capacity_finding(finding_type: &str) -> bool {
    CAPACITY_FINDINGS.contains(&finding_type)
}

/// Proposals to notify about this tick. Two cases, both Pending and
/// Critical/High only:
///
/// 1. **First appearance** — the `(finding_type, scope)` was not
///    pending in `previous` (the pre-tick snapshot). A refresh of an
///    already-pending finding does not re-notify.
/// 2. **Escalation** — already pending and notified, but now at a
///    higher severity than it was last notified at. Without this a
///    disk that went "fills in 2 days" (High, notified) → "fills in 40
///    minutes" (Critical) said nothing new.
///
/// The caller must record the dispatched severity back onto each
/// proposal (`notified_severity`) so the same escalation is not sent
/// twice.
pub fn find_alerts_to_dispatch<'a>(
    previous: &[Proposal],
    current: &'a [Proposal],
) -> Vec<&'a Proposal> {
    use std::collections::HashSet;
    let prev_pending: HashSet<(&str, &ProposalScope)> = previous.iter()
        .filter(|p| matches!(p.status, crate::predictive::proposal::ProposalStatus::Pending))
        .map(|p| (p.finding_type.as_str(), &p.scope))
        .collect();

    current.iter()
        .filter(|p| matches!(p.status, crate::predictive::proposal::ProposalStatus::Pending))
        .filter(|p| matches!(p.severity, Severity::Critical | Severity::High))
        .filter(|p| {
            let first_appearance = !prev_pending.contains(&(p.finding_type.as_str(), &p.scope));
            // Lower rank = more severe (Critical 0 … Info 3).
            let escalated = p.notified_severity
                .is_some_and(|n| p.severity.rank() < n.rank());
            first_appearance || escalated
        })
        .collect()
}

/// Capacity findings that were pending AND had been notified before
/// this tick, and that auto-resolved this tick because the condition
/// cleared. The operator was told the disk was filling; they should be
/// told when it no longer is.
pub fn find_capacity_recoveries<'a>(
    previous: &'a [Proposal],
    current: &[Proposal],
) -> Vec<&'a Proposal> {
    use crate::predictive::proposal::{ApprovalOutcome, ProposalStatus};
    previous.iter()
        .filter(|p| matches!(p.status, ProposalStatus::Pending))
        .filter(|p| p.notified_severity.is_some())
        .filter(|p| is_capacity_finding(&p.finding_type))
        .filter(|prev| current.iter().any(|c|
            c.id == prev.id
                && matches!(c.status, ProposalStatus::Approved {
                    outcome: ApprovalOutcome::ConditionCleared, ..
                })
        ))
        .collect()
}

/// Fire the existing alerting channels for a list of newly-appeared
/// proposals. Spawns one task per proposal so a slow Discord webhook
/// doesn't sequence-stall the others. `send_local_alert` resolves the
/// cluster name + hostname inside the dispatch, so operators see
/// `[<cluster> / <host>] <title>` in Discord/Slack/Telegram and the
/// email body opens with a Cluster/Host/When header — fixes the
/// previous "Scope: ws-784bcbe6" UX where notifications carried only
/// the internal node-id slug.
pub fn dispatch_alerts(proposals: Vec<Proposal>) {
    if proposals.is_empty() { return; }
    let cfg = crate::alerting::AlertConfig::load();
    // `has_delivery` covers email as well as the push channels: `send_local_alert`
    // below fans out to both, so gating on push alone silently dropped every
    // predictive page for an operator whose only delivery path is email.
    if !cfg.enabled || !cfg.has_delivery() {
        // Operator hasn't configured notifications — inbox only.
        // This is the common case and shouldn't log noise.
        return;
    }
    for p in proposals {
        tokio::spawn(async move {
            let (title, message) = format_for_channel(&p);
            // Map predictive finding_type → AlertCategory. The
            // `compromise_indicator:*` family (root-shell hijack, locker
            // binary, C2 connection, proxmox-services-masked, bash-history
            // signature, immutable PVE UI — see predictive/compromise_indicators.rs)
            // are real host-compromise signals and must fire under Simple
            // mode. Everything else (disk-fill ETA, container restart-loops,
            // memory creep) is early-warning Threshold material visible in
            // the Predictive Inbox; Simple mode suppresses the push for those.
            let category = if p.finding_type.starts_with("compromise_indicator:") {
                crate::alerting::AlertCategory::Compromise
            } else if is_capacity_finding(&p.finding_type) {
                // Disk running out: fires under Simple verbosity, and a
                // Critical one (hours left) also beats quiet hours.
                crate::alerting::AlertCategory::Capacity {
                    urgent: p.severity == Severity::Critical,
                }
            } else {
                crate::alerting::AlertCategory::Threshold
            };
            crate::alerting::send_local_alert(category, &title, &message).await;
        });
    }
}

/// Tell the operator a capacity finding they were notified about has
/// cleared. `current_state` is a one-line "now: 310 GB free of 436 GB"
/// for the finding's resource when the caller has it.
pub fn dispatch_recoveries(recoveries: Vec<(Proposal, Option<String>)>) {
    if recoveries.is_empty() { return; }
    let cfg = crate::alerting::AlertConfig::load();
    if !cfg.enabled || !cfg.has_delivery() || !cfg.recovery_notifications {
        return;
    }
    for (p, current_state) in recoveries {
        tokio::spawn(async move {
            let (title, message) = format_recovery(&p, current_state.as_deref());
            crate::alerting::send_local_alert(
                crate::alerting::AlertCategory::Capacity { urgent: false },
                &title, &message,
            ).await;
        });
    }
}

fn format_recovery(p: &Proposal, current_state: Option<&str>) -> (String, String) {
    let resource = p.scope.resource_id.as_deref().unwrap_or("resource");
    let what = if p.finding_type == crate::predictive::threshold::FINDING_HOST_DISK_FREE {
        format!("{} is back above its free-space floor", resource)
    } else {
        format!("{} is no longer on course to fill", resource)
    };
    let title = format!("✅ RECOVERED — {}", what);
    let mut message = format!("Earlier alert: {}", p.title);
    if let Some(now) = current_state {
        message.push_str(&format!("\n\nNow: {}", now));
    }
    (title, message)
}

fn format_for_channel(p: &Proposal) -> (String, String) {
    let sev_marker = match p.severity {
        Severity::Critical => "🔴 CRITICAL",
        Severity::High     => "🟠 HIGH",
        Severity::Warn     => "🟡 WARN",
        Severity::Info     => "ℹ INFO",
    };
    // An escalation re-notifies the same finding — say so, or the
    // operator reads it as a duplicate of the earlier message.
    let escalated = p.notified_severity.is_some_and(|n| p.severity.rank() < n.rank());
    let title = if escalated {
        format!("{} (WORSE) — {}", sev_marker, p.title)
    } else {
        format!("{} — {}", sev_marker, p.title)
    };

    // Trim the why-text to a sensible length for chat embeds.
    let why_short = if p.why.len() > 480 {
        format!("{}…", &p.why[..480])
    } else {
        p.why.clone()
    };

    let evidence_lines: Vec<String> = p.evidence.iter()
        .map(|e| format!("• {}: {}", e.label, e.value))
        .collect();

    // Body intentionally omits `p.scope.node_id` — the dispatch wraps
    // this with a Cluster:/Host:/When: header via `send_local_alert`,
    // so duplicating the raw slug here would just be noise. The
    // resource_id (container, disk, etc.) is still useful when present
    // because it disambiguates which *thing on this host* fired.
    let mut message = match &p.scope.resource_id {
        Some(r) => format!("Resource: {}\n\n{}", r, why_short),
        None    => why_short,
    };
    if !evidence_lines.is_empty() {
        message.push_str("\n\nEvidence:\n");
        message.push_str(&evidence_lines.join("\n"));
    }
    message.push_str("\n\nOpen the Predictive Inbox to snooze, dismiss, or apply.");

    (title, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predictive::proposal::{
        ApprovalOutcome, ProposalStatus, RemediationPlan,
    };

    fn p(finding: &str, sev: Severity, status: ProposalStatus) -> Proposal {
        let mut x = Proposal::new_rule(
            finding, sev,
            "title", "why".repeat(50),
            vec![],
            RemediationPlan::Manual { instructions: "x".into(), commands: vec![] },
            ProposalScope { node_id: "n".into(), resource_id: Some("r".into()) },
        );
        x.status = status;
        x
    }

    #[test]
    fn first_appearance_critical_returns_proposal() {
        let prev = vec![];
        let curr = vec![p("disk_fill_eta", Severity::Critical, ProposalStatus::Pending)];
        let alerts = find_alerts_to_dispatch(&prev, &curr);
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn already_pending_not_re_alerted() {
        // Same (finding, scope) pending in both prev and curr → no alert.
        let prev = vec![p("disk_fill_eta", Severity::Critical, ProposalStatus::Pending)];
        let curr = vec![p("disk_fill_eta", Severity::Critical, ProposalStatus::Pending)];
        // Note: dedup uses (finding_type, scope), and our test
        // helper produces fresh proposals each call with different
        // ids — but identical scope. The set lookup matches on
        // (str, &ProposalScope), so this works.
        let alerts = find_alerts_to_dispatch(&prev, &curr);
        assert_eq!(alerts.len(), 0,
            "a still-pending finding must not re-notify on every tick");
    }

    #[test]
    fn warn_and_info_not_alerted() {
        let prev = vec![];
        let curr = vec![
            p("disk_fill_eta", Severity::Warn, ProposalStatus::Pending),
            p("disk_fill_eta", Severity::Info, ProposalStatus::Pending),
        ];
        let alerts = find_alerts_to_dispatch(&prev, &curr);
        assert_eq!(alerts.len(), 0,
            "Warn/Info findings stay in the inbox, never page the operator");
    }

    #[test]
    fn dismissed_status_does_not_alert() {
        let prev = vec![];
        let curr = vec![p("disk_fill_eta", Severity::Critical,
            ProposalStatus::Dismissed {
                reason: "false positive".into(),
                dismissed_at: chrono::Utc::now(),
            })];
        let alerts = find_alerts_to_dispatch(&prev, &curr);
        assert_eq!(alerts.len(), 0);
    }

    #[test]
    fn escalation_re_alerts_once() {
        // Notified at High last tick; now Critical → notify again.
        let mut prev_p = p("disk_fill_eta", Severity::High, ProposalStatus::Pending);
        prev_p.notified_severity = Some(Severity::High);
        let mut cur = prev_p.clone();
        cur.severity = Severity::Critical;
        let prev = vec![prev_p];
        let curr = vec![cur.clone()];
        assert_eq!(find_alerts_to_dispatch(&prev, &curr).len(), 1);

        // After dispatch the caller records Critical; staying Critical
        // (or dropping back to High) must not re-notify.
        cur.notified_severity = Some(Severity::Critical);
        let curr = vec![cur.clone()];
        assert_eq!(find_alerts_to_dispatch(&curr, &curr).len(), 0);
        cur.severity = Severity::High;
        let curr2 = vec![cur];
        assert_eq!(find_alerts_to_dispatch(&curr, &curr2).len(), 0);
    }

    #[test]
    fn legacy_pending_without_marker_does_not_page_on_upgrade() {
        // Persisted before notified_severity existed: still pending,
        // marker None. An upgrade must not page the whole backlog.
        let x = p("disk_fill_eta", Severity::Critical, ProposalStatus::Pending);
        let prev = vec![x.clone()];
        let curr = vec![x];
        assert_eq!(find_alerts_to_dispatch(&prev, &curr).len(), 0);
    }

    #[test]
    fn capacity_recovery_only_for_notified_and_cleared() {
        let mut was = p("host_disk_low_free", Severity::High, ProposalStatus::Pending);
        was.notified_severity = Some(Severity::High);
        let mut now = was.clone();
        now.status = ProposalStatus::Approved {
            applied_at: chrono::Utc::now(),
            outcome: ApprovalOutcome::ConditionCleared,
        };
        assert_eq!(find_capacity_recoveries(&[was.clone()], &[now.clone()]).len(), 1);

        // Never notified (e.g. no delivery configured at the time): silent.
        let mut quiet = was.clone();
        quiet.notified_severity = None;
        assert_eq!(find_capacity_recoveries(&[quiet], &[now.clone()]).len(), 0);

        // Not a capacity finding: silent.
        let mut cpu = was.clone();
        cpu.finding_type = "host_cpu_high".into();
        let mut cpu_now = now.clone();
        cpu_now.finding_type = "host_cpu_high".into();
        assert_eq!(find_capacity_recoveries(&[cpu], &[cpu_now]).len(), 0);
    }

    #[test]
    fn auto_resolved_does_not_alert() {
        // ConditionCleared via auto_resolve — operator never had
        // anything to do, must not page them.
        let prev = vec![];
        let curr = vec![p("disk_fill_eta", Severity::Critical,
            ProposalStatus::Approved {
                applied_at: chrono::Utc::now(),
                outcome: ApprovalOutcome::ConditionCleared,
            })];
        let alerts = find_alerts_to_dispatch(&prev, &curr);
        assert_eq!(alerts.len(), 0);
    }
}
