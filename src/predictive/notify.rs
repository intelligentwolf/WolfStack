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
//! ## Async-fire-and-forget
//!
//! Notification I/O can be slow (Discord webhooks, SMTP). We don't
//! want to block the tick body. Each dispatch is `tokio::spawn`'d
//! so the orchestrator returns to its 5-min sleep promptly.

use crate::predictive::Proposal;
use crate::predictive::proposal::{ProposalScope, Severity};

/// Find proposals that are *new this tick* — present in `current`
/// (the post-upsert state) at Pending status but absent from
/// `previous` (the pre-tick snapshot). Only Critical and High are
/// notification-worthy; anything else is inbox-only.
pub fn find_first_appearance_alerts<'a>(
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
        .filter(|p| !prev_pending.contains(&(p.finding_type.as_str(), &p.scope)))
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
            } else {
                crate::alerting::AlertCategory::Threshold
            };
            crate::alerting::send_local_alert(category, &title, &message).await;
        });
    }
}

fn format_for_channel(p: &Proposal) -> (String, String) {
    let sev_marker = match p.severity {
        Severity::Critical => "🔴 CRITICAL",
        Severity::High     => "🟠 HIGH",
        Severity::Warn     => "🟡 WARN",
        Severity::Info     => "ℹ INFO",
    };
    let title = format!("{} — {}", sev_marker, p.title);

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
        ApprovalOutcome, ProposalSource, ProposalStatus, RemediationPlan,
    };

    fn p(finding: &str, sev: Severity, status: ProposalStatus) -> Proposal {
        let mut x = Proposal::new(
            finding, ProposalSource::Rule, sev,
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
        let alerts = find_first_appearance_alerts(&prev, &curr);
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
        let alerts = find_first_appearance_alerts(&prev, &curr);
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
        let alerts = find_first_appearance_alerts(&prev, &curr);
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
        let alerts = find_first_appearance_alerts(&prev, &curr);
        assert_eq!(alerts.len(), 0);
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
        let alerts = find_first_appearance_alerts(&prev, &curr);
        assert_eq!(alerts.len(), 0);
    }
}
