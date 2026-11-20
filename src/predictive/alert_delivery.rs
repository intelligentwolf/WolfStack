// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! "Alerts from this node reach nobody."
//!
//! ## Why this exists (wolfstack-2, 2026-11-19)
//!
//! wolfstack-2's root disk filled and took a Galera node out of the
//! cluster. WolfStack had found the problem hours earlier, but none of
//! wolfstack-1/2/3 had alerting enabled or any delivery channel set up,
//! so every finding sat in the Predictive Inbox and nobody was told.
//! Nothing anywhere said that alerting was off. An unconfigured install
//! is the default state, so this is the most likely way for a real
//! warning to go unseen.
//!
//! This finding makes that state visible. It's `Warn`, not a notifying
//! tier: by definition there is no channel to deliver it on. It's shown
//! in the inbox and, via the dashboard banner, in the browser of anyone
//! looking at any node in the cluster.
//!
//! The condition matches what `notify::dispatch_alerts` checks before
//! sending (`enabled && has_delivery()`), so the finding is present
//! exactly when predictive alerts would be dropped.

use std::time::Duration;

use crate::predictive::{
    Context,
    ack::AckStore,
    proposal::{Evidence, Proposal, ProposalScope, ProposalStore, RemediationPlan, Severity},
};

pub const FINDING_TYPE: &str = "alert_delivery_missing";

/// Node-scoped: one finding per node, not per channel.
const RESOURCE: &str = "alerting";

/// Alert-delivery state of this node. `None` when the config couldn't
/// be read this tick (sampler timed out); the finding is then left
/// uncovered so it neither appears nor auto-resolves on no data.
#[derive(Debug, Clone, Default)]
pub struct AlertDeliveryFacts {
    pub state: Option<DeliveryState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryState {
    /// Settings → Alerts → "Enable alerts".
    pub enabled: bool,
    /// At least one selected channel (email, Discord, Slack, Telegram,
    /// ntfy) has credentials.
    pub has_delivery: bool,
}

pub async fn sample_now_async(timeout: Duration) -> AlertDeliveryFacts {
    let fut = tokio::task::spawn_blocking(|| {
        let cfg = crate::alerting::AlertConfig::load();
        DeliveryState { enabled: cfg.enabled, has_delivery: cfg.has_delivery() }
    });
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(s)) => AlertDeliveryFacts { state: Some(s) },
        _ => AlertDeliveryFacts::default(),
    }
}

fn scope_for(ctx: &Context) -> ProposalScope {
    ProposalScope { node_id: ctx.node_id.clone(), resource_id: Some(RESOURCE.into()) }
}

pub fn analyze(
    ctx: &Context,
    facts: &AlertDeliveryFacts,
    acks: &AckStore,
    proposals: &ProposalStore,
) -> Vec<Proposal> {
    let Some(st) = facts.state else { return Vec::new() };
    if st.enabled && st.has_delivery { return Vec::new(); }
    let scope = scope_for(ctx);
    if acks.suppresses(FINDING_TYPE, &scope) || proposals.is_suppressed(FINDING_TYPE, &scope) {
        return Vec::new();
    }

    let problem = match (st.enabled, st.has_delivery) {
        (false, false) => "Alerts are switched off and no delivery channel is set up.",
        (false, true) => "A delivery channel is set up, but alerts are switched off.",
        (true, false) => "Alerts are switched on, but no delivery channel (email, Discord, \
                          Slack, Telegram or ntfy) is set up or selected.",
        (true, true) => unreachable!("returned above"),
    };

    vec![Proposal::new_rule(
        FINDING_TYPE,
        Severity::Warn,
        "Alerts from this node reach nobody",
        format!(
            "{} Warnings this node raises — a disk about to fill, a host \
             compromise, a failed backup — appear only in this inbox and \
             the browser banner. If nobody is looking, nobody is told.",
            problem,
        ),
        vec![
            Evidence {
                label: "Alerts enabled".into(),
                value: if st.enabled { "yes" } else { "no" }.into(),
                detail: None,
                links: Vec::new(),
            },
            Evidence {
                label: "Delivery channel".into(),
                value: if st.has_delivery { "configured" } else { "none" }.into(),
                detail: Some("Email: Settings → AI Agent → Email Alerts. Push channels: \
                              Settings → Alerts → Notifications".into()),
                links: Vec::new(),
            },
        ],
        RemediationPlan::Manual {
            instructions: "On this node: Settings → Alerts → Notifications — \
                switch alerts on and set up a push channel (ntfy, Discord, \
                Slack or Telegram), and/or email under Settings → AI Agent → \
                Email Alerts. Press Send test. Then use \"Copy to every node \
                in this cluster\" on the Notifications page so the other \
                nodes deliver too.".into(),
            commands: Vec::new(),
        },
        scope,
    )]
}

pub fn covered_scopes(ctx: &Context, facts: &AlertDeliveryFacts) -> Vec<(String, ProposalScope)> {
    match facts.state {
        Some(_) => vec![(FINDING_TYPE.to_string(), scope_for(ctx))],
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predictive::NetworkSnapshot;

    fn ctx() -> Context {
        Context { node_id: "node-a".into(), network: NetworkSnapshot::from_parts(vec![], vec![]) }
    }

    fn facts(enabled: bool, has_delivery: bool) -> AlertDeliveryFacts {
        AlertDeliveryFacts { state: Some(DeliveryState { enabled, has_delivery }) }
    }

    #[test]
    fn fires_for_every_non_delivering_state() {
        for (e, d) in [(false, false), (false, true), (true, false)] {
            let p = analyze(&ctx(), &facts(e, d), &AckStore::default(), &ProposalStore::default());
            assert_eq!(p.len(), 1, "enabled={} delivery={}", e, d);
            assert_eq!(p[0].severity, Severity::Warn);
        }
    }

    #[test]
    fn quiet_when_alerts_can_be_delivered() {
        let p = analyze(&ctx(), &facts(true, true), &AckStore::default(), &ProposalStore::default());
        assert!(p.is_empty());
    }

    #[test]
    fn no_data_neither_fires_nor_covers() {
        let f = AlertDeliveryFacts::default();
        assert!(analyze(&ctx(), &f, &AckStore::default(), &ProposalStore::default()).is_empty());
        assert!(covered_scopes(&ctx(), &f).is_empty(),
            "an unread config must not auto-resolve an existing finding");
    }
}
