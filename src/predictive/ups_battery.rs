// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! UPS battery that needs replacing.
//!
//! ## Why this exists (RutgerDiehard, 2026-09-25)
//!
//! "WolfStack doesn't surface a failed UPS battery; in either predictive
//! inbox, issues scanner or UPS Power for each node." NUT reports a worn
//! battery as the `RB` token in `ups.status` ("The battery needs to be
//! replaced", NUT docs/new-drivers.txt "Status data"), some drivers also
//! count `battery.packs.bad`, and several report a failed battery ONLY
//! through `ups.test.result` (see `ups::self_test_failed` for which).
//! The UPS module parsed only OL/OB/LB, so all of it was dropped before
//! anything could show it. A dead battery is
//! silent until the next outage: the UPS drops the load the moment mains
//! fails, and the staged shutdown never gets a chance to run.
//!
//! The decision itself lives in `ups::parse_upsc` (`replace_battery`), so
//! the UPS page, the Issues scan and this finding can never disagree about
//! what counts as a failed battery. Severity High so the first appearance
//! pages the operator through the normal notification channels.

use std::time::Duration;

use crate::predictive::{
    Context,
    ack::AckStore,
    proposal::{Evidence, Proposal, ProposalScope, ProposalStore, RemediationPlan, Severity},
};

pub const FINDING_TYPE: &str = "ups_battery_replace";

/// One successful reading of the configured UPS. `None` in [`UpsFacts`]
/// means no target is configured, `upsc` is missing, or the read failed.
/// All three leave the finding uncovered, so an unreachable upsd never
/// auto-resolves a real fault.
#[derive(Debug, Clone)]
pub struct UpsReading {
    pub target: String,
    pub live: crate::ups::UpsLiveStatus,
}

#[derive(Debug, Clone, Default)]
pub struct UpsFacts {
    pub reading: Option<UpsReading>,
}

/// Read the UPS this node is configured to monitor. Reads the same
/// `/etc/wolfstack/ups.json` target the UPS page and engine use.
pub async fn sample_now_async(timeout: Duration) -> UpsFacts {
    let fut = tokio::task::spawn_blocking(sample_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(f)) => f,
        _ => UpsFacts::default(),
    }
}

fn sample_now() -> UpsFacts {
    let target = crate::ups::UpsConfig::load().ups.trim().to_string();
    if target.is_empty() || !crate::ups::upsc_installed() {
        return UpsFacts::default();
    }
    match crate::ups::query_ups(&target) {
        Ok(live) => UpsFacts { reading: Some(UpsReading { target, live }) },
        Err(_) => UpsFacts::default(),
    }
}

fn scope_for(ctx: &Context, target: &str) -> ProposalScope {
    ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some(format!("ups:{}", target)),
    }
}

pub fn analyze(
    ctx: &Context,
    facts: &UpsFacts,
    acks: &AckStore,
    proposals: &ProposalStore,
) -> Vec<Proposal> {
    let Some(r) = &facts.reading else { return Vec::new() };
    let Some(why_flagged) = crate::ups::battery_fault_summary(&r.live) else { return Vec::new() };
    let scope = scope_for(ctx, &r.target);
    if acks.suppresses(FINDING_TYPE, &scope) || proposals.is_suppressed(FINDING_TYPE, &scope) {
        return Vec::new();
    }

    let name = if r.live.model.is_empty() {
        format!("UPS '{}'", r.target)
    } else {
        format!("UPS '{}' ({})", r.target, r.live.model)
    };
    let mut evidence = vec![Evidence {
        label: "ups.status".into(),
        value: r.live.status.clone(),
        detail: Some("RB = the battery needs to be replaced (NUT status flag)".into()),
        links: Vec::new(),
    }];
    if let Some(n) = r.live.battery_packs_bad {
        evidence.push(Evidence {
            label: "Bad battery packs".into(),
            value: n.to_string(),
            detail: None,
            links: Vec::new(),
        });
    }
    if let Some(t) = &r.live.test_result {
        evidence.push(Evidence {
            label: "Last self-test".into(),
            value: t.clone(),
            detail: r.live.test_failed.then(|| {
                "The UPS keeps reporting this result until the next self-test runs.".into()
            }),
            links: Vec::new(),
        });
    }
    if let Some(d) = &r.live.battery_date {
        evidence.push(Evidence {
            label: "Battery installed".into(),
            value: d.clone(),
            detail: None,
            links: Vec::new(),
        });
    }
    if let Some(c) = r.live.charge {
        evidence.push(Evidence {
            label: "Charge".into(),
            value: format!("{}%", c),
            detail: Some(
                "A worn battery can still read 100% on mains; the charge figure says \
                 nothing about how long it will hold the load."
                    .into(),
            ),
            links: Vec::new(),
        });
    }

    vec![Proposal::new_rule(
        FINDING_TYPE,
        Severity::High,
        format!("{} battery needs replacing", name),
        format!(
            "{}: {}. A failed battery is invisible while mains power is present, then \
             fails all at once: at the next power cut the UPS may drop the load at once \
             or hold it for far less time than its runtime figure suggests, before any \
             staged shutdown can run. Replace the battery before relying on this UPS.",
            name, why_flagged,
        ),
        evidence,
        RemediationPlan::Manual {
            instructions: format!(
                "Replace the battery pack in {name}. Afterwards, run the UPS's own battery \
                 self-test (from its front panel, or through NUT if your driver supports the \
                 command) and check that the RB flag has gone from ups.status and the test \
                 result shows a pass. A failed test result stays until a new test runs, so \
                 this finding clears by itself only after that passing test. \
                 Some UPS models also want the battery-installation date reset from their \
                 front panel or vendor tool."
            ),
            commands: vec![
                format!("upsc {}", r.target),
                format!("upscmd -l {}", r.target),
                format!("upscmd -u <nut-user> {} test.battery.start.quick", r.target),
            ],
        },
        scope,
    )]
}

/// Covered only when the UPS was actually read this tick, so a comms
/// failure leaves an open finding alone rather than auto-resolving it.
pub fn covered_scopes(ctx: &Context, facts: &UpsFacts) -> Vec<(String, ProposalScope)> {
    match &facts.reading {
        Some(r) => vec![(FINDING_TYPE.to_string(), scope_for(ctx, &r.target))],
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(status: &str) -> crate::ups::UpsLiveStatus {
        crate::ups::UpsLiveStatus {
            status: status.into(),
            on_battery: false,
            low_battery: false,
            charge: Some(100),
            runtime_secs: None,
            load: None,
            replace_battery: status.split_whitespace().any(|t| t == "RB"),
            test_failed: false,
            battery_packs_bad: None,
            test_result: None,
            alarm: None,
            battery_date: None,
            model: "Back-UPS".into(),
            read_at: 0,
        }
    }

    fn facts(status: &str) -> UpsFacts {
        UpsFacts { reading: Some(UpsReading { target: "ups@nas".into(), live: live(status) }) }
    }

    #[test]
    fn replace_battery_raises_high_finding() {
        let ctx = Context::for_node("n1");
        let out = analyze(&ctx, &facts("OL RB"), &AckStore::default(), &ProposalStore::default());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::High);
        assert_eq!(out[0].scope.resource_id.as_deref(), Some("ups:ups@nas"));
    }

    #[test]
    fn healthy_battery_is_quiet_but_covered() {
        let ctx = Context::for_node("n1");
        let f = facts("OL");
        assert!(analyze(&ctx, &f, &AckStore::default(), &ProposalStore::default()).is_empty());
        assert_eq!(covered_scopes(&ctx, &f).len(), 1);
    }

    #[test]
    fn unreadable_ups_is_not_covered() {
        let ctx = Context::for_node("n1");
        assert!(covered_scopes(&ctx, &UpsFacts::default()).is_empty());
    }
}
