// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Container restart-loop detection — Item 3 of the predictive plan.
//!
//! Watches each Docker container's cumulative `State.RestartCount`
//! (already populated by `containers::docker_list_all_cached()` from
//! the existing batched-inspect call — no new docker invocation
//! needed) and emits a finding when the count rises beyond a
//! threshold within a short window. Catches the "container kept
//! dying overnight" pattern that operators usually only notice when
//! the service falls over for the third time at 3 am.
//!
//! ## Severity tiers (delta over window)
//!
//! | Recent restarts                     | Severity   |
//! |-------------------------------------|------------|
//! | ≥ 5 in last 10 min                  | `Critical` |
//! | ≥ 3 in last 10 min                  | `High`     |
//! | ≥ 3 in last 30 min                  | `Warn`     |
//! | container state currently `restarting` | bump severity one tier |
//!
//! ## LXC out of scope
//!
//! LXC containers run their own internal init (typically systemd),
//! so restart-loops there are service-level events the systemd
//! journal already handles. The runtime itself doesn't expose a
//! comparable counter cheaply, and adding parallel detection logic
//! would duplicate what's already available via per-LXC journal
//! tail. Re-evaluate when an operator actually asks for it.
//!
//! ## Why a delta-on-counter, not state-transition tracking
//!
//! Tracking state transitions ("running" → "exited" → "running")
//! between 5-min ticks would miss any restart that completes
//! between samples — exactly the fast-loop case we most want to
//! catch. `RestartCount` is monotonic and survives the sampling
//! window, so a fast loop produces a large delta that we DO see.

use std::time::Duration;

use crate::predictive::{
    Context,
    metrics::MetricsHistory,
    proposal::{
        Evidence, Proposal, ProposalScope, RemediationPlan, Severity,
    },
    ack::AckStore,
    container_disk::{Runtime, resource_id, maybe_reset_history, ContainerDiskFact},
};

/// Stable identifier for this finding type.
pub const FINDING_TYPE: &str = "docker_restart_loop";

/// Metric name in [`MetricsHistory`] — same shape as disk samples
/// but the value is the cumulative `RestartCount`, not a
/// percentage.
pub const METRIC: &str = "restart_count";

/// Lookback window for the "rapid loop" detection (Critical/High).
const RAPID_WINDOW_MINUTES: i64 = 10;
/// Lookback window for the "intermittent loop" detection (Warn).
const SUSTAINED_WINDOW_MINUTES: i64 = 30;

/// Threshold for `Critical` severity within `RAPID_WINDOW_MINUTES`.
const RAPID_CRITICAL_DELTA: u64 = 5;
/// Threshold for `High` severity within `RAPID_WINDOW_MINUTES`.
const RAPID_HIGH_DELTA: u64 = 3;
/// Threshold for `Warn` severity within `SUSTAINED_WINDOW_MINUTES`.
const SUSTAINED_DELTA: u64 = 3;

/// One row of restart-count data per running Docker container,
/// derived from the existing `containers::ContainerInfo` cache
/// (which already reads `State.RestartCount` from the batched
/// inspect call).
#[derive(Debug, Clone, PartialEq)]
pub struct RestartFact {
    pub name: String,
    pub id: String,         // for ID-rotation guard via `maybe_reset_history`
    pub image: String,
    pub state: String,      // "running", "restarting", "exited", …
    pub restart_count: u64,
}

/// Sampler — pulls restart counts out of the existing Docker
/// container cache. Synchronous because the cache fronts the
/// expensive Docker-socket call (cache TTL is 30 s; well within our
/// 5-min tick).
pub fn sample_docker_restarts_now() -> Vec<RestartFact> {
    let mut out = Vec::new();
    if !crate::containers::has_docker_cached() { return out; }
    for c in crate::containers::docker_list_all_cached() {
        // Only running containers — a stopped container's
        // RestartCount is frozen and the analyzer's "delta in last
        // 10 min" question doesn't apply.
        if !is_running_or_restarting(&c.state) { continue; }
        let Some(count) = c.restart_count else { continue; };
        out.push(RestartFact {
            name: c.name.clone(),
            id: c.id.clone(),
            image: c.image.clone(),
            state: c.state.clone(),
            restart_count: count,
        });
    }
    out
}

/// Async timeout-bounded variant. Mirrors the pattern in
/// `container_disk::sample_containers_now_async`.
pub async fn sample_docker_restarts_now_async(timeout: Duration) -> Vec<RestartFact> {
    let fut = tokio::task::spawn_blocking(sample_docker_restarts_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(facts)) => facts,
        Ok(Err(e)) => {
            tracing::warn!("predictive: restart-count sampling task panicked: {}", e);
            Vec::new()
        }
        Err(_) => {
            tracing::warn!(
                "predictive: restart-count sampling timed out after {}s — \
                 skipping restart-loop analysis this tick",
                timeout.as_secs(),
            );
            Vec::new()
        }
    }
}

fn is_running_or_restarting(state: &str) -> bool {
    let s = state.to_ascii_lowercase();
    s == "running" || s == "restarting" || s == "started"
}

/// Reset history when a container's ID changes (rebuild under the
/// same name). Reuses the disk analyzer's machinery — the sentinel
/// metric and id-hash fn live in `container_disk` because that's
/// where the convention was first paid for.
pub fn maybe_reset_history_for(history: &mut MetricsHistory, fact: &RestartFact) {
    // Build a temporary `ContainerDiskFact` shim so we can reuse
    // the existing `container_disk::maybe_reset_history` (which
    // takes the disk fact type). The fields we don't care about
    // for the reset check are zero-valued; only `id` and `name`
    // and `runtime` actually matter.
    let shim = ContainerDiskFact {
        runtime: Runtime::Docker,
        name: fact.name.clone(),
        id: fact.id.clone(),
        image: fact.image.clone(),
        used_pct: 0.0,
        total_bytes: 0,
        used_bytes: 0,
    };
    maybe_reset_history(history, &shim);
}

/// Sum the deltas over a window — for a monotonic counter, that's
/// simply `latest - earliest_within_window`. Returns `None` when no
/// sample is old enough to bracket the window.
fn delta_over_window(
    history: &MetricsHistory,
    resource: &str,
    metric: &str,
    window: chrono::Duration,
    current: u64,
) -> Option<u64> {
    let samples = history.samples(resource, metric)?;
    if samples.is_empty() { return None; }
    let now = chrono::Utc::now();
    let cutoff = now - window;
    // Find the oldest sample at or after `cutoff` — that's our
    // baseline. If every sample is younger than the window we
    // don't have history reaching back that far yet.
    let baseline = samples.iter().find(|s| s.ts >= cutoff)?;
    let baseline_count = baseline.value as u64;
    Some(current.saturating_sub(baseline_count))
}

/// Run the analyzer.
pub fn analyze(
    ctx: &Context,
    history: &MetricsHistory,
    current: &[RestartFact],
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();

    for fact in current {
        let resource = resource_id(Runtime::Docker, &fact.name);
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(resource.clone()),
        };
        if acks.suppresses(FINDING_TYPE, &scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE, &scope) { continue; }

        let rapid = delta_over_window(
            history, &resource, METRIC,
            chrono::Duration::minutes(RAPID_WINDOW_MINUTES),
            fact.restart_count,
        );
        let sustained = delta_over_window(
            history, &resource, METRIC,
            chrono::Duration::minutes(SUSTAINED_WINDOW_MINUTES),
            fact.restart_count,
        );

        let Some(verdict) = compute_verdict(rapid, sustained, &fact.state) else { continue; };
        out.push(build_proposal(fact, &scope, &verdict));
    }
    out
}

#[derive(Debug, Clone)]
struct Verdict {
    severity: Severity,
    rapid_delta: u64,
    sustained_delta: u64,
    /// `true` when the container is currently in `restarting` state
    /// — the analyzer bumps severity one tier in this case because
    /// the loop hasn't even paused.
    actively_restarting: bool,
}

fn compute_verdict(
    rapid: Option<u64>,
    sustained: Option<u64>,
    state: &str,
) -> Option<Verdict> {
    let rapid = rapid.unwrap_or(0);
    let sustained = sustained.unwrap_or(0);

    let actively_restarting = state.eq_ignore_ascii_case("restarting");

    // Tier the rapid first; if rapid doesn't trip but sustained does,
    // fall through to Warn. If neither trips, no proposal.
    let mut sev = if rapid >= RAPID_CRITICAL_DELTA { Severity::Critical }
        else if rapid >= RAPID_HIGH_DELTA { Severity::High }
        else if sustained >= SUSTAINED_DELTA { Severity::Warn }
        else { return None; };

    if actively_restarting { sev = bump(sev); }

    Some(Verdict { severity: sev, rapid_delta: rapid, sustained_delta: sustained, actively_restarting })
}

fn bump(sev: Severity) -> Severity {
    match sev {
        Severity::Info => Severity::Warn,
        Severity::Warn => Severity::High,
        Severity::High => Severity::Critical,
        Severity::Critical => Severity::Critical,
    }
}

fn build_proposal(fact: &RestartFact, scope: &ProposalScope, v: &Verdict) -> Proposal {
    let title = if v.actively_restarting {
        format!("Container '{}' is restart-looping right now", fact.name)
    } else if v.rapid_delta >= RAPID_HIGH_DELTA {
        format!(
            "Container '{}' has restarted {} time{} in the last {} min",
            fact.name, v.rapid_delta,
            if v.rapid_delta == 1 { "" } else { "s" },
            RAPID_WINDOW_MINUTES,
        )
    } else {
        format!(
            "Container '{}' has restarted {} time{} in the last {} min",
            fact.name, v.sustained_delta,
            if v.sustained_delta == 1 { "" } else { "s" },
            SUSTAINED_WINDOW_MINUTES,
        )
    };

    let why = format!(
        "Docker container '{}' (image '{}') has incremented its \
         RestartCount by {} in the last {} minutes (and {} in the \
         last {} minutes). Current state: {}. Sustained restart \
         loops indicate a service that's failing to start cleanly — \
         common causes: misconfigured environment, missing volume \
         mount, an upstream dependency that isn't ready, or a \
         crashing entrypoint.",
        fact.name, fact.image, v.rapid_delta, RAPID_WINDOW_MINUTES,
        v.sustained_delta, SUSTAINED_WINDOW_MINUTES,
        fact.state,
    );

    let evidence = vec![
        Evidence {
            label: "Container".into(),
            value: fact.name.clone(),
            detail: Some(format!("docker · {}", fact.image)),
            links: Vec::new(),
        },
        Evidence {
            label: format!("Restarts (last {}m)", RAPID_WINDOW_MINUTES),
            value: v.rapid_delta.to_string(),
            detail: None,
            links: Vec::new(),
        },
        Evidence {
            label: format!("Restarts (last {}m)", SUSTAINED_WINDOW_MINUTES),
            value: v.sustained_delta.to_string(),
            detail: None,
            links: Vec::new(),
        },
        Evidence {
            label: "Current state".into(),
            value: fact.state.clone(),
            detail: if v.actively_restarting {
                Some("Severity bumped one tier — the loop hasn't paused.".into())
            } else { None },
            links: Vec::new(),
        },
    ];

    let remediation = RemediationPlan::Manual {
        instructions: format!(
            "Inspect why container '{name}' is failing to start cleanly. \
             The container's recent stdout/stderr almost always contains \
             the cause. If the container has a `restart: always` policy, \
             docker will keep retrying — disabling it temporarily makes \
             debugging easier.",
            name = fact.name,
        ),
        commands: vec![
            format!("docker logs --tail 200 {} 2>&1 | tail -50", fact.name),
            format!("docker inspect --format '{{{{.State.Error}}}} {{{{.State.ExitCode}}}}' {}", fact.name),
            format!("docker inspect --format '{{{{json .HostConfig.RestartPolicy}}}}' {} | python3 -m json.tool", fact.name),
            format!("docker stop {}    # halt the loop while you investigate", fact.name),
        ],
    };

    Proposal::new_rule(
        FINDING_TYPE,
        v.severity,
        title,
        why,
        evidence,
        remediation,
        scope.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use crate::predictive::NetworkSnapshot;
    use crate::predictive::proposal::ProposalStore;

    fn ctx() -> Context {
        Context {
            node_id: "node-a".into(),
            network: NetworkSnapshot::from_parts(vec![], vec![]),
        }
    }

    fn fact(name: &str, count: u64, state: &str) -> RestartFact {
        RestartFact {
            name: name.into(),
            id: format!("id-{}", name),
            image: "test/image:latest".into(),
            state: state.into(),
            restart_count: count,
        }
    }

    fn seed_count(history: &mut MetricsHistory, name: &str, samples: &[(i64, u64)]) {
        let now = Utc::now();
        for (mins_ago, count) in samples {
            history.record_at(
                &resource_id(Runtime::Docker, name),
                METRIC,
                *count as f64,
                now - ChronoDuration::minutes(*mins_ago),
            );
        }
    }

    // ── Verdict thresholds ───────────────────────────────────────

    #[test]
    fn no_verdict_when_no_restarts() {
        let v = compute_verdict(Some(0), Some(0), "running");
        assert!(v.is_none());
    }

    #[test]
    fn rapid_5_is_critical() {
        let v = compute_verdict(Some(5), Some(5), "running").expect("verdict");
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn rapid_3_is_high() {
        let v = compute_verdict(Some(3), Some(3), "running").expect("verdict");
        assert_eq!(v.severity, Severity::High);
    }

    #[test]
    fn sustained_3_only_is_warn() {
        let v = compute_verdict(Some(0), Some(3), "running").expect("verdict");
        assert_eq!(v.severity, Severity::Warn);
    }

    #[test]
    fn restarting_state_bumps_severity_one_tier() {
        // Same delta numbers but state == restarting → bumps Warn → High
        let v = compute_verdict(Some(0), Some(3), "restarting").expect("verdict");
        assert_eq!(v.severity, Severity::High);
        assert!(v.actively_restarting);
    }

    #[test]
    fn restarting_state_caps_at_critical() {
        // Critical + bump = still Critical, never overflows.
        let v = compute_verdict(Some(10), Some(10), "restarting").expect("verdict");
        assert_eq!(v.severity, Severity::Critical);
    }

    // ── Delta computation ────────────────────────────────────────

    #[test]
    fn delta_returns_difference_from_baseline() {
        let mut h = MetricsHistory::default();
        seed_count(&mut h, "loopy", &[(20, 5), (10, 7), (1, 12)]);
        // Window = 15 min, current = 12, baseline (oldest in
        // window) is sample at 10 min ago = 7. Delta = 5.
        let d = delta_over_window(
            &h, &resource_id(Runtime::Docker, "loopy"),
            METRIC, ChronoDuration::minutes(15), 12,
        );
        assert_eq!(d, Some(5));
    }

    #[test]
    fn delta_returns_none_when_no_history_in_window() {
        let mut h = MetricsHistory::default();
        // Only sample is 60 min ago; window is 10 min → no
        // baseline within window.
        seed_count(&mut h, "loopy", &[(60, 10)]);
        let d = delta_over_window(
            &h, &resource_id(Runtime::Docker, "loopy"),
            METRIC, ChronoDuration::minutes(10), 12,
        );
        assert_eq!(d, None);
    }

    #[test]
    fn delta_saturates_on_counter_reset() {
        // Counter went DOWN (container recreated, restart_count
        // reset to 0). saturating_sub returns 0, not underflow.
        let mut h = MetricsHistory::default();
        seed_count(&mut h, "loopy", &[(5, 100)]);
        let d = delta_over_window(
            &h, &resource_id(Runtime::Docker, "loopy"),
            METRIC, ChronoDuration::minutes(10), 0,
        );
        assert_eq!(d, Some(0));
    }

    // ── End-to-end analyzer behaviour ────────────────────────────

    #[test]
    fn analyzer_emits_for_rapid_loop() {
        // Baseline within the 10-min rapid window is the 8-min-ago
        // sample with count=0. Current=5 → delta=5 → Critical tier.
        // (Earlier draft had a 4-min-ago=5 + 1-min-ago=5 mid-window
        // which produced delta=3, the High tier, not Critical.)
        let mut h = MetricsHistory::default();
        seed_count(&mut h, "loopy", &[(8, 0), (4, 3), (1, 5)]);
        let facts = vec![fact("loopy", 5, "running")];
        let proposals = analyze(
            &ctx(), &h, &facts,
            &AckStore::default(),
            &ProposalStore::default(),
        );
        assert_eq!(proposals.len(), 1);
        let p = &proposals[0];
        assert_eq!(p.finding_type, FINDING_TYPE);
        assert_eq!(p.severity, Severity::Critical);
        assert!(p.title.contains("loopy"));
    }

    #[test]
    fn analyzer_stays_quiet_on_steady_container() {
        let mut h = MetricsHistory::default();
        // RestartCount is stable at 2 — no recent restarts.
        seed_count(&mut h, "stable", &[(40, 2), (20, 2), (5, 2)]);
        let facts = vec![fact("stable", 2, "running")];
        let proposals = analyze(
            &ctx(), &h, &facts,
            &AckStore::default(),
            &ProposalStore::default(),
        );
        assert!(proposals.is_empty(),
            "stable RestartCount must produce no finding even though count > 0");
    }

    #[test]
    fn analyzer_respects_ack() {
        let mut h = MetricsHistory::default();
        seed_count(&mut h, "flappy", &[(15, 0), (5, 5)]);
        let facts = vec![fact("flappy", 5, "running")];
        let mut acks = AckStore::default();
        acks.add(crate::predictive::ack::Ack::new(
            FINDING_TYPE,
            crate::predictive::ack::AckScope::Resource {
                node_id: "node-a".into(),
                resource_id: resource_id(Runtime::Docker, "flappy"),
            },
            "Healthcheck-driven restart, expected during deploys",
            "paul", None,
        ));
        let proposals = analyze(&ctx(), &h, &facts, &acks, &ProposalStore::default());
        assert!(proposals.is_empty());
    }

    /// Discipline: analyzer can stay quiet when nothing is wrong.
    #[test]
    fn analyzer_can_stay_quiet() {
        let mut h = MetricsHistory::default();
        seed_count(&mut h, "calm", &[(40, 0), (30, 0), (10, 0)]);
        let facts = vec![fact("calm", 0, "running")];
        let proposals = analyze(
            &ctx(), &h, &facts,
            &AckStore::default(),
            &ProposalStore::default(),
        );
        assert!(proposals.is_empty());
    }
}
