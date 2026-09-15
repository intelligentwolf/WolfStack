// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Container memory pressure — Item 5 of the predictive plan.
//!
//! Per-running-container memory check covering the same conditions
//! that `alerting::check_container_thresholds` was firing in the
//! 2-second `cached_status_bg` loop. Convergence:
//! - This analyzer is the canonical memory-pressure source going
//!   forward.
//! - The legacy dispatch in `main.rs` can be retired once this is
//!   live and no operator complains about missed alerts.
//!
//! ## Severity tiers
//!
//! | memory % of cgroup limit | Severity   |
//! |--------------------------|------------|
//! | ≥ 95 %                   | `Critical` |
//! | ≥ 90 %                   | `High`     |
//! | ≥ 80 %                   | `Warn`     |
//! | < 80 %                   | suppressed |
//!
//! Containers without a memory limit (`memory_limit == 0`) are
//! skipped — there's nothing to compute a percentage against and
//! firing on absolute usage would be noise on multi-tenant hosts.
//!
//! ## What this DOESN'T cover (yet)
//!
//! Trend-based "memory will hit the limit in 2 hours" using the
//! same linear-fit machinery as disk-fill. The shape is identical
//! (cgroup `memory.current` over time → ETA to limit) and shares
//! the same `disk_verdict` core. Adding it is a follow-up; the
//! threshold check above is what retires the legacy duplicate.

use std::time::Duration;

use crate::predictive::{
    Context,
    proposal::{
        Evidence, Proposal, ProposalScope, RemediationPlan, Severity,
    },
    ack::AckStore,
    container_disk::{Runtime, resource_id},
};

pub const FINDING_TYPE_DOCKER: &str = "docker_memory_pressure";
pub const FINDING_TYPE_LXC: &str    = "lxc_memory_pressure";

const WARN_PCT: f64 = 80.0;
const HIGH_PCT: f64 = 90.0;
const CRITICAL_PCT: f64 = 95.0;

/// Per-container memory fact, runtime-tagged. Sourced from the
/// existing `containers::docker_stats_cached()` and `lxc_stats_cached()`
/// — same data feeding the legacy threshold dispatch.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryFact {
    pub runtime: Runtime,
    pub name: String,
    pub memory_pct: f64,
    pub memory_used_bytes: u64,
    pub memory_limit_bytes: u64,
}

impl MemoryFact {
    pub fn finding_type(&self) -> &'static str {
        match self.runtime {
            Runtime::Docker => FINDING_TYPE_DOCKER,
            Runtime::Lxc    => FINDING_TYPE_LXC,
        }
    }
}

/// Sample container memory stats. Synchronous because the cache TTL
/// in `containers/mod.rs` already keeps the underlying Docker-socket
/// / `lxc-info` calls cheap.
pub fn sample_container_memory_now() -> Vec<MemoryFact> {
    let mut out = Vec::new();
    for s in crate::containers::docker_stats_cached() {
        if let Some(f) = stat_to_fact(&s, Runtime::Docker) { out.push(f); }
    }
    for s in crate::containers::lxc_stats_cached() {
        if let Some(f) = stat_to_fact(&s, Runtime::Lxc) { out.push(f); }
    }
    out
}

pub async fn sample_container_memory_now_async(timeout: Duration) -> Vec<MemoryFact> {
    let fut = tokio::task::spawn_blocking(sample_container_memory_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            tracing::warn!("predictive: container memory sampling task panicked: {}", e);
            Vec::new()
        }
        Err(_) => {
            tracing::warn!(
                "predictive: container memory sampling timed out after {}s",
                timeout.as_secs(),
            );
            Vec::new()
        }
    }
}

fn stat_to_fact(s: &crate::containers::ContainerStats, runtime: Runtime) -> Option<MemoryFact> {
    if s.memory_limit == 0 { return None; }  // no quota → nothing to compute against
    Some(MemoryFact {
        runtime,
        name: s.name.clone(),
        memory_pct: s.memory_percent,
        memory_used_bytes: s.memory_usage,
        memory_limit_bytes: s.memory_limit,
    })
}

/// Map a memory percentage to a severity tier. `None` when below
/// the warning threshold.
pub fn severity_for_pct(pct: f64) -> Option<Severity> {
    if pct >= CRITICAL_PCT { Some(Severity::Critical) }
    else if pct >= HIGH_PCT { Some(Severity::High) }
    else if pct >= WARN_PCT { Some(Severity::Warn) }
    else { None }
}

pub fn analyze(
    ctx: &Context,
    current: &[MemoryFact],
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    // Respect the Settings → Alerts "Container memory alert" toggle. Default
    // true (existing behaviour unchanged); when off, emit nothing — existing
    // findings auto-resolve since covered_scopes still reports their scopes
    // (wabil 2026-06-21).
    if !crate::alerting::AlertConfig::load().alert_containers {
        return Vec::new();
    }
    let mut out = Vec::new();
    for fact in current {
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(resource_id(fact.runtime, &fact.name)),
        };
        let finding_type = fact.finding_type();
        if acks.suppresses(finding_type, &scope) { continue; }
        if proposals.is_suppressed(finding_type, &scope) { continue; }

        let Some(severity) = severity_for_pct(fact.memory_pct) else { continue; };
        out.push(build_proposal(fact, &scope, severity));
    }
    out
}

pub fn covered_scopes(
    ctx: &Context,
    current: &[MemoryFact],
) -> Vec<(String, ProposalScope)> {
    current.iter().map(|f| (
        f.finding_type().to_string(),
        ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(resource_id(f.runtime, &f.name)),
        },
    )).collect()
}

fn build_proposal(fact: &MemoryFact, scope: &ProposalScope, severity: Severity) -> Proposal {
    let runtime_label = match fact.runtime {
        Runtime::Docker => "docker",
        Runtime::Lxc    => "lxc",
    };
    let used_gb = fact.memory_used_bytes as f64 / 1_073_741_824.0;
    let limit_gb = fact.memory_limit_bytes as f64 / 1_073_741_824.0;

    let title = format!(
        "{} container '{}' memory at {:.1}% of limit",
        runtime_label, fact.name, fact.memory_pct,
    );

    let why = format!(
        "{} container '{}' is using {:.2} GB of its {:.2} GB cgroup \
         memory limit ({:.1}%). At ≥95 % the OOM killer may start \
         terminating processes inside the container; at ≥90 % the \
         container is one large allocation away from that. Common \
         causes: a leak, a workload that's outgrown its limit, or \
         a missing eviction in the application's own cache.",
        runtime_label, fact.name, used_gb, limit_gb, fact.memory_pct,
    );

    let evidence = vec![
        Evidence {
            label: "Memory".into(),
            value: format!("{:.1}% of limit", fact.memory_pct),
            detail: Some(format!("{:.2} GB used of {:.2} GB", used_gb, limit_gb)),
            links: Vec::new(),
        },
        Evidence {
            label: "Container".into(),
            value: fact.name.clone(),
            detail: Some(runtime_label.into()),
            links: Vec::new(),
        },
    ];

    let remediation = match fact.runtime {
        Runtime::Docker => RemediationPlan::Manual {
            instructions: format!(
                "Inspect what's holding memory in container '{name}'. \
                 If the limit is too tight for the workload, raise it; \
                 if there's a leak, the journal usually shows it. \
                 Restarting the container is the cheapest mitigation \
                 if you can't fix the cause immediately.",
                name = fact.name,
            ),
            commands: vec![
                format!("docker stats --no-stream {}", fact.name),
                format!("docker top {}", fact.name),
                format!("docker logs --tail 200 {} 2>&1 | grep -iE 'oom|out of memory|killed' || true", fact.name),
                format!("docker update --memory={}m {}    # raise limit", limit_gb as u64 * 1024 + 256, fact.name),
            ],
        },
        Runtime::Lxc => RemediationPlan::Manual {
            instructions: format!(
                "LXC container '{name}' is approaching its cgroup \
                 memory limit. Either raise the limit or identify \
                 the process that's consuming it.",
                name = fact.name,
            ),
            commands: vec![
                format!("sudo lxc-attach -n {} -- ps aux --sort=-rss | head -10", fact.name),
                format!("sudo cat /sys/fs/cgroup/lxc.payload.{}/memory.current 2>/dev/null", fact.name),
            ],
        },
    };

    Proposal::new_rule(
        fact.finding_type(), severity,
        title, why, evidence, remediation, scope.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predictive::NetworkSnapshot;
    use crate::predictive::proposal::ProposalStore;

    fn ctx() -> Context {
        Context {
            node_id: "node-a".into(),
            network: NetworkSnapshot::from_parts(vec![], vec![]),
        }
    }

    fn fact(runtime: Runtime, name: &str, pct: f64) -> MemoryFact {
        MemoryFact {
            runtime, name: name.into(),
            memory_pct: pct,
            memory_used_bytes: ((pct / 100.0) * 4.0 * 1_073_741_824.0) as u64,
            memory_limit_bytes: 4 * 1_073_741_824,
        }
    }

    #[test]
    fn severity_thresholds() {
        assert_eq!(severity_for_pct(50.0), None);
        assert_eq!(severity_for_pct(79.99), None);
        assert_eq!(severity_for_pct(80.0), Some(Severity::Warn));
        assert_eq!(severity_for_pct(89.99), Some(Severity::Warn));
        assert_eq!(severity_for_pct(90.0), Some(Severity::High));
        assert_eq!(severity_for_pct(94.99), Some(Severity::High));
        assert_eq!(severity_for_pct(95.0), Some(Severity::Critical));
        assert_eq!(severity_for_pct(99.9), Some(Severity::Critical));
    }

    #[test]
    fn skip_unlimited_containers() {
        // memory_limit == 0 → no fact emitted (we check earlier in
        // `stat_to_fact`; the analyzer never sees these).
        let stat = crate::containers::ContainerStats {
            id: "x".into(), name: "free".into(),
            cpu_percent: 0.0, cpu_capacity_percent: 100.0, host_cpu_cores: 1,
            memory_usage: 999, memory_limit: 0,
            memory_percent: 100.0,
            memory_cache: 0, memory_anon: 999, memory_shmem: 0, memory_kernel: 0,
            net_input: 0, net_output: 0, block_read: 0, block_write: 0,
            pids: 1, runtime: "docker".into(),
        };
        assert!(stat_to_fact(&stat, Runtime::Docker).is_none());
    }

    #[test]
    fn analyzer_emits_for_high_memory() {
        let facts = vec![fact(Runtime::Docker, "leaky", 92.0)];
        let p = analyze(&ctx(), &facts, &AckStore::default(), &ProposalStore::default());
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].severity, Severity::High);
        assert_eq!(p[0].finding_type, FINDING_TYPE_DOCKER);
        assert!(p[0].title.contains("leaky"));
    }

    #[test]
    fn ack_against_docker_does_not_silence_lxc() {
        // Same name, different runtime → distinct findings.
        let facts = vec![
            fact(Runtime::Docker, "redis", 92.0),
            fact(Runtime::Lxc, "redis", 92.0),
        ];
        let mut acks = AckStore::default();
        acks.add(crate::predictive::ack::Ack::new(
            FINDING_TYPE_DOCKER,
            crate::predictive::ack::AckScope::Resource {
                node_id: "node-a".into(),
                resource_id: resource_id(Runtime::Docker, "redis"),
            },
            "expected memory headroom for cache warmup",
            "paul", None,
        ));
        let p = analyze(&ctx(), &facts, &acks, &ProposalStore::default());
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].finding_type, FINDING_TYPE_LXC);
    }

    #[test]
    fn analyzer_can_stay_quiet() {
        let facts = vec![fact(Runtime::Docker, "ok", 50.0)];
        let p = analyze(&ctx(), &facts, &AckStore::default(), &ProposalStore::default());
        assert!(p.is_empty());
    }
}
