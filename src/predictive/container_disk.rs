// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Per-container disk-fill prediction (Docker + LXC).
//!
//! ## What this analyzer covers
//!
//! For each running Docker or LXC container on this node:
//! 1. Read its currently-reported `disk_usage` / `disk_total` from
//!    [`crate::containers`] (which derives them from a `df` against
//!    the container's storage path / rootfs).
//! 2. Sample the resulting used-percentage into [`MetricsHistory`].
//! 3. Run the same linear-fit verdict as host disk-fill via
//!    [`crate::predictive::disk_verdict::compute_verdict`].
//! 4. Emit a runtime-specific finding type (`docker_storage_fill_eta`
//!    or `lxc_storage_fill_eta`) so operator acks can be scoped per
//!    runtime — "ack all docker fills" should not also silence LXC.
//!
//! ## Where this overlaps host disk-fill, and why that's deliberate
//!
//! When a Docker daemon's `/var/lib/docker` is on a shared filesystem
//! that's also mounted at `/var` on the host, both the host and the
//! per-container view will report similar percentages and both
//! analyzers may fire. That's intentional — the host finding tells
//! the operator *the filesystem is filling*, the per-container
//! finding tells them *which container is on it*. Different question,
//! different answer; the Inbox can carry both.
//!
//! For ZFS / BTRFS subvol / dedicated-mount setups, the per-container
//! and per-host views diverge meaningfully and only the relevant one
//! fires.
//!
//! ## What this analyzer does NOT cover (yet — see plan)
//!
//! - Per-volume usage attribution. `docker volume inspect` + `du -sb`
//!   per volume would let us blame a specific named volume; deferred
//!   because of the cost of `du` on multi-GB volumes and the lack of
//!   a fixed cap to predict against.
//! - Per-container layer (writable overlay) attribution via
//!   `docker ps -s SizeRw`. Cheap to add when needed.
//! - Cross-node aggregation. Each node's orchestrator runs this
//!   locally; cluster aggregation is the next plan item (#2).

use std::time::Duration;

use crate::predictive::{
    Context,
    metrics::MetricsHistory,
    proposal::{
        Evidence, Proposal, ProposalScope, RemediationPlan,
    },
    ack::AckStore,
    disk_verdict::{
        compute_verdict, humanise_hours, FILL_TARGET_PCT, MIN_USED_PCT, Verdict,
    },
};

/// Per-container disk fact, normalised across runtimes.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerDiskFact {
    pub runtime: Runtime,
    /// Container name (stable identifier — survives ID rotation,
    /// which would happen on `docker rm` + `docker run` of the same
    /// service).
    pub name: String,
    /// Container ID — captured for change detection. If a container
    /// is destroyed and recreated under the same name, the ID
    /// rotates and the analyzer must reset history (otherwise it'd
    /// fit a line through samples from two different containers).
    pub id: String,
    pub image: String,
    pub used_pct: f64,
    pub total_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime { Docker, Lxc }

impl Runtime {
    pub fn finding_type(self) -> &'static str {
        match self {
            Runtime::Docker => "docker_storage_fill_eta",
            Runtime::Lxc    => "lxc_storage_fill_eta",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Runtime::Docker => "docker",
            Runtime::Lxc    => "lxc",
        }
    }
}

/// Metric name used in [`MetricsHistory`]. Same key as host disk-fill
/// because the *meaning* is the same (used %); resource_id keeps
/// per-container series separate.
pub const METRIC: &str = "disk_used_pct";

/// Sampler — pulls already-cached container info from
/// [`crate::containers`]. Synchronous because the cache fronts the
/// expensive Docker-socket / lxc-info calls; cache TTL is 30 s which
/// is comfortably fresh for our 5-min tick cadence.
pub fn sample_containers_now() -> Vec<ContainerDiskFact> {
    let mut out = Vec::new();

    if crate::containers::has_docker_cached() {
        for c in crate::containers::docker_list_all_cached() {
            if let Some(fact) = container_to_fact(&c, Runtime::Docker) {
                out.push(fact);
            }
        }
    }

    if crate::containers::has_lxc_cached() {
        for c in crate::containers::lxc_list_all_cached() {
            if let Some(fact) = container_to_fact(&c, Runtime::Lxc) {
                out.push(fact);
            }
        }
    }

    out
}

/// Async timeout-bounded variant. Like
/// [`crate::predictive::disk_fill::sample_disks_now_async`] but for
/// containers. Wrapped in `spawn_blocking` because the underlying
/// cache lookups can fall through to subprocess calls; cap the whole
/// fan-out at `timeout`.
pub async fn sample_containers_now_async(timeout: Duration) -> Vec<ContainerDiskFact> {
    let fut = tokio::task::spawn_blocking(sample_containers_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(facts)) => facts,
        Ok(Err(e)) => {
            tracing::warn!("predictive: container sampling task panicked: {}", e);
            Vec::new()
        }
        Err(_) => {
            tracing::warn!(
                "predictive: container sampling timed out after {}s — \
                 skipping container disk analysis this tick",
                timeout.as_secs(),
            );
            Vec::new()
        }
    }
}

/// Convert a [`crate::containers::ContainerInfo`] into a
/// [`ContainerDiskFact`] if the container is in a state we should
/// analyze and has the disk fields populated. Returns `None` when:
/// - The container is not running (stopped/paused — disk usage is
///   frozen and any "trend" would be illusory).
/// - `disk_usage` or `disk_total` is missing (df couldn't read the
///   storage path, or the container has no storage path).
/// - `disk_total` is zero (avoid division-by-zero).
fn container_to_fact(
    c: &crate::containers::ContainerInfo,
    runtime: Runtime,
) -> Option<ContainerDiskFact> {
    if !is_running_state(&c.state) { return None; }
    let used = c.disk_usage?;
    let total = c.disk_total?;
    if total == 0 { return None; }
    let used_pct = (used as f64 / total as f64) * 100.0;
    Some(ContainerDiskFact {
        runtime,
        name: c.name.clone(),
        id: c.id.clone(),
        image: c.image.clone(),
        used_pct,
        total_bytes: total,
        used_bytes: used,
    })
}

fn is_running_state(state: &str) -> bool {
    let s = state.to_ascii_lowercase();
    s == "running" || s == "started"
}

/// Build the resource_id that goes into `ProposalScope.resource_id`.
/// Uses the container *name* so it survives `docker rm` + recreation
/// of the same service. The history-reset-on-id-change guard is
/// applied separately (`maybe_reset_history`) before recording.
pub fn resource_id(runtime: Runtime, name: &str) -> String {
    format!("{}:{}", runtime.label(), name)
}

/// Detect container ID rotation and clear the affected history when
/// it happens. Without this, samples from "old postgres container"
/// and "new postgres container" would be fit as a single line — the
/// kind of false positive that erodes trust.
///
/// Strategy: store the most recent sampled ID in a sidecar metric
/// (`__container_id`) per resource. If it doesn't match the current
/// ID, drop both the id sentinel and the disk_used_pct series.
pub fn maybe_reset_history(history: &mut MetricsHistory, fact: &ContainerDiskFact) {
    let resource = resource_id(fact.runtime, &fact.name);
    let current_hash = fact_id_hash(&fact.id);
    // Compare numerically — the sentinel was written as `u32 as f64`
    // and u32 fits in f64 with no precision loss, so the round-trip
    // is exact. Earlier code did this by comparing `to_string()`
    // results; same result, less obscure.
    let needs_reset = history
        .samples(&resource, ID_SENTINEL_METRIC)
        .and_then(|s| s.back())
        .map(|s| (s.value as u32) != current_hash)
        .unwrap_or(false);
    if needs_reset
        && let Some(per_resource) = history.by_resource.get_mut(&resource) {
            per_resource.clear();
        }
    // Always (re)write the id sentinel so the next tick's check is
    // valid even on the first encounter.
    history.record(&resource, ID_SENTINEL_METRIC, current_hash as f64);
}

const ID_SENTINEL_METRIC: &str = "__container_id_hash";

/// Stable u32 hash of the container ID, encoded as f64 for storage
/// in [`MetricsHistory`] (which only carries floats). Collisions in
/// 32 bits among containers on a single node are vanishingly rare;
/// the worst case is an unnecessary history-reset, which is fine.
///
/// **Deterministic across process restarts.** The earlier version of
/// this used `std::collections::hash_map::DefaultHasher`, which is
/// HashDoS-randomised per-process — so a server restart would see a
/// different hash for the same container ID and wipe all history on
/// every boot. FNV-1a is a fixed seed, so a restart preserves the
/// sentinel match. Collision rate at 32 bits over the typical fleet
/// of <100 containers per node is comfortably <1e-7.
fn fact_id_hash(id: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5; // FNV-1a 32-bit offset basis
    for byte in id.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193); // FNV prime
    }
    hash
}

/// Run the analyzer.
///
/// Same shape as `disk_fill::analyze` — returns fresh [`Proposal`]s
/// for the orchestrator to upsert. Suppression by ack / snooze /
/// dismiss is checked here.
pub fn analyze(
    ctx: &Context,
    history: &MetricsHistory,
    current: &[ContainerDiskFact],
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();

    for fact in current {
        let already_alarming = fact.used_pct >= FILL_TARGET_PCT;
        if fact.used_pct < MIN_USED_PCT && !already_alarming {
            continue;
        }

        let resource = resource_id(fact.runtime, &fact.name);
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(resource.clone()),
        };
        let finding_type = fact.runtime.finding_type();

        if acks.suppresses(finding_type, &scope) { continue; }
        if proposals.is_suppressed(finding_type, &scope) { continue; }

        let Some(samples) = history.samples(&resource, METRIC) else { continue; };
        let Some(verdict) = compute_verdict(samples, fact.used_pct, FILL_TARGET_PCT) else { continue; };

        out.push(build_proposal(fact, &scope, &verdict));
    }
    out
}

fn build_proposal(fact: &ContainerDiskFact, scope: &ProposalScope, v: &Verdict) -> Proposal {
    let runtime_label = fact.runtime.label();
    let title = match v.eta_hours {
        Some(h) if h < 1.0 => format!(
            "{} container '{}' storage fills within the hour",
            runtime_label, fact.name,
        ),
        Some(h) if h < 24.0 => format!(
            "{} container '{}' storage fills in ~{:.0}h",
            runtime_label, fact.name, h,
        ),
        Some(h) => format!(
            "{} container '{}' storage fills in ~{:.1}d",
            runtime_label, fact.name, h / 24.0,
        ),
        None => format!(
            "{} container '{}' storage at {:.0}% and not filling further",
            runtime_label, fact.name, fact.used_pct,
        ),
    };

    let why = match v.eta_hours {
        Some(h) => format!(
            "{} container '{}' (image '{}') storage is currently {:.0}% used \
             and growing at {:.2}%/h — projected to hit {:.0}% in ~{}. \
             Based on {} samples spanning {} min.",
            runtime_label, fact.name, fact.image,
            fact.used_pct, v.slope_pct_per_hour, FILL_TARGET_PCT,
            humanise_hours(h),
            v.samples_used, v.span_minutes,
        ),
        None => format!(
            "{} container '{}' (image '{}') storage is at {:.0}% — \
             past {:.0}% but not growing further over the last {} min \
             (slope {:.2}%/h).",
            runtime_label, fact.name, fact.image,
            fact.used_pct, FILL_TARGET_PCT, v.span_minutes, v.slope_pct_per_hour,
        ),
    };

    let evidence = vec![
        Evidence {
            label: "Container".into(),
            value: fact.name.clone(),
            detail: Some(format!("{} · {}", runtime_label, fact.image)),
            links: Vec::new(),
        },
        Evidence {
            label: "Current usage".into(),
            value: format!("{:.1}%", fact.used_pct),
            detail: Some(format!(
                "{:.1} GB used of {:.1} GB",
                fact.used_bytes as f64 / 1_073_741_824.0,
                fact.total_bytes as f64 / 1_073_741_824.0,
            )),
            links: Vec::new(),
        },
        Evidence {
            label: "Growth rate".into(),
            value: format!("{:+.2} %/h", v.slope_pct_per_hour),
            detail: Some(format!(
                "Linear fit over {} samples spanning {} min",
                v.samples_used, v.span_minutes,
            )),
            links: Vec::new(),
        },
    ];

    let remediation = build_remediation(fact);

    Proposal::new_rule(
        fact.runtime.finding_type(),
        v.severity,
        title,
        why,
        evidence,
        remediation,
        scope.clone(),
    )
}

/// Remediation hints — runtime-specific. Conservative — every
/// suggestion is bounded and reversible. No automatic deletes.
fn build_remediation(fact: &ContainerDiskFact) -> RemediationPlan {
    match fact.runtime {
        Runtime::Docker => RemediationPlan::Manual {
            instructions: format!(
                "Inspect what's filling container '{name}'. The mutable \
                 layer (writes inside the container) and any unbound \
                 volume mount are the usual culprits. Truncating runaway \
                 logs is often the cheapest first step. Volumes that hold \
                 real data should be checked before any prune.",
                name = fact.name,
            ),
            commands: vec![
                format!("docker logs --tail 50 {} 2>&1 | tail", fact.name),
                format!("docker exec {} sh -c 'du -h --max-depth=1 / 2>/dev/null | sort -h | tail -10'", fact.name),
                format!("docker inspect --format '{{{{json .Mounts}}}}' {} | python3 -m json.tool", fact.name),
                "docker system df".into(),
            ],
        },
        Runtime::Lxc => RemediationPlan::Manual {
            instructions: format!(
                "Inspect what's filling LXC container '{name}'. Common \
                 culprits: /var/log inside the container, unbounded \
                 application caches, or a wedged service writing into \
                 /tmp.",
                name = fact.name,
            ),
            commands: vec![
                format!("sudo lxc-attach -n {} -- du -h --max-depth=1 /var 2>/dev/null | sort -h | tail -10", fact.name),
                format!("sudo lxc-attach -n {} -- journalctl --disk-usage", fact.name),
                format!("sudo lxc-attach -n {} -- df -h", fact.name),
            ],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use crate::predictive::NetworkSnapshot;
    use crate::predictive::proposal::{ProposalStore, Severity};

    fn ctx() -> Context {
        Context {
            node_id: "node-a".into(),
            network: NetworkSnapshot::from_parts(vec![], vec![]),
        }
    }

    fn fact(rt: Runtime, name: &str, id: &str, used_pct: f64) -> ContainerDiskFact {
        let total = 100u64 * 1_073_741_824;
        ContainerDiskFact {
            runtime: rt,
            name: name.into(),
            id: id.into(),
            image: "test/image:latest".into(),
            used_pct,
            total_bytes: total,
            used_bytes: ((used_pct / 100.0) * total as f64) as u64,
        }
    }

    fn seed_growth(
        history: &mut MetricsHistory,
        resource: &str,
        n: usize,
        cadence_min: i64,
        start_pct: f64,
        pct_per_hour: f64,
    ) {
        let now = Utc::now();
        let total_min = (n as i64 - 1) * cadence_min;
        for i in 0..n {
            let ts = now - ChronoDuration::minutes(total_min - i as i64 * cadence_min);
            let elapsed_h = (i as i64 * cadence_min) as f64 / 60.0;
            let value = start_pct + pct_per_hour * elapsed_h;
            history.record_at(resource, METRIC, value, ts);
        }
    }

    /// FNV-1a is deterministic — same input must produce same
    /// output every call. Checks against known FNV-1a 32-bit values
    /// for two well-known strings so a regression in the
    /// implementation can't slip past unnoticed (the original
    /// `DefaultHasher` version of this would have failed this test
    /// trivially on a second process invocation).
    #[test]
    fn fact_id_hash_is_deterministic_fnv1a() {
        // Repeat-call determinism in the same process.
        assert_eq!(fact_id_hash("abc123"), fact_id_hash("abc123"));
        // Different inputs produce different hashes (pin to canonical
        // FNV-1a 32-bit reference values for "" and "a").
        assert_eq!(fact_id_hash(""), 0x811c_9dc5);
        assert_eq!(fact_id_hash("a"), 0xe40c_292c);
        // Container-ID-shaped inputs also hash distinctly.
        assert_ne!(fact_id_hash("abc123"), fact_id_hash("def456"));
    }

    #[test]
    fn finding_types_are_runtime_specific() {
        // Acks against `docker_storage_fill_eta` must not silence LXC,
        // and vice versa. This is the contract the rest of the code
        // depends on — pin it.
        assert_eq!(Runtime::Docker.finding_type(), "docker_storage_fill_eta");
        assert_eq!(Runtime::Lxc.finding_type(), "lxc_storage_fill_eta");
        assert_ne!(Runtime::Docker.finding_type(), Runtime::Lxc.finding_type());
    }

    #[test]
    fn resource_ids_distinguish_runtimes() {
        // A container called "postgres" running under Docker AND a
        // separate one under LXC must produce distinct resource_ids
        // so their histories don't blend.
        assert_eq!(resource_id(Runtime::Docker, "postgres"), "docker:postgres");
        assert_eq!(resource_id(Runtime::Lxc, "postgres"), "lxc:postgres");
    }

    #[test]
    fn skips_stopped_containers() {
        let info = crate::containers::ContainerInfo {
            id: "abc".into(), name: "c".into(), image: "i".into(),
            status: "Exited".into(), state: "stopped".into(),
            created: "".into(), ports: vec![], runtime: "docker".into(),
            ip_address: "".into(), autostart: false, hostname: "".into(),
            storage_path: None,
            disk_usage: Some(50_000_000), disk_total: Some(100_000_000),
            fs_type: None, version: None, services: vec![],
            gateway: "".into(), mac_address: "".into(), network_name: "".into(), restart_count: None,
            port_mappings: Vec::new(),
            possible_ghost: false,
            ha_replica: false,
        };
        assert!(container_to_fact(&info, Runtime::Docker).is_none(),
            "stopped containers must not be analyzed — disk usage is frozen");
    }

    #[test]
    fn skips_containers_without_disk_total() {
        let info = crate::containers::ContainerInfo {
            id: "abc".into(), name: "c".into(), image: "i".into(),
            status: "Up".into(), state: "running".into(),
            created: "".into(), ports: vec![], runtime: "docker".into(),
            ip_address: "".into(), autostart: false, hostname: "".into(),
            storage_path: Some("/var/lib/docker".into()),
            disk_usage: Some(50), disk_total: None,
            fs_type: None, version: None, services: vec![],
            gateway: "".into(), mac_address: "".into(), network_name: "".into(), restart_count: None,
            port_mappings: Vec::new(),
            possible_ghost: false,
            ha_replica: false,
        };
        assert!(container_to_fact(&info, Runtime::Docker).is_none());
    }

    #[test]
    fn skips_zero_total_avoids_division_by_zero() {
        let info = crate::containers::ContainerInfo {
            id: "abc".into(), name: "c".into(), image: "i".into(),
            status: "Up".into(), state: "running".into(),
            created: "".into(), ports: vec![], runtime: "docker".into(),
            ip_address: "".into(), autostart: false, hostname: "".into(),
            storage_path: Some("/var/lib/docker".into()),
            disk_usage: Some(50), disk_total: Some(0),
            fs_type: None, version: None, services: vec![],
            gateway: "".into(), mac_address: "".into(), network_name: "".into(), restart_count: None,
            port_mappings: Vec::new(),
            possible_ghost: false,
            ha_replica: false,
        };
        assert!(container_to_fact(&info, Runtime::Docker).is_none());
    }

    #[test]
    fn analyze_skips_low_used_containers() {
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "docker:postgres", 8, 10, 30.0, 5.0);
        let facts = vec![fact(Runtime::Docker, "postgres", "abc", 35.0)];
        let proposals = analyze(
            &ctx(), &h, &facts,
            &AckStore::default(),
            &ProposalStore::default(),
        );
        assert!(proposals.is_empty(),
            "containers below MIN_USED_PCT shouldn't fire even with steep growth");
    }

    #[test]
    fn analyze_emits_for_growing_docker_container() {
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "docker:postgres", 8, 10, 75.0, 2.0);
        let facts = vec![fact(Runtime::Docker, "postgres", "abc", 76.0)];
        let proposals = analyze(
            &ctx(), &h, &facts,
            &AckStore::default(),
            &ProposalStore::default(),
        );
        assert_eq!(proposals.len(), 1);
        let p = &proposals[0];
        assert_eq!(p.finding_type, "docker_storage_fill_eta");
        assert_eq!(p.scope.resource_id.as_deref(), Some("docker:postgres"));
        assert!(p.title.contains("postgres"));
        match &p.remediation {
            RemediationPlan::Manual { commands, .. } =>
                assert!(commands.iter().any(|c| c.starts_with("docker"))),
            _ => panic!("expected Manual"),
        }
    }

    #[test]
    fn analyze_emits_for_growing_lxc_container() {
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "lxc:web", 8, 10, 75.0, 2.0);
        let facts = vec![fact(Runtime::Lxc, "web", "ct101", 76.0)];
        let proposals = analyze(
            &ctx(), &h, &facts,
            &AckStore::default(),
            &ProposalStore::default(),
        );
        assert_eq!(proposals.len(), 1);
        let p = &proposals[0];
        assert_eq!(p.finding_type, "lxc_storage_fill_eta");
        match &p.remediation {
            RemediationPlan::Manual { commands, .. } =>
                assert!(commands.iter().any(|c| c.contains("lxc-attach"))),
            _ => panic!("expected Manual"),
        }
    }

    #[test]
    fn ack_against_docker_does_not_silence_lxc() {
        // The exact contract from `finding_types_are_runtime_specific`
        // — verify it actually behaves at the ack-suppression level.
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "docker:postgres", 8, 10, 75.0, 2.0);
        seed_growth(&mut h, "lxc:postgres", 8, 10, 75.0, 2.0);
        let facts = vec![
            fact(Runtime::Docker, "postgres", "abc", 76.0),
            fact(Runtime::Lxc, "postgres", "ct101", 76.0),
        ];
        let mut acks = AckStore::default();
        // Ack the docker one only.
        acks.add(crate::predictive::ack::Ack::new(
            "docker_storage_fill_eta",
            crate::predictive::ack::AckScope::Resource {
                node_id: "node-a".into(),
                resource_id: "docker:postgres".into(),
            },
            "intentional cache, separate cron clears it",
            "paul", None,
        ));

        let proposals = analyze(&ctx(), &h, &facts, &acks, &ProposalStore::default());
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].finding_type, "lxc_storage_fill_eta",
            "LXC finding must still fire even though docker is acked");
    }

    #[test]
    fn history_resets_on_container_id_rotation() {
        // Container "postgres" recreated under same name → new ID.
        // Old samples must be discarded before the next sample is
        // recorded, otherwise the slope is fit through samples from
        // two different containers.
        let mut h = MetricsHistory::default();
        let f1 = fact(Runtime::Docker, "postgres", "id-A", 80.0);
        // Seed history under the old ID's expected resource id.
        seed_growth(&mut h, &resource_id(Runtime::Docker, "postgres"), 8, 10, 75.0, 2.0);
        // First call records the id sentinel — but doesn't clear
        // history because there's no prior sentinel to mismatch.
        maybe_reset_history(&mut h, &f1);
        let len_after_first = h.samples("docker:postgres", METRIC).map(|s| s.len()).unwrap_or(0);
        assert!(len_after_first >= 8, "first call must NOT clear history (no prior id known)");

        // Second container: same name, different id.
        let f2 = fact(Runtime::Docker, "postgres", "id-B", 30.0);
        maybe_reset_history(&mut h, &f2);
        let len_after_reset = h.samples("docker:postgres", METRIC).map(|s| s.len()).unwrap_or(0);
        assert_eq!(len_after_reset, 0,
            "id rotation must clear history so we don't fit a line \
             through two different containers' samples");
    }

    /// Discipline rule: the analyzer can stay quiet when nothing
    /// interesting is happening. Mirrors the host-disk-fill test of
    /// the same name.
    #[test]
    fn analyzer_can_stay_quiet() {
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "docker:postgres", 8, 10, 30.0, 0.1);
        let facts = vec![fact(Runtime::Docker, "postgres", "abc", 35.0)];
        let proposals = analyze(
            &ctx(), &h, &facts,
            &AckStore::default(),
            &ProposalStore::default(),
        );
        assert!(proposals.is_empty());
        let _ = Severity::Info; // keep import grounded
    }
}
