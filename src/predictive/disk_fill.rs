// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Disk-fill prediction — the v1 analyzer.
//!
//! Watches disk-usage trend per mount, extrapolates linearly, and
//! emits a proposal when ETA to 95% (or 100% if already past 95%)
//! crosses a tier threshold. The first proactive ops finding
//! WolfStack ships, deliberately chosen because:
//!
//! - It's deterministic: arithmetic on `df` output. No machine
//!   learning, no false-positive risk from pattern-matching.
//! - It hits where operators actually feel the pain: the
//!   `/var/lib/docker` fills overnight scenario.
//! - The remediation is bounded and reversible (`docker system
//!   prune`, `journalctl --vacuum-time=…`) so v1 can ship as a
//!   `Manual` plan without needing a one-click handler stack.
//!
//! ## Severity tiers
//!
//! | ETA to 95% (or 100% if past) | Severity |
//! |------------------------------|----------|
//! | < 6 h                        | Critical |
//! | < 48 h                       | High     |
//! | < 7 d                        | Warn     |
//! | ≥ 7 d                        | suppress |
//!
//! Already at 95% but flat or shrinking → `Warn` (no ETA, but still
//! worth surfacing once). Already at 95% and still growing → severity
//! by ETA-to-100% as if we're starting over.
//!
//! ## Why these thresholds
//!
//! 6 h is roughly "before you go to bed and find the disk full at
//! 3 am". 48 h is "you'll see this on Monday morning even if you
//! went away for the weekend". 7 d is the ambient awareness tier —
//! still worth knowing about, doesn't need urgency.

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

/// Stable identifier for this finding type. Used as the dedup key in
/// the proposal store and as the lookup key in the ack store.
pub const FINDING_TYPE: &str = "disk_fill_eta";

/// Metric name we record into [`MetricsHistory`] for each mount.
pub const METRIC: &str = "disk_used_pct";

// All other tier/threshold constants live in `disk_verdict.rs` so
// host/Docker/LXC/VM analyzers reach the same answer for the same
// inputs.

/// One row from the system enumeration of mounted filesystems.
#[derive(Debug, Clone, PartialEq)]
pub struct DiskFact {
    pub mount: String,
    pub fstype: String,
    pub used_pct: f64,
    pub total_bytes: u64,
    pub avail_bytes: u64,
}

/// Async timeout-bounded variant. Used by the orchestrator. On
/// timeout the child process is killed (tokio::process drops kill
/// the child) and we return an empty Vec — analyzers will then
/// silently skip the tick rather than hang.
///
/// Pseudo / virtual filesystems are filtered out by `parse_df_output`:
/// `tmpfs`, `devtmpfs`, `proc`, `sysfs`, `cgroup*`, `overlay`,
/// `squashfs`, `fuse.snapfuse`, `tracefs`, `bpf`, `debugfs`,
/// `securityfs`, `pstore`, `mqueue`, `nsfs`, `ramfs`. Without this,
/// we'd see hundreds of mounts and analyze each.
pub async fn sample_disks_now_async(timeout: Duration) -> Vec<DiskFact> {
    let cmd = tokio::process::Command::new("df")
        .args(["-B1", "--output=target,fstype,size,used,avail,pcent"])
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(timeout, cmd).await {
        Ok(Ok(o)) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            parse_df_output(&text)
        }
        Ok(Ok(_)) | Ok(Err(_)) => Vec::new(),
        Err(_) => {
            tracing::warn!(
                "predictive: df timed out after {}s — \
                 skipping disk-fill analysis this tick (likely a \
                 stuck NFS mount)",
                timeout.as_secs(),
            );
            Vec::new()
        }
    }
}

fn parse_df_output(text: &str) -> Vec<DiskFact> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        // df with --output produces: target fstype size used avail pcent
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 { continue; }
        let mount = cols[0].to_string();
        let fstype = cols[1].to_string();
        if is_pseudo_fs(&fstype) { continue; }
        let total_bytes: u64 = cols[2].parse().unwrap_or(0);
        let _used_bytes: u64 = cols[3].parse().unwrap_or(0);
        let avail_bytes: u64 = cols[4].parse().unwrap_or(0);
        let used_pct: f64 = cols[5].trim_end_matches('%').parse().unwrap_or(0.0);
        if total_bytes == 0 { continue; }
        out.push(DiskFact { mount, fstype, used_pct, total_bytes, avail_bytes });
    }
    out
}

fn is_pseudo_fs(fstype: &str) -> bool {
    matches!(fstype,
        "tmpfs" | "devtmpfs" | "proc" | "sysfs" | "overlay" | "squashfs"
        | "tracefs" | "bpf" | "debugfs" | "securityfs" | "pstore"
        | "mqueue" | "nsfs" | "ramfs" | "autofs" | "binfmt_misc"
        | "configfs" | "fusectl" | "hugetlbfs" | "rpc_pipefs" | "selinuxfs"
        | "fuse.gvfsd-fuse" | "fuse.portal" | "fuse.snapfuse"
    ) || fstype.starts_with("cgroup")
}

/// Run the analyzer.
///
/// Returns a list of fresh `Proposal`s for the orchestrator to
/// upsert. Already-suppressed ones (acked, snoozed, dismissed) are
/// filtered here so the orchestrator's wire-up stays trivial.
pub fn analyze(
    ctx: &Context,
    history: &MetricsHistory,
    current: &[DiskFact],
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();

    for fact in current {
        if fact.used_pct < MIN_USED_PCT && !is_already_alarming(fact) {
            continue;
        }
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(fact.mount.clone()),
        };
        if acks.suppresses(FINDING_TYPE, &scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE, &scope) { continue; }

        let Some(samples) = history.samples(&fact.mount, METRIC) else { continue; };
        let Some(verdict) = compute_verdict(samples, fact.used_pct, FILL_TARGET_PCT) else { continue; };

        out.push(build_proposal(fact, &scope, &verdict));
    }
    out
}

/// "Already alarming" = already past 95%. We always re-emit for
/// these regardless of the MIN_USED_PCT gate.
fn is_already_alarming(fact: &DiskFact) -> bool {
    fact.used_pct >= FILL_TARGET_PCT
}

fn build_proposal(fact: &DiskFact, scope: &ProposalScope, v: &Verdict) -> Proposal {
    let title = match v.eta_hours {
        Some(h) if h < 1.0 => format!("{} fills within the hour", fact.mount),
        Some(h) if h < 24.0 => format!("{} fills in ~{:.0}h", fact.mount, h),
        Some(h) => format!("{} fills in ~{:.1}d", fact.mount, h / 24.0),
        None => format!("{} is at {:.0}% and not filling further", fact.mount, fact.used_pct),
    };

    let why = match v.eta_hours {
        Some(h) => format!(
            "Currently {:.0}% used, growing at {:.2}%/h — projected to hit \
             {:.0}% in ~{}. Based on {} samples spanning {} min.",
            fact.used_pct,
            v.slope_pct_per_hour,
            FILL_TARGET_PCT,
            humanise_hours(h),
            v.samples_used,
            v.span_minutes,
        ),
        None => format!(
            "Currently {:.0}% used and not growing over the last {} min \
             (slope {:.2}%/h). Already past {:.0}% — surface for awareness \
             even though there's no ETA.",
            fact.used_pct, v.span_minutes, v.slope_pct_per_hour, FILL_TARGET_PCT,
        ),
    };

    let evidence = vec![
        Evidence {
            label: "Current usage".into(),
            value: format!("{:.1}%", fact.used_pct),
            detail: Some(format!(
                "{:.1} GB free of {:.1} GB",
                fact.avail_bytes as f64 / 1_073_741_824.0,
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
        FINDING_TYPE,
        v.severity,
        title,
        why,
        evidence,
        remediation,
        scope.clone(),
    )
}

/// Remediation hint based on which mount is filling. Conservative —
/// when in doubt, suggest investigation rather than a destructive
/// command. Every command listed must be safe-by-default (dry-run
/// where possible, or bounded retention).
fn build_remediation(fact: &DiskFact) -> RemediationPlan {
    let m = fact.mount.as_str();
    // Anchor docker-storage matching to the actual mount root —
    // `contains` would match `/data/var/lib/docker/foo` too, which
    // belongs to a totally different docker daemon and shouldn't
    // get the prune suggestion.
    if m == "/var/lib/docker" || m.starts_with("/var/lib/docker/") {
        RemediationPlan::Manual {
            instructions: "Docker keeps stopped containers, dangling images, \
                and unused volumes around indefinitely. A `system prune -a` \
                with `--volumes` reclaims most of the space. Review what \
                will be removed first if any of those volumes are not \
                yet backed up.".into(),
            commands: vec![
                "docker system df".into(),
                "docker system prune -a --volumes".into(),
            ],
        }
    } else if m == "/var/log" || m.starts_with("/var/log/") {
        RemediationPlan::Manual {
            instructions: "Log retention may be longer than necessary. \
                Vacuum the journal to a bounded window and check for \
                runaway log files outside the journal.".into(),
            commands: vec![
                "journalctl --disk-usage".into(),
                "sudo journalctl --vacuum-time=7d".into(),
                format!("sudo du -h --max-depth=1 {} | sort -h", m),
            ],
        }
    } else if m == "/var/lib/lxc" || m.starts_with("/var/lib/lxc/")
        || m == "/var/lib/vz" || m.starts_with("/var/lib/vz/")
    {
        RemediationPlan::Manual {
            instructions: "Container/VM image storage. Identify the largest \
                consumers and consider archiving or removing dormant \
                images.".into(),
            commands: vec![
                format!("sudo du -h --max-depth=2 {} | sort -h | tail -20", m),
            ],
        }
    } else if m == "/var/lib/wolfstack" || m.starts_with("/var/lib/wolfstack/")
        || m == "/etc/wolfstack" || m.starts_with("/etc/wolfstack/")
    {
        RemediationPlan::Manual {
            instructions: "WolfStack-managed data. Check the Backups page for \
                old backup artefacts and the Status Pages page for stale \
                uptime history.".into(),
            commands: vec![
                format!("sudo du -h --max-depth=2 {} | sort -h | tail -20", m),
            ],
        }
    } else {
        RemediationPlan::Manual {
            instructions: "Investigate the largest directories on this mount \
                and remove or archive accordingly.".into(),
            commands: vec![
                format!("sudo du -h --max-depth=1 {} 2>/dev/null | sort -h | tail -20", m),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    use crate::predictive::Context;
    use crate::predictive::NetworkSnapshot;
    use crate::predictive::proposal::{ProposalStore, Severity};
    use crate::predictive::disk_verdict::{CRITICAL_HOURS, HIGH_HOURS};

    fn ctx() -> Context {
        Context {
            node_id: "node-a".into(),
            network: NetworkSnapshot::from_parts(vec![], vec![]),
        }
    }

    fn fact(mount: &str, used_pct: f64) -> DiskFact {
        DiskFact {
            mount: mount.into(),
            fstype: "ext4".into(),
            used_pct,
            total_bytes: 100 * 1_073_741_824,
            avail_bytes: ((100.0 - used_pct) / 100.0 * 100.0 * 1_073_741_824.0) as u64,
        }
    }

    /// Seed a history with N samples at `cadence_min` apart, growing
    /// `pct_per_hour` per hour.
    fn seed_growth(
        history: &mut MetricsHistory,
        mount: &str,
        n: usize,
        cadence_min: i64,
        start_pct: f64,
        pct_per_hour: f64,
    ) {
        let now = Utc::now();
        let total_min = (n as i64 - 1) * cadence_min;
        for i in 0..n {
            let ts = now - Duration::minutes(total_min - i as i64 * cadence_min);
            let elapsed_h = (i as i64 * cadence_min) as f64 / 60.0;
            let value = start_pct + pct_per_hour * elapsed_h;
            history.record_at(mount, METRIC, value, ts);
        }
    }

    // ── Sampling / df parsing ─────────────────────────────────────

    #[test]
    fn parse_df_skips_pseudo_fs() {
        let df = "Mounted on   Type     1B-blocks      Used     Avail Use%
/            ext4     50000000  20000000  30000000  40%
/proc        proc            0         0         0   0%
/sys         sysfs           0         0         0   0%
/dev/shm     tmpfs    16000000         0  16000000   0%
/snap/foo    squashfs   500000    500000         0 100%
/var/lib/docker overlay  100000   50000   50000  50%
/data        ext4     1000000   800000   200000  80%";
        let facts = parse_df_output(df);
        let mounts: Vec<&str> = facts.iter().map(|f| f.mount.as_str()).collect();
        assert_eq!(mounts, vec!["/", "/data"]);
    }

    #[test]
    fn parse_df_extracts_used_pct() {
        let df = "Mounted on   Type   1B-blocks   Used    Avail   Use%
/data        ext4   1000000     800000  200000  80%";
        let facts = parse_df_output(df);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].used_pct, 80.0);
        assert_eq!(facts[0].total_bytes, 1_000_000);
        assert_eq!(facts[0].avail_bytes, 200_000);
    }

    // Severity-tier mapping is owned by `disk_verdict.rs` and tested
    // there — disk-fill just consumes the verdict.

    // ── Compute verdict ──────────────────────────────────────────

    #[test]
    fn no_verdict_with_too_few_samples() {
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "/data", 2, 30, 70.0, 1.0);
        let f = fact("/data", 71.0);
        let samples = h.samples("/data", METRIC).unwrap();
        assert!(compute_verdict(samples, f.used_pct, FILL_TARGET_PCT).is_none());
    }

    #[test]
    fn no_verdict_with_too_short_span() {
        let mut h = MetricsHistory::default();
        // 5 samples but only 5 min apart = 20 min span < 30 min min.
        seed_growth(&mut h, "/data", 5, 5, 70.0, 1.0);
        let f = fact("/data", 70.4);
        let samples = h.samples("/data", METRIC).unwrap();
        assert!(compute_verdict(samples, f.used_pct, FILL_TARGET_PCT).is_none());
    }

    #[test]
    fn shrinking_below_target_produces_no_verdict() {
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "/data", 6, 10, 70.0, -0.5);
        let f = fact("/data", 65.0);
        let samples = h.samples("/data", METRIC).unwrap();
        assert!(compute_verdict(samples, f.used_pct, FILL_TARGET_PCT).is_none());
    }

    #[test]
    fn fast_growth_yields_critical() {
        // 70% now, growing 4%/h → ETA to 95% = 25/4 = 6.25h → High
        // bump to 5%/h → 5h → Critical
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "/data", 8, 10, 65.0, 5.0);
        let f = fact("/data", 70.0);
        let samples = h.samples("/data", METRIC).unwrap();
        let v = compute_verdict(samples, f.used_pct, FILL_TARGET_PCT).expect("verdict");
        assert_eq!(v.severity, Severity::Critical);
        assert!(v.eta_hours.unwrap() < CRITICAL_HOURS);
    }

    #[test]
    fn slow_growth_below_target_yields_warn() {
        // 70%, +0.5%/h → ETA 50h → Warn
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "/data", 8, 10, 69.0, 0.5);
        let f = fact("/data", 70.0);
        let samples = h.samples("/data", METRIC).unwrap();
        let v = compute_verdict(samples, f.used_pct, FILL_TARGET_PCT).expect("verdict");
        assert_eq!(v.severity, Severity::Warn);
    }

    #[test]
    fn growth_beyond_horizon_is_suppressed() {
        // +0.05%/h → 25/0.05 = 500h ≫ 168h horizon → None
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "/data", 8, 10, 70.0, 0.05);
        let f = fact("/data", 70.0);
        let samples = h.samples("/data", METRIC).unwrap();
        assert!(compute_verdict(samples, f.used_pct, FILL_TARGET_PCT).is_none());
    }

    #[test]
    fn already_full_and_flat_yields_warn() {
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "/data", 8, 10, 96.0, 0.0);
        let f = fact("/data", 96.0);
        let samples = h.samples("/data", METRIC).unwrap();
        let v = compute_verdict(samples, f.used_pct, FILL_TARGET_PCT).expect("verdict");
        assert_eq!(v.severity, Severity::Warn);
        assert!(v.eta_hours.is_none());
    }

    #[test]
    fn already_full_and_growing_yields_eta_severity() {
        // 96% used, +0.5%/h → ETA to 100% = 8h → High
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "/data", 8, 10, 95.5, 0.5);
        let f = fact("/data", 96.0);
        let samples = h.samples("/data", METRIC).unwrap();
        let v = compute_verdict(samples, f.used_pct, FILL_TARGET_PCT).expect("verdict");
        assert_eq!(v.severity, Severity::High);
        assert!(v.eta_hours.unwrap() < HIGH_HOURS);
    }

    // ── Full analyze() path ──────────────────────────────────────

    /// Reviewer-flagged BLOCKER (now fix-verified): `contains` would
    /// have matched `/data/var/lib/docker/foo` (a totally different
    /// docker daemon's storage on a side-mount). The fix requires
    /// the matcher to anchor at the mount root.
    #[test]
    fn docker_remediation_is_anchored_at_mount_root() {
        let docker_root = build_remediation(&fact("/var/lib/docker", 80.0));
        match &docker_root {
            RemediationPlan::Manual { commands, .. } =>
                assert!(commands.iter().any(|c| c.contains("system prune")),
                    "exact /var/lib/docker mount must get docker hint"),
            _ => panic!("expected Manual"),
        }

        let docker_subdir = build_remediation(&fact("/var/lib/docker/overlay2", 80.0));
        match &docker_subdir {
            RemediationPlan::Manual { commands, .. } =>
                assert!(commands.iter().any(|c| c.contains("system prune")),
                    "subdirs of /var/lib/docker still get the docker hint"),
            _ => panic!("expected Manual"),
        }

        let unrelated = build_remediation(&fact("/data/var/lib/docker-evidence", 80.0));
        match &unrelated {
            RemediationPlan::Manual { commands, .. } =>
                assert!(commands.iter().all(|c| !c.contains("system prune")),
                    "mounts that merely contain the substring must NOT \
                     get the docker hint"),
            _ => panic!("expected Manual"),
        }
    }

    #[test]
    fn analyze_skips_low_used_disks() {
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "/data", 8, 10, 30.0, 5.0);  // even fast growth
        let facts = vec![fact("/data", 35.0)];
        let acks = AckStore::default();
        let store = ProposalStore::default();
        let proposals = analyze(&ctx(), &h, &facts, &acks, &store);
        assert!(proposals.is_empty(),
            "disks below MIN_USED_PCT shouldn't fire even with steep growth");
    }

    #[test]
    fn analyze_emits_for_growing_disk() {
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "/var/lib/docker", 8, 10, 75.0, 2.0);
        let facts = vec![fact("/var/lib/docker", 76.0)];
        let acks = AckStore::default();
        let store = ProposalStore::default();
        let proposals = analyze(&ctx(), &h, &facts, &acks, &store);
        assert_eq!(proposals.len(), 1);
        let p = &proposals[0];
        assert_eq!(p.finding_type, FINDING_TYPE);
        assert_eq!(p.scope.resource_id.as_deref(), Some("/var/lib/docker"));
        // Docker remediation hint should mention `docker system prune`.
        match &p.remediation {
            RemediationPlan::Manual { commands, .. } => {
                assert!(commands.iter().any(|c| c.contains("system prune")));
            }
            other => panic!("expected Manual remediation, got {:?}", other),
        }
    }

    #[test]
    fn analyze_respects_ack_for_resource() {
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "/data", 8, 10, 75.0, 2.0);
        let facts = vec![fact("/data", 76.0)];
        let mut acks = AckStore::default();
        acks.add(crate::predictive::ack::Ack::new(
            FINDING_TYPE,
            crate::predictive::ack::AckScope::Resource {
                node_id: "node-a".into(),
                resource_id: "/data".into(),
            },
            "/data is intentionally near-full — archive job tracks it",
            "paul",
            None,
        ));

        let store = ProposalStore::default();
        let proposals = analyze(&ctx(), &h, &facts, &acks, &store);
        assert!(proposals.is_empty(),
            "resource-scoped ack must suppress this finding");
    }

    #[test]
    fn analyze_respects_dismissed_proposal() {
        let mut h = MetricsHistory::default();
        seed_growth(&mut h, "/data", 8, 10, 75.0, 2.0);
        let facts = vec![fact("/data", 76.0)];
        let acks = AckStore::default();
        let mut store = ProposalStore::default();

        // Pre-existing dismissed proposal for the same scope.
        store.upsert(Proposal::new_rule(
            FINDING_TYPE, Severity::Warn,
            "old", "old", vec![],
            RemediationPlan::Manual { instructions: "x".into(), commands: vec![] },
            ProposalScope { node_id: "node-a".into(), resource_id: Some("/data".into()) },
        ));
        let id = store.proposals[0].id.clone();
        store.dismiss(&id, "false positive").unwrap();

        let proposals = analyze(&ctx(), &h, &facts, &acks, &store);
        assert!(proposals.is_empty(),
            "dismissed proposal must keep analyzer quiet");
    }

    /// Suppression-discipline guard: at least one cell of the
    /// reachability/severity space produces NO finding. The plan
    /// rule is "every analyzer ships with a unit test asserting at
    /// least one class is suppressed". For disk-fill the equivalent
    /// is showing that the right combination of inputs (low usage,
    /// flat trend, far-out ETA, ack, prior dismiss) results in zero
    /// proposals — proving the analyzer can stay quiet.
    #[test]
    fn analyzer_can_stay_quiet() {
        let mut h = MetricsHistory::default();
        // Below threshold, slowly growing — should be silent.
        seed_growth(&mut h, "/data", 8, 10, 30.0, 0.1);
        let facts = vec![fact("/data", 35.0)];
        let proposals = analyze(
            &ctx(), &h, &facts,
            &AckStore::default(),
            &ProposalStore::default(),
        );
        assert!(proposals.is_empty());
    }

    /// Suppress unused-import noise on chrono in tests when the
    /// trait paths aren't otherwise referenced from the test mod.
    #[allow(dead_code)] fn _hashmap_keep_alive() -> HashMap<String, ()> { HashMap::new() }
}
