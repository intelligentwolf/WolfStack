// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Backup freshness — Item 6 of the predictive plan.
//!
//! For every enabled `BackupSchedule` in `backup/mod.rs`, check
//! whether `last_run` is within the expected interval. If it isn't,
//! emit a finding so the operator knows their backup pipeline has
//! drifted before the next disaster makes it obvious.
//!
//! ## Severity tiers
//!
//! | Missed by                  | Severity   |
//! |----------------------------|------------|
//! | ≥ 7× interval              | `Critical` |
//! | ≥ 4× interval              | `High`     |
//! | ≥ 2× interval              | `Warn`     |
//! | < 2× interval              | suppressed |
//!
//! Examples:
//! - Daily schedule, last_run 30h ago → 1.25× interval → no finding
//! - Daily schedule, last_run 49h ago → 2.04× → Warn
//! - Daily schedule, last_run 5d ago → 5× → High
//! - Weekly schedule, last_run 60d ago → 8.5× → Critical
//!
//! ## Run OUTCOME — `backup_failed`
//!
//! Freshness alone is not enough, and the gap was not theoretical.
//! `last_run` is stamped even when every target in the run fails, so a
//! schedule that fails nightly looks perfectly fresh. On a live fleet
//! (2026-08-25) a full PBS datastore made every backup fail with
//! `Disk quota exceeded`; `last_run` kept updating on time, so this
//! analyzer stayed silent for **8 days** while the fleet had no backups
//! at all.
//!
//! The structured failure data was already available all along — the
//! same `BackupConfig` this module loads carries `entries[]` with a
//! per-target `status` and `error`. The `backup_failed` finding reads
//! the outcome of the most recent run and fires when targets in it
//! failed: `Critical` when the whole run failed (zero protection),
//! `High` when it partly failed.
//!
//! ## What this DOESN'T cover
//!
//! - Per-target backup *freshness* (only schedule level, plus the
//!   run-outcome counts above). A target silently dropped from a
//!   schedule stops being backed up without either finding firing.

use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::predictive::{
    Context,
    proposal::{
        Evidence, Proposal, ProposalScope, RemediationPlan, Severity,
    },
    ack::AckStore,
};

pub const FINDING_TYPE: &str = "backup_stale";
/// The most recent run of a schedule had failing targets. Distinct from
/// `backup_stale`: a schedule can be perfectly punctual and still protect
/// nothing.
pub const FINDING_TYPE_FAILED: &str = "backup_failed";

const WARN_MULT: f64 = 2.0;
const HIGH_MULT: f64 = 4.0;
const CRITICAL_MULT: f64 = 7.0;

/// Per-schedule freshness fact. Computed once per tick from the
/// existing `BackupConfig` on disk; this analyzer never writes to
/// the backup module.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ScheduleFact {
    /// Stable id used as the resource_id so acks scope to the
    /// specific schedule.
    pub id: String,
    pub name: String,
    pub interval_hours: f64,
    /// Time since `last_run`. `None` when last_run is empty (never
    /// ran). The analyzer treats Never as the most-stale state and
    /// fires on the same severity ladder using a synthetic
    /// "missed_mult = HIGH_MULT" so it shows up at High.
    pub since_last_run_hours: Option<f64>,
    /// Raw last_run for the proposal evidence panel.
    pub last_run_iso: String,
    /// Hours since the schedule was CREATED. `None` for schedules created
    /// before `created_at` existed (treated as old enough to alarm). Used to
    /// give a brand-new schedule one full interval before the "never run"
    /// finding fires — its first run may simply not be due yet.
    pub age_hours: Option<f64>,
    /// Targets in the MOST RECENT run that ended `Failed`.
    pub last_run_failed: usize,
    /// Targets in the most recent run that produced any outcome at all
    /// (failed + completed). Zero when no entry can be attributed to the
    /// latest run — in which case no outcome finding is emitted, because
    /// "no records" is not evidence of failure.
    pub last_run_total: usize,
    /// One representative error from the most recent run, for the evidence
    /// panel. Empty when nothing failed.
    pub last_error: String,
}

/// Sample backup schedules. Synchronous — local file read only.
pub fn sample_backup_freshness_now() -> Vec<ScheduleFact> {
    let cfg = crate::backup::load_config();
    let now = Utc::now();
    cfg.schedules.iter()
        .filter(|s| s.enabled)
        .map(|s| {
            let interval_hours = match s.frequency {
                crate::backup::BackupFrequency::Daily   => 24.0,
                crate::backup::BackupFrequency::Weekly  => 24.0 * 7.0,
                crate::backup::BackupFrequency::Monthly => 24.0 * 30.0,
            };
            let since = parse_iso(&s.last_run).map(|t|
                (now - t).num_milliseconds() as f64 / 3_600_000.0
            );
            let age = parse_iso(&s.created_at).map(|t|
                (now - t).num_milliseconds() as f64 / 3_600_000.0
            );
            let (last_run_failed, last_run_total, last_error) =
                last_run_outcome(&cfg, &s.id, &s.last_run);

            ScheduleFact {
                id: s.id.clone(),
                name: s.name.clone(),
                interval_hours,
                since_last_run_hours: since,
                last_run_iso: s.last_run.clone(),
                age_hours: age,
                last_run_failed,
                last_run_total,
                last_error,
            }
        })
        .collect()
}

/// Outcome of a schedule's most recent run: (failed, total, first error).
///
/// "Most recent run" = entries for this schedule stamped at or after the
/// schedule's `last_run`. Entries are written as each target finishes, so they
/// all land at or after the run's start. An `InProgress` entry is ignored — it
/// has not decided yet, and counting it as a success would mask a run that is
/// about to fail.
pub fn last_run_outcome(
    cfg: &crate::backup::BackupConfig,
    schedule_id: &str,
    last_run: &str,
) -> (usize, usize, String) {
    let Some(start) = parse_iso(last_run) else {
        // Never ran, or an unparseable stamp — the freshness ladder covers
        // that case; there is no run to judge.
        return (0, 0, String::new());
    };
    let mut failed = 0usize;
    let mut total = 0usize;
    let mut first_error = String::new();
    for e in cfg.entries.iter() {
        if e.schedule_id != schedule_id {
            continue;
        }
        match parse_iso(&e.created_at) {
            Some(t) if t >= start => {}
            _ => continue,
        }
        match e.status {
            crate::backup::BackupStatus::Failed => {
                failed += 1;
                total += 1;
                if first_error.is_empty() && !e.error.is_empty() {
                    first_error = e.error.clone();
                }
            }
            crate::backup::BackupStatus::Completed => {
                total += 1;
            }
            _ => {}
        }
    }
    (failed, total, first_error)
}

pub async fn sample_backup_freshness_now_async(timeout: Duration) -> Vec<ScheduleFact> {
    let fut = tokio::task::spawn_blocking(sample_backup_freshness_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            tracing::warn!("predictive: backup-freshness sampling task panicked: {}", e);
            Vec::new()
        }
        Err(_) => {
            tracing::warn!(
                "predictive: backup-freshness sampling timed out after {}s",
                timeout.as_secs(),
            );
            Vec::new()
        }
    }
}

fn parse_iso(s: &str) -> Option<DateTime<Utc>> {
    if s.is_empty() { return None; }
    DateTime::parse_from_rfc3339(s).ok().map(|t| t.with_timezone(&Utc))
}

/// Severity from the ratio of (time since last run) / (expected
/// interval). Returns `None` for fresh schedules.
pub fn severity_for_mult(mult: f64) -> Option<Severity> {
    if mult >= CRITICAL_MULT { Some(Severity::Critical) }
    else if mult >= HIGH_MULT { Some(Severity::High) }
    else if mult >= WARN_MULT { Some(Severity::Warn) }
    else { None }
}

pub fn analyze(
    ctx: &Context,
    current: &[ScheduleFact],
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    for fact in current {
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("backup:{}", fact.id)),
        };

        // Run OUTCOME is independent of freshness — a schedule that fires on
        // time every night and fails every night is the worst case, and the
        // freshness ladder below would never fire for it. Emitted first and
        // separately suppressed so acknowledging one does not hide the other.
        if fact.last_run_failed > 0
            && !acks.suppresses(FINDING_TYPE_FAILED, &scope)
            && !proposals.is_suppressed(FINDING_TYPE_FAILED, &scope)
        {
            out.push(build_failure_proposal(fact, &scope));
        }

        if acks.suppresses(FINDING_TYPE, &scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE, &scope) { continue; }

        // For a never-ran schedule, treat as High severity (missed
        // 4× interval). The schedule may be brand new and not yet
        // executed, but a schedule sitting `enabled: true` with
        // empty last_run for any meaningful time is exactly the
        // pre-disaster condition this analyzer exists to catch.
        let (severity, mult) = match fact.since_last_run_hours {
            Some(h) => {
                let mult = h / fact.interval_hours;
                match severity_for_mult(mult) {
                    Some(s) => (s, mult),
                    None    => continue,
                }
            }
            None => {
                // Never run. A schedule younger than one full interval simply
                // hasn't reached its first run yet (created 21:06, first nightly
                // run still hours away) — don't alarm (wabil 2026-06-22). Once a
                // whole interval has elapsed with still no run, it IS the
                // pre-disaster condition this analyzer exists to catch.
                if let Some(age) = fact.age_hours
                    && age < fact.interval_hours { continue; }
                (Severity::High, HIGH_MULT)
            }
        };
        out.push(build_proposal(fact, &scope, severity, mult));
    }
    out
}

pub fn covered_scopes(
    ctx: &Context,
    current: &[ScheduleFact],
) -> Vec<(String, ProposalScope)> {
    let mut out = Vec::with_capacity(current.len() * 2);
    for f in current {
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("backup:{}", f.id)),
        };
        out.push((FINDING_TYPE.to_string(), scope.clone()));
        // Both finding types are covered whenever the schedule is sampled, so
        // a resolved failure clears its proposal instead of lingering.
        out.push((FINDING_TYPE_FAILED.to_string(), scope));
    }
    out
}

/// A run whose targets failed. `Critical` when the ENTIRE run failed — the
/// operator has no recovery point from it at all — `High` when it partly
/// succeeded.
fn build_failure_proposal(fact: &ScheduleFact, scope: &ProposalScope) -> Proposal {
    let all_failed = fact.last_run_failed >= fact.last_run_total;
    let severity = if all_failed { Severity::Critical } else { Severity::High };

    let title = if all_failed {
        format!("Backup '{}' failed completely — {} of {} target{} failed",
            fact.name, fact.last_run_failed, fact.last_run_total,
            if fact.last_run_total == 1 { "" } else { "s" })
    } else {
        format!("Backup '{}' partly failed — {} of {} targets failed",
            fact.name, fact.last_run_failed, fact.last_run_total)
    };

    let why = format!(
        "The most recent run of backup schedule '{}' (started {}) recorded \
         {} failed target{} out of {}. The schedule itself is running on \
         time, so freshness checks look healthy and the failure is invisible \
         unless the entries are read — a full destination can fail every \
         target nightly for weeks while the dashboard shows a punctual \
         schedule.{}",
        fact.name, fact.last_run_iso,
        fact.last_run_failed,
        if fact.last_run_failed == 1 { "" } else { "s" },
        fact.last_run_total,
        if all_failed {
            " Every target failed: this run produced NO recoverable backup."
        } else {
            ""
        },
    );

    let mut evidence = vec![
        Evidence {
            label: "Schedule".into(),
            value: fact.name.clone(),
            detail: Some(format!("last run started {}", fact.last_run_iso)),
            links: Vec::new(),
        },
        Evidence {
            label: "Failed targets".into(),
            value: format!("{} of {}", fact.last_run_failed, fact.last_run_total),
            detail: None,
            links: Vec::new(),
        },
    ];
    if !fact.last_error.is_empty() {
        evidence.push(Evidence {
            label: "Error".into(),
            value: fact.last_error.chars().take(400).collect::<String>(),
            detail: None,
            links: Vec::new(),
        });
    }

    Proposal::new_rule(
        FINDING_TYPE_FAILED, severity, title, why, evidence,
        RemediationPlan::Manual {
            instructions:
                "Read the error on the failed entries and clear its cause. A \
                 destination that is out of space is the common one — free \
                 space or lower the schedule's retention, then re-run the \
                 schedule and confirm the entries complete."
                    .to_string(),
            commands: Vec::new(),
        },
        scope.clone(),
    )
}

fn build_proposal(
    fact: &ScheduleFact,
    scope: &ProposalScope,
    severity: Severity,
    mult: f64,
) -> Proposal {
    let interval_label = if fact.interval_hours <= 24.0 { "daily" }
        else if fact.interval_hours <= 24.0 * 7.0 { "weekly" }
        else { "monthly" };

    let (title, why) = match fact.since_last_run_hours {
        Some(h) => {
            let days = h / 24.0;
            let title = format!(
                "Backup '{}' hasn't run in {:.1} day{} ({:.1}× the {} interval)",
                fact.name, days,
                if (days - 1.0).abs() < 0.05 { "" } else { "s" },
                mult, interval_label,
            );
            let why = format!(
                "Backup schedule '{}' is configured to run {} but its \
                 last_run was {} — that's {:.1} day{} ago, {:.1}× the \
                 expected cadence. The scheduler may have stopped, the \
                 destination may be unreachable, or the schedule itself \
                 was paused without disabling. Whatever the cause, the \
                 cluster's recovery point is older than the operator \
                 thinks.",
                fact.name, interval_label, fact.last_run_iso,
                days, if (days - 1.0).abs() < 0.05 { "" } else { "s" },
                mult,
            );
            (title, why)
        }
        None => {
            let title = format!("Backup '{}' has never run", fact.name);
            let why = format!(
                "Backup schedule '{}' is enabled with a {} cadence but \
                 has no last_run timestamp recorded — it has either \
                 never executed or has been failing in a way that \
                 prevents the timestamp from updating. Either way, the \
                 operator's mental model of \"backups are happening\" \
                 doesn't match reality.",
                fact.name, interval_label,
            );
            (title, why)
        }
    };

    let evidence = vec![
        Evidence {
            label: "Schedule".into(),
            value: fact.name.clone(),
            detail: Some(format!("{} cadence (interval ~{:.0}h)", interval_label, fact.interval_hours)),
            links: Vec::new(),
        },
        Evidence {
            label: "Last run".into(),
            value: if fact.last_run_iso.is_empty() { "never".into() } else { fact.last_run_iso.clone() },
            detail: fact.since_last_run_hours.map(|h| format!("{:.1} hours ago", h)),
            links: Vec::new(),
        },
        Evidence {
            label: "Missed by".into(),
            value: format!("{:.1}× interval", mult),
            detail: None,
            links: Vec::new(),
        },
    ];

    let remediation = RemediationPlan::Manual {
        instructions: format!(
            "Inspect why '{name}' isn't running on schedule. Common \
             causes: scheduler service stopped, destination \
             unreachable, credentials rotated, or a hung previous run. \
             Trigger a one-shot backup from the Backups page to see \
             the live error if any. Investigate before assuming the \
             cluster has recent recovery points.",
            name = fact.name,
        ),
        commands: vec![
            "sudo systemctl status wolfstack    # is the scheduler healthy?".into(),
            "sudo journalctl -u wolfstack --since '24 hours ago' | grep -iE 'backup|schedule' | tail -30".into(),
            "ls -la /etc/wolfstack/backups.json".into(),
        ],
    };

    Proposal::new_rule(
        FINDING_TYPE, severity,
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

    fn fact_with_age(name: &str, interval_hours: f64, since_hours: Option<f64>) -> ScheduleFact {
        ScheduleFact {
            id: format!("id-{}", name),
            name: name.into(),
            interval_hours,
            since_last_run_hours: since_hours,
            last_run_iso: "2026-04-01T00:00:00Z".into(),
            // None = unknown creation age → never-ran fires immediately, the
            // legacy behaviour these tests assert. Grace is covered separately.
            age_hours: None,
            // A clean run by default: these tests exercise the freshness
            // ladder, not the outcome finding.
            ..Default::default()
        }
    }

    #[test]
    fn severity_thresholds() {
        assert_eq!(severity_for_mult(1.0), None);
        assert_eq!(severity_for_mult(1.99), None);
        assert_eq!(severity_for_mult(2.0), Some(Severity::Warn));
        assert_eq!(severity_for_mult(3.99), Some(Severity::Warn));
        assert_eq!(severity_for_mult(4.0), Some(Severity::High));
        assert_eq!(severity_for_mult(6.99), Some(Severity::High));
        assert_eq!(severity_for_mult(7.0), Some(Severity::Critical));
        assert_eq!(severity_for_mult(20.0), Some(Severity::Critical));
    }

    #[test]
    fn fresh_daily_silent() {
        // 12h since last run on a daily schedule = 0.5× → no finding
        let facts = vec![fact_with_age("daily", 24.0, Some(12.0))];
        let p = analyze(&ctx(), &facts, &AckStore::default(), &ProposalStore::default());
        assert!(p.is_empty());
    }

    #[test]
    fn missed_2x_interval_is_warn() {
        // 50h since last run on a daily schedule = 2.08×
        let facts = vec![fact_with_age("daily", 24.0, Some(50.0))];
        let p = analyze(&ctx(), &facts, &AckStore::default(), &ProposalStore::default());
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].severity, Severity::Warn);
    }

    #[test]
    fn missed_7x_interval_is_critical() {
        let facts = vec![fact_with_age("daily", 24.0, Some(24.0 * 8.0))];
        let p = analyze(&ctx(), &facts, &AckStore::default(), &ProposalStore::default());
        assert_eq!(p[0].severity, Severity::Critical);
    }

    #[test]
    fn never_ran_is_high() {
        // Brand-new enabled schedule with no last_run → High by
        // default (synthetic mult = 4×).
        let facts = vec![fact_with_age("brand-new", 24.0, None)];
        let p = analyze(&ctx(), &facts, &AckStore::default(), &ProposalStore::default());
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].severity, Severity::High);
        assert!(p[0].title.contains("never run"));
    }

    #[test]
    fn never_ran_but_young_is_silent_then_fires_after_one_interval() {
        // wabil 2026-06-22: a daily schedule created 5h ago whose first nightly
        // run isn't due yet must NOT be flagged "never run".
        let young = ScheduleFact {
            id: "id-young".into(), name: "Nightly".into(), interval_hours: 24.0,
            since_last_run_hours: None, last_run_iso: String::new(), age_hours: Some(5.0),
            ..Default::default()
        };
        let p = analyze(&ctx(), &[young], &AckStore::default(), &ProposalStore::default());
        assert!(p.is_empty(), "a schedule younger than one interval must stay silent");

        // Past one full interval with still no run → the real problem fires.
        let stale = ScheduleFact {
            id: "id-stale".into(), name: "Nightly".into(), interval_hours: 24.0,
            since_last_run_hours: None, last_run_iso: String::new(), age_hours: Some(30.0),
            ..Default::default()
        };
        let p = analyze(&ctx(), &[stale], &AckStore::default(), &ProposalStore::default());
        assert_eq!(p.len(), 1, "after one interval, never-run must alarm");
        assert_eq!(p[0].severity, Severity::High);
    }

    #[test]
    fn ack_silences_specific_schedule() {
        let facts = vec![fact_with_age("staging-daily", 24.0, Some(72.0))];
        let mut acks = AckStore::default();
        acks.add(crate::predictive::ack::Ack::new(
            FINDING_TYPE,
            crate::predictive::ack::AckScope::Resource {
                node_id: "node-a".into(),
                resource_id: "backup:id-staging-daily".into(),
            },
            "staging cluster — backups paused during refactor",
            "paul", None,
        ));
        let p = analyze(&ctx(), &facts, &acks, &ProposalStore::default());
        assert!(p.is_empty());
    }

    #[test]
    fn weekly_schedule_uses_weekly_window() {
        // 8 days since last run on a weekly schedule = 1.14× → no
        // finding. The same 8 days on a daily schedule would be 8×
        // → Critical.
        let weekly = vec![fact_with_age("weekly", 24.0 * 7.0, Some(24.0 * 8.0))];
        let p = analyze(&ctx(), &weekly, &AckStore::default(), &ProposalStore::default());
        assert!(p.is_empty());
    }

    #[test]
    fn analyzer_can_stay_quiet() {
        let facts = vec![fact_with_age("ok", 24.0, Some(2.0))];
        let p = analyze(&ctx(), &facts, &AckStore::default(), &ProposalStore::default());
        assert!(p.is_empty());
    }

    // ── Run outcome (`backup_failed`) ────────────────────────────

    fn entry(schedule: &str, created: &str, status: crate::backup::BackupStatus, err: &str)
        -> crate::backup::BackupEntry
    {
        crate::backup::BackupEntry {
            id: format!("{}-{}", schedule, created),
            target: Default::default(),
            storage: Default::default(),
            filename: "x.tar.gz".into(),
            size_bytes: 0,
            created_at: created.into(),
            status,
            error: err.into(),
            schedule_id: schedule.into(),
            comments: String::new(),
            node_hostname: String::new(),
            docker_config: String::new(),
            mounts: Vec::new(),
        }
    }

    /// Only entries from the LATEST run count — an older run's failures must
    /// not keep alarming once a later run has succeeded.
    #[test]
    fn last_run_outcome_counts_only_the_latest_run() {
        use crate::backup::BackupStatus::*;
        let cfg = crate::backup::BackupConfig { entries: vec![
            // Previous run — all failed, but superseded.
            entry("s", "2026-08-20T03:00:00Z", Failed, "old failure"),
            entry("s", "2026-08-20T03:05:00Z", Failed, "old failure"),
            // Latest run.
            entry("s", "2026-08-25T03:00:00Z", Completed, ""),
            entry("s", "2026-08-25T03:05:00Z", Failed, "Disk quota exceeded"),
            // Another schedule entirely.
            entry("other", "2026-08-25T03:06:00Z", Failed, "not ours"),
            // Still running — undecided, must not be counted either way.
            entry("s", "2026-08-25T03:07:00Z", InProgress, ""),
        ], ..Default::default() };
        let (failed, total, err) = last_run_outcome(&cfg, "s", "2026-08-25T03:00:00Z");
        assert_eq!((failed, total), (1, 2), "one of two decided targets failed");
        assert_eq!(err, "Disk quota exceeded");
    }

    /// A schedule with no last_run has no run to judge.
    #[test]
    fn last_run_outcome_is_empty_without_a_last_run() {
        let cfg = crate::backup::BackupConfig { entries: vec![entry(
            "s", "2026-08-25T03:00:00Z",
            crate::backup::BackupStatus::Failed, "boom")], ..Default::default() };
        assert_eq!(last_run_outcome(&cfg, "s", ""), (0, 0, String::new()));
    }

    /// The 8-day blind spot: the schedule is perfectly punctual (2h since
    /// last run → no freshness finding) but every target failed. Before
    /// `backup_failed` existed this produced NOTHING.
    #[test]
    fn punctual_schedule_with_a_fully_failed_run_is_critical() {
        let fact = ScheduleFact {
            last_run_failed: 11, last_run_total: 11,
            last_error: "PBS backup failed: Disk quota exceeded (os error 122)".into(),
            ..fact_with_age("wolfstack-1", 24.0, Some(2.0))
        };
        let p = analyze(&ctx(), &[fact], &AckStore::default(), &ProposalStore::default());
        assert_eq!(p.len(), 1, "the failure must be reported on its own");
        assert_eq!(p[0].finding_type, FINDING_TYPE_FAILED);
        assert_eq!(p[0].severity, Severity::Critical, "a wholly failed run leaves no backup");
        assert!(p[0].evidence.iter().any(|e| e.value.contains("Disk quota exceeded")),
            "the operator needs the actual error: {:?}", p[0].evidence);
    }

    /// Partial failure is serious but not total — something was protected.
    #[test]
    fn partly_failed_run_is_high_not_critical() {
        let fact = ScheduleFact {
            last_run_failed: 3, last_run_total: 11,
            ..fact_with_age("wolfstack-1", 24.0, Some(2.0))
        };
        let p = analyze(&ctx(), &[fact], &AckStore::default(), &ProposalStore::default());
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].severity, Severity::High);
    }

    /// A clean run says nothing.
    #[test]
    fn clean_run_emits_no_failure_finding() {
        let fact = ScheduleFact {
            last_run_failed: 0, last_run_total: 11,
            ..fact_with_age("wolfstack-1", 24.0, Some(2.0))
        };
        let p = analyze(&ctx(), &[fact], &AckStore::default(), &ProposalStore::default());
        assert!(p.is_empty(), "nothing failed and the schedule is fresh: {:?}", p);
    }

    /// Stale AND failing reports both — they are different problems with
    /// different fixes, and acking one must not hide the other.
    #[test]
    fn stale_and_failing_reports_both_findings() {
        let fact = ScheduleFact {
            last_run_failed: 5, last_run_total: 5,
            ..fact_with_age("wolfstack-1", 24.0, Some(120.0))
        };
        let p = analyze(&ctx(), &[fact], &AckStore::default(), &ProposalStore::default());
        assert_eq!(p.len(), 2, "one failure finding and one staleness finding: {:?}", p);
        assert!(p.iter().any(|x| x.finding_type == FINDING_TYPE_FAILED));
        assert!(p.iter().any(|x| x.finding_type == FINDING_TYPE));
    }

    /// Acking the failure leaves the staleness finding intact.
    #[test]
    fn acking_failure_does_not_silence_staleness() {
        let fact = ScheduleFact {
            last_run_failed: 5, last_run_total: 5,
            ..fact_with_age("wolfstack-1", 24.0, Some(120.0))
        };
        let mut acks = AckStore::default();
        acks.add(crate::predictive::ack::Ack::new(
            FINDING_TYPE_FAILED,
            crate::predictive::ack::AckScope::Resource {
                node_id: "node-a".into(),
                resource_id: "backup:id-wolfstack-1".into(),
            },
            "known — datastore full, provider running GC",
            "paul", None,
        ));
        let p = analyze(&ctx(), &[fact], &acks, &ProposalStore::default());
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].finding_type, FINDING_TYPE);
    }
}
