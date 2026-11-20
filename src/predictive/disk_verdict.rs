// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Shared disk-fill verdict computation.
//!
//! Extracted from `disk_fill.rs` so the host, Docker, and LXC
//! analyzers (and any future filesystem-shaped analyzer — VM disk,
//! cgroup limits, etc.) all reach the same answer when handed the
//! same samples + current state. Never duplicate the math.
//!
//! ## Tier thresholds
//!
//! | ETA to target (or 100% if already past) | Severity   |
//! |-----------------------------------------|------------|
//! | < 6 h                                   | `Critical` |
//! | < 48 h                                  | `High`     |
//! | < 7 d                                   | `Warn`     |
//! | ≥ 7 d                                   | suppressed |
//!
//! Already at/past target with non-positive slope → `Warn` with
//! `eta_hours = None` ("flat full" — at the cliff but not getting
//! worse). Already past target with positive slope → ETA-to-100%.
//!
//! These rationales are explained per constant in `disk_fill.rs`'s
//! module doc; this file owns the actual constants now.
//!
//! ## Which samples the ETA comes from
//!
//! One least-squares line over the whole 24 h buffer averages a sudden
//! fill away: a disk flat for 20 h that then grows 20 GB an hour reads
//! as a gentle slope, and the alert arrives after the disk is full
//! (wolfstack-2, 2026-11-19). So the fit runs over three windows —
//! the whole buffer, the last [`MEDIUM_WINDOW_MINUTES`] and the last
//! [`SHORT_WINDOW_MINUTES`] — and the shortest ETA wins. The short
//! window is the noisiest (one big download moves it), so it only
//! counts when it says the disk fills within [`SHORT_WINDOW_MAX_ETA_HOURS`]:
//! at that rate it is a runaway, not noise.
//!
//! ## Size-scaled free-space floor
//!
//! [`free_space_floor_bytes`] is the point-in-time safety net used by
//! the threshold analyzer: how much free space is "too little" for a
//! disk of a given size. A flat number is wrong both ways — 10 GB is
//! minutes of runway for a 400 GB database disk and an alarm that
//! never clears on a 16 GB root.

use std::collections::VecDeque;

use crate::predictive::metrics::{MetricSample, linear_fit};
use crate::predictive::proposal::Severity;

/// We need at least this many samples to trust a regression. With
/// fewer, slope is dominated by sampling noise.
pub const MIN_SAMPLES: usize = 3;

/// Samples must span at least this long before we'll fit a line.
/// Below 30 min the analyzer would hallucinate trend from noise.
pub const MIN_SPAN_MINUTES: i64 = 30;

/// Don't surface anything beyond this horizon — past 7 days the
/// linear extrapolation is dominated by long-term cycles (weekly
/// log rotation, cron sweeps) rather than the near-term trajectory.
pub const MAX_HORIZON_HOURS: f64 = 24.0 * 7.0;

/// Severity boundaries (in hours of ETA).
pub const CRITICAL_HOURS: f64 = 6.0;
pub const HIGH_HOURS: f64 = 48.0;

/// Don't bother predicting on resources below this used-percent —
/// even with steep growth they're not the issue today, and noisy
/// growth curves on near-empty resources produce silly ETAs.
pub const MIN_USED_PCT: f64 = 50.0;

/// Default fill target used by host/Docker/LXC analyzers. Already-
/// past-target resources fall through to the ETA-to-100% branch.
pub const FILL_TARGET_PCT: f64 = 95.0;

/// Recent-growth window: catches a fill that started within the last
/// few hours, which the 24 h fit dilutes. 72 samples at the 5-min
/// orchestrator cadence — plenty for a stable fit.
pub const MEDIUM_WINDOW_MINUTES: i64 = 6 * 60;

/// Runaway window: 12 samples at the 5-min cadence. See
/// [`SHORT_WINDOW_MAX_ETA_HOURS`] for why it is gated.
pub const SHORT_WINDOW_MINUTES: i64 = 60;

/// The last-hour fit only counts when it predicts the target within
/// this many hours. One hour of samples is easily moved by a single
/// large write (a backup staging, an image pull); gating it to
/// "full within two hours" keeps it for genuine runaways.
pub const SHORT_WINDOW_MAX_ETA_HOURS: f64 = 2.0;

/// Free-space floor, as a fraction of the filesystem size, below
/// which the threshold analyzer warns.
pub const FLOOR_WARN_FRACTION: f64 = 0.10;
/// The warn floor never drops below this, however small the disk —
/// under ~5 GB free, package upgrades and log bursts start failing.
pub const FLOOR_WARN_MIN_BYTES: u64 = 5 * 1024 * 1024 * 1024;
/// …and never needs to exceed this: 100 GB of headroom is days of
/// runway even for a busy database, so a 4 TB disk warns at 97.5 %
/// rather than at 3.6 TB used.
pub const FLOOR_WARN_MAX_BYTES: u64 = 100 * 1024 * 1024 * 1024;
/// On small disks the 5 GB minimum would be most of the disk (an
/// 8 GB root would warn at 37 % used). Cap the floor at this fraction
/// of the size so small disks warn at ~80 % instead.
pub const FLOOR_WARN_MAX_FRACTION: f64 = 0.20;
/// Critical floor = warn floor / this. A 436 GB disk: warn under
/// 43.6 GB free, critical under 10.9 GB.
pub const FLOOR_CRITICAL_DIVISOR: u64 = 4;

/// `(warn_below, critical_below)` free-space floors in bytes for a
/// filesystem of `total_bytes`. Pure — see the `FLOOR_*` constants
/// for how each bound was chosen.
pub fn free_space_floor_bytes(total_bytes: u64) -> (u64, u64) {
    let scaled = (total_bytes as f64 * FLOOR_WARN_FRACTION) as u64;
    let clamped = scaled.clamp(FLOOR_WARN_MIN_BYTES, FLOOR_WARN_MAX_BYTES);
    let small_disk_cap = (total_bytes as f64 * FLOOR_WARN_MAX_FRACTION) as u64;
    let warn = clamped.min(small_disk_cap);
    (warn, warn / FLOOR_CRITICAL_DIVISOR)
}

/// Raise `Warn` to `High` for a filesystem that holds something whose
/// failure is an outage (the OS root, container root filesystems,
/// database data). `High` is the lowest tier that notifies, so a
/// "/ fills in 4 days" finding on a database host reaches the
/// operator instead of waiting in the inbox. Never raises to
/// `Critical`: that tier bypasses quiet hours and must stay reserved
/// for "hours, not days".
pub fn escalate_for_role(sev: Severity, holds_critical_data: bool) -> Severity {
    if holds_critical_data && sev == Severity::Warn { Severity::High } else { sev }
}

/// One verdict from the regression. Carried by the analyzer into
/// the proposal builder.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub severity: Severity,
    /// Hours-to-target. `None` when the resource is already at/past
    /// `target` with non-positive slope ("flat full").
    pub eta_hours: Option<f64>,
    pub slope_pct_per_hour: f64,
    pub samples_used: usize,
    pub span_minutes: i64,
}

/// Compute a verdict from a sample series + current usage state.
///
/// Pure function — no I/O, no clocks. Trivially testable.
///
/// Returns `None` when:
/// - fewer than `MIN_SAMPLES` samples
/// - sample-window shorter than `MIN_SPAN_MINUTES`
/// - the linear fit can't produce a slope (zero x-variance)
/// - currently below target AND slope ≤ 0 (shrinking — no problem)
/// - currently below target AND projected ETA exceeds the horizon
///   (so far in the future the trend is meaningless)
pub fn compute_verdict(
    samples: &VecDeque<MetricSample>,
    used_pct_now: f64,
    target_pct: f64,
) -> Option<Verdict> {
    // The whole buffer must clear the sample/span bars before any
    // window is considered — the same contract as before windows
    // existed, so a freshly-started node stays quiet until it has
    // half an hour of history.
    let full = fit_window(samples, None)?;
    let fits: Vec<WindowFit> = [Some(MEDIUM_WINDOW_MINUTES), Some(SHORT_WINDOW_MINUTES)]
        .into_iter()
        .filter_map(|w| fit_window(samples, w))
        .chain(std::iter::once(full.clone()))
        .collect();

    // Past target → the ETA that matters is to 100 %.
    let past_target = used_pct_now >= target_pct;
    let eta_target = if past_target { 100.0 } else { target_pct };

    // Shortest ETA among the windows allowed to speak.
    let best = fits.iter()
        .filter(|f| f.slope_per_hour > 0.0)
        .map(|f| (f, ((eta_target - used_pct_now) / f.slope_per_hour).max(0.0)))
        .filter(|(f, eta)| {
            f.window_minutes != Some(SHORT_WINDOW_MINUTES)
                || *eta < SHORT_WINDOW_MAX_ETA_HOURS
        })
        .min_by(|a, b| a.1.total_cmp(&b.1));

    match best {
        Some((f, eta_hours)) => {
            // Below target, beyond the horizon: too far out for a
            // linear projection to mean anything.
            if !past_target && eta_hours > MAX_HORIZON_HOURS { return None; }
            Some(Verdict {
                severity: severity_from_eta(eta_hours),
                eta_hours: Some(eta_hours),
                slope_pct_per_hour: f.slope_per_hour,
                samples_used: f.samples,
                span_minutes: f.span_minutes,
            })
        }
        // Nothing growing. Past target is still an at-the-cliff state
        // worth one Warn; below target is no problem.
        None if past_target => Some(Verdict {
            severity: Severity::Warn,
            eta_hours: None,
            slope_pct_per_hour: full.slope_per_hour,
            samples_used: full.samples,
            span_minutes: full.span_minutes,
        }),
        None => None,
    }
}

/// One linear fit over a trailing window of the sample buffer.
#[derive(Debug, Clone)]
struct WindowFit {
    /// `None` = the whole buffer.
    window_minutes: Option<i64>,
    slope_per_hour: f64,
    samples: usize,
    span_minutes: i64,
}

/// Fit the samples whose timestamp falls within `window_minutes` of the
/// newest one (`None` = all of them). `None` result when the window
/// holds fewer than [`MIN_SAMPLES`], spans less than
/// [`MIN_SPAN_MINUTES`], or has no x-variance.
fn fit_window(samples: &VecDeque<MetricSample>, window_minutes: Option<i64>) -> Option<WindowFit> {
    let newest = samples.back()?.ts;
    let tail: VecDeque<MetricSample> = match window_minutes {
        None => samples.clone(),
        Some(w) => {
            let cutoff = newest - chrono::Duration::minutes(w);
            samples.iter().filter(|s| s.ts >= cutoff).cloned().collect()
        }
    };
    if tail.len() < MIN_SAMPLES { return None; }
    let span = tail.back()?.ts - tail.front()?.ts;
    if span.num_minutes() < MIN_SPAN_MINUTES { return None; }
    let (slope_per_sec, _intercept) = linear_fit(&tail)?;
    Some(WindowFit {
        window_minutes,
        slope_per_hour: slope_per_sec * 3600.0,
        samples: tail.len(),
        span_minutes: span.num_minutes(),
    })
}

pub fn severity_from_eta(eta_hours: f64) -> Severity {
    if eta_hours < CRITICAL_HOURS { Severity::Critical }
    else if eta_hours < HIGH_HOURS { Severity::High }
    else { Severity::Warn }
}

/// Render hours into a compact human label suitable for proposal
/// titles: "45 min", "12.3 h", "2.1 days".
pub fn humanise_hours(h: f64) -> String {
    if h < 1.0 { format!("{:.0} min", (h * 60.0).max(1.0)) }
    else if h < 24.0 { format!("{:.1} h", h) }
    else { format!("{:.1} days", h / 24.0) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn buf(growth_pct_per_h: f64, n: usize, start_pct: f64, cadence_min: i64) -> VecDeque<MetricSample> {
        let mut out = VecDeque::new();
        let now = Utc::now();
        let total_min = (n as i64 - 1) * cadence_min;
        for i in 0..n {
            let ts = now - Duration::minutes(total_min - i as i64 * cadence_min);
            let elapsed_h = (i as i64 * cadence_min) as f64 / 60.0;
            out.push_back(MetricSample { ts, value: start_pct + growth_pct_per_h * elapsed_h });
        }
        out
    }

    #[test]
    fn severity_thresholds_match_constants() {
        assert_eq!(severity_from_eta(2.0), Severity::Critical);
        assert_eq!(severity_from_eta(CRITICAL_HOURS - 0.01), Severity::Critical);
        assert_eq!(severity_from_eta(CRITICAL_HOURS), Severity::High);
        assert_eq!(severity_from_eta(HIGH_HOURS - 0.01), Severity::High);
        assert_eq!(severity_from_eta(HIGH_HOURS), Severity::Warn);
        assert_eq!(severity_from_eta(96.0), Severity::Warn);
    }

    #[test]
    fn refuses_too_few_samples() {
        let s = buf(2.0, 2, 70.0, 30);
        assert!(compute_verdict(&s, 70.0, 95.0).is_none());
    }

    #[test]
    fn refuses_too_short_span() {
        let s = buf(2.0, 5, 70.0, 5); // 20 min span < 30
        assert!(compute_verdict(&s, 70.0, 95.0).is_none());
    }

    #[test]
    fn refuses_below_target_shrinking() {
        let s = buf(-1.0, 6, 75.0, 10);
        assert!(compute_verdict(&s, 70.0, 95.0).is_none());
    }

    #[test]
    fn refuses_eta_beyond_horizon() {
        // 0.05 %/h × 25 = 500 h ≫ 168 h horizon
        let s = buf(0.05, 8, 70.0, 10);
        assert!(compute_verdict(&s, 70.0, 95.0).is_none());
    }

    #[test]
    fn fast_growth_critical() {
        // 5 %/h → 25/5 = 5 h to target → Critical
        let s = buf(5.0, 8, 65.0, 10);
        let v = compute_verdict(&s, 70.0, 95.0).expect("verdict");
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn slow_growth_warn() {
        // 0.5 %/h → 50 h → Warn (between HIGH_HOURS=48 and horizon)
        let s = buf(0.5, 8, 69.0, 10);
        let v = compute_verdict(&s, 70.0, 95.0).expect("verdict");
        assert_eq!(v.severity, Severity::Warn);
    }

    #[test]
    fn already_past_target_flat_warn() {
        let s = buf(0.0, 8, 96.0, 10);
        let v = compute_verdict(&s, 96.0, 95.0).expect("verdict");
        assert_eq!(v.severity, Severity::Warn);
        assert!(v.eta_hours.is_none());
    }

    #[test]
    fn already_past_target_growing_uses_100_pct() {
        // 96% used, 0.5%/h → 4/0.5 = 8 h → High
        let s = buf(0.5, 8, 95.5, 10);
        let v = compute_verdict(&s, 96.0, 95.0).expect("verdict");
        assert_eq!(v.severity, Severity::High);
        assert!(v.eta_hours.unwrap() < HIGH_HOURS);
    }

    /// Flat for most of the buffer, then a sharp climb. The whole-buffer
    /// fit dilutes the climb; the recent windows must catch it. This is
    /// the wolfstack-2 shape (2026-11-19).
    fn flat_then_climb(flat_h: i64, climb_h: i64, climb_pct_per_h: f64, start: f64) -> VecDeque<MetricSample> {
        let mut out = VecDeque::new();
        let now = Utc::now();
        let total_min = (flat_h + climb_h) * 60;
        let mut m = 0;
        while m <= total_min {
            let ts = now - Duration::minutes(total_min - m);
            let climb_min = (m - flat_h * 60).max(0) as f64;
            out.push_back(MetricSample { ts, value: start + climb_pct_per_h * climb_min / 60.0 });
            m += 5;
        }
        out
    }

    #[test]
    fn recent_climb_beats_diluted_full_window() {
        // 20 h flat at 60 %, then 4 h at +5 %/h → 80 % now, 15 points
        // to target at 5 %/h = 3 h → Critical. The full 24 h fit alone
        // would read well under 2 %/h and say High or Warn.
        let s = flat_then_climb(20, 4, 5.0, 60.0);
        let now = s.back().unwrap().value;
        let v = compute_verdict(&s, now, 95.0).expect("verdict");
        assert_eq!(v.severity, Severity::Critical, "eta {:?}", v.eta_hours);
        let full = fit_window(&s, None).expect("full fit");
        assert!(severity_from_eta((95.0 - now) / full.slope_per_hour) != Severity::Critical,
            "precondition: the whole-buffer fit alone must NOT reach Critical");
        assert!(v.slope_pct_per_hour > full.slope_per_hour * 2.0,
            "slope must come from a recent window: {} vs full {}", v.slope_pct_per_hour, full.slope_per_hour);
    }

    #[test]
    fn short_window_ignored_unless_runaway() {
        // 23 h flat at 70 %, last hour +3 %/h → 73 %: last-hour ETA to
        // 95 % = 7.3 h — not a runaway, so the short window must not
        // speak. The 6 h window sees a much gentler slope.
        let s = flat_then_climb(23, 1, 3.0, 70.0);
        let now = s.back().unwrap().value;
        let v = compute_verdict(&s, now, 95.0);
        if let Some(v) = v {
            assert!(v.eta_hours.unwrap() >= SHORT_WINDOW_MAX_ETA_HOURS,
                "a 7 h last-hour ETA must not be reported, got {:?}", v.eta_hours);
            assert_ne!(v.severity, Severity::Critical);
        }
    }

    #[test]
    fn short_window_counts_for_runaway() {
        // 23 h flat at 80 %, last hour +12 %/h → 92 %: 3 points to go at
        // 12 %/h = 15 min → must be Critical with a sub-2 h ETA.
        let s = flat_then_climb(23, 1, 12.0, 80.0);
        let now = s.back().unwrap().value;
        let v = compute_verdict(&s, now, 95.0).expect("verdict");
        assert_eq!(v.severity, Severity::Critical);
        assert!(v.eta_hours.unwrap() < SHORT_WINDOW_MAX_ETA_HOURS);
    }

    #[test]
    fn floor_scales_with_disk_size() {
        const GB: u64 = 1024 * 1024 * 1024;
        // 436 GB (wolfstack-2 root): 10 % = 43.6 GB warn, ~10.9 GB critical.
        let (w, c) = free_space_floor_bytes(436 * GB);
        assert!(w > 43 * GB && w < 44 * GB, "warn {}", w / GB);
        assert_eq!(c, w / FLOOR_CRITICAL_DIVISOR);
        // 4 TB: capped at 100 GB (warns at 97.5 % used).
        let (w, _) = free_space_floor_bytes(4096 * GB);
        assert_eq!(w, FLOOR_WARN_MAX_BYTES);
        // 30 GB: 10 % = 3 GB → raised to the 5 GB minimum.
        let (w, _) = free_space_floor_bytes(30 * GB);
        assert_eq!(w, FLOOR_WARN_MIN_BYTES);
        // 8 GB: the 5 GB minimum would be 62 % of the disk — capped at 20 %.
        let (w, _) = free_space_floor_bytes(8 * GB);
        assert_eq!(w, (8.0 * GB as f64 * FLOOR_WARN_MAX_FRACTION) as u64);
    }

    #[test]
    fn role_escalation_only_lifts_warn_to_high() {
        assert_eq!(escalate_for_role(Severity::Warn, true), Severity::High);
        assert_eq!(escalate_for_role(Severity::High, true), Severity::High);
        assert_eq!(escalate_for_role(Severity::Critical, true), Severity::Critical);
        assert_eq!(escalate_for_role(Severity::Warn, false), Severity::Warn);
    }

    #[test]
    fn humanise_minutes() {
        assert_eq!(humanise_hours(0.5), "30 min");
        assert_eq!(humanise_hours(0.0), "1 min");
        assert!(humanise_hours(2.5).contains("h"));
        assert!(humanise_hours(72.0).contains("days"));
    }
}
