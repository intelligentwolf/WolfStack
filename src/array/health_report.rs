// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Physical-disk health surfaces beyond the one-shot alert:
//!
//!   * the node's CURRENT hardware faults, published by the storage watcher
//!     in `main.rs` every tick and carried in `SystemMetrics`, so every
//!     node's dashboard can show a banner for any node whose disk is failing
//!     (the alert log is in-memory and buried in the Tasks panel — on
//!     2026-11-15 wolfstack-1's md3 mirror lost a disk and nobody saw it for
//!     eight days);
//!   * the weekly "are the disks OK" report, so silence is never mistaken for
//!     health: if the report stops arriving, the operator knows to look.
//!
//! Hardware only — physical disks and the RAID arrays built from them. Mounts
//! (NFS, S3, Gluster, …) are deliberately out of scope here.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// One thing wrong with this node's disk hardware right now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareFault {
    /// "critical" or "warning".
    pub severity: String,
    pub title: String,
    pub detail: String,
}

fn faults_cell() -> &'static std::sync::RwLock<Vec<HardwareFault>> {
    static FAULTS: std::sync::OnceLock<std::sync::RwLock<Vec<HardwareFault>>> =
        std::sync::OnceLock::new();
    FAULTS.get_or_init(|| std::sync::RwLock::new(Vec::new()))
}

/// Replace the published fault set. Called by the storage watcher once per
/// tick with everything it currently sees wrong, so a repaired disk clears.
pub fn publish_hardware_faults(faults: Vec<HardwareFault>) {
    let mut g = faults_cell().write().unwrap_or_else(|e| e.into_inner());
    *g = faults;
}

/// The fault set as of the watcher's last tick. Empty until the first tick.
pub fn hardware_faults() -> Vec<HardwareFault> {
    faults_cell().read().unwrap_or_else(|e| e.into_inner()).clone()
}

// ─── Weekly report ───

pub const WEEKLY_REPORT_INTERVAL_SECS: u64 = 7 * 86_400;

#[derive(Serialize, Deserialize, Default)]
struct ReportState {
    #[serde(default)]
    last_sent: u64,
}

fn report_state_path() -> PathBuf {
    PathBuf::from(crate::paths::get().config_dir.clone()).join("disk-health-report.json")
}

fn load_state() -> ReportState {
    std::fs::read_to_string(report_state_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Persisted so an agent restart neither skips a week nor re-sends.
/// A node that has never sent one is due straight away (the watcher only
/// asks on its hourly tick, so that is an hour after start).
pub fn weekly_report_due(now: u64) -> bool {
    report_due_at(load_state().last_sent, now)
}

fn report_due_at(last_sent: u64, now: u64) -> bool {
    last_sent == 0 || now.saturating_sub(last_sent) >= WEEKLY_REPORT_INTERVAL_SECS
}

pub fn mark_weekly_report_sent(now: u64) {
    let Ok(json) = serde_json::to_string_pretty(&ReportState { last_sent: now }) else { return };
    let path = report_state_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = crate::paths::write_secure(&path.to_string_lossy(), json) {
        tracing::warn!("could not persist disk health report state: {e}");
    }
}

/// What the report says about one physical disk.
pub struct ReportDisk {
    pub device: String,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub size_bytes: u64,
    pub smart: Option<super::DiskSmart>,
}

/// Identify each disk (lsblk) for the report. Blocking: shells out.
pub fn report_disks(phys: &[(String, super::SmartCheck)]) -> Vec<ReportDisk> {
    phys.iter()
        .map(|(dev, check)| {
            let info = super::lsblk_disk_info(dev);
            ReportDisk {
                device: dev.clone(),
                model: info.as_ref().and_then(|i| i.model.clone()),
                serial: info.as_ref().and_then(|i| i.serial.clone()),
                size_bytes: info.as_ref().map(|i| i.size_bytes).unwrap_or(0),
                smart: check.smart.clone(),
            }
        })
        .collect()
}

/// Decimal GB/TB, matching what drive vendors print on the label.
fn fmt_size(bytes: u64) -> String {
    let gb = bytes as f64 / 1e9;
    if gb >= 1000.0 { format!("{:.1} TB", gb / 1000.0) } else { format!("{:.0} GB", gb) }
}

/// Build the weekly report's (title, body). Pure, so it is unit-tested.
pub fn build_weekly_report(
    disks: &[ReportDisk],
    arrays: &[super::Array],
    faults: &[HardwareFault],
) -> (String, String) {
    let unread = disks.iter().filter(|d| d.smart.is_none()).count();
    let checked = disks.len() - unread;
    let title = if !faults.is_empty() {
        format!("Weekly disk check: {} {} attention",
            faults.len(), if faults.len() == 1 { "problem needs" } else { "problems need" })
    } else if checked == 0 {
        "Weekly disk check: no disk health data on this node".to_string()
    } else {
        format!("Weekly disk check: all {} disk{} healthy",
            checked, if checked == 1 { "" } else { "s" })
    };

    let mut body = String::new();
    if !faults.is_empty() {
        body.push_str("PROBLEMS\n");
        for f in faults {
            body.push_str(&format!("  - {}: {}\n", f.title, f.detail));
        }
        body.push('\n');
    }

    body.push_str("PHYSICAL DISKS\n");
    if disks.is_empty() {
        body.push_str("  (none found)\n");
    }
    for d in disks {
        let ident = match (&d.model, &d.serial) {
            (Some(m), Some(s)) => format!("{m} (serial {s})"),
            (Some(m), None) => m.clone(),
            (None, Some(s)) => format!("serial {s}"),
            (None, None) => "unknown model".to_string(),
        };
        let size = if d.size_bytes > 0 { format!(", {}", fmt_size(d.size_bytes)) } else { String::new() };
        let state = match &d.smart {
            None => "no health data (virtual disk, or a controller that hides SMART) — not checked".to_string(),
            Some(s) => {
                let reasons = s.failing_reasons();
                let mut parts = vec![if reasons.is_empty() {
                    "healthy".to_string()
                } else {
                    format!("FAILING — {}", reasons.join("; "))
                }];
                if let Some(t) = s.temperature_c { parts.push(format!("{t}°C")); }
                if let Some(h) = s.power_on_hours { parts.push(format!("{} days powered on", h / 24)); }
                if let Some(u) = s.nvme_pct_used { parts.push(format!("{u}% of rated endurance used")); }
                parts.join(", ")
            }
        };
        body.push_str(&format!("  - {} — {}{}: {}\n", d.device, ident, size, state));
    }

    if !arrays.is_empty() {
        body.push_str("\nRAID ARRAYS\n");
        for a in arrays {
            let members = a.disks.iter()
                .map(|d| format!("{} {}", d.device, d.state))
                .collect::<Vec<_>>()
                .join(", ");
            let state = if a.state == "degraded" { "DEGRADED".to_string() } else { a.state.clone() };
            body.push_str(&format!("  - /dev/{} ({}): {} — members: {}\n",
                a.name, a.level, state, if members.is_empty() { "none".into() } else { members }));
        }
    }

    body.push_str("\nThis report is sent once a week so that silence never passes for health. \
If it stops arriving, check this node.\n");
    (title, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(dev: &str, smart: Option<crate::array::DiskSmart>) -> ReportDisk {
        ReportDisk {
            device: dev.into(),
            model: Some("SAMSUNG MZVL2512HCJQ-00B00".into()),
            serial: Some("S675".into()),
            size_bytes: 512_110_190_592,
            smart,
        }
    }

    fn healthy() -> crate::array::DiskSmart {
        crate::array::DiskSmart {
            passed: Some(true),
            temperature_c: Some(38),
            power_on_hours: Some(24 * 100),
            ..Default::default()
        }
    }

    #[test]
    fn all_healthy_says_so_and_counts_only_checked_disks() {
        let (title, body) = build_weekly_report(
            &[disk("/dev/nvme0n1", Some(healthy())), disk("/dev/vda", None)], &[], &[]);
        assert_eq!(title, "Weekly disk check: all 1 disk healthy");
        assert!(body.contains("/dev/nvme0n1 — SAMSUNG MZVL2512HCJQ-00B00 (serial S675), 512 GB: healthy, 38°C, 100 days powered on"));
        assert!(body.contains("/dev/vda") && body.contains("not checked"));
        assert!(!body.contains("PROBLEMS"));
    }

    #[test]
    fn faults_lead_the_report() {
        let faults = vec![HardwareFault {
            severity: "critical".into(),
            title: "Array degraded: /dev/md3".into(),
            detail: "level=raid1 disks=[/dev/nvme2n1(active)]".into(),
        }];
        let arr = crate::array::Array {
            name: "md3".into(), level: "raid1".into(), state: "degraded".into(),
            sync_progress: None, sync_speed_kbs: None, disks: vec![],
            size_bytes: 0, used_bytes: 0, backend: "mdadm".into(),
        };
        let (title, body) = build_weekly_report(&[disk("/dev/nvme2n1", Some(healthy()))], &[arr], &faults);
        assert_eq!(title, "Weekly disk check: 1 problem needs attention");
        assert!(body.starts_with("PROBLEMS\n  - Array degraded: /dev/md3"));
        assert!(body.contains("/dev/md3 (raid1): DEGRADED"));
    }

    #[test]
    fn failing_disk_is_named_failing() {
        let bad = crate::array::DiskSmart { passed: Some(false), ..Default::default() };
        let (_, body) = build_weekly_report(&[disk("/dev/sda", Some(bad))], &[], &[]);
        assert!(body.contains("/dev/sda") && body.contains("FAILING"));
    }

    #[test]
    fn no_readable_disks_is_not_reported_as_healthy() {
        let (title, _) = build_weekly_report(&[disk("/dev/vda", None)], &[], &[]);
        assert_eq!(title, "Weekly disk check: no disk health data on this node");
    }

    #[test]
    fn due_when_never_sent_or_a_week_has_passed() {
        assert!(report_due_at(0, 1_000));
        assert!(!report_due_at(1_000, 1_000 + WEEKLY_REPORT_INTERVAL_SECS - 1));
        assert!(report_due_at(1_000, 1_000 + WEEKLY_REPORT_INTERVAL_SECS));
    }
}
