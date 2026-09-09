// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Point-in-time threshold checks — convergence A.
//!
//! Replaces the duplicated threshold logic that lived in three
//! places before this delta:
//!
//! - `api::collect_issues` (Issues page)
//! - `alerting::check_thresholds` (Discord/Slack/email dispatch)
//! - implicit duplication in `security.rs`'s posture scan
//!
//! All three checked the same conditions (CPU/mem/disk/swap/load/
//! failed-systemd) with slightly different thresholds and surfaced
//! to different UIs. This module is the single source of truth.
//!
//! ## Convergence behaviour
//!
//! - `collect_issues` becomes a thin shim that reads the predictive
//!   ProposalStore and converts threshold-class findings into the
//!   legacy `Issue` shape (so the Issues page keeps working during
//!   the migration window).
//! - `alerting::check_thresholds` retires; the orchestrator's
//!   first-appearance notification dispatch fires the same channels
//!   when a Critical/High threshold proposal first lands.
//! - One sample per condition per tick (5 min cadence). The
//!   high-frequency CPU/mem feed in `cached_status_bg` (every 2 s)
//!   stays — that's for live UI charts, not for findings.
//!
//! ## Thresholds (preserved from `collect_issues`)
//!
//! | Metric         | Warn   | Critical |
//! |----------------|--------|----------|
//! | CPU usage      | 75 %   | 90 %     |
//! | Memory usage   | 80 %   | 90 %     |
//! | Disk free      | <10 GB | <2 GB    |
//! | Swap usage     | 50 %   | —        |
//! | Load × CPU     | 1.0×   | 2.0×     |
//! | Failed systemd | warn   | —        |
//!
//! Disk uses *free GB* not percent because a 10 TB disk at 95 % is
//! "500 GB free, fine for hours" while a 32 GB root at 95 % is
//! "1.6 GB free, urgent".

use std::time::Duration;

use crate::predictive::{
    Context,
    proposal::{
        Evidence, Proposal, ProposalScope, ProposalSource, RemediationPlan, Severity,
    },
    ack::AckStore,
};

pub const FINDING_HOST_CPU: &str = "host_cpu_high";
pub const FINDING_HOST_MEMORY: &str = "host_memory_high";
pub const FINDING_HOST_DISK_FREE: &str = "host_disk_low_free";
pub const FINDING_HOST_SWAP: &str = "host_swap_high";
pub const FINDING_HOST_LOAD: &str = "host_load_high";
pub const FINDING_SYSTEMD_FAILED: &str = "systemd_unit_failed";

const CPU_WARN: f32 = 75.0;
const CPU_CRITICAL: f32 = 90.0;
const MEM_WARN: f32 = 80.0;
const MEM_CRITICAL: f32 = 90.0;
const DISK_FREE_WARN_GB: f64 = 10.0;
const DISK_FREE_CRITICAL_GB: f64 = 2.0;
const SWAP_WARN_PCT: f64 = 50.0;
const LOAD_WARN_MULT: f64 = 1.0;     // load > cpu_count
const LOAD_CRITICAL_MULT: f64 = 2.0; // load > 2 × cpu_count

/// Stable scope-resource id for a node-level finding (CPU, mem,
/// swap, load). Per-mount disk findings use the mount as the
/// resource_id; per-unit systemd uses the unit name.
const NODE_RESOURCE: &str = "host";

/// Failed systemd units, plus whether we actually got to ask.
///
/// The distinction matters for auto-resolve: an empty `units` with
/// `scanned == true` means "systemd reports nothing failed", which lets a
/// previously-flagged unit's finding clear (the operator fixed it, or ran
/// `systemctl reset-failed`). An empty `units` with `scanned == false` means
/// we never got an answer — no systemd (Unraid), `systemctl` missing, or the
/// call timed out — and must NOT be read as "everything is fine now".
/// Conflating the two left a repaired unit's finding in the inbox for ever,
/// because `covered_scopes` only ever covered units that were *currently*
/// failing.
#[derive(Debug, Clone, Default)]
pub struct FailedUnitsFacts {
    pub units: Vec<String>,
    pub scanned: bool,
}

/// Sample failed systemd units. `scanned` is false if `systemctl` errors or
/// isn't present.
pub fn sample_failed_systemd_units_now() -> FailedUnitsFacts {
    let out = match std::process::Command::new("systemctl")
        .args(["--failed", "--no-legend", "--plain"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return FailedUnitsFacts::default(),
    };
    let units = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .collect();
    FailedUnitsFacts { units, scanned: true }
}

/// Async timeout-bounded variant. A timeout yields `scanned == false` —
/// stuck systemd is exactly the case where we must not conclude anything.
pub async fn sample_failed_systemd_units_now_async(timeout: Duration) -> FailedUnitsFacts {
    let fut = tokio::task::spawn_blocking(sample_failed_systemd_units_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(v)) => v,
        _ => FailedUnitsFacts::default(),
    }
}

/// Run the threshold analyzer.
pub fn analyze(
    ctx: &Context,
    metrics: &crate::monitoring::SystemMetrics,
    failed_units: &FailedUnitsFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();

    // Honour the operator's Settings → Alerts event toggles. These default to
    // true, so an existing install with default config behaves EXACTLY as
    // before; turning "High CPU alert" / "High memory alert" / disk off now
    // actually suppresses the finding (previously these toggles were wired to
    // the retired legacy loop, not this engine — wabil 2026-06-21). A finding
    // already in the Inbox auto-resolves on the next tick because the scope
    // stays "covered" but is no longer emitted.
    let acfg = crate::alerting::AlertConfig::load();

    // ── CPU ──
    if acfg.alert_cpu
        && let Some(p) = check_cpu(ctx, metrics, acks, proposals) { out.push(p); }
    // ── Memory ──
    if acfg.alert_memory
        && let Some(p) = check_memory(ctx, metrics, acks, proposals) { out.push(p); }
    // ── Per-mount disk free space ──
    if acfg.alert_disk {
        out.extend(check_disks(ctx, metrics, acks, proposals));
    }
    // ── Swap ──
    if let Some(p) = check_swap(ctx, metrics, acks, proposals) { out.push(p); }
    // ── Load ──
    if let Some(p) = check_load(ctx, metrics, acks, proposals) { out.push(p); }
    // ── Failed systemd units ──
    out.extend(check_failed_units(ctx, &failed_units.units, acks, proposals));

    out
}

/// "Covered" scopes for auto-resolve. Threshold checks evaluate the
/// same set every tick (CPU, memory, swap, load — node-scoped) plus
/// every currently-mounted disk + every CURRENTLY-failing systemd
/// unit. Without this, a CPU spike that subsides would leave its
/// proposal stuck Pending until the 90-day prune.
///
/// Note what the systemd line does NOT cover: a unit that has stopped
/// failing drops out of `failed_units`, so its finding is no longer covered
/// here and `auto_resolve_cleared` can't clear it. (The comment here used to
/// claim "every previously-emitted systemd unit", which was never true.)
/// That case is closed by the orchestrator, which feeds
/// `proposal::vanished_scopes` with `failed_units.scanned` — the flag
/// that separates "systemd says nothing is failing" from "we never got an
/// answer".
pub fn covered_scopes(
    ctx: &Context,
    metrics: &crate::monitoring::SystemMetrics,
    failed_units: &FailedUnitsFacts,
) -> Vec<(String, ProposalScope)> {
    let node_scope = || ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some(NODE_RESOURCE.into()),
    };
    let mut out = vec![
        (FINDING_HOST_CPU.into(), node_scope()),
        (FINDING_HOST_MEMORY.into(), node_scope()),
        (FINDING_HOST_SWAP.into(), node_scope()),
        (FINDING_HOST_LOAD.into(), node_scope()),
    ];
    for d in &metrics.disks {
        if should_skip_disk(d) { continue; }
        out.push((
            FINDING_HOST_DISK_FREE.into(),
            ProposalScope {
                node_id: ctx.node_id.clone(),
                resource_id: Some(d.mount_point.clone()),
            },
        ));
    }
    for unit in &failed_units.units {
        out.push((
            FINDING_SYSTEMD_FAILED.into(),
            ProposalScope {
                node_id: ctx.node_id.clone(),
                resource_id: Some(unit.clone()),
            },
        ));
    }
    out
}

// ── Individual checks ───────────────────────────────────────────

fn check_cpu(
    ctx: &Context,
    metrics: &crate::monitoring::SystemMetrics,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Option<Proposal> {
    let pct = metrics.cpu_usage_percent;
    let sev = if pct >= CPU_CRITICAL { Severity::Critical }
        else if pct >= CPU_WARN { Severity::Warn }
        else { return None; };
    let scope = ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some(NODE_RESOURCE.into()),
    };
    if acks.suppresses(FINDING_HOST_CPU, &scope) { return None; }
    if proposals.is_suppressed(FINDING_HOST_CPU, &scope) { return None; }

    Some(Proposal::new(
        FINDING_HOST_CPU, ProposalSource::Rule, sev,
        format!("CPU usage at {:.1}%", pct),
        format!(
            "CPU is at {:.1}% — the system may be unresponsive to \
             new requests. Sustained > 90 % indicates a runaway \
             process; sustained > 75 % is worth investigating before \
             it gets worse.",
            pct,
        ),
        vec![Evidence {
            label: "CPU usage".into(),
            value: format!("{:.1}%", pct),
            detail: Some(format!(
                "Load average: {:.2} / {:.2} / {:.2} ({} CPUs)",
                metrics.load_avg.one, metrics.load_avg.five,
                metrics.load_avg.fifteen, metrics.cpu_count,
            )),
            links: Vec::new(),
        }],
        RemediationPlan::Manual {
            instructions: "Identify the largest CPU consumers and \
                decide whether they're expected (a build job, an \
                analysis run) or runaway. Bound long-running tasks \
                with `nice` / cgroups if they're stealing capacity \
                from the foreground.".into(),
            commands: vec![
                "ps aux --sort=-pcpu | head -20".into(),
                "top -bn1 -o %CPU | head -20".into(),
            ],
        },
        scope,
    ))
}

fn check_memory(
    ctx: &Context,
    metrics: &crate::monitoring::SystemMetrics,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Option<Proposal> {
    let pct = metrics.memory_percent;
    let sev = if pct >= MEM_CRITICAL { Severity::Critical }
        else if pct >= MEM_WARN { Severity::Warn }
        else { return None; };
    let scope = ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some(NODE_RESOURCE.into()),
    };
    if acks.suppresses(FINDING_HOST_MEMORY, &scope) { return None; }
    if proposals.is_suppressed(FINDING_HOST_MEMORY, &scope) { return None; }

    let used_gb = metrics.memory_used_bytes as f64 / 1_073_741_824.0;
    let total_gb = metrics.memory_total_bytes as f64 / 1_073_741_824.0;

    Some(Proposal::new(
        FINDING_HOST_MEMORY, ProposalSource::Rule, sev,
        format!("Memory usage at {:.1}%", pct),
        format!(
            "Memory is at {:.1}% ({:.1} GB used of {:.1} GB). At >90 % \
             the OOM killer may start terminating processes; sustained \
             >80 % means the system is one big workload away from \
             swapping or OOMing.",
            pct, used_gb, total_gb,
        ),
        vec![Evidence {
            label: "Memory".into(),
            value: format!("{:.1}%", pct),
            detail: Some(format!("{:.1} GB used of {:.1} GB", used_gb, total_gb)),
            links: Vec::new(),
        }],
        RemediationPlan::Manual {
            instructions: "Identify the largest memory consumers and \
                whether they're expected. Containers without memory \
                limits can grow until they OOM the host; setting \
                `--memory` (Docker) or cgroup limits (LXC) caps the \
                blast radius.".into(),
            commands: vec![
                "ps aux --sort=-rss | head -20".into(),
                "free -h".into(),
                "docker stats --no-stream --format 'table {{.Name}}\\t{{.MemPerc}}\\t{{.MemUsage}}' 2>/dev/null".into(),
            ],
        },
        scope,
    ))
}

fn should_skip_disk(d: &crate::monitoring::DiskMetrics) -> bool {
    // /boot is owned by the dedicated `boot_partition` analyzer,
    // which sizes its free-space floor from the kernels actually on
    // the partition (2× the largest kernel set) instead of a flat
    // >99 % rule. The old rule alerted only once /boot was already
    // effectively full — wolf1 (2026-08-01) reached 100 % with nine
    // kernels and dpkg failed mid-unpack before any warning fired.
    // The generic GB thresholds below would misfire the other way: a
    // healthy 975 MB /boot always has <2 GB free and would page
    // Critical forever. So the generic check skips /boot entirely.
    if d.mount_point.starts_with("/boot") { return true; }
    // /etc/pve is pmxcfs (a tiny FUSE config fs managed by Proxmox):
    // only flag it at >99 %.
    d.mount_point == "/etc/pve" && d.usage_percent <= 99.0
}

fn check_disks(
    ctx: &Context,
    metrics: &crate::monitoring::SystemMetrics,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    for d in &metrics.disks {
        if should_skip_disk(d) { continue; }
        let free_gb = d.available_bytes as f64 / 1_073_741_824.0;
        let sev = if free_gb < DISK_FREE_CRITICAL_GB { Severity::Critical }
            else if free_gb < DISK_FREE_WARN_GB { Severity::Warn }
            else { continue; };
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(d.mount_point.clone()),
        };
        if acks.suppresses(FINDING_HOST_DISK_FREE, &scope) { continue; }
        if proposals.is_suppressed(FINDING_HOST_DISK_FREE, &scope) { continue; }

        let total_gb = d.total_bytes as f64 / 1_073_741_824.0;
        let used_gb = d.used_bytes as f64 / 1_073_741_824.0;

        out.push(Proposal::new(
            FINDING_HOST_DISK_FREE, ProposalSource::Rule, sev,
            format!("{} has {:.1} GB free", d.mount_point, free_gb),
            format!(
                "{} has {:.1} GB free of {:.1} GB total ({:.1}% used). \
                 Below 2 GB free, services that buffer to disk may \
                 fail unpredictably.",
                d.mount_point, free_gb, total_gb, d.usage_percent,
            ),
            vec![
                Evidence {
                    label: "Free".into(),
                    value: format!("{:.1} GB", free_gb),
                    detail: Some(format!(
                        "{:.1} GB used / {:.1} GB total ({:.1}%)",
                        used_gb, total_gb, d.usage_percent,
                    )),
                    links: Vec::new(),
                },
                Evidence {
                    label: "Filesystem".into(),
                    value: d.fs_type.clone(),
                    detail: Some(d.name.clone()),
                    links: Vec::new(),
                },
            ],
            RemediationPlan::Manual {
                instructions: format!(
                    "Find the largest consumers under {} and decide \
                     what to archive or remove. The trend-based \
                     disk-fill analyzer will already have surfaced \
                     this if it's been growing for a while; this \
                     point-in-time check catches the case where free \
                     space drops suddenly (failed log rotation, \
                     runaway dump, etc.).",
                    d.mount_point,
                ),
                commands: vec![
                    format!("sudo du -h --max-depth=1 {} 2>/dev/null | sort -h | tail -20", d.mount_point),
                    format!("df -h {}", d.mount_point),
                ],
            },
            scope,
        ));
    }
    out
}

fn check_swap(
    ctx: &Context,
    metrics: &crate::monitoring::SystemMetrics,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Option<Proposal> {
    if metrics.swap_total_bytes == 0 { return None; }
    let pct = (metrics.swap_used_bytes as f64 / metrics.swap_total_bytes as f64) * 100.0;
    if pct < SWAP_WARN_PCT { return None; }

    let scope = ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some(NODE_RESOURCE.into()),
    };
    if acks.suppresses(FINDING_HOST_SWAP, &scope) { return None; }
    if proposals.is_suppressed(FINDING_HOST_SWAP, &scope) { return None; }

    let used_gb = metrics.swap_used_bytes as f64 / 1_073_741_824.0;
    let total_gb = metrics.swap_total_bytes as f64 / 1_073_741_824.0;

    Some(Proposal::new(
        FINDING_HOST_SWAP, ProposalSource::Rule, Severity::Warn,
        format!("Swap usage at {:.0}%", pct),
        format!(
            "{:.1} GB of {:.1} GB swap is in use ({:.0}%). Heavy swap \
             usage usually means RAM pressure earlier — even if memory \
             usage isn't at threshold now, the system has been pushed \
             far enough to evict pages.",
            used_gb, total_gb, pct,
        ),
        vec![Evidence {
            label: "Swap".into(),
            value: format!("{:.0}%", pct),
            detail: Some(format!("{:.1} GB used of {:.1} GB", used_gb, total_gb)),
            links: Vec::new(),
        }],
        RemediationPlan::Manual {
            instructions: "Identify which processes are holding pages \
                in swap and whether the host needs more RAM, tighter \
                container memory limits, or a closer look at the \
                memory leak suspect.".into(),
            commands: vec![
                "smem -t -k -p -c \"name pss rss swap\" -P '^(?!.*kernel)' 2>/dev/null | sort -k4 | tail -20".into(),
                "for p in /proc/*/status; do awk '/VmSwap|Name/{printf $2 \" \" $3 \"|\"}END{ print \"\"}' $p 2>/dev/null; done | sort -k2 -n -t'|' | tail -20".into(),
            ],
        },
        scope,
    ))
}

fn check_load(
    ctx: &Context,
    metrics: &crate::monitoring::SystemMetrics,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Option<Proposal> {
    let cpu_count = metrics.cpu_count.max(1) as f64;
    let load1 = metrics.load_avg.one;
    let mult = load1 / cpu_count;
    let sev = if mult >= LOAD_CRITICAL_MULT { Severity::Critical }
        else if mult >= LOAD_WARN_MULT { Severity::Warn }
        else { return None; };
    let scope = ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some(NODE_RESOURCE.into()),
    };
    if acks.suppresses(FINDING_HOST_LOAD, &scope) { return None; }
    if proposals.is_suppressed(FINDING_HOST_LOAD, &scope) { return None; }

    Some(Proposal::new(
        FINDING_HOST_LOAD, ProposalSource::Rule, sev,
        format!("Load average {:.2} ({:.1}× CPU count)", load1, mult),
        format!(
            "1-minute load average is {:.2} on a {}-CPU host \
             ({:.1}× capacity). Sustained load > N CPUs means runnable \
             tasks are queuing for CPU time. Above 2× CPUs the system \
             may not catch up without intervention.",
            load1, metrics.cpu_count, mult,
        ),
        vec![Evidence {
            label: "Load (1/5/15)".into(),
            value: format!("{:.2} / {:.2} / {:.2}",
                metrics.load_avg.one, metrics.load_avg.five, metrics.load_avg.fifteen),
            detail: Some(format!("{} CPUs, ratio {:.1}×", metrics.cpu_count, mult)),
            links: Vec::new(),
        }],
        RemediationPlan::Manual {
            instructions: "Top the runnable-task queue and check for \
                I/O-bound waits — high load with low CPU usually means \
                disk or network I/O is the bottleneck.".into(),
            commands: vec![
                "uptime".into(),
                "ps -eo pid,user,stat,pcpu,comm | awk '$3 ~ /R|D/' | head -20".into(),
                "iostat -xz 2 3 2>/dev/null".into(),
            ],
        },
        scope,
    ))
}

fn check_failed_units(
    ctx: &Context,
    failed_units: &[String],
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    failed_units.iter().filter_map(|unit| {
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(unit.clone()),
        };
        if acks.suppresses(FINDING_SYSTEMD_FAILED, &scope) { return None; }
        if proposals.is_suppressed(FINDING_SYSTEMD_FAILED, &scope) { return None; }

        Some(Proposal::new(
            FINDING_SYSTEMD_FAILED, ProposalSource::Rule, Severity::Warn,
            format!("Systemd unit '{}' failed", unit),
            format!(
                "{} is in `failed` state per `systemctl --failed`. \
                 The unit either crashed unexpectedly or hit its \
                 RestartLimit. The journal carries the cause.",
                unit,
            ),
            vec![Evidence {
                label: "Unit".into(),
                value: unit.clone(),
                detail: None,
                links: Vec::new(),
            }],
            RemediationPlan::Manual {
                instructions: format!(
                    "Inspect the journal for {} and decide whether to \
                     restart, fix configuration, or mask the unit.",
                    unit,
                ),
                commands: vec![
                    format!("systemctl status {}", unit),
                    format!("journalctl -u {} -n 100 --no-pager", unit),
                    format!("sudo systemctl reset-failed {}    # if you've fixed it", unit),
                ],
            },
            scope,
        ))
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predictive::NetworkSnapshot;
    use crate::predictive::proposal::ProposalStore;
    use crate::monitoring::{DiskMetrics, LoadAverage, SystemMetrics};

    fn ctx() -> Context {
        Context {
            node_id: "node-a".into(),
            network: NetworkSnapshot::from_parts(vec![], vec![]),
        }
    }

    fn metrics(cpu: f32, mem: f32, free_gb: f64, total_gb: f64) -> SystemMetrics {
        SystemMetrics {
            hostname: "test".into(),
            uptime_secs: 0,
            cpu_usage_percent: cpu,
            cpu_count: 4,
            cpu_model: "test".into(),
            memory_total_bytes: 16 * 1_073_741_824,
            memory_used_bytes: ((mem as f64 / 100.0) * 16.0 * 1_073_741_824.0) as u64,
            memory_percent: mem,
            swap_total_bytes: 0,
            swap_used_bytes: 0,
            disks: vec![DiskMetrics {
                name: "test".into(),
                mount_point: "/".into(),
                fs_type: "ext4".into(),
                total_bytes: (total_gb * 1_073_741_824.0) as u64,
                used_bytes: ((total_gb - free_gb) * 1_073_741_824.0) as u64,
                available_bytes: (free_gb * 1_073_741_824.0) as u64,
                usage_percent: ((total_gb - free_gb) / total_gb * 100.0) as f32,
            }],
            network: vec![],
            load_avg: LoadAverage { one: 1.0, five: 1.0, fifteen: 1.0 },
            processes: 100,
            os_name: None, os_version: None, kernel_version: None,
            hardware_tier: "low".into(),
        }
    }

    // ── CPU ──

    #[test]
    fn cpu_below_warn_silent() {
        let m = metrics(50.0, 10.0, 100.0, 200.0);
        let p = analyze(&ctx(), &m, &FailedUnitsFacts::default(), &AckStore::default(), &ProposalStore::default());
        assert!(p.iter().all(|x| x.finding_type != FINDING_HOST_CPU));
    }

    #[test]
    fn cpu_warn_threshold() {
        let m = metrics(80.0, 10.0, 100.0, 200.0);
        let p = analyze(&ctx(), &m, &FailedUnitsFacts::default(), &AckStore::default(), &ProposalStore::default());
        let cpu = p.iter().find(|x| x.finding_type == FINDING_HOST_CPU).expect("cpu");
        assert_eq!(cpu.severity, Severity::Warn);
    }

    #[test]
    fn cpu_critical_threshold() {
        let m = metrics(95.0, 10.0, 100.0, 200.0);
        let p = analyze(&ctx(), &m, &FailedUnitsFacts::default(), &AckStore::default(), &ProposalStore::default());
        let cpu = p.iter().find(|x| x.finding_type == FINDING_HOST_CPU).expect("cpu");
        assert_eq!(cpu.severity, Severity::Critical);
    }

    // ── Memory + disk ──

    #[test]
    fn disk_low_free_critical() {
        let m = metrics(10.0, 10.0, 1.0, 200.0); // 1 GB free
        let p = analyze(&ctx(), &m, &FailedUnitsFacts::default(), &AckStore::default(), &ProposalStore::default());
        let d = p.iter().find(|x| x.finding_type == FINDING_HOST_DISK_FREE).expect("disk");
        assert_eq!(d.severity, Severity::Critical);
    }

    #[test]
    fn disk_low_free_warn() {
        let m = metrics(10.0, 10.0, 5.0, 200.0); // 5 GB free
        let p = analyze(&ctx(), &m, &FailedUnitsFacts::default(), &AckStore::default(), &ProposalStore::default());
        let d = p.iter().find(|x| x.finding_type == FINDING_HOST_DISK_FREE).expect("disk");
        assert_eq!(d.severity, Severity::Warn);
    }

    #[test]
    fn disk_skips_boot_below_99() {
        let mut m = metrics(10.0, 10.0, 100.0, 200.0);
        m.disks.push(DiskMetrics {
            name: "boot".into(),
            mount_point: "/boot".into(),
            fs_type: "vfat".into(),
            total_bytes: 1_000_000_000,
            used_bytes:    900_000_000,
            available_bytes: 100_000_000,
            usage_percent: 90.0,
        });
        let p = analyze(&ctx(), &m, &FailedUnitsFacts::default(), &AckStore::default(), &ProposalStore::default());
        // /boot never fires from the GENERIC check — the dedicated
        // boot_partition analyzer owns it.
        assert!(p.iter().all(|x|
            x.scope.resource_id.as_deref() != Some("/boot")
        ));
    }

    /// Even a 100 %-full /boot stays out of the generic GB check —
    /// its <2 GB free would otherwise page Critical with the WRONG
    /// message (generic "free GB" advice, no kernel-purge safety
    /// warning). boot_partition::analyze carries the correct finding.
    #[test]
    fn disk_skips_boot_even_at_100_pct() {
        let mut m = metrics(10.0, 10.0, 100.0, 200.0);
        m.disks.push(DiskMetrics {
            name: "boot".into(),
            mount_point: "/boot".into(),
            fs_type: "ext4".into(),
            total_bytes: 1_000_000_000,
            used_bytes:  1_000_000_000,
            available_bytes: 0,
            usage_percent: 100.0,
        });
        let p = analyze(&ctx(), &m, &FailedUnitsFacts::default(), &AckStore::default(), &ProposalStore::default());
        assert!(p.iter().all(|x|
            x.scope.resource_id.as_deref() != Some("/boot")
        ));
    }

    // ── Load ──

    #[test]
    fn load_critical_at_2x_cpus() {
        let mut m = metrics(10.0, 10.0, 100.0, 200.0);
        m.load_avg = LoadAverage { one: 9.0, five: 8.0, fifteen: 7.0 }; // 2.25× 4 CPUs
        let p = analyze(&ctx(), &m, &FailedUnitsFacts::default(), &AckStore::default(), &ProposalStore::default());
        let l = p.iter().find(|x| x.finding_type == FINDING_HOST_LOAD).expect("load");
        assert_eq!(l.severity, Severity::Critical);
    }

    // ── Suppression ──

    #[test]
    fn ack_suppresses_finding() {
        let m = metrics(95.0, 10.0, 100.0, 200.0);
        let mut acks = AckStore::default();
        acks.add(crate::predictive::ack::Ack::new(
            FINDING_HOST_CPU,
            crate::predictive::ack::AckScope::Resource {
                node_id: "node-a".into(),
                resource_id: NODE_RESOURCE.into(),
            },
            "compile box, expected to peg CPU",
            "paul", None,
        ));
        let p = analyze(&ctx(), &m, &FailedUnitsFacts::default(), &acks, &ProposalStore::default());
        assert!(p.iter().all(|x| x.finding_type != FINDING_HOST_CPU),
            "ack must silence the CPU finding");
    }

    /// Failed systemd units produce per-unit findings.
    #[test]
    fn one_finding_per_failed_unit() {
        let m = metrics(10.0, 10.0, 100.0, 200.0);
        let units = FailedUnitsFacts {
            units: vec!["wolfstack.service".to_string(), "broken.timer".to_string()],
            scanned: true,
        };
        let p = analyze(&ctx(), &m, &units, &AckStore::default(), &ProposalStore::default());
        let failed: Vec<_> = p.iter().filter(|x| x.finding_type == FINDING_SYSTEMD_FAILED).collect();
        assert_eq!(failed.len(), 2);
    }

    /// covered_scopes always covers CPU/mem/swap/load + every
    /// currently-mounted disk, regardless of whether the analyzer
    /// flagged it. That's what makes auto-resolve work for cleared
    /// thresholds.
    #[test]
    fn covered_scopes_covers_all_node_metrics() {
        let m = metrics(10.0, 10.0, 100.0, 200.0);
        let cov = covered_scopes(&ctx(), &m, &FailedUnitsFacts::default());
        let types: Vec<&str> = cov.iter().map(|(t, _)| t.as_str()).collect();
        assert!(types.contains(&FINDING_HOST_CPU));
        assert!(types.contains(&FINDING_HOST_MEMORY));
        assert!(types.contains(&FINDING_HOST_SWAP));
        assert!(types.contains(&FINDING_HOST_LOAD));
        assert!(types.contains(&FINDING_HOST_DISK_FREE));
    }

    /// Analyzer can stay quiet on a healthy host.
    #[test]
    fn analyzer_can_stay_quiet() {
        let m = metrics(10.0, 10.0, 100.0, 200.0);
        let p = analyze(&ctx(), &m, &FailedUnitsFacts::default(), &AckStore::default(), &ProposalStore::default());
        assert!(p.is_empty());
    }
    /// A unit the operator has fixed must stop being reported. It drops out of
    /// `systemctl --failed`, so `covered_scopes` no longer covers it and
    /// `auto_resolve_cleared` structurally cannot clear it — the orchestrator
    /// closes that gap by feeding `vanished_scopes` the `scanned` flag. This
    /// test pins that composition; without the wiring the finding is immortal.
    #[test]
    fn a_repaired_systemd_unit_retires_when_the_scan_succeeded() {
        use crate::predictive::proposal::{
            ApprovalOutcome, ProposalStatus, ProposalSource, RemediationPlan, vanished_scopes,
        };
        let m = metrics(10.0, 10.0, 100.0, 200.0);
        let scope = ProposalScope {
            node_id: "node-a".into(),
            resource_id: Some("broken.timer".into()),
        };
        let mut store = crate::predictive::proposal::ProposalStore::default();
        store.upsert(Proposal::new(
            FINDING_SYSTEMD_FAILED, ProposalSource::Rule, Severity::Warn,
            "Systemd unit 'broken.timer' failed", "why", vec![],
            RemediationPlan::Manual { instructions: "x".into(), commands: vec![] },
            scope.clone(),
        ));

        // systemctl answered, and nothing is failing any more.
        let repaired = FailedUnitsFacts { units: vec![], scanned: true };
        let covered = covered_scopes(&ctx(), &m, &repaired);
        let vanished = vanished_scopes(
            &[FINDING_SYSTEMD_FAILED], repaired.scanned, &covered, &store, "node-a",
        );
        assert_eq!(vanished.len(), 1, "the repaired unit must be recognised as gone");
        assert_eq!(store.resolve_vanished(&vanished), 1);
        match &store.proposals[0].status {
            ProposalStatus::Approved { outcome: ApprovalOutcome::ResourceGone { .. }, .. } => {}
            other => panic!("expected ResourceGone, got {:?}", other),
        }

        // Now the safety case: systemd never answered (no systemd, timeout).
        // Identical empty unit list, but the finding must survive.
        let mut store2 = crate::predictive::proposal::ProposalStore::default();
        store2.upsert(Proposal::new(
            FINDING_SYSTEMD_FAILED, ProposalSource::Rule, Severity::Warn,
            "Systemd unit 'broken.timer' failed", "why", vec![],
            RemediationPlan::Manual { instructions: "x".into(), commands: vec![] },
            scope.clone(),
        ));
        let unknown = FailedUnitsFacts::default();
        let covered2 = covered_scopes(&ctx(), &m, &unknown);
        assert!(vanished_scopes(
            &[FINDING_SYSTEMD_FAILED], unknown.scanned, &covered2, &store2, "node-a",
        ).is_empty());
        assert!(matches!(store2.proposals[0].status, ProposalStatus::Pending));
    }
}
