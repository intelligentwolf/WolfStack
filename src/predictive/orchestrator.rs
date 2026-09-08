// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Background loop that drives the predictive pipeline.
//!
//! Cadence is 5 minutes — short enough that a runaway disk-fill
//! shows up before bed-time, long enough that the linear-fit window
//! covers ≥30 min of real growth before a proposal can fire (the
//! analyzer requires `MIN_SAMPLES = 3` and `MIN_SPAN_MINUTES = 30`).
//!
//! Each tick:
//!   1. Sample disks via `df`
//!   2. Record each used-pct sample into the rolling history
//!   3. Garbage-collect history for resources that no longer exist
//!   4. Persist the history (so a restart doesn't blind us 24h)
//!   5. Run analyzers, collecting fresh proposals
//!   6. Upsert into the proposal store, persist
//!
//! Steps 1 and 4–6 do blocking I/O (subprocess + file write + lock
//! acquisition); the whole tick body runs inside `spawn_blocking` so
//! the async runtime stays responsive.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::predictive::{
    AckStore, Context, MetricsHistory, ProposalStore,
    disk_fill, container_disk, container_restart, container_memory,
    threshold, cert_expiry, backup_freshness, vm_disk, security_posture,
    vulnerability, osv, port_conflict, wolfnet_dhcp, wolfnet_reachability,
    docker_wolfnet_collision, missing_subnet_route, compromise_indicators,
    tamper_detection, threat_intel,
    unused_packages, notify, container_boot, boot_partition, boot_health, wolfnet_ip_conflict,
};

/// Cadence between ticks once the loop is running.
pub const TICK_INTERVAL: Duration = Duration::from_secs(300);

/// Initial wait before the first tick. Spreads load away from the
/// startup window — many other background tasks are also kicking off
/// in the first minute.
pub const STARTUP_DELAY: Duration = Duration::from_secs(60);

/// Hard timeout for the `df` invocation. A stuck NFS mount can make
/// `statfs(2)` block indefinitely; we'd rather skip a tick than
/// burn a worker thread forever.
const DF_TIMEOUT: Duration = Duration::from_secs(15);

/// Hard timeout for the per-container sampling fan-out. Each
/// container's cache lookup can fall through to a Docker-socket /
/// `lxc-info` call. With many containers this could add up.
const CONTAINER_SAMPLE_TIMEOUT: Duration = Duration::from_secs(20);

/// Hard timeout for `systemctl --failed` — stuck systemd is rare
/// but a hung dbus could otherwise stall the tick.
const SYSTEMD_TIMEOUT: Duration = Duration::from_secs(5);

/// Hard timeout for the container-boot sweep. Sized ABOVE the
/// sampler's own 45s internal budget (10s per container, serial) so
/// the outer guard never discards a sweep the sampler bounded itself
/// — same lesson as VULN_SAMPLE_TIMEOUT: the outer timeout must hold
/// the inner worst case or one slow container throws away the tick.
const CONTAINER_BOOT_TIMEOUT: Duration = Duration::from_secs(60);

/// Hard timeout for cert sampling. `openssl x509` per-file is cheap
/// (low ms) but the worst case if `/etc/letsencrypt/live` lives on
/// a hung NFS bind is that we're sitting in `read_dir`.
const CERT_SAMPLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Hard timeout for the full vulnerability sample (host + LXC fan-
/// out). Larger than the others because it shells out to apt/dnf per LXC
/// container AND (when trivy is installed) runs `trivy image` per unique Docker
/// image — trivy's first scan can download its vuln DB and take tens of seconds.
/// Sized to hold the inner worst case (host ≤20s + LXC ≤60s + Docker ≤90s =
/// 170s) with headroom; samplers run concurrently via `tokio::join!`, so this
/// bounds the tick's worst case (not a sum), comfortably under the 5-min
/// cadence. If this were smaller than a single inner scan, one slow scan would
/// trip the outer guard and discard the whole tick's findings.
const VULN_SAMPLE_TIMEOUT: Duration = Duration::from_secs(180);

/// Hard timeout for the OSV sampler. Inventory collection is fast
/// (local subprocess); the HTTP layer is internally rate-limited to
/// once per hour, so most ticks return cached results in under a
/// second. The first scan after a restart can take ~30s for a
/// fleet's worth of unique packages — we budget 90s as a hard cap so
/// even a slow OSV response can't blow past the 5-min cadence.
const OSV_SAMPLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Resolved (Approved/Dismissed) proposals are pruned on every
/// tick once they're older than this. Pending and active-Snoozed
/// entries are never touched. Keeps the on-disk file bounded over
/// years of operation.
const RESOLVED_RETENTION_DAYS: i64 = 90;

/// Run forever. Spawned once from `main.rs`; never returns under
/// normal operation.
pub async fn run_loop(
    proposals: Arc<RwLock<ProposalStore>>,
    acks: Arc<RwLock<AckStore>>,
    metrics: Arc<RwLock<MetricsHistory>>,
    monitor: Arc<Mutex<crate::monitoring::SystemMonitor>>,
    node_id: String,
) {
    tokio::time::sleep(STARTUP_DELAY).await;
    loop {
        tick(&proposals, &acks, &metrics, &monitor, &node_id).await;
        tokio::time::sleep(TICK_INTERVAL).await;
    }
}

/// One iteration. Public so `/api/proposals/run-now` can invoke it
/// for an immediate refresh without waiting for the 5-min cadence.
///
/// ## Lock discipline
///
/// Each lock is held for the smallest possible window. Read locks
/// are used to *clone snapshots* out of the stores, not to hold the
/// store while running analysis — otherwise a burst of API reads
/// could starve a concurrent `proposals.write()` (snooze/dismiss)
/// since `std::sync::RwLock` is not write-preferring on Linux. The
/// clones are cheap (vectors of small structs); the latency benefit
/// is real on a busy cluster.
pub async fn tick(
    proposals: &Arc<RwLock<ProposalStore>>,
    acks: &Arc<RwLock<AckStore>>,
    metrics: &Arc<RwLock<MetricsHistory>>,
    monitor: &Arc<Mutex<crate::monitoring::SystemMonitor>>,
    node_id: &str,
) {
    // 1. Sample data sources concurrently with hard timeouts. Each
    //    sampler kills its child process on timeout — stuck NFS or
    //    a wedged docker daemon can no longer hang the orchestrator.
    let (host_facts, container_facts, restart_facts, failed_units, cert_facts, mem_facts, backup_facts, vm_facts, sshd_cfg, vuln_facts, osv_facts, port_facts, wolfnet_dhcp_facts, wolfnet_reach_facts, docker_wn_collision_facts, missing_route_facts, compromise_facts, tamper_facts, threat_intel_facts, unused_pkg_facts, container_boot_facts, boot_facts, boot_health_facts, wn_conflict_facts) = tokio::join!(
        disk_fill::sample_disks_now_async(DF_TIMEOUT),
        container_disk::sample_containers_now_async(CONTAINER_SAMPLE_TIMEOUT),
        container_restart::sample_docker_restarts_now_async(CONTAINER_SAMPLE_TIMEOUT),
        threshold::sample_failed_systemd_units_now_async(SYSTEMD_TIMEOUT),
        cert_expiry::sample_certs_now_async(CERT_SAMPLE_TIMEOUT),
        container_memory::sample_container_memory_now_async(CONTAINER_SAMPLE_TIMEOUT),
        backup_freshness::sample_backup_freshness_now_async(SYSTEMD_TIMEOUT),
        vm_disk::sample_vm_disks_now_async(CERT_SAMPLE_TIMEOUT),
        security_posture::sample_sshd_config_now_async(SYSTEMD_TIMEOUT),
        vulnerability::sample_now_async(VULN_SAMPLE_TIMEOUT),
        osv::sample_now_async(OSV_SAMPLE_TIMEOUT),
        port_conflict::sample_now_async(CONTAINER_SAMPLE_TIMEOUT),
        wolfnet_dhcp::sample_now_async(SYSTEMD_TIMEOUT),
        wolfnet_reachability::sample_now_async(SYSTEMD_TIMEOUT),
        docker_wolfnet_collision::sample_now_async(CONTAINER_SAMPLE_TIMEOUT),
        missing_subnet_route::sample_now_async(SYSTEMD_TIMEOUT),
        compromise_indicators::sample_now_async(SYSTEMD_TIMEOUT),
        tamper_detection::sample_now_async(SYSTEMD_TIMEOUT),
        threat_intel::sample_now_async(VULN_SAMPLE_TIMEOUT),
        unused_packages::sample_now_async(VULN_SAMPLE_TIMEOUT),
        // Per-container `systemctl --failed` probes: 10s per container,
        // 45s sweep budget internally; dedicated outer timeout above it.
        container_boot::sample_now_async(CONTAINER_BOOT_TIMEOUT),
        // /boot kernel-headroom + orphaned-kernel facts. A dozen
        // dpkg-query calls at most (one per kernel image), bounded
        // by the same systemd-class timeout.
        boot_partition::sample_now_async(SYSTEMD_TIMEOUT),
        // Previous-boot journal + /etc/fstab: two journalctl calls and
        // one file read.
        boot_health::sample_now_async(SYSTEMD_TIMEOUT),
        // In-memory peer reports + one small status file.
        wolfnet_ip_conflict::sample_now_async(SYSTEMD_TIMEOUT),
    );
    // Sample current SystemMetrics off the shared monitor — same
    // sysinfo source as the live UI, so threshold findings line up
    // with what operators see in the live charts.
    let sys_metrics_opt: Option<crate::monitoring::SystemMetrics> = {
        let mon = monitor.clone();
        tokio::task::spawn_blocking(move || {
            mon.lock().ok().map(|mut m| m.collect())
        }).await.ok().flatten()
    };
    let no_vuln_data = vuln_facts.host_updates.is_empty()
        && vuln_facts.lxc_results.iter().all(|r| r.updates.is_empty() && r.error.is_some());
    let no_osv_data = osv_facts.findings.is_empty()
        && osv_facts.covered_targets.is_empty()
        && osv_facts.unrecognized_derivatives.is_empty();
    let no_data = host_facts.is_empty() && container_facts.is_empty()
        && restart_facts.is_empty() && cert_facts.is_empty()
        && mem_facts.is_empty() && backup_facts.is_empty()
        && vm_facts.is_empty() && sys_metrics_opt.is_none()
        && no_vuln_data && no_osv_data;
    if no_data {
        tracing::debug!("predictive tick: no usable data from any sampler");
        return;
    }

    // 2. Record + GC + prune. The retention set is the union of
    //    every resource we currently see — across host mounts,
    //    docker containers, and lxc containers.
    {
        let mut h = lock_write(metrics, "metrics");
        for f in &host_facts {
            h.record(&f.mount, disk_fill::METRIC, f.used_pct);
        }
        for f in &container_facts {
            // Container-id rotation guard: if a container was
            // destroyed and recreated under the same name we'd
            // otherwise fit a regression line through samples from
            // two different containers. `maybe_reset_history` clears
            // the affected series before the new sample is recorded.
            container_disk::maybe_reset_history(&mut h, f);
            h.record(
                &container_disk::resource_id(f.runtime, &f.name),
                container_disk::METRIC,
                f.used_pct,
            );
        }
        for f in &restart_facts {
            // Same id-rotation reset path as disk — a recreated
            // container's `RestartCount` resets to 0 and we must
            // not fit a delta across the boundary.
            container_restart::maybe_reset_history_for(&mut h, f);
            h.record(
                &container_disk::resource_id(
                    container_disk::Runtime::Docker, &f.name),
                container_restart::METRIC,
                f.restart_count as f64,
            );
        }
        let live_resources: HashSet<String> = host_facts.iter()
            .map(|f| f.mount.clone())
            .chain(container_facts.iter()
                .map(|f| container_disk::resource_id(f.runtime, &f.name)))
            .chain(restart_facts.iter()
                .map(|f| container_disk::resource_id(
                    container_disk::Runtime::Docker, &f.name)))
            .collect();
        h.retain_resources(|r| live_resources.contains(r));
        if let Err(e) = h.save() {
            tracing::warn!("predictive: failed to save metrics history: {}", e);
        }
    }
    {
        let mut a = lock_write(acks, "acks");
        let pruned = a.prune_expired();
        if pruned > 0 {
            tracing::info!("predictive tick: pruned {} expired ack(s)", pruned);
            if let Err(e) = a.save() {
                tracing::warn!("predictive: failed to save acks after prune: {}", e);
            }
        }
    }
    {
        let mut p = lock_write(proposals, "proposals");
        let pruned = p.prune_resolved_older_than(RESOLVED_RETENTION_DAYS);
        if pruned > 0 {
            tracing::info!("predictive tick: pruned {} resolved proposal(s) older than {}d",
                pruned, RESOLVED_RETENTION_DAYS);
            if let Err(e) = p.save() {
                tracing::warn!("predictive: failed to save proposals after prune: {}", e);
            }
        }
    }

    // 3. Snapshot the read-side stores under their own short locks.
    //    Each clone happens under one lock; the lock drops at the
    //    end of the let binding's scope.
    let history_snap: MetricsHistory = lock_read(metrics, "metrics").clone();
    let acks_snap: AckStore = lock_read(acks, "acks").clone();
    let proposals_snap: ProposalStore = lock_read(proposals, "proposals").clone();

    // 4. Build context. Now that the security-posture analyzer
    //    consumes `NetworkReachability::classify_bind`, we need the
    //    full snapshot (`Context::current` runs `ip` + `ss`). The
    //    cost is two extra subprocess calls per tick — cheap, runs
    //    inside spawn_blocking equivalent below.
    let ctx_node_id = node_id.to_string();
    let ctx = tokio::task::spawn_blocking(move || Context::current(ctx_node_id))
        .await
        .unwrap_or_else(|_| Context::for_node(node_id.to_string()));

    // 4b. Post-sample remediation pass for the compromise analyzer.
    //     Runs AFTER ack/proposal snapshots exist so suppression
    //     gates the auto-fix the same way it gates the proposal —
    //     an operator who acked "yes, root shell is /usr/bin/fish on
    //     purpose" won't have it reverted by the next tick.
    let compromise_facts = compromise_indicators::remediate_if_unacked(
        compromise_facts, &acks_snap, &proposals_snap, &ctx,
    ).await;
    let tamper_facts = tamper_detection::remediate_if_unacked(
        tamper_facts, &acks_snap, &proposals_snap, &ctx,
    ).await;
    let threat_intel_facts = threat_intel::remediate_if_unacked(
        threat_intel_facts, &acks_snap, &proposals_snap, &ctx,
    ).await;

    // 5. Run every analyzer against the snapshots. No locks held.
    //    Each analyzer is independent — extending the list adds a
    //    new analyzer without touching any other code path.
    let mut new_proposals: Vec<crate::predictive::Proposal> = Vec::new();
    new_proposals.extend(disk_fill::analyze(
        &ctx, &history_snap, &host_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(container_disk::analyze(
        &ctx, &history_snap, &container_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(container_restart::analyze(
        &ctx, &history_snap, &restart_facts, &acks_snap, &proposals_snap,
    ));
    if let Some(ref sys) = sys_metrics_opt {
        new_proposals.extend(threshold::analyze(
            &ctx, sys, &failed_units, &acks_snap, &proposals_snap,
        ));
    }
    new_proposals.extend(cert_expiry::analyze(
        &ctx, &cert_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(container_memory::analyze(
        &ctx, &mem_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(backup_freshness::analyze(
        &ctx, &backup_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(vm_disk::analyze(
        &ctx, &vm_facts, &acks_snap, &proposals_snap,
    ));
    // The persisted config is the source of truth (`set_config` always writes
    // it), so this reflects the live state. Read off the async executor —
    // consistent with the other facts above — and fail safe toward "disabled"
    // so a read error surfaces the finding rather than hiding it.
    let scan_detector_enabled = tokio::task::spawn_blocking(|| {
        crate::scan_detector::ScanDetectorConfig::load().enabled
    }).await.unwrap_or(false);
    new_proposals.extend(security_posture::analyze(
        &ctx, &sshd_cfg, scan_detector_enabled, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(vulnerability::analyze(
        &ctx, &vuln_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(osv::analyze(
        &ctx, &osv_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(port_conflict::analyze(
        &ctx, &port_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(wolfnet_dhcp::analyze(
        &ctx, &wolfnet_dhcp_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(wolfnet_reachability::analyze(
        &ctx, &wolfnet_reach_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(docker_wolfnet_collision::analyze(
        &ctx, &docker_wn_collision_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(missing_subnet_route::analyze(
        &ctx, &missing_route_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(compromise_indicators::analyze(
        &ctx, &compromise_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(tamper_detection::analyze(
        &ctx, &tamper_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(threat_intel::analyze(
        &ctx, &threat_intel_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(unused_packages::analyze(
        &ctx, &unused_pkg_facts, &vuln_facts, &osv_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(container_boot::analyze(
        &ctx, &container_boot_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(boot_partition::analyze(
        &ctx, &boot_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(boot_health::analyze(
        &ctx, &boot_health_facts, &acks_snap, &proposals_snap,
    ));
    new_proposals.extend(wolfnet_ip_conflict::analyze(
        &ctx, &wn_conflict_facts, &acks_snap, &proposals_snap,
    ));

    // 5b. Build the "covered" set — every (finding_type, scope) the
    //     analyzers had data for this tick. Auto-resolve uses this
    //     to distinguish "condition cleared" (covered, not emitted)
    //     from "data source down" (not covered at all). Without this
    //     distinction, an NFS hang that empties host_facts could
    //     auto-resolve every disk-fill proposal in the inbox.
    let mut covered = build_covered_scopes(&ctx, &host_facts, &container_facts, &restart_facts);
    if let Some(ref sys) = sys_metrics_opt {
        covered.extend(threshold::covered_scopes(&ctx, sys, &failed_units));
    }
    covered.extend(cert_expiry::covered_scopes(&ctx, &cert_facts));
    covered.extend(container_memory::covered_scopes(&ctx, &mem_facts));
    covered.extend(backup_freshness::covered_scopes(&ctx, &backup_facts));
    covered.extend(vm_disk::covered_scopes(&ctx, &vm_facts));
    covered.extend(security_posture::covered_scopes(&ctx, &sshd_cfg));
    covered.extend(vulnerability::covered_scopes(&ctx, &vuln_facts));
    covered.extend(port_conflict::covered_scopes(&ctx, &port_facts));
    covered.extend(wolfnet_dhcp::covered_scopes(&ctx, &wolfnet_dhcp_facts));
    covered.extend(wolfnet_reachability::covered_scopes(&ctx, &wolfnet_reach_facts));
    covered.extend(docker_wolfnet_collision::covered_scopes(&ctx, &docker_wn_collision_facts));
    covered.extend(missing_subnet_route::covered_scopes(&ctx, &missing_route_facts));
    covered.extend(compromise_indicators::covered_scopes(&ctx, &compromise_facts));
    covered.extend(tamper_detection::covered_scopes(&ctx, &tamper_facts));
    covered.extend(threat_intel::covered_scopes(&ctx, &threat_intel_facts));
    covered.extend(unused_packages::covered_scopes(&ctx, &unused_pkg_facts));
    covered.extend(osv::covered_scopes(&ctx, &osv_facts));
    covered.extend(container_boot::covered_scopes(&ctx, &container_boot_facts));
    covered.extend(boot_partition::covered_scopes(&ctx, &boot_facts));
    covered.extend(boot_health::covered_scopes(&ctx, &boot_health_facts, &proposals_snap));
    covered.extend(wolfnet_ip_conflict::covered_scopes(&ctx, &wn_conflict_facts, &proposals_snap));
    // Mark every PRIOR pending OSV proposal whose target was scanned
    // this tick as covered, even if its CVE didn't re-emit. That's
    // what closes the loop when a package gets upgraded — the CVE
    // drops out of the OSV match list and auto_resolve_cleared sees
    // it covered-but-not-emitted.
    covered.extend(osv::extra_covered_from_store(&ctx, &osv_facts, &proposals_snap));
    let emitted: Vec<(String, crate::predictive::ProposalScope)> = new_proposals.iter()
        .map(|p| (p.finding_type.clone(), p.scope.clone()))
        .collect();

    // 6. Single write-lock window: upsert new proposals + auto-
    //    resolve cleared ones. Both must happen atomically because
    //    auto_resolve_cleared inspects status, and a fresh upsert
    //    may have just refreshed a status the operator dismissed
    //    seconds ago. Order: upsert first (preserves operator
    //    intent — see ProposalStore::upsert), then resolve cleared.
    let upserted = new_proposals.len();
    let mut s = lock_write(proposals, "proposals");
    let mut fresh = 0usize;
    for p in new_proposals {
        if !s.contains_key(&p.dedup_key()) {
            fresh += 1;
        }
        s.upsert(p);
    }
    // Stamp "last checked" on every finding the analyzers actually evaluated
    // this tick (covered) — so the inbox can show whether a non-resolving
    // finding is still being detected or no longer being looked at.
    //
    // INVARIANT for the save gate below: a pending proposal in `covered` is
    // always also either re-emitted (condition still fires → counts toward
    // `upserted`) or auto-resolved (condition cleared → counts toward
    // `resolved`). So any tick that advances a `last_checked_at` also bumps one
    // of those counters and gets persisted. If a future change adds entries to
    // `covered` that are NEITHER re-emitted nor resolvable, fold a "touched"
    // flag from `touch_checked` into the save gate or these stamps won't survive
    // a restart.
    s.touch_checked(&covered);
    let resolved = s.auto_resolve_cleared(&covered, &emitted);
    // A standing condition re-emits the same proposals every tick — that's
    // a refresh, not news, and logging it 12x/hour is journal spam. INFO
    // only when something actually appeared or cleared; the steady-state
    // refresh drops to DEBUG. (Persistence below still keys off upserted,
    // so refreshed timestamps/evidence keep being saved.)
    if fresh > 0 || resolved > 0 {
        tracing::info!(
            "predictive tick: {} new proposal(s), {} refreshed, auto-resolved {} cleared",
            fresh, upserted - fresh, resolved,
        );
    } else if upserted > 0 {
        tracing::debug!(
            "predictive tick: refreshed {} standing proposal(s)", upserted,
        );
    }
    if (upserted > 0 || resolved > 0)
        && let Err(e) = s.save() {
            tracing::warn!("predictive: failed to save proposals: {}", e);
        }

    // 7. Notification dispatch — first appearance only. Compares
    //    the post-upsert state vs the pre-tick snapshot so a
    //    proposal that was already pending doesn't re-page the
    //    operator. Severity gated to Critical/High inside
    //    `find_first_appearance_alerts`. Spawned async so a slow
    //    Discord webhook doesn't stall the orchestrator's loop.
    let alerts: Vec<crate::predictive::Proposal> = notify::find_first_appearance_alerts(
        &proposals_snap.proposals, &s.proposals,
    ).into_iter().cloned().collect();
    drop(s);  // release the write lock before spawning dispatch tasks
    if !alerts.is_empty() {
        tracing::info!("predictive tick: dispatching {} first-appearance alert(s)", alerts.len());
        notify::dispatch_alerts(alerts);
    }
}

/// Build the `(finding_type, scope)` pairs each analyzer evaluated
/// this tick. Used by `auto_resolve_cleared` to distinguish "the
/// condition for this proposal cleared" from "the data source
/// silently failed".
fn build_covered_scopes(
    ctx: &Context,
    host_facts: &[disk_fill::DiskFact],
    container_facts: &[container_disk::ContainerDiskFact],
    restart_facts: &[container_restart::RestartFact],
) -> Vec<(String, crate::predictive::ProposalScope)> {
    let mut out = Vec::with_capacity(
        host_facts.len() + container_facts.len() + restart_facts.len()
    );
    for f in host_facts {
        out.push((
            disk_fill::FINDING_TYPE.to_string(),
            crate::predictive::ProposalScope {
                node_id: ctx.node_id.clone(),
                resource_id: Some(f.mount.clone()),
            },
        ));
    }
    for f in container_facts {
        out.push((
            f.runtime.finding_type().to_string(),
            crate::predictive::ProposalScope {
                node_id: ctx.node_id.clone(),
                resource_id: Some(container_disk::resource_id(f.runtime, &f.name)),
            },
        ));
    }
    for f in restart_facts {
        out.push((
            container_restart::FINDING_TYPE.to_string(),
            crate::predictive::ProposalScope {
                node_id: ctx.node_id.clone(),
                resource_id: Some(container_disk::resource_id(
                    container_disk::Runtime::Docker, &f.name)),
            },
        ));
    }
    out
}

/// Helpers that fall back to the inner guard if the lock is poisoned.
/// We never panic on poison — the analyzer's view may be slightly
/// stale, but that's better than crashing the orchestrator forever.
fn lock_write<'a, T>(
    lock: &'a Arc<RwLock<T>>, label: &'static str,
) -> std::sync::RwLockWriteGuard<'a, T> {
    lock.write().unwrap_or_else(|e| {
        tracing::warn!("predictive: {} write poisoned, recovering", label);
        e.into_inner()
    })
}

fn lock_read<'a, T>(
    lock: &'a Arc<RwLock<T>>, label: &'static str,
) -> std::sync::RwLockReadGuard<'a, T> {
    lock.read().unwrap_or_else(|e| {
        tracing::warn!("predictive: {} read poisoned, recovering", label);
        e.into_inner()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predictive::ack::AckStore;
    use crate::predictive::metrics::MetricsHistory;
    use crate::predictive::proposal::ProposalStore;

    /// Smoke test that the tick body runs cleanly against an empty
    /// state. Doesn't assert on output — analyzer behaviour is
    /// covered by its own tests; this exists only to prove that lock
    /// acquisition order is sound and that save-failures are
    /// tolerated (the test environment can't write `/etc/wolfstack`,
    /// which the orchestrator deliberately treats as a warning, not
    /// an error).
    #[tokio::test]
    async fn tick_does_not_panic_on_empty_state() {
        let proposals = Arc::new(RwLock::new(ProposalStore::default()));
        let acks = Arc::new(RwLock::new(AckStore::default()));
        let metrics = Arc::new(RwLock::new(MetricsHistory::default()));
        let monitor = Arc::new(Mutex::new(crate::monitoring::SystemMonitor::new()));

        tick(&proposals, &acks, &metrics, &monitor, "test-node").await;

        // No assertions — getting here without panicking is the
        // contract being tested.
    }
}
