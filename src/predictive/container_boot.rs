// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Degraded-container-boot detector.
//!
//! Background: two incidents on the same day (2026-07-05).
//!
//! 1. wolfscale-3 (unprivileged LXC, Debian 13/systemd 257): the host's
//!    LXC AppArmor profile denied systemd's boot mounts (sd-mkdcreds
//!    ramfs, /tmp //run/lock //dev/mqueue move-mounts) → 22 units failed
//!    with 243/CREDENTIALS including systemd-tmpfiles-setup → /run/mysqld
//!    was never created → mariadb dead after every container restart
//!    until someone ran `systemd-tmpfiles --create` by hand.
//! 2. wabil's Proxmox Backup Server LXC: PBS gets /run/proxmox-backup's
//!    `backup` ownership ENTIRELY from its tmpfs mount unit
//!    (`run-proxmox\x2dbackup.mount`, options uid=backup,gid=backup —
//!    see the unit in proxmox-backup.git etc/). When that mount is
//!    denied inside a container the directory falls back to plain
//!    root-owned, the proxy (user `backup`) can't write, and the web
//!    GUI fails after every restart.
//!
//! Both share one signature: a RUNNING container whose systemd boot is
//! silently degraded — failed .mount / tmpfiles / journald / credential
//! units — that only bites when a service needs the missing plumbing.
//! Operators never look inside a "running" container for failed units,
//! so this analyzer does it for them on every tick.
//!
//! Non-systemd containers (Alpine without systemd, busybox init) don't
//! have `systemctl` — the probe fails fast and the container is skipped
//! without a finding (and without being marked evaluated, so nothing
//! auto-resolves off bad data).

use std::time::Duration;

use crate::predictive::{
    Context,
    ack::AckStore,
    proposal::{
        Evidence, Proposal, ProposalScope, RemediationPlan, Severity,
    },
};

/// Generic degraded-boot finding — one card per container.
pub const FINDING_TYPE: &str = "lxc_boot_degraded";
/// PBS-specific finding — the runtime-dir ownership fix is exact and
/// safe, so it gets its own card with the precise commands.
pub const FINDING_TYPE_PBS: &str = "lxc_pbs_run_dir_ownership";

/// Boot-critical unit prefixes we alert on. Anything else in
/// `systemctl --failed` (an app service that crashed) is the
/// threshold analyzer's territory, not a boot problem.
const BOOT_UNIT_PREFIXES: &[&str] = &[
    "systemd-tmpfiles-setup",
    "systemd-journald",
    "systemd-sysctl",
    "systemd-networkd",
    "systemd-logind",
    "systemd-udev-load-credentials",
    "systemd-tmpfiles-clean",
];

#[derive(Debug, Clone, Default)]
pub struct ContainerBootFacts {
    /// True iff LXC enumeration ran this tick. False = data source
    /// down; auto-resolve must not fire.
    pub scanned: bool,
    pub degraded: Vec<ContainerBootHealth>,
    /// Every container successfully probed this tick (degraded or
    /// clean) — drives auto-resolve when a container is fixed.
    pub evaluated: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ContainerBootHealth {
    pub container: String,
    /// Failed boot-critical units, e.g. `systemd-tmpfiles-setup.service`,
    /// `run-proxmox\x2dbackup.mount`.
    pub failed_units: Vec<String>,
}

/// Single source of truth for "is this PBS's runtime-dir mount unit" —
/// used by both the detector and the generic-card filter so the two
/// can never drift apart.
fn is_pbs_mount(unit: &str) -> bool {
    unit.contains("proxmox") && unit.ends_with(".mount")
}

impl ContainerBootHealth {
    /// The PBS runtime-dir mount, if it's among the failures.
    pub fn pbs_mount_unit(&self) -> Option<&str> {
        self.failed_units.iter()
            .map(|u| u.as_str())
            .find(|u| is_pbs_mount(u))
    }
}

/// Extract boot-critical failed units from `systemctl --failed
/// --no-legend --plain` output. The unit name is the first token that
/// looks like a unit (systemd may still prefix a `●`/`×` bullet).
pub fn parse_failed_boot_units(output: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in output.lines() {
        let unit = line.split_whitespace()
            .find(|tok| tok.contains('.'))
            .unwrap_or("");
        if unit.is_empty() { continue; }
        let is_boot = unit.ends_with(".mount")
            || BOOT_UNIT_PREFIXES.iter().any(|p| unit.starts_with(p));
        if is_boot {
            out.push(unit.to_string());
        }
    }
    out
}

/// Capped exec — same pattern as vulnerability::run_capped (kept local:
/// analyzers are deliberately self-contained). Returns stdout on exit 0,
/// None on non-zero/timeout/spawn failure; kills the child on timeout.
fn run_capped(prog: &str, args: &[&str], timeout: Duration) -> Option<String> {
    use std::io::Read;
    use std::time::Instant;
    let mut child = std::process::Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                let mut buf = String::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_string(&mut buf);
                }
                return Some(buf);
            }
            Ok(Some(_)) => return None,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Per-container probe budget. `systemctl --failed` inside a healthy
/// container answers in milliseconds; a wedged one gets killed.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Whole-sweep budget. Serial 10s probes across a fleet of wedged
/// containers would otherwise run 10s × N — the sweep stops here and
/// unprobed containers simply aren't marked evaluated this tick (so
/// their findings can't auto-resolve off missing data). The outer
/// orchestrator timeout is sized above this (same lesson as the
/// vulnerability sampler's dedicated budget).
const SWEEP_BUDGET: Duration = Duration::from_secs(45);

/// Synchronous sampler — runs inside spawn_blocking. Probes every
/// running LXC container on this node via `lxc-attach` (works on both
/// native LXC and Proxmox hosts — Proxmox containers ARE LXC, named by
/// vmid; same precedent as the vulnerability analyzer).
pub fn sample_now() -> ContainerBootFacts {
    let mut facts = ContainerBootFacts { scanned: true, ..Default::default() };
    let deadline = std::time::Instant::now() + SWEEP_BUDGET;
    for c in crate::containers::lxc_list_all_cached() {
        if c.runtime != "lxc" { continue; }
        if c.state != "running" { continue; }
        let now = std::time::Instant::now();
        if now >= deadline {
            tracing::debug!("container_boot: sweep budget exhausted; remaining containers probed next tick");
            break;
        }
        let out = run_capped(
            "lxc-attach",
            &["-n", c.name.as_str(), "--", "systemctl", "--failed", "--no-legend", "--plain"],
            PROBE_TIMEOUT.min(deadline - now),
        );
        // None = no systemd in the container / attach failed / timed
        // out. Skip WITHOUT marking evaluated so an existing finding
        // for this container never auto-resolves off a broken probe.
        let Some(text) = out else { continue };
        facts.evaluated.push(c.name.clone());
        let failed = parse_failed_boot_units(&text);
        if !failed.is_empty() {
            facts.degraded.push(ContainerBootHealth {
                container: c.name.clone(),
                failed_units: failed,
            });
        }
    }
    facts
}

pub async fn sample_now_async(timeout: Duration) -> ContainerBootFacts {
    let fut = tokio::task::spawn_blocking(sample_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(f)) => f,
        _ => ContainerBootFacts::default(),
    }
}

fn scope_generic(ctx: &Context, container: &str) -> ProposalScope {
    ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some(format!("lxc:boot:{}", container)),
    }
}

fn scope_pbs(ctx: &Context, container: &str) -> ProposalScope {
    ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some(format!("lxc:boot:pbs:{}", container)),
    }
}

pub fn analyze(
    ctx: &Context,
    facts: &ContainerBootFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    if !facts.scanned { return out; }
    for h in &facts.degraded {
        // PBS runtime-dir card first — exact cause, exact fix.
        if let Some(mount_unit) = h.pbs_mount_unit() {
            let scope = scope_pbs(ctx, &h.container);
            if !acks.suppresses(FINDING_TYPE_PBS, &scope)
                && !proposals.is_suppressed(FINDING_TYPE_PBS, &scope)
            {
                out.push(build_pbs_proposal(&h.container, mount_unit, scope));
            }
        }
        // Generic degraded-boot card covers everything else (and the
        // PBS container too when it has OTHER failed boot units).
        let non_pbs: Vec<&String> = h.failed_units.iter()
            .filter(|u| !is_pbs_mount(u))
            .collect();
        if non_pbs.is_empty() { continue; }
        let scope = scope_generic(ctx, &h.container);
        if acks.suppresses(FINDING_TYPE, &scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE, &scope) { continue; }
        out.push(build_generic_proposal(&h.container, &non_pbs, scope));
    }
    out
}

pub fn covered_scopes(
    ctx: &Context,
    facts: &ContainerBootFacts,
) -> Vec<(String, ProposalScope)> {
    let mut out = Vec::new();
    if !facts.scanned { return out; }
    for name in &facts.evaluated {
        out.push((FINDING_TYPE.to_string(), scope_generic(ctx, name)));
        out.push((FINDING_TYPE_PBS.to_string(), scope_pbs(ctx, name)));
    }
    out
}

fn build_pbs_proposal(container: &str, mount_unit: &str, scope: ProposalScope) -> Proposal {
    let evidence = vec![
        Evidence {
            label: "Failed unit".into(),
            value: mount_unit.to_string(),
            detail: Some(
                "PBS mounts a tmpfs at /run/proxmox-backup with \
                 uid=backup,gid=backup — the ownership comes ONLY from \
                 these mount options. Inside a container the host's LXC \
                 AppArmor profile typically denies the mount, the \
                 directory falls back to plain root-owned, and the \
                 proxy daemon (user 'backup') cannot write its runtime \
                 files — so the web GUI fails after every restart.".into(),
            ),
            links: Vec::new(),
        },
    ];
    // Mask the unit we actually DETECTED failing (already in systemd's
    // escaped form, e.g. `run-proxmox\x2dbackup.mount`; single quotes
    // deliver the backslash to systemctl intact) — never a hardcoded
    // literal that could diverge from the evidence (review 2026-07-05).
    let commands = vec![
        format!("lxc-attach -n {} -- systemctl mask '{}'", container, mount_unit),
        format!("lxc-attach -n {} -- sh -c \"printf 'd /run/proxmox-backup 0755 backup backup -\\n' > /etc/tmpfiles.d/proxmox-backup-lxc.conf\"", container),
        format!("lxc-attach -n {} -- systemd-tmpfiles --create", container),
        format!("lxc-attach -n {} -- systemctl restart proxmox-backup proxmox-backup-proxy", container),
    ];
    Proposal::new_rule(
        FINDING_TYPE_PBS,
        Severity::High,
        format!("PBS in '{}' loses /run/proxmox-backup ownership on every restart", container),
        "Proxmox Backup Server relies on a tmpfs mount unit to give \
         /run/proxmox-backup to the 'backup' user; that mount is being \
         denied inside this container, so each restart leaves the \
         directory root-owned and the PBS web GUI down. The fix below \
         masks the (undeniably failing) mount unit and hands ownership \
         to a tmpfiles.d entry instead — survives restarts and PBS \
         upgrades, needs no AppArmor loosening. The tmpfs's unlimited \
         inodes only matter for very large datastores' chunk locks; a \
         plain directory on the container's /run is fine otherwise.".to_string(),
        evidence,
        RemediationPlan::Manual {
            instructions: "Run these inside the container (via the host). \
                           They apply immediately and persist across restarts."
                .to_string(),
            commands,
        },
        scope,
    )
}

fn build_generic_proposal(container: &str, failed: &[&String], scope: ProposalScope) -> Proposal {
    // .mount / tmpfiles failures break runtime directories — that's how
    // both 2026-07-05 incidents bit. Anything else (journald, networkd,
    // logind) still means degraded, but services usually limp on.
    let severe = failed.iter().any(|u|
        u.ends_with(".mount") || u.starts_with("systemd-tmpfiles-setup"));
    let severity = if severe { Severity::High } else { Severity::Warn };
    let evidence = vec![
        Evidence {
            label: "Failed boot units".into(),
            value: format!("{}", failed.len()),
            detail: Some(failed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n")),
            links: Vec::new(),
        },
    ];
    let commands = vec![
        format!("lxc-attach -n {} -- systemctl --failed", container),
        format!("lxc-attach -n {} -- systemd-tmpfiles --create   # immediate heal for missing /run dirs", container),
        "journalctl -k --since '1 hour ago' | grep -i 'apparmor.*DENIED' | tail -20   # on this host".to_string(),
    ];
    Proposal::new_rule(
        FINDING_TYPE,
        severity,
        format!("Container '{}' is running with a degraded boot ({} failed boot unit{})",
            container, failed.len(), if failed.len() == 1 { "" } else { "s" }),
        "This container is up, but core systemd boot units failed — \
         typically the host's LXC AppArmor profile denying mounts or \
         credential setup that a newer systemd (Debian 13 / systemd 257) \
         needs. Services that depend on the missing plumbing (runtime \
         directories under /run, journald logging) break after every \
         container restart, usually long after anyone was watching. \
         `systemd-tmpfiles --create` heals missing /run directories \
         right now; the lasting fix is adjusting the container's \
         AppArmor profile (check the host's kernel log for DENIED \
         lines, then either allow the denied mounts via \
         lxc.apparmor.raw or, for unprivileged containers, \
         lxc.apparmor.profile = unconfined).".to_string(),
        evidence,
        RemediationPlan::Manual {
            instructions: "Diagnose with the commands below. The tmpfiles \
                           command is a safe immediate heal; the AppArmor \
                           change is the permanent fix.".to_string(),
            commands,
        },
        scope,
    )
}

/// Proactive, non-disruptive self-heal for the recurring PBS-in-LXC
/// runtime-dir ownership loss (wabil, 2026-07-15: "lose PBS webui + LXC
/// backups every reboot; mkstemp /run/proxmox-backup EACCES; chown
/// backup:backup fixes it until next reboot").
///
/// PBS gets /run/proxmox-backup's `backup` ownership ONLY from a tmpfs
/// mount unit whose uid=backup option a container's AppArmor profile
/// often drops — so every boot the directory is root-owned and the
/// proxy (user `backup`) can't write. The detector card
/// (`build_pbs_proposal`) only fires when that mount unit lands in
/// `systemctl --failed`; wabil's case (dir mounted/created root-owned
/// but the unit not "failed") slips past it, so the card never reached
/// him. This closes that gap by fixing the SYMPTOM directly, for every
/// running PBS LXC:
///   1. install a tmpfiles.d drop-in that recreates the dir with
///      `backup` ownership on every boot — the PERMANENT fix;
///   2. apply it now (`systemd-tmpfiles --create`) and chown the live
///      dir, so the running proxy recovers on its next write.
///
/// Deliberately does NOT mask units or restart the proxy — those are
/// the disruptive steps that stay in the operator card. Idempotent
/// (exits early once the drop-in exists), PBS-only (keyed off
/// /etc/proxmox-backup), and safe to run on every WolfStack start.
///
/// One-shot at startup is enough: the drop-in persists, so after the
/// first heal every future reboot is correct with no further action.
pub fn ensure_pbs_runtime_dir_persistence() {
    // The whole heal, run inside the container so we never assume the
    // host paths line up with the container's. Single-quoted so the
    // container's own shell evaluates it. Exits 0 (no output) unless it
    // actually healed something, in which case it prints HEALED.
    // Write the drop-in to a temp file then mv it into place, so a
    // partial/interrupted write can never leave an EMPTY drop-in that
    // the existence check then treats as "already fixed" forever. Only
    // the atomic mv publishes the final path.
    const HEAL: &str = "\
[ -d /etc/proxmox-backup ] || exit 0; \
[ -f /etc/tmpfiles.d/proxmox-backup-lxc.conf ] && exit 0; \
printf 'd /run/proxmox-backup 0755 backup backup -\\n' > /etc/tmpfiles.d/.proxmox-backup-lxc.conf.tmp || exit 0; \
mv /etc/tmpfiles.d/.proxmox-backup-lxc.conf.tmp /etc/tmpfiles.d/proxmox-backup-lxc.conf || exit 0; \
systemd-tmpfiles --create /etc/tmpfiles.d/proxmox-backup-lxc.conf 2>/dev/null || true; \
[ -d /run/proxmox-backup ] && chown backup:backup /run/proxmox-backup 2>/dev/null || true; \
echo HEALED";

    // Bound the whole sweep like sample_now's SWEEP_BUDGET — on a fleet
    // of many stalled containers, back-to-back 10s attach timeouts would
    // otherwise tie up a blocking thread for minutes. Unswept containers
    // get healed on the next WolfStack start (the fix is one-shot anyway).
    let deadline = std::time::Instant::now() + SWEEP_BUDGET;
    for c in crate::containers::lxc_list_all_cached() {
        if c.runtime != "lxc" || c.state != "running" { continue; }
        let now = std::time::Instant::now();
        if now >= deadline { break; }
        let out = run_capped(
            "lxc-attach",
            &["-n", c.name.as_str(), "--", "sh", "-c", HEAL],
            PROBE_TIMEOUT.min(deadline - now),
        );
        if out.as_deref().map(|s| s.contains("HEALED")).unwrap_or(false) {
            tracing::info!(
                "container_boot: installed persistent /run/proxmox-backup ownership fix \
                 (tmpfiles.d) in PBS container '{}' — survives reboots",
                c.name,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_failed_units_with_and_without_bullets() {
        let out = "\
● run-proxmox\\x2dbackup.mount loaded failed failed Mount tmpfs at /run/proxmox-backup
systemd-tmpfiles-setup.service loaded failed failed Create System Files and Directories
× systemd-journald.service     loaded failed failed Journal Service
postfix.service                loaded failed failed Postfix Mail Transport Agent
nftables.service               loaded failed failed nftables
";
        let units = parse_failed_boot_units(out);
        // postfix + nftables are app-level, not boot-critical.
        assert_eq!(units, vec![
            "run-proxmox\\x2dbackup.mount".to_string(),
            "systemd-tmpfiles-setup.service".to_string(),
            "systemd-journald.service".to_string(),
        ]);
    }

    #[test]
    fn empty_output_means_clean() {
        assert!(parse_failed_boot_units("").is_empty());
        assert!(parse_failed_boot_units("\n\n").is_empty());
    }

    #[test]
    fn pbs_mount_detected() {
        let h = ContainerBootHealth {
            container: "pbs".into(),
            failed_units: vec!["run-proxmox\\x2dbackup.mount".into()],
        };
        assert!(h.pbs_mount_unit().is_some());
        let h2 = ContainerBootHealth {
            container: "web".into(),
            failed_units: vec!["tmp.mount".into()],
        };
        assert!(h2.pbs_mount_unit().is_none());
    }
}
