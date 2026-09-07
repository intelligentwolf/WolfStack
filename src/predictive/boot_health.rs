// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Boot health — did the previous boot fall into systemd's emergency
//! shell, and does /etc/fstab hold a line that can send the next one
//! there?
//!
//! ## Why this module exists (Markos, Orange Pi 5 Max, 2026-09-07)
//!
//! A community host dropped to "You are in emergency mode" on every
//! reboot after an update. The operator could only send phone photos
//! of the console, never a `journalctl`, so the diagnosis had to come
//! from the box itself. That is what this analyzer does: on every
//! tick it reads the PREVIOUS boot's journal for the emergency
//! transition and the errors around it, and it reads /etc/fstab for
//! the lines that produce that transition, then puts both in the
//! inbox where an operator can screenshot them.
//!
//! ## What actually sends systemd to emergency mode
//!
//! `local-fs.target` carries `OnFailure=emergency.target`. A mount
//! from /etc/fstab without `nofail` is *required* by that target, so
//! one failed local mount stops the whole boot. Network filesystems
//! are not in that path — they hang off `remote-fs.target`, which has
//! no OnFailure — so the lines that matter are local ones:
//!
//! * a device that is not present (`UUID=` of a drive that was pulled,
//!   an SD card, a USB disk that enumerates late) — the classic
//!   "Timed out waiting for device" followed by emergency mode;
//! * a FUSE / mergerfs / overlay pool whose backing storage is not
//!   there yet at mount time;
//! * the documented WolfStack foot-gun: a line ordered with
//!   `x-systemd.requires=wolfstack-mounts.target` but without
//!   `nofail`, which is an ordering cycle systemd breaks by deleting
//!   an arbitrary job (see storage/mod.rs, "systemd ordering for WebUI
//!   auto-mounts"). WolfStack now repairs that one itself at startup
//!   and reports here that it did.
//!
//! Which types are "network" comes from systemd's own
//! `fstype_is_network()` (src/basic/mountpoint-util.c): the `fuse.`
//! prefix is stripped, then the name is checked against the @network
//! set (`systemd-analyze filesystems @network`) plus davfs, glusterfs,
//! lustre and sshfs.

use std::time::Duration;

use crate::predictive::{
    Context,
    ack::AckStore,
    proposal::{Evidence, Proposal, ProposalScope, ProposalSource, RemediationPlan, Severity},
};

pub const FINDING_EMERGENCY: &str = "boot_emergency_mode";
pub const FINDING_FSTAB_RISK: &str = "fstab_boot_risk";
pub const FINDING_FSTAB_REPAIRED: &str = "fstab_nofail_repaired";

/// Resource id for the whole-boot finding.
const BOOT_RESOURCE: &str = "boot";
/// Cap on journal context lines carried into the proposal.
const MAX_JOURNAL_LINES: usize = 24;

/// Everything the analyzer needs, gathered by the sampler so
/// `analyze()` touches no filesystem and no subprocess.
#[derive(Debug, Clone, Default)]
pub struct BootHealthFacts {
    /// `journalctl -b -1` was readable (persistent journal present).
    pub journal_present: bool,
    /// The previous boot reached emergency.target / emergency.service.
    pub prev_boot_emergency: bool,
    /// Error-level journal lines from the previous boot that explain
    /// a failed boot (dependency failures, device timeouts, ordering
    /// cycles, failed mounts). Capped at MAX_JOURNAL_LINES.
    pub prev_boot_lines: Vec<String>,
    /// /etc/fstab was readable.
    pub fstab_present: bool,
    /// Mount points of every fstab line (used for auto-resolve).
    pub fstab_mountpoints: Vec<String>,
    pub fstab_risks: Vec<FstabRisk>,
    /// Mount points whose fstab line WolfStack itself repaired at this
    /// daemon start (storage::fstab_repairs_this_start).
    pub repaired: Vec<String>,
    /// What the startup repair reported, so a still-present risky line
    /// is explained truthfully (not run yet / failed / file changed).
    pub repair_state: crate::storage::FstabRepairState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FstabRiskKind {
    /// Options reference wolfstack-mounts.target without `nofail`.
    /// The startup repair normally fixes this; `repair_state` says why
    /// it is still here (not run yet, failed, or the file changed).
    WolfstackTargetNoNofail,
    /// A local FUSE / mergerfs / overlay filesystem without `nofail` —
    /// it fails whenever its backing storage is not up at mount time.
    FuseNoNofail,
    /// The block device the line names does not exist on this host
    /// right now, and the line has no `nofail`.
    DeviceMissing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FstabRisk {
    pub mountpoint: String,
    pub device: String,
    pub fstype: String,
    pub options: String,
    pub kind: FstabRiskKind,
    /// The original line, verbatim.
    pub line: String,
}

impl FstabRisk {
    /// The same line with `nofail` prepended to its options.
    pub fn fixed_line(&self) -> String {
        with_nofail(&self.line).unwrap_or_else(|| self.line.clone())
    }
}

/// systemd's `fstype_is_network()`: strip a `fuse.` prefix, then match
/// the @network set plus the four extras the function lists itself.
pub fn fstype_is_network(fstype: &str) -> bool {
    let t = fstype.strip_prefix("fuse.").unwrap_or(fstype);
    matches!(
        t,
        "afs" | "ceph" | "cifs" | "gfs" | "gfs2" | "ncp" | "ncpfs" | "nfs" | "nfs4"
            | "ocfs2" | "orangefs" | "pvfs2" | "smb3" | "smbfs"
            | "davfs" | "glusterfs" | "lustre" | "sshfs"
    )
}

/// Filesystem types that are local as far as systemd is concerned but
/// depend on something that may not be there yet at mount time.
fn fstype_is_local_fuse_like(fstype: &str) -> bool {
    fstype == "fuse"
        || fstype.starts_with("fuse.")
        || matches!(fstype, "mergerfs" | "overlay" | "unionfs" | "aufs")
}

/// Pseudo / API filesystems and swap: never a boot risk in the sense
/// this analyzer cares about.
fn fstype_is_ignored(fstype: &str) -> bool {
    matches!(
        fstype,
        "swap" | "proc" | "sysfs" | "tmpfs" | "devtmpfs" | "devpts" | "debugfs" | "tracefs"
            | "securityfs" | "configfs" | "cgroup" | "cgroup2" | "binfmt_misc" | "efivarfs"
            | "hugetlbfs" | "mqueue" | "pstore" | "bpf" | "autofs" | "none" | "ramfs"
            | "squashfs" | "iso9660" | "udf" | "nsfs" | "fusectl"
    )
}

/// One parsed fstab line: (device, mountpoint, fstype, options).
fn split_fstab_line(line: &str) -> Option<(&str, &str, &str, &str)> {
    let l = line.trim();
    if l.is_empty() || l.starts_with('#') {
        return None;
    }
    let mut it = l.split_whitespace();
    let dev = it.next()?;
    let mp = it.next()?;
    let fs = it.next()?;
    let opts = it.next().unwrap_or("defaults");
    Some((dev, mp, fs, opts))
}

fn has_opt(options: &str, opt: &str) -> bool {
    options.split(',').any(|o| o == opt)
}

/// The line with `nofail` prepended to its options field, whitespace
/// preserved elsewhere. None if the line does not parse as a mount.
pub fn with_nofail(line: &str) -> Option<String> {
    let (_, _, _, opts) = split_fstab_line(line)?;
    if has_opt(opts, "nofail") {
        return Some(line.to_string());
    }
    // Replace the 4th whitespace-separated token in place so comments
    // and column alignment survive. Locate it by walking tokens.
    let mut idx = 0usize;
    let mut field = 0usize;
    let bytes = line.as_bytes();
    let mut in_tok = false;
    let mut tok_start = 0usize;
    while idx < bytes.len() {
        let ws = bytes[idx].is_ascii_whitespace();
        if !in_tok && !ws {
            in_tok = true;
            tok_start = idx;
            field += 1;
        } else if in_tok && ws {
            in_tok = false;
            if field == 4 {
                let mut out = String::with_capacity(line.len() + 7);
                out.push_str(&line[..tok_start]);
                out.push_str("nofail,");
                out.push_str(&line[tok_start..]);
                return Some(out);
            }
        }
        idx += 1;
    }
    if in_tok && field == 4 {
        let mut out = String::with_capacity(line.len() + 7);
        out.push_str(&line[..tok_start]);
        out.push_str("nofail,");
        out.push_str(&line[tok_start..]);
        return Some(out);
    }
    // Only three fields: options are implicit "defaults". Append.
    if field == 3 {
        return Some(format!("{} nofail", line.trim_end()));
    }
    None
}

/// Pure: classify every fstab line. `device_exists` answers whether the
/// block device a line names is present right now — `None` when the
/// spec is not a block device (remote paths, `none`, mergerfs branch
/// lists) or cannot be checked. Returns the risks and the mount point
/// of every parsed line.
pub fn analyze_fstab(
    text: &str,
    device_exists: &dyn Fn(&str) -> Option<bool>,
) -> (Vec<FstabRisk>, Vec<String>) {
    let mut risks = Vec::new();
    let mut mountpoints = Vec::new();
    for line in text.lines() {
        let Some((dev, mp, fs, opts)) = split_fstab_line(line) else { continue };
        if fstype_is_ignored(fs) || mp == "none" {
            continue;
        }
        mountpoints.push(mp.to_string());
        if has_opt(opts, "nofail") || has_opt(opts, "noauto") {
            continue;
        }
        let mk = |kind: FstabRiskKind| FstabRisk {
            mountpoint: mp.to_string(),
            device: dev.to_string(),
            fstype: fs.to_string(),
            options: opts.to_string(),
            kind,
            line: line.to_string(),
        };
        if opts.contains("wolfstack-mounts") {
            risks.push(mk(FstabRiskKind::WolfstackTargetNoNofail));
            continue;
        }
        // Network mounts hang off remote-fs.target, which cannot reach
        // emergency mode — nothing to say about them here.
        if fstype_is_network(fs) || has_opt(opts, "_netdev") {
            continue;
        }
        if fstype_is_local_fuse_like(fs) {
            risks.push(mk(FstabRiskKind::FuseNoNofail));
            continue;
        }
        if device_exists(dev) == Some(false) {
            risks.push(mk(FstabRiskKind::DeviceMissing));
        }
    }
    (risks, mountpoints)
}

/// Resolve an fstab device spec to the path systemd waits on.
fn device_path(spec: &str) -> Option<String> {
    if let Some(u) = spec.strip_prefix("UUID=") {
        return Some(format!("/dev/disk/by-uuid/{}", u.trim_matches('"')));
    }
    if let Some(l) = spec.strip_prefix("LABEL=") {
        return Some(format!("/dev/disk/by-label/{}", l.trim_matches('"')));
    }
    if let Some(u) = spec.strip_prefix("PARTUUID=") {
        return Some(format!("/dev/disk/by-partuuid/{}", u.trim_matches('"')));
    }
    if let Some(l) = spec.strip_prefix("PARTLABEL=") {
        return Some(format!("/dev/disk/by-partlabel/{}", l.trim_matches('"')));
    }
    if spec.starts_with("/dev/") {
        return Some(spec.to_string());
    }
    None
}

/// Pure: did this previous-boot journal text reach emergency mode, and
/// which lines explain why. `unit_lines` is the output of
/// `journalctl -b -1 -u emergency.target -u emergency.service`;
/// `err_lines` is `journalctl -b -1 -p err`.
pub fn classify_previous_boot(unit_lines: &str, err_lines: &str) -> (bool, Vec<String>) {
    let emergency = unit_lines.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("emergency")
    });
    let markers = [
        "dependency failed",
        "timed out waiting for device",
        "ordering cycle",
        "failed to mount",
        "failed with result",
        "emergency",
        "mount: ",
        "unknown filesystem type",
        "can't find",
        "no such file or directory",
    ];
    let mut out: Vec<String> = err_lines
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .filter(|l| {
            let low = l.to_ascii_lowercase();
            markers.iter().any(|m| low.contains(m))
        })
        .map(|l| l.to_string())
        .collect();
    out.truncate(MAX_JOURNAL_LINES);
    (emergency, out)
}

/// Run `journalctl` with the given arguments, bounded by `timeout`.
/// tokio::process with kill_on_drop: a journalctl wedged on a corrupt
/// journal (failing SD card — the class of hardware this module was
/// written for) is killed when the timeout drops the future, not left
/// behind on the blocking pool every tick. None on failure/timeout.
async fn journalctl(args: &[&str], timeout: Duration) -> Option<String> {
    let cmd = tokio::process::Command::new("journalctl")
        .args(args)
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(timeout, cmd).await {
        Ok(Ok(o)) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).to_string()),
        Ok(_) => None,
        Err(_) => {
            tracing::warn!("predictive: journalctl timed out after {}s — skipping boot-health this tick", timeout.as_secs());
            None
        }
    }
}

pub async fn sample_now_async(timeout: Duration) -> BootHealthFacts {
    let mut facts = BootHealthFacts::default();

    // Previous boot. `-b -1` fails outright without a persistent
    // journal, in which case we cannot say anything about it.
    let unit_lines = journalctl(
        &["-b", "-1", "-q", "--no-pager", "-o", "cat", "-u", "emergency.target", "-u", "emergency.service"],
        timeout,
    )
    .await;
    if let Some(unit_lines) = unit_lines {
        facts.journal_present = true;
        let err_lines = journalctl(
            &["-b", "-1", "-q", "--no-pager", "-o", "short-iso", "-p", "err", "-n", "600"],
            timeout,
        )
        .await
        .unwrap_or_default();
        let (emergency, lines) = classify_previous_boot(&unit_lines, &err_lines);
        facts.prev_boot_emergency = emergency;
        facts.prev_boot_lines = lines;
    }

    // fstab: a small local file, but the device-existence probes touch
    // /dev/disk/by-*, so keep the whole read off the runtime.
    let fstab = tokio::task::spawn_blocking(|| {
        let text = std::fs::read_to_string("/etc/fstab").ok()?;
        let exists = |spec: &str| -> Option<bool> {
            device_path(spec).map(|p| std::path::Path::new(&p).exists())
        };
        Some(analyze_fstab(&text, &exists))
    });
    if let Ok(Ok(Some((risks, mps)))) = tokio::time::timeout(timeout, fstab).await {
        facts.fstab_present = true;
        facts.fstab_risks = risks;
        facts.fstab_mountpoints = mps;
    }

    facts.repaired = crate::storage::fstab_repairs_this_start();
    facts.repair_state = crate::storage::fstab_repair_state();
    facts
}

fn risk_scope(ctx: &Context, mountpoint: &str) -> ProposalScope {
    ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some(format!("fstab:{}", mountpoint)),
    }
}

pub fn analyze(
    ctx: &Context,
    facts: &BootHealthFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();

    // ── Previous boot stopped in emergency mode ──
    if facts.journal_present && facts.prev_boot_emergency {
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(BOOT_RESOURCE.into()),
        };
        if !acks.suppresses(FINDING_EMERGENCY, &scope)
            && !proposals.is_suppressed(FINDING_EMERGENCY, &scope)
        {
            let mut evidence = Vec::new();
            if facts.prev_boot_lines.is_empty() {
                evidence.push(Evidence {
                    label: "Journal".into(),
                    value: "emergency.target reached; no error-level lines recorded".into(),
                    detail: None,
                    links: Vec::new(),
                });
            } else {
                evidence.push(Evidence {
                    label: "Journal".into(),
                    value: facts.prev_boot_lines[0].clone(),
                    detail: Some(facts.prev_boot_lines.join("\n")),
                    links: Vec::new(),
                });
            }
            for r in &facts.fstab_risks {
                evidence.push(Evidence {
                    label: "fstab".into(),
                    value: format!("{} ({})", r.mountpoint, risk_kind_label(&r.kind)),
                    detail: Some(r.line.clone()),
                    links: Vec::new(),
                });
            }
            for mp in &facts.repaired {
                evidence.push(Evidence {
                    label: "Repaired".into(),
                    value: format!("{}: nofail added by WolfStack", mp),
                    detail: None,
                    links: Vec::new(),
                });
            }
            let why = format!(
                "The last boot of this host reached systemd's emergency shell before it \
                 finished. That happens when a filesystem listed in /etc/fstab without \
                 `nofail` fails to mount: local-fs.target is then failed and its \
                 OnFailure= is emergency.target. Everything else keeps starting in \
                 parallel — network, cloud-init, remote filesystems — which is why the \
                 console looks almost normal right up to the prompt. The lines below \
                 are the error-level journal entries from that boot{}. Fix the line \
                 (or add `nofail` so a missed mount no longer stops the machine), then \
                 reboot once to confirm; this finding clears on the next clean boot.",
                if facts.fstab_risks.is_empty() {
                    String::new()
                } else {
                    format!(
                        ", and {} fstab line(s) on this host can produce exactly that failure",
                        facts.fstab_risks.len()
                    )
                }
            );
            out.push(Proposal::new(
                FINDING_EMERGENCY,
                ProposalSource::Rule,
                Severity::High,
                "The previous boot stopped in emergency mode",
                why,
                evidence,
                RemediationPlan::Manual {
                    instructions: "Read the previous boot's errors, then fix or add `nofail` to \
                                   the fstab line they name. The commands below are safe to run \
                                   as-is; the fstab edit is yours to make."
                        .into(),
                    commands: vec![
                        "journalctl -b -1 -p err --no-pager".into(),
                        "systemctl --failed --no-pager".into(),
                        "cat /etc/fstab".into(),
                    ],
                },
                scope,
            ));
        }
    }

    // ── fstab lines that can stop the next boot ──
    if facts.fstab_present {
        for r in &facts.fstab_risks {
            let scope = risk_scope(ctx, &r.mountpoint);
            if acks.suppresses(FINDING_FSTAB_RISK, &scope)
                || proposals.is_suppressed(FINDING_FSTAB_RISK, &scope)
            {
                continue;
            }
            let (sev, title, why) = match r.kind {
                FstabRiskKind::DeviceMissing => (
                    Severity::High,
                    format!("{} is in fstab without nofail and its device is missing", r.mountpoint),
                    format!(
                        "/etc/fstab mounts {} from `{}`, which does not exist on this host right \
                         now. Without `nofail`, systemd waits 90 s for that device at boot, fails \
                         local-fs.target, and drops into emergency mode — the machine does not come \
                         up without someone at the console. Add `nofail` (the mount is then skipped \
                         when the device is absent) or remove the line if the disk is gone.",
                        r.mountpoint, r.device
                    ),
                ),
                FstabRiskKind::FuseNoNofail => (
                    Severity::Warn,
                    format!("{} ({}) is in fstab without nofail", r.mountpoint, r.fstype),
                    format!(
                        "/etc/fstab mounts {} as `{}`. systemd treats it as a local filesystem, so \
                         it is required by local-fs.target; the first boot on which its backing \
                         storage is not ready when the mount runs ends in emergency mode instead of \
                         a missing mount. Add `nofail` so a miss is logged rather than fatal.",
                        r.mountpoint, r.fstype
                    ),
                ),
                FstabRiskKind::WolfstackTargetNoNofail => (
                    Severity::High,
                    format!("{} orders on wolfstack-mounts.target without nofail", r.mountpoint),
                    format!(
                        "/etc/fstab mounts {} with `x-systemd.requires=wolfstack-mounts.target` but \
                         no `nofail`. That is an ordering cycle: the fstab generator puts the mount \
                         before local-fs.target while the target chain runs after wolfstack.service, \
                         and systemd breaks the cycle by deleting an arbitrary job — so boot fails on \
                         some reboots and not others. {}",
                        r.mountpoint,
                        repair_state_sentence(&facts.repair_state),
                    ),
                ),
            };
            out.push(Proposal::new(
                FINDING_FSTAB_RISK,
                ProposalSource::Rule,
                sev,
                title,
                why,
                vec![
                    Evidence {
                        label: "Line".into(),
                        value: r.line.trim().to_string(),
                        detail: None,
                        links: Vec::new(),
                    },
                    Evidence {
                        label: "Fixed".into(),
                        value: r.fixed_line().trim().to_string(),
                        detail: None,
                        links: Vec::new(),
                    },
                ],
                RemediationPlan::Manual {
                    instructions: "Back up /etc/fstab, replace the line with the fixed version, then \
                                   reload systemd so the generated mount unit picks it up."
                        .into(),
                    commands: vec![
                        "sudo cp /etc/fstab /etc/fstab.bak".into(),
                        format!("# replace:\n{}\n# with:\n{}", r.line.trim(), r.fixed_line().trim()),
                        "sudo systemctl daemon-reload".into(),
                    ],
                },
                scope,
            ));
        }

        // ── Lines WolfStack repaired itself at this start ──
        for mp in &facts.repaired {
            let scope = risk_scope(ctx, mp);
            if acks.suppresses(FINDING_FSTAB_REPAIRED, &scope)
                || proposals.is_suppressed(FINDING_FSTAB_REPAIRED, &scope)
            {
                continue;
            }
            out.push(Proposal::new(
                FINDING_FSTAB_REPAIRED,
                ProposalSource::Rule,
                Severity::Info,
                format!("WolfStack added nofail to the fstab line for {}", mp),
                format!(
                    "The /etc/fstab line for {} was ordered on wolfstack-mounts.target without \
                     `nofail`, which can stop boot in emergency mode (see the storage docs: \
                     nofail is mandatory with that option). WolfStack added `nofail` at startup; \
                     the previous file is kept as /etc/fstab.wolfstack-bak-<timestamp>. Nothing \
                     else on the line changed.",
                    mp
                ),
                Vec::new(),
                RemediationPlan::Manual {
                    instructions: "No action needed. Review the line if you want to.".into(),
                    commands: vec![format!("grep -n ' {} ' /etc/fstab", mp)],
                },
                scope,
            ));
        }
    }

    out
}

/// The truthful tail for a wolfstack-mounts.target line that is still
/// missing `nofail`, from what the startup repair actually reported.
fn repair_state_sentence(state: &crate::storage::FstabRepairState) -> String {
    use crate::storage::FstabRepairState as S;
    match state {
        S::NotRun => "WolfStack adds `nofail` to such a line itself at startup; that step has not \
                      run yet in this session (slow start), so this should clear on its own within \
                      a few minutes — add it by hand if it does not."
            .to_string(),
        S::Failed { error, .. } => format!(
            "WolfStack tried to add `nofail` at startup and could not: {}. Add it by hand.",
            error
        ),
        S::Clean | S::Repaired(_) => "The file has changed since WolfStack's startup repair ran; \
                                     add `nofail` by hand, or restart WolfStack to repair it again."
            .to_string(),
    }
}

fn risk_kind_label(kind: &FstabRiskKind) -> &'static str {
    match kind {
        FstabRiskKind::DeviceMissing => "device missing, no nofail",
        FstabRiskKind::FuseNoNofail => "local FUSE mount, no nofail",
        FstabRiskKind::WolfstackTargetNoNofail => "wolfstack-mounts.target without nofail",
    }
}

/// Covered scopes for auto-resolve. The emergency finding is covered
/// whenever the previous boot's journal was readable (a clean boot
/// then clears it). fstab findings are covered for every mount point
/// still listed in fstab, plus any mount point that carries a stored
/// proposal on this node — so deleting the line resolves too.
pub fn covered_scopes(
    ctx: &Context,
    facts: &BootHealthFacts,
    store: &crate::predictive::proposal::ProposalStore,
) -> Vec<(String, ProposalScope)> {
    let mut out = Vec::new();
    if facts.journal_present {
        out.push((
            FINDING_EMERGENCY.to_string(),
            ProposalScope {
                node_id: ctx.node_id.clone(),
                resource_id: Some(BOOT_RESOURCE.into()),
            },
        ));
    }
    if facts.fstab_present {
        for mp in &facts.fstab_mountpoints {
            out.push((FINDING_FSTAB_RISK.to_string(), risk_scope(ctx, mp)));
            out.push((FINDING_FSTAB_REPAIRED.to_string(), risk_scope(ctx, mp)));
        }
        for p in &store.proposals {
            if p.scope.node_id != ctx.node_id {
                continue;
            }
            if p.finding_type != FINDING_FSTAB_RISK && p.finding_type != FINDING_FSTAB_REPAIRED {
                continue;
            }
            out.push((p.finding_type.clone(), p.scope.clone()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_device_info(_: &str) -> Option<bool> { None }

    #[test]
    fn network_types_follow_systemd_including_fuse_prefix() {
        assert!(fstype_is_network("nfs"));
        assert!(fstype_is_network("cifs"));
        assert!(fstype_is_network("fuse.sshfs"));
        assert!(fstype_is_network("fuse.glusterfs"));
        assert!(!fstype_is_network("fuse.mergerfs"));
        assert!(!fstype_is_network("ext4"));
    }

    #[test]
    fn wolfstack_target_line_without_nofail_is_flagged_and_fixed_in_place() {
        let fstab = "\
# comment
UUID=abc / ext4 errors=remount-ro 0 1
/mnt/a:/mnt/b   /srv/pool   fuse.mergerfs   defaults,allow_other,x-systemd.requires=wolfstack-mounts.target   0 0
";
        let (risks, mps) = analyze_fstab(fstab, &no_device_info);
        assert_eq!(mps, vec!["/".to_string(), "/srv/pool".to_string()]);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].kind, FstabRiskKind::WolfstackTargetNoNofail);
        assert_eq!(
            risks[0].fixed_line(),
            "/mnt/a:/mnt/b   /srv/pool   fuse.mergerfs   nofail,defaults,allow_other,x-systemd.requires=wolfstack-mounts.target   0 0"
        );
    }

    #[test]
    fn nofail_noauto_and_network_lines_are_not_risks() {
        let fstab = "\
UUID=abc /data ext4 defaults,nofail 0 2
UUID=def /later ext4 noauto 0 2
nas:/export /mnt/nas nfs defaults 0 0
//nas/share /mnt/smb cifs credentials=/etc/c 0 0
/mnt/x /pool fuse.mergerfs _netdev,defaults 0 0
";
        let exists = |_: &str| Some(false);
        let (risks, mps) = analyze_fstab(fstab, &exists);
        assert!(risks.is_empty(), "{:?}", risks);
        assert_eq!(mps.len(), 5);
    }

    #[test]
    fn missing_device_without_nofail_is_high_risk_and_present_device_is_not() {
        let fstab = "\
UUID=gone /mnt/usb ext4 defaults 0 2
UUID=here /mnt/ssd ext4 defaults 0 2
";
        let exists = |spec: &str| Some(spec == "UUID=here");
        let (risks, _) = analyze_fstab(fstab, &exists);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].mountpoint, "/mnt/usb");
        assert_eq!(risks[0].kind, FstabRiskKind::DeviceMissing);
        assert_eq!(risks[0].fixed_line(), "UUID=gone /mnt/usb ext4 nofail,defaults 0 2");
    }

    #[test]
    fn local_fuse_pool_without_nofail_is_a_warning() {
        let fstab = "/mnt/d1:/mnt/d2 /storage fuse.mergerfs defaults,allow_other 0 0\n";
        let (risks, _) = analyze_fstab(fstab, &no_device_info);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].kind, FstabRiskKind::FuseNoNofail);
    }

    #[test]
    fn pseudo_filesystems_and_swap_are_ignored() {
        let fstab = "\
proc /proc proc defaults 0 0
tmpfs /tmp tmpfs defaults 0 0
UUID=sw none swap sw 0 0
";
        let exists = |_: &str| Some(false);
        let (risks, mps) = analyze_fstab(fstab, &exists);
        assert!(risks.is_empty());
        assert!(mps.is_empty());
    }

    #[test]
    fn three_field_line_gets_nofail_appended() {
        assert_eq!(with_nofail("UUID=x /mnt ext4").unwrap(), "UUID=x /mnt ext4 nofail");
        assert_eq!(with_nofail("# comment"), None);
        assert_eq!(with_nofail("UUID=x /mnt ext4 nofail 0 0").unwrap(), "UUID=x /mnt ext4 nofail 0 0");
    }

    #[test]
    fn device_specs_resolve_to_udev_paths() {
        assert_eq!(device_path("UUID=1234").as_deref(), Some("/dev/disk/by-uuid/1234"));
        assert_eq!(device_path("LABEL=data").as_deref(), Some("/dev/disk/by-label/data"));
        assert_eq!(device_path("PARTUUID=ab").as_deref(), Some("/dev/disk/by-partuuid/ab"));
        assert_eq!(device_path("/dev/sda1").as_deref(), Some("/dev/sda1"));
        assert_eq!(device_path("nas:/export"), None);
        assert_eq!(device_path("/mnt/a:/mnt/b"), None);
    }

    #[test]
    fn previous_boot_classification_reads_the_unit_lines_and_keeps_only_relevant_errors() {
        let units = "Reached target emergency.target - Emergency Mode.\nStarted emergency.service - Emergency Shell.\n";
        let errs = "\
2026-09-07T10:00:01+0000 wolf5 systemd[1]: Timed out waiting for device dev-disk-by\\x2duuid-abc.device - /dev/disk/by-uuid/abc.
2026-09-07T10:00:01+0000 wolf5 systemd[1]: Dependency failed for mnt-usb.mount - /mnt/usb.
2026-09-07T10:00:02+0000 wolf5 kernel: rockchip-vop2 fdd90000.vop: [drm:vop2_power_domain_off_by_disabled_vp] *ERROR* unexpected power on pd6
";
        let (emergency, lines) = classify_previous_boot(units, errs);
        assert!(emergency);
        assert_eq!(lines.len(), 2, "{:?}", lines);
        assert!(lines[0].contains("Timed out waiting for device"));
        assert!(lines[1].contains("Dependency failed"));
    }

    #[test]
    fn a_clean_previous_boot_is_not_emergency() {
        let (emergency, lines) = classify_previous_boot("", "some unrelated error\n");
        assert!(!emergency);
        assert!(lines.is_empty());
    }
}
