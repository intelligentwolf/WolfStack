// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Intrusion analyzer — compromise detection across the host AND every
//! running container, built from a real container compromise by the
//! LILITH_VITE_V3 Vite exploit kit (November 2026).
//!
//! The kit ran inside an LXC container for days before a miner's process
//! name tripped the host scanner. Everything it left behind was visible
//! from the host the whole time; nothing was looking inside containers. Each detector
//! here closes one of those gaps:
//!
//! | detector     | catches                                                       |
//! |--------------|---------------------------------------------------------------|
//! | `hooks`      | `NODE_OPTIONS=--require …` / `LD_PRELOAD` in start-up files and live process environments |
//! | `sysfiles`   | unpackaged files in package-only dirs; `touch -r`-forged timestamps; the kit's literal files |
//! | `sshkeys`    | SSH keys added after a target was first seen; unpackaged AuthorizedKeysCommand |
//! | `procs`      | processes running from /tmp, /dev/shm or memory; miners; fresh /tmp executables — in containers |
//! | `devservers` | Vite/webpack/Next dev servers reachable from outside, worst when a proxy publishes them |
//! | `npm`        | installed dev-server packages that differ from the registry tarball |
//!
//! Findings are `compromise_indicator:*` (dispatched as
//! `AlertCategory::Compromise`, so they page in Simple mode) except the
//! dev-server exposure, which is posture (`exposure:*`). Every
//! container-scoped compromise card offers the one-click Quarantine
//! (`crate::quarantine`) through `POST /api/proposals/{id}/apply`.
//!
//! Resource ids are `intrusion:<target>|<item>`, where `<target>` is
//! `host`, `lxc:<name>`, `pve:<vmid>`, `docker:<id12>`, `podman:<id12>`
//! or `cri:<id12>` (see `targets`), and `<item>` names the specific
//! file, key, process image or port — so dismissing one card (e.g.
//! "yes, that LD_PRELOAD is ours") never hides a different one.

pub mod devservers;
pub mod hooks;
pub mod net;
pub mod npm;
pub mod pkgdb;
pub mod procs;
pub mod rootfs;
pub mod sshkeys;
pub mod sysfiles;
pub mod targets;

use crate::predictive::proposal::{Evidence, Proposal, ProposalScope, ProposalStatus, ProposalStore, RemediationPlan, Severity};
use crate::predictive::{AckStore, Context};
use rootfs::RootFs;
use std::collections::{BTreeSet, HashSet};
use std::time::Duration;
use targets::{Target, TargetKind};

pub const FT_HOOK_FILE: &str = "compromise_indicator:injection_hook";
pub const FT_HOOK_PROC: &str = "compromise_indicator:injected_process";
pub const FT_UNPACKAGED: &str = "compromise_indicator:unpackaged_system_file";
pub const FT_KNOWN_FILE: &str = "compromise_indicator:known_attack_file";
pub const FT_SSH_KEY: &str = "compromise_indicator:new_ssh_key";
pub const FT_KEYS_CMD: &str = "compromise_indicator:ssh_keys_command";
pub const FT_STAGING: &str = "compromise_indicator:process_from_tmp";
pub const FT_MINER: &str = "compromise_indicator:container_miner";
pub const FT_TMP_FILE: &str = "compromise_indicator:container_tmp_executable";
pub const FT_NPM: &str = "compromise_indicator:tampered_npm_package";
pub const FT_DEV_SERVER: &str = "exposure:dev_server";
pub const FT_QUARANTINED: &str = "security_quarantine";
pub const FT_SCAN_STALLED: &str = "security_intrusion_scan_stalled";

pub const ALL_TYPES: &[&str] = &[
    FT_HOOK_FILE, FT_HOOK_PROC, FT_UNPACKAGED, FT_KNOWN_FILE, FT_SSH_KEY, FT_KEYS_CMD,
    FT_STAGING, FT_MINER, FT_TMP_FILE, FT_NPM, FT_DEV_SERVER, FT_QUARANTINED, FT_SCAN_STALLED,
];

/// Finding types the one-click Quarantine is offered on (container
/// targets only), with the processes it stops.
pub fn quarantine_kill_spec(ft: &str) -> Option<crate::quarantine::KillSpec> {
    use crate::quarantine::KillSpec;
    Some(match ft {
        FT_STAGING => KillSpec::Staging,
        FT_MINER => KillSpec::Miners,
        FT_HOOK_PROC => KillSpec::EnvHooks,
        FT_HOOK_FILE | FT_UNPACKAGED | FT_KNOWN_FILE | FT_SSH_KEY | FT_KEYS_CMD | FT_TMP_FILE | FT_NPM => KillSpec::None,
        _ => return None,
    })
}

/// How long a predictive tick waits for a fresh scan before using the last
/// completed one. The scan itself runs on in the background: it never
/// holds up the other analyzers' sampling.
pub const TICK_WAIT: Duration = Duration::from_secs(20);
/// A scan running longer than this is reported as stalled (a hung
/// filesystem the guards did not catch, or a host under extreme load).
pub const STALL_AFTER: Duration = Duration::from_secs(15 * 60);
/// A completed scan older than this is not reused.
const MAX_FACTS_AGE: Duration = Duration::from_secs(30 * 60);
/// The command line waits this long for its single scan.
pub const CLI_TIMEOUT: Duration = Duration::from_secs(600);

pub fn resource_id(target_key: &str, item: &str) -> String {
    format!("intrusion:{}|{}", target_key, item)
}

/// (target key, item) of an intrusion resource id.
pub fn parse_resource(rid: &str) -> Option<(&str, &str)> {
    rid.strip_prefix("intrusion:")?.split_once('|')
}

/// One finding before it becomes a Proposal.
#[derive(Debug, Clone)]
pub struct Item {
    pub ft: &'static str,
    pub target_key: String,
    pub item: String,
    pub severity: Severity,
    pub title: String,
    pub why: String,
    pub evidence: Vec<Evidence>,
    pub instructions: String,
    pub commands: Vec<String>,
}

#[derive(Debug, Clone)]
struct SshRaw {
    key: String,
    label: String,
    kind: TargetKind,
    entries: Vec<sshkeys::KeyEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct IntrusionFacts {
    pub scanned: bool,
    pub items: Vec<Item>,
    /// (finding type, target key) fully evaluated this pass.
    pub covered_targets: Vec<(&'static str, String)>,
    /// (finding type, resource id) evaluated individually (npm installs).
    pub covered_exact: Vec<(&'static str, String)>,
    ssh_raw: Vec<SshRaw>,
}

fn ev(label: &str, value: impl Into<String>) -> Evidence {
    Evidence { label: label.into(), value: value.into(), detail: None, links: Vec::new() }
}

fn ev_detail(label: &str, value: impl Into<String>, detail: impl Into<String>) -> Evidence {
    Evidence { label: label.into(), value: value.into(), detail: Some(detail.into()), links: Vec::new() }
}

/// POSIX single-quote a word for the host shell.
pub fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Command prefix that runs a command inside the target from the host
/// shell (inbox recipes always run in the host shell of the node).
pub fn exec_prefix(t_kind: TargetKind, t_key: &str) -> String {
    let id = t_key.split_once(':').map(|(_, i)| i).unwrap_or("");
    match t_kind {
        TargetKind::Host => String::new(),
        TargetKind::Lxc => format!("lxc-attach -n {} -- ", sq(id)),
        TargetKind::Proxmox => format!("pct exec {} -- ", id),
        TargetKind::Docker => format!("docker exec {} ", id),
        TargetKind::Podman => format!("podman exec {} ", id),
        TargetKind::Cri => format!("crictl exec {} ", id),
    }
}

fn fmt_time(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| t.to_string())
}

fn short_hash(s: &str) -> String {
    sysfiles::sha256_hex(s.as_bytes())[..12].to_string()
}

/// A `sed` address that deletes lines containing `needle`, or None when
/// the needle has characters we will not put in a one-click recipe.
fn sed_delete(needle: &str, file: &str, prefix: &str) -> Option<String> {
    if needle.is_empty() || !needle.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b'/' | b'=')) {
        return None;
    }
    // `\|…|` delimiter: base64 and paths contain '/', never '|'.
    let pat = needle.replace('.', r"\.");
    Some(format!("{}sed -i.wolfstack-bak {} {}", prefix, sq(&format!(r"\|{}|d", pat)), sq(file)))
}

const QUARANTINE_HINT: &str = "If you did not put this here, use Quarantine on this card first: it cuts the container's network from the host side, stops the processes this finding names, and keeps their binaries and environment as evidence.";

// ─── Sampling ──────────────────────────────────────────────────────

/// When the scan in flight started (None = none running).
static RUNNING_SINCE: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
/// Last completed scan.
static LATEST: std::sync::Mutex<Option<(std::time::Instant, IntrusionFacts)>> = std::sync::Mutex::new(None);

fn latest_fresh() -> Option<IntrusionFacts> {
    LATEST.lock().unwrap_or_else(|e| e.into_inner()).as_ref()
        .filter(|(at, _)| at.elapsed() < MAX_FACTS_AGE)
        .map(|(_, f)| f.clone())
}

/// Facts for this predictive tick. Starts a background scan unless one is
/// already running (never two walkers at once), waits up to `wait` for it,
/// and otherwise returns the last completed scan. A scan stuck past
/// [`STALL_AFTER`] adds a "scan stalled" finding so a lost scanner is
/// visible in the inbox instead of only in the log.
pub async fn sample_now_async(wait: Duration) -> IntrusionFacts {
    let started_here = {
        let mut r = RUNNING_SINCE.lock().unwrap_or_else(|e| e.into_inner());
        if r.is_none() { *r = Some(std::time::Instant::now()); true } else { false }
    };
    if started_here {
        let handle = tokio::task::spawn_blocking(|| {
            let f = sample_blocking(chrono::Utc::now().timestamp());
            if f.scanned {
                *LATEST.lock().unwrap_or_else(|e| e.into_inner()) = Some((std::time::Instant::now(), f.clone()));
            }
            *RUNNING_SINCE.lock().unwrap_or_else(|e| e.into_inner()) = None;
            f
        });
        match tokio::time::timeout(wait, handle).await {
            Ok(Ok(f)) => return f,
            Ok(Err(e)) => {
                *RUNNING_SINCE.lock().unwrap_or_else(|e| e.into_inner()) = None;
                tracing::warn!("intrusion: scan task panicked: {}", e);
            }
            Err(_) => {} // still running; it stores its result when done
        }
    }
    let running_for = RUNNING_SINCE.lock().unwrap_or_else(|e| e.into_inner()).map(|s| s.elapsed());
    match running_for {
        Some(d) if d > STALL_AFTER => {
            tracing::error!("intrusion: scan has been running for {}s", d.as_secs());
            let mut f = latest_fresh().unwrap_or_else(|| IntrusionFacts { scanned: true, ..Default::default() });
            f.items.push(Item {
                ft: FT_SCAN_STALLED,
                target_key: targets::HOST_KEY.into(),
                item: "stalled".into(),
                severity: Severity::High,
                title: "The intrusion scan on this node has stalled".into(),
                why: format!("One pass of the container-wide intrusion scan has been running for {} minutes. Until it finishes, new compromise indicators on this node are not being detected. A filesystem that stops answering (a dead network or FUSE mount) is the usual cause.", d.as_secs() / 60),
                evidence: vec![ev("Running for", format!("{} s", d.as_secs()))],
                instructions: "Look for hung mounts and processes in D state; restarting WolfStack starts a fresh scan.".into(),
                commands: vec!["ps -eo pid,stat,wchan:32,cmd | awk '$2 ~ /D/'".into(), "findmnt -t fuse,fuse.rclone,nfs,nfs4,cifs".into()],
            });
            f
        }
        _ => latest_fresh().unwrap_or_default(),
    }
}

/// One complete scan for the command line, bounded by [`CLI_TIMEOUT`].
pub async fn scan_once() -> IntrusionFacts {
    let handle = tokio::task::spawn_blocking(|| sample_blocking(chrono::Utc::now().timestamp()));
    match tokio::time::timeout(CLI_TIMEOUT, handle).await {
        Ok(Ok(f)) => f,
        _ => IntrusionFacts::default(),
    }
}

struct Scan<'a> {
    t: &'a Target,
    root: RootFs,
    prefix: String,
}

fn sample_blocking(now: i64) -> IntrusionFacts {
    let all = targets::enumerate();
    let mut facts = IntrusionFacts { scanned: true, ..Default::default() };
    // The host filesystem, for reading overlay upper layers (host paths).
    let Some(host_root) = RootFs::for_pid(1) else { return IntrusionFacts::default() };
    let scans: Vec<Scan> = all.iter().filter_map(|t| {
        RootFs::for_pid(t.init_pid).map(|root| Scan { t, root, prefix: exec_prefix(t.kind, &t.key) })
    }).collect();

    // Proxy configs from every target: a load-balancer CT can publish a
    // dev server living in another CT.
    let mut proxy_refs = Vec::new();
    for s in &scans { proxy_refs.extend(devservers::proxy_refs(&s.t.key, &s.root)); }

    let npm_deadline = std::time::Instant::now() + npm::TICK_BUDGET;
    let mut npm_fetches = 0usize;
    for s in &scans {
        scan_target(s, &host_root, now, &proxy_refs, npm_deadline, &mut npm_fetches, &mut facts);
    }

    // A completed scan is the proof the scanner is not stalled.
    facts.covered_targets.push((FT_SCAN_STALLED, targets::HOST_KEY.to_string()));

    // Active quarantines (also for containers that are stopped now).
    for r in crate::quarantine::records() {
        let killed = r.killed.iter().filter(|k| k.killed).count();
        facts.items.push(Item {
            ft: FT_QUARANTINED,
            target_key: r.target_key.clone(),
            item: "quarantine".into(),
            severity: if r.fully_isolated { Severity::High } else { Severity::Critical },
            title: if r.fully_isolated {
                format!("{} is quarantined", r.label)
            } else {
                format!("{} is quarantined but NOT fully isolated", r.label)
            },
            why: format!("Quarantined by {} at {}. {}", r.actor, r.started_at.format("%Y-%m-%d %H:%M UTC"), r.reason),
            evidence: vec![
                // The device names are those at quarantine time; a restarted
                // container has a new veth, which reconcile isolates too.
                ev("Network (at quarantine)", r.network.clone()),
                ev("Processes killed", killed.to_string()),
                ev("Processes left frozen", r.killed.iter().filter(|k| !k.killed && k.note.starts_with("left FROZEN")).count().to_string()),
                ev("Evidence", r.evidence_dir.clone()),
            ],
            instructions: if r.fully_isolated {
                "The container is cut off from the network until released. Investigate with the evidence directory (process binaries, command lines, environments, SHA-256s), clean or rebuild the container, rotate any secret it held, then release it.".into()
            } else {
                "This container is NOT fully cut off — see Network. Stop it (it stays quarantined while stopped) or remove the interfaces that could not be isolated, then investigate with the evidence directory, clean or rebuild it, rotate its secrets, and release it.".into()
            },
            commands: vec![format!("ls -la {}", sq(&r.evidence_dir)), format!("cat {}/quarantine.json", sq(&r.evidence_dir))],
        });
        facts.covered_targets.push((FT_QUARANTINED, r.target_key.clone()));
    }
    facts
}

fn scan_target(
    s: &Scan,
    host_root: &RootFs,
    now: i64,
    proxy_refs: &[devservers::ProxyRef],
    npm_deadline: std::time::Instant,
    npm_fetches: &mut usize,
    facts: &mut IntrusionFacts,
) {
    let t = s.t;
    let root = &s.root;
    let is_host = t.kind == TargetKind::Host;
    let root_path = if is_host { "/".to_string() } else { format!("/proc/{}/root", t.init_pid) };

    // ── gather ──
    let mut file_hooks: Vec<(String, Vec<hooks::Hook>)> = Vec::new();
    // Start-up files are a few KB. One past the cap cannot be inspected —
    // and padding a profile is how a hook would be hidden from a capped
    // read — so it is reported rather than silently skipped or truncated.
    const STARTUP_CAP: usize = 4 << 20;
    let mut oversized: Vec<(String, u64)> = Vec::new();
    for f in hooks::startup_files(root) {
        match root.read_checked(&f, STARTUP_CAP) {
            Ok(b) => {
                let h = hooks::hooks_in_text(&String::from_utf8_lossy(&b));
                if !h.is_empty() { file_hooks.push((format!("/{}", f), h)); }
            }
            Err(rootfs::ReadErr::TooLarge) => {
                oversized.push((format!("/{}", f), root.lstat(&f).map(|m| m.size).unwrap_or(0)));
            }
            Err(_) => {}
        }
    }
    for (file, size) in &oversized {
        facts.items.push(Item {
            ft: FT_HOOK_FILE,
            target_key: t.key.clone(),
            item: format!("oversized|{}", file),
            severity: Severity::High,
            title: format!("Start-up file {} is too large to inspect ({})", file, t.label),
            why: format!("{} is {} bytes. Shell and environment start-up files are normally a few kilobytes; one this large is read by every login shell yet cannot be checked for code-injection hooks. Padding a file is a way to hide a line in it.", file, size),
            evidence: vec![ev("File", file.clone()), ev("Size", format!("{} bytes", size))],
            instructions: "Look at what makes the file so large and whether it carries a NODE_OPTIONS / LD_PRELOAD line.".into(),
            commands: vec![
                format!("{}ls -la {}", s.prefix, sq(file)),
                format!("{}grep -n -E 'NODE_OPTIONS|LD_PRELOAD|LD_AUDIT|PERL5OPT|RUBYOPT|javaagent' {}", s.prefix, sq(file)),
            ],
        });
    }
    if let Some(text) = root.read_string("etc/ld.so.preload", 1 << 16) {
        let refs = hooks::ld_so_preload_refs(&text);
        if !refs.is_empty() {
            file_hooks.push(("/etc/ld.so.preload".into(),
                vec![hooks::Hook { var: "ld.so.preload".into(), value: text.trim().to_string(), refs }]));
        }
    }
    let candidates = sysfiles::collect(root, now);
    let keys_cmd = sshkeys::sshd_keyword(root, "AuthorizedKeysCommand")
        .filter(|v| !v.eq_ignore_ascii_case("none"))
        .and_then(|v| v.split_whitespace().next().map(|s| s.to_string()));
    let procs_found = procs::scan(t, root, now);

    // ── one ownership query for everything this target needs ──
    let mut want: BTreeSet<String> = BTreeSet::new();
    for (_, hs) in &file_hooks { for h in hs { for r in &h.refs { if r.starts_with('/') { want.insert(r.clone()); } } } }
    for (h, _) in procs_found.env_hooks.values() { for r in &h.refs { if r.starts_with('/') { want.insert(r.clone()); } } }
    for c in &candidates { want.insert(c.path.clone()); }
    if let Some(k) = &keys_cmd { want.insert(k.clone()); }
    let want_v: Vec<String> = want.into_iter().collect();
    let ownership = pkgdb::owned(root, &root_path, &want_v);
    // On an overlay-rooted container (Docker / Podman / CRI) a file the
    // container sees but its writable layer does not hold came from the
    // IMAGE — shipped by the image author, the image's equivalent of a
    // package file. Anything written or modified after start (the kit's
    // preload, a rewritten system binary — overlayfs copies a file up
    // before changing it) is in the upper layer and stays suspect.
    // Fails CLOSED: if the upper layer itself cannot be seen, nothing is
    // treated as image-provided (absence from an unreadable layer proves
    // nothing).
    let upper_visible = root.upperdir.as_deref()
        .is_some_and(|u| host_root.lstat(u).is_some_and(|m| m.is_dir()));
    let image_provided = |p: &str| upper_visible && root.upperdir.as_deref().is_some_and(|u| {
        root.lstat(p).is_some() && host_root.lstat(&format!("{}{}", u, p)).is_none()
    });
    let owned = |p: &str| {
        if image_provided(p) { return Some(true); }
        ownership.as_ref().map(|(_, set)| set.contains(p))
    };

    // FT_QUARANTINED too: a quarantine released from the command line has
    // no record left, and its card must resolve rather than linger.
    for ft in [FT_HOOK_FILE, FT_HOOK_PROC, FT_KNOWN_FILE, FT_KEYS_CMD, FT_STAGING, FT_DEV_SERVER, FT_QUARANTINED] {
        facts.covered_targets.push((ft, t.key.clone()));
    }
    if ownership.is_some() {
        facts.covered_targets.push((FT_UNPACKAGED, t.key.clone()));
    } else if let Some(mgr) = pkgdb::detect(root)
        && !(mgr == pkgdb::Manager::Rpm && !is_host) {
        // A package database that exists but cannot be read within budget
        // switches the unpackaged-file check off for this target — which is
        // exactly what an attacker padding it would want. Say so.
        facts.covered_targets.push((FT_UNPACKAGED, t.key.clone()));
        facts.items.push(Item {
            ft: FT_UNPACKAGED,
            target_key: t.key.clone(),
            item: "pkgdb|unreadable".into(),
            severity: Severity::High,
            title: format!("{} package database could not be read ({})", mgr.name(), t.label),
            why: format!("The {} database on this target is unreadable or unusually large, so WolfStack cannot tell which system files came from packages. Until it can, planted files in system directories go unnoticed.", mgr.name()),
            evidence: vec![ev("Package manager", mgr.name())],
            instructions: "Check the package database is intact (for dpkg: `dpkg --audit`, and the size of /var/lib/dpkg/info/*.list).".into(),
            commands: vec![format!("{}du -sh /var/lib/dpkg/info /var/lib/pacman/local /lib/apk/db 2>/dev/null", s.prefix)],
        });
    }
    if !is_host {
        for ft in [FT_MINER, FT_TMP_FILE] { facts.covered_targets.push((ft, t.key.clone())); }
    }

    // ── loader hooks in files ──
    for (file, hs) in &file_hooks {
        for h in hs {
            let verdicts: Vec<(String, hooks::Verdict)> = h.refs.iter()
                .map(|r| (r.clone(), hooks::judge(r, if r.starts_with('/') { owned(r) } else { None })))
                .collect();
            let worst = verdicts.iter().map(|(_, v)| *v).max().unwrap_or(hooks::Verdict::Suspicious);
            if worst == hooks::Verdict::Packaged { continue; }
            let mut evidence = vec![ev("File", file.clone()), ev("Variable", h.var.clone()),
                ev_detail("Assignment", h.value.chars().take(160).collect::<String>(), h.value.clone())];
            for (r, v) in &verdicts {
                let mut line = format!("{:?}", v);
                if r.starts_with('/') && let Some(b) = root.read(r, 32 << 20) {
                    let sha = sysfiles::sha256_hex(&b);
                    if let Some(k) = sysfiles::known_bad_hash(&sha) { line = format!("KNOWN ATTACK FILE: {}", k); }
                    line.push_str(&format!(" — sha256 {}", sha));
                }
                evidence.push(ev(&format!("Loads {}", r), line));
            }
            let mut commands = vec![format!("{}grep -n {} {}", s.prefix, sq(&h.var), sq(file))];
            for (r, _) in &verdicts {
                if r.starts_with('/') {
                    commands.push(format!("{}ls -la --time-style=full-iso {}", s.prefix, sq(r)));
                    commands.push(format!("{}sha256sum {}", s.prefix, sq(r)));
                }
            }
            if let Some(needle) = verdicts.first().map(|(r, _)| r.rsplit('/').next().unwrap_or(r).to_string())
                && let Some(c) = sed_delete(&needle, file, &s.prefix) {
                commands.push(c);
            }
            facts.items.push(Item {
                ft: FT_HOOK_FILE,
                target_key: t.key.clone(),
                item: format!("hook|{}|{}", file, short_hash(&format!("{}={}", h.var, h.value))),
                severity: if worst == hooks::Verdict::Hidden { Severity::Critical } else { Severity::High },
                title: format!("Code-injection hook {} in {} ({})", h.var, file, t.label),
                why: format!("{} sets {} so that every new process loads {}. This is how the LILITH_VITE_V3 kit (November 2026) kept a webshell inside every Node process of a compromised container. A loader the system's packages do not own, in a start-up file, is persistence until proven otherwise.",
                    file, h.var, h.refs.join(", ")),
                evidence,
                instructions: format!("Check what the referenced file is and who added the line. If it is not yours, quarantine first, then remove the line (the sed below keeps a .wolfstack-bak copy) and restart the affected services from a clean shell — running processes keep the hook until restarted. {}", QUARANTINE_HINT),
                commands,
            });
        }
    }

    // ── loader hooks in live processes ──
    // A loader the container was DEFINED with (image ENV / `-e`) is part of
    // the image, not an injection; anything else is judged on its own.
    let declared_refs: HashSet<String> = {
        let id = t.key.split_once(':').map(|(_, i)| i).unwrap_or("");
        let env = targets::declared_env(t.kind, id).join("\0");
        hooks::hooks_in_environ(env.as_bytes()).into_iter().flat_map(|h| h.refs).collect()
    };
    for ((var, value), (h, list)) in &procs_found.env_hooks {
        let verdicts: Vec<(String, hooks::Verdict)> = h.refs.iter()
            .map(|r| (r.clone(), if declared_refs.contains(r) {
                hooks::Verdict::Packaged
            } else {
                hooks::judge(r, if r.starts_with('/') { owned(r) } else { None })
            }))
            .collect();
        let worst = verdicts.iter().map(|(_, v)| *v).max().unwrap_or(hooks::Verdict::Suspicious);
        if worst == hooks::Verdict::Packaged { continue; }
        let pids: Vec<String> = list.iter().map(|p| p.pid.to_string()).collect();
        let mut evidence = vec![ev("Variable", var.clone()), ev_detail("Value", value.chars().take(160).collect::<String>(), value.clone()),
            ev("Processes", format!("{} process(es)", list.len()))];
        for p in list.iter().take(10) { evidence.push(ev(&format!("PID {}", p.pid), procs::describe(p))); }
        facts.items.push(Item {
            ft: FT_HOOK_PROC,
            target_key: t.key.clone(),
            item: format!("env|{}|{}", var, short_hash(value)),
            severity: if worst == hooks::Verdict::Hidden { Severity::Critical } else { Severity::High },
            title: format!("{} process(es) running with an injected {} ({})", list.len(), var, t.label),
            why: format!("These processes were started with {}={} and loaded {} into themselves. Removing the line from a profile does not fix them — they keep the injected code until restarted.", var, value, h.refs.join(", ")),
            evidence,
            instructions: format!("{} Quarantine stops these processes. Otherwise restart each service from a clean environment after the start-up hook is removed.", QUARANTINE_HINT),
            commands: vec![format!("ps -o pid,ppid,user,lstart,cmd -p {}", pids.join(","))],
        });
    }

    // ── unpackaged / forged-timestamp system files ──
    if ownership.is_some() {
        for c in &candidates {
            if owned(&c.path) == Some(true) { continue; }
            // A literal file of the 2026-11-16 kit gets its own, more
            // specific card below — one file, one card.
            if sysfiles::KNOWN_IOC_PATHS.iter().any(|(p, _)| c.path.trim_start_matches('/') == *p) { continue; }
            let body = root.read(&c.path, 32 << 20);
            let sha = body.as_deref().map(sysfiles::sha256_hex);
            let known = sha.as_deref().and_then(sysfiles::known_bad_hash);
            let head = body.as_deref().map(|b| String::from_utf8_lossy(&b[..b.len().min(200)]).lines().next().unwrap_or("").to_string());
            let (why_shape, sev) = match &c.reason {
                sysfiles::Reason::PackageOnlyDir => (
                    "It sits in a directory that only ever holds files installed by the package manager, and no installed package owns it. The attack hid its C2 client as /usr/lib/systemd/systemd-sysconf-sync and its SSH backdoor as /usr/lib/openssh/ssh-key-helper.".to_string(),
                    Severity::Critical),
                sysfiles::Reason::ForgedTimestamp { cloned_from } => (
                    match cloned_from {
                        Some(d) => format!("Its modification time ({}) is an exact copy of {}'s, but its inode was changed {} — the signature of `touch -r {}`, used to make a planted file look like part of the original install.",
                            fmt_time(c.meta.mtime), d, fmt_time(c.meta.ctime), d),
                        None => format!("Its modification time says {} but its inode was changed {}: the content timestamp was set back. A file restored from a backup looks like this too, but a restore changes many files at once and this one changed alone.",
                            fmt_time(c.meta.mtime), fmt_time(c.meta.ctime)),
                    },
                    Severity::Critical),
            };
            let mut evidence = vec![
                ev("Path", c.path.clone()),
                ev("Mode / size", format!("{:04o}, {} bytes", c.meta.mode & 0o7777, c.meta.size)),
                ev("Modified (claimed)", fmt_time(c.meta.mtime)),
                ev("Inode changed (real)", fmt_time(c.meta.ctime)),
            ];
            if let Some((mgr, _)) = &ownership { evidence.push(ev("Package owner", format!("none ({})", mgr.name()))); }
            if let Some(h) = &sha { evidence.push(ev("SHA-256", h.clone())); }
            if let Some(k) = known { evidence.push(ev("KNOWN ATTACK FILE", k)); }
            if let Some(h) = head.filter(|h| !h.is_empty()) { evidence.push(ev("First line", h.chars().take(160).collect::<String>())); }
            facts.items.push(Item {
                ft: FT_UNPACKAGED,
                target_key: t.key.clone(),
                // Content, not ctime: a chmod/touch must not re-page a
                // dismissed card, a changed payload must.
                item: format!("file|{}|{}", c.path, sha.as_deref().map(|h| &h[..12]).unwrap_or("unreadable")),
                severity: sev,
                title: format!("Unpackaged system file {} ({})", c.path, t.label),
                why: why_shape,
                evidence,
                instructions: format!("Find out what installed it. If nothing you know of did: {} Then look for whatever runs it (cron, systemd units, profiles) — the other cards on this target usually name it.", QUARANTINE_HINT),
                commands: vec![
                    format!("{}ls -la --time-style=full-iso {}", s.prefix, sq(&c.path)),
                    format!("{}stat {}", s.prefix, sq(&c.path)),
                    format!("{}head -c 2000 {}", s.prefix, sq(&c.path)),
                    format!("{}grep -rl {} /etc/cron.d /etc/crontab /var/spool/cron /etc/systemd/system 2>/dev/null",
                        s.prefix, sq(c.path.rsplit('/').next().unwrap_or(&c.path))),
                ],
            });
        }
    }

    // ── literal files of the 2026-11-16 kit ──
    for (p, what) in sysfiles::KNOWN_IOC_PATHS {
        let Some(m) = root.lstat(p) else { continue };
        let path = format!("/{}", p);
        let sha = root.read(p, 32 << 20).map(|b| sysfiles::sha256_hex(&b));
        let mut evidence = vec![ev("Path", path.clone()), ev("What it is", *what),
            ev("Inode changed", fmt_time(m.ctime))];
        if let Some(h) = &sha { evidence.push(ev("SHA-256", h.clone())); }
        facts.items.push(Item {
            ft: FT_KNOWN_FILE,
            target_key: t.key.clone(),
            item: format!("ioc|{}", path),
            severity: Severity::Critical,
            title: format!("Known attack file {} ({})", path, t.label),
            why: format!("This path is written by the LILITH_VITE_V3 exploit kit, seen compromising Node.js hosts in November 2026 ({}). Its presence means the same kit, or the same operator, is on this target.", what),
            evidence,
            instructions: format!("{} Then follow the full clean-up: the kit also adds an SSH key, NODE_OPTIONS lines to /etc/profile, /root/.bashrc and /root/.profile, a cron entry and a systemd unit, and rewrites vite's bin/vite.js, dist/node/cli.js and dist/node/index.js.", QUARANTINE_HINT),
            commands: vec![format!("{}ls -la --time-style=full-iso {}", s.prefix, sq(&path))],
        });
    }

    // ── AuthorizedKeysCommand ──
    if let Some(cmd) = &keys_cmd
        && owned(cmd) != Some(true) {
        facts.items.push(Item {
            ft: FT_KEYS_CMD,
            target_key: t.key.clone(),
            item: format!("cmd|{}", cmd),
            severity: Severity::Critical,
            title: format!("sshd runs an unpackaged AuthorizedKeysCommand ({})", t.label),
            why: format!("sshd asks {} which keys may log in, for every login. No installed package owns that program, so whoever wrote it decides who gets in — the 2026-11-16 kit installed exactly such a helper.", cmd),
            evidence: vec![ev("AuthorizedKeysCommand", cmd.clone())],
            instructions: format!("Unless you set this up (LDAP/SSSD helpers are packaged and would not appear here), remove the AuthorizedKeysCommand line from sshd_config and restart sshd. {}", QUARANTINE_HINT),
            commands: vec![
                format!("{}grep -rn AuthorizedKeysCommand /etc/ssh/", s.prefix),
                format!("{}cat {}", s.prefix, sq(cmd)),
            ],
        });
    }

    // ── live process indicators ──
    for (exe, (place, list)) in &procs_found.staging {
        let pids: Vec<String> = list.iter().map(|p| p.pid.to_string()).collect();
        let mut evidence = vec![ev("Executable", exe.clone()), ev("Location", place.clone())];
        for p in list.iter().take(10) {
            let mut d = procs::describe(p);
            if let Some(k) = p.sha256.as_deref().and_then(sysfiles::known_bad_hash) { d.push_str(&format!("\n  KNOWN ATTACK FILE: {}", k)); }
            evidence.push(ev(&format!("PID {}", p.pid), d));
        }
        facts.items.push(Item {
            ft: FT_STAGING,
            target_key: t.key.clone(),
            item: format!("exe|{}", exe),
            severity: Severity::Critical,
            title: format!("Process running from {} ({})", place, t.label),
            why: format!("{} process(es) are executing {} — a world-writable scratch location where software is never installed. Malware stages there; the LILITH_VITE_V3 miner re-drops itself into /tmp/tmp.XXXXXX/ every time it is killed.", list.len(), exe),
            evidence,
            instructions: if is_host {
                "Identify the parent and how it was started before killing anything; record the SHA-256 for threat-intel. Do not delete the binary — it is evidence.".into()
            } else { QUARANTINE_HINT.to_string() },
            commands: vec![format!("ps -o pid,ppid,user,lstart,cmd -p {}", pids.join(",")),
                format!("ls -la /proc/{}/exe", list[0].pid)],
        });
    }
    if !is_host {
        for (name, list) in &procs_found.miners {
            let pids: Vec<String> = list.iter().map(|p| p.pid.to_string()).collect();
            let mut evidence = vec![ev("Process name", name.clone())];
            for p in list.iter().take(10) { evidence.push(ev(&format!("PID {}", p.pid), procs::describe(p))); }
            facts.items.push(Item {
                ft: FT_MINER,
                target_key: t.key.clone(),
                item: format!("miner|{}", name),
                severity: Severity::Critical,
                title: format!("Crypto-miner {} running in {}", name, t.label),
                why: "A known crypto-miner is running inside this container. Miners are the usual payload of a break-in, and they rarely come alone — expect a C2 client and a way back in (SSH key, loader hook).".into(),
                evidence,
                instructions: format!("{} Killing the miner alone does not work while its launcher is alive — the LILITH_VITE_V3 miner is respawned within a second, then re-downloaded.", QUARANTINE_HINT),
                commands: vec![format!("ps -o pid,ppid,user,lstart,cmd -p {}", pids.join(","))],
            });
        }
        for (path, desc) in &procs_found.tmp_files {
            facts.items.push(Item {
                ft: FT_TMP_FILE,
                target_key: t.key.clone(),
                item: format!("tmp|{}", path),
                severity: Severity::Critical,
                title: format!("Freshly-dropped executable {} ({})", path, t.label),
                why: "An executable file appeared in the container's /tmp or /dev/shm in the last 24 hours. Those directories are world-writable scratch space; malware stages its next step there.".into(),
                evidence: vec![ev("Path", path.clone()), ev("File", desc.clone())],
                instructions: "Check what it is and what created it. If it is a build artefact, move it out of /tmp so it stops matching.".into(),
                commands: vec![format!("{}ls -la --time-style=full-iso {}", s.prefix, sq(path)),
                    format!("{}sha256sum {}", s.prefix, sq(path))],
            });
        }
    }

    // ── SSH keys (baseline applied in finalize_ssh, which needs the proposal store) ──
    // Only a complete read of every key file is evaluated (and counted as
    // covered) — see sshkeys::collect.
    if root.lstat("etc/passwd").is_some()
        && let Some(entries) = sshkeys::collect(root, is_host) {
        facts.ssh_raw.push(SshRaw { key: t.key.clone(), label: t.label.clone(), kind: t.kind, entries });
    }

    // ── dev servers ──
    let ips = net::local_addresses(t.init_pid);
    let token_tunnel = devservers::has_token_tunnel(t);
    for d in devservers::find(t) {
        let routes: Vec<&devservers::ProxyRef> = proxy_refs.iter().filter(|r| devservers::routes_to(r, &t.key, &ips, d.port)).collect();
        let public = ips.iter().any(devservers::is_public);
        let sev = if !routes.is_empty() { Severity::Critical } else if public { Severity::High } else { Severity::Warn };
        let mut evidence = vec![ev("Server", d.kind), ev("Listening", format!("{}:{}", d.bind, d.port)),
            ev("Project", d.cwd.clone()), ev("PID", d.pid.to_string()), ev_detail("Command", d.cmdline.chars().take(120).collect::<String>(), d.cmdline.clone())];
        for r in routes.iter().take(5) {
            evidence.push(ev("Published by", format!("{} ({}): {}", r.file, r.target_key, r.line)));
        }
        if token_tunnel {
            evidence.push(ev("Cloudflare tunnel", "a remotely-managed tunnel (cloudflared --token) runs here; its routes live in the Cloudflare dashboard and cannot be checked from this host"));
        }
        if !ips.is_empty() {
            evidence.push(ev("Addresses", ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")));
        }
        facts.items.push(Item {
            ft: FT_DEV_SERVER,
            target_key: t.key.clone(),
            item: format!("dev|{}", d.port),
            severity: sev,
            title: if routes.is_empty() {
                format!("{} on port {} listens on all interfaces ({})", d.kind, d.port, t.label)
            } else {
                format!("{} on port {} is published by a reverse proxy ({})", d.kind, d.port, t.label)
            },
            why: "A development server serves its project's source tree and answers module-transform requests; it is built for the developer's own browser, not the internet. Vite dev-server advisories — file reads (/@fs/, ?raw, .env) and remote code execution (GHSA-p4f5-76q4-ffq7, November 2026) — are exactly how the LILITH_VITE_V3 kit gets in: through a dev server a reverse proxy has published.".into(),
            evidence,
            instructions: "Serve a production build instead (`vite build` then `vite preview` or a static server), or bind the dev server to 127.0.0.1 and reach it over SSH/WolfNet. If it must stay reachable, put authentication in front of it in the proxy.".into(),
            commands: vec![format!("nsenter -t {} -n ss -ltnp {}", t.init_pid, sq(&format!("sport = :{}", d.port)))],
        });
    }

    // ── npm integrity ──
    for (inst, outcome) in npm::check_target(&t.key, root, now, npm_deadline, npm_fetches) {
        let rid_item = format!("npm|{}", inst.dir);
        match outcome {
            npm::Outcome::Clean => facts.covered_exact.push((FT_NPM, resource_id(&t.key, &rid_item))),
            npm::Outcome::Unverified(_) => {}
            npm::Outcome::Unpublished(why) => {
                facts.covered_exact.push((FT_NPM, resource_id(&t.key, &rid_item)));
                facts.items.push(Item {
                    ft: FT_NPM,
                    target_key: t.key.clone(),
                    item: rid_item,
                    severity: Severity::High,
                    title: format!("{} at {} cannot be verified against the npm registry ({})", inst.name, inst.dir, t.label),
                    why: format!("This copy of {} cannot have come from registry.npmjs.org: {}. A locally built or forked package looks like this; so does one whose version string was edited to dodge the integrity check.", inst.name, why),
                    evidence: vec![ev("Package", inst.name), ev("Installed at", inst.dir.clone()), ev("Reason", why)],
                    instructions: format!("If you build or fork this package yourself, dismiss the card. Otherwise reinstall the project's dependencies from the registry. {}", QUARANTINE_HINT),
                    commands: vec![format!("{}cat {}", s.prefix, sq(&format!("{}/package.json", inst.dir)))],
                });
            }
            npm::Outcome::Tampered { changed, missing } => {
                facts.covered_exact.push((FT_NPM, resource_id(&t.key, &rid_item)));
                let project = inst.dir.split("/node_modules/").next().unwrap_or(&inst.dir).to_string();
                let mut evidence = vec![ev("Package", format!("{}@{}", inst.name, inst.version)), ev("Installed at", inst.dir.clone())];
                if !changed.is_empty() {
                    evidence.push(ev_detail("Changed files", format!("{} file(s)", changed.len()), changed.join("\n")));
                }
                if !missing.is_empty() {
                    evidence.push(ev_detail("Missing files", format!("{} file(s)", missing.len()), missing.join("\n")));
                }
                facts.items.push(Item {
                    ft: FT_NPM,
                    target_key: t.key.clone(),
                    item: rid_item,
                    severity: if changed.is_empty() { Severity::High } else { Severity::Critical },
                    title: format!("{}@{} differs from the npm registry ({})", inst.name, inst.version, t.label),
                    why: format!("Files of the installed {} do not match the {} tarball published on registry.npmjs.org (checked against the registry's own integrity hash). The 2026-11-16 kit rewrote vite's bin/vite.js, dist/node/cli.js and dist/node/index.js so every start of the project re-armed it.",
                        inst.name, inst.version),
                    evidence,
                    instructions: format!("Reinstall the project's dependencies from the registry, then restart its processes. {}", QUARANTINE_HINT),
                    // --ignore-scripts: the project is compromised; its lifecycle
                    // scripts must not run (as root) during the repair.
                    commands: vec![format!("{}npm --prefix {} ci --ignore-scripts", s.prefix, sq(&project))],
                });
            }
        }
    }
}

/// Apply the SSH key baseline (needs the proposal store, for which keys
/// the operator has trusted by dismissing their cards). Runs after the
/// orchestrator has taken its store snapshot.
pub async fn finalize_ssh(mut facts: IntrusionFacts, proposals: &ProposalStore) -> IntrusionFacts {
    if !facts.scanned { return facts; }
    let raw = std::mem::take(&mut facts.ssh_raw);
    // Dismissed new-key cards → trusted baseline keys, per target.
    let trusted: Vec<(String, String)> = proposals.proposals.iter()
        .filter(|p| p.finding_type == FT_SSH_KEY && matches!(p.status, ProposalStatus::Dismissed { .. }))
        .filter_map(|p| {
            let (tk, item) = parse_resource(p.scope.resource_id.as_deref()?)?;
            let rest = item.strip_prefix("key|")?;
            Some((tk.to_string(), rest.to_string()))
        })
        .collect();
    let built = tokio::task::spawn_blocking(move || {
        let mut items = Vec::new();
        let mut covered = Vec::new();
        for r in raw {
            let tr: BTreeSet<String> = trusted.iter().filter(|(k, _)| *k == r.key).map(|(_, v)| v.clone()).collect();
            let prefix = exec_prefix(r.kind, &r.key);
            for e in sshkeys::reconcile(&r.key, &r.entries, &tr) {
                let known = sshkeys::known_bad_label(&e);
                let mut commands = vec![format!("{}cat {}", prefix, sq(&e.file))];
                if let Some(bl) = &e.blob && let Some(c) = sed_delete(bl, &e.file, &prefix) { commands.push(c); }
                let mut evidence = vec![ev("Account", e.user.clone()), ev("File", e.file.clone()), ev("Key", e.summary.clone())];
                if let Some(k) = known { evidence.push(ev("KNOWN ATTACK KEY", k)); }
                items.push(Item {
                    ft: FT_SSH_KEY,
                    target_key: r.key.clone(),
                    item: format!("key|{}", sshkeys::baseline_key(&e)),
                    severity: Severity::Critical,
                    title: if known.is_some() {
                        format!("Attacker's SSH key authorised for {} ({})", e.user, r.label)
                    } else {
                        format!("New SSH key authorised for {} ({})", e.user, r.label)
                    },
                    why: if known.is_some() {
                        "This is the operator key the LILITH_VITE_V3 kit (November 2026) installs on the hosts it compromises. Whoever holds it can log in as this account regardless of any password.".into()
                    } else {
                        format!("{} gained a key that was not there when WolfStack first scanned this target. A key is a way back in that survives every password change. If you added it, dismiss this card — WolfStack then treats it as trusted.", e.file)
                    },
                    evidence,
                    instructions: format!("If you did not add this key, remove it (the sed below keeps a .wolfstack-bak copy) and find out how it got there. {}", QUARANTINE_HINT),
                    commands,
                });
            }
            covered.push((FT_SSH_KEY, r.key));
        }
        (items, covered)
    }).await;
    if let Ok((items, covered)) = built {
        facts.items.extend(items);
        facts.covered_targets.extend(covered);
    }
    facts
}

// ─── Command-line report (`wolfstack --intrusion-scan`) ────────────

/// Print every finding, grouped by target, worst first. Returns true when
/// any compromise finding is Critical.
pub fn print_report(facts: &IntrusionFacts) -> bool {
    let scanned: BTreeSet<&str> = facts.covered_targets.iter().map(|(_, k)| k.as_str()).collect();
    println!("WolfStack intrusion scan — {} target(s): {}", scanned.len(),
        scanned.iter().copied().collect::<Vec<_>>().join(", "));
    let mut items: Vec<&Item> = facts.items.iter().collect();
    items.sort_by(|a, b| a.target_key.cmp(&b.target_key)
        .then(a.severity.rank().cmp(&b.severity.rank())));
    if items.is_empty() {
        println!("\nNo findings.");
        return false;
    }
    let mut current = "";
    for i in &items {
        if i.target_key != current {
            current = &i.target_key;
            println!("\n══ {} ══", current);
        }
        println!("\n[{:?}] {}", i.severity, i.title);
        println!("  type: {}   id: {}", i.ft, resource_id(&i.target_key, &i.item));
        println!("  {}", i.why);
        for e in &i.evidence {
            println!("  • {}: {}", e.label, e.detail.as_deref().unwrap_or(&e.value).replace('\n', "\n      "));
        }
        if !i.commands.is_empty() {
            println!("  commands (host shell):");
            for c in &i.commands { println!("    {}", c); }
        }
    }
    let critical = items.iter().any(|i| i.severity == Severity::Critical && i.ft.starts_with("compromise_indicator:"));
    println!("\n{} finding(s){}.", items.len(), if critical { ", including CRITICAL compromise indicators" } else { "" });
    critical
}

// ─── Proposals ─────────────────────────────────────────────────────

fn suppressed(ft: &str, scope: &ProposalScope, acks: &AckStore, proposals: &ProposalStore) -> bool {
    acks.suppresses(ft, scope) || proposals.is_suppressed(ft, scope)
}

pub fn analyze(ctx: &Context, facts: &IntrusionFacts, acks: &AckStore, proposals: &ProposalStore) -> Vec<Proposal> {
    if !facts.scanned { return Vec::new(); }
    let mut seen: HashSet<(String, String)> = HashSet::new();
    facts.items.iter().filter_map(|i| {
        let scope = ProposalScope { node_id: ctx.node_id.clone(), resource_id: Some(resource_id(&i.target_key, &i.item)) };
        if !seen.insert((i.ft.to_string(), resource_id(&i.target_key, &i.item))) { return None; }
        if suppressed(i.ft, &scope, acks, proposals) { return None; }
        Some(Proposal::new_rule(i.ft, i.severity, i.title.clone(), i.why.clone(), i.evidence.clone(),
            RemediationPlan::Manual { instructions: i.instructions.clone(), commands: i.commands.clone() },
            scope))
    }).collect()
}

/// Every pending intrusion proposal whose target (or exact resource) was
/// evaluated this pass, plus everything emitted — so a cleaned finding
/// auto-resolves, and one on a container that wasn't scanned (stopped,
/// unreadable) stays as it was.
pub fn covered_scopes(ctx: &Context, facts: &IntrusionFacts, proposals: &ProposalStore) -> Vec<(String, ProposalScope)> {
    if !facts.scanned { return Vec::new(); }
    let targets: HashSet<(&str, &str)> = facts.covered_targets.iter().map(|(f, k)| (*f, k.as_str())).collect();
    let exact: HashSet<(&str, &str)> = facts.covered_exact.iter().map(|(f, r)| (*f, r.as_str())).collect();
    let mut out: Vec<(String, ProposalScope)> = facts.items.iter().map(|i| (i.ft.to_string(), ProposalScope {
        node_id: ctx.node_id.clone(), resource_id: Some(resource_id(&i.target_key, &i.item)),
    })).collect();
    for p in &proposals.proposals {
        if p.scope.node_id != ctx.node_id || !ALL_TYPES.contains(&p.finding_type.as_str()) { continue; }
        let Some(rid) = p.scope.resource_id.as_deref() else { continue };
        let Some((tk, _)) = parse_resource(rid) else { continue };
        let ft = p.finding_type.as_str();
        let hit = if ft == FT_NPM { exact.contains(&(ft, rid)) } else { targets.contains(&(ft, tk)) };
        if hit { out.push((p.finding_type.clone(), p.scope.clone())); }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_ids_round_trip() {
        let r = resource_id("lxc:nodejs", "hook|/etc/profile|abc");
        assert_eq!(parse_resource(&r), Some(("lxc:nodejs", "hook|/etc/profile|abc")));
        assert_eq!(parse_resource("lxc:nodejs"), None);
    }

    #[test]
    fn exec_prefixes() {
        assert_eq!(exec_prefix(TargetKind::Lxc, "lxc:nodejs"), "lxc-attach -n 'nodejs' -- ");
        assert_eq!(exec_prefix(TargetKind::Proxmox, "pve:107"), "pct exec 107 -- ");
        assert_eq!(exec_prefix(TargetKind::Docker, "docker:abcdef012345"), "docker exec abcdef012345 ");
        assert_eq!(exec_prefix(TargetKind::Host, "host"), "");
    }

    #[test]
    fn sed_recipe_is_only_built_for_safe_needles() {
        let c = sed_delete("node-telemetry-preload.cjs", "/etc/profile", "lxc-attach -n 'nodejs' -- ").unwrap();
        assert_eq!(c, r"lxc-attach -n 'nodejs' -- sed -i.wolfstack-bak '\|node-telemetry-preload\.cjs|d' '/etc/profile'");
        assert!(sed_delete("x'; rm -rf / #", "/etc/profile", "").is_none());
        assert!(sed_delete("", "/etc/profile", "").is_none());
    }

    #[test]
    fn single_quoting() {
        assert_eq!(sq("a b"), "'a b'");
        assert_eq!(sq("it's"), r"'it'\''s'");
    }

    #[test]
    fn quarantine_offered_on_compromise_types_only() {
        assert!(quarantine_kill_spec(FT_MINER).is_some());
        assert!(quarantine_kill_spec(FT_NPM).is_some());
        assert!(quarantine_kill_spec(FT_DEV_SERVER).is_none());
        assert!(quarantine_kill_spec(FT_QUARANTINED).is_none());
    }
}
