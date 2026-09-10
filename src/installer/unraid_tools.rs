// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Unraid tool bootstrapper — Unraid is a RAM-based Slackware with no
//! package manager: /usr/local/bin is recreated on every boot, so anything
//! we install there evaporates. This module gives Unraid agent nodes the
//! tools WolfStack features need (PBS backups, SMART monitoring) by
//! downloading static builds from the rolling `unraid-tools-v1` GitHub
//! release (built/verified by .github/workflows/unraid-tools.yml),
//! persisting them on the array at /mnt/user/appdata/wolfstack/tools, and
//! re-linking them into /usr/local/bin on every startup (klasSponsor,
//! 2026-07-03: "wolfstack could just reinstall what's needed when it's run
//! at startup").
//!
//! Runs from the post-bind background startup thread — per the masterpier
//! lesson (2026-07-03) nothing here may gate the dashboard bind, and every
//! external command is timeout-bounded.

use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{info, warn};

/// Tools we ensure: (binary name, release asset name). Unraid is x86_64-only
/// as a product, so amd64 assets are sufficient.
const TOOLS: &[(&str, &str)] = &[
    // Official Proxmox static client (extracted from their signed deb by CI).
    // Needed for PBS backup destinations; pxar for file-level archives.
    ("proxmox-backup-client", "proxmox-backup-client-x86_64"),
    ("pxar", "pxar-x86_64"),
    // Static musl smartctl — Unraid ships its own smartctl, so this only
    // downloads on stripped-down or future variants where it's absent
    // (the on-PATH check below skips natively-present tools entirely).
    ("smartctl", "smartctl-x86_64"),
];

const RELEASE_BASE: &str =
    "https://github.com/intelligentwolf/WolfStack/releases/download/unraid-tools-v1";

/// WolfNet ships its own prebuilt static binaries on the WolfNet repo's
/// latest release — the same assets setup.sh downloads on every other
/// distro (setup.sh: `PREBUILT_URL=".../releases/latest/download"`,
/// assets `wolfnet-x86_64` / `wolfnetctl-x86_64`). Unraid can't run
/// setup.sh (Slackware — no apt/dnf/pacman, and its /etc is RAM), so
/// the agent bundles WolfNet the same way it bundles the other tools
/// (klas, 2026-08-11: "wolfnet could be bundled into the agent").
const WOLFNET_RELEASE_BASE: &str =
    "https://github.com/intelligentwolf/WolfNet/releases/latest/download";
const WOLFNET_TOOLS: &[(&str, &str)] = &[
    ("wolfnet", "wolfnet-x86_64"),
    ("wolfnetctl", "wolfnetctl-x86_64"),
];

/// Same array-backed appdata dir setup.sh installs the agent into — /etc and
/// /usr/local/bin are RAM, this survives reboots.
const TOOLS_DIR: &str = "/mnt/user/appdata/wolfstack/tools";
const LINK_DIR: &str = "/usr/local/bin";

/// WolfNet state that must survive reboots: config.toml + private.key.
/// `/etc/wolfnet` (the path every wolfnet default and every WolfStack
/// networking feature uses) becomes a symlink to this dir.
const WOLFNET_ETC: &str = "/etc/wolfnet";
const WOLFNET_APPDATA: &str = "/mnt/user/appdata/wolfstack/wolfnet";

pub fn is_unraid() -> bool {
    Path::new("/etc/unraid-version").exists()
}

/// Ensure every manifest tool is usable on this Unraid node. No-op on
/// non-Unraid systems and on tools already on PATH. Logs state changes only:
/// silent when everything is already in place.
pub fn ensure_unraid_tools() {
    if !is_unraid() {
        return;
    }
    if std::env::consts::ARCH != "x86_64" {
        // Unraid is x86_64-only; anything else has no assets to fetch.
        return;
    }
    for (bin, asset) in TOOLS {
        ensure_tool(bin, asset, RELEASE_BASE);
    }
    // The operator's "disable" is the systemd `is-enabled` equivalent: it
    // decides whether the daemon comes up with the agent. Read it once here,
    // before the first ensure, so a disabled node boots with WolfNet off
    // exactly like a disabled unit would.
    if wolfnet_disabled_marker().exists() {
        WOLFNET_STOPPED.store(true, Ordering::Relaxed);
        info!("unraid wolfnet: disabled by the operator ({}) — not starting the daemon", wolfnet_disabled_marker().display());
    }
    ensure_unraid_wolfnet();
    // Supervision tick: Unraid has no systemd, so the agent keeps the
    // wolfnet daemon alive. 60s matches how fast a mesh outage becomes
    // operator-visible without burning cycles — each pass is a `which`
    // + symlink stat + pgrep unless something actually needs doing.
    std::thread::spawn(|| loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
        ensure_unraid_wolfnet();
    });
}

/// Bundle WolfNet on Unraid: binaries persisted + linked like every
/// other tool, `/etc/wolfnet` symlinked onto the array so the identity
/// key survives reboots, a first-run config written when there is none
/// (what setup.sh does everywhere else), and the daemon started.
/// Also called from the supervision tick (see `supervise_forever`) so
/// a crashed daemon comes back within a minute.
pub fn ensure_unraid_wolfnet() {
    if !is_unraid() || std::env::consts::ARCH != "x86_64" {
        return;
    }
    let _serial = wolfnet_control_lock();
    ensure_unraid_wolfnet_locked();
}

/// The ensure pass proper. Caller MUST hold `wolfnet_control_lock()`:
/// the spawn decision in `start_wolfnet_if_configured` is three separate
/// checks, and only this lock makes them one atomic decision between the
/// supervision tick and an operator's Start/Restart.
fn ensure_unraid_wolfnet_locked() {
    for (bin, asset) in WOLFNET_TOOLS {
        ensure_tool(bin, asset, WOLFNET_RELEASE_BASE);
    }
    persist_wolfnet_etc();
    generate_wolfnet_config_if_missing();
    start_wolfnet_if_configured();
}

/// Serialises everything that may spawn, signal or reap the wolfnet
/// daemon: the 60 s supervision tick and every operator action. Without
/// it two Restart clicks (each on its own web::block thread) or a Start
/// racing the tick could both pass the "not running" checks and spawn
/// twice, or one could reap-and-respawn while the other was still
/// waiting on the old daemon and then `wait()` on the NEW one forever
/// (review finding, 2026-09-10). Never held across an await; held for
/// the length of one ensure pass or one action, which may include the
/// five-second stop grace.
fn wolfnet_control_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    match LOCK.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

// ─── First-run WolfNet configuration ─────────────────────────────────
//
// On every other platform setup.sh writes /etc/wolfnet/config.toml at
// install time (setup.sh:2500-2593). Its Unraid branch is self-contained
// and exits first (setup.sh:950-959), so an Unraid agent got the binaries
// (above) but never a config — and `start_wolfnet_if_configured` then had
// nothing to start, forever. klas 2026-09-10: "wolfnet installed by default
// with the unraid agent would be great". This is the installer's block,
// translated step for step, run once when no config exists.

/// setup.sh:2503-2507 — the host's primary IPv4, tried in the installer's
/// order: the default route's `src`, then `ip route get 1.1.1.1`, then the
/// first global-scope address.
fn detect_host_ip() -> Option<String> {
    let run = |args: &[&str]| -> Option<String> {
        Command::new("timeout").arg("5").arg("ip").args(args).output().ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
    };
    if let Some(out) = run(&["-4", "route", "show", "default"])
        && let Some(ip) = src_after_keyword(&out, "src") { return Some(ip); }
    if let Some(out) = run(&["-4", "route", "get", "1.1.1.1"])
        && let Some(ip) = src_after_keyword(&out, "src") { return Some(ip); }
    if let Some(out) = run(&["-4", "addr", "show", "scope", "global"])
        && let Some(cidr) = out.lines().find(|l| l.trim_start().starts_with("inet ")).and_then(|l| l.split_whitespace().nth(1))
    { return cidr.split('/').next().map(|s| s.to_string()); }
    None
}

/// Pure: the token after the first `keyword` in `text` (awk's `$(i+1)`).
fn src_after_keyword(text: &str, keyword: &str) -> Option<String> {
    let toks: Vec<&str> = text.split_whitespace().collect();
    toks.iter().position(|t| *t == keyword).and_then(|i| toks.get(i + 1)).map(|s| s.to_string())
}

/// setup.sh:2508-2512 — the host IP's last octet, kept when 1..=254,
/// otherwise 1.
fn last_octet_of(host_ip: Option<&str>) -> u8 {
    host_ip
        .and_then(|ip| ip.trim().rsplit('.').next())
        .and_then(|o| o.parse::<u16>().ok())
        .filter(|o| (1..=254).contains(o))
        .map(|o| o as u8)
        .unwrap_or(1)
}

/// setup.sh:2513-2531 — the first of 10.10.{10,20,…,90} that appears in
/// neither `ip route show` nor `ip addr show` (matched as "10.10.N." exactly
/// like the installer's grep), else the installer's own fallback 10.10.10.
/// Pure over the two command outputs.
fn pick_free_wolfnet_subnet(route_show: &str, addr_show: &str) -> String {
    for third in [10u8, 20, 30, 40, 50, 60, 70, 80, 90] {
        let needle = format!("10.10.{}.", third);
        if !route_show.contains(&needle) && !addr_show.contains(&needle) {
            return format!("10.10.{}", third);
        }
    }
    "10.10.10".to_string()
}

/// setup.sh:2573-2590 — the config the installer writes, byte for byte
/// apart from the values. `discovery` is the installer's prompt answer;
/// there is no prompt here, so callers pass its default (N → false).
fn render_wolfnet_config(address: &str, key_file: &str, discovery: bool) -> String {
    format!(
"# WolfNet Configuration
# Auto-generated by WolfStack installer
# Provides cluster overlay network

[network]
interface = \"wolfnet0\"
address = \"{address}\"
subnet = 24
listen_port = 9600
gateway = false
discovery = {discovery}
mtu = 1400

[security]
private_key_file = \"{key_file}\"

# Peers will be added automatically when you add servers to WolfStack
")
}

/// Write the first-run config when `/etc/wolfnet` is our array-backed
/// symlink and holds no config.toml yet. Refuses to run when the symlink
/// is not in place: the daemon is started against /etc/wolfnet/config.toml,
/// so a config written anywhere else would be one the supervisor never sees.
fn generate_wolfnet_config_if_missing() {
    let etc = Path::new(WOLFNET_ETC);
    match std::fs::read_link(etc) {
        Ok(target) if target == Path::new(WOLFNET_APPDATA) => {}
        _ => return, // persist_wolfnet_etc already warned about why
    }
    let config_path = etc.join("config.toml");
    if config_path.exists() {
        return;
    }
    let wolfnet_bin = format!("{}/wolfnet", LINK_DIR);
    if !Path::new(&wolfnet_bin).exists() {
        return; // ensure_tool warned; try again next tick
    }

    // setup.sh:2503-2512
    let host_ip = detect_host_ip();
    let mut last_octet = last_octet_of(host_ip.as_deref());
    // setup.sh:2513-2531
    let route_show = Command::new("timeout").args(["5", "ip", "route", "show"]).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    let addr_show = Command::new("timeout").args(["5", "ip", "addr", "show"]).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    let subnet = pick_free_wolfnet_subnet(&route_show, &addr_show);
    // setup.sh:2535-2546 — the candidate is free when nobody answers a ping;
    // otherwise step the last octet (wrapping 254 → 1), at most 253 times.
    let mut address = format!("{}.{}", subnet, last_octet);
    for _ in 0..253 {
        let answered = Command::new("ping").args(["-c", "1", "-W", "1", &address]).output()
            .map(|o| o.status.success()).unwrap_or(false);
        if !answered { break; }
        warn!("unraid wolfnet: {} already answers — trying the next address", address);
        last_octet = (last_octet % 254) + 1;
        address = format!("{}.{}", subnet, last_octet);
    }

    // setup.sh:2570-2571 — `wolfnet genkey --output <key>` (wolfnet
    // src/main.rs:44-48: `Genkey { output }`). Written via the /etc/wolfnet
    // path so it lands in appdata through the symlink, and referenced by
    // that same path — wolfnet's own default (config.rs default_key_path).
    let key_file = format!("{}/private.key", WOLFNET_ETC);
    if !Path::new(&key_file).exists() {
        let keygen = Command::new("timeout").args(["30", &wolfnet_bin, "genkey", "--output", &key_file]).output();
        match keygen {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                warn!("unraid wolfnet: genkey failed: {} — not writing a config without a key",
                    String::from_utf8_lossy(&o.stderr).trim());
                return;
            }
            Err(e) => { warn!("unraid wolfnet: cannot run genkey: {} — not writing a config", e); return; }
        }
    }

    // setup.sh:2549-2568 — the installer asks about LAN discovery with a
    // default of N; the agent cannot ask, so it takes the default. The
    // WolfNet page → Network Settings turns it on.
    let content = render_wolfnet_config(&address, &key_file, false);
    let tmp = Path::new(WOLFNET_APPDATA).join("config.toml.tmp");
    let written = std::fs::write(&tmp, content)
        .and_then(|_| std::fs::rename(&tmp, Path::new(WOLFNET_APPDATA).join("config.toml")));
    match written {
        Ok(()) => info!("unraid wolfnet: first-run config written — {}/24 on wolfnet0, LAN discovery off (change either on the WolfNet page); peers are added as this node joins a cluster", address),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            warn!("unraid wolfnet: cannot write config.toml: {}", e);
        }
    }
}

#[cfg(test)]
mod first_run_config_tests {
    use super::*;

    #[test]
    fn last_octet_follows_the_installer() {
        assert_eq!(last_octet_of(Some("192.168.1.42")), 42);
        assert_eq!(last_octet_of(Some("10.0.0.254")), 254);
        assert_eq!(last_octet_of(Some("10.0.0.0")), 1, "0 is out of range → 1");
        assert_eq!(last_octet_of(Some("10.0.0.255")), 1);
        assert_eq!(last_octet_of(None), 1);
        assert_eq!(last_octet_of(Some("garbage")), 1);
    }

    #[test]
    fn subnet_pick_skips_ranges_already_present() {
        assert_eq!(pick_free_wolfnet_subnet("default via 192.168.1.1 dev eth0\n", "inet 192.168.1.5/24"), "10.10.10");
        // 10.10.10.x is routed (a WolfNet already on the LAN) → next one.
        assert_eq!(pick_free_wolfnet_subnet("10.10.10.0/24 dev wolfnet0\n", ""), "10.10.20");
        // Present only as an address counts too.
        assert_eq!(pick_free_wolfnet_subnet("", "inet 10.10.10.7/24 scope global br0"), "10.10.20");
        // "10.10.100." must not be mistaken for "10.10.10." (the dot anchors it).
        assert_eq!(pick_free_wolfnet_subnet("10.10.100.0/24 dev br0", ""), "10.10.10");
        let all = (1..=9).map(|i| format!("10.10.{}0.0/24 dev x\n", i)).collect::<String>();
        assert_eq!(pick_free_wolfnet_subnet(&all, ""), "10.10.10", "installer's fallback when none is free");
    }

    #[test]
    fn src_token_extraction() {
        assert_eq!(src_after_keyword("default via 10.10.10.1 dev enp87s0 proto dhcp src 10.10.10.20 metric 100", "src"), Some("10.10.10.20".into()));
        assert_eq!(src_after_keyword("1.1.1.1 via 10.10.10.1 dev eth0 src 10.10.10.30 uid 0\n    cache", "src"), Some("10.10.10.30".into()));
        assert_eq!(src_after_keyword("default via 10.10.10.1 dev eth0", "src"), None);
    }

    #[test]
    fn rendered_config_is_the_installers() {
        let c = render_wolfnet_config("10.10.10.20", "/etc/wolfnet/private.key", false);
        assert!(c.contains("address = \"10.10.10.20\""));
        assert!(c.contains("subnet = 24"));
        assert!(c.contains("listen_port = 9600"));
        assert!(c.contains("discovery = false"));
        assert!(c.contains("gateway = false"));
        assert!(c.contains("mtu = 1400"));
        assert!(c.contains("private_key_file = \"/etc/wolfnet/private.key\""));
        // It must parse as TOML with the fields wolfnet reads (config.rs).
        let doc: toml::Value = toml::from_str(&c).expect("valid TOML");
        assert_eq!(doc["network"]["address"].as_str(), Some("10.10.10.20"));
        assert_eq!(doc["network"]["subnet"].as_integer(), Some(24));
        assert_eq!(doc["security"]["private_key_file"].as_str(), Some("/etc/wolfnet/private.key"));
    }
}

/// Make `/etc/wolfnet` a symlink to the array-backed appdata dir.
/// A real directory left by a manual install is migrated (copied) into
/// appdata first so an existing identity key is never lost — the
/// private key IS the node's mesh identity; losing it would orphan the
/// node from every peer.
fn persist_wolfnet_etc() {
    let etc = Path::new(WOLFNET_ETC);
    if let Err(e) = std::fs::create_dir_all(WOLFNET_APPDATA) {
        warn!("unraid wolfnet: cannot create {}: {}", WOLFNET_APPDATA, e);
        return;
    }
    // Already the symlink we want? (symlink_metadata: never follow.)
    if let Ok(meta) = std::fs::symlink_metadata(etc) {
        if meta.file_type().is_symlink() {
            return;
        }
        // Real dir from a manual install this boot — migrate contents
        // that appdata doesn't already have (never overwrite: appdata
        // is the durable copy, RAM /etc is the transient one). The dir
        // is only replaced when EVERY entry migrated cleanly — a
        // failed or skipped copy followed by remove_dir_all would
        // destroy the one copy of the node's mesh identity key.
        if meta.is_dir() {
            let mut migration_clean = true;
            match std::fs::read_dir(etc) {
                Ok(entries) => {
                    for ent in entries.flatten() {
                        let src = ent.path();
                        if src.is_dir() {
                            // wolfnet keeps a flat config dir; anything
                            // deeper is operator-made — don't guess,
                            // don't delete.
                            warn!("unraid wolfnet: {} contains a subdirectory ({:?}) — leaving /etc/wolfnet as-is; move it into {} manually", WOLFNET_ETC, ent.file_name(), WOLFNET_APPDATA);
                            migration_clean = false;
                            continue;
                        }
                        let dest = Path::new(WOLFNET_APPDATA).join(ent.file_name());
                        if !dest.exists()
                            && let Err(e) = std::fs::copy(&src, &dest) {
                                warn!("unraid wolfnet: migrating {:?}: {}", ent.file_name(), e);
                                migration_clean = false;
                            }
                    }
                }
                Err(e) => {
                    warn!("unraid wolfnet: cannot read {}: {}", WOLFNET_ETC, e);
                    migration_clean = false;
                }
            }
            if !migration_clean {
                return; // retry next supervision tick; never delete unmigrated state
            }
            if let Err(e) = std::fs::remove_dir_all(etc) {
                warn!("unraid wolfnet: cannot replace {} with symlink: {}", WOLFNET_ETC, e);
                return;
            }
        } else if std::fs::remove_file(etc).is_err() {
            return;
        }
    }
    match std::os::unix::fs::symlink(WOLFNET_APPDATA, etc) {
        Ok(()) => info!("unraid wolfnet: {} → {}", WOLFNET_ETC, WOLFNET_APPDATA),
        Err(e) => warn!("unraid wolfnet: symlink {}: {}", WOLFNET_ETC, e),
    }
}

/// Start the wolfnet daemon when a config exists and it isn't already
/// running. Unraid has no systemd — the agent is the supervisor. The
/// invocation matches setup.sh's systemd unit verbatim
/// (`ExecStart=/usr/local/bin/wolfnet --config /etc/wolfnet/config.toml`);
/// pgrep is the same liveness check src/networking uses for reloads.
fn start_wolfnet_if_configured() {
    if !Path::new(WOLFNET_APPDATA).join("config.toml").exists() {
        return; // not configured — nothing to run
    }
    // The operator pressed Stop (or the node is disabled): the supervisor
    // must not undo that on its next tick. Cleared by Start/Restart.
    if WOLFNET_STOPPED.load(Ordering::Relaxed) {
        return;
    }
    // 1. A daemon WE started and that is still alive is authoritative —
    //    no probe involved. This is the check that makes a spawn storm
    //    impossible.
    {
        let mut owned = wolfnet_child();
        if let Some(child) = owned.as_mut() {
            match child.try_wait() {
                Ok(None) => return,               // still running
                Ok(Some(status)) => {             // exited; try_wait reaped it
                    warn!("unraid wolfnet: daemon exited ({}) — restarting after backoff", status);
                    *owned = None;
                }
                // Can't tell whether our own child is alive — never spawn
                // on uncertainty.
                Err(e) => {
                    warn!("unraid wolfnet: cannot check daemon state: {} — not starting another", e);
                    return;
                }
            }
        }
    }

    // 2. Backoff: a daemon that dies immediately must not be respawned
    //    every single tick. Doubles to a 1h ceiling and resets once one
    //    survives a tick.
    let now = now_secs();
    if now < WOLFNET_RETRY_AFTER.load(Ordering::Relaxed) {
        return;
    }

    // 3. Someone else's wolfnet (manual install, or ours from before an
    //    agent restart)? Read procfs directly: `pgrep -x` was the old
    //    check and its exit status is ambiguous on busybox, where an
    //    unsupported flag looks exactly like "no match" — which meant a
    //    new VPN daemon every 60 seconds, forever (klas, Unraid,
    //    2026-08-12). Unknown => do NOT spawn.
    match wolfnet_running_externally() {
        Some(true) => return,
        None => {
            warn!("unraid wolfnet: could not determine whether a daemon is already running — not starting another");
            return;
        }
        Some(false) => {}
    }
    let log = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open(format!("{}/wolfnet.log", WOLFNET_APPDATA));
    let Ok(log) = log else {
        warn!("unraid wolfnet: cannot open wolfnet.log — not starting");
        return;
    };
    let err = match log.try_clone() {
        Ok(c) => c,
        Err(_) => { warn!("unraid wolfnet: cannot clone log handle — not starting"); return; }
    };
    match Command::new(format!("{}/wolfnet", LINK_DIR))
        .args(["--config", "/etc/wolfnet/config.toml"])
        .stdin(std::process::Stdio::null())
        .stdout(log)
        .stderr(err)
        .spawn()
    {
        Ok(child) => {
            info!("unraid wolfnet: daemon started (pid {})", child.id());
            // Keep the Child: the next tick calls try_wait() on it, which
            // both answers "is it alive?" authoritatively and reaps it
            // when it isn't. (The old code moved the Child into a waiter
            // thread, leaving the supervisor with nothing to check but a
            // pgrep probe.)
            *wolfnet_child() = Some(child);
            // Next failure waits at least the base interval; a daemon that
            // survives resets this below.
            WOLFNET_RETRY_AFTER.store(now_secs() + WOLFNET_RETRY_BASE_SECS, Ordering::Relaxed);
            WOLFNET_RETRY_BACKOFF.store(WOLFNET_RETRY_BASE_SECS, Ordering::Relaxed);
        }
        Err(e) => {
            // Exponential backoff, capped at an hour: a host that can
            // never start wolfnet (missing /dev/net/tun, bad config)
            // must not pay for a spawn attempt every minute forever.
            let next = (WOLFNET_RETRY_BACKOFF.load(Ordering::Relaxed) * 2)
                .clamp(WOLFNET_RETRY_BASE_SECS, WOLFNET_RETRY_MAX_SECS);
            WOLFNET_RETRY_BACKOFF.store(next, Ordering::Relaxed);
            WOLFNET_RETRY_AFTER.store(now_secs() + next, Ordering::Relaxed);
            warn!("unraid wolfnet: failed to start daemon: {} — next attempt in {}s", e, next);
        }
    }
}

/// The wolfnet daemon this process started, if any. Owning the `Child`
/// is what makes liveness authoritative instead of probe-dependent.
fn wolfnet_child() -> std::sync::MutexGuard<'static, Option<std::process::Child>> {
    static CHILD: std::sync::LazyLock<std::sync::Mutex<Option<std::process::Child>>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(None));
    match CHILD.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

const WOLFNET_RETRY_BASE_SECS: u64 = 60;
const WOLFNET_RETRY_MAX_SECS: u64 = 3600;
static WOLFNET_RETRY_AFTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static WOLFNET_RETRY_BACKOFF: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(WOLFNET_RETRY_BASE_SECS);

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Is a wolfnet daemon running that we don't own? Reads `/proc/<pid>/comm`
/// rather than shelling out, so the answer doesn't depend on which
/// `pgrep` the distro ships. `None` means "couldn't tell" — callers must
/// treat that as "do not spawn", never as "not running".
///
/// Runs once per supervision tick (60s), so this is not a hot scan —
/// see tests/resource_safety.rs for the scans that must stay cached.
fn wolfnet_running_externally() -> Option<bool> {
    wolfnet_pids().map(|pids| !pids.is_empty())
}

/// Every `wolfnet` daemon PID on the host, from `/proc/<pid>/comm` (the
/// same probe as `wolfnet_running_externally`, which is defined on top of
/// this). `None` means /proc could not be read at all — "couldn't tell".
/// The agent's own PID is never `wolfnet`, so this never lists ourselves.
fn wolfnet_pids() -> Option<Vec<u32>> {
    let entries = std::fs::read_dir("/proc").ok()?;
    let mut pids = Vec::new();
    for ent in entries.flatten() {
        let name = ent.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        // A process can exit mid-scan; a missing comm is not an error.
        if let Ok(comm) = std::fs::read_to_string(format!("/proc/{}/comm", pid))
            && comm.trim() == "wolfnet" {
                pids.push(pid);
            }
    }
    Some(pids)
}

// ─── Operator service control (the systemctl stand-in) ───────────────
//
// On every other platform WolfStack drives WolfNet through systemd:
// `systemctl start|stop|restart|enable|disable wolfnet`
// (src/networking/mod.rs `wolfnet_service_action`). Unraid has no systemd
// and this agent IS the supervisor, so the WolfNet page's Start/Stop/
// Restart buttons landed on "systemd (systemctl) isn't available on this
// host" (klas, Unraid, 2026-09-10). These functions give each systemctl
// verb its supervisor equivalent:
//
//   start    → clear the stop latch + backoff, run the ensure pass (which
//              fetches, persists, configures and spawns), verify it lives
//   stop     → set the stop latch (so the 60s tick does not undo it),
//              SIGTERM the daemon, SIGKILL after a grace period
//   restart  → stop without latching, then start
//   enable   → remove the persisted disable marker
//   disable  → write the persisted disable marker (honoured at the next
//              agent start; like `systemctl disable`, it does not stop
//              a running daemon)
//
// Like `systemctl stop`, the stop latch is process state: it lasts until
// Start, an agent restart, or a reboot. Only Disable persists.

/// Operator asked for the daemon to stay down (Stop, or a disabled node).
static WOLFNET_STOPPED: AtomicBool = AtomicBool::new(false);

/// Persisted "do not start WolfNet with the agent" marker — lives on the
/// array next to config.toml so it survives reboots, which RAM /etc and
/// /var do not.
fn wolfnet_disabled_marker() -> std::path::PathBuf {
    Path::new(WOLFNET_APPDATA).join("disabled")
}

/// (installed, running) the way `get_wolfnet_status` reports it on a
/// systemd host: installed = the bundled binary is present (the agent's
/// equivalent of "the unit exists"), running = a daemon is alive — either
/// the child this process owns or one started before an agent restart.
pub fn wolfnet_state() -> (bool, bool) {
    let installed = Path::new(LINK_DIR).join("wolfnet").exists()
        || Path::new(TOOLS_DIR).join("wolfnet").exists();
    (installed, wolfnet_daemon_running())
}

/// `systemctl is-enabled` equivalent: no persisted disable marker.
pub fn wolfnet_enabled() -> bool {
    !wolfnet_disabled_marker().exists()
}

/// Is any wolfnet daemon alive right now? Checks the owned child first
/// (authoritative, and reaps it if it has exited), then the procfs scan.
/// Uncertainty from the scan counts as "not running" HERE because this
/// answers a status question, not a spawn decision — the spawn path keeps
/// its own "never spawn on uncertainty" rule in `start_wolfnet_if_configured`.
fn wolfnet_daemon_running() -> bool {
    {
        let mut owned = wolfnet_child();
        if let Some(child) = owned.as_mut() {
            match child.try_wait() {
                Ok(None) => return true,
                Ok(Some(_)) => *owned = None,
                Err(_) => {}
            }
        }
    }
    wolfnet_running_externally() == Some(true)
}

/// Start/stop/restart/enable/disable WolfNet on an Unraid node. Returns
/// the operator-facing message on success. Errors when the host is not
/// Unraid (callers dispatch on `is_unraid()` first), the verb is unknown,
/// or the daemon does not come up.
pub fn wolfnet_service_action(action: &str) -> Result<String, String> {
    if !is_unraid() {
        return Err("Not an Unraid host — WolfNet is managed through systemd here.".to_string());
    }
    let _serial = wolfnet_control_lock();
    match action {
        "start" => {
            WOLFNET_STOPPED.store(false, Ordering::Relaxed);
            if wolfnet_daemon_running() {
                return Ok("WolfNet is already running".to_string());
            }
            start_wolfnet_now()?;
            Ok("WolfNet started".to_string())
        }
        "stop" => {
            WOLFNET_STOPPED.store(true, Ordering::Relaxed);
            let stopped = stop_wolfnet_daemon()?;
            Ok(if stopped == 0 {
                "WolfNet was not running; the agent will keep it stopped until Start".to_string()
            } else {
                "WolfNet stopped; the agent will keep it stopped until Start (or a reboot — use Disable to keep it off)".to_string()
            })
        }
        "restart" => {
            WOLFNET_STOPPED.store(false, Ordering::Relaxed);
            stop_wolfnet_daemon()?;
            start_wolfnet_now()?;
            Ok("WolfNet restarted".to_string())
        }
        "enable" => {
            match std::fs::remove_file(wolfnet_disabled_marker()) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("Failed to enable WolfNet: {}", e)),
            }
            Ok("WolfNet enabled — it will start with the agent from its next start or a reboot; press Start to run it now".to_string())
        }
        "disable" => {
            std::fs::write(
                wolfnet_disabled_marker(),
                concat!(
                    "WolfStack: WolfNet will not be started with the agent while this file exists.\n",
                    "Remove it, or press Enable on the WolfNet page.\n",
                ),
            )
            .map_err(|e| format!("Failed to disable WolfNet: {}", e))?;
            Ok("WolfNet disabled — it will not start with the agent (Stop it to bring it down now)".to_string())
        }
        other => Err(format!("Unknown WolfNet action: {}", other)),
    }
}

/// Run the ensure pass immediately (ignoring any failure backoff — the
/// operator asked) and confirm the daemon is alive half a second later,
/// the same settle time `reload_or_restart_wolfnet` gives a SIGHUP.
/// Caller holds `wolfnet_control_lock()`.
fn start_wolfnet_now() -> Result<(), String> {
    WOLFNET_RETRY_AFTER.store(0, Ordering::Relaxed);
    WOLFNET_RETRY_BACKOFF.store(WOLFNET_RETRY_BASE_SECS, Ordering::Relaxed);
    ensure_unraid_wolfnet_locked();
    std::thread::sleep(std::time::Duration::from_millis(500));
    if wolfnet_daemon_running() {
        return Ok(());
    }
    let config = Path::new(WOLFNET_APPDATA).join("config.toml");
    if !Path::new(LINK_DIR).join("wolfnet").exists() {
        return Err(format!(
            "WolfNet binary is not installed and could not be downloaded to {} — check the agent log and the node's internet access",
            TOOLS_DIR
        ));
    }
    if !config.exists() {
        return Err(format!(
            "WolfNet has no configuration and the agent could not write one at {} — check the agent log",
            config.display()
        ));
    }
    Err(format!(
        "WolfNet did not stay running — see {}/wolfnet.log",
        WOLFNET_APPDATA
    ))
}

/// SIGTERM every wolfnet daemon (the owned child and any external one),
/// wait up to five seconds for a clean exit, SIGKILL whatever is left,
/// and reap the owned child. Returns how many daemons were signalled.
fn stop_wolfnet_daemon() -> Result<usize, String> {
    let mut pids: Vec<u32> = Vec::new();
    let mut owned_pid: Option<u32> = None;
    {
        let mut owned = wolfnet_child();
        if let Some(child) = owned.as_mut() {
            match child.try_wait() {
                Ok(None) => {
                    owned_pid = Some(child.id());
                    pids.push(child.id());
                }
                _ => *owned = None, // already gone — nothing to signal
            }
        }
    }
    match wolfnet_pids() {
        Some(external) => {
            for pid in external {
                if !pids.contains(&pid) {
                    pids.push(pid);
                }
            }
        }
        // /proc unreadable: we can still stop the daemon we own — its PID
        // came from the Child handle, not from the scan.
        None if owned_pid.is_some() => {
            warn!("unraid wolfnet: cannot read /proc — stopping only the daemon this agent started");
        }
        None => return Err("cannot read /proc to find the WolfNet daemon".to_string()),
    }
    if pids.is_empty() {
        return Ok(0);
    }
    for &pid in &pids {
        // SAFETY: kill(2) with a PID we just read from /proc and a fixed
        // signal has no memory-safety preconditions.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM); }
    }
    // Grace period: wolfnet tears down its TUN device and status file on
    // SIGTERM; give it the time systemd's default stop would.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if pids.iter().all(|pid| !pid_is_live_wolfnet(*pid)) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    for &pid in &pids {
        // Re-checked by name right before the kill: a PID that exited
        // during the grace window and was recycled by something else
        // must never be the one we SIGKILL.
        if pid_is_live_wolfnet(pid) {
            warn!("unraid wolfnet: pid {} ignored SIGTERM for 5s — sending SIGKILL", pid);
            // SAFETY: as above.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL); }
        }
    }
    // Reap the child WE signalled so it does not linger as a zombie and
    // the next start does not see a stale handle. The slot is compared by
    // PID: with the control lock held nobody can have replaced it, and
    // the check keeps a mismatch from ever turning into a wait() on a
    // live daemon.
    {
        let mut owned = wolfnet_child();
        if let Some(child) = owned.as_mut()
            && Some(child.id()) == owned_pid
        {
            let _ = child.wait();
            *owned = None;
        }
    }
    info!("unraid wolfnet: stopped {} daemon(s) on operator request", pids.len());
    Ok(pids.len())
}

/// Is `pid` still a running (non-zombie) process whose comm is `wolfnet`?
/// False for an exited PID, a reaped-and-recycled PID now belonging to
/// something else, and an exited-but-unreaped zombie (only our own child
/// can be one, and stop reaps it right after).
fn pid_is_live_wolfnet(pid: u32) -> bool {
    let is_wolfnet = std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|c| c.trim() == "wolfnet")
        .unwrap_or(false);
    is_wolfnet && !zombie(pid)
}

/// An exited-but-unreaped process still has a /proc entry; treat it as
/// gone for the purposes of the stop wait.
fn zombie(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{}/stat", pid))
        .map(|s| {
            // "<pid> (<comm>) <state> ..." — comm may contain spaces, so
            // take the field after the LAST ')'.
            s.rsplit(')').next()
                .map(|rest| rest.trim_start().starts_with('Z'))
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

fn ensure_tool(bin: &str, asset: &str, base: &str) {
    // Already runnable (native Unraid tool, or our link from a prior pass)?
    // `which` is present on Unraid (busybox/coreutils both ship it).
    let on_path = Command::new("which").arg(bin).output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if on_path {
        return;
    }

    let persisted = format!("{}/{}", TOOLS_DIR, bin);
    if !Path::new(&persisted).exists() {
        if let Err(e) = download_tool(base, asset, &persisted) {
            warn!("unraid tools: could not fetch {}: {} — the feature needing it will report it missing", bin, e);
            return;
        }
        info!("unraid tools: downloaded {} → {}", bin, persisted);
    }

    // Re-link into RAM-backed /usr/local/bin (fresh every boot).
    let link = format!("{}/{}", LINK_DIR, bin);
    let _ = std::fs::remove_file(&link); // stale symlink from a previous boot image
    match std::os::unix::fs::symlink(&persisted, &link) {
        Ok(()) => info!("unraid tools: {} linked → {}", bin, link),
        Err(e) => warn!("unraid tools: could not link {} into {}: {}", bin, LINK_DIR, e),
    }
}

/// Download one asset to `dest` via curl (present on every Unraid — setup.sh
/// itself arrives through it). Temp-file + rename so a cut connection never
/// leaves a half-written binary where a feature might exec it. Bounded:
/// 15s connect, 10min total (assets are up to ~20MB, lines can be slow).
fn download_tool(base: &str, asset: &str, dest: &str) -> Result<(), String> {
    if let Some(dir) = Path::new(dest).parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {}", dir.display(), e))?;
    }
    let url = format!("{}/{}", base, asset);
    let tmp = format!("{}.download", dest);
    let out = Command::new("curl")
        .args(["-fSL", "--connect-timeout", "15", "--max-time", "600", "-o", &tmp, &url])
        .output()
        .map_err(|e| format!("failed to run curl: {}", e))?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "download of {} failed: {}",
            url,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    // Executable before the rename so the file is never visible non-runnable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {}: {}", tmp, e))?;
    }
    std::fs::rename(&tmp, dest).map_err(|e| format!("rename into place: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_assets_are_x86_64_suffixed() {
        // The release only carries x86_64 assets (Unraid is x86_64-only);
        // a manifest entry without the suffix would 404 on every node.
        for (bin, asset) in TOOLS.iter().chain(WOLFNET_TOOLS) {
            assert!(asset.ends_with("-x86_64"), "{} asset {} lacks arch suffix", bin, asset);
            assert!(!bin.contains('/'), "{} must be a bare binary name", bin);
        }
    }

    #[test]
    fn non_unraid_is_a_noop() {
        // On any dev/CI box without /etc/unraid-version this must return
        // without touching the filesystem — guard the guard.
        if !is_unraid() {
            ensure_unraid_tools(); // must not panic, download, or link anything
        }
    }
}

#[cfg(test)]
mod wolfnet_supervision_tests {
    use super::*;

    #[test]
    fn liveness_probe_never_reports_false_on_uncertainty() {
        // The supervisor must only spawn on a DEFINITE "not running".
        // `pgrep -x` was the old probe and its exit status is ambiguous
        // on busybox — an unsupported flag looks identical to "no
        // match", which spawned a new VPN daemon every 60s forever
        // (klas, Unraid, 2026-08-12). The procfs reader answers
        // Some(true)/Some(false) only when it actually knows.
        let answer = wolfnet_running_externally();
        // Deliberately NOT asserting true or false: the answer depends
        // on whether the host happens to run wolfnet (the dev box does,
        // which is how this probe was confirmed against a live process).
        // The invariant under test is that with /proc readable the probe
        // commits to a DEFINITE answer, and that "couldn't tell" is
        // None — never Some(false), which is the value that would let
        // the supervisor spawn.
        if std::path::Path::new("/proc/self/comm").exists() {
            assert!(answer.is_some(), "with /proc readable the probe must give a definite answer");
        }
        // Whatever it says, it must agree with itself — a probe that
        // flickered would spawn on the tick that happened to say false.
        assert_eq!(answer, wolfnet_running_externally(), "probe must be stable across calls");
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        // Mirrors the failure path's arithmetic: doubling, floored at
        // the base interval and capped at an hour, so a host that can
        // never start wolfnet stops paying a spawn per minute.
        let mut backoff = WOLFNET_RETRY_BASE_SECS;
        let mut seen = Vec::new();
        for _ in 0..10 {
            backoff = (backoff * 2).clamp(WOLFNET_RETRY_BASE_SECS, WOLFNET_RETRY_MAX_SECS);
            seen.push(backoff);
        }
        assert!(seen[0] > WOLFNET_RETRY_BASE_SECS, "backoff must grow after a failure");
        assert!(seen.iter().all(|s| *s <= WOLFNET_RETRY_MAX_SECS), "backoff must be capped");
        assert_eq!(*seen.last().unwrap(), WOLFNET_RETRY_MAX_SECS, "repeated failure settles at the cap");
    }

    #[test]
    fn supervision_is_a_no_op_off_unraid() {
        // Every path is guarded by is_unraid(); on a non-Unraid host
        // this must not spawn, scan, or touch the filesystem.
        if !is_unraid() {
            ensure_unraid_wolfnet();
            assert!(wolfnet_child().is_none(), "no daemon may be owned on a non-Unraid host");
        }
    }

    #[test]
    fn service_control_refuses_off_unraid() {
        // The systemctl stand-in must never signal or spawn anything on a
        // host that is not Unraid — callers dispatch on is_unraid() and
        // this is the belt to that brace. Every verb, including unknown
        // ones, is an Err there and leaves the stop latch untouched.
        if !is_unraid() {
            let before = WOLFNET_STOPPED.load(Ordering::Relaxed);
            for verb in ["start", "stop", "restart", "enable", "disable", "bogus"] {
                assert!(wolfnet_service_action(verb).is_err(), "{} must refuse off Unraid", verb);
            }
            assert_eq!(WOLFNET_STOPPED.load(Ordering::Relaxed), before);
            assert!(wolfnet_child().is_none());
        }
    }

    #[test]
    fn kill_target_check_never_matches_a_foreign_process() {
        // SIGKILL is only ever sent to a PID that is STILL a live wolfnet.
        // This process is not wolfnet, and a PID that does not exist is
        // not one either — both must read false, or a recycled PID could
        // be killed.
        assert!(!pid_is_live_wolfnet(std::process::id()));
        assert!(!pid_is_live_wolfnet(u32::MAX));
        if let Some(p) = wolfnet_pids() {
            assert!(!p.contains(&std::process::id()), "the agent itself is never a wolfnet daemon");
        }
    }

    #[test]
    fn control_lock_is_not_reentrant_by_construction() {
        // ensure_unraid_wolfnet() takes the lock and calls the _locked
        // variant; wolfnet_service_action takes it and calls the _locked
        // variant too. Re-entering through the public fn from inside an
        // action would self-deadlock (std::sync::Mutex), so the only
        // legal pattern is take → drop → take again, in sequence. This
        // pins that the guard type is a plain droppable MutexGuard.
        let g = wolfnet_control_lock();
        drop(g);
        let _g2 = wolfnet_control_lock();
    }

    #[test]
    fn zombie_parser_reads_state_after_last_paren() {
        // /proc/<pid>/stat: "<pid> (<comm>) <state> ..." — comm can hold
        // spaces and parentheses, so the state is after the LAST ')'.
        // Our own process is alive, never a zombie.
        assert!(!zombie(std::process::id()));
        // A PID that does not exist is not a zombie either.
        assert!(!zombie(u32::MAX));
    }

    #[test]
    fn disabled_marker_lives_beside_the_config() {
        // The marker must persist across reboots, so it has to be on the
        // array with config.toml — not in RAM-backed /etc or /var.
        let marker = wolfnet_disabled_marker();
        assert_eq!(marker.parent().unwrap(), Path::new(WOLFNET_APPDATA));
        assert!(WOLFNET_APPDATA.starts_with("/mnt/user/appdata/"));
    }
}
