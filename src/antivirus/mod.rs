// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Host-side signature antivirus / rootkit scanning.
//!
//! Wraps **ClamAV** (signature AV), **rkhunter** (rootkit hunter), and
//! **chkrootkit** (complementary rootkit scanner) so an operator can
//! install + scan + quarantine across an entire fleet from the
//! Security page.
//!
//! ## Coverage model
//!
//! One install per *host* covers every workload on it: ClamAV reads
//! the host filesystem directly, which includes every LXC rootfs
//! (`/var/lib/lxc`, `/var/lib/vz/private`), every Docker overlay
//! (`/var/lib/docker`), and every container engine path WolfStack
//! manages. Running VMs are NOT covered — their disks are locked and
//! their filesystems are independent. That's a separate feature
//! (libguestfs / guest-agent driven), explicitly out of scope here.
//!
//! ## Action model
//!
//! - **ClamAV** findings → file path is known + confidence is high.
//!   Default action: **quarantine** the file (chmod 000 + move to
//!   `/var/quarantine/wolfstack/<id>/<basename>`) AND **kill any
//!   processes currently using it** (via fuser / /proc walk). Both
//!   reversible from the UI — restore puts the file back with its
//!   original mode + owner; delete removes it permanently.
//! - **rkhunter** / **chkrootkit** findings → high false-positive rate
//!   on Debian/Proxmox (`/dev/.udev`, `/etc/.pwd.lock`, package-upgrade
//!   transient warnings). Stored as findings + alert only; no auto-action.
//!
//! ## Distros
//!
//! Detected via `/etc/os-release` ID/ID_LIKE. Supported install
//! managers: `apt` (Debian/Ubuntu/Proxmox), `dnf` (Fedora/RHEL/Rocky/
//! Alma), `pacman` (Arch), `zypper` (openSUSE). On Arch, chkrootkit
//! is AUR-only and is reported as `not_available` rather than failed.
//!
//! ## Persistence
//!
//! - `/etc/wolfstack/antivirus.json`           — config
//! - `/etc/wolfstack/antivirus-findings.json`  — last N findings (cap 500)
//! - `/etc/wolfstack/antivirus-quarantine.json` — current quarantine inventory
//! - `/var/quarantine/wolfstack/`              — quarantined file payloads

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::RwLock;
use std::time::SystemTime;

// ══════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════

const CONFIG_PATH: &str = "/etc/wolfstack/antivirus.json";
const FINDINGS_PATH: &str = "/etc/wolfstack/antivirus-findings.json";
const QUARANTINE_INDEX_PATH: &str = "/etc/wolfstack/antivirus-quarantine.json";
const QUARANTINE_ROOT: &str = "/var/quarantine/wolfstack";
const MAX_FINDINGS_RETAINED: usize = 500;
/// Live-output ring buffer cap for install runs. apt-get install with a
/// fresh ClamAV signature download emits a few hundred lines; 800 gives
/// plenty of headroom without unbounded growth if something goes wrong.
const MAX_INSTALL_LINES: usize = 800;

/// Filesystem subtrees never worth scanning. Kernel-virtual or
/// WolfStack-owned. ClamAV's `--exclude-dir` accepts regex anchored
/// at the start.
///
/// These are the *static* defaults. At scan time we ALSO read
/// `/proc/mounts` via `discover_skippable_mountpoints` and add an
/// explicit exclude for every mountpoint whose fs type is network /
/// FUSE / overlay / virtual — that's how we keep clamscan out of
/// S3FS-mounted buckets, NFS shares, sshfs, etc. wherever they are
/// in the tree (not just /mnt).
const SCAN_EXCLUDE_REGEX: &[&str] = &[
    "^/sys",
    "^/proc",
    "^/dev",
    "^/run",
    "^/var/lib/wolfstack",
    "^/var/quarantine",
    // Live VM disk images — locked, scanning while running can hang or
    // produce false reads.
    "^/var/lib/vz/images",
    "^/var/lib/libvirt/images",
    // Conventional remote-mount roots — defensive even though the
    // /proc/mounts walk usually catches the actual mountpoints below.
    "^/mnt",
    "^/media",
];

/// Filesystem types that should NEVER be scanned. We always exclude
/// these regardless of where they're mounted.
///
/// - Network filesystems (nfs/cifs/9p/ceph/etc.) — files belong to the
///   server, which has its own scanner; walking them from a client
///   either hangs (stale mount) or burns hours on millions of files.
/// - FUSE-backed mounts (`fuse.*`) — typical case is s3fs, rclone-mount,
///   gocryptfs, sshfs. Same arguments as network mounts.
/// - Virtual / pseudo filesystems — proc/sys/devpts/cgroup/etc. Nothing
///   to scan; some have files that block forever on read().
/// - Overlay — Docker container layer storage. Scanned via the underlying
///   block fs at /var/lib/docker; the overlay mount itself is a
///   duplicate view.
/// - squashfs / iso9660 — read-only image mounts; the image file is
///   scanned by its host filesystem.
fn is_skippable_fstype(t: &str) -> bool {
    if t.starts_with("fuse") { return true; }      // fuse, fuse.sshfs, fuse.s3fs, fuseblk…
    matches!(t,
        // Network
        "nfs" | "nfs4" | "cifs" | "smb" | "smbfs" |
        "ceph" | "9p" | "gfs2" | "ocfs2" | "lustre" | "afs" | "coda" |
        // Virtual / pseudo
        "proc" | "sysfs" | "devpts" | "devtmpfs" | "tmpfs" |
        "cgroup" | "cgroup2" | "pstore" | "bpf" | "autofs" |
        "securityfs" | "debugfs" | "configfs" | "fusectl" |
        "mqueue" | "hugetlbfs" | "tracefs" | "ramfs" |
        "rpc_pipefs" | "nsfs" | "binfmt_misc" | "efivarfs" |
        // Container overlay / read-only image mounts
        "overlay" | "overlay2" | "squashfs" | "iso9660"
    )
}

/// Read `/proc/mounts` and return every mountpoint whose fs type is
/// in [`is_skippable_fstype`]. Mountpoints come back *un-escaped*
/// — `/proc/mounts` uses `\nnn` octal for spaces / tabs / newlines and
/// we restore those so the path matches what clamscan sees on disk.
fn discover_skippable_mountpoints() -> Vec<String> {
    let text = match std::fs::read_to_string("/proc/mounts") {
        Ok(t) => t, Err(_) => return Vec::new(),
    };
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 { continue; }
        let mp = parts[1];
        let ty = parts[2];
        if !is_skippable_fstype(ty) { continue; }
        let unescaped = unescape_mount_path(mp);
        // Never exclude "/" — that would silently skip the whole scan.
        // (Shouldn't happen in practice; tmpfs is sometimes mounted at
        // odd places but never at /.)
        if unescaped == "/" { continue; }
        out.push(unescaped);
    }
    out.sort();
    out.dedup();
    out
}

/// Decode `/proc/mounts` octal-escape sequences. `\\040` is space,
/// `\\011` is tab, `\\012` is newline, `\\134` is literal backslash.
fn unescape_mount_path(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len()
            && bytes[i+1].is_ascii_digit()
            && bytes[i+2].is_ascii_digit()
            && bytes[i+3].is_ascii_digit()
        {
            let a = (bytes[i+1] - b'0') as u32;
            let b = (bytes[i+2] - b'0') as u32;
            let c = (bytes[i+3] - b'0') as u32;
            // Octal — digits 0-7 only.
            if a < 8 && b < 8 && c < 8 {
                let byte = (a * 64 + b * 8 + c) as u8;
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Escape regex metacharacters in a literal path so it can be embedded
/// in a ClamAV `--exclude-dir` regex without false matches. ClamAV
/// uses POSIX extended regex; the metacharacters we escape are the
/// usual suspects.
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if "\\.+*?^$()[]{}|".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Default scan root. Single `/` walks everything else through the
/// excludes above. Operators can override via config.
const DEFAULT_SCAN_ROOT: &str = "/";

// ══════════════════════════════════════════════════════════
// Configuration
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntivirusConfig {
    /// Master enable. When false, no scheduled scans, no auto-action.
    /// On-demand scans from the API still work for verification.
    #[serde(default)]
    pub enabled: bool,
    /// Hours between scheduled scans. 0 = manual only. Clamped to
    /// [1, 168] at apply time when non-zero.
    #[serde(default = "default_schedule_hours")]
    pub schedule_hours: u32,
    /// Quarantine ClamAV-detected files automatically. Default true.
    #[serde(default = "default_true")]
    pub auto_quarantine: bool,
    /// Kill processes currently using a ClamAV-detected file.
    /// Default true. Only triggers when `auto_quarantine` is also true.
    #[serde(default = "default_true")]
    pub auto_kill: bool,
    /// Include ClamAV in scans.
    #[serde(default = "default_true")]
    pub run_clamav: bool,
    /// Include rkhunter in scans.
    #[serde(default = "default_true")]
    pub run_rkhunter: bool,
    /// Include chkrootkit in scans.
    #[serde(default = "default_true")]
    pub run_chkrootkit: bool,
    /// Roots to scan with ClamAV. Defaults to `["/"]` which (combined
    /// with the exclude regex) walks the full host including container
    /// layers.
    #[serde(default = "default_scan_roots")]
    pub scan_roots: Vec<String>,
    /// Additional excludes (regex, ClamAV `--exclude-dir` form).
    /// Appended to `SCAN_EXCLUDE_REGEX`.
    #[serde(default)]
    pub extra_excludes: Vec<String>,
    /// Real-time on-access scanning via clamonacc + clamd. When true,
    /// every file open is scanned via the kernel's fanotify API and
    /// matches are auto-quarantined (--move to /var/quarantine/wolfstack).
    /// OFF by default — opt-in because:
    /// (a) requires installing clamav-daemon / clamd (extra package)
    /// (b) adds latency to every file open on the host
    /// (c) eats memory (clamd loads the full signature DB resident)
    #[serde(default)]
    pub enable_on_access: bool,
}

fn default_true() -> bool { true }
fn default_schedule_hours() -> u32 { 24 }
fn default_scan_roots() -> Vec<String> { vec![DEFAULT_SCAN_ROOT.into()] }

impl Default for AntivirusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            schedule_hours: default_schedule_hours(),
            auto_quarantine: true,
            auto_kill: true,
            run_clamav: true,
            run_rkhunter: true,
            run_chkrootkit: true,
            scan_roots: default_scan_roots(),
            extra_excludes: Vec::new(),
            enable_on_access: false,
        }
    }
}

impl AntivirusConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string(CONFIG_PATH) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = Path::new(CONFIG_PATH).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into());
        std::fs::write(CONFIG_PATH, body)?;
        let _ = chmod_600(CONFIG_PATH);
        Ok(())
    }

    /// Build the effective exclude-regex list (defaults + user extras).
    pub fn effective_excludes(&self) -> Vec<String> {
        let mut out: Vec<String> = SCAN_EXCLUDE_REGEX.iter().map(|s| s.to_string()).collect();
        out.extend(self.extra_excludes.iter().cloned());
        out
    }
}

// ══════════════════════════════════════════════════════════
// Installation status
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolStatus {
    pub installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Last ClamAV signature update timestamp (ClamAV only). Format: RFC3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_db_update: Option<String>,
    /// Set to true when the tool exists in repos but isn't currently
    /// installed (e.g. chkrootkit on Arch — AUR-only, we don't auto-pull).
    #[serde(default)]
    pub not_available_on_distro: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InstallStatus {
    pub clamav: ToolStatus,
    pub rkhunter: ToolStatus,
    pub chkrootkit: ToolStatus,
    pub distro: String,
    pub package_manager: String,
    /// On-access scanning daemon + service status. "disabled" |
    /// "enabling" | "enabled" | "disabling" | "failed". Derived from
    /// systemd unit state — refreshed by detect_install_status.
    #[serde(default = "default_on_access_state")]
    pub on_access_state: String,
    /// Last failure reason if on_access_state == "failed".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_access_error: Option<String>,
}

fn default_on_access_state() -> String { "disabled".into() }

/// Per-distro-family knowledge for on-access scanning. Captures the
/// package name, systemd unit names, config file path, and clamd log
/// path — all of which differ between distros for the same upstream
/// software.
#[derive(Debug, Clone)]
struct OnAccessProfile {
    /// Package providing clamd + clamonacc binaries.
    pkg_daemon: &'static str,
    /// systemd service that runs clamd.
    svc_daemon: &'static str,
    /// systemd service that runs clamonacc. None means we manage it
    /// ourselves via a generated unit (no distro-provided service).
    svc_onacc: Option<&'static str>,
    /// Path to the clamd.conf the daemon reads.
    clamd_conf: &'static str,
    /// Path to the clamd log file we tail for FOUND events.
    clamd_log: &'static str,
}

fn on_access_profile_for(family: &str) -> Option<OnAccessProfile> {
    match family {
        "debian" => Some(OnAccessProfile {
            pkg_daemon: "clamav-daemon",
            svc_daemon: "clamav-daemon.service",
            svc_onacc: Some("clamav-clamonacc.service"),
            clamd_conf: "/etc/clamav/clamd.conf",
            clamd_log:  "/var/log/clamav/clamav.log",
        }),
        "redhat" => Some(OnAccessProfile {
            pkg_daemon: "clamd",
            svc_daemon: "clamd@scan.service",
            svc_onacc: None, // RHEL/Fedora typically don't ship a clamonacc unit
            clamd_conf: "/etc/clamd.d/scan.conf",
            clamd_log:  "/var/log/clamd.scan",
        }),
        "arch" => Some(OnAccessProfile {
            pkg_daemon: "clamav",
            svc_daemon: "clamav-daemon.service",
            svc_onacc: None,
            clamd_conf: "/etc/clamav/clamd.conf",
            clamd_log:  "/var/log/clamav/clamav.log",
        }),
        "suse" => Some(OnAccessProfile {
            pkg_daemon: "clamd",
            svc_daemon: "clamd.service",
            svc_onacc: None,
            clamd_conf: "/etc/clamd.conf",
            clamd_log:  "/var/log/clamav/clamav.log",
        }),
        _ => None,
    }
}

/// Does systemd know about `unit` (installed, not necessarily running)?
/// `systemctl cat` resolves template units (e.g. `clamd@scan.service`) and
/// exits non-zero for unknown units, so it's a reliable presence check.
fn systemd_unit_exists(unit: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(["cat", unit])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Fallback profile for distros not in `on_access_profile_for`'s known-family
/// table (Gentoo, Void, Alpine, NixOS, exotic derivatives, …). ClamAV's
/// clamd/clamonacc are standard across distros — only the config/service/log
/// *paths* vary — so we detect them from the common candidates present on THIS
/// host rather than hard-coding a family. Returns None only when no clamd.conf
/// exists at all (clamd isn't installed), which is the genuine "can't do it"
/// case. Every candidate is a &'static str, so the profile stays borrow-free.
///
/// Package auto-install still can't run on an unknown package manager
/// (`build_install_cmd_family` returns None), so on these distros on-access
/// requires clamd+clamonacc to be installed already — but once they are, it now
/// works instead of hard-erroring.
fn detect_generic_profile() -> Option<OnAccessProfile> {
    let clamd_conf = ["/etc/clamav/clamd.conf", "/etc/clamd.d/scan.conf", "/etc/clamd.conf"]
        .into_iter()
        .find(|p| Path::new(p).exists())?;
    // Require an actual clamd service unit — a blind fallback to a guessed name
    // would fail 5s later at `systemctl restart` with a misleading "clamonacc
    // failed to stay running". If we can't identify how to start clamd, we
    // honestly can't enable on-access; None here yields a clear resolve error.
    let svc_daemon = ["clamav-daemon.service", "clamd@scan.service", "clamd.service"]
        .into_iter()
        .find(|u| systemd_unit_exists(u))?;
    let svc_onacc = ["clamav-clamonacc.service", "clamonacc.service"]
        .into_iter()
        .find(|u| systemd_unit_exists(u));
    let clamd_log = ["/var/log/clamav/clamav.log", "/var/log/clamd.scan"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .unwrap_or("/var/log/clamav/clamav.log");
    Some(OnAccessProfile { pkg_daemon: "clamav", svc_daemon, svc_onacc, clamd_conf, clamd_log })
}

/// Resolve the on-access profile for a distro family, falling back to
/// host-path detection for unknown families. Single source of truth for the
/// enable/disable, state-detect and tailer-resume paths.
fn resolve_on_access_profile(family: &str) -> Option<OnAccessProfile> {
    on_access_profile_for(family).or_else(detect_generic_profile)
}

const ON_ACCESS_BLOCK_BEGIN: &str = "# === WolfStack on-access begin (do not edit between markers) ===";
const ON_ACCESS_BLOCK_END:   &str = "# === WolfStack on-access end ===";
const ON_ACCESS_UNIT_PATH:   &str = "/etc/systemd/system/wolfstack-clamonacc.service";

pub fn detect_install_status() -> InstallStatus {
    let (distro, id_like) = parse_os_release();
    let family = distro_family_with_idlike(&distro, &id_like);
    let pm = pkg_manager_family(family);
    let on_access_state = detect_on_access_state(family);
    InstallStatus {
        clamav: detect_clamav(),
        rkhunter: detect_simple_binary("rkhunter", "--version"),
        chkrootkit: detect_chkrootkit_family(family),
        distro,
        package_manager: pm.unwrap_or_default(),
        on_access_state,
        on_access_error: None,
    }
}

/// Inspect systemd to decide whether on-access scanning is currently
/// active on this host. The result is purely advisory — apply_on_access
/// is the source of truth while a state transition is in flight.
fn detect_on_access_state(family: &str) -> String {
    let prof = match resolve_on_access_profile(family) {
        Some(p) => p, None => return "disabled".into(),
    };
    let daemon_active = systemd_is_active(prof.svc_daemon);
    let onacc_active = match prof.svc_onacc {
        Some(svc) => systemd_is_active(svc),
        // No distro-provided clamonacc unit — check the one we manage.
        None => systemd_is_active("wolfstack-clamonacc.service"),
    };
    if daemon_active && onacc_active { "enabled".into() }
    else { "disabled".into() }
}

fn detect_clamav() -> ToolStatus {
    let mut s = detect_simple_binary("clamscan", "--version");
    if !s.installed { return s; }
    // ClamAV signature freshness — read the main.cvd / daily.cvd file
    // mtimes in /var/lib/clamav. Newest mtime wins.
    let dir = Path::new("/var/lib/clamav");
    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut newest: Option<SystemTime> = None;
        for e in entries.flatten() {
            let name = e.file_name();
            let n = name.to_string_lossy();
            if !(n.ends_with(".cvd") || n.ends_with(".cld")) { continue; }
            if let Ok(m) = e.metadata()
                && let Ok(t) = m.modified() {
                    newest = Some(newest.map(|x| x.max(t)).unwrap_or(t));
                }
        }
        if let Some(t) = newest {
            s.last_db_update = Some(format_rfc3339(t));
        }
    }
    s
}

fn detect_simple_binary(bin: &str, version_arg: &str) -> ToolStatus {
    let path = which(bin);
    if path.is_none() {
        return ToolStatus { installed: false, ..Default::default() };
    }
    let version = Command::new(bin).arg(version_arg).output()
        .ok()
        .and_then(|o| if o.status.success() {
            Some(String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("").trim().to_string())
        } else { None });
    ToolStatus { installed: true, version, last_db_update: None, not_available_on_distro: false }
}

fn detect_chkrootkit_family(family: &str) -> ToolStatus {
    let mut s = detect_simple_binary("chkrootkit", "-V");
    if !s.installed && family == "arch" {
        // Arch / CachyOS / Manjaro core repos don't ship chkrootkit —
        // it's AUR-only.
        s.not_available_on_distro = true;
    }
    s
}

// ══════════════════════════════════════════════════════════
// Distro detection + package manager dispatch
// ══════════════════════════════════════════════════════════

/// `/etc/os-release` ID, lowercased. Kept public so other modules can
/// branch on the raw distro name without re-parsing os-release.
#[allow(dead_code)]
pub fn detect_distro_id() -> String {
    parse_os_release().0
}

/// Parse `/etc/os-release` and return (ID, ID_LIKE) — both lowercased.
/// ID_LIKE is space-separated in the file; we keep it as a single string
/// so callers can split it themselves.
fn parse_os_release() -> (String, String) {
    let text = match std::fs::read_to_string("/etc/os-release") {
        Ok(t) => t, Err(_) => return ("unknown".into(), String::new()),
    };
    let mut id = String::from("unknown");
    let mut id_like = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("ID=") {
            id = rest.trim().trim_matches('"').to_ascii_lowercase();
        } else if let Some(rest) = line.strip_prefix("ID_LIKE=") {
            id_like = rest.trim().trim_matches('"').to_ascii_lowercase();
        }
    }
    (id, id_like)
}

#[cfg(test)]
fn distro_family(distro: &str) -> &'static str {
    distro_family_with_idlike(distro, "")
}

/// Resolve a distro family, falling back to ID_LIKE for derivatives
/// the explicit table doesn't know (CachyOS, EndeavourOS variants,
/// downstream RHEL rebuilds, etc.). Match the FIRST entry in ID_LIKE
/// — os-release lists them most-specific-first.
fn distro_family_with_idlike(distro: &str, id_like: &str) -> &'static str {
    let direct = match distro {
        "debian" | "ubuntu" | "proxmox" | "raspbian" | "linuxmint" | "pop" | "kali" => "debian",
        "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "ol" | "amzn" => "redhat",
        "arch" | "archlinux" | "manjaro" | "endeavouros" | "garuda" | "cachyos" => "arch",
        "opensuse-leap" | "opensuse-tumbleweed" | "opensuse" | "sles" | "sled" => "suse",
        _ => "unknown",
    };
    if direct != "unknown" { return direct; }
    // Fallback: scan ID_LIKE tokens. Recurse with the first token as a
    // "distro" to reuse the table — never recurses more than once
    // because direct lookups can't return "unknown" inside this path.
    for tok in id_like.split_whitespace() {
        let fam = match tok {
            "debian" | "ubuntu" => "debian",
            "fedora" | "rhel" | "centos" => "redhat",
            "arch" => "arch",
            "opensuse" | "suse" | "sles" => "suse",
            _ => continue,
        };
        return fam;
    }
    "unknown"
}

/// The package manager binary appropriate for the host distro family.
fn pkg_manager_family(family: &str) -> Option<String> {
    match family {
        "debian"  => Some("apt-get".into()),
        "redhat"  => Some("dnf".into()),
        "arch"    => Some("pacman".into()),
        "suse"    => Some("zypper".into()),
        _ => None,
    }
}

/// Build the install command argv for a list of packages on the
/// given distro family. Returns None for unsupported families.
fn build_install_cmd_family(family: &str, packages: &[&str]) -> Option<Vec<String>> {
    match family {
        "debian" => {
            // DEBIAN_FRONTEND=noninteractive is set by the caller via env.
            // -q                          : quieter output (still useful, less noise)
            // -y                          : assume yes
            // --no-install-recommends     : keep the install minimal
            // Dpkg::Options force-conf*   : never prompt about modified
            //                               config files; keep the
            //                               currently-installed version
            //                               on conflict (safe default).
            // DPkg::Lock::Timeout=600     : wait up to 10 min for the apt /
            //                               dpkg lock. WITHOUT THIS Ubuntu
            //                               installs race-fail against
            //                               unattended-upgrades / apt-daily
            //                               with "Could not get lock
            //                               /var/lib/dpkg/lock-frontend".
            //                               Proxmox doesn't ship those
            //                               timers so the same code worked
            //                               there but blew up on Ubuntu.
            //                               10 min covers most realistic
            //                               unattended-upgrades sessions
            //                               (including kernel + initramfs
            //                               rebuilds). Available in apt
            //                               1.9+ (Ubuntu 20.04 / Debian 11
            //                               and newer; ignored as an
            //                               unknown option on older apt
            //                               rather than failing — apt
            //                               silently drops unknown -o keys).
            let mut v = vec![
                "apt-get".into(), "install".into(),
                "-q".into(), "-y".into(),
                "--no-install-recommends".into(),
                "-o".into(), "Dpkg::Options::=--force-confdef".into(),
                "-o".into(), "Dpkg::Options::=--force-confold".into(),
                "-o".into(), "DPkg::Lock::Timeout=600".into(),
            ];
            v.extend(packages.iter().map(|s| s.to_string()));
            Some(v)
        }
        "redhat" => {
            // -y                              : assume yes (incl. GPG key import in modern dnf)
            // --setopt=install_weak_deps=False: equivalent of apt's --no-install-recommends
            // -q                              : less noise; full progress still visible in our log
            let mut v = vec![
                "dnf".into(), "install".into(),
                "-y".into(), "-q".into(),
                "--setopt=install_weak_deps=False".into(),
            ];
            v.extend(packages.iter().map(|s| s.to_string()));
            Some(v)
        }
        "arch" => {
            // --noconfirm   : answer yes to every prompt (incl. "remove conflict?")
            // --needed      : skip already-installed packages (idempotent)
            // --noprogressbar: pacman's progress bar uses carriage returns
            //                 that produce binary-looking output in our
            //                 line-streamed log. Disabling it keeps lines
            //                 clean. Final pkg-by-pkg progress still
            //                 visible.
            let mut v = vec![
                "pacman".into(), "-S".into(),
                "--noconfirm".into(), "--needed".into(),
                "--noprogressbar".into(),
            ];
            v.extend(packages.iter().map(|s| s.to_string()));
            Some(v)
        }
        "suse" => {
            // --non-interactive : assume default answer to every prompt
            // --quiet           : less noise (errors still surfaced)
            // --no-recommends   : equivalent of --no-install-recommends
            let mut v = vec![
                "zypper".into(),
                "--non-interactive".into(),
                "--quiet".into(),
                "install".into(),
                "--no-recommends".into(),
            ];
            v.extend(packages.iter().map(|s| s.to_string()));
            Some(v)
        }
        _ => None,
    }
}

/// Package names per distro family. Debian and SUSE name ClamAV
/// `clamav` + a separate `clamav-freshclam`; Fedora ships freshclam
/// in `clamav-update`. rkhunter and chkrootkit are consistent across
/// supported distros except chkrootkit on Arch (AUR, skipped).
fn packages_for_family(family: &str) -> Vec<&'static str> {
    match family {
        "debian" => vec!["clamav", "clamav-freshclam", "rkhunter", "chkrootkit"],
        "redhat" => vec!["clamav", "clamav-update", "rkhunter", "chkrootkit"],
        "arch"   => vec!["clamav", "rkhunter"], // chkrootkit AUR-only — skipped
        "suse"   => vec!["clamav", "rkhunter", "chkrootkit"],
        _        => vec![],
    }
}

// ══════════════════════════════════════════════════════════
// Install action
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct InstallResult {
    pub ok: bool,
    pub distro: String,
    pub command: String,
    pub stdout: String,
    pub stderr: String,
    pub status: InstallStatus,
}

/// Install ClamAV + rkhunter + chkrootkit on this host using the
/// distro's native package manager. Idempotent — pre-installed
/// packages are skipped by the package manager itself. After install,
/// kicks off `freshclam` once to seed signature DB (best-effort,
/// failures are surfaced but don't fail the install).
/// Run a command with stdout+stderr streamed line-by-line into the
/// install_progress ring buffer. Returns true if the command exited 0.
/// Lines are pushed as they arrive (interactive feel for the UI) and
/// every line is prefixed with the command's short label so the operator
/// can tell apart `apt-get update` output from `freshclam` output in
/// the combined log.
fn run_streaming(
    state: &AntivirusState,
    label: &str,
    argv: &[&str],
    env: &[(&str, &str)],
) -> bool {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    if argv.is_empty() {
        state.push_install_line(format!("[{}] ERROR: empty argv", label));
        return false;
    }
    state.push_install_line(format!("$ {}", argv.join(" ")));

    let mut cmd = Command::new(argv[0]);
    cmd.args(&argv[1..])
        // Redirect stdin from /dev/null so anything that tries to
        // prompt (rkhunter's press-a-key, debconf low-priority asks,
        // shell `read`) gets EOF and either skips the prompt or
        // fails fast — never blocks forever.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env { cmd.env(k, v); }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            state.push_install_line(format!("[{}] ERROR: failed to spawn: {}", label, e));
            return false;
        }
    };
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => { state.push_install_line(format!("[{}] ERROR: no stdout pipe", label)); return false; }
    };
    let stderr = match child.stderr.take() {
        Some(s) => s,
        None => { state.push_install_line(format!("[{}] ERROR: no stderr pipe", label)); return false; }
    };

    // Read stdout + stderr concurrently. Using std::thread::scope so we
    // can borrow `state` and `label` directly — no Arc cloning needed
    // because the scope joins both threads before returning.
    std::thread::scope(|s| {
        s.spawn(|| {
            for line in BufReader::new(stdout).lines().map_while(|r| r.ok()) {
                state.push_install_line(line);
            }
        });
        s.spawn(|| {
            for line in BufReader::new(stderr).lines().map_while(|r| r.ok()) {
                // Tag stderr lines so the UI can colour them differently.
                // apt + dnf emit progress on stderr; rkhunter writes
                // warnings to stderr — keeping them visible is the
                // whole point of streaming.
                state.push_install_line(format!("[stderr] {}", line));
            }
        });
    });

    match child.wait() {
        Ok(s) => s.success(),
        Err(e) => {
            state.push_install_line(format!("[{}] wait() failed: {}", label, e));
            false
        }
    }
}

pub fn install_tools(state: &AntivirusState) -> InstallResult {
    // Mark running and clear any previous log.
    {
        let mut g = state.install_progress.write().unwrap();
        *g = InstallProgress {
            running: true,
            started_at: Some(now_rfc3339()),
            finished_at: None,
            ok: None,
            error: None,
            lines: Vec::new(),
        };
    }

    let (distro, id_like) = parse_os_release();
    let family = distro_family_with_idlike(&distro, &id_like);
    state.push_install_line(format!("==> Detected distro: {} (family: {})", distro, family));

    // Open the firewall holes the install path needs (no-op if the
    // block-outbound.sh lockdown isn't active). We MUST remove these
    // again in finalize_install — caller's responsibility.
    open_install_holes(state);

    let pkgs = packages_for_family(family);
    if pkgs.is_empty() {
        let err = format!(
            "Unsupported distro '{}' (ID_LIKE='{}'). Supported: apt (Debian/Ubuntu/Proxmox), dnf (Fedora/RHEL/Rocky/Alma), pacman (Arch/CachyOS), zypper (openSUSE).",
            distro, id_like);
        state.push_install_line(format!("==> ERROR: {}", err));
        finalize_install(state, false, Some(err.clone()));
        return InstallResult {
            ok: false, distro, command: String::new(),
            stdout: String::new(), stderr: err,
            status: detect_install_status(),
        };
    }

    let argv = match build_install_cmd_family(family, &pkgs) {
        Some(v) => v,
        None => {
            let err = "no package manager command for distro family".to_string();
            state.push_install_line(format!("==> ERROR: {}", err));
            finalize_install(state, false, Some(err.clone()));
            return InstallResult {
                ok: false, distro, command: String::new(),
                stdout: String::new(), stderr: err,
                status: detect_install_status(),
            };
        }
    };
    let cmdline = argv.join(" ");

    // Environment to suppress every prompt path on apt:
    //  - DEBIAN_FRONTEND=noninteractive    — main switch
    //  - DEBCONF_NONINTERACTIVE_SEEN=true  — treat all questions as
    //                                         already-answered
    //  - APT_LISTCHANGES_FRONTEND=none     — apt-listchanges may pop
    //                                         a pager on package
    //                                         upgrade; this blocks it
    //  - NEEDRESTART_MODE=a                — needrestart on Debian 12
    //                                         prompts about service
    //                                         restarts; 'a'utomatic
    //                                         skips the question.
    let apt_env: &[(&str, &str)] = &[
        ("DEBIAN_FRONTEND", "noninteractive"),
        ("DEBCONF_NONINTERACTIVE_SEEN", "true"),
        ("APT_LISTCHANGES_FRONTEND", "none"),
        ("NEEDRESTART_MODE", "a"),
    ];

    // apt-get update first (apt only — dnf/pacman/zypper handle this
    // implicitly on install).
    if family == "debian" {
        // Show the operator what (if anything) is currently holding the
        // dpkg lock so a wait isn't a silent stare. apt itself emits
        // "Waiting for cache lock: …" every 10s on stderr; this line
        // explains WHY at the start instead of mid-stream.
        if let Some(holder) = current_dpkg_lock_holder() {
            state.push_install_line(format!(
                "==> dpkg/apt lock currently held by {} — will wait up to 10 min for it",
                holder));
        }
        state.push_install_line("==> apt-get update (waits up to 10 min for the apt/dpkg lock — Ubuntu's unattended-upgrades / apt-daily may be running)".into());
        // Same DPkg::Lock::Timeout reasoning as build_install_cmd_family —
        // apt-get update grabs the lists lock, and on Ubuntu the apt-daily
        // timer races us for it on a fresh boot.
        run_streaming(state, "apt-update",
            &["apt-get", "update", "-q", "-o", "DPkg::Lock::Timeout=600"],
            apt_env);
    }

    // Actual install.
    state.push_install_line(format!("==> Installing: {}", pkgs.join(" ")));
    let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let install_env: &[(&str, &str)] = if family == "debian" { apt_env } else { &[] };
    let ok = run_streaming(state, "install", &argv_refs, install_env);

    if !ok {
        state.push_install_line("==> Install command FAILED — see lines above for details.".into());
        finalize_install(state, false, Some("package manager exited non-zero".into()));
        return InstallResult {
            ok: false, distro, command: cmdline,
            stdout: String::new(), stderr: "package manager failed".into(),
            status: detect_install_status(),
        };
    }

    // Customer report 2026-05-25 (klasSponsor): logrotate refused to run
    // because /etc/logrotate.d/clamav-freshclam references the `clamav`
    // user via `su clamav clamav` but the user didn't exist on his box.
    // Almost certainly a partial install at some point (apt postinst
    // interrupted, dpkg --force-confold left a half state, etc.) — the
    // Debian package's postinst would have created it via adduser.
    //
    // Self-heal: ensure the clamav user+group exist after a successful
    // package install. Idempotent — `getent passwd clamav` succeeds
    // when the user already exists and we skip the create. Limited to
    // debian-family because clamav's group/user naming is consistent
    // there (Fedora/RHEL ship via clamupdate group; Arch uses clamav
    // already; suse uses vscan — none have hit this bug).
    if family == "debian" {
        ensure_clamav_user(state);
    }

    // Seed ClamAV signatures (best-effort).
    if which("freshclam").is_some() {
        state.push_install_line("==> freshclam (seeding ClamAV signatures)".into());
        // On Debian the daemon holds the DB lock — stop, run one-shot, restore.
        let svc_was_active = systemd_is_active("clamav-freshclam.service")
            || systemd_is_active("clamav-freshclam-daemon.service");
        if svc_was_active {
            run_streaming(state, "systemctl", &["systemctl", "stop", "clamav-freshclam.service"], &[]);
        }
        run_streaming(state, "freshclam", &["freshclam"], &[]);
        if svc_was_active {
            run_streaming(state, "systemctl", &["systemctl", "start", "clamav-freshclam.service"], &[]);
        } else {
            run_streaming(state, "systemctl", &["systemctl", "enable", "--now", "clamav-freshclam.service"], &[]);
        }
    }

    // rkhunter signature + property baseline (idempotent).
    // --skip-keypress: rkhunter pauses for keyboard input between
    // sections by default. Without this flag the subprocess would hang
    // forever waiting for a key press that never comes (we close stdin
    // already, but the flag makes the intent explicit and stops
    // rkhunter even emitting the prompt line).
    if which("rkhunter").is_some() {
        state.push_install_line("==> rkhunter --update".into());
        run_streaming(state, "rkhunter",
            &["rkhunter", "--update", "--nocolors", "--skip-keypress"], &[]);
        state.push_install_line("==> rkhunter --propupd".into());
        run_streaming(state, "rkhunter",
            &["rkhunter", "--propupd", "--nocolors", "--skip-keypress"], &[]);
    }

    // The package install may have created system users (clamav,
    // freshclam, etc.). Reseed the /etc/passwd baseline NOW so the
    // tamper detector doesn't restore the pre-install snapshot and
    // delete them on the next 5-minute tick (piranhaSponsor 2026-06-10).
    if std::path::Path::new("/etc/passwd").exists() {
        match crate::predictive::baselines::reseed(
            "/etc/passwd",
            "auto:antivirus-install",
            "reseeded after antivirus package install added service users",
        ) {
            Ok(_) => state.push_install_line(
                "==> Reseeded /etc/passwd baseline (new service users are now accepted)".into()),
            Err(e) => state.push_install_line(
                format!("==> WARNING: could not reseed /etc/passwd baseline: {} — \
                         the tamper detector may flag the new users", e)),
        }
    }

    state.push_install_line("==> Install complete.".into());
    finalize_install(state, true, None);

    InstallResult {
        ok: true, distro, command: cmdline,
        stdout: String::new(), stderr: String::new(),
        status: detect_install_status(),
    }
}

// ══════════════════════════════════════════════════════════
// On-access (real-time) scanning — clamonacc + clamd
// ══════════════════════════════════════════════════════════

/// Build the managed clamd.conf block. Lists every excludable path
/// we know about (static defaults + non-local mounts discovered at
/// apply time) so fanotify doesn't loop on /proc, /sys, or eat S3FS
/// shares.
fn build_on_access_clamd_block() -> String {
    let mut out = String::new();
    out.push_str(ON_ACCESS_BLOCK_BEGIN);
    out.push('\n');
    out.push_str("# Managed by WolfStack — toggled via the Security page.\n");
    out.push_str("ScanOnAccess yes\n");
    out.push_str("OnAccessMountPath /\n");
    // Default exclusions matching the scheduled-scan filter.
    let static_excludes = [
        "/proc", "/sys", "/dev", "/run",
        "/var/quarantine/wolfstack",
        "/var/lib/wolfstack",
        "/var/lib/vz/images",
        "/var/lib/libvirt/images",
        "/var/log/clamav",
    ];
    for p in &static_excludes {
        out.push_str(&format!("OnAccessExcludePath {}\n", p));
    }
    // Discovered non-local mounts (NFS, S3FS, sshfs, overlay, tmpfs, etc.).
    for mp in discover_skippable_mountpoints() {
        if mp == "/" { continue; }
        out.push_str(&format!("OnAccessExcludePath {}\n", mp));
    }
    // Don't trigger on our own scanner reading files (prevents the
    // file-A-was-just-scanned-which-reads-file-B feedback loop).
    out.push_str("OnAccessExcludeUname clamav\n");
    // Conservative: alert + (clamonacc --move) quarantine, no read-block.
    out.push_str("OnAccessPrevention no\n");
    out.push_str("OnAccessDisableDDD no\n");
    // Scan directory metadata changes too — catches malware moving
    // files into a watched dir.
    out.push_str("OnAccessExtraScanning yes\n");
    out.push_str(ON_ACCESS_BLOCK_END);
    out.push('\n');
    out
}

/// Inject or update the managed block in clamd.conf. Idempotent — if
/// the markers are already present, the block between them is
/// replaced. Existing settings outside the markers are untouched.
fn install_clamd_conf_block(conf_path: &str) -> std::io::Result<()> {
    let existing = std::fs::read_to_string(conf_path).unwrap_or_default();
    let block = build_on_access_clamd_block();
    let updated = if existing.contains(ON_ACCESS_BLOCK_BEGIN)
        && existing.contains(ON_ACCESS_BLOCK_END)
    {
        // Replace existing block.
        let begin = existing.find(ON_ACCESS_BLOCK_BEGIN).unwrap();
        let end = existing.find(ON_ACCESS_BLOCK_END).unwrap()
            + ON_ACCESS_BLOCK_END.len();
        // Consume up to and including the newline after END.
        let after_end = existing[end..].find('\n').map(|n| end + n + 1).unwrap_or(end);
        format!("{}{}{}", &existing[..begin], block, &existing[after_end..])
    } else {
        // Append (with a separator newline if needed).
        let mut s = existing;
        if !s.ends_with('\n') { s.push('\n'); }
        s.push('\n');
        s.push_str(&block);
        s
    };
    if let Some(parent) = Path::new(conf_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(conf_path, updated)
}

/// Remove the managed block but leave any other lines alone.
fn remove_clamd_conf_block(conf_path: &str) -> std::io::Result<()> {
    let existing = match std::fs::read_to_string(conf_path) {
        Ok(s) => s, Err(_) => return Ok(()),  // file gone, nothing to do
    };
    if !existing.contains(ON_ACCESS_BLOCK_BEGIN) {
        return Ok(());
    }
    let begin = existing.find(ON_ACCESS_BLOCK_BEGIN).unwrap();
    let end = existing.find(ON_ACCESS_BLOCK_END)
        .map(|i| i + ON_ACCESS_BLOCK_END.len())
        .unwrap_or(begin);
    let after_end = existing[end..].find('\n').map(|n| end + n + 1).unwrap_or(end);
    // Trim a single leading blank line if we created one on insertion.
    let mut leading = begin;
    if leading > 0 && existing.as_bytes().get(leading - 1) == Some(&b'\n')
        && existing.as_bytes().get(leading.saturating_sub(2)) == Some(&b'\n')
    {
        leading -= 1;
    }
    let updated = format!("{}{}", &existing[..leading], &existing[after_end..]);
    std::fs::write(conf_path, updated)
}

/// systemd unit we drop in when the distro doesn't ship a clamonacc
/// service. Runs clamonacc in the foreground with --move to our
/// quarantine dir so detections auto-quarantine the same way clamscan
/// does.
const WOLFSTACK_CLAMONACC_UNIT: &str = "\
[Unit]
Description=WolfStack-managed clamonacc on-access scanner
After=clamav-daemon.service clamd.service clamd@scan.service
Wants=clamav-daemon.service

[Service]
Type=simple
ExecStartPre=/bin/mkdir -p /var/quarantine/wolfstack
ExecStart=/usr/bin/clamonacc --foreground --move=/var/quarantine/wolfstack
Restart=on-failure
RestartSec=10
# CAP_SYS_ADMIN required for fanotify with FAN_CLASS_CONTENT/PRE_CONTENT
AmbientCapabilities=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
";

fn write_managed_onacc_unit(state: &AntivirusState) -> bool {
    state.push_install_line(format!("==> Writing systemd unit at {}", ON_ACCESS_UNIT_PATH));
    if let Err(e) = std::fs::write(ON_ACCESS_UNIT_PATH, WOLFSTACK_CLAMONACC_UNIT) {
        state.push_install_line(format!("[on-access] ERROR writing unit: {}", e));
        return false;
    }
    run_streaming(state, "systemctl", &["systemctl", "daemon-reload"], &[]);
    true
}

fn remove_managed_onacc_unit(state: &AntivirusState) {
    if Path::new(ON_ACCESS_UNIT_PATH).exists() {
        run_streaming(state, "systemctl", &["systemctl", "disable", "wolfstack-clamonacc.service"], &[]);
        run_streaming(state, "systemctl", &["systemctl", "stop", "wolfstack-clamonacc.service"], &[]);
        let _ = std::fs::remove_file(ON_ACCESS_UNIT_PATH);
        run_streaming(state, "systemctl", &["systemctl", "daemon-reload"], &[]);
    }
}

use std::sync::atomic::Ordering;

/// Toggle on-access scanning. Takes an `Arc<AntivirusState>` so it
/// can clone for the tailer thread that lives past this call.
/// Streams every step into the existing install_progress log so the
/// operator sees apt install / config edits / service start lines in
/// the install terminal modal.
///
/// Idempotent — calling apply_on_access(arc, true) when already
/// enabled re-runs the config injection and restarts the daemon
/// (useful after distro upgrades / signature changes).
pub fn apply_on_access(state: std::sync::Arc<AntivirusState>, target: bool) {
    // Re-use the install_progress ring buffer so the same UI terminal
    // shows what's happening.
    {
        let mut g = state.install_progress.write().unwrap();
        *g = InstallProgress {
            running: true,
            started_at: Some(now_rfc3339()),
            finished_at: None,
            ok: None,
            error: None,
            lines: Vec::new(),
        };
    }

    let (distro, id_like) = parse_os_release();
    let family = distro_family_with_idlike(&distro, &id_like);
    let prof = match resolve_on_access_profile(family) {
        Some(p) => p,
        None => {
            let err = format!(
                "on-access scanning needs ClamAV: couldn't find a clamd.conf + clamd \
                 systemd service on distro '{}'. Install clamd + clamonacc (the \
                 clamav / clamav-daemon package) and retry.",
                distro);
            state.push_install_line(format!("==> ERROR: {}", err));
            finalize_install(&state, false, Some(err));
            return;
        }
    };
    state.push_install_line(format!(
        "==> on-access scanning: target={} (distro={} family={})",
        if target { "ENABLE" } else { "disable" }, distro, family));

    if target {
        // 1. Install the daemon package if neither binary is present.
        //    The clamav-daemon package (Debian) or clamd (RHEL/SUSE)
        //    typically bundles both clamd AND clamonacc, but we check
        //    both binaries to handle the rare split.
        if which("clamd").is_none() || which("clamonacc").is_none() {
            state.push_install_line(format!("==> Installing {}", prof.pkg_daemon));
            let apt_env: &[(&str, &str)] = &[
                ("DEBIAN_FRONTEND", "noninteractive"),
                ("DEBCONF_NONINTERACTIVE_SEEN", "true"),
                ("APT_LISTCHANGES_FRONTEND", "none"),
                ("NEEDRESTART_MODE", "a"),
            ];
            let argv = match build_install_cmd_family(family, &[prof.pkg_daemon]) {
                Some(v) => v,
                None => {
                    let err = "no package manager command for distro family".to_string();
                    state.push_install_line(format!("==> ERROR: {}", err));
                    finalize_install(&state, false, Some(err));
                    return;
                }
            };
            let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
            open_install_holes(&state);
            let ok = run_streaming(
                &state, "pkg-install", &argv_refs,
                if family == "debian" { apt_env } else { &[] },
            );
            close_install_holes(&state);
            if !ok {
                let err = "package install for clamav-daemon/clamd failed".to_string();
                finalize_install(&state, false, Some(err));
                return;
            }
        } else {
            state.push_install_line("==> clamd + clamonacc already installed — skipping package install.".into());
        }

        // 1b. Pre-seed the signature DB if /var/lib/clamav is empty.
        //     piranhaSponsor 2026-05-27: enabling on-access used to
        //     fail with the vague "clamonacc failed to stay running"
        //     error because step 3 below restarts clamd, clamd
        //     refuses to start without signatures, then clamonacc
        //     dies because clamd is dead. Seed first so the daemons
        //     actually come up.
        if !clamav_signatures_present() {
            state.push_install_line(
                "==> /var/lib/clamav is empty — running ClamAV repair (freshclam) before starting clamd".into());
            let rr = repair_clamav_signatures();
            for ln in &rr.lines {
                state.push_install_line(format!("    {}", ln));
            }
            if !rr.signatures_present_after {
                let err = format!(
                    "cannot start clamd without signatures: {}",
                    rr.error.unwrap_or_else(|| "freshclam did not produce a usable DB".into()),
                );
                state.push_install_line(format!("==> ERROR: {}", err));
                finalize_install(&state, false, Some(err));
                return;
            }
        }

        // 2. Write managed clamd.conf block.
        state.push_install_line(format!("==> Injecting managed block into {}", prof.clamd_conf));
        if let Err(e) = install_clamd_conf_block(prof.clamd_conf) {
            let err = format!("write {}: {}", prof.clamd_conf, e);
            state.push_install_line(format!("==> ERROR: {}", err));
            finalize_install(&state, false, Some(err));
            return;
        }
        state.push_install_line(format!(
            "==> clamd.conf updated. Managed block lists {} non-local mount(s) to exclude.",
            discover_skippable_mountpoints().len()));

        // 3. Restart clamd to pick up the new config. enable --now is
        //    idempotent; restart is required because the unit may
        //    already be running with the old config.
        state.push_install_line(format!("==> Restarting {}", prof.svc_daemon));
        run_streaming(&state, "systemctl",
            &["systemctl", "enable", "--now", prof.svc_daemon], &[]);
        run_streaming(&state, "systemctl",
            &["systemctl", "restart", prof.svc_daemon], &[]);
        // Wait for clamd to load the signature DB. On a busy server
        // with the full freshclam set this can be 10-30 seconds.
        state.push_install_line("==> Waiting for clamd to finish loading signatures…".into());
        std::thread::sleep(std::time::Duration::from_secs(5));

        // 4. Start clamonacc — distro service or our managed unit.
        let onacc_svc: String = match prof.svc_onacc {
            Some(s) => s.to_string(),
            None => {
                if !write_managed_onacc_unit(&state) {
                    let err = "failed to write wolfstack-clamonacc.service".to_string();
                    finalize_install(&state, false, Some(err));
                    return;
                }
                "wolfstack-clamonacc.service".to_string()
            }
        };
        state.push_install_line(format!("==> Starting {}", onacc_svc));
        run_streaming(&state, "systemctl",
            &["systemctl", "enable", "--now", &onacc_svc], &[]);
        std::thread::sleep(std::time::Duration::from_secs(2));
        if !systemd_is_active(&onacc_svc) {
            let err = format!(
                "{} failed to stay running — check `journalctl -u {}` for details",
                onacc_svc, onacc_svc);
            state.push_install_line(format!("==> ERROR: {}", err));
            finalize_install(&state, false, Some(err));
            return;
        }

        // 5. Start the findings tailer.
        start_on_access_tailer(state.clone(), prof.clamd_log.to_string());

        state.push_install_line("==> On-access scanning ENABLED. New findings will appear in the Security page.".into());
        finalize_install(&state, true, None);
    } else {
        // Disable path.
        if let Some(svc) = prof.svc_onacc {
            state.push_install_line(format!("==> Stopping {}", svc));
            run_streaming(&state, "systemctl",
                &["systemctl", "disable", "--now", svc], &[]);
        } else {
            remove_managed_onacc_unit(&state);
        }
        state.push_install_line(format!("==> Removing managed block from {}", prof.clamd_conf));
        if let Err(e) = remove_clamd_conf_block(prof.clamd_conf) {
            state.push_install_line(format!(
                "[on-access] WARN: could not strip managed block: {}", e));
        }
        // Restart clamd so the on-access directives stop taking effect.
        // We leave it RUNNING because clamdscan + clamonacc-as-occasional-
        // tool are still useful. If the user wants the daemon stopped
        // they can do that separately.
        run_streaming(&state, "systemctl",
            &["systemctl", "restart", prof.svc_daemon], &[]);
        // Signal tailer thread to exit.
        state.on_access_tailer_stop.store(true, Ordering::SeqCst);
        state.push_install_line("==> On-access scanning DISABLED.".into());
        finalize_install(&state, true, None);
    }
}

// ─── Background tailer for clamd.log → findings ──────────────

/// Re-attach the log tailer at startup if on-access scanning was
/// enabled in the persisted config AND systemd shows the daemon +
/// clamonacc actually running. Without this, a wolfstack restart
/// silently stops surfacing on-access findings even though clamonacc
/// itself keeps running.
pub fn resume_on_access_tailer_if_enabled(state: std::sync::Arc<AntivirusState>) {
    let want = state.config.read().map(|g| g.enable_on_access).unwrap_or(false);
    if !want { return; }
    let (distro, id_like) = parse_os_release();
    let family = distro_family_with_idlike(&distro, &id_like);
    let prof = match resolve_on_access_profile(family) { Some(p) => p, None => return };
    // Verify systemd state matches intent — don't start a tailer if
    // clamonacc isn't actually running.
    let onacc_active = match prof.svc_onacc {
        Some(svc) => systemd_is_active(svc),
        None => systemd_is_active("wolfstack-clamonacc.service"),
    };
    if !onacc_active {
        tracing::warn!(
            "antivirus: enable_on_access=true in config but clamonacc service is not active; tailer not started"
        );
        return;
    }
    tracing::info!("antivirus: resuming on-access log tailer (log={})", prof.clamd_log);
    start_on_access_tailer(state, prof.clamd_log.to_string());
}

/// Spawn the on-access log tailer thread. Replaces any existing
/// tailer by flipping the stop flag (existing thread notices on its
/// next 2-second tick and exits) then re-arming and launching a new
/// thread.
fn start_on_access_tailer(state: std::sync::Arc<AntivirusState>, log_path: String) {
    // Stop any existing tailer first.
    state.on_access_tailer_stop.store(true, Ordering::SeqCst);
    // Give the old tailer a tick to notice. 500ms > our 200ms poll
    // resolution so the previous instance is guaranteed to see the
    // flag before we re-arm it.
    std::thread::sleep(std::time::Duration::from_millis(500));
    state.on_access_tailer_stop.store(false, Ordering::SeqCst);

    state.push_install_line(format!("==> Tailing {} for FOUND events (background)", log_path));
    let stop = state.on_access_tailer_stop.clone();
    let state_for_thread = state.clone();
    std::thread::spawn(move || {
        on_access_tailer_loop(state_for_thread, log_path, stop);
    });
}

/// Tailer body — polls the clamd log file every 2s, reads any new
/// content from the last offset, parses FOUND lines, and pushes them
/// into the findings list as `scanner="clamonacc"` entries.
///
/// Behaviour notes:
/// - Starts at EOF on first poll so we don't replay historical FOUNDs
///   from prior sessions (those are already recorded).
/// - Detects log rotation by checking if file size shrank since last
///   poll; resets offset to 0.
/// - The file at `path` is the one quarantined by clamonacc's --move
///   to `/var/quarantine/wolfstack/`. We don't (yet) reconcile that
///   into our quarantine index — the file IS quarantined on disk but
///   won't appear in the per-node Quarantine table. That's a
///   documented v1 limitation.
fn on_access_tailer_loop(
    state: std::sync::Arc<AntivirusState>,
    log_path: String,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::io::{Read, Seek, SeekFrom};
    let mut offset: u64 = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
    let mut buf = String::new();
    while !stop.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let mut f = match std::fs::File::open(&log_path) { Ok(f) => f, Err(_) => continue };
        let meta = match f.metadata() { Ok(m) => m, Err(_) => continue };
        let len = meta.len();
        if len < offset { offset = 0; }   // log rotated
        if len == offset { continue; }
        if f.seek(SeekFrom::Start(offset)).is_err() { continue; }
        buf.clear();
        if f.read_to_string(&mut buf).is_err() { continue; }
        offset = len;
        for line in buf.lines() {
            let trimmed = line.trim();
            if !trimmed.ends_with("FOUND") { continue; }
            // clamd log line format:
            //   "Mon Jan  1 12:34:56 2024 -> /path: ThreatName FOUND"
            let payload = match trimmed.find(" -> ") {
                Some(idx) => &trimmed[idx + 4..],
                None => trimmed,
            };
            if let Some(hit) = parse_one_clamav_hit(payload) {
                let finding = Finding {
                    id: new_id(),
                    scanner: "clamonacc".into(),
                    severity: "critical".into(),
                    title: format!("clamonacc: {}", hit.threat),
                    detail: format!(
                        "On-access detection: '{}' in {}. File auto-moved to /var/quarantine/wolfstack/ by clamonacc.",
                        hit.threat, hit.path),
                    path: Some(hit.path.clone()),
                    threat_name: Some(hit.threat.clone()),
                    detected_at: now_rfc3339(),
                    // clamonacc with --move handles the quarantine itself —
                    // no process kill (different from clamscan flow).
                    action_taken: "quarantined_by_clamonacc".into(),
                    quarantine_id: None,
                    killed_pids: Vec::new(),
                };
                append_findings(&state, vec![finding]);
            }
        }
    }
}

fn finalize_install(state: &AntivirusState, ok: bool, error: Option<String>) {
    // Always close the firewall holes — even on failure paths. The
    // close is idempotent so calling it when no holes were opened
    // is a cheap no-op.
    close_install_holes(state);
    if let Ok(mut g) = state.install_progress.write() {
        g.running = false;
        g.finished_at = Some(now_rfc3339());
        g.ok = Some(ok);
        g.error = error;
    }
}

fn systemd_is_active(unit: &str) -> bool {
    Command::new("systemctl").args(["is-active", "--quiet", unit])
        .status().map(|s| s.success()).unwrap_or(false)
}

/// Make sure the `clamav` system user + group exist on Debian/Ubuntu
/// after the package install. Normally the .deb's postinst handles this,
/// but a partial install (interrupted apt, dpkg --force flags, manual
/// user cleanup) can leave the user missing while the logrotate config
/// in /etc/logrotate.d/clamav-freshclam still references it — logrotate
/// then refuses to rotate freshclam.log and ALL logrotate runs fail.
///
/// Idempotent: `getent passwd clamav` returns 0 when the user exists,
/// in which case we don't touch anything. `adduser --system --group`
/// (Debian's wrapper) is the canonical create form and is also a
/// no-op if the user already exists. Logs each step so the operator
/// sees what we did.
fn ensure_clamav_user(state: &AntivirusState) {
    if clamav_user_present() {
        return; // healthy — nothing to do
    }
    state.push_install_line(
        "==> 'clamav' user/group missing — creating (logrotate's clamav-freshclam.conf needs it)".into());
    // adduser --system --quiet --group is Debian's wrapper for creating
    // a system user with a matching primary group. The home directory
    // defaults to /var/lib/clamav (set in adduser.conf via DSHELL_VAR
    // on Debian); --no-create-home prevents adduser from clobbering
    // an existing directory if the package created /var/lib/clamav
    // already.
    let ok = run_streaming(state, "adduser",
        &["adduser", "--system", "--quiet", "--group",
          "--no-create-home", "--home", "/var/lib/clamav",
          "clamav"],
        &[]);
    if !ok {
        // useradd is the lower-level fallback if adduser isn't installed
        // (rare — Debian/Ubuntu base have adduser by default).
        let _ = run_streaming(state, "useradd",
            &["useradd", "--system",
              "--home-dir", "/var/lib/clamav",
              "--no-create-home",
              "--user-group",
              "--shell", "/usr/sbin/nologin",
              "clamav"],
            &[]);
    }
    chown_clamav_dirs();
    // Verify — if both adduser AND useradd failed silently (e.g. a
    // half-existing entry where the passwd row is present but the
    // matching group row isn't), freshclam will fail seconds later
    // with "Can't drop privileges". Surface it now so the operator
    // can see exactly which step needs hand-fixing.
    if !clamav_user_present() {
        state.push_install_line(
            "✗ Failed to create 'clamav' user/group — freshclam will not be able to update signatures. \
             Hand-fix with: `adduser --system --group clamav` then re-run the installer.".into());
    }
}

/// Return true if both the `clamav` user and `clamav` group exist.
fn clamav_user_present() -> bool {
    let user_exists = Command::new("getent").args(["passwd", "clamav"])
        .status().map(|s| s.success()).unwrap_or(false);
    let group_exists = Command::new("getent").args(["group", "clamav"])
        .status().map(|s| s.success()).unwrap_or(false);
    user_exists && group_exists
}

/// Self-heal for the clamav-user → logrotate failure mode (runs at startup
/// AND on a periodic timer — see the caller in main.rs).
///
/// piranhaSponsor reported (2026-05-27) that v24.7.4's fix didn't take
/// on his cluster: his nodes already had clamav installed in the
/// partial-install state BEFORE upgrading WolfStack, so neither
/// `do_install_packages` (no apt install happens — already installed)
/// nor `scheduled_scan_recover` (his DB is fine, scans don't fail)
/// ever exercises the heal. logrotate keeps failing daily on its own
/// systemd timer, fully outside WolfStack's view.
///
/// Match every other WolfStack startup hook (LXC bridges, WolfNet
/// routes, WolfRouter config): re-assert the desired state on every
/// boot. Narrow scope — only act when the clamav-freshclam logrotate
/// config is actually present, so we don't create the user on hosts
/// that don't have ClamAV at all. Debian-family only because that's
/// where the user-naming convention matches (Fedora/RHEL use clamupdate,
/// SUSE uses vscan).
///
/// Idempotent and silent — WolfStack runs it at startup AND on a periodic
/// timer (a daily logrotate run that fails *after* boot would otherwise sit
/// stale-red until the next reboot, re-surfacing in the predictive inbox);
/// healthy hosts no-op in microseconds.
///
/// Two-step as of 2026-05-30 (Gary/KO4BSR): step 1 heals the cause
/// (missing user), step 2 converges the *symptom* — a `logrotate.service`
/// left in systemd's `failed` state, which the prior gens fixed the cause
/// for but never cleared, so the dashboard stayed red for up to a day.
/// See [`converge_stale_logrotate_failure`].
pub fn self_heal_clamav_logrotate() {
    if !std::path::Path::new("/etc/logrotate.d/clamav-freshclam").exists() {
        return;
    }
    let (distro, id_like) = parse_os_release();
    if distro_family_with_idlike(&distro, &id_like) != "debian" {
        return;
    }

    // Step 1 — heal the cause. The clamav-freshclam logrotate snippet
    // rotates as the clamav user (`su clamav clamav`), so a missing user
    // fails that rotation and, because logrotate aborts the run on the
    // first erroring config, takes the WHOLE logrotate.service down with
    // it. Create the user if it's absent.
    if !clamav_user_present() {
        tracing::warn!(
            "ClamAV 'clamav' user missing despite /etc/logrotate.d/clamav-freshclam being installed; \
             creating user to stop logrotate failures (piranhaSponsor 2026-05-27)"
        );
        if !ensure_clamav_user_silent() {
            tracing::error!(
                "Failed to auto-create the 'clamav' user; logrotate's clamav-freshclam config will keep failing. \
                 Hand-fix with: `adduser --system --group clamav`"
            );
            return; // cause not fixed — nothing to converge yet
        }
    }

    // Step 2 — converge the unit. Healing the cause does NOT un-fail a
    // systemd oneshot: logrotate.service stays `failed` until its next
    // successful run, which the daily timer may not deliver for ~24h —
    // so the health monitor and dashboard keep showing red long after the
    // problem is gone (Gary/KO4BSR, 2026-05-30). Re-run logrotate the way
    // the timer would and clear the stale failure only if it genuinely
    // succeeds; if it still fails, surface logrotate's own words so the
    // journal carries a definitive cause (e.g. the modern "insecure
    // permissions" check on an unrelated logdir, which user-creation can
    // never fix) instead of a silent red unit.
    converge_stale_logrotate_failure();
}

/// Clear a stale `logrotate.service` failure once its cause is healed,
/// but only on real evidence — never by blindly masking the unit.
///
/// systemd keeps a failed oneshot red until its next *successful* run, so
/// fixing the underlying config doesn't reset the state on its own. We
/// re-run `logrotate /etc/logrotate.conf` exactly as the daily timer does
/// — NO `--force`, so only due logs rotate and the exit code mirrors what
/// the timer's next tick would produce. On exit 0 we `reset-failed` so the
/// monitor reflects reality immediately. On any non-zero exit we log
/// logrotate's stderr at error level (it names the true culprit) and leave
/// the unit failed — an honest red beats a hidden one, and the line we
/// emit becomes the diagnostic artifact for the next fix.
///
/// Gated on the unit actually being failed, so healthy hosts never run
/// logrotate off-schedule. Errors invoking systemctl/logrotate are
/// tolerated — worst case the unit simply stays red until the timer ticks.
fn converge_stale_logrotate_failure() {
    let is_failed = Command::new("systemctl")
        .args(["is-failed", "logrotate.service"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "failed")
        .unwrap_or(false);
    if !is_failed {
        return; // nothing stale to clear
    }

    // /etc/logrotate.conf is the canonical entrypoint and pulls in every
    // /etc/logrotate.d/* snippet, so this exercises the same set the timer
    // does. No --force: we want the timer's true success/fail semantics,
    // not a forced rotation with side effects on logs that aren't due.
    let run = Command::new("logrotate")
        .arg("/etc/logrotate.conf")
        .output();
    match run {
        Ok(o) if o.status.success() => {
            let _ = Command::new("systemctl")
                .args(["reset-failed", "logrotate.service"])
                .status();
            tracing::info!(
                "logrotate ran cleanly after clamav self-heal; cleared stale logrotate.service failed state"
            );
        }
        Ok(o) => {
            // Still broken — keep the red and hand the operator the reason.
            let stderr = String::from_utf8_lossy(&o.stderr);
            let tail = stderr
                .lines()
                .filter(|l| !l.trim().is_empty())
                .rev()
                .take(5)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join(" | ");
            tracing::error!(
                "logrotate still fails after clamav self-heal (exit {:?}); leaving logrotate.service failed. \
                 logrotate said: {}",
                o.status.code(),
                if tail.is_empty() { "(no stderr captured)".to_string() } else { tail },
            );
        }
        Err(e) => {
            tracing::error!("could not run logrotate to verify clamav self-heal: {}", e);
        }
    }
}

/// Silent counterpart to `ensure_clamav_user` for use outside the
/// install path (e.g. the scan-time auto-recovery). Same idempotent
/// logic, but without the install-log side effects. Returns whether
/// the user is present after the call.
fn ensure_clamav_user_silent() -> bool {
    if clamav_user_present() { return true; }
    // adduser (Debian wrapper) first, then useradd as a fallback.
    let ok = Command::new("adduser")
        .args(["--system", "--quiet", "--group",
               "--no-create-home", "--home", "/var/lib/clamav",
               "clamav"])
        .status().map(|s| s.success()).unwrap_or(false);
    if !ok {
        let _ = Command::new("useradd")
            .args(["--system",
                   "--home-dir", "/var/lib/clamav",
                   "--no-create-home",
                   "--user-group",
                   "--shell", "/usr/sbin/nologin",
                   "clamav"])
            .status();
    }
    chown_clamav_dirs();
    clamav_user_present()
}

/// Re-chown the directories the clamav package would have owned. Used
/// after creating the missing user — freshclam needs to write into
/// /var/lib/clamav as the clamav user, so the directory must be owned
/// by it. Errors are tolerated: missing directories will be created
/// by the package postinst (or by freshclam itself) on a later run.
fn chown_clamav_dirs() {
    for path in &["/var/log/clamav", "/var/lib/clamav", "/var/run/clamav"] {
        if std::path::Path::new(path).exists() {
            let _ = Command::new("chown").args(["-R", "clamav:clamav", path]).status();
        }
    }
}

/// Best-effort: who currently holds the dpkg lock? Returns a short
/// description like "PID 1234 (unattended-upgr)" or None when free /
/// not detectable. Used to make the install log informative when
/// DPkg::Lock::Timeout kicks in so the operator sees WHY we're waiting.
/// fuser is preferred (definitive, single-line) with a fallback to lsof.
/// Both are usually installed on Ubuntu/Debian; if neither is present
/// we just return None and the operator sees apt's own progress lines.
fn current_dpkg_lock_holder() -> Option<String> {
    const LOCK: &str = "/var/lib/dpkg/lock-frontend";
    if !std::path::Path::new(LOCK).exists() { return None; }
    // fuser prints just "PID" on the lock file when held. -v adds
    // a header to stderr we can ignore; we read stdout for the PID.
    if let Ok(out) = Command::new("fuser").arg(LOCK).output() {
        let pid_text = String::from_utf8_lossy(&out.stdout);
        let pid = pid_text.split_whitespace().next().unwrap_or("").trim();
        if !pid.is_empty() {
            // Resolve PID → comm via /proc/<pid>/comm for a friendly name.
            let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            return Some(match comm {
                Some(c) => format!("PID {} ({})", pid, c),
                None => format!("PID {}", pid),
            });
        }
    }
    None
}

// ══════════════════════════════════════════════════════════
// Firewall hole coordination for the block-outbound lockdown
// ══════════════════════════════════════════════════════════
//
// Operators run block-outbound.sh on their Proxmox hosts to default-deny
// outbound. That lockdown breaks apt-get install and freshclam unless
// we open the right holes. We coordinate this here so the operator
// doesn't have to manually run allow-updates.sh + an as-yet-unwritten
// allow-clamav.sh before clicking Install.
//
// Rules we add are tagged `IR-allow-av-install` so they're cleanly
// removable even if WolfStack crashes mid-install (operator can grep
// the tag and delete by hand).

const FIREWALL_TAG: &str = "IR-allow-av-install";

/// Hostnames the antivirus install path reaches beyond apt mirrors —
/// these are NOT in /etc/apt/sources.list and need explicit allowance.
const AV_EXTRA_HOSTS: &[&str] = &[
    // ClamAV signature CDN (freshclam fetches from these).
    "database.clamav.net",
    "db.local.clamav.net",
    "current.cvd.clamav.net",
    // rkhunter signature checks (SourceForge-hosted, redirects across
    // a CDN; the canonical host is enough for the initial connect, and
    // the redirect destinations come back via DNS so they're resolved
    // through our DNS allow rule).
    "rkhunter.sourceforge.net",
    "sourceforge.net",
];

/// True when the block-outbound.sh "default deny" rule is present.
fn lockdown_active() -> bool {
    let out = match Command::new("iptables-save").output() {
        Ok(o) => o, Err(_) => return false,
    };
    String::from_utf8_lossy(&out.stdout).contains("IR-block: default deny")
}

/// Hostnames discovered from /etc/apt/sources.list and sources.list.d.
/// Same parsing logic as allow-updates.sh so we cover ceph.list,
/// docker.list, kcare.list, pve-enterprise.list, etc., without
/// hard-coding.
fn apt_mirror_hosts() -> Vec<String> {
    let mut hosts: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Main sources.list
    if let Ok(s) = std::fs::read_to_string("/etc/apt/sources.list") {
        for url in extract_urls_from(&s) { hosts.insert(url); }
    }
    // .list and .sources under sources.list.d/
    if let Ok(entries) = std::fs::read_dir("/etc/apt/sources.list.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "list" && ext != "sources" { continue; }
            if let Ok(s) = std::fs::read_to_string(&path) {
                for url in extract_urls_from(&s) { hosts.insert(url); }
            }
        }
    }
    // Proxmox-specific extras even if not currently in sources (some
    // helpers fetch from these directly).
    hosts.insert("download.proxmox.com".into());
    hosts.insert("enterprise.proxmox.com".into());
    hosts.into_iter().collect()
}

fn extract_urls_from(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
        // Find http:// or https:// and extract the host portion (up to / or whitespace).
        for proto in ["http://", "https://"] {
            let mut start = 0;
            while let Some(idx) = trimmed[start..].find(proto) {
                let abs = start + idx + proto.len();
                let rest = &trimmed[abs..];
                let end = rest.find(|c: char| c == '/' || c.is_whitespace()).unwrap_or(rest.len());
                let host = &rest[..end];
                if !host.is_empty() {
                    // Strip :port if present.
                    let host = host.split(':').next().unwrap_or(host);
                    out.push(host.to_string());
                }
                start = abs + end;
            }
        }
    }
    out
}

fn dns_resolvers() -> Vec<String> {
    let text = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(t) => t, Err(_) => return Vec::new(),
    };
    text.lines()
        .filter_map(|l| l.strip_prefix("nameserver"))
        .map(|r| r.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn resolve_host_ips(host: &str) -> Vec<String> {
    let out = match Command::new("getent").args(["ahosts", host]).output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let mut ips = std::collections::HashSet::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(ip) = line.split_whitespace().next() {
            ips.insert(ip.to_string());
        }
    }
    ips.into_iter().collect()
}

/// Insert a single ACCEPT rule with the IR-allow-av-install tag.
/// `family` is "v4" or "v6"; the right binary is selected accordingly.
fn add_accept_rule(family: &str, dest: &str, proto: &str, dport: u16, label: &str) -> bool {
    let bin = if family == "v6" { "ip6tables" } else { "iptables" };
    let comment = format!("{}: {}", FIREWALL_TAG, label);
    let status = Command::new(bin)
        .args(["-I", "OUTPUT", "1", "-d", dest, "-p", proto, "--dport", &dport.to_string(),
               "-j", "ACCEPT", "-m", "comment", "--comment", &comment])
        .status();
    status.map(|s| s.success()).unwrap_or(false)
}

/// Open every outbound hole the install path needs. No-op if the
/// IR-block lockdown isn't active.
pub fn open_install_holes(state: &AntivirusState) {
    if !lockdown_active() {
        state.push_install_line("==> No block-outbound lockdown detected — skipping firewall hole coordination.".into());
        return;
    }
    state.push_install_line(format!("==> block-outbound lockdown detected — opening temporary holes (tag '{}')", FIREWALL_TAG));

    // 1. DNS to configured resolvers — needed to resolve everything else.
    let resolvers = dns_resolvers();
    if resolvers.is_empty() {
        state.push_install_line("[firewall] WARNING: no nameservers in /etc/resolv.conf — install will fail to resolve mirrors.".into());
    }
    for ns in &resolvers {
        let family = if ns.contains(':') { "v6" } else { "v4" };
        add_accept_rule(family, ns, "udp", 53, "DNS");
        add_accept_rule(family, ns, "tcp", 53, "DNS");
        state.push_install_line(format!("[firewall] +DNS to {}", ns));
    }

    // 2. apt mirror hosts.
    let mirrors = apt_mirror_hosts();
    state.push_install_line(format!("[firewall] Found {} apt mirror hostname(s) to whitelist", mirrors.len()));
    for host in &mirrors {
        let ips = resolve_host_ips(host);
        if ips.is_empty() {
            state.push_install_line(format!("[firewall] WARN could not resolve {} — skipping", host));
            continue;
        }
        for ip in &ips {
            let family = if ip.contains(':') { "v6" } else { "v4" };
            add_accept_rule(family, ip, "tcp", 443, &format!("{}:443", host));
            add_accept_rule(family, ip, "tcp", 80,  &format!("{}:80",  host));
        }
        state.push_install_line(format!("[firewall] +{} -> {} IP(s)", host, ips.len()));
    }

    // 3. AV-specific hostnames (ClamAV CDN, rkhunter mirrors).
    for host in AV_EXTRA_HOSTS {
        let ips = resolve_host_ips(host);
        if ips.is_empty() {
            state.push_install_line(format!("[firewall] WARN could not resolve {} — skipping", host));
            continue;
        }
        for ip in &ips {
            let family = if ip.contains(':') { "v6" } else { "v4" };
            add_accept_rule(family, ip, "tcp", 443, &format!("{}:443", host));
            add_accept_rule(family, ip, "tcp", 80,  &format!("{}:80",  host));
        }
        state.push_install_line(format!("[firewall] +{} -> {} IP(s)", host, ips.len()));
    }
}

/// Remove every rule tagged IR-allow-av-install. Safe to call even if
/// `open_install_holes` was never invoked (or already closed) — both
/// iptables-save and the per-rule delete are idempotent here.
pub fn close_install_holes(state: &AntivirusState) {
    let match_str = format!("--comment \"{}", FIREWALL_TAG);
    let mut removed = 0usize;
    for bin in ["iptables", "ip6tables"] {
        let save_bin = format!("{}-save", bin);
        loop {
            let saved = match Command::new(&save_bin).output() {
                Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
                _ => break,
            };
            let line = match saved.lines().find(|l| l.contains(&match_str)) {
                Some(l) => l.to_string(), None => break,
            };
            // Convert "-A OUTPUT ..." to "-D OUTPUT ..." and pass each
            // token as a separate arg (iptables doesn't accept a single
            // pre-quoted string).
            let delete_line = line.replacen("-A ", "-D ", 1);
            let argv = match shell_split(&delete_line) {
                Some(v) => v, None => break,
            };
            let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
            let status = Command::new(bin).args(&argv_refs).status();
            if status.map(|s| s.success()).unwrap_or(false) {
                removed += 1;
            } else {
                // If iptables refuses to delete a rule we just located,
                // bail to avoid an infinite loop.
                break;
            }
        }
    }
    if removed > 0 {
        state.push_install_line(format!("==> Removed {} firewall hole(s) tagged '{}'", removed, FIREWALL_TAG));
    }
}

/// Tiny shell-style splitter for iptables-save rule lines. They use
/// regular space-separated tokens with `--comment "quoted text"` as the
/// only quoting case. Returns None if quoting is malformed.
fn shell_split(s: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for ch in s.chars() {
        match ch {
            '"' => in_quote = !in_quote,
            ' ' if !in_quote => {
                if !cur.is_empty() { out.push(std::mem::take(&mut cur)); }
            }
            _ => cur.push(ch),
        }
    }
    if in_quote { return None; }
    if !cur.is_empty() { out.push(cur); }
    Some(out)
}

// ══════════════════════════════════════════════════════════
// Findings + persistence
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    /// "clamav" | "rkhunter" | "chkrootkit"
    pub scanner: String,
    /// "critical" | "warning" | "info"
    pub severity: String,
    pub title: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_name: Option<String>,
    pub detected_at: String,
    /// "quarantined" | "killed_processes" | "alert_only"
    pub action_taken: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_id: Option<String>,
    #[serde(default)]
    pub killed_pids: Vec<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub quarantined_path: String,
    pub original_mode: u32,
    pub original_uid: u32,
    pub original_gid: u32,
    pub size_bytes: u64,
    pub threat_name: String,
    pub scanner: String,
    pub quarantined_at: String,
}

fn load_findings() -> Vec<Finding> {
    std::fs::read_to_string(FINDINGS_PATH).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_findings(v: &[Finding]) -> std::io::Result<()> {
    if let Some(parent) = Path::new(FINDINGS_PATH).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(v).unwrap_or_else(|_| "[]".into());
    std::fs::write(FINDINGS_PATH, body)?;
    let _ = chmod_600(FINDINGS_PATH);
    Ok(())
}

fn load_quarantine_index() -> Vec<QuarantineEntry> {
    std::fs::read_to_string(QUARANTINE_INDEX_PATH).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_quarantine_index(v: &[QuarantineEntry]) -> std::io::Result<()> {
    if let Some(parent) = Path::new(QUARANTINE_INDEX_PATH).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(v).unwrap_or_else(|_| "[]".into());
    std::fs::write(QUARANTINE_INDEX_PATH, body)?;
    let _ = chmod_600(QUARANTINE_INDEX_PATH);
    Ok(())
}

// ══════════════════════════════════════════════════════════
// In-memory state — referenced from AppState
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
#[derive(Default)]
pub struct ScanState {
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_scanner: Option<String>,
    pub progress_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_clamav_run: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_rkhunter_run: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_chkrootkit_run: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}


/// Live install-run state. The endpoint `GET /api/antivirus/install-log`
/// returns this; the UI polls it to render a terminal-style log box.
#[derive(Debug, Clone, Serialize, Default)]
pub struct InstallProgress {
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    /// `None` while running, then `Some(true|false)` after exit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Ring-buffered log lines (oldest first). Capped at MAX_INSTALL_LINES.
    pub lines: Vec<String>,
}

pub struct AntivirusState {
    pub config: RwLock<AntivirusConfig>,
    pub scan_state: RwLock<ScanState>,
    pub findings: RwLock<Vec<Finding>>,
    pub quarantine: RwLock<Vec<QuarantineEntry>>,
    pub install_status: RwLock<InstallStatus>,
    pub install_progress: RwLock<InstallProgress>,
    /// Signal for the on-access log tailer thread to stop. Flipped to
    /// true on disable; the tailer checks it every 2s and exits.
    pub on_access_tailer_stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl AntivirusState {
    pub fn load() -> Self {
        let config = AntivirusConfig::load();
        let findings = load_findings();
        let quarantine = load_quarantine_index();
        // Reconstruct ScanState's "last X run" markers from findings so
        // the UI shows continuity across restarts.
        let mut scan_state = ScanState::default();
        for f in &findings {
            match f.scanner.as_str() {
                "clamav"     => scan_state.last_clamav_run     = Some(f.detected_at.clone()),
                "rkhunter"   => scan_state.last_rkhunter_run   = Some(f.detected_at.clone()),
                "chkrootkit" => scan_state.last_chkrootkit_run = Some(f.detected_at.clone()),
                _ => {}
            }
        }
        let install_status = detect_install_status();
        Self {
            config: RwLock::new(config),
            scan_state: RwLock::new(scan_state),
            findings: RwLock::new(findings),
            quarantine: RwLock::new(quarantine),
            install_status: RwLock::new(install_status),
            install_progress: RwLock::new(InstallProgress::default()),
            on_access_tailer_stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn refresh_install_status(&self) {
        let s = detect_install_status();
        if let Ok(mut g) = self.install_status.write() { *g = s; }
    }

    /// Append a line to the rolling install log. Caller is responsible
    /// for not flooding (we trim to MAX_INSTALL_LINES from the front to
    /// keep memory bounded even on a misbehaving subprocess).
    pub fn push_install_line(&self, line: String) {
        if let Ok(mut g) = self.install_progress.write() {
            g.lines.push(line);
            if g.lines.len() > MAX_INSTALL_LINES {
                let drop = g.lines.len() - MAX_INSTALL_LINES;
                g.lines.drain(..drop);
            }
        }
    }
}

// ══════════════════════════════════════════════════════════
// ClamAV scan
// ══════════════════════════════════════════════════════════

/// One ClamAV hit as parsed from `clamscan --infected` output.
#[derive(Debug, Clone)]
struct ClamHit {
    path: String,
    threat: String,
}

/// Run clamscan over the configured scan roots. Returns the list of
/// hits. Streams stdout line-by-line so we can:
///
/// 1. Update `scan_state.progress_message` every N files with the
///    current file path — gives the UI a live signal that work is
///    happening and lets the operator confirm clamscan isn't stuck
///    on a hung mount.
/// 2. Capture the FOUND lines for the findings list.
///
/// We auto-derive a list of mountpoints to exclude from `/proc/mounts`
/// (anything network / FUSE / overlay / virtual). That keeps clamscan
/// out of S3FS/NFS/sshfs mounts wherever they're attached — not just
/// the conventional /mnt and /media paths.
fn run_clamav_scan(
    state: &AntivirusState,
    cfg: &AntivirusConfig,
) -> Result<Vec<ClamHit>, String> {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    if which("clamscan").is_none() {
        return Err("clamscan binary not found — install ClamAV first".into());
    }

    let mut args: Vec<String> = vec![
        "-r".into(),         // recursive
        "--no-summary".into(),
        "--max-filesize=200M".into(),
        "--max-scansize=2000M".into(),
        "--cross-fs=yes".into(),
        // Notably NO --infected here: we want every "path: OK" line so
        // the progress sampler can see what file clamscan is currently
        // working on. We filter for FOUND in the line loop below.
    ];
    for ex in cfg.effective_excludes() {
        args.push(format!("--exclude-dir={}", ex));
    }
    // Dynamic mount-based excludes. Discovered every scan so a freshly-
    // attached NFS share is honoured without restarting WolfStack.
    let skip_mounts = discover_skippable_mountpoints();
    if !skip_mounts.is_empty()
        && let Ok(mut s) = state.scan_state.write() {
            s.progress_message = format!(
                "Excluding {} non-local mount(s) (NFS / CIFS / FUSE / S3FS / overlay / tmpfs / etc.)",
                skip_mounts.len());
        }
    for mp in &skip_mounts {
        // ClamAV --exclude-dir is a POSIX regex tested against directory
        // pathnames. `^<escaped>(/|$)` excludes the mountpoint itself
        // AND anything beneath it.
        args.push(format!("--exclude-dir=^{}(/|$)", regex_escape(mp)));
    }
    for root in &cfg.scan_roots { args.push(root.clone()); }

    let mut child = Command::new("clamscan")
        .args(&args)
        // No stdin — clamscan never prompts but belt-and-braces in
        // case some future flag does.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to exec clamscan: {}", e))?;
    let stdout = child.stdout.take()
        .ok_or_else(|| "clamscan: no stdout pipe".to_string())?;
    let stderr = child.stderr.take()
        .ok_or_else(|| "clamscan: no stderr pipe".to_string())?;

    // Sample-rate for progress updates: every N file lines, refresh
    // scan_state.progress_message with the current path + total count.
    // Picking 100 keeps the lock acquisition cost negligible while
    // still updating the UI roughly every second on a typical scan
    // throughput (a few hundred files/sec).
    const PROGRESS_SAMPLE_EVERY: u64 = 100;

    let hits: std::sync::Mutex<Vec<ClamHit>> = std::sync::Mutex::new(Vec::new());
    let stderr_tail: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

    std::thread::scope(|s| {
        // Parse the live stream from stdout.
        s.spawn(|| {
            let mut files_seen: u64 = 0;
            for line in BufReader::new(stdout).lines().map_while(|r| r.ok()) {
                let trimmed = line.trim();
                if trimmed.is_empty() { continue; }
                // Classify the line.
                if trimmed.ends_with(" FOUND") {
                    // Real hit. Parse it and stash for the caller.
                    if let Some(h) = parse_one_clamav_hit(trimmed)
                        && let Ok(mut g) = hits.lock() { g.push(h); }
                    files_seen += 1;
                    if let Ok(mut ss) = state.scan_state.write() {
                        ss.progress_message = format!(
                            "ClamAV scanned {} files · last finding: {}",
                            files_seen, trimmed);
                    }
                } else if trimmed.ends_with(": OK") {
                    files_seen += 1;
                    if files_seen.is_multiple_of(PROGRESS_SAMPLE_EVERY) {
                        // Trim the path-only part for display; clamscan
                        // emits "/path/to/file: OK" so strip the suffix.
                        let path = trimmed.rsplit_once(": OK").map(|(p, _)| p).unwrap_or(trimmed);
                        if let Ok(mut ss) = state.scan_state.write() {
                            ss.progress_message = format!(
                                "ClamAV scanned {} files · currently: {}",
                                files_seen, path);
                        }
                    }
                }
                // Other line shapes (engine startup, library load,
                // summary lines we get with --no-summary off, etc.)
                // — ignored on purpose.
            }
            // Final progress update so the UI shows the total even
            // for very fast scans that didn't hit the sample rate.
            if let Ok(mut ss) = state.scan_state.write() {
                ss.progress_message = format!("ClamAV scanned {} files", files_seen);
            }
        });
        // Collect stderr in case clamscan exits non-zero with an error.
        // Bounded — 4KB tail is enough to surface "DB load failed" etc.
        s.spawn(|| {
            const STDERR_TAIL_CAP: usize = 4096;
            for line in BufReader::new(stderr).lines().map_while(|r| r.ok()) {
                if let Ok(mut g) = stderr_tail.lock() {
                    g.push_str(&line);
                    g.push('\n');
                    if g.len() > STDERR_TAIL_CAP {
                        let drop = g.len() - STDERR_TAIL_CAP;
                        g.drain(..drop);
                    }
                }
            }
        });
    });

    let status = child.wait()
        .map_err(|e| format!("clamscan wait failed: {}", e))?;
    let code = status.code().unwrap_or(-1);
    // clamscan exit codes:
    //   0 = clean, 1 = hits found, 2 = error
    if code == 2 {
        let tail = stderr_tail.lock().map(|g| g.clone()).unwrap_or_default();
        return Err(format!("clamscan exited with errors (code 2). stderr={}",
            tail.chars().take(400).collect::<String>()));
    }

    Ok(hits.into_inner().unwrap_or_default())
}

/// Parse a single `path: ThreatName.Variant FOUND` line into a ClamHit.
/// Shared by `run_clamav_scan` (live streaming) and
/// `parse_clamav_output` (bulk parsing of a captured buffer).
fn parse_one_clamav_hit(line: &str) -> Option<ClamHit> {
    let line = line.trim();
    if !line.ends_with(" FOUND") { return None; }
    let body = &line[..line.len() - " FOUND".len()];
    let idx = body.rfind(": ")?;
    let path = body[..idx].trim().to_string();
    let threat = body[idx + 2..].trim().to_string();
    if path.is_empty() || threat.is_empty() { return None; }
    Some(ClamHit { path, threat })
}

/// Parse a full clamscan output buffer into hits. Used by the unit
/// test for the parsing logic; the live scanner now uses
/// `parse_one_clamav_hit` directly on each streamed line.
#[cfg(test)]
fn parse_clamav_output(s: &str) -> Vec<ClamHit> {
    s.lines().filter_map(parse_one_clamav_hit).collect()
}

// ══════════════════════════════════════════════════════════
// rkhunter scan
// ══════════════════════════════════════════════════════════

fn run_rkhunter_scan() -> Result<Vec<Finding>, String> {
    if which("rkhunter").is_none() {
        return Err("rkhunter binary not found".into());
    }
    let output = Command::new("rkhunter")
        .args(["--check", "--skip-keypress", "--report-warnings-only",
               "--nocolors", "--no-mail-on-warning"])
        .output()
        .map_err(|e| format!("failed to exec rkhunter: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    // rkhunter exit codes:
    //   0 = no warnings
    //   1 = warnings (still a successful run)
    //   2 = warnings + errors
    //   non-zero with empty output = real failure
    let code = output.status.code().unwrap_or(-1);
    if code > 2 && stdout.trim().is_empty() {
        return Err(format!("rkhunter exited {} with no output. stderr={}",
            code, stderr.chars().take(400).collect::<String>()));
    }
    Ok(parse_rkhunter_output(&stdout))
}

/// Substring patterns that mark a rkhunter "Warning:" line as a
/// known false positive across mainstream distros. Matched
/// case-insensitively against the warning's detail text. Operators
/// can layer additional patterns via the `extra_excludes` config
/// (which is regex for clamscan but works as substring for rkhunter
/// — kept deliberately simple).
///
/// Sources for each pattern:
/// - Debian/Proxmox: official rkhunter false-positive issue tracker
/// - RHEL/Fedora: the systemd / prelink / Java false positives all
///   distros inherit
/// - Arch: pacman-created files in /etc that rkhunter flags
const RKHUNTER_FALSE_POSITIVE_PATTERNS: &[&str] = &[
    // Debian / Proxmox / Ubuntu — scripts shipped as commands in
    // packages rkhunter expects to be ELF binaries.
    "/usr/bin/lwp-request",
    "/usr/share/ifupdown2/__main__.py",
    "/usr/bin/egrep",        // grep shipped as a wrapper script on some Debian versions
    "/usr/bin/fgrep",
    // Hidden files created by stock packages on every modern Debian.
    "Hidden file found: /etc/.updated",
    "Hidden file found: /etc/.pwd.lock",
    "Hidden file found: /etc/.java",
    "Hidden directory found: /etc/.java",
    "Hidden file found: /usr/share/man/man5/.k5identity.5.gz",
    "Hidden file found: /usr/share/man/man5/.k5login.5.gz",
    "Hidden file found: /usr/share/man/man1/..1.gz",
    "Hidden file found: /usr/bin/.fipscheck.hmac",
    "Hidden directory found: /etc/.git",  // installer scripts on some images
    // Systemd creates these on every modern Linux box.
    "Suspicious file types found in /dev",
    // Informational comparisons, not security warnings.
    "The SSH and rkhunter configuration options should be the same",
    "The SSH configuration option 'AllowRootLogin'",  // older rkhunter checks a deprecated option name
    // Prelink false positives on RHEL/Fedora — prelink rewrites ELF
    // entry addresses so rkhunter's hash check disagrees with its
    // earlier baseline. Benign on any host where prelink ran.
    "differs from the prelink dependency",
    "is not on the prelink path",
    // SSH protocol 1 check — modern sshd defaults to v2-only so the
    // "v1 not disabled" warning is informational on every recent box.
    "Checking if SSH protocol v1 is allowed",
    // Properties-changed warnings from package upgrades — rkhunter
    // doesn't auto-refresh its property database, so legitimate apt
    // upgrades trigger these. We can't tell apart "package upgraded"
    // from "binary swapped by attacker" without --propupd having run
    // recently, so this is a documented limitation; advise via the
    // hint instead of spamming the operator.
    "File properties have changed:",
];

/// Parse rkhunter `--report-warnings-only` stdout into findings,
/// dropping lines that match RKHUNTER_FALSE_POSITIVE_PATTERNS so the
/// operator's findings list isn't drowned in distro-shipped quirks.
/// Lines look like:
///   `Warning: <text>` or `[13:42:01] Warning: <text>`
fn parse_rkhunter_output(s: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let now = now_rfc3339();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        // Strip leading "[HH:MM:SS] " timestamp if rkhunter emitted it.
        let stripped = if line.starts_with('[') {
            line.find("] ").map(|i| line[i+2..].trim()).unwrap_or(line)
        } else { line };
        let Some(rest) = stripped.strip_prefix("Warning:")
            .or_else(|| stripped.strip_prefix("WARNING:")) else { continue; };
        let detail = rest.trim();
        if detail.is_empty() { continue; }
        // Drop the known false positives.
        if is_rkhunter_false_positive(detail) { continue; }
        out.push(Finding {
            id: new_id(),
            scanner: "rkhunter".into(),
            severity: "warning".into(),
            title: detail.chars().take(120).collect(),
            detail: detail.into(),
            path: None, threat_name: None,
            detected_at: now.clone(),
            action_taken: "alert_only".into(),
            quarantine_id: None,
            killed_pids: Vec::new(),
        });
    }
    out
}

fn is_rkhunter_false_positive(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    RKHUNTER_FALSE_POSITIVE_PATTERNS.iter()
        .any(|pat| lower.contains(&pat.to_ascii_lowercase()))
}

// ══════════════════════════════════════════════════════════
// chkrootkit scan
// ══════════════════════════════════════════════════════════

fn run_chkrootkit_scan() -> Result<Vec<Finding>, String> {
    if which("chkrootkit").is_none() {
        return Err("chkrootkit binary not found".into());
    }
    let output = Command::new("chkrootkit").output()
        .map_err(|e| format!("failed to exec chkrootkit: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(parse_chkrootkit_output(&stdout))
}

/// Parse chkrootkit output. ONLY emit findings for lines containing
/// literal uppercase `INFECTED` — that's chkrootkit's documented hit
/// marker. The old "everything not in CLEAN_TOKENS is a finding"
/// heuristic was generating dozens of false-positive entries from
/// progress markers like:
///   - `Checking 'aliens'... started`
///   - `Checking 'aliens'... finished`
///   - `Searching for X... not tested`
///     chkrootkit emits these between every real check; they're status,
///     not results. Real hits look like:
///   - `Checking 'bindshell'... INFECTED (PORTS: 31337)`
///   - `eth0: PACKET SNIFFER(/path/to/proc)` (no '...' separator but contains INFECTED later)
fn parse_chkrootkit_output(s: &str) -> Vec<Finding> {
    let now = now_rfc3339();
    let mut out = Vec::new();
    for line in s.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        // chkrootkit's hit token is always uppercase INFECTED; we match
        // case-sensitively to avoid catching the word "infected" in
        // descriptive prose (e.g. "checking for non-infected files").
        if !trimmed.contains("INFECTED") { continue; }
        out.push(Finding {
            id: new_id(),
            scanner: "chkrootkit".into(),
            severity: "critical".into(),
            title: trimmed.chars().take(120).collect(),
            detail: trimmed.into(),
            path: None, threat_name: None,
            detected_at: now.clone(),
            action_taken: "alert_only".into(),
            quarantine_id: None,
            killed_pids: Vec::new(),
        });
    }
    out
}

// ══════════════════════════════════════════════════════════
// Quarantine + process kill
// ══════════════════════════════════════════════════════════

/// Move `path` into the quarantine root, preserving original
/// permissions / owner in the index entry so restore is exact.
/// Returns the new QuarantineEntry.
pub fn quarantine_file(
    path: &str, threat_name: &str, scanner: &str,
) -> Result<QuarantineEntry, String> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::MetadataExt;

    let p = Path::new(path);
    let meta = std::fs::metadata(p)
        .map_err(|e| format!("stat {}: {}", path, e))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path));
    }
    let id = new_id();
    let dest_dir = PathBuf::from(QUARANTINE_ROOT).join(&id);
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("create {}: {}", dest_dir.display(), e))?;
    let _ = chmod_path(&dest_dir, 0o700);

    let basename = p.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file")
        .to_string();
    let dest = dest_dir.join(&basename);

    // chmod 000 BEFORE moving so any concurrent reader gets EACCES the
    // moment we begin.
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o000));
    // Try rename first (cheap, atomic, same-filesystem). If that fails
    // because the source crosses a filesystem boundary, fall back to
    // copy + remove.
    if std::fs::rename(p, &dest).is_err() {
        std::fs::copy(p, &dest)
            .map_err(|e| format!("copy {} -> {}: {}", path, dest.display(), e))?;
        std::fs::remove_file(p)
            .map_err(|e| format!("remove {} after copy: {}", path, e))?;
    }
    let _ = chmod_path(&dest, 0o000);

    let entry = QuarantineEntry {
        id,
        original_path: path.to_string(),
        quarantined_path: dest.display().to_string(),
        original_mode: meta.permissions().mode() & 0o7777,
        original_uid: meta.uid(),
        original_gid: meta.gid(),
        size_bytes: meta.size(),
        threat_name: threat_name.into(),
        scanner: scanner.into(),
        quarantined_at: now_rfc3339(),
    };
    Ok(entry)
}

/// Move a quarantined file back to its original path with original
/// mode / owner. Updates the on-disk index to remove the entry.
pub fn restore_quarantined(state: &AntivirusState, id: &str) -> Result<(), String> {
    use std::os::unix::fs::chown;
    use std::os::unix::fs::PermissionsExt;
    let (entry, removed_idx) = {
        let g = state.quarantine.read().map_err(|_| "lock poisoned".to_string())?;
        let idx = g.iter().position(|e| e.id == id)
            .ok_or_else(|| format!("quarantine entry {} not found", id))?;
        (g[idx].clone(), idx)
    };
    let dest = Path::new(&entry.original_path);
    if let Some(parent) = dest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if dest.exists() {
        return Err(format!(
            "refusing to restore: {} already exists. Move it aside first.",
            entry.original_path));
    }
    std::fs::rename(&entry.quarantined_path, dest)
        .or_else(|_| std::fs::copy(&entry.quarantined_path, dest).map(|_| ()))
        .map_err(|e| format!("restore move failed: {}", e))?;
    // Set permissions + ownership before announcing success.
    let _ = std::fs::set_permissions(dest,
        std::fs::Permissions::from_mode(entry.original_mode));
    let _ = chown(dest, Some(entry.original_uid), Some(entry.original_gid));
    // Clean up the now-empty quarantine subdir.
    if let Some(parent) = Path::new(&entry.quarantined_path).parent() {
        let _ = std::fs::remove_dir_all(parent);
    }
    // Persist index — drop the entry.
    {
        let mut g = state.quarantine.write().map_err(|_| "lock poisoned".to_string())?;
        g.remove(removed_idx);
        save_quarantine_index(&g).map_err(|e| format!("save index: {}", e))?;
    }
    Ok(())
}

/// Permanently delete a quarantined entry. The on-disk payload is
/// shredded if `shred` is available, otherwise normal unlink.
pub fn delete_quarantined(state: &AntivirusState, id: &str) -> Result<(), String> {
    let (entry, removed_idx) = {
        let g = state.quarantine.read().map_err(|_| "lock poisoned".to_string())?;
        let idx = g.iter().position(|e| e.id == id)
            .ok_or_else(|| format!("quarantine entry {} not found", id))?;
        (g[idx].clone(), idx)
    };
    let payload = Path::new(&entry.quarantined_path);
    if payload.exists() {
        if which("shred").is_some() {
            let _ = Command::new("shred").args(["-u", "-z", "-n", "1"])
                .arg(payload).output();
        }
        // shred -u removes; if shred missing or failed, fall back to unlink.
        if payload.exists() {
            let _ = std::fs::remove_file(payload);
        }
    }
    // Clean up containing dir.
    if let Some(parent) = payload.parent() {
        let _ = std::fs::remove_dir_all(parent);
    }
    {
        let mut g = state.quarantine.write().map_err(|_| "lock poisoned".to_string())?;
        g.remove(removed_idx);
        save_quarantine_index(&g).map_err(|e| format!("save index: {}", e))?;
    }
    Ok(())
}

/// Best-effort enumeration of PIDs currently using `path`. Tries
/// `fuser` first (most accurate), then walks /proc/*/exe + /proc/*/maps
/// as a fallback so we still get something on hosts without fuser.
pub fn pids_using(path: &str) -> Vec<i32> {
    let mut pids: HashSet<i32> = HashSet::new();
    if which("fuser").is_some()
        && let Ok(out) = Command::new("fuser").arg(path).output() {
            // fuser writes PIDs to stderr (yes, really) prefixed with the path.
            let s = String::from_utf8_lossy(&out.stderr);
            for tok in s.split_whitespace() {
                if let Ok(p) = tok.trim_end_matches(|c: char| !c.is_ascii_digit()).parse::<i32>()
                    && p > 0 { pids.insert(p); }
            }
            let s2 = String::from_utf8_lossy(&out.stdout);
            for tok in s2.split_whitespace() {
                if let Ok(p) = tok.parse::<i32>()
                    && p > 0 { pids.insert(p); }
            }
        }
    // /proc walk fallback / supplement — catches the case where the
    // binary has been deleted (shows up as "/path (deleted)") and fuser
    // can't find it any more.
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let name = e.file_name();
            let n = name.to_string_lossy();
            if !n.chars().all(|c| c.is_ascii_digit()) { continue; }
            let pid: i32 = match n.parse() { Ok(p) => p, Err(_) => continue };
            // exe symlink
            if let Ok(target) = std::fs::read_link(e.path().join("exe")) {
                let t = target.to_string_lossy();
                let t_stripped = t.trim_end_matches(" (deleted)");
                if t_stripped == path { pids.insert(pid); continue; }
            }
            // maps — for libraries loaded as shared objects
            if let Ok(maps) = std::fs::read_to_string(e.path().join("maps"))
                && maps.contains(path) { pids.insert(pid); }
        }
    }
    let mut v: Vec<i32> = pids.into_iter().collect();
    v.sort();
    v
}

/// SIGKILL each PID. Returns the PIDs that were successfully signalled.
pub fn kill_pids(pids: &[i32]) -> Vec<i32> {
    let mut killed = Vec::new();
    for &pid in pids {
        if pid <= 1 { continue; }  // never touch PID 1
        // Skip kernel threads (PPID==2). Killing one would do nothing
        // useful and `kill -9` on them returns EPERM anyway.
        if is_kernel_thread(pid) { continue; }
        // SECURITY/SAFETY: never SIGKILL a cluster-critical daemon on a
        // ClamAV hit. A false-positive signature match on a pmxcfs /
        // corosync / qemu / ceph / database binary would otherwise take the
        // host (or the whole cluster) down. Reuse the scan-detector's
        // essential-safety list (it handles the 15-byte /proc/comm
        // truncation). AV scans run unattended on a schedule, so this is
        // the only thing standing between an FP and a downed node.
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if !comm.is_empty() && crate::scan_detector::is_essential_safety_comm(&comm) {
            tracing::warn!(
                "antivirus: refusing to kill PID {} ({}) — on the essential-safety list \
                 (likely a ClamAV false positive on a system/cluster binary)",
                pid, comm
            );
            continue;
        }
        let r = Command::new("kill").args(["-9", &pid.to_string()]).status();
        if r.map(|s| s.success()).unwrap_or(false) {
            killed.push(pid);
        }
    }
    killed
}

fn is_kernel_thread(pid: i32) -> bool {
    let stat = match std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
        Ok(s) => s, Err(_) => return false,
    };
    // /proc/PID/stat: pid (comm) state ppid ...
    // comm can contain spaces — find the last ')'.
    if let Some(close) = stat.rfind(')') {
        let tail = &stat[close+1..];
        let parts: Vec<&str> = tail.split_whitespace().collect();
        if parts.len() >= 2
            && let Ok(ppid) = parts[1].parse::<i32>() {
                return ppid == 2 || ppid == 0;
            }
    }
    false
}

// ══════════════════════════════════════════════════════════
// Top-level scan orchestration
// ══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct ScanRunSummary {
    pub started_at: String,
    pub completed_at: String,
    pub clamav_hits: usize,
    pub rkhunter_findings: usize,
    pub chkrootkit_findings: usize,
    pub quarantined: usize,
    pub processes_killed: usize,
    pub errors: Vec<String>,
}

/// Outcome of `repair_clamav_signatures()` — a step-by-step record of
/// what was attempted, plus the final state so the caller can decide
/// whether to retry / surface to the UI / abort.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ClamavRepairResult {
    /// True if /var/lib/clamav contains a usable signature DB after
    /// the repair (main.cvd / main.cld / equivalent).
    pub signatures_present_after: bool,
    /// True if freshclam exited 0.
    pub freshclam_ok: bool,
    /// Did we have to create the clamav user during this run?
    pub healed_user: bool,
    /// Was the clamav-freshclam.service running before we started
    /// (we stop it for the one-shot freshclam to release the DB lock).
    pub freshclam_service_was_active: bool,
    /// Per-step log lines suitable for surfacing into the UI.
    pub lines: Vec<String>,
    /// Final human-readable failure reason. `None` on success.
    pub error: Option<String>,
}

/// Heal a "missing ClamAV signature DB" on this host: ensure the
/// `clamav` user exists, run `freshclam` once to seed signatures,
/// and re-enable the freshclam daemon for future updates.
///
/// piranhaSponsor reported (2026-05-27) that this used to be invisible:
/// the old `try_recover_clamav_signatures` returned a bare `bool` and
/// swallowed every failure reason, so when freshclam exited non-zero
/// the operator saw only the original "No supported database files"
/// error from the scan retry with zero clue WHY recovery didn't fire.
///
/// This now returns a structured `ClamavRepairResult` so callers can
/// surface the actual failure (freshclam missing / network blocked /
/// /var/lib/clamav permissions wrong / clamav user creation failed)
/// into the scan error AND the Repair-button UI.
pub fn repair_clamav_signatures() -> ClamavRepairResult {
    let mut r = ClamavRepairResult::default();

    if which("freshclam").is_none() {
        r.error = Some(
            "freshclam not installed — install the `clamav-freshclam` (Debian) or \
             `clamav-update` (RHEL) package, or re-run the WolfStack ClamAV installer".into(),
        );
        r.lines.push(format!("✗ {}", r.error.as_deref().unwrap_or("")));
        return r;
    }
    r.lines.push("→ freshclam binary present".into());

    // freshclam drops privileges to the `clamav` user on Debian. If a
    // partial package install left the user missing, freshclam exits
    // before writing any signature. Heal first.
    let (distro, id_like) = parse_os_release();
    if distro_family_with_idlike(&distro, &id_like) == "debian" {
        if clamav_user_present() {
            r.lines.push("→ `clamav` user present".into());
        } else {
            r.lines.push("→ `clamav` user missing — creating…".into());
            let healed = ensure_clamav_user_silent();
            r.healed_user = healed;
            if !healed {
                r.error = Some(
                    "could not create the `clamav` system user (adduser + useradd both failed). \
                     Hand-fix with: `adduser --system --group clamav` then click Repair again".into(),
                );
                r.lines.push(format!("✗ {}", r.error.as_deref().unwrap_or("")));
                return r;
            }
            r.lines.push("→ `clamav` user/group created".into());
        }
    }

    // freshclam needs an exclusive lock on /var/lib/clamav. If the
    // freshclam daemon is currently running it holds that lock, so we
    // stop it, run the one-shot, and start it again. If it wasn't
    // running we leave it that way until we confirm freshclam works,
    // then enable it so future updates run automatically.
    r.freshclam_service_was_active = systemd_is_active("clamav-freshclam.service")
        || systemd_is_active("clamav-freshclam-daemon.service");
    if r.freshclam_service_was_active {
        r.lines.push("→ stopping clamav-freshclam.service to release DB lock".into());
        let _ = Command::new("systemctl")
            .args(["stop", "clamav-freshclam.service"]).status();
    }

    r.lines.push("→ running `freshclam`…".into());
    let fc_out = Command::new("freshclam")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();
    match fc_out {
        Ok(o) => {
            r.freshclam_ok = o.status.success();
            // Tail the combined output (cap to 800 chars) so failures
            // like network errors / mirror unreachable surface in the
            // UI without overwhelming the operator with the full log.
            let mut combined = String::new();
            combined.push_str(&String::from_utf8_lossy(&o.stdout));
            combined.push_str(&String::from_utf8_lossy(&o.stderr));
            let tail = combined.lines()
                .rev()
                .take(8)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n");
            if !tail.is_empty() {
                r.lines.push(format!("  freshclam output (last 8 lines):\n{}", tail));
            }
            if !r.freshclam_ok {
                let code = o.status.code().map(|c| c.to_string()).unwrap_or_else(|| "?".into());
                r.error = Some(format!(
                    "freshclam exited with code {} — common causes: outbound HTTP/HTTPS blocked \
                     to db.local.clamav.net / database.clamav.net (check your firewall / \
                     block-outbound rules), DNS failing, or /var/lib/clamav permissions wrong",
                    code,
                ));
            }
        }
        Err(e) => {
            r.error = Some(format!("could not exec freshclam: {}", e));
        }
    }

    // Restore service state.
    if r.freshclam_service_was_active {
        r.lines.push("→ restarting clamav-freshclam.service".into());
        let _ = Command::new("systemctl")
            .args(["start", "clamav-freshclam.service"]).status();
    } else if r.freshclam_ok {
        r.lines.push("→ enabling clamav-freshclam.service for future auto-updates".into());
        let _ = Command::new("systemctl")
            .args(["enable", "--now", "clamav-freshclam.service"]).status();
    }

    r.signatures_present_after = clamav_signatures_present();
    if r.signatures_present_after {
        r.lines.push("✓ /var/lib/clamav now contains signature files".into());
        // Success — clear any earlier error left by a non-fatal step.
        if r.freshclam_ok {
            r.error = None;
        }
    } else if r.error.is_none() {
        r.error = Some(
            "freshclam reported success but /var/lib/clamav still has no signature files — \
             check `journalctl -u clamav-freshclam` and /etc/clamav/freshclam.conf".into(),
        );
    }
    if let Some(ref e) = r.error {
        r.lines.push(format!("✗ {}", e));
    }
    r
}

/// True when /var/lib/clamav contains at least one usable signature DB
/// (main.cvd / main.cld / main.cud). ClamAV needs `main` to start at
/// all — daily / bytecode are optional updates.
fn clamav_signatures_present() -> bool {
    let dir = std::path::Path::new("/var/lib/clamav");
    let rd = match std::fs::read_dir(dir) { Ok(r) => r, Err(_) => return false };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let s = name.to_string_lossy();
        if s.starts_with("main.")
            && (s.ends_with(".cvd") || s.ends_with(".cld") || s.ends_with(".cud"))
        {
            return true;
        }
    }
    false
}

/// True when the scan error string we got from `run_clamav_scan`
/// matches the "missing signature DB" signature. Used both at scan-
/// retry time and by the Repair button to decide whether the repair
/// is the right tool for the surfaced error.
pub fn is_clamav_missing_db_error(err: &str) -> bool {
    let lower = err.to_lowercase();
    lower.contains("no supported database files")
        || lower.contains("cli_loaddbdir")
}

/// Old `try_recover_clamav_signatures` wrapper, preserved for the scan
/// retry path but now returning the structured result so callers can
/// surface the failure reason. Returns `Some(result)` if the error
/// matched the missing-DB signature and we attempted recovery;
/// `None` otherwise (caller doesn't need to retry).
fn try_recover_clamav_signatures(state: &AntivirusState, err: &str) -> Option<ClamavRepairResult> {
    if !is_clamav_missing_db_error(err) { return None; }
    {
        let mut s = state.scan_state.write().unwrap();
        s.progress_message =
            "ClamAV signature DB missing — running freshclam to recover…".into();
    }
    Some(repair_clamav_signatures())
}

/// Run every configured scanner sequentially. ClamAV first (longest
/// runner gets started while other tools could be skipped), then the
/// rootkit checks. New findings are appended to the persisted history.
///
/// Blocking — caller is expected to wrap in `tokio::task::spawn_blocking`
/// or run from a dedicated thread. Updates `state.scan_state` as it
/// progresses so the UI can show live status.
pub fn run_full_scan(state: &AntivirusState) -> ScanRunSummary {
    let started_at = now_rfc3339();
    {
        let mut s = state.scan_state.write().unwrap();
        s.running = true;
        s.started_at = Some(started_at.clone());
        s.completed_at = None;
        s.active_scanner = None;
        s.progress_message = "Starting scan…".into();
        s.last_error = None;
    }

    let cfg = state.config.read().unwrap().clone();
    let mut summary = ScanRunSummary {
        started_at: started_at.clone(),
        completed_at: String::new(),
        clamav_hits: 0,
        rkhunter_findings: 0,
        chkrootkit_findings: 0,
        quarantined: 0,
        processes_killed: 0,
        errors: Vec::new(),
    };

    // ─── ClamAV ─────────────────────────────────────────
    if cfg.run_clamav && which("clamscan").is_some() {
        {
            let mut s = state.scan_state.write().unwrap();
            s.active_scanner = Some("clamav".into());
            s.progress_message = "Running ClamAV signature scan…".into();
        }
        let mut scan_result = run_clamav_scan(state, &cfg);
        // Auto-recover from the "signature DB never seeded" failure
        // mode: freshclam has never run, /var/lib/clamav is empty, and
        // every clamscan exits 2. Run freshclam once and retry — and
        // if the recovery itself fails, surface WHY into the scan
        // error so the operator can see whether freshclam is missing,
        // network-blocked, etc. (piranhaSponsor 2026-05-27).
        let mut repair_note: Option<String> = None;
        if let Err(ref e) = scan_result
            && let Some(rr) = try_recover_clamav_signatures(state, e) {
                if rr.signatures_present_after {
                    {
                        let mut s = state.scan_state.write().unwrap();
                        s.progress_message =
                            "Retrying ClamAV scan with refreshed signatures…".into();
                    }
                    scan_result = run_clamav_scan(state, &cfg);
                } else if let Some(reason) = rr.error.clone() {
                    repair_note = Some(format!("auto-repair failed: {}", reason));
                }
            }
        match scan_result {
            Ok(hits) => {
                summary.clamav_hits = hits.len();
                handle_clamav_hits(state, &cfg, &hits, &mut summary);
                let mut s = state.scan_state.write().unwrap();
                s.last_clamav_run = Some(now_rfc3339());
            }
            Err(e) => {
                let full = match repair_note {
                    Some(note) => format!("clamav: {} | {}", e, note),
                    None => format!("clamav: {}", e),
                };
                summary.errors.push(full.clone());
                let mut s = state.scan_state.write().unwrap();
                s.last_error = Some(full);
            }
        }
    }

    // ─── rkhunter ───────────────────────────────────────
    if cfg.run_rkhunter && which("rkhunter").is_some() {
        {
            let mut s = state.scan_state.write().unwrap();
            s.active_scanner = Some("rkhunter".into());
            s.progress_message = "Running rkhunter rootkit scan…".into();
        }
        match run_rkhunter_scan() {
            Ok(findings) => {
                summary.rkhunter_findings = findings.len();
                append_findings(state, findings);
                let mut s = state.scan_state.write().unwrap();
                s.last_rkhunter_run = Some(now_rfc3339());
            }
            Err(e) => {
                summary.errors.push(format!("rkhunter: {}", e));
                let mut s = state.scan_state.write().unwrap();
                s.last_error = Some(format!("rkhunter: {}", e));
            }
        }
    }

    // ─── chkrootkit ─────────────────────────────────────
    if cfg.run_chkrootkit && which("chkrootkit").is_some() {
        {
            let mut s = state.scan_state.write().unwrap();
            s.active_scanner = Some("chkrootkit".into());
            s.progress_message = "Running chkrootkit scan…".into();
        }
        match run_chkrootkit_scan() {
            Ok(findings) => {
                summary.chkrootkit_findings = findings.len();
                append_findings(state, findings);
                let mut s = state.scan_state.write().unwrap();
                s.last_chkrootkit_run = Some(now_rfc3339());
            }
            Err(e) => {
                summary.errors.push(format!("chkrootkit: {}", e));
                let mut s = state.scan_state.write().unwrap();
                s.last_error = Some(format!("chkrootkit: {}", e));
            }
        }
    }

    let completed_at = now_rfc3339();
    summary.completed_at = completed_at.clone();
    {
        let mut s = state.scan_state.write().unwrap();
        s.running = false;
        s.completed_at = Some(completed_at);
        s.active_scanner = None;
        s.progress_message = if summary.errors.is_empty() {
            "Scan complete.".into()
        } else {
            format!("Scan completed with {} error(s).", summary.errors.len())
        };
    }
    summary
}

/// Convert ClamAV hits into Finding records, optionally
/// quarantining + killing processes per the config.
fn handle_clamav_hits(
    state: &AntivirusState,
    cfg: &AntivirusConfig,
    hits: &[ClamHit],
    summary: &mut ScanRunSummary,
) {
    let mut new_findings: Vec<Finding> = Vec::new();
    let mut new_quarantine: Vec<QuarantineEntry> = Vec::new();
    let now = now_rfc3339();

    for hit in hits {
        let mut killed_pids: Vec<i32> = Vec::new();
        let mut action = "alert_only".to_string();
        let mut quarantine_id: Option<String> = None;

        if cfg.auto_quarantine {
            // Kill processes BEFORE moving the file so they don't get
            // weird EACCES surprises mid-syscall.
            if cfg.auto_kill {
                let pids = pids_using(&hit.path);
                if !pids.is_empty() {
                    killed_pids = kill_pids(&pids);
                    if !killed_pids.is_empty() {
                        action = "killed_processes".into();
                    }
                }
            }
            match quarantine_file(&hit.path, &hit.threat, "clamav") {
                Ok(entry) => {
                    quarantine_id = Some(entry.id.clone());
                    new_quarantine.push(entry);
                    action = if killed_pids.is_empty() {
                        "quarantined".into()
                    } else {
                        "killed_processes_and_quarantined".into()
                    };
                }
                Err(e) => {
                    summary.errors.push(format!("quarantine {}: {}", hit.path, e));
                }
            }
        }

        if !killed_pids.is_empty() {
            summary.processes_killed += killed_pids.len();
        }
        if quarantine_id.is_some() {
            summary.quarantined += 1;
        }

        new_findings.push(Finding {
            id: new_id(),
            scanner: "clamav".into(),
            severity: "critical".into(),
            title: format!("ClamAV: {}", hit.threat),
            detail: format!("Detected '{}' in {}", hit.threat, hit.path),
            path: Some(hit.path.clone()),
            threat_name: Some(hit.threat.clone()),
            detected_at: now.clone(),
            action_taken: action,
            quarantine_id,
            killed_pids,
        });
    }

    if !new_quarantine.is_empty()
        && let Ok(mut g) = state.quarantine.write() {
            for e in new_quarantine { g.push(e); }
            let _ = save_quarantine_index(&g);
        }
    append_findings(state, new_findings);
}

/// Remove a finding by id from both the in-memory list and the
/// persisted JSON. Returns true if a finding was found and removed.
/// Used by the UI Dismiss button to clear alert-only findings the
/// operator has confirmed benign.
pub fn dismiss_finding(state: &AntivirusState, id: &str) -> bool {
    let mut g = match state.findings.write() { Ok(g) => g, Err(_) => return false };
    let before = g.len();
    g.retain(|f| f.id != id);
    let removed = g.len() < before;
    if removed { let _ = save_findings(&g); }
    removed
}

/// Prepend new findings to the in-memory + on-disk list, capped at
/// `MAX_FINDINGS_RETAINED`. New findings appear at the top so the
/// UI shows the latest run first.
fn append_findings(state: &AntivirusState, mut new_findings: Vec<Finding>) {
    if new_findings.is_empty() { return; }
    if let Ok(mut g) = state.findings.write() {
        new_findings.append(&mut g.clone());
        if new_findings.len() > MAX_FINDINGS_RETAINED {
            new_findings.truncate(MAX_FINDINGS_RETAINED);
        }
        *g = new_findings;
        let _ = save_findings(&g);
    }
}

// ══════════════════════════════════════════════════════════
// Scheduled scan tick (called from main.rs background loop)
// ══════════════════════════════════════════════════════════

/// If the configured schedule is due, fire a full scan in a blocking
/// thread. Returns immediately if not due or if a scan is already
/// running. Designed to be invoked from a low-cadence tokio interval
/// (e.g. every 5 minutes); the blocking work is offloaded.
pub fn maybe_run_scheduled_scan(state: std::sync::Arc<AntivirusState>) {
    let cfg = match state.config.read() { Ok(g) => g.clone(), Err(_) => return };
    if !cfg.enabled || cfg.schedule_hours == 0 { return; }
    if state.scan_state.read().map(|s| s.running).unwrap_or(false) { return; }

    // Most recent completed run across all three scanners.
    let last = {
        let s = state.scan_state.read().unwrap();
        [s.last_clamav_run.clone(), s.last_rkhunter_run.clone(),
         s.last_chkrootkit_run.clone()]
            .into_iter().flatten().max()
    };
    let due = match last {
        None => true,
        Some(ts) => {
            match chrono::DateTime::parse_from_rfc3339(&ts) {
                Ok(t) => {
                    let secs = chrono::Utc::now().signed_duration_since(t).num_seconds();
                    secs >= cfg.schedule_hours as i64 * 3600
                }
                Err(_) => true,
            }
        }
    };
    if !due { return; }

    let state_for_thread = state.clone();
    std::thread::spawn(move || {
        let _ = run_full_scan(&state_for_thread);
    });
}

// ══════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════

fn now_rfc3339() -> String { chrono::Utc::now().to_rfc3339() }

fn format_rfc3339(t: SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = t.into();
    dt.to_rfc3339()
}

fn new_id() -> String {
    // 16 hex chars from /dev/urandom — collision-resistant for our
    // workload (a few hundred quarantine entries ever).
    use std::io::Read;
    let mut buf = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn which(bin: &str) -> Option<PathBuf> {
    // Honour PATH from the environment, but always add /usr/local/sbin,
    // /usr/sbin, /sbin first because most AV/IDS binaries live there
    // and minimal shells (cron, systemd unit Environment=…) often miss
    // them.
    let mut paths: Vec<PathBuf> = vec![
        "/usr/local/sbin".into(), "/usr/sbin".into(), "/sbin".into(),
        "/usr/local/bin".into(), "/usr/bin".into(), "/bin".into(),
    ];
    if let Ok(p) = std::env::var("PATH") {
        for s in p.split(':') {
            let pb: PathBuf = s.into();
            if !paths.iter().any(|x| x == &pb) { paths.push(pb); }
        }
    }
    for p in paths {
        let candidate = p.join(bin);
        if candidate.is_file() {
            // executable check — st_mode & 0o111
            use std::os::unix::fs::PermissionsExt;
            if let Ok(m) = std::fs::metadata(&candidate)
                && m.permissions().mode() & 0o111 != 0 {
                    return Some(candidate);
                }
        }
    }
    None
}

fn chmod_600(path: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

fn chmod_path(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

// ══════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamav_output_parsing() {
        let s = "/tmp/eicar.com: Eicar-Signature FOUND\n\
                 /var/lib/lxc/web/rootfs/tmp/x: Linux.Trojan.Kinsing FOUND\n\
                 ----------- SCAN SUMMARY -----------\n";
        let hits = parse_clamav_output(s);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].path, "/tmp/eicar.com");
        assert_eq!(hits[0].threat, "Eicar-Signature");
        assert_eq!(hits[1].path, "/var/lib/lxc/web/rootfs/tmp/x");
        assert_eq!(hits[1].threat, "Linux.Trojan.Kinsing");
    }

    #[test]
    fn rkhunter_output_parsing_includes_real_warnings() {
        // Real-looking warning that ISN'T in the false-positive list.
        let s = "[13:42:00] Info: Starting test\n\
                 [13:42:01] Warning: Suspicious binary at /tmp/x.bin\n\
                 [13:42:02] Info: All clean\n";
        let f = parse_rkhunter_output(s);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, "warning");
        assert!(f[0].detail.contains("/tmp/x.bin"));
    }

    #[test]
    fn rkhunter_false_positives_filtered_across_distros() {
        // One example per OS family the operator might run, all
        // pulled from real-world reports.
        let inputs = &[
            // Debian/Proxmox
            "Warning: The command '/usr/bin/lwp-request' has been replaced by a script: /usr/bin/lwp-request: Perl script text executable",
            "Warning: The command '/usr/share/ifupdown2/__main__.py' has been replaced by a script",
            "Warning: Hidden file found: /etc/.updated: ASCII text",
            "Warning: Suspicious file types found in /dev:",
            // Universal (every modern distro)
            "Warning: Hidden file found: /etc/.pwd.lock",
            "Warning: The SSH and rkhunter configuration options should be the same:",
            // RHEL/Fedora prelink quirk
            "Warning: /usr/bin/foo differs from the prelink dependency",
            // Older sshd v1-check noise
            "Warning: Checking if SSH protocol v1 is allowed: it is",
        ];
        for line in inputs {
            let f = parse_rkhunter_output(line);
            assert!(f.is_empty(),
                "expected line to be filtered as false positive: {}\n got: {:?}",
                line, f);
        }
    }

    #[test]
    fn rkhunter_false_positive_alongside_real_warning() {
        let s = "Warning: Hidden file found: /etc/.updated: ASCII text\n\
                 Warning: Unsigned ELF in /tmp/dropper\n";
        let f = parse_rkhunter_output(s);
        // First line filtered as known FP, second line is a real warning.
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("/tmp/dropper"));
    }

    #[test]
    fn chkrootkit_only_infected_lines_become_findings() {
        // Real chkrootkit output mixes progress markers ("started" /
        // "finished" / "not tested") with the actual results. Only
        // lines containing INFECTED should surface.
        let s = "Checking `aliens'... started\n\
                 Checking `aliens'... no suspicious files\n\
                 Checking `aliens'... finished\n\
                 Checking `lkm'... started\n\
                 Searching for Adore LKM... not tested\n\
                 Checking `lkm'... finished\n\
                 Checking `asp'... not infected\n\
                 Searching for Linux BPF Door... WARNING\n\
                 Checking `bindshell'... INFECTED (PORTS:  31337)\n";
        let f = parse_chkrootkit_output(s);
        assert_eq!(f.len(), 1, "expected only 1 INFECTED finding, got {}: {:?}", f.len(), f);
        assert!(f[0].detail.contains("INFECTED"));
        assert!(f[0].detail.contains("bindshell"));
    }

    #[test]
    fn chkrootkit_infected_match_is_case_sensitive() {
        // chkrootkit uses uppercase INFECTED. The word "infected" can
        // appear in normal output ("not infected"); we don't want to
        // catch that.
        let s = "Checking `foo'... not infected\n\
                 Some background note about infected files in general\n";
        let f = parse_chkrootkit_output(s);
        assert!(f.is_empty());
    }

    #[test]
    fn distro_family_resolution() {
        assert_eq!(distro_family("debian"), "debian");
        assert_eq!(distro_family("ubuntu"), "debian");
        assert_eq!(distro_family("proxmox"), "debian");
        assert_eq!(distro_family("fedora"), "redhat");
        assert_eq!(distro_family("rocky"), "redhat");
        assert_eq!(distro_family("arch"), "arch");
        assert_eq!(distro_family("cachyos"), "arch");
        assert_eq!(distro_family("opensuse-leap"), "suse");
        assert_eq!(distro_family("plan9"), "unknown");
    }

    #[test]
    fn distro_family_falls_back_to_id_like() {
        // Unknown direct ID, but ID_LIKE points at a known family.
        assert_eq!(distro_family_with_idlike("cachyos", "arch"), "arch");
        assert_eq!(distro_family_with_idlike("garuda", "arch"), "arch");
        assert_eq!(distro_family_with_idlike("almalinux", "rhel centos fedora"), "redhat");
        assert_eq!(distro_family_with_idlike("popnewdistro", "ubuntu debian"), "debian");
        // No match anywhere → unknown.
        assert_eq!(distro_family_with_idlike("solaris", "unix"), "unknown");
    }

    #[test]
    fn install_cmd_shape_per_family() {
        let pkgs = &["clamav", "rkhunter"];
        let debian = build_install_cmd_family("debian", pkgs).unwrap();
        assert_eq!(debian[0], "apt-get");
        assert!(debian.contains(&"-y".to_string()));
        let redhat = build_install_cmd_family("redhat", pkgs).unwrap();
        assert_eq!(redhat[0], "dnf");
        let arch = build_install_cmd_family("arch", pkgs).unwrap();
        assert_eq!(arch[0], "pacman");
        assert!(arch.contains(&"--noconfirm".to_string()));
        let suse = build_install_cmd_family("suse", pkgs).unwrap();
        assert_eq!(suse[0], "zypper");
        assert!(build_install_cmd_family("plan9", pkgs).is_none());
    }

    /// Regression: customer report 2026-05-25 — clamav install on Ubuntu
    /// failed because apt-daily / unattended-upgrades held the dpkg lock.
    /// Proxmox doesn't ship those timers so the same install code worked
    /// there. Fix: pass DPkg::Lock::Timeout so apt-get *waits* for the
    /// lock instead of erroring immediately.
    #[test]
    fn debian_install_cmd_sets_dpkg_lock_timeout() {
        let argv = build_install_cmd_family("debian", &["clamav"]).unwrap();
        // The option is passed as two consecutive tokens: -o then K=V.
        let timeout_pair = argv.windows(2).find(|w|
            w[0] == "-o" && w[1].starts_with("DPkg::Lock::Timeout="));
        let pair = timeout_pair.unwrap_or_else(|| panic!(
            "debian install command must set DPkg::Lock::Timeout — without it \
             apt races unattended-upgrades on Ubuntu and fails to acquire \
             /var/lib/dpkg/lock-frontend. argv was: {:?}", argv));
        // Value must be >= 60 to be useful; <60 means we'd give up before
        // unattended-upgrades finishes one apt step.
        let val: u64 = pair[1].trim_start_matches("DPkg::Lock::Timeout=")
            .parse().expect("DPkg::Lock::Timeout value must parse as u64");
        assert!(val >= 60,
            "DPkg::Lock::Timeout={} is too short to ride out an active \
             unattended-upgrades — must be >= 60s", val);
    }

    #[test]
    fn packages_for_family_excludes_arch_chkrootkit() {
        let arch_pkgs = packages_for_family("arch");
        assert!(!arch_pkgs.contains(&"chkrootkit"));
        let debian_pkgs = packages_for_family("debian");
        assert!(debian_pkgs.contains(&"chkrootkit"));
        let redhat_pkgs = packages_for_family("redhat");
        assert!(redhat_pkgs.contains(&"chkrootkit"));
    }

    #[test]
    fn clamd_conf_block_inject_replace_remove_roundtrip() {
        // Use a temp file so we don't touch the real clamd.conf.
        let tmp = std::env::temp_dir().join(format!(
            "wolfstack-clamd-{}.conf", std::process::id()));
        let path = tmp.to_string_lossy().to_string();
        // Start with a user's existing config.
        let initial = "# User settings\nLogVerbose yes\nUser clamav\n";
        std::fs::write(&path, initial).unwrap();
        // First injection appends the block.
        install_clamd_conf_block(&path).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.starts_with("# User settings"), "user content must be preserved at the top");
        assert!(after.contains(ON_ACCESS_BLOCK_BEGIN));
        assert!(after.contains(ON_ACCESS_BLOCK_END));
        assert!(after.contains("ScanOnAccess yes"));
        assert!(after.contains("OnAccessExcludePath /proc"));
        // Re-injection must replace the block in place (no duplicate markers).
        install_clamd_conf_block(&path).unwrap();
        let after2 = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after2.matches(ON_ACCESS_BLOCK_BEGIN).count(), 1, "begin marker must appear exactly once");
        assert_eq!(after2.matches(ON_ACCESS_BLOCK_END).count(), 1, "end marker must appear exactly once");
        assert!(after2.contains("LogVerbose yes"), "user content survives re-injection");
        // Removal strips the block + leaves user content intact.
        remove_clamd_conf_block(&path).unwrap();
        let after3 = std::fs::read_to_string(&path).unwrap();
        assert!(!after3.contains(ON_ACCESS_BLOCK_BEGIN));
        assert!(!after3.contains(ON_ACCESS_BLOCK_END));
        assert!(after3.contains("LogVerbose yes"));
        assert!(after3.contains("User clamav"));
        // Idempotent: removing again is a no-op.
        remove_clamd_conf_block(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), after3);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn unescape_mount_path_decodes_octal_escapes() {
        // /proc/mounts encodes space as \040, tab as \011, newline as \012.
        assert_eq!(unescape_mount_path("/mnt/space\\040here"), "/mnt/space here");
        assert_eq!(unescape_mount_path("/no/escapes"), "/no/escapes");
        // Non-octal digit (8 or 9) should NOT be treated as an escape.
        assert_eq!(unescape_mount_path("/path\\189/end"), "/path\\189/end");
    }

    #[test]
    fn skippable_fstypes_cover_network_fuse_and_virtual() {
        // Network
        assert!(is_skippable_fstype("nfs"));
        assert!(is_skippable_fstype("nfs4"));
        assert!(is_skippable_fstype("cifs"));
        assert!(is_skippable_fstype("ceph"));
        // FUSE family — wildcard via starts_with("fuse")
        assert!(is_skippable_fstype("fuse"));
        assert!(is_skippable_fstype("fuse.s3fs"));
        assert!(is_skippable_fstype("fuse.sshfs"));
        assert!(is_skippable_fstype("fuseblk"));
        // Virtual
        assert!(is_skippable_fstype("tmpfs"));
        assert!(is_skippable_fstype("proc"));
        assert!(is_skippable_fstype("cgroup2"));
        // Overlay / image
        assert!(is_skippable_fstype("overlay"));
        assert!(is_skippable_fstype("squashfs"));
        // Local block fs — must NOT be skipped, those are what we
        // actually want scanned.
        assert!(!is_skippable_fstype("ext4"));
        assert!(!is_skippable_fstype("xfs"));
        assert!(!is_skippable_fstype("zfs"));
        assert!(!is_skippable_fstype("btrfs"));
        assert!(!is_skippable_fstype("vfat"));
        assert!(!is_skippable_fstype("ntfs"));
    }

    #[test]
    fn regex_escape_escapes_metacharacters() {
        assert_eq!(regex_escape("/mnt/foo"), "/mnt/foo");
        assert_eq!(regex_escape("/mnt/with (parens)"), "/mnt/with \\(parens\\)");
        assert_eq!(regex_escape("/a.b+c"), "/a\\.b\\+c");
    }

    #[test]
    fn shell_split_handles_quoted_comments() {
        // Real iptables-save line for one of our rules.
        let line = "-A OUTPUT -d 1.2.3.4/32 -p tcp -m tcp --dport 443 -j ACCEPT -m comment --comment \"IR-allow-av-install: deb.debian.org:443\"";
        let parts = shell_split(line).unwrap();
        // The quoted comment must be a single token.
        let comment_idx = parts.iter().position(|p| p.starts_with("IR-allow-av-install:")).unwrap();
        assert!(parts[comment_idx].contains("deb.debian.org:443"));
        // No empty tokens.
        for p in &parts { assert!(!p.is_empty()); }
    }

    #[test]
    fn shell_split_rejects_unterminated_quote() {
        assert!(shell_split("-A OUTPUT -m comment --comment \"unterminated").is_none());
    }

    #[test]
    fn extract_urls_finds_https_and_http_and_strips_port() {
        let s = "
            # comment
            deb https://download.docker.com/linux/debian bookworm stable
            deb http://archive.ubuntu.com/ubuntu jammy main
            deb https://repo.tuxcare.com/kernelcare/ubuntu jammy main
            deb https://mirror.example.com:8443/path foo bar
        ";
        let hosts = extract_urls_from(s);
        assert!(hosts.contains(&"download.docker.com".to_string()));
        assert!(hosts.contains(&"archive.ubuntu.com".to_string()));
        assert!(hosts.contains(&"repo.tuxcare.com".to_string()));
        assert!(hosts.contains(&"mirror.example.com".to_string()));
        // Comment line ignored.
        assert!(!hosts.iter().any(|h| h.starts_with("comment")));
    }

    #[test]
    fn effective_excludes_combines_defaults_and_extras() {
        let cfg = AntivirusConfig {
            extra_excludes: vec!["^/srv/big-data".into()],
            ..AntivirusConfig::default()
        };
        let ex = cfg.effective_excludes();
        assert!(ex.contains(&"^/proc".to_string()));
        assert!(ex.contains(&"^/srv/big-data".to_string()));
    }
}
