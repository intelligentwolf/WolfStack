// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Disk-array management — the storage backend Klas asked for. Sits
//! on top of either:
//!
//!   * Vanilla **Linux mdadm** software RAID (RAID 0/1/5/6/10) — the
//!     default everywhere; status via `/proc/mdstat`, control via
//!     `mdadm`.
//!   * **NoNRAID** (open-source port of the Unraid parity driver to
//!     mainline kernels) — same `/proc/mdstat`-style status surface,
//!     control via `mdcmd`. We auto-detect the binary and prefer it
//!     when present so Unraid migrants get their `mdcmd start` /
//!     `mdcmd stop` semantics.
//!
//! v1.0 scope:
//!   * List arrays + per-disk detail (size, role, SMART status)
//!   * Start / stop the array
//!   * Trigger a parity check now, or schedule one (cron-style)
//!   * Predictive analyser that fires on degraded / failed-disk /
//!     parity-mismatch events through the existing alert channels
//!
//! Not in v1.0: array creation, add/remove disks, filesystem ops on
//! top of the array. Use `mdadm`/`mdcmd` directly for those —
//! WolfStack's job is monitoring + day-to-day ops.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;

// ─── Backend detection ───

/// Which control plane to use for array ops. Detected once per call;
/// cheap (just checks for binary presence).
///
/// `Unraid` = a commercial Unraid host: its patched md driver emits the
/// same flat key=value status as NoNRAID (the NoNRAID fork is
/// rebrand-only — qvr/nonraid README "Driver implementation
/// differences": md→nmd, /proc/mdstat→/proc/nmdstat, mdcmd→nmdcmd) but
/// at `/proc/mdstat`, with `mdcmd` as the control tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend { Mdadm, Nonraid, Unraid }

pub fn detect_backend() -> Backend {
    // Escape hatch: operator can force mdadm even when NoNRAID
    // signals are present. Intended as a last-resort if the NoNRAID
    // detection or parser produces unexpected results on a real host
    // — set WOLFSTACK_ARRAY_DISABLE_NONRAID=1 in the wolfstack
    // systemd unit's Environment= line, restart, and the host
    // reverts to the pre-fix behaviour (mdadm-only).
    if env_truthy("WOLFSTACK_ARRAY_DISABLE_NONRAID") {
        return Backend::Mdadm;
    }
    // Commercial Unraid host — /etc/unraid-version is the product's
    // own identity file (same signal installer::unraid_tools uses).
    // Must be checked BEFORE the mdcmd fallback below: Unraid ships
    // `mdcmd`, and classifying it as Nonraid made list_arrays read
    // /proc/nmdstat (which only the NoNRAID fork registers) instead
    // of Unraid's own flat-format /proc/mdstat.
    if crate::installer::unraid_tools::is_unraid() { return Backend::Unraid; }
    // Strongest signal: the NoNRAID-specific procfs file. Created by
    // the md_nonraid kernel module at register time
    // (md_nonraid/6.12/md_unraid.c:2229) and exists for the lifetime
    // of the module — present even when no array has been imported.
    if std::path::Path::new("/proc/nmdstat").exists() { return Backend::Nonraid; }
    // Fallback signals — module loaded but procfs registration somehow
    // failed (extremely rare), or userspace tool present without the
    // module yet (operator hasn't run `modprobe nonraid` since boot).
    if nonraid_module_loaded() || nmdctl_path().is_some() || legacy_mdcmd_path().is_some() {
        return Backend::Nonraid;
    }
    Backend::Mdadm
}

/// True iff the named env var is set to a truthy value (1/true/yes,
/// case-insensitive). Empty or unset → false. Used for boolean
/// escape-hatch flags.
fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let lower = v.trim().to_ascii_lowercase();
            matches!(lower.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => false,
    }
}

/// Resolve the path to `nmdctl` — NoNRAID's userspace control tool.
/// `WOLFSTACK_NMDCTL` env override takes precedence so operators with
/// custom-install paths can pin it explicitly.
///
/// Verified install paths (cite: qvr/nonraid `tools/debian/install`
/// installs to `usr/bin/`; README recommends `/usr/local/bin/` for
/// manual installs; Arch AUR `nonraid-git` uses `/usr/bin/`).
pub fn nmdctl_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("WOLFSTACK_NMDCTL") {
        let pb = PathBuf::from(&p);
        if pb.exists() { return Some(pb); }
    }
    which("nmdctl")
}

/// Resolve the path to `mdcmd` — commercial Unraid's legacy userspace
/// tool. Kept as a fallback so WolfStack still works on legitimate
/// Unraid hosts (where `/proc/mdstat` is patched in place and `mdcmd`
/// is the right control surface). NoNRAID intentionally split this
/// out into `nmdctl` so the two never coexist.
pub fn legacy_mdcmd_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("WOLFSTACK_MDCMD") {
        let pb = PathBuf::from(&p);
        if pb.exists() { return Some(pb); }
    }
    which("mdcmd")
}

/// True iff the `md_nonraid` (or its alias `nonraid`) kernel module
/// is loaded.
///
/// Module-name fact-check (cite: qvr/nonraid `dkms.conf`
/// `BUILT_MODULE_NAME[0]=md-nonraid`; kernel converts `-` to `_` when
/// loading, so `/proc/modules` shows the token `md_nonraid`. The
/// alias `nonraid` is declared at `md_unraid.c:2250` so
/// `modprobe nonraid` works, but the loaded-module name remains
/// `md_nonraid`. The RAID-6 parity helper `nonraid6_pq` is loaded as
/// a sibling — present is also a positive signal.)
pub fn nonraid_module_loaded() -> bool {
    for sys_path in ["/sys/module/md_nonraid", "/sys/module/nonraid", "/sys/module/nonraid6_pq"] {
        if std::path::Path::new(sys_path).exists() { return true; }
    }
    if let Ok(s) = std::fs::read_to_string("/proc/modules") {
        for line in s.lines() {
            // Module name is the first whitespace-delimited token.
            match line.split_whitespace().next() {
                Some("md_nonraid") | Some("nonraid") | Some("nonraid6_pq") => return true,
                _ => {}
            }
        }
    }
    false
}

// ─── Public types ───

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Array {
    /// Kernel device name, e.g. "md0" / "md1".
    pub name: String,
    /// "raid1" / "raid5" / "raid6" / "raid10" / "uraid" / "linear" / "..."
    pub level: String,
    /// "active" / "clean" / "degraded" / "resyncing" / "checking" / "recovering" / "stopped" / "unknown"
    pub state: String,
    /// Sync progress 0..=100 if a check/resync is running.
    pub sync_progress: Option<u8>,
    /// Speed in KB/s reported by the kernel during sync.
    pub sync_speed_kbs: Option<u64>,
    pub disks: Vec<Disk>,
    /// Array-level size, bytes. Zero if not derivable.
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default)]
    pub used_bytes: u64,
    /// One of "mdadm" / "nonraid".
    pub backend: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Disk {
    /// Block device path on the host, e.g. "/dev/sda".
    pub device: String,
    /// "data" / "parity" / "parity2" / "spare" / "missing" / "unknown".
    pub role: String,
    /// "active" / "in_sync" / "faulty" / "spare" / "missing" / "syncing" / "unknown".
    pub state: String,
    pub size_bytes: u64,
    pub used_bytes: u64,
    /// SMART overall — "PASSED" / "FAILED" / "unknown". Best-effort —
    /// we run smartctl with a tight timeout; if it's missing, we mark
    /// unknown rather than fail the whole array view.
    pub smart_status: String,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub temperature_c: Option<i32>,
    /// NoNRAID slot number (0 = P parity, 29 = Q parity, 1..28 =
    /// data). None for mdadm-managed disks. Used by the frontend to
    /// render slot order and by the backend to map data disks to
    /// their `/mnt/diskN` mountpoint.
    #[serde(default)]
    pub slot: Option<u32>,
    /// NoNRAID virtual device name (e.g. "/dev/nmd1p1"). Synthesized
    /// by md_nonraid for each data slot so filesystems mount and
    /// read/write through the parity-aware md layer rather than the
    /// raw disk. `device` above still holds the underlying physical
    /// disk (sda1) for SMART correlation. None for mdadm and for
    /// NoNRAID parity slots (parity disks have no per-slot virtual
    /// device — `diskName.0` and `diskName.29` are unused per
    /// md_unraid.c:1842 `if (disk_active || disk_enabled)`).
    #[serde(default)]
    pub virtual_device: Option<String>,
    /// Filesystem mountpoint, if mounted. Used by the frontend to
    /// render "mounted at /mnt/disk1" and by used_bytes calculation.
    #[serde(default)]
    pub mountpoint: Option<String>,
}

// ─── Persisted config ───

fn config_path() -> PathBuf {
    PathBuf::from(crate::paths::get().config_dir.clone()).join("arrays.json")
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ArrayConfig {
    /// Per-array operator preferences.
    #[serde(default)]
    pub schedules: Vec<ParitySchedule>,
    /// Alert toggles per array. Default: all on.
    #[serde(default)]
    pub alert_overrides: Vec<AlertOverride>,
    /// Scheduled SMART short self-tests. `#[serde(default)]` so an existing
    /// arrays.json without the key loads and picks up the safe defaults.
    #[serde(default)]
    pub smart_tests: SmartTestConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ParitySchedule {
    pub array: String,        // "md0"
    pub cron: String,         // standard 5-field cron expression
    /// "check" = read-only verify (the safe default), "repair" =
    /// fix mismatches (only safe when you trust the data more than
    /// the parity).
    pub action: String,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AlertOverride {
    pub array: String,
    /// Suppress these alerts. Values: "degraded", "failed_disk",
    /// "smart_prefail", "parity_mismatch", "sync_started", "sync_done".
    pub suppress: Vec<String>,
}

impl ArrayConfig {
    pub fn load() -> Self {
        std::fs::read_to_string(config_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    pub fn save(&self) -> std::io::Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        crate::paths::write_secure(&path.to_string_lossy(), json)
            .map_err(std::io::Error::other)
    }
}

// ─── Array enumeration ───
//
// Two backends, two completely different on-disk surfaces:
//
//   * mdadm   → `/proc/mdstat` (kernel md driver — indented blocks)
//   * NoNRAID → `/proc/nmdstat` (md_nonraid module — flat key=value)
//
// We pick the source by the backend the detector resolved to. Reading
// `/proc/mdstat` on a NoNRAID-only host returns essentially empty
// content (just the "Personalities" header) because md_nonraid does
// NOT patch the kernel `md` driver in place — it registers as a
// separate procfs file (`/proc/nmdstat`). The old behaviour of
// reading `/proc/mdstat` for NoNRAID was the root cause of "the
// storage array is not finding nonraid".
//
// Format references (verified against qvr/nonraid main branch):
//   * `/proc/nmdstat` write code:  md_nonraid/6.12/md_unraid.c:1690-1862
//   * procfs registration:         md_nonraid/6.12/md_unraid.c:2228-2229
//   * Slot constants:              md_nonraid/6.12/md_unraid.h:74-76
//     (MD_SB_DISKS=30, MD_SB_P_IDX=0, MD_SB_Q_IDX=29)
//   * Reference parser (Bash):     tools/nmdctl
//   * Real fixture for testing:    tools/tests/test_nmdctl_basic.bats

/// List every array the configured backend reports. Returns an empty
/// Vec if neither backend's procfs surface is present.
pub fn list_arrays() -> Vec<Array> {
    match detect_backend() {
        Backend::Nonraid => list_arrays_nonraid(),
        Backend::Unraid => list_arrays_unraid(),
        Backend::Mdadm => list_arrays_mdadm(),
    }
}

/// mdadm path — read /proc/mdstat as before. Behaviour preserved
/// verbatim from the pre-fix code; only the dispatcher above changed.
fn list_arrays_mdadm() -> Vec<Array> {
    let content = match std::fs::read_to_string("/proc/mdstat") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut arrays = parse_mdstat(&content, "mdadm");
    for a in arrays.iter_mut() {
        a.used_bytes = filesystem_used_bytes_for(&format!("/dev/{}", a.name)).unwrap_or(0);
    }
    arrays
}

/// NoNRAID path — read /proc/nmdstat and synthesize a single Array
/// from the key=value content. NoNRAID's module supports exactly one
/// superblock loaded at a time (cite: only one `register_blkdev` call
/// in md_unraid.c:2217 → one MAJOR_NR → one array per module-load),
/// so the result is at most one entry.
///
/// Per-disk filesystem fill is sourced from `/proc/mounts` so we honour
/// whatever prefix the operator passed to `nmdctl mount` (default
/// `/mnt/disk`, but any prefix is legal — see tools/nmdctl
/// MOUNTPREFIX). For each data disk we match the disk's virtual
/// device (`/dev/nmd<N>p1`) against the mount source.
fn list_arrays_nonraid() -> Vec<Array> {
    let content = match std::fs::read_to_string("/proc/nmdstat") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut arrays = parse_nmdstat(&content);
    fill_array_mounts(&mut arrays);
    arrays
}

/// Commercial-Unraid path — the patched md driver writes the same flat
/// key=value status as NoNRAID, but at `/proc/mdstat` with `md`-named
/// devices (`/dev/mdXp1`). Devices come from the file content, so the
/// shared parser produces the right paths without translation. The
/// `/proc/nmdstat` fallback covers a hypothetical future Unraid that
/// adopts the fork's split-module naming — content-sniffed either way,
/// so a host with neither yields no arrays rather than a phantom.
fn list_arrays_unraid() -> Vec<Array> {
    for path in ["/proc/mdstat", "/proc/nmdstat"] {
        let Ok(content) = std::fs::read_to_string(path) else { continue };
        if !content.contains("mdState=") { continue; }
        let mut arrays = parse_nmdstat(&content);
        for a in arrays.iter_mut() {
            a.backend = "unraid".into();
            if path == "/proc/mdstat" {
                // The commercial driver registers block major "md",
                // not the fork's "nmd" (the rename is the fork's own
                // patch — qvr/nonraid README).
                a.name = "md".into();
            }
        }
        fill_array_mounts(&mut arrays);
        return arrays;
    }
    Vec::new()
}

/// Fill per-data-disk mountpoint + used bytes from /proc/mounts.
/// Shared by the NoNRAID and Unraid list paths — both mount
/// filesystems on the md-layer virtual device (`/dev/nmdXp1` /
/// `/dev/mdXp1`), whatever prefix the operator mounts them under.
fn fill_array_mounts(arrays: &mut [Array]) {
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let mount_map = parse_proc_mounts(&mounts);

    for a in arrays.iter_mut() {
        let mut total_used = 0u64;
        for d in a.disks.iter_mut() {
            if d.role != "data" { continue; }
            // Try the virtual device first (the canonical mount
            // source for NoNRAID — filesystems are mounted on
            // /dev/nmd<N>p1, not the underlying disk).
            let candidates: Vec<&str> = [d.virtual_device.as_deref(), Some(d.device.as_str())]
                .into_iter()
                .flatten()
                .filter(|s| !s.is_empty())
                .collect();
            for cand in candidates {
                if let Some(mnt) = mount_map.get(cand) {
                    d.mountpoint = Some(mnt.clone());
                    if let Some(u) = statfs_used_bytes(mnt) {
                        d.used_bytes = u;
                        total_used = total_used.saturating_add(u);
                    }
                    break;
                }
            }
        }
        a.used_bytes = total_used;
    }
}

/// Parse `/proc/mounts` into a `device → mountpoint` map. Octal
/// escapes (\040 for space, \011 for tab, \012 for newline, \134 for
/// backslash) in field 2 are decoded per fstab(5). Used by the
/// NoNRAID per-disk fill to find where each `/dev/nmd<N>p1` is
/// mounted regardless of the operator's chosen mount prefix.
fn parse_proc_mounts(content: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in content.lines() {
        let mut it = line.split_whitespace();
        let src = match it.next() { Some(s) => s, None => continue };
        let mnt = match it.next() { Some(m) => decode_mount_escapes(m), None => continue };
        // First mount wins for a given device (multiple bind-mounts of
        // the same source would otherwise overwrite each other; the
        // first is typically the "primary" filesystem mount).
        map.entry(src.to_string()).or_insert(mnt);
    }
    map
}

fn decode_mount_escapes(s: &str) -> String {
    // fstab(5) only escapes \040 (space), \011 (tab), \012 (newline),
    // \134 (backslash) in mount points. Anything else passes through.
    let mut out = String::with_capacity(s.len());
    let mut bytes = s.bytes().peekable();
    while let Some(b) = bytes.next() {
        if b == b'\\' {
            let d1 = bytes.peek().copied();
            if let Some(d1) = d1 {
                // Octal triplet?
                if d1.is_ascii_digit() {
                    let mut digits = [0u8; 3];
                    digits[0] = d1;
                    bytes.next();
                    for slot in &mut digits[1..] {
                        match bytes.peek().copied() {
                            Some(d) if d.is_ascii_digit() => { *slot = d; bytes.next(); }
                            _ => { *slot = b'0'; }
                        }
                    }
                    let octal = std::str::from_utf8(&digits).ok()
                        .and_then(|s| u8::from_str_radix(s, 8).ok());
                    if let Some(code) = octal {
                        if (code.is_ascii() && code >= 0x20) || code == 0x09 || code == 0x0a {
                            out.push(code as char);
                        } else {
                            out.push('\\');
                            for d in &digits { out.push(*d as char); }
                        }
                        continue;
                    }
                }
            }
            out.push('\\');
        } else {
            out.push(b as char);
        }
    }
    out
}

/// Used bytes on a filesystem via statvfs — replaces the previous
/// `df` shellout. Works without the df binary (some minimal LXC
/// containers omit it) and avoids parsing locale-affected output.
fn statfs_used_bytes(path: &str) -> Option<u64> {
    use std::ffi::CString;
    let cpath = CString::new(path).ok()?;
    // SAFETY: zero-init is valid for libc::statvfs (POD struct).
    let mut sv: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(cpath.as_ptr(), &mut sv as *mut _) };
    if rc != 0 { return None; }
    // Block size for application use is f_frsize (POSIX). Some
    // filesystems return 0 here — fall back to f_bsize.
    let block_size = if sv.f_frsize > 0 { sv.f_frsize as u64 } else { sv.f_bsize as u64 };
    let used_blocks = sv.f_blocks.saturating_sub(sv.f_bfree) as u64;
    Some(used_blocks.saturating_mul(block_size))
}

/// Pure parser for `/proc/mdstat` content. Carved out so the unit
/// tests can exercise it without a real /proc filesystem.
///
/// Active header:   `md0 : active raid1 sda1[0] sdb1[1]`
/// Inactive header: `md0 : inactive sda1[0] sdb1[1]`           (no level word)
/// Read-only:       `md0 : active (read-only) raid1 sda1[0] ...`
pub fn parse_mdstat(content: &str, backend_label: &str) -> Vec<Array> {
    let mut arrays: Vec<Array> = Vec::new();
    let mut lines = content.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("md") { continue; }
        // Need a colon directly after the name — skips
        // "md_d0_raid_disk" or other prefixes.
        let (name_field, rest) = match trimmed.split_once(':') {
            Some(p) => p,
            None => continue,
        };
        let name = name_field.trim().to_string();
        if name.is_empty() || !name.starts_with("md") { continue; }

        let mut tokens = rest.split_whitespace().peekable();
        let state_raw = tokens.next().unwrap_or("unknown").to_lowercase();

        // "active" may be followed by an optional "(read-only)" or
        // "(auto-read-only)" annotation before the level word. Skip
        // any parenthesised flags.
        while let Some(t) = tokens.peek() {
            if t.starts_with('(') && t.ends_with(')') { tokens.next(); } else { break; }
        }

        // Inactive arrays have no level word — the next token is the
        // first disk (matching `<name>[<idx>]`). Detect this and leave
        // level as "unknown" rather than mis-consuming the first disk.
        let level = match tokens.peek() {
            Some(t) if looks_like_disk_token(t) => "unknown".to_string(),
            Some(_) => tokens.next().unwrap().to_string(),
            None => "unknown".to_string(),
        };

        let mut disks: Vec<Disk> = Vec::new();
        for token in tokens {
            if !looks_like_disk_token(token) { continue; }
            let dev_part = token.split('[').next().unwrap_or(token);
            let device = format!("/dev/{}", dev_part);
            let dstate = if token.contains("(F)") { "faulty" }
                else if token.contains("(S)") { "spare" }
                else if token.contains("(R)") { "replacement" }
                else { "in_sync" }.to_string();
            disks.push(Disk {
                device,
                role: "data".into(),
                state: dstate,
                size_bytes: 0,
                used_bytes: 0,
                smart_status: "unknown".into(),
                model: None,
                serial: None,
                temperature_c: None,
                slot: None,
                virtual_device: None,
                mountpoint: None,
            });
        }

        let mut sync_progress = None;
        let mut sync_speed_kbs = None;
        let mut size_bytes = 0u64;
        let mut state_refined = state_raw.clone();
        while let Some(next) = lines.peek() {
            let t = next.trim_start();
            if t.is_empty() || (t.starts_with("md") && t.contains(':')) { break; }
            if t.contains("blocks") {
                if let Some(blocks_str) = t.split_whitespace().next()
                    && let Ok(blocks) = blocks_str.parse::<u64>() {
                        size_bytes = blocks * 1024;
                    }
                if t.contains('_') {
                    state_refined = "degraded".into();
                } else if t.contains("[U") {
                    state_refined = "clean".into();
                }
            }
            if t.contains('=') && (t.contains("resync") || t.contains("recovery")
                || t.contains("check") || t.contains("reshape"))
            {
                if let Some(pct_idx) = t.find('%') {
                    let head = &t[..pct_idx];
                    let pct: String = head.chars().rev()
                        .take_while(|c| c.is_ascii_digit() || *c == '.').collect();
                    let pct: String = pct.chars().rev().collect();
                    if let Ok(p) = pct.parse::<f64>() {
                        sync_progress = Some(p as u8);
                    }
                }
                if let Some(sp_pos) = t.find("speed=") {
                    let rest = &t[sp_pos + 6..];
                    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(n) = num.parse::<u64>() {
                        sync_speed_kbs = Some(n);
                    }
                }
                if t.contains("recovery") { state_refined = "recovering".into(); }
                else if t.contains("check") { state_refined = "checking".into(); }
                else if t.contains("reshape") { state_refined = "reshaping".into(); }
                else if t.contains("resync") { state_refined = "resyncing".into(); }
            }
            lines.next();
        }

        arrays.push(Array {
            name,
            level,
            state: state_refined,
            sync_progress,
            sync_speed_kbs,
            disks,
            size_bytes,
            used_bytes: 0, // filled by list_arrays() outside the pure parser
            backend: backend_label.into(),
        });
    }
    arrays
}

// ─── /proc/nmdstat parser (NoNRAID) ───
//
// Format is flat `key=value\n` lines. Per-disk records use a `.N`
// suffix on the key, where N is the slot index 0..29 (0=P parity,
// 29=Q parity, 1..28=data — cite md_nonraid/6.12/md_unraid.h:74-76).
//
// Reference parser: `tools/nmdctl` parse_nmdstat() in the upstream
// repo. We re-implement it in Rust rather than shell out because:
//   1) We want fast, dependency-free access (nmdctl needs root + a
//      shell roundtrip on every refresh).
//   2) The data shape is small and stable.
//   3) Having a Rust parser lets us unit-test against the upstream
//      bats fixture verbatim.
//
// Fixture used for tests: `tools/tests/test_nmdctl_basic.bats`
// `create_mock_nmdstat()` (3-disk array, 1 parity + 2 data).

/// Parse a `/proc/nmdstat` snapshot into our normalised Array
/// representation. NoNRAID supports a single superblock per module
/// load, so the result is either zero or one entry.
pub fn parse_nmdstat(content: &str) -> Vec<Array> {
    use std::collections::HashMap;
    let mut kv: HashMap<String, String> = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if let Some((k, v)) = line.split_once('=') {
            kv.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    // Empty / no array → return nothing rather than a phantom entry.
    if kv.is_empty() { return Vec::new(); }
    // `mdState` is required for a meaningful array. If it's absent we
    // treat the file as "module loaded, no array imported yet" and
    // return empty so the UI shows the "no arrays" state with the
    // diagnostic hint rather than a half-populated row.
    let md_state = match kv.get("mdState") { Some(s) => s.as_str(), None => return Vec::new() };

    // Discover every slot index present by scanning for `<key>.<N>=`
    // forms. Use a sorted BTreeSet so output order is deterministic
    // (P first, data slots ascending, Q last).
    let mut slots: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for k in kv.keys() {
        if let Some(dot) = k.find('.')
            && let Ok(n) = k[dot + 1..].parse::<u32>() {
                slots.insert(n);
            }
    }

    let mut disks: Vec<Disk> = Vec::new();
    let mut total_data_bytes: u64 = 0;
    let mut total_parity_bytes: u64 = 0;
    let mut any_missing = false;
    let mut any_disabled = false;
    for slot in slots.iter().copied() {
        // Size: prefer rdevSize (real device); fall back to diskSize
        // (configured slot size from the superblock). Both are in
        // 1024-byte blocks (cite: docs/nmdstat.5).
        let size_kb: u64 = kv.get(&format!("rdevSize.{}", slot))
            .or_else(|| kv.get(&format!("diskSize.{}", slot)))
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let size_bytes = size_kb.saturating_mul(1024);

        // Underlying physical device. NoNRAID stores names without
        // /dev/ prefix (sda1, nvme0n1p1). Empty / "(null)" / absent
        // → no disk in this slot.
        let phys = kv.get(&format!("rdevName.{}", slot))
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty() && *s != "(null)" && *s != "none")
            .unwrap_or("");
        let device = if phys.is_empty() {
            String::new()
        } else if phys.starts_with("/dev/") {
            phys.to_string()
        } else {
            format!("/dev/{}", phys)
        };

        // rdevStatus → our normalised disk state. Values listed in
        // qvr/nonraid docs/nmdstat.5 NOTES section. Missing key for a
        // slot that has a sized rdev → assume "unknown" rather than
        // silently picking a state.
        let raw_status = kv.get(&format!("rdevStatus.{}", slot)).map(|s| s.as_str()).unwrap_or("");
        let state = match raw_status {
            "DISK_OK"          => "in_sync",
            // DISK_NP = "no disk present, no disk configured"
            // (md_unraid.c:400) — an EMPTY SLOT, not a lost disk. The
            // real driver prints ALL 30 slots (md_status loops
            // 0..MD_SB_DISKS), so every unused slot arrives as
            // DISK_NP. Mapping it to "missing" rendered phantom
            // missing-disk rows and flagged healthy arrays as
            // degraded (klas, ninni 2026-08-11). The reference mock
            // the fixtures were lifted from omits empty slots, which
            // is why the tests never caught it. DISK_NP_MISSING
            // ("enabled, but missing") is the real missing-disk state.
            "DISK_NP"          => "empty",
            "DISK_NP_MISSING"
            | "DISK_NP_DSBL"   => "missing",
            "DISK_INVALID"
            | "DISK_WRONG"
            | "DISK_DSBL"      => "faulty",
            "DISK_DSBL_NEW"
            | "DISK_NEW"       => "spare",
            ""                 => "unknown",
            _                  => "unknown",
        }.to_string();
        if state == "missing"  { any_missing = true; }
        if raw_status == "DISK_DSBL" || raw_status == "DISK_INVALID" || raw_status == "DISK_WRONG" {
            any_disabled = true;
        }

        // Role from slot index. AUTHORITATIVE: md_nonraid/6.12/md_unraid.h:74-76
        //   MD_SB_P_IDX = 0  (P parity)
        //   MD_SB_Q_IDX = 29 (Q parity, dual-parity slot)
        //   1..28 = data
        //   30 = reserved (won't appear in practice)
        let role = match slot {
            0  => { total_parity_bytes = total_parity_bytes.saturating_add(size_bytes); "parity"  }
            29 => { total_parity_bytes = total_parity_bytes.saturating_add(size_bytes); "parity2" }
            1..=28 => { total_data_bytes = total_data_bytes.saturating_add(size_bytes); "data"    }
            _ => "unknown",
        }.to_string();

        // Skip slots with nothing to show: no device, no size, and a
        // status that's either absent (the mock's Q-parity
        // placeholder: `diskSize.29=0` with no rdevName.29) or
        // DISK_NP (the real driver prints every one of the 30 slots,
        // so all unused slots arrive as sized-0 DISK_NP). A DISK_NP
        // slot that somehow carries a size or device is kept and shown
        // as "empty" rather than silently dropped.
        if device.is_empty() && size_bytes == 0
            && (raw_status.is_empty() || raw_status == "DISK_NP") {
            continue;
        }

        let serial = kv.get(&format!("diskId.{}", slot))
            .filter(|s| !s.is_empty() && s.as_str() != "(null)")
            .cloned();

        // Virtual md-layer block device. `diskName.N` per the kernel
        // source (md_unraid.c:1842) is populated for data slots that
        // are active or enabled — i.e. visible to the filesystem.
        // Format is "nmd<N>p1" (always partition 1; per
        // md_unraid.c:2217 the block major is registered as "nmd").
        // Parity slots (0, 29) don't get a per-slot block device, so
        // diskName.0 / diskName.29 are absent or empty.
        let virtual_device = kv.get(&format!("diskName.{}", slot))
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty() && *s != "(null)")
            .map(|s| if s.starts_with("/dev/") { s.to_string() } else { format!("/dev/{}", s) });

        disks.push(Disk {
            device,
            role,
            state,
            size_bytes,
            used_bytes: 0,           // filled by list_arrays_nonraid via /proc/mounts
            smart_status: "unknown".into(),
            model: None,
            serial,
            temperature_c: None,
            slot: Some(slot),
            virtual_device,
            mountpoint: None,        // filled by list_arrays_nonraid via /proc/mounts
        });
    }

    // Array-level state mapping (cite: docs/nmdstat.5 NOTES section
    // for the full enum and the paused-check rule).
    //
    // mdResync semantics:
    //   * mdResync != 0       → sync active
    //   * mdResync == 0  &&  mdResyncPos > 0  → sync PAUSED (position retained)
    //   * mdResync == 0  &&  mdResyncPos == 0 → no sync activity
    let resync_active = kv.get("mdResync").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) != 0;
    let resync_pos:  u64 = kv.get("mdResyncPos").and_then(|s| s.parse().ok()).unwrap_or(0);
    let resync_size: u64 = kv.get("mdResyncSize").and_then(|s| s.parse().ok()).unwrap_or(0);
    let resync_db:   u64 = kv.get("mdResyncDb").and_then(|s| s.parse().ok()).unwrap_or(0);
    let resync_dt:   u64 = kv.get("mdResyncDt").and_then(|s| s.parse().ok()).unwrap_or(0);
    let resync_action = kv.get("mdResyncAction").map(|s| s.as_str()).unwrap_or("");

    let mut state = match md_state {
        "STARTED" => {
            if any_missing || any_disabled { "degraded" }
            else if resync_active {
                if resync_action.starts_with("recon") || resync_action.starts_with("clear") {
                    "recovering"
                } else {
                    "checking"
                }
            } else { "active" }
        }
        "STOPPED" | "NEW_ARRAY" => "stopped",
        "RECON_DISK"            => "recovering",
        "DISABLE_DISK" | "SWAP_DSBL" => "degraded",
        s if s.starts_with("ERROR:") => "unknown",
        _ => "unknown",
    }.to_string();
    // sbState=1 = clean shutdown; 0 = unclean. If we're STARTED+clean
    // and not degraded/syncing, prefer "clean" over "active" for
    // alignment with mdadm output.
    if state == "active" && kv.get("sbState").map(|s| s.as_str()) == Some("1") {
        state = "clean".into();
    }

    let sync_progress: Option<u8> = if resync_size > 0 && (resync_active || resync_pos > 0) {
        Some(((resync_pos as f64 / resync_size as f64) * 100.0).clamp(0.0, 100.0) as u8)
    } else { None };
    let sync_speed_kbs: Option<u64> = if resync_active && resync_dt > 0 {
        Some(resync_db / resync_dt)
    } else { None };

    // A module with no populated slots at all (fresh load, superblock
    // never imported, or stopped with an empty config) is "no array",
    // not an array of ghosts — returning a disk-less entry is what
    // rendered klas's stub card. The diagnostics panel covers the
    // "module loaded but nothing imported" case with an actionable
    // hint, which is strictly more useful than a phantom row.
    if disks.is_empty() {
        return Vec::new();
    }

    // Single-array model — register the array under the block device
    // class name "nmd" (verified against md_unraid.c:2217 register_blkdev
    // call). validate_array_name() in the API accepts this fine.
    vec![Array {
        name: "nmd".into(),
        level: "uraid".into(),
        state,
        sync_progress,
        sync_speed_kbs,
        disks,
        size_bytes: total_data_bytes,
        used_bytes: 0,           // filled by caller
        backend: "nonraid".into(),
    }]
}

/// Heuristic: does this token look like a disk entry (e.g. "sda1[0]"
/// / "nvme0n1p1[0]" / "sdb1[1](F)")? Used by the parser to
/// distinguish disk tokens from level / option words on inactive
/// arrays.
fn looks_like_disk_token(t: &str) -> bool {
    // Must contain "[<digits>]" somewhere and start with a letter.
    if !t.starts_with(|c: char| c.is_ascii_alphabetic()) { return false; }
    let Some(open) = t.find('[') else { return false; };
    let Some(close) = t[open..].find(']') else { return false; };
    let inside = &t[open + 1 .. open + close];
    !inside.is_empty() && inside.chars().all(|c| c.is_ascii_digit())
}

/// Enrich an array with per-disk SMART data + role refinement from
/// `mdadm --detail`. Slow-ish (smartctl per disk), so we only do it
/// when the operator views detail — not on every list refresh.
pub fn array_detail(name: &str) -> Option<Array> {
    let mut arr = list_arrays().into_iter().find(|a| a.name == name)?;

    // Refine roles from `mdadm --detail`.
    let detail = Command::new("mdadm")
        .args(["--detail", &format!("/dev/{}", name)])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    for d in arr.disks.iter_mut() {
        let dev = d.device.trim_start_matches("/dev/");
        // mdadm --detail line:
        //   "       0       8        1        0      active sync   /dev/sda1"
        //   "       1       8       17        -      faulty   /dev/sdb1"
        for line in detail.lines() {
            if !line.contains(dev) { continue; }
            let lc = line.to_ascii_lowercase();
            if lc.contains("faulty")    { d.state = "faulty".into(); }
            else if lc.contains("spare")     { d.state = "spare".into(); }
            else if lc.contains("active")    { d.state = "active".into(); }
            // role detection (parity vs data) — mdadm doesn't print
            // an explicit "parity" word for vanilla raid5/6, but
            // NoNRAID does. For uraid/raid5, the LAST disk in the
            // listing is the parity. We approximate by leaving role
            // = data here and let nonraid_detail() override below.
        }
        // Per-disk size, model, serial, SMART. Best-effort.
        if let Some(info) = lsblk_disk_info(&d.device) {
            d.size_bytes = info.size_bytes;
            d.model = info.model;
            d.serial = info.serial;
        }
        if let Some((status, temp)) = smart_summary(&d.device) {
            d.smart_status = status;
            d.temperature_c = temp;
        }
    }

    // For NoNRAID, roles + per-disk fill are populated by
    // parse_nmdstat() / list_arrays_nonraid() directly from
    // /proc/nmdstat and /mnt/diskN — no further refinement needed
    // here. The previous code shelled out to `mdcmd status` which
    // doesn't exist on NoNRAID hosts and would have silently no-op'd.

    Some(arr)
}

// ─── Operations ───

#[derive(Debug)]
pub enum ArrayError {
    NotInstalled { tool: String, install_package: String },
    CommandFailed(String),
    NoSuchArray(String),
    Io(std::io::Error),
}

impl std::fmt::Display for ArrayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArrayError::NotInstalled { tool, install_package } => write!(
                f, "{} not installed (install package '{}')", tool, install_package
            ),
            ArrayError::CommandFailed(s) => write!(f, "command failed: {}", s),
            ArrayError::NoSuchArray(n) => write!(f, "no such array: {}", n),
            ArrayError::Io(e) => write!(f, "io: {}", e),
        }
    }
}

impl From<std::io::Error> for ArrayError {
    fn from(e: std::io::Error) -> Self { ArrayError::Io(e) }
}

/// Stop an array.
///
/// - mdadm: `mdadm --stop /dev/mdN`
/// - NoNRAID: `nmdctl -u stop` (unattended; per upstream usage block
///   in `tools/nmdctl`: lines 54-105). NoNRAID has a single-array
///   model so the array name is implicit.
/// - Legacy commercial Unraid: `mdcmd stop` (kept as a fallback).
pub fn stop_array(name: &str) -> Result<String, ArrayError> {
    if list_arrays().iter().find(|a| a.name == name).is_none() {
        return Err(ArrayError::NoSuchArray(name.into()));
    }
    match detect_backend() {
        // Unraid shares the Nonraid path: nonraid_action falls back to
        // `mdcmd` (with subcommand translation) when nmdctl is absent,
        // which is exactly the commercial-Unraid control surface.
        Backend::Nonraid | Backend::Unraid => nonraid_action(&["stop"]),
        Backend::Mdadm   => run_capturing("mdadm", &["--stop", &format!("/dev/{}", name)], "mdadm"),
    }
}

/// Start (assemble) an array.
///
/// - NoNRAID: `nmdctl -u start` (legacy fallback: `mdcmd start`).
/// - mdadm: `mdadm --assemble /dev/mdN`.
pub fn start_array(name: &str) -> Result<String, ArrayError> {
    match detect_backend() {
        Backend::Nonraid | Backend::Unraid => nonraid_action(&["start"]),
        Backend::Mdadm   => run_capturing("mdadm", &["--assemble", &format!("/dev/{}", name)], "mdadm"),
    }
}

/// Trigger a parity check. Action is "check" (read-only verify, the
/// default) or "repair" (overwrite mismatches).
///
/// NoNRAID nmdctl spelling (cite: `tools/nmdctl` usage block lines
/// 87-89): `nmdctl -u check NOCORRECT` for read-only, `nmdctl -u
/// check CORRECT` for repair. The `CORRECT` keyword maps to the
/// kernel's `mdResyncCorr=1` flag (cite: `md_unraid.c:1714-1787`).
/// Legacy Unraid `mdcmd` spelling: `mdcmd check` / `mdcmd check correct`.
pub fn parity_check(name: &str, action: &str) -> Result<String, ArrayError> {
    if !["check", "repair"].contains(&action) {
        return Err(ArrayError::CommandFailed(format!(
            "action must be 'check' or 'repair', got '{}'", action
        )));
    }
    match detect_backend() {
        Backend::Nonraid | Backend::Unraid => {
            let mode = if action == "repair" { "CORRECT" } else { "NOCORRECT" };
            nonraid_action(&["check", mode])
        }
        Backend::Mdadm => {
            // Vanilla mdadm: write to /sys/block/mdN/md/sync_action.
            let path = format!("/sys/block/{}/md/sync_action", name);
            std::fs::write(&path, action.as_bytes())
                .map_err(|e| ArrayError::CommandFailed(format!("write {}: {}", path, e)))?;
            Ok(format!("{} started on /dev/{}", action, name))
        }
    }
}

/// Cancel an in-progress parity check.
///
/// NoNRAID: `nmdctl -u check CANCEL` (cite: `tools/nmdctl` usage line
/// 89: `check [OPTION] ... CORRECT (default), NOCORRECT, PAUSE,
/// RESUME, CANCEL`). The historical `nocheck` subcommand exists in
/// the kernel-level `/proc/nmdcmd` interface (cite: `docs/nmdcmd.8`)
/// but `nmdctl` folds it into `check CANCEL` for the userspace
/// surface, which is the path we use. Legacy `mdcmd nocheck` kept as
/// a fallback for commercial Unraid.
pub fn parity_cancel(name: &str) -> Result<String, ArrayError> {
    match detect_backend() {
        Backend::Nonraid | Backend::Unraid => nonraid_action(&["check", "CANCEL"]),
        Backend::Mdadm => {
            let path = format!("/sys/block/{}/md/sync_action", name);
            std::fs::write(&path, b"idle")
                .map_err(|e| ArrayError::CommandFailed(format!("write {}: {}", path, e)))?;
            Ok(format!("parity check cancelled on /dev/{}", name))
        }
    }
}

/// Run an action against the NoNRAID array. Tries `nmdctl -u …` first
/// (the modern Debian/Ubuntu binary, name confirmed against the
/// repo's `tools/debian/install`). If `nmdctl` is not installed,
/// falls back to legacy `mdcmd …` for commercial-Unraid hosts. The
/// subcommand semantics differ between the two — the caller is
/// responsible for passing the NoNRAID/nmdctl form; the legacy
/// fallback translates the well-known commands.
///
/// **Asynchronous semantics.** All these commands return as soon as
/// the kernel has accepted the request — they do NOT wait for the
/// underlying operation to complete:
///   * `start` returns once the array is imported and the md devices
///     are visible; it does NOT wait for any auto-mount.
///   * `stop` returns once the kernel has begun teardown; the actual
///     unmount + flush may take a moment longer.
///   * `check CORRECT|NOCORRECT` returns immediately — the actual
///     parity walk runs for hours in the kernel. Poll
///     /proc/nmdstat (mdResync != 0, mdResyncPos) for progress.
///   * `check CANCEL/PAUSE/RESUME` returns once the kernel has
///     scheduled the state change.
///     This matches the existing mdadm path (write to
///     /sys/block/mdN/md/sync_action is also fire-and-forget).
fn nonraid_action(args: &[&str]) -> Result<String, ArrayError> {
    if nmdctl_path().is_some() {
        // `-u` (unattended) suppresses interactive prompts.
        let mut full: Vec<&str> = vec!["-u"];
        full.extend_from_slice(args);
        return run_capturing("nmdctl", &full, "nonraid-tools");
    }
    // Legacy `mdcmd` fallback — only meaningful on commercial Unraid.
    // Translate the well-known nmdctl subcommands back to the mdcmd
    // form so operators on Unraid still get a working path.
    let translated: Vec<&str> = match args {
        ["check", "CORRECT"]   => vec!["check", "correct"],
        ["check", "NOCORRECT"] => vec!["check"],
        ["check", "CANCEL"]    => vec!["nocheck"],
        ["check", "PAUSE"]     => vec!["nocheck", "PAUSE"],
        ["check", "RESUME"]    => vec!["check", "RESUME"],
        // start / stop / import / etc. are spelled identically.
        _ => args.to_vec(),
    };
    run_capturing("mdcmd", &translated, "mdcmd")
}

// ─── Helpers ───

fn run_capturing(bin: &str, args: &[&str], pkg: &str) -> Result<String, ArrayError> {
    // Route nmdctl / mdcmd through the resolved path so env overrides
    // (WOLFSTACK_NMDCTL / WOLFSTACK_MDCMD) and non-PATH install
    // locations are honoured. PATH-only lookup would miss
    // /usr/local/bin and any operator-pinned path.
    let bin_to_run: std::borrow::Cow<str> = match bin {
        "nmdctl" => nmdctl_path()
            .map(|p| std::borrow::Cow::Owned(p.to_string_lossy().into_owned()))
            .unwrap_or(std::borrow::Cow::Borrowed(bin)),
        "mdcmd" => legacy_mdcmd_path()
            .map(|p| std::borrow::Cow::Owned(p.to_string_lossy().into_owned()))
            .unwrap_or(std::borrow::Cow::Borrowed(bin)),
        _ => std::borrow::Cow::Borrowed(bin),
    };
    let out = Command::new(bin_to_run.as_ref()).args(args).output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ArrayError::NotInstalled { tool: bin.into(), install_package: pkg.into() }
        } else { ArrayError::Io(e) }
    })?;
    if !out.status.success() {
        return Err(ArrayError::CommandFailed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn which(bin: &str) -> Option<PathBuf> {
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        if dir.is_empty() { continue; }
        let candidate = PathBuf::from(dir).join(bin);
        if candidate.exists() { return Some(candidate); }
    }
    // Search every directory NoNRAID / Unraid-style installs are known
    // to land in. systemd's default service PATH already covers the
    // first six; the rest are non-standard but real-world.
    for fixed in WHICH_FIXED_DIRS {
        let candidate = PathBuf::from(fixed).join(bin);
        if candidate.exists() { return Some(candidate); }
    }
    None
}

/// Directories `which()` falls back on when `$PATH` doesn't surface
/// the binary. Exported as a constant so the diagnostic endpoint can
/// surface exactly what we looked at.
pub const WHICH_FIXED_DIRS: &[&str] = &[
    "/sbin",
    "/usr/sbin",
    "/usr/local/sbin",
    "/bin",
    "/usr/bin",
    "/usr/local/bin",
    "/opt/nonraid/sbin",
    "/opt/nonraid/bin",
    "/boot/nonraid/sbin",
];

struct LsblkInfo { size_bytes: u64, model: Option<String>, serial: Option<String> }

fn lsblk_disk_info(device: &str) -> Option<LsblkInfo> {
    let out = Command::new("lsblk")
        .args(["-Jbno", "NAME,SIZE,MODEL,SERIAL", device])
        .output().ok()?;
    if !out.status.success() { return None; }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let arr = v.get("blockdevices").and_then(|x| x.as_array())?;
    let first = arr.first()?;
    Some(LsblkInfo {
        size_bytes: first.get("size").and_then(|x| x.as_u64()).unwrap_or(0),
        model: first.get("model").and_then(|x| x.as_str()).filter(|s| !s.is_empty()).map(|s| s.trim().to_string()),
        serial: first.get("serial").and_then(|x| x.as_str()).filter(|s| !s.is_empty()).map(|s| s.trim().to_string()),
    })
}

fn smart_summary(device: &str) -> Option<(String, Option<i32>)> {
    // smartctl returns non-zero on SMART errors which is fine — we
    // still parse stdout. Tight 5s timeout: SMART scans can hang on
    // misbehaving USB enclosures.
    let out = Command::new("timeout").args(["5", "smartctl", "-H", "-A", device]).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut status = "unknown".to_string();
    let mut temp: Option<i32> = None;
    for line in s.lines() {
        let l = line.trim();
        if let Some(idx) = l.find("overall-health self-assessment test result:") {
            let rest = l[idx + "overall-health self-assessment test result:".len()..].trim();
            status = rest.to_string();
        }
        // SMART attribute 194 is Temperature_Celsius — line format:
        //   "194 Temperature_Celsius     0x0022   ... 38 ..."
        if l.starts_with("194") && l.contains("Temperature")
            && let Some(num) = l.split_whitespace().nth(9).and_then(|t| t.parse::<i32>().ok()) {
                temp = Some(num);
            }
    }
    Some((status, temp))
}

/// Best-effort one-time install of smartmontools when `smartctl` is missing.
/// Without it every SMART surface (failing-disk Issues alerts, Storage health
/// badges, upgrade-scanner disk checks) silently degrades to "no data" — the
/// operator believes disks are monitored when nothing is being read (Paul,
/// 2026-07-03). Guarded to ONE resolution per process: a system where the
/// install fails (offline, or no package manager at all — e.g. Unraid, where
/// setup.sh's static-binary path applies instead) is remembered and never
/// retried, so the 60s watcher doesn't hammer the package manager.
/// Same runtime-install approach as `storage::install_s3fs`; the package is
/// named `smartmontools` on every supported family. The install is bounded by
/// coreutils `timeout` so a hung package manager can't wedge the watcher; the
/// caller runs on the blocking pool, never on the async runtime.
pub fn ensure_smartmontools() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    // 0 = unresolved, 1 = smartctl available, 2 = unavailable (gave up),
    // 3 = install attempt claimed (in flight)
    static SMARTCTL_STATE: AtomicU8 = AtomicU8::new(0);
    match SMARTCTL_STATE.load(Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let have = Command::new("which").arg("smartctl").output()
        .map(|o| o.status.success()).unwrap_or(false);
    if have {
        SMARTCTL_STATE.store(1, Ordering::Relaxed);
        return true;
    }
    // Claim the single install attempt via CAS — a concurrent second caller
    // (future call sites; today's watcher is sequential) must not race a
    // second package-manager run, lose to the dpkg/rpm lock, and poison the
    // verdict to "unavailable" when the winner actually installed it
    // (review catch, 2026-07-03). Losers report "not yet available" for this
    // call; the next poll re-reads the winner's resolved state.
    if SMARTCTL_STATE.compare_exchange(0, 3, Ordering::Relaxed, Ordering::Relaxed).is_err() {
        return SMARTCTL_STATE.load(Ordering::Relaxed) == 1;
    }
    tracing::info!("smartctl not found — attempting one-time smartmontools install");
    let output = match crate::installer::detect_distro() {
        crate::installer::DistroFamily::Arch =>
            Command::new("timeout").args(["300", "pacman", "-S", "--noconfirm", "smartmontools"]).output(),
        crate::installer::DistroFamily::Alpine =>
            Command::new("timeout").args(["300", "apk", "add", "smartmontools"]).output(),
        crate::installer::DistroFamily::RedHat =>
            Command::new("timeout").args(["300", "dnf", "install", "-y", "smartmontools"]).output(),
        crate::installer::DistroFamily::Suse =>
            Command::new("timeout").args(["300", "zypper", "--non-interactive", "install", "smartmontools"]).output(),
        // Debian family + Unknown: apt-get (matches install_s3fs's fallback).
        _ =>
            Command::new("timeout").args(["300", "apt-get", "install", "-y", "smartmontools"]).output(),
    };
    let installed = output.map(|o| o.status.success()).unwrap_or(false)
        && Command::new("which").arg("smartctl").output()
            .map(|o| o.status.success()).unwrap_or(false);
    if installed {
        tracing::info!("smartmontools installed — SMART disk monitoring active");
        SMARTCTL_STATE.store(1, Ordering::Relaxed);
    } else {
        tracing::warn!("smartmontools could not be installed — SMART disk monitoring unavailable on this node (install it manually to enable failing-disk alerts)");
        SMARTCTL_STATE.store(2, Ordering::Relaxed);
    }
    installed
}

/// Whether a whole-disk device has real hardware behind it.
///
/// `/sys/block/<name>/device` is the driver-model link to the backing
/// device. SCSI/SATA, NVMe, virtio, MMC and Xen disks all have one;
/// purely virtual block devices — zram above all — do not. That link is
/// therefore the kernel's own answer to "could this thing possibly have
/// SMART data", which is exactly the question being asked.
///
/// Name matching was rejected: it needs extending for every new virtual
/// driver, and gets it wrong on platforms whose real disks use an
/// unexpected prefix.
fn disk_has_backing_hardware(dev_path: &str) -> bool {
    let name = dev_path.strip_prefix("/dev/").unwrap_or(dev_path);
    std::path::Path::new(&format!("/sys/block/{name}/device")).exists()
}

/// List whole physical disk device paths (`/dev/sda`, `/dev/nvme0n1`, …) —
/// lsblk type=disk only, so partitions, loop and rom devices are excluded,
/// and then only those with real hardware behind them.
///
/// The hardware check is not cosmetic. `lsblk` reports **zram devices as
/// type `disk`**, and a host with zram enabled (the default on Ubuntu,
/// Fedora and most desktop distros — commonly one per CPU, so 16+ on a
/// large box) had every one of them treated as a physical drive. Each got
/// `timeout 10 smartctl …` and then a `-d sat` retry, so 16 zram devices
/// cost 64 pointless processes on every scan, forever, on a device that
/// cannot have SMART data by construction.
///
/// Observed on a user's node 2026-08-13: smartctl running against
/// `/dev/zram0` and `/dev/zram1` in the process trace.
pub fn list_physical_disks() -> Vec<String> {
    let out = match Command::new("lsblk").args(["-dnpo", "NAME,TYPE"]).output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let name = it.next()?;
            let typ = it.next()?;
            if typ == "disk" { Some(name.to_string()) } else { None }
        })
        .filter(|dev| disk_has_backing_hardware(dev))
        .collect()
}

/// Whether a whole-disk device spins (HDD) or is solid-state (SSD/NVMe),
/// read from `/sys/block/<name>/queue/rotational` (`1` = rotational).
/// Used to decide the SMART standby guard: only a rotational disk can be
/// spun down and woken, so only it needs `-n standby` protection — an SSD
/// or NVMe has no spin state and must ALWAYS be read (see the Issues
/// watcher). Defaults to `true` (keep the guard) when nothing can be read,
/// so an unknown device is never woken on a hunch.
///
/// Handles partition paths too (`/dev/sdb1`, `/dev/nvme0n1p2`): those have
/// no `/sys/block/<name>` entry, so we follow the `/sys/class/block/<name>`
/// symlink to its parent whole-disk directory and read the flag there. That
/// matters for array members, which are often partition slices.
pub fn disk_is_rotational(device: &str) -> bool {
    let name = device.strip_prefix("/dev/").unwrap_or(device);
    // Whole disk (sda, nvme0n1): direct queue attribute.
    if let Ok(s) = std::fs::read_to_string(format!("/sys/block/{}/queue/rotational", name)) {
        return s.trim() == "1";
    }
    // Partition: /sys/class/block/<name> symlinks to …/block/<parent>/<name>;
    // the parent dir name is the whole disk that carries the queue attribute.
    if let Ok(target) = std::fs::read_link(format!("/sys/class/block/{}", name))
        && let Some(parent) = target.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str())
            && let Ok(s) = std::fs::read_to_string(format!("/sys/block/{}/queue/rotational", parent)) {
                return s.trim() == "1";
            }
    true
}

/// Full SMART health snapshot for one physical disk. Field names match the JSON
/// the Storage page's frontend already reads, so the same struct feeds both the
/// Storage UI and the Issues watcher — ONE definition of "failing", no drift.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DiskSmart {
    /// Vendor overall-health self-assessment (`smart_status.passed`).
    pub passed: Option<bool>,
    pub temperature_c: Option<i64>,
    pub power_on_hours: Option<u64>,
    /// ATA attr 5 — Reallocated Sector Count (raw).
    pub reallocated_sectors: Option<u64>,
    /// ATA attr 197 — Current Pending Sector Count (raw).
    pub pending_sectors: Option<u64>,
    /// ATA attr 198 — Offline Uncorrectable (raw).
    pub uncorrectable_sectors: Option<u64>,
    /// ATA attr 187 — Reported Uncorrectable Errors (raw).
    pub reported_uncorrectable: Option<u64>,
    /// ATA attr 177 / 233 — SSD wear-leveling / media-wearout indicator.
    pub wear_level: Option<u64>,
    pub total_written_sectors: Option<u64>,
    /// NVMe available_spare (normalised %, 0–100).
    pub nvme_spare_pct: Option<u64>,
    /// NVMe available_spare_threshold — spare below this = critical.
    pub nvme_spare_threshold: Option<u64>,
    /// NVMe percentage_used — endurance consumed (may exceed 100).
    pub nvme_pct_used: Option<u64>,
    /// NVMe media_and_data_integrity_errors (uncorrectable — data loss).
    pub nvme_media_errors: Option<u64>,
    /// NVMe SMART/Health `critical_warning` bitfield. The canonical NVMe
    /// failure flag — a drive can raise this without tripping the
    /// spare/endurance/media-error counters. Bits per Linux `nvme.h`
    /// NVME_SMART_CRIT_* / NVMe base spec: 0x01 available-spare below
    /// threshold, 0x02 temperature, 0x04 reliability degraded, 0x08 media
    /// read-only, 0x10 volatile-memory backup failed, 0x20 PMR read-only.
    pub nvme_critical_warning: Option<u64>,
}

impl DiskSmart {
    /// Why this disk counts as failing, grounded in Backblaze's large-scale
    /// study — the raw value of SMART 5 / 187 / 197 / 198 being > 0 is "a reason
    /// to investigate" and a strong failure predictor — plus the vendor
    /// overall-health verdict and the NVMe wear/spare signals. Empty = healthy.
    /// (188 Command-Timeout is deliberately excluded: it's cabling/power noise
    /// and the Storage page doesn't surface it.)
    pub fn failing_reasons(&self) -> Vec<String> {
        let mut r = Vec::new();
        if self.passed == Some(false) {
            r.push("SMART overall-health self-assessment reports FAILED".to_string());
        }
        if let Some(n) = self.reallocated_sectors.filter(|&n| n > 0) {
            r.push(format!("{} reallocated sector(s)", n));
        }
        if let Some(n) = self.pending_sectors.filter(|&n| n > 0) {
            r.push(format!("{} current-pending sector(s)", n));
        }
        if let Some(n) = self.uncorrectable_sectors.filter(|&n| n > 0) {
            r.push(format!("{} offline-uncorrectable sector(s)", n));
        }
        if let Some(n) = self.reported_uncorrectable.filter(|&n| n > 0) {
            r.push(format!("{} reported-uncorrectable error(s)", n));
        }
        if let (Some(spare), Some(thr)) = (self.nvme_spare_pct, self.nvme_spare_threshold) {
            // Spare below the drive's own threshold = critical wear-out.
            if thr > 0 && spare < thr {
                r.push(format!("NVMe available spare {}% below threshold {}%", spare, thr));
            }
        }
        if let Some(u) = self.nvme_pct_used.filter(|&u| u >= 100) {
            r.push(format!("NVMe endurance used {}% (rated life consumed)", u));
        }
        if let Some(e) = self.nvme_media_errors.filter(|&e| e > 0) {
            r.push(format!("{} NVMe media/data-integrity error(s)", e));
        }
        // NVMe critical_warning bitfield (Linux nvme.h NVME_SMART_CRIT_* /
        // NVMe base spec). Flag every hardware-failure bit but deliberately
        // EXCLUDE 0x02 temperature — an environmental, usually-transient
        // over/under-temp condition (a fanless mini-PC NVMe throttles, it isn't
        // dying), same spirit as excluding ATA 188 command-timeout above. Any
        // remaining bit = back up and replace the drive.
        if let Some(cw) = self.nvme_critical_warning {
            if cw & 0x01 != 0 { r.push("NVMe available spare below threshold (critical_warning 0x01)".to_string()); }
            if cw & 0x04 != 0 { r.push("NVMe reliability degraded (critical_warning 0x04)".to_string()); }
            if cw & 0x08 != 0 { r.push("NVMe media in read-only mode (critical_warning 0x08)".to_string()); }
            if cw & 0x10 != 0 { r.push("NVMe volatile-memory backup failed (critical_warning 0x10)".to_string()); }
            if cw & 0x20 != 0 { r.push("NVMe persistent-memory region read-only (critical_warning 0x20)".to_string()); }
        }
        r
    }
}

/// Read the full SMART attribute set for a device via `smartctl --json -H -A`.
/// `respect_standby` adds `-n standby` (ATA-only — smartmontools ignores it for
/// NVMe/SCSI) so a spun-down ATA disk is NOT woken. The Issues watcher passes
/// true (polls every 60s), the Storage view passes false. None when smartctl is
/// missing, the disk can't be read, or nothing parseable came back.
///
/// Tries smartctl's auto device-type detection first; if that yields nothing
/// parseable, retries once forcing SAT translation (`-d sat`). USB enclosures
/// frequently need that — without it smartctl emits only an error envelope and
/// the drive would be invisible to every health check. A readable disk parses on
/// the first attempt and never retries; a standby ATA disk (respect_standby) does
/// incur the second probe, but `-n standby` rides the SAT transport too so it
/// still isn't woken — just an extra fast-returning smartctl process.
pub fn disk_smart_health(device: &str, respect_standby: bool) -> Option<DiskSmart> {
    read_disk_smart(device, respect_standby, None)
        .or_else(|| read_disk_smart(device, respect_standby, Some("sat")))
}

/// One smartctl invocation with an optional explicit `-d <dev_type>`; parses the
/// JSON into a DiskSmart, or None if nothing usable came back. Split out so
/// `disk_smart_health` can fall back from auto-detection to `-d sat`.
fn read_disk_smart(device: &str, respect_standby: bool, dev_type: Option<&str>) -> Option<DiskSmart> {
    let mut args: Vec<&str> = vec!["10", "smartctl", "--json=c", "-H", "-A"];
    if respect_standby {
        args.push("-n");
        args.push("standby");
    }
    if let Some(t) = dev_type {
        args.push("-d");
        args.push(t);
    }
    args.push(device);
    let out = Command::new("timeout").args(&args).output().ok()?;
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;

    let attrs = json
        .get("ata_smart_attributes")
        .and_then(|a| a.get("table"))
        .and_then(|t| t.as_array());
    let find_attr = |id: u64| -> Option<u64> {
        attrs?
            .iter()
            .find(|a| a.get("id").and_then(|v| v.as_u64()) == Some(id))
            .and_then(|a| a.get("raw").and_then(|r| r.get("value")).and_then(|v| v.as_u64()))
    };

    let smart = DiskSmart {
        passed: json.pointer("/smart_status/passed").and_then(|v| v.as_bool()),
        temperature_c: json.pointer("/temperature/current").and_then(|v| v.as_i64()),
        power_on_hours: json.pointer("/power_on_time/hours").and_then(|v| v.as_u64()),
        reallocated_sectors: find_attr(5),
        pending_sectors: find_attr(197),
        uncorrectable_sectors: find_attr(198),
        reported_uncorrectable: find_attr(187),
        wear_level: find_attr(177).or_else(|| find_attr(233)),
        total_written_sectors: json
            .pointer("/ata_device_statistics/pages")
            .and_then(|p| p.as_array())
            .and_then(|pages| {
                pages
                    .iter()
                    .flat_map(|page| page.get("table").and_then(|t| t.as_array()).into_iter().flatten())
                    .find(|e| e.get("name").and_then(|n| n.as_str()) == Some("Logical Sectors Written"))
            })
            .and_then(|e| e.get("value").and_then(|v| v.as_u64())),
        nvme_spare_pct: json
            .pointer("/nvme_smart_health_information_log/available_spare")
            .and_then(|v| v.as_u64()),
        nvme_spare_threshold: json
            .pointer("/nvme_smart_health_information_log/available_spare_threshold")
            .and_then(|v| v.as_u64()),
        nvme_pct_used: json
            .pointer("/nvme_smart_health_information_log/percentage_used")
            .and_then(|v| v.as_u64()),
        nvme_media_errors: json
            .pointer("/nvme_smart_health_information_log/media_errors")
            .and_then(|v| v.as_u64()),
        nvme_critical_warning: json
            .pointer("/nvme_smart_health_information_log/critical_warning")
            .and_then(|v| v.as_u64()),
    };

    // Nothing parseable (disk in standby, or an unsupported device that emitted
    // only an error envelope) → None, so the caller skips rather than alerts —
    // and disk_smart_health then retries with `-d sat`.
    let empty = smart.passed.is_none()
        && attrs.is_none()
        && smart.nvme_spare_pct.is_none()
        && smart.nvme_spare_threshold.is_none()
        && smart.nvme_pct_used.is_none()
        && smart.nvme_media_errors.is_none()
        && smart.nvme_critical_warning.is_none();
    if empty {
        return None;
    }
    Some(smart)
}

// ─── Standby-aware health polling ───

/// A spun-down rotational disk cannot be read without waking it, so the Issues
/// watcher passes `respect_standby` and `read_disk_smart` returns `None` for
/// it. Correct per poll, wrong as a policy: on a host that spins disks down
/// aggressively (Unraid's array default) a drive can sit un-evaluated for its
/// whole life, accumulate reallocated/pending sectors and die with no alert
/// ever raised — while the Storage page shows it healthy, because that surface
/// reads with the guard OFF and wakes the disk (klas, 2026-07-31). So: never
/// wake a disk on the normal cadence, but guarantee every disk is genuinely
/// READ at least once a day.
const SMART_FORCE_AFTER_SECS: u64 = 86_400;

/// After this long with no successful read — including the forced one — the
/// disk is genuinely unmonitored and the operator has to be told, because on
/// every surface "no data" is indistinguishable from "healthy".
pub const SMART_UNREADABLE_ALERT_SECS: u64 = 7 * 86_400;

fn smart_state_path() -> PathBuf {
    PathBuf::from(crate::paths::get().config_dir.clone()).join("smart-state.json")
}

/// Last wall-clock second at which each device yielded a usable SMART read.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct SmartReadState {
    #[serde(default)]
    last_ok: std::collections::HashMap<String, u64>,
    /// device -> unix seconds at which we last *started* a self-test. A hard
    /// wall-clock floor for the scheduler, so a drive that reports no usable
    /// test timestamp still can't be re-tested on every tick.
    #[serde(default)]
    last_test_at: std::collections::HashMap<String, u64>,
    /// device -> how many scheduled tests we have started. Drives the
    /// every-Nth escalation to an extended test in the wear-out stage.
    #[serde(default)]
    test_count: std::collections::HashMap<String, u64>,
}

/// Persisted, not process-local: held only in memory, an agent restart would
/// re-seed every device and a node that restarts more often than weekly could
/// never reach the 24h forced-read or 7-day unreadable thresholds at all — the
/// exact node that most needs them.
fn smart_read_log() -> &'static std::sync::Mutex<SmartReadState> {
    static LAST_OK: std::sync::OnceLock<std::sync::Mutex<SmartReadState>> =
        std::sync::OnceLock::new();
    LAST_OK.get_or_init(|| {
        let loaded = std::fs::read_to_string(smart_state_path())
            .ok()
            .and_then(|s| serde_json::from_str::<SmartReadState>(&s).ok())
            .unwrap_or_default();
        std::sync::Mutex::new(loaded)
    })
}

/// Flush the read log, at most hourly. The thresholds it feeds are measured in
/// days, so an hourly write is ample and keeps a healthy node from rewriting
/// the file on every 60s poll.
fn persist_read_log(state: &SmartReadState, now: u64) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST_WRITE: AtomicU64 = AtomicU64::new(0);
    let prev = LAST_WRITE.load(Ordering::Relaxed);
    if now.saturating_sub(prev) < 3_600 {
        return;
    }
    if LAST_WRITE
        .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return; // another caller is writing this hour's copy
    }
    persist_read_log_now(state);
}

/// Unthrottled flush, for state we cannot afford to lose to the hourly window.
fn persist_read_log_now(state: &SmartReadState) {
    let Ok(json) = serde_json::to_string_pretty(state) else { return };
    let path = smart_state_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = crate::paths::write_secure(&path.to_string_lossy(), json) {
        tracing::warn!("could not persist SMART read state: {e}");
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Outcome of one watchdog poll of a device.
pub struct SmartCheck {
    /// The reading, when one could be taken on this poll.
    pub smart: Option<DiskSmart>,
    /// Seconds since this device last yielded a usable read (measured from
    /// first sighting until one succeeds). Drives the "unmonitored" alert.
    pub stale_secs: u64,
}

/// Poll one disk's health for the Issues watcher without breaking spin-down.
///
/// Solid-state devices have no spin state and are always read directly.
/// Rotational disks are read behind the `-n standby` guard, so a sleeping
/// drive is left alone — unless it has gone longer than
/// `SMART_FORCE_AFTER_SECS` without a successful read, in which case exactly
/// one guard-free read is taken. First sighting seeds the timer rather than
/// forcing, so a reboot never spins the whole array up at once.
pub fn disk_smart_health_watchdog(device: &str) -> SmartCheck {
    let now = now_secs();
    if !disk_is_rotational(device) {
        let smart = disk_smart_health(device, false);
        return finish_check(device, smart, now);
    }
    if let Some(smart) = disk_smart_health(device, true) {
        return finish_check(device, Some(smart), now);
    }
    // Asleep or unreadable. Force a read only when this disk is overdue one.
    let due = {
        let log = smart_read_log().lock().unwrap_or_else(|e| e.into_inner());
        log.last_ok
            .get(device)
            .map(|&last| now.saturating_sub(last) >= SMART_FORCE_AFTER_SECS)
            .unwrap_or(false)
    };
    if !due {
        return finish_check(device, None, now);
    }
    finish_check(device, disk_smart_health(device, false), now)
}

/// Record a successful read, or seed the timer on first sighting, and report
/// how stale this device's health data now is.
fn finish_check(device: &str, smart: Option<DiskSmart>, now: u64) -> SmartCheck {
    let mut log = smart_read_log().lock().unwrap_or_else(|e| e.into_inner());
    let last = if smart.is_some() {
        log.last_ok.insert(device.to_string(), now);
        now
    } else {
        *log.last_ok.entry(device.to_string()).or_insert(now)
    };
    persist_read_log(&log, now);
    SmartCheck { smart, stale_secs: now.saturating_sub(last) }
}

// ─── SMART short self-tests ───

/// Operator settings for scheduled SMART short self-tests.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SmartTestConfig {
    /// Master switch. On by default, which is safe because `allow_wake` is
    /// off: the scheduler then only tests disks that are already spinning, so
    /// a spun-down array pays nothing for having this enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Fixed cadence in days. 0 (the default) derives it from drive age.
    #[serde(default)]
    pub interval_days: u32,
    /// Devices never to test — e.g. drives behind enclosures that don't
    /// implement self-test and would just log a refusal every cycle.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Permit spinning a sleeping disk up in order to test it. Off by
    /// default: waking a whole array on a timer is precisely what operators
    /// spin their disks down to avoid.
    #[serde(default)]
    pub allow_wake: bool,
    /// Escalate to the *extended* self-test periodically once a drive reaches
    /// the wear-out end of the curve. A short test only samples the drive; the
    /// extended test scans the full surface, which is the deeper diagnostic
    /// worth paying for exactly when failure probability is climbing again
    /// (klas, 2026-07-31). Every 4th scheduled test becomes an extended one,
    /// so on the wear-out cadence that lands roughly monthly.
    #[serde(default = "default_true")]
    pub deep_test_in_wear_out: bool,
}

fn default_true() -> bool { true }

/// One in every N scheduled tests is the extended variant, for drives in the
/// wear-out stage. Four keeps the deep scan roughly monthly against the 7-day
/// wear-out cadence, without leaving an ageing drive scanning continuously.
const DEEP_TEST_EVERY: u64 = 4;

impl Default for SmartTestConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_days: 0,
            exclude: Vec::new(),
            allow_wake: false,
            deep_test_in_wear_out: true,
        }
    }
}

/// Test interval in hours, positioned on the drive-failure bathtub curve from
/// the drive's own power-on hours. Failure rate is elevated during infant
/// mortality and again during wear-out, and lowest across the flat middle, so
/// the cadence tightens at both ends instead of being uniform (klas,
/// 2026-07-31). Boundaries are 1 year (8760 h) and 4 years (35 040 h) of
/// powered life.
pub fn self_test_interval_hours(power_on_hours: Option<u64>, cfg: &SmartTestConfig) -> u64 {
    if cfg.interval_days > 0 {
        return cfg.interval_days as u64 * 24;
    }
    match power_on_hours {
        Some(h) if h < 8_760 => 7 * 24,   // infant mortality — watch closely
        Some(h) if h < 35_040 => 30 * 24, // constant-rate middle — relax
        Some(_) => 7 * 24,                // wear-out — watch closely again
        None => 14 * 24,                  // age unknown — split the difference
    }
}

/// Which segment of the bathtub curve a drive currently sits in. Presentation
/// only — the scheduler uses `self_test_interval_hours`.
pub fn life_stage(power_on_hours: Option<u64>) -> &'static str {
    match power_on_hours {
        Some(h) if h < 8_760 => "early-life",
        Some(h) if h < 35_040 => "steady-state",
        Some(_) => "wear-out",
        None => "unknown",
    }
}

/// Newest self-test outcome for a device.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SelfTestStatus {
    /// `Some(true)` passed, `Some(false)` failed, `None` when the newest entry
    /// was aborted/interrupted — genuinely unknown — or no test has ever run.
    pub passed: Option<bool>,
    /// smartctl's own wording for the newest entry.
    pub result: Option<String>,
    /// Drive power-on hours at which the newest test ran. The drive's own
    /// clock, so it survives reboots and agent restarts with no persistence.
    pub last_test_hours: Option<u64>,
    /// A self-test is running right now — never start a second one.
    pub in_progress: bool,
}

/// Read the self-test log. Mirrors `disk_smart_health`'s auto-detect →
/// `-d sat` fallback, since USB enclosures need the SAT transport here too.
pub fn self_test_status(device: &str) -> Option<SelfTestStatus> {
    read_self_test(device, None).or_else(|| read_self_test(device, Some("sat")))
}

fn read_self_test(device: &str, dev_type: Option<&str>) -> Option<SelfTestStatus> {
    let mut args: Vec<&str> = vec!["15", "smartctl", "--json=c", "-l", "selftest"];
    if let Some(t) = dev_type {
        args.push("-d");
        args.push(t);
    }
    args.push(device);
    let out = Command::new("timeout").args(&args).output().ok()?;
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;

    // NVMe — nvme_self_test_log.table[]. self_test_result.value 0x0 is a clean
    // pass; 0x5 (fatal/unknown error), 0x6 (unknown failed segment) and 0x7
    // (failed segments) are real failures; every other code is an abort and
    // must NOT be reported as failure. The table is written at the raw result
    // index, so it can be sparse — take the first populated entry, which is
    // the most recent per the NVMe log layout.
    // Source: smartmontools nvmeprint.cpp print_self_test_log().
    if let Some(log) = json.get("nvme_self_test_log") {
        let in_progress = log
            .pointer("/current_self_test_operation/value")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            != 0;
        let newest = log
            .get("table")
            .and_then(|t| t.as_array())
            .and_then(|t| t.iter().find(|e| e.get("self_test_result").is_some()));
        let (passed, result, hours) = match newest {
            Some(e) => (
                match e.pointer("/self_test_result/value").and_then(|v| v.as_u64()) {
                    Some(0x0) => Some(true),
                    Some(0x5) | Some(0x6) | Some(0x7) => Some(false),
                    _ => None,
                },
                e.pointer("/self_test_result/string").and_then(|v| v.as_str()).map(String::from),
                e.get("power_on_hours").and_then(|v| v.as_u64()),
            ),
            None => (None, None, None),
        };
        return Some(SelfTestStatus { passed, result, last_test_hours: hours, in_progress });
    }

    // ATA — ata_smart_self_test_log.standard.table[], newest first (it is
    // built in the same order smartctl prints, where "#1" is the most recent).
    // `status.passed` is emitted for every completed test and deliberately
    // OMITTED when the test was aborted or interrupted, so absence means
    // unknown, never failure. `status.remaining_percent` present = still running.
    // Source: smartmontools ataprint.cpp ataPrintSmartSelfTestEntry().
    let newest = json
        .pointer("/ata_smart_self_test_log/standard/table")
        .and_then(|t| t.as_array())
        .and_then(|t| t.iter().find(|e| e.get("status").is_some()));
    match newest {
        Some(e) => Some(SelfTestStatus {
            passed: e.pointer("/status/passed").and_then(|v| v.as_bool()),
            result: e.pointer("/status/string").and_then(|v| v.as_str()).map(String::from),
            last_test_hours: e.get("lifetime_hours").and_then(|v| v.as_u64()),
            in_progress: e.pointer("/status/remaining_percent").is_some(),
        }),
        // Log present but empty = "no self-tests have been logged", which is a
        // valid status (and means one is due), not a read error.
        None => json
            .pointer("/ata_smart_self_test_log/standard")
            .map(|_| SelfTestStatus::default()),
    }
}

/// Which self-test to run next on this device: `"long"` when the drive has
/// reached wear-out and this is its every-Nth scheduled test, `"short"`
/// otherwise. A short test samples; the extended test scans the whole surface.
pub fn next_self_test_kind(device: &str, power_on_hours: Option<u64>, cfg: &SmartTestConfig) -> &'static str {
    if !cfg.deep_test_in_wear_out || life_stage(power_on_hours) != "wear-out" {
        return "short";
    }
    let log = smart_read_log().lock().unwrap_or_else(|e| e.into_inner());
    let count = log.test_count.get(device).copied().unwrap_or(0);
    // Escalate on the Nth, N*2th, … so an ageing drive still gets short tests
    // in between rather than back-to-back full-surface scans.
    if count % DEEP_TEST_EVERY == DEEP_TEST_EVERY - 1 { "long" } else { "short" }
}

/// Start a SMART self-test (`kind` = `"short"` or `"long"`). Errors carry
/// smartctl's own last message so the operator sees why a drive refused
/// rather than a generic failure.
pub fn start_self_test(device: &str, kind: &str) -> Result<(), String> {
    // Only these two are accepted — never interpolate caller input into an
    // argv slot smartctl will interpret.
    let kind = match kind {
        "long" => "long",
        "short" => "short",
        other => return Err(format!("unsupported self-test type '{other}'")),
    };
    let out = Command::new("timeout")
        .args(["20", "smartctl", "-t", kind, device])
        .output()
        .map_err(|e| format!("could not run smartctl: {e}"))?;
    if out.status.success() {
        record_self_test_started(device);
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let text = if stderr.trim().is_empty() {
        String::from_utf8_lossy(&out.stdout).to_string()
    } else {
        stderr
    };
    Err(text
        .lines()
        .map(str::trim).rfind(|l| !l.is_empty())
        .unwrap_or("smartctl refused the self-test")
        .to_string())
}

/// Note that a test was started, for the scheduler's wall-clock floor and the
/// every-Nth extended-test escalation.
fn record_self_test_started(device: &str) {
    let now = now_secs();
    let mut log = smart_read_log().lock().unwrap_or_else(|e| e.into_inner());
    log.last_test_at.insert(device.to_string(), now);
    *log.test_count.entry(device.to_string()).or_insert(0) += 1;
    // Force the flush: losing this would let the scheduler re-test on the very
    // next tick, which for a drive reporting no test timestamp means hourly.
    persist_read_log_now(&log);
}

/// Whether `device` is due a scheduled short self-test.
///
/// Two independent brakes, because either signal alone has a hole: the drive's
/// own power-on-hours clock is authoritative when available, and a wall-clock
/// floor covers drives that report no usable test timestamp — without it, such
/// a drive would be re-tested on every scheduler tick.
pub fn self_test_due(
    device: &str,
    smart: &DiskSmart,
    status: &SelfTestStatus,
    cfg: &SmartTestConfig,
) -> bool {
    if !cfg.enabled || status.in_progress {
        return false;
    }
    if cfg.exclude.iter().any(|d| d == device) {
        return false;
    }
    let interval_h = self_test_interval_hours(smart.power_on_hours, cfg);
    {
        let log = smart_read_log().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&started) = log.last_test_at.get(device)
            && now_secs().saturating_sub(started) < interval_h * 3_600 {
                return false;
            }
    }
    match (smart.power_on_hours, status.last_test_hours) {
        (Some(current), Some(last)) => current.saturating_sub(last) >= interval_h,
        // Never tested, or no usable timestamp — establish a baseline. The
        // wall-clock floor above is what keeps this from firing repeatedly.
        _ => true,
    }
}

fn filesystem_used_bytes_for(device: &str) -> Option<u64> {
    // If the array's underlying device has a mounted filesystem,
    // report its `df` usage. Best-effort — not every array has one
    // (could be an LVM PV, a raw block target, etc.).
    let out = Command::new("df").args(["-Bk", "--output=used", device]).output().ok()?;
    if !out.status.success() { return None; }
    let s = String::from_utf8_lossy(&out.stdout);
    let used_kb: u64 = s.lines().nth(1)?.trim().trim_end_matches('K').parse().ok()?;
    Some(used_kb * 1024)
}

// ─── Predictive integration ───

/// Snapshot every array's state and emit predictive findings for any
/// unhappy condition. Called from the existing predictive
/// orchestrator on its 5-minute tick. Findings flow through the
/// existing alert channels (private — never the public status page).
#[allow(dead_code)]
pub fn predictive_findings() -> Vec<ArrayFinding> {
    let mut findings = Vec::new();
    for arr in list_arrays() {
        if arr.state == "degraded" {
            let missing: Vec<String> = arr.disks.iter()
                .filter(|d| d.state == "faulty" || d.state == "missing")
                .map(|d| d.device.clone()).collect();
            findings.push(ArrayFinding {
                array: arr.name.clone(),
                kind: "degraded".into(),
                severity: "critical".into(),
                detail: format!("array degraded — disks unhealthy: [{}]", missing.join(", ")),
            });
        }
        for d in &arr.disks {
            // Use the same full-attribute evaluator the Issues watcher / Storage
            // page use (Backblaze SMART 5/187/197/198, NVMe wear, overall-health)
            // rather than the overall-health-only `d.smart_status`, so this stays
            // consistent and doesn't silently under-alert if it's ever wired in.
            // Standby guard gated on rotational-ness, same as the Issues watcher:
            // an SSD/NVMe array member must always be read, never skipped because
            // its power-mode probe couldn't confirm an active state.
            if let Some(reasons) = disk_smart_health(&d.device, disk_is_rotational(&d.device))
                .map(|h| h.failing_reasons())
                .filter(|r| !r.is_empty())
            {
                findings.push(ArrayFinding {
                    array: arr.name.clone(),
                    kind: "smart_prefail".into(),
                    severity: "critical".into(),
                    detail: format!("disk {} is failing (SMART): {}", d.device, reasons.join("; ")),
                });
            }
        }
    }
    findings
}

#[derive(Debug, Clone, Serialize)]
pub struct ArrayFinding {
    pub array: String,
    pub kind: String,
    pub severity: String,
    pub detail: String,
}

// ─── Diagnostics ───
//
// When detection silently falls through to mdadm on a host where
// NoNRAID IS installed, the operator has no signal as to why. This
// captures every input the detector considers — and the raw inputs
// the parser sees — so the frontend can render an actionable
// "Detection report" instead of just "No arrays found".

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ArrayDiagnostics {
    /// What `detect_backend()` resolved to: "mdadm" or "nonraid".
    pub detected_backend: String,

    // ─── NoNRAID-specific signals ───
    /// Path to `nmdctl` if found (the modern NoNRAID userspace tool).
    pub nmdctl_path: Option<String>,
    /// Value of the WOLFSTACK_NMDCTL env override, if set.
    pub nmdctl_env_override: Option<String>,
    /// True if the env override pointed at a path that exists.
    pub nmdctl_env_override_exists: bool,
    /// True if `md_nonraid` (or alias `nonraid`, or `nonraid6_pq`) is
    /// loaded per /proc/modules or /sys/module/.
    pub nonraid_kernel_module_loaded: bool,
    /// `/proc/nmdstat` existence + size + first 4 KB of content.
    /// Present iff the md_nonraid module is registered. This is the
    /// AUTHORITATIVE NoNRAID status surface (cite:
    /// md_unraid.c:2229).
    pub procfs_nmdstat_present: bool,
    pub procfs_nmdstat_bytes: u64,
    pub procfs_nmdstat_head: String,

    // ─── Legacy Unraid / mdadm signals ───
    /// Path to legacy `mdcmd` if found (commercial Unraid only).
    pub mdcmd_path: Option<String>,
    /// Value of the WOLFSTACK_MDCMD env override, if set.
    pub mdcmd_env_override: Option<String>,
    pub mdcmd_env_override_exists: bool,
    /// Path to `mdadm` if found.
    pub mdadm_path: Option<String>,
    /// `/proc/mdstat` existence + content. For NoNRAID hosts this is
    /// typically just the "Personalities" header — the md_nonraid
    /// module doesn't write to it.
    pub procfs_mdstat_present: bool,
    pub procfs_mdstat_bytes: u64,
    pub procfs_mdstat_head: String,

    // ─── Environment ───
    /// Directories `which()` searched after $PATH.
    pub which_searched_dirs: Vec<String>,
    /// $PATH as seen by the wolfstack process (systemd-default usually).
    pub process_path_env: String,

    // ─── Verdict ───
    /// Count of arrays the parser actually found.
    pub parsed_array_count: usize,
    /// True if WOLFSTACK_ARRAY_DISABLE_NONRAID is forcing the
    /// mdadm path. Surfaced so the operator can see why detection
    /// went mdadm-only on a host that has NoNRAID signals.
    #[serde(default)]
    pub nonraid_disabled_by_env: bool,
    /// Human-readable suggestions, derived from the above signals.
    pub hints: Vec<String>,
}

/// Collect every signal the array detector relies on, plus the raw
/// content of both `/proc/mdstat` AND `/proc/nmdstat`. Cheap — only
/// read-only filesystem probes. Used by `GET /api/array/diagnose`
/// when the operator hits "Diagnose" in the UI.
pub fn diagnose() -> ArrayDiagnostics {
    // nmdctl signals
    let nmdctl_env = std::env::var("WOLFSTACK_NMDCTL").ok();
    let nmdctl_env_exists = nmdctl_env.as_deref()
        .map(|p| std::path::Path::new(p).exists())
        .unwrap_or(false);
    let nmdctl = nmdctl_path().map(|p| p.to_string_lossy().into_owned());

    // mdcmd (legacy Unraid) signals
    let mdcmd_env = std::env::var("WOLFSTACK_MDCMD").ok();
    let mdcmd_env_exists = mdcmd_env.as_deref()
        .map(|p| std::path::Path::new(p).exists())
        .unwrap_or(false);
    let mdcmd = legacy_mdcmd_path().map(|p| p.to_string_lossy().into_owned());

    let mdadm = which("mdadm").map(|p| p.to_string_lossy().into_owned());
    let nonraid_module = nonraid_module_loaded();

    let snapshot = |path: &str| -> (bool, u64, String) {
        match std::fs::read(path) {
            Ok(bytes) => {
                let total = bytes.len() as u64;
                let head = &bytes[..bytes.len().min(4096)];
                (true, total, String::from_utf8_lossy(head).into_owned())
            }
            Err(_) => (false, 0, String::new()),
        }
    };
    let (mdstat_present,  mdstat_bytes,  mdstat_head)  = snapshot("/proc/mdstat");
    let (nmdstat_present, nmdstat_bytes, nmdstat_head) = snapshot("/proc/nmdstat");

    let parsed_count = list_arrays().len();
    let backend = match detect_backend() {
        Backend::Mdadm => "mdadm",
        Backend::Nonraid => "nonraid",
        Backend::Unraid => "unraid",
    }.to_string();

    let nonraid_disabled = env_truthy("WOLFSTACK_ARRAY_DISABLE_NONRAID");
    let mut hints: Vec<String> = Vec::new();

    // ─── Hint logic ───
    // Order matters: most specific / most actionable hints first.

    if nonraid_disabled {
        hints.push(
            "WOLFSTACK_ARRAY_DISABLE_NONRAID is set — NoNRAID detection is forced off. \
             Unset the env var in /etc/systemd/system/wolfstack.service and restart \
             wolfstack to re-enable NoNRAID support.".into(),
        );
    }
    if backend == "nonraid" && nmdstat_present && parsed_count == 0 {
        // We CAN see /proc/nmdstat but it parsed empty. This means
        // either the array hasn't been imported / started yet, or
        // mdState is missing from the file.
        hints.push(
            "NoNRAID kernel module is loaded and /proc/nmdstat is present, but no array is \
             reported. The superblock may not be imported. Run `sudo nmdctl import` (then \
             `sudo nmdctl start` to bring it online). If this is a fresh install, see \
             https://github.com/qvr/nonraid for the create-array walkthrough.".into(),
        );
    }
    if backend == "unraid" && parsed_count == 0 {
        hints.push(
            "This is an Unraid host but no array is reported. If the array is stopped, start \
             it from the Unraid webGui (Main → Start). If it's running and still not shown \
             here, the /proc/mdstat snapshot below is what WolfStack parsed — send it to \
             support.".into(),
        );
    }
    if backend == "nonraid" && !nmdstat_present {
        hints.push(
            "Backend detected as NoNRAID but /proc/nmdstat is missing — the md_nonraid module \
             registers this file at load time. Try `sudo modprobe nonraid` and \
             verify with `lsmod | grep nonraid`.".into(),
        );
    }
    if nonraid_module && nmdctl.is_none() {
        hints.push(
            "The md_nonraid kernel module is loaded but the `nmdctl` userspace tool was not found. \
             Install nonraid-tools (Debian/Ubuntu: `sudo add-apt-repository ppa:qvr/nonraid && \
             sudo apt install nonraid-tools`; Arch: `yay -S nonraid-git`), or pin a custom path \
             via Environment=WOLFSTACK_NMDCTL=/full/path/to/nmdctl in \
             /etc/systemd/system/wolfstack.service.".into(),
        );
    }
    if !mdstat_present && !nmdstat_present {
        hints.push(
            "Neither /proc/mdstat nor /proc/nmdstat exists — no array kernel module is loaded. \
             For mdadm: `sudo modprobe md_mod`. For NoNRAID: `sudo modprobe nonraid`.".into(),
        );
    }
    if let Some(ref ev) = nmdctl_env
        && !nmdctl_env_exists {
            hints.push(format!(
                "WOLFSTACK_NMDCTL is set to '{}' but no file exists at that path.", ev
            ));
        }
    if let Some(ref ev) = mdcmd_env
        && !mdcmd_env_exists {
            hints.push(format!(
                "WOLFSTACK_MDCMD is set to '{}' but no file exists at that path.", ev
            ));
        }
    if backend == "mdadm" && nmdstat_present {
        // Shouldn't happen because detect_backend() prioritises
        // /proc/nmdstat, but if it does it's worth flagging.
        hints.push(
            "/proc/nmdstat exists but backend resolved to mdadm — likely a detection bug. \
             Please report with this diagnostic report attached.".into(),
        );
    }
    if hints.is_empty() && backend == "mdadm" && !nonraid_module && nmdctl.is_none() {
        hints.push(
            "No NoNRAID indicators found on this host — backend correctly resolved to mdadm.".into(),
        );
    }
    if hints.is_empty() && backend == "nonraid" && parsed_count > 0 {
        hints.push(format!(
            "NoNRAID backend working correctly — {} array reported.", parsed_count
        ));
    }

    ArrayDiagnostics {
        detected_backend: backend,
        nmdctl_path: nmdctl,
        nmdctl_env_override: nmdctl_env,
        nmdctl_env_override_exists: nmdctl_env_exists,
        nonraid_kernel_module_loaded: nonraid_module,
        procfs_nmdstat_present: nmdstat_present,
        procfs_nmdstat_bytes: nmdstat_bytes,
        procfs_nmdstat_head: nmdstat_head,
        mdcmd_path: mdcmd,
        mdcmd_env_override: mdcmd_env,
        mdcmd_env_override_exists: mdcmd_env_exists,
        mdadm_path: mdadm,
        procfs_mdstat_present: mdstat_present,
        procfs_mdstat_bytes: mdstat_bytes,
        procfs_mdstat_head: mdstat_head,
        which_searched_dirs: WHICH_FIXED_DIRS.iter().map(|s| s.to_string()).collect(),
        process_path_env: std::env::var("PATH").unwrap_or_default(),
        parsed_array_count: parsed_count,
        nonraid_disabled_by_env: nonraid_disabled,
        hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_arrays_returns_empty_on_no_mdstat() {
        // On a host without /proc/mdstat (most dev machines, this
        // CI runner, etc.), list_arrays returns Vec::new() rather
        // than panicking.
        let r = list_arrays();
        let _ = r.len(); // just exercising the path
    }

    #[test]
    fn parity_check_rejects_bad_action() {
        let err = parity_check("md0", "wipe").unwrap_err();
        assert!(matches!(err, ArrayError::CommandFailed(_)));
    }

    #[test]
    fn detect_backend_returns_a_value() {
        // Doesn't matter which; just must not panic on either path.
        let _ = detect_backend();
    }

    #[test]
    fn array_config_save_load_roundtrip() {
        let mut cfg = ArrayConfig::default();
        cfg.schedules.push(ParitySchedule {
            array: "md0".into(),
            cron: "0 3 * * 0".into(),
            action: "check".into(),
            enabled: true,
        });
        // We can't actually save in tests (root-owned config dir) but
        // we can verify the JSON shape round-trips.
        let json = serde_json::to_string(&cfg).unwrap();
        let back: ArrayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schedules.len(), 1);
        assert_eq!(back.schedules[0].array, "md0");
    }

    #[test]
    fn parse_mdstat_clean_raid1() {
        let sample = "Personalities : [raid1]\n\
            md0 : active raid1 sda1[0] sdb1[1]\n      \
            1953382464 blocks super 1.2 [2/2] [UU]\n      \
            bitmap: 0/15 pages [0KB], 65536KB chunk\n\n\
            unused devices: <none>\n";
        let arrays = parse_mdstat(sample, "mdadm");
        assert_eq!(arrays.len(), 1, "expected one array, got {:?}", arrays);
        let a = &arrays[0];
        assert_eq!(a.name, "md0");
        assert_eq!(a.level, "raid1");
        assert_eq!(a.state, "clean");
        assert_eq!(a.disks.len(), 2);
        assert_eq!(a.disks[0].device, "/dev/sda1");
        assert_eq!(a.disks[1].device, "/dev/sdb1");
        for d in &a.disks { assert_eq!(d.state, "in_sync"); }
    }

    #[test]
    fn parse_mdstat_inactive_array_does_not_steal_first_disk_as_level() {
        // Inactive arrays have no level word — the disk list comes
        // straight after "inactive". The bug being pinned: the
        // pre-fix parser advanced past "inactive" then called
        // parts.next() again expecting a level word, swallowing the
        // first disk as the level and leaving it out of the disk list.
        let sample = "Personalities : [raid1]\n\
            md0 : inactive sda1[0] sdb1[1]\n      \
            1953382464 blocks super 1.2\n\n\
            unused devices: <none>\n";
        let arrays = parse_mdstat(sample, "mdadm");
        assert_eq!(arrays.len(), 1);
        let a = &arrays[0];
        assert_eq!(a.state, "inactive");
        assert_eq!(a.level, "unknown", "inactive arrays have no level word");
        assert_eq!(a.disks.len(), 2, "first disk must not be consumed as level — got {:?}", a.disks);
        assert_eq!(a.disks[0].device, "/dev/sda1");
    }

    #[test]
    fn parse_mdstat_degraded_raid1() {
        let sample = "Personalities : [raid1]\n\
            md0 : active raid1 sda1[0] sdb1[1](F)\n      \
            1953382464 blocks super 1.2 [2/1] [U_]\n\n\
            unused devices: <none>\n";
        let arrays = parse_mdstat(sample, "mdadm");
        let a = &arrays[0];
        assert_eq!(a.state, "degraded");
        let faulty = a.disks.iter().find(|d| d.device == "/dev/sdb1").unwrap();
        assert_eq!(faulty.state, "faulty");
    }

    #[test]
    fn parse_mdstat_resyncing_progress_and_speed() {
        let sample = "Personalities : [raid1]\n\
            md0 : active raid1 sda1[0] sdb1[1]\n      \
            1953382464 blocks super 1.2 [2/2] [UU]\n      \
            [=>...................]  resync = 12.3% (240000/1953382464) finish=8.4min speed=234567K/sec\n\n\
            unused devices: <none>\n";
        let arrays = parse_mdstat(sample, "mdadm");
        let a = &arrays[0];
        assert_eq!(a.state, "resyncing");
        assert_eq!(a.sync_progress, Some(12));
        assert_eq!(a.sync_speed_kbs, Some(234567));
    }

    #[test]
    fn parse_mdstat_check_running() {
        let sample = "md0 : active raid5 sda1[0] sdb1[1] sdc1[2]\n      \
            3906764800 blocks super 1.2 level 5, 64k chunk, algorithm 2 [3/3] [UUU]\n      \
            [=>...................]  check =  5.7% (74203264/3906764800) finish=99.9min speed=614305K/sec\n\n";
        let arrays = parse_mdstat(sample, "mdadm");
        let a = &arrays[0];
        assert_eq!(a.state, "checking");
        assert_eq!(a.sync_progress, Some(5));
    }

    #[test]
    fn parse_mdstat_read_only_annotation_skipped() {
        // `active (read-only)` appears between state and level. The
        // parser must not consume "(read-only)" as the level word.
        let sample = "md0 : active (read-only) raid1 sda1[0] sdb1[1]\n      \
            1953382464 blocks super 1.2 [2/2] [UU]\n\n";
        let arrays = parse_mdstat(sample, "mdadm");
        assert_eq!(arrays[0].level, "raid1");
        assert_eq!(arrays[0].disks.len(), 2);
    }

    #[test]
    fn parse_mdstat_ignores_personalities_and_unused_lines() {
        let sample = "Personalities : [raid1] [raid6] [raid5] [raid4]\n\
            unused devices: <none>\n";
        let arrays = parse_mdstat(sample, "mdadm");
        assert!(arrays.is_empty());
    }

    #[test]
    fn parse_mdstat_handles_nvme_partition_names() {
        // NVMe devices use the `nvme0n1p1` naming convention. Make
        // sure looks_like_disk_token doesn't reject them.
        let sample = "md0 : active raid1 nvme0n1p1[0] nvme1n1p1[1]\n      \
            1953382464 blocks super 1.2 [2/2] [UU]\n\n";
        let arrays = parse_mdstat(sample, "mdadm");
        assert_eq!(arrays[0].disks.len(), 2);
        assert_eq!(arrays[0].disks[0].device, "/dev/nvme0n1p1");
    }

    #[test]
    fn parse_mdstat_reshape_in_progress_maps_to_reshaping_state() {
        // Reshape is a real mdadm state (e.g. RAID5 → RAID6 grow).
        // Must map to "reshaping" not the catch-all "resyncing".
        let sample = "md0 : active raid5 sda1[0] sdb1[1] sdc1[2] sdd1[3]\n      \
            5860528128 blocks super 1.2 level 5, 64k chunk, algorithm 2 [4/4] [UUUU]\n      \
            [==>..................]  reshape = 11.4% (333912448/2930264064) finish=156.4min speed=276544K/sec\n\n";
        let arrays = parse_mdstat(sample, "mdadm");
        assert_eq!(arrays[0].state, "reshaping");
        assert_eq!(arrays[0].sync_progress, Some(11));
    }

    #[test]
    fn parse_mdstat_auto_read_only_annotation() {
        // Kernel marks newly-assembled arrays as `(auto-read-only)`
        // until first write. Must skip the parens flag and pick raid1
        // as the level.
        let sample = "md0 : active (auto-read-only) raid1 sda1[0] sdb1[1]\n      \
            1953382464 blocks super 1.2 [2/2] [UU]\n\n";
        let arrays = parse_mdstat(sample, "mdadm");
        assert_eq!(arrays[0].level, "raid1");
        assert_eq!(arrays[0].disks.len(), 2);
    }

    #[test]
    fn looks_like_disk_token_rejects_non_disk_words() {
        // Negatives — these tokens appear in mdstat lines and must not
        // be interpreted as disks.
        for bad in ["active", "raid1", "(read-only)", "blocks", "[UU]", "5.7%"] {
            assert!(!looks_like_disk_token(bad), "should reject: {:?}", bad);
        }
        // Positives.
        for good in ["sda1[0]", "sdb1[1](F)", "nvme0n1p1[0]", "sdc1[2](S)"] {
            assert!(looks_like_disk_token(good), "should accept: {:?}", good);
        }
    }

    // ─── /proc/nmdstat (NoNRAID) parser tests ───
    //
    // Fixtures lifted from qvr/nonraid `tools/tests/test_nmdctl_basic.bats`
    // `create_mock_nmdstat()` (the project's own reference data). Keeping
    // the format verbatim — every byte of difference is a potential parse
    // miss in production.

    /// Fixture: 3-disk array, 1 parity + 2 data, all healthy, no
    /// resync activity. Matches upstream's create_mock_nmdstat with
    /// default args (state=STARTED, missing=0, invalid=0, resync=0).
    fn nmdstat_fixture_healthy() -> &'static str {
        "\
mdState=STARTED
mdNumDisks=3
sbName=/test.dat
sbLabel=MockArray
mdNumMissing=0
mdNumInvalid=0
mdNumWrong=0
mdNumDisabled=0
mdNumReplaced=0
mdNumNew=0
mdResync=0
mdResyncAction=check P
mdResyncCorr=0
mdResyncPos=0
mdResyncSize=0
mdResyncDt=10
mdResyncDb=5000
diskSize.0=2000000
diskSize.1=1000000
diskSize.2=1000000
diskSize.29=0
diskId.0=MOCK_PARITY_DISK
diskId.1=MOCK_DATA_DISK_1
diskId.2=MOCK_DATA_DISK_2
diskName.1=nmd1p1
diskName.2=nmd1p2
rdevName.0=sda1
rdevName.1=sdb1
rdevName.2=sdc1
rdevStatus.0=DISK_OK
rdevStatus.1=DISK_OK
rdevStatus.2=DISK_OK
rdevNumErrors.0=0
rdevNumErrors.1=0
rdevNumErrors.2=0
sbSynced=1700000000
sbSynced2=1700000000
sbSyncErrs=0
sbSyncExit=0
"
    }

    /// Fixture shaped like the REAL driver's output: md_status() loops
    /// 0..MD_SB_DISKS and prints every slot (md_unraid.c:1872-1877),
    /// so unused slots arrive as `rdevStatus.N=DISK_NP` with size 0
    /// and empty names — they are NOT omitted the way the nmdctl mock
    /// omits them. 1 parity + 2 data populated, slots 3..=29 empty.
    fn nmdstat_fixture_real_driver_started() -> String {
        let mut s = String::from(
            "\
sbName=/boot/config/super.dat
sbNumDisks=3
mdVersion=2.9.5
mdState=STARTED
mdNumDisks=3
mdNumMissing=0
mdResync=0
mdResyncPos=0
mdResyncSize=0
diskNumber.0=0
diskName.0=
diskSize.0=2000000
diskId.0=REAL_PARITY
rdevStatus.0=DISK_OK
rdevName.0=sdb
rdevSize.0=2000000
diskNumber.1=1
diskName.1=nmd1p1
diskSize.1=1000000
diskId.1=REAL_DATA_1
rdevStatus.1=DISK_OK
rdevName.1=sdc
rdevSize.1=1000000
diskNumber.2=2
diskName.2=nmd2p1
diskSize.2=1000000
diskId.2=REAL_DATA_2
rdevStatus.2=DISK_OK
rdevName.2=sdd
rdevSize.2=1000000
",
        );
        for n in 3..=29 {
            s.push_str(&format!(
                "diskNumber.{n}={n}\ndiskName.{n}=\ndiskSize.{n}=0\ndiskId.{n}=\n\
                 rdevStatus.{n}=DISK_NP\nrdevName.{n}=\nrdevSize.{n}=0\n"
            ));
        }
        s
    }

    #[test]
    fn parse_nmdstat_real_driver_output_skips_empty_slots_and_is_not_degraded() {
        // The klas bug (ninni, 2026-08-11): DISK_NP slots rendered as
        // phantom "missing" rows and any_missing forced a healthy
        // STARTED array to report "degraded".
        let arrs = parse_nmdstat(&nmdstat_fixture_real_driver_started());
        assert_eq!(arrs.len(), 1);
        let a = &arrs[0];
        assert_eq!(a.disks.len(), 3, "the 27 DISK_NP empty slots must not render as rows");
        assert_eq!(a.state, "active", "DISK_NP empty slots must not count as missing/degraded");
    }

    #[test]
    fn parse_nmdstat_stopped_empty_module_yields_no_arrays() {
        // Module loaded, superblock never imported: every slot is
        // DISK_NP / size 0, mdState=STOPPED. This must be "no arrays"
        // (the UI's empty state has the diagnose flow), not a stub
        // card of missing disks.
        let mut s = String::from("sbName=\nsbNumDisks=0\nmdState=STOPPED\nmdNumDisks=0\nmdResync=0\n");
        for n in 0..=29 {
            s.push_str(&format!(
                "diskNumber.{n}={n}\ndiskName.{n}=\ndiskSize.{n}=0\ndiskId.{n}=\n\
                 rdevStatus.{n}=DISK_NP\nrdevName.{n}=\nrdevSize.{n}=0\n"
            ));
        }
        assert!(parse_nmdstat(&s).is_empty(), "empty stopped module must yield zero arrays");
    }

    #[test]
    fn parse_nmdstat_started_array_with_truly_missing_disk_is_degraded() {
        // DISK_NP_MISSING ("enabled, but missing" — md_unraid.c:402)
        // is the REAL missing-disk state and must still degrade the
        // array — the DISK_NP fix must not swallow it.
        let fixture = "\
mdState=STARTED
sbNumDisks=3
mdNumMissing=1
mdResync=0
diskSize.0=2000000
rdevStatus.0=DISK_OK
rdevName.0=sdb
diskSize.1=1000000
diskId.1=GONE_DISK
rdevStatus.1=DISK_NP_MISSING
rdevName.1=
diskSize.2=1000000
rdevStatus.2=DISK_OK
rdevName.2=sdd
";
        let arrs = parse_nmdstat(fixture);
        assert_eq!(arrs.len(), 1);
        assert_eq!(arrs[0].state, "degraded");
        let missing: Vec<_> = arrs[0].disks.iter().filter(|d| d.state == "missing").collect();
        assert_eq!(missing.len(), 1, "exactly the DISK_NP_MISSING slot is missing");
        assert_eq!(missing[0].slot, Some(1));
    }

    #[test]
    fn parse_nmdstat_commercial_unraid_content_keeps_md_device_names() {
        // Commercial Unraid's driver prints diskName.N=md<N>p1 (the
        // fork's nmd naming is the fork's own rebrand patch). Virtual
        // device paths must come from the content, not a hardcoded
        // class prefix.
        let fixture = "\
mdState=STARTED
sbNumDisks=2
mdResync=0
diskSize.0=2000000
rdevStatus.0=DISK_OK
rdevName.0=sdb
diskSize.1=1000000
diskName.1=md1p1
rdevStatus.1=DISK_OK
rdevName.1=sdc
";
        let arrs = parse_nmdstat(fixture);
        assert_eq!(arrs.len(), 1);
        let data = arrs[0].disks.iter().find(|d| d.slot == Some(1)).unwrap();
        assert_eq!(data.virtual_device.as_deref(), Some("/dev/md1p1"));
    }

    #[test]
    fn parse_nmdstat_healthy_array_yields_one_started_array() {
        let arrs = parse_nmdstat(nmdstat_fixture_healthy());
        assert_eq!(arrs.len(), 1, "exactly one array per nonraid module-load");
        let a = &arrs[0];
        assert_eq!(a.name, "nmd");
        assert_eq!(a.level, "uraid");
        assert_eq!(a.backend, "nonraid");
        // mdState=STARTED + no missing + no resync → "active". sbState
        // not set in fixture so we don't roll up to "clean".
        assert_eq!(a.state, "active");
        assert!(a.sync_progress.is_none());
        assert!(a.sync_speed_kbs.is_none());
        // Three disks: slot 0 (P parity) + 1 + 2 (data). Slot 29
        // diskSize.29=0 with no rdevName.29 → must NOT produce a
        // phantom Q-parity disk row.
        assert_eq!(a.disks.len(), 3, "Q-parity placeholder must be skipped");
        // Total data bytes = sum of slots 1+2 sizes (each 1_000_000 KB).
        assert_eq!(a.size_bytes, 2_000_000 * 1024);
    }

    #[test]
    fn parse_nmdstat_slot_0_is_parity_29_is_parity2_others_data() {
        // Build a fixture that exercises slot 0, 1, 28, 29. The
        // critical assertion: slot 28 must be DATA, slot 29 must be
        // parity2. The old code had this backwards which would
        // mislabel a healthy data disk as a parity disk.
        let fixture = "\
mdState=STARTED
sbName=/test.dat
sbLabel=DualParity
mdNumDisks=4
mdNumMissing=0
mdResync=0
mdResyncSize=0
mdResyncPos=0
diskSize.0=4000000
diskSize.1=1000000
diskSize.28=1000000
diskSize.29=4000000
rdevName.0=sda1
rdevName.1=sdb1
rdevName.28=sdc1
rdevName.29=sdd1
rdevStatus.0=DISK_OK
rdevStatus.1=DISK_OK
rdevStatus.28=DISK_OK
rdevStatus.29=DISK_OK
";
        let arrs = parse_nmdstat(fixture);
        assert_eq!(arrs.len(), 1);
        let disks = &arrs[0].disks;
        // Sorted by slot ascending — index 0 of vec = slot 0 (P), then 1, 28, 29.
        let by_slot: std::collections::HashMap<u32, &Disk> =
            disks.iter().map(|d| (d.slot.unwrap(), d)).collect();

        assert_eq!(by_slot.get(&0).unwrap().role,  "parity",  "slot 0 must be P parity");
        assert_eq!(by_slot.get(&1).unwrap().role,  "data",    "slot 1 must be data");
        assert_eq!(by_slot.get(&28).unwrap().role, "data",    "slot 28 must be DATA (NOT parity2 — that was the bug)");
        assert_eq!(by_slot.get(&29).unwrap().role, "parity2", "slot 29 must be Q parity");
    }

    #[test]
    fn parse_nmdstat_check_running_yields_progress_and_speed() {
        // Same fixture but with resync active mid-check.
        let fixture = "\
mdState=STARTED
sbName=/test.dat
sbLabel=MockArray
mdNumDisks=3
mdNumMissing=0
mdResync=1
mdResyncAction=check P
mdResyncCorr=0
mdResyncPos=500000
mdResyncSize=1000000
mdResyncDt=10
mdResyncDb=80000
diskSize.0=2000000
diskSize.1=1000000
diskSize.2=1000000
rdevName.0=sda1
rdevName.1=sdb1
rdevName.2=sdc1
rdevStatus.0=DISK_OK
rdevStatus.1=DISK_OK
rdevStatus.2=DISK_OK
";
        let arrs = parse_nmdstat(fixture);
        assert_eq!(arrs.len(), 1);
        let a = &arrs[0];
        assert_eq!(a.state, "checking", "resync_active with check action → checking");
        // 500000 / 1000000 = 50%
        assert_eq!(a.sync_progress, Some(50));
        // 80000 KB / 10 ticks = 8000 KB/s
        assert_eq!(a.sync_speed_kbs, Some(8000));
    }

    #[test]
    fn parse_nmdstat_recon_action_yields_recovering_state() {
        let fixture = "\
mdState=STARTED
sbName=/test.dat
sbLabel=Recon
mdResync=1
mdResyncAction=recon P
mdResyncPos=100
mdResyncSize=1000
mdResyncDt=1
mdResyncDb=100
diskSize.0=2000000
diskSize.1=1000000
rdevName.0=sda1
rdevName.1=sdb1
rdevStatus.0=DISK_OK
rdevStatus.1=DISK_OK
";
        let a = &parse_nmdstat(fixture)[0];
        assert_eq!(a.state, "recovering");
    }

    #[test]
    fn parse_nmdstat_paused_check_detected_via_pos_without_active() {
        // Per docs/nmdstat.5: paused = mdResync=0 AND mdResyncPos > 0.
        let fixture = "\
mdState=STARTED
mdResync=0
mdResyncPos=300000
mdResyncSize=1000000
diskSize.0=2000000
diskSize.1=1000000
rdevName.0=sda1
rdevName.1=sdb1
rdevStatus.0=DISK_OK
rdevStatus.1=DISK_OK
";
        let a = &parse_nmdstat(fixture)[0];
        // State is "active" because no resync IS active, but
        // sync_progress should still report the paused position so the
        // UI can render it as "paused at 30%".
        assert_eq!(a.sync_progress, Some(30));
        assert_eq!(a.sync_speed_kbs, None, "paused = no speed");
    }

    #[test]
    fn parse_nmdstat_missing_disk_yields_degraded() {
        let fixture = "\
mdState=STARTED
mdNumDisks=3
mdNumMissing=1
mdResync=0
mdResyncSize=0
diskSize.0=2000000
diskSize.1=1000000
diskSize.2=1000000
rdevName.0=sda1
rdevName.1=sdb1
rdevName.2=
rdevStatus.0=DISK_OK
rdevStatus.1=DISK_OK
rdevStatus.2=DISK_NP_MISSING
";
        let a = &parse_nmdstat(fixture)[0];
        assert_eq!(a.state, "degraded");
        // Disk in slot 2 should be present in the list but with state=missing.
        let slot2 = a.disks.iter().find(|d| d.slot == Some(2)).expect("slot 2 must be in disk list");
        assert_eq!(slot2.state, "missing");
    }

    #[test]
    fn parse_nmdstat_stopped_array() {
        let fixture = "\
mdState=STOPPED
mdNumDisks=2
mdResync=0
mdResyncSize=0
diskSize.0=2000000
diskSize.1=1000000
rdevName.0=sda1
rdevName.1=sdb1
rdevStatus.0=DISK_OK
rdevStatus.1=DISK_OK
";
        let a = &parse_nmdstat(fixture)[0];
        assert_eq!(a.state, "stopped");
    }

    #[test]
    fn parse_nmdstat_no_mdstate_returns_empty() {
        // Module loaded but no array imported — file exists but is
        // empty / lacks mdState. Must NOT produce a phantom array.
        let arrs = parse_nmdstat("");
        assert!(arrs.is_empty());
        // Same when only sbName is present (a module-only state).
        let arrs = parse_nmdstat("sbName=\n");
        assert!(arrs.is_empty());
    }

    #[test]
    fn parse_nmdstat_clean_shutdown_promotes_active_to_clean() {
        let fixture = "\
mdState=STARTED
sbState=1
mdResync=0
mdResyncSize=0
diskSize.0=2000000
diskSize.1=1000000
rdevName.0=sda1
rdevName.1=sdb1
rdevStatus.0=DISK_OK
rdevStatus.1=DISK_OK
";
        assert_eq!(parse_nmdstat(fixture)[0].state, "clean");
    }

    #[test]
    fn parse_nmdstat_device_paths_get_dev_prefix() {
        let a = &parse_nmdstat(nmdstat_fixture_healthy())[0];
        for d in &a.disks {
            assert!(d.device.starts_with("/dev/"), "device must be absolute: {}", d.device);
        }
    }

    #[test]
    fn parse_nmdstat_serial_populated_from_diskid() {
        let a = &parse_nmdstat(nmdstat_fixture_healthy())[0];
        let parity = a.disks.iter().find(|d| d.slot == Some(0)).unwrap();
        assert_eq!(parity.serial.as_deref(), Some("MOCK_PARITY_DISK"));
    }

    #[test]
    fn parse_nmdstat_virtual_device_populated_for_data_slots() {
        // Fixture has diskName.1=nmd1p1 and diskName.2=nmd1p2.
        let a = &parse_nmdstat(nmdstat_fixture_healthy())[0];
        let slot1 = a.disks.iter().find(|d| d.slot == Some(1)).unwrap();
        let slot2 = a.disks.iter().find(|d| d.slot == Some(2)).unwrap();
        assert_eq!(slot1.virtual_device.as_deref(), Some("/dev/nmd1p1"));
        assert_eq!(slot2.virtual_device.as_deref(), Some("/dev/nmd1p2"));
        // Parity slot 0 has no diskName.0 in fixture → no virtual dev.
        let slot0 = a.disks.iter().find(|d| d.slot == Some(0)).unwrap();
        assert!(slot0.virtual_device.is_none(), "parity disk should have no virtual device");
    }

    // ─── /proc/mounts parser tests ───

    #[test]
    fn parse_proc_mounts_basic_lookup() {
        let sample = "\
/dev/sda1 / ext4 rw,relatime 0 0
/dev/nmd1p1 /mnt/disk1 xfs rw,relatime 0 0
/dev/nmd2p1 /mnt/disk2 xfs rw,relatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev 0 0
";
        let map = parse_proc_mounts(sample);
        assert_eq!(map.get("/dev/nmd1p1").map(String::as_str), Some("/mnt/disk1"));
        assert_eq!(map.get("/dev/nmd2p1").map(String::as_str), Some("/mnt/disk2"));
        assert_eq!(map.get("/dev/sda1").map(String::as_str), Some("/"));
    }

    #[test]
    fn parse_proc_mounts_handles_custom_prefix() {
        // Operator passed `nmdctl mount /custom/storage/disk` —
        // mountpoints don't start with /mnt/disk. The /proc/mounts
        // parser must NOT assume a path prefix.
        let sample = "\
/dev/nmd1p1 /custom/storage/disk1 xfs rw 0 0
/dev/nmd2p1 /custom/storage/disk2 xfs rw 0 0
";
        let map = parse_proc_mounts(sample);
        assert_eq!(map.get("/dev/nmd1p1").map(String::as_str), Some("/custom/storage/disk1"));
        assert_eq!(map.get("/dev/nmd2p1").map(String::as_str), Some("/custom/storage/disk2"));
    }

    #[test]
    fn parse_proc_mounts_handles_octal_escapes_in_path() {
        // Per fstab(5): spaces in mount paths are encoded as \040.
        let sample = "/dev/nmd1p1 /mnt/my\\040disk\\0401 xfs rw 0 0\n";
        let map = parse_proc_mounts(sample);
        assert_eq!(map.get("/dev/nmd1p1").map(String::as_str), Some("/mnt/my disk 1"));
    }

    #[test]
    fn decode_mount_escapes_passes_through_normal_paths() {
        assert_eq!(decode_mount_escapes("/mnt/disk1"), "/mnt/disk1");
        assert_eq!(decode_mount_escapes("/nfs/path with no escape"), "/nfs/path with no escape");
    }

    // Convenience: a disk is failing iff it has at least one reason.
    fn failing(s: &DiskSmart) -> bool { !s.failing_reasons().is_empty() }

    #[test]
    fn rotational_defaults_to_true_when_unreadable() {
        // A device with no /sys/block entry must default to rotational=true so
        // the SMART standby guard is kept (never wake an unknown disk on a
        // hunch). A real SSD/NVMe reads "0" from sysfs and is handled live.
        assert!(disk_is_rotational("/dev/definitely-not-a-real-disk-zzz"));
    }

    #[test]
    fn self_test_cadence_follows_the_bathtub_curve() {
        let cfg = SmartTestConfig::default();
        // Infant mortality and wear-out are the high-failure ends of the
        // curve, so both get the tight cadence; the flat middle relaxes.
        assert_eq!(self_test_interval_hours(Some(100), &cfg), 7 * 24);
        assert_eq!(self_test_interval_hours(Some(8_759), &cfg), 7 * 24);
        assert_eq!(self_test_interval_hours(Some(8_760), &cfg), 30 * 24);
        assert_eq!(self_test_interval_hours(Some(35_039), &cfg), 30 * 24);
        assert_eq!(self_test_interval_hours(Some(35_040), &cfg), 7 * 24);
        // Unknown age sits between the two rather than picking an extreme.
        assert_eq!(self_test_interval_hours(None, &cfg), 14 * 24);
        // An explicit interval overrides the curve entirely.
        let fixed = SmartTestConfig { interval_days: 3, ..Default::default() };
        assert_eq!(self_test_interval_hours(Some(100), &fixed), 72);
    }

    #[test]
    fn life_stage_labels_match_the_cadence_boundaries() {
        assert_eq!(life_stage(Some(0)), "early-life");
        assert_eq!(life_stage(Some(8_760)), "steady-state");
        assert_eq!(life_stage(Some(35_040)), "wear-out");
        assert_eq!(life_stage(None), "unknown");
    }

    #[test]
    fn self_test_is_not_due_when_disabled_excluded_or_already_running() {
        let smart = DiskSmart { power_on_hours: Some(50_000), ..Default::default() };
        let never_tested = SelfTestStatus::default();
        let dev = "/dev/zzz-due-probe";

        let off = SmartTestConfig { enabled: false, ..Default::default() };
        assert!(!self_test_due(dev, &smart, &never_tested, &off));

        let excluded = SmartTestConfig { exclude: vec![dev.to_string()], ..Default::default() };
        assert!(!self_test_due(dev, &smart, &never_tested, &excluded));

        // A test already running must never trigger a second one.
        let running = SelfTestStatus { in_progress: true, ..Default::default() };
        assert!(!self_test_due(dev, &smart, &running, &SmartTestConfig::default()));

        // Enabled, never tested, nothing running → due, so a fresh disk gets
        // a baseline rather than waiting a full interval for its first test.
        assert!(self_test_due(dev, &smart, &never_tested, &SmartTestConfig::default()));
    }

    #[test]
    fn self_test_due_respects_the_drive_own_hour_clock() {
        let cfg = SmartTestConfig::default();
        let dev = "/dev/zzz-clock-probe";
        // Steady-state drive (30-day cadence = 720 h) tested 100 powered hours
        // ago is not due; the same drive 800 hours on is.
        let smart = DiskSmart { power_on_hours: Some(20_000), ..Default::default() };
        let recent = SelfTestStatus { last_test_hours: Some(19_900), ..Default::default() };
        assert!(!self_test_due(dev, &smart, &recent, &cfg));
        let stale = SelfTestStatus { last_test_hours: Some(19_200), ..Default::default() };
        assert!(self_test_due(dev, &smart, &stale, &cfg));
    }

    #[test]
    fn deep_test_escalates_only_in_wear_out() {
        let cfg = SmartTestConfig::default();
        // Young and mid-life drives never escalate, whatever the count.
        assert_eq!(next_self_test_kind("/dev/zzz-kind-a", Some(1_000), &cfg), "short");
        assert_eq!(next_self_test_kind("/dev/zzz-kind-a", Some(20_000), &cfg), "short");
        // A wear-out drive with no history starts on short (count 0).
        assert_eq!(next_self_test_kind("/dev/zzz-kind-b", Some(40_000), &cfg), "short");
        // ...and escalates on the Nth.
        for _ in 0..(DEEP_TEST_EVERY - 1) {
            record_self_test_started("/dev/zzz-kind-b");
        }
        assert_eq!(next_self_test_kind("/dev/zzz-kind-b", Some(40_000), &cfg), "long");
        // Opting out keeps it on short even at wear-out.
        let no_deep = SmartTestConfig { deep_test_in_wear_out: false, ..Default::default() };
        assert_eq!(next_self_test_kind("/dev/zzz-kind-b", Some(40_000), &no_deep), "short");
    }

    #[test]
    fn smart_check_seeds_on_first_sighting_then_tracks_staleness() {
        // Unique device name: the read log is a process-global map shared by
        // every test in this binary.
        let dev = "/dev/zzz-staleness-probe";
        // First sighting of an unreadable (spun-down) disk seeds the timer
        // instead of counting as already-stale — that's what stops a reboot
        // from force-waking every disk in the array at once.
        let c = finish_check(dev, None, 1_000);
        assert!(c.smart.is_none());
        assert_eq!(c.stale_secs, 0);
        // Still unreadable an hour on: staleness runs from the seed.
        let c = finish_check(dev, None, 4_600);
        assert_eq!(c.stale_secs, 3_600);
        // A successful read clears it.
        let c = finish_check(dev, Some(DiskSmart::default()), 5_000);
        assert!(c.smart.is_some());
        assert_eq!(c.stale_secs, 0);
        // ...and staleness restarts from that read, not from first sighting.
        let c = finish_check(dev, None, 5_600);
        assert_eq!(c.stale_secs, 600);
    }

    #[test]
    fn disk_smart_healthy_is_not_failing() {
        let s = DiskSmart {
            passed: Some(true),
            temperature_c: Some(32),
            power_on_hours: Some(10_000),
            reallocated_sectors: Some(0),
            pending_sectors: Some(0),
            uncorrectable_sectors: Some(0),
            reported_uncorrectable: Some(0),
            ..Default::default()
        };
        assert!(!failing(&s));
        assert!(s.failing_reasons().is_empty());
    }

    #[test]
    fn disk_smart_overall_health_failed_is_failing() {
        let s = DiskSmart { passed: Some(false), ..Default::default() };
        assert!(failing(&s));
        assert!(s.failing_reasons()[0].contains("FAILED"));
    }

    #[test]
    fn disk_smart_passed_but_bad_attributes_is_failing() {
        // The RutgerDiehard case: vendor overall-health says PASSED, but the
        // Backblaze attributes (reallocated/pending) are non-zero → failing.
        // This is exactly what the Storage page reddens and Issues must mirror.
        let realloc = DiskSmart {
            passed: Some(true),
            reallocated_sectors: Some(24),
            ..Default::default()
        };
        assert!(failing(&realloc));
        assert!(realloc.failing_reasons().iter().any(|r| r.contains("reallocated")));

        let pending = DiskSmart { passed: Some(true), pending_sectors: Some(3), ..Default::default() };
        assert!(failing(&pending));

        let uncorr = DiskSmart { passed: Some(true), uncorrectable_sectors: Some(1), ..Default::default() };
        assert!(failing(&uncorr));

        let reported = DiskSmart { passed: Some(true), reported_uncorrectable: Some(2), ..Default::default() };
        assert!(failing(&reported));
    }

    #[test]
    fn disk_smart_nvme_wear_and_spare() {
        // Spare above threshold + healthy wear → fine.
        let ok = DiskSmart {
            passed: Some(true),
            nvme_spare_pct: Some(100),
            nvme_spare_threshold: Some(10),
            nvme_pct_used: Some(40),
            ..Default::default()
        };
        assert!(!failing(&ok));

        // Spare dropped below threshold → failing.
        let low_spare = DiskSmart {
            nvme_spare_pct: Some(5),
            nvme_spare_threshold: Some(10),
            ..Default::default()
        };
        assert!(failing(&low_spare));
        assert!(low_spare.failing_reasons().iter().any(|r| r.contains("spare")));

        // Endurance fully consumed → failing.
        let worn = DiskSmart { nvme_pct_used: Some(100), ..Default::default() };
        assert!(failing(&worn));

        // NVMe media/data-integrity errors → failing.
        let media = DiskSmart { nvme_media_errors: Some(1), ..Default::default() };
        assert!(failing(&media));
    }

    #[test]
    fn disk_smart_nvme_critical_warning() {
        // Bit positions per Linux nvme.h NVME_SMART_CRIT_* / NVMe base spec:
        // 0x01 spare-below-threshold, 0x02 temperature, 0x04 reliability,
        // 0x08 media read-only, 0x10 volatile-backup, 0x20 PMR read-only.

        // Healthy NVMe: critical_warning == 0 → not failing.
        let ok = DiskSmart { nvme_critical_warning: Some(0), ..Default::default() };
        assert!(!failing(&ok));

        // 0x01 available-spare below threshold (hardware wear-out) → failing.
        let spare = DiskSmart { nvme_critical_warning: Some(0x01), ..Default::default() };
        assert!(spare.failing_reasons().iter().any(|r| r.contains("spare")));

        // 0x04 reliability degraded → failing.
        let rel = DiskSmart { nvme_critical_warning: Some(0x04), ..Default::default() };
        assert!(rel.failing_reasons().iter().any(|r| r.contains("reliability")));

        // 0x08 media read-only → failing.
        let ro = DiskSmart { nvme_critical_warning: Some(0x08), ..Default::default() };
        assert!(ro.failing_reasons().iter().any(|r| r.contains("read-only")));

        // 0x02 temperature ALONE is environmental, not a hardware failure —
        // deliberately NOT flagged (avoids crying wolf on a hot fanless NVMe).
        // Same exclusion spirit as ATA 188 command-timeout.
        let temp = DiskSmart { nvme_critical_warning: Some(0x02), ..Default::default() };
        assert!(!failing(&temp));

        // Combined bitfield (temperature + reliability) → reliability still
        // flagged, temperature still ignored.
        let combo = DiskSmart { nvme_critical_warning: Some(0x02 | 0x04), ..Default::default() };
        let reasons = combo.failing_reasons();
        assert!(reasons.iter().any(|r| r.contains("reliability")));
        assert!(!reasons.iter().any(|r| r.contains("temperature")));
    }

    #[test]
    fn disk_smart_unknown_fields_are_not_failing() {
        // All-None (e.g. a disk we couldn't read attributes for) must NOT alert.
        let s = DiskSmart::default();
        assert!(!failing(&s));
    }
}

#[cfg(test)]
mod virtual_disk_filter_tests {
    use super::*;

    /// zram is the case that actually bit us: `lsblk -dnpo NAME,TYPE`
    /// reports it as type `disk`, so the old type-only filter handed it
    /// straight to smartctl. Conditional on the host actually having zram
    /// — skipping is honest, a fabricated pass is not.
    #[test]
    fn zram_is_not_treated_as_a_physical_disk() {
        if !std::path::Path::new("/sys/block/zram0").exists() {
            eprintln!("skipped: no zram device on this host");
            return;
        }
        assert!(
            !disk_has_backing_hardware("/dev/zram0"),
            "zram0 has no /sys/block/zram0/device link and must not be treated as hardware"
        );
        assert!(
            !list_physical_disks().iter().any(|d| d.contains("zram")),
            "list_physical_disks() must not return zram devices: {:?}",
            list_physical_disks()
        );
    }

    /// The filter must not throw the real disks out with the virtual ones.
    /// Every device the kernel exposes with a `device` link is hardware we
    /// genuinely want SMART data for.
    #[test]
    fn real_disks_survive_the_filter() {
        let Ok(entries) = std::fs::read_dir("/sys/block") else {
            eprintln!("skipped: /sys/block unreadable");
            return;
        };
        let mut hardware_backed = Vec::new();
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if e.path().join("device").exists() {
                hardware_backed.push(name);
            }
        }
        if hardware_backed.is_empty() {
            eprintln!("skipped: no hardware-backed block devices visible");
            return;
        }
        for name in &hardware_backed {
            assert!(
                disk_has_backing_hardware(&format!("/dev/{name}")),
                "{name} is hardware-backed in /sys but the filter rejected it"
            );
        }
    }

    #[test]
    fn accepts_bare_names_and_dev_paths_alike() {
        // Callers pass /dev/-prefixed paths; the sysfs lookup needs the bare
        // name. Both spellings must agree or the filter silently drops disks.
        let Ok(entries) = std::fs::read_dir("/sys/block") else { return };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            assert_eq!(
                disk_has_backing_hardware(&name),
                disk_has_backing_hardware(&format!("/dev/{name}")),
                "bare vs /dev/ disagreement for {name}"
            );
        }
    }
}
