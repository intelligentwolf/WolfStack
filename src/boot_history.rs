// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Boot history — "what was in the log before the crash?" (klas 2026-11-05).
//!
//! journald keeps every boot's log separately when its storage is
//! persistent, so after a crash the previous boot's final lines are
//! `journalctl -b -1`. This module provides:
//! - [`list_boots`]: the recorded boots with first/last log time and whether
//!   a clean shutdown was logged — the last log time of a boot with no
//!   shutdown logged is, to within a few seconds, when the box died;
//! - [`journal_status`] / [`enable_persistent_journal`]: whether journald is
//!   writing to disk at all (volatile journals lose every boot but the
//!   current one, and with it exactly the crash evidence), and a fix;
//! - [`list_pstore`] / [`read_pstore_file`]: kernel panic / oops dumps the
//!   firmware preserved across the reset (the kernel usually cannot write a
//!   panic to the journal, but pstore survives the reboot).
//!
//! Every value parsed here comes from `journalctl -o json` (field names are
//! journald's own `_BOOT_ID`, `__REALTIME_TIMESTAMP` in microseconds) or the
//! `--list-boots` JSON (`index`, `boot_id`, `first_entry`, `last_entry`,
//! microseconds) — verified against systemd 262 output.

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

/// systemd catalog `98268866d1d54a499c4e98921d93bc40` — "System shutdown
/// initiated" (systemd.catalog; logged by systemd-logind
/// `bus_manager_log_shutdown` with a SHUTDOWN=reboot|poweroff|… field).
const SHUTDOWN_MESSAGE_ID: &str = "98268866d1d54a499c4e98921d93bc40";

/// Boots returned at most — the UI lists recent history, not years.
const MAX_BOOTS: usize = 30;

/// Where journald writes its system journal when storage is persistent.
const PERSISTENT_JOURNAL_DIR: &str = "/var/log/journal";

/// Drop-in WolfStack writes to turn persistent storage on.
const PERSIST_DROPIN_DIR: &str = "/etc/systemd/journald.conf.d";
const PERSIST_DROPIN_FILE: &str = "/etc/systemd/journald.conf.d/50-wolfstack-persistent.conf";

/// pstore locations: the live pstore filesystem, and where systemd-pstore
/// archives entries on boot (it empties /sys/fs/pstore into here).
const PSTORE_ROOTS: [&str; 2] = ["/var/lib/systemd/pstore", "/sys/fs/pstore"];
/// Max bytes returned when viewing one pstore file.
const PSTORE_READ_MAX: u64 = 512 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct BootEntry {
    /// journalctl's relative index: 0 = current boot, -1 = previous, …
    pub index: i64,
    pub boot_id: String,
    /// Unix seconds of the first / last journal entry in this boot.
    pub first_entry: Option<u64>,
    pub last_entry: Option<u64>,
    /// Some(true) = a shutdown was logged for this boot; Some(false) = none
    /// logged (crash, power loss, hard reset, or a forced reboot that skips
    /// logind); None = can't tell (current boot, or this host never logs the
    /// shutdown message so its absence means nothing).
    pub clean_shutdown: Option<bool>,
    /// The logged SHUTDOWN= kind ("reboot", "poweroff", …) when clean.
    pub shutdown_kind: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JournalStatus {
    /// journalctl present and answering (systemd host).
    pub journald: bool,
    /// journald currently writes its system journal to /var/log/journal.
    pub persistent: bool,
    /// WolfStack's persistence drop-in is installed.
    pub wolfstack_dropin: bool,
    pub unraid: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BootReport {
    pub status: JournalStatus,
    pub boots: Vec<BootEntry>,
    /// Set when the boot list could not be read (shown to the operator).
    pub error: Option<String>,
}

fn machine_id() -> Option<String> {
    let id = std::fs::read_to_string("/etc/machine-id").ok()?;
    let id = id.trim();
    (id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit())).then(|| id.to_string())
}

fn journalctl_available() -> bool {
    Command::new("journalctl").arg("--version")
        .stdout(Stdio::null()).stderr(Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
}

/// Ground truth, not config parsing: journald's active system journal file
/// is `<dir>/<machine-id>/system.journal`, so persistence is whether that file
/// exists under /var/log/journal. (Storage=auto + a missing /var/log/journal,
/// Storage=volatile, or a drop-in elsewhere all show up here as "not
/// persistent" without us having to re-implement journald's config merge.)
pub fn journal_status() -> JournalStatus {
    let journald = journalctl_available();
    let persistent = machine_id()
        .map(|mid| std::path::Path::new(PERSISTENT_JOURNAL_DIR).join(&mid).join("system.journal").exists())
        .unwrap_or(false);
    JournalStatus {
        journald,
        persistent,
        wolfstack_dropin: std::path::Path::new(PERSIST_DROPIN_FILE).exists(),
        unraid: crate::installer::unraid_tools::is_unraid(),
    }
}

fn usec_to_secs(v: &serde_json::Value) -> Option<u64> {
    // journald emits __REALTIME_TIMESTAMP as a decimal STRING in entry JSON,
    // and --list-boots emits first_entry/last_entry as JSON numbers.
    match v {
        serde_json::Value::Number(n) => n.as_u64().map(|u| u / 1_000_000),
        serde_json::Value::String(s) => s.parse::<u64>().ok().map(|u| u / 1_000_000),
        _ => None,
    }
}

fn is_boot_id(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate a boot selector from the API: a 32-hex boot id or a relative
/// index in -999..=0. Returns the argument to hand to `journalctl -b`.
pub fn validate_boot_selector(s: &str) -> Option<String> {
    let s = s.trim();
    if is_boot_id(s) { return Some(s.to_ascii_lowercase()); }
    match s.parse::<i64>() {
        Ok(i) if (-999..=0).contains(&i) => Some(i.to_string()),
        _ => None,
    }
}

/// `journalctl --list-boots -o json`. Older systemd ignores `-o` for
/// --list-boots and prints text, so on a JSON parse failure fall back to the
/// text listing for index + boot id only (their first two columns on every
/// version) and fetch the timestamps per boot from entry JSON.
fn raw_boot_list() -> Result<Vec<BootEntry>, String> {
    let out = Command::new("journalctl")
        .args(["--list-boots", "--no-pager", "-o", "json"])
        .output()
        .map_err(|e| format!("journalctl: {}", e))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if err.is_empty() { "journalctl --list-boots failed".into() } else { err });
    }
    let text = String::from_utf8_lossy(&out.stdout);
    if let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(text.trim()) {
        let mut boots: Vec<BootEntry> = items.iter().filter_map(|b| {
            let boot_id = b.get("boot_id")?.as_str()?.to_string();
            if !is_boot_id(&boot_id) { return None; }
            Some(BootEntry {
                index: b.get("index")?.as_i64()?,
                boot_id,
                first_entry: b.get("first_entry").and_then(usec_to_secs),
                last_entry: b.get("last_entry").and_then(usec_to_secs),
                clean_shutdown: None,
                shutdown_kind: None,
            })
        }).collect();
        boots.sort_by_key(|b| std::cmp::Reverse(b.index));
        boots.truncate(MAX_BOOTS);
        return Ok(boots);
    }
    // Text fallback: "<index> <boot_id> <first…> <last…>" (newer systemd
    // adds an "IDX BOOT ID …" header line, which fails the parse and is
    // skipped).
    let mut boots: Vec<BootEntry> = text.lines().filter_map(|l| {
        let mut it = l.split_whitespace();
        let index = it.next()?.parse::<i64>().ok()?;
        let boot_id = it.next()?.to_string();
        is_boot_id(&boot_id).then_some(BootEntry {
            index, boot_id, first_entry: None, last_entry: None,
            clean_shutdown: None, shutdown_kind: None,
        })
    }).collect();
    boots.sort_by_key(|b| std::cmp::Reverse(b.index));
    boots.truncate(MAX_BOOTS);
    for b in &mut boots {
        b.last_entry = boot_edge_timestamp(&b.boot_id, true);
        b.first_entry = boot_edge_timestamp(&b.boot_id, false);
    }
    Ok(boots)
}

/// First or last entry time of one boot from entry JSON. `last`: `-n 1`
/// (the newest entry). First: stream the boot oldest-first and stop after
/// the first line, so we never read a whole boot's journal.
fn boot_edge_timestamp(boot_id: &str, last: bool) -> Option<u64> {
    let mut cmd = Command::new("journalctl");
    cmd.args(["-b", boot_id, "-o", "json", "--no-pager"]);
    if last { cmd.args(["-n", "1"]); }
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let mut line = String::new();
    let read = child.stdout.take().map(|s| BufReader::new(s).read_line(&mut line));
    let _ = child.kill();
    let _ = child.wait();
    read?.ok()?;
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    v.get("__REALTIME_TIMESTAMP").and_then(usec_to_secs)
}

/// boot_id → logged SHUTDOWN kind, for every boot that logged a shutdown.
fn shutdown_markers() -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(o) = Command::new("journalctl")
        .args([&format!("MESSAGE_ID={}", SHUTDOWN_MESSAGE_ID), "-o", "json", "--no-pager"])
        .output() else { return out; };
    if !o.status.success() { return out; }
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let Some(id) = v.get("_BOOT_ID").and_then(|x| x.as_str()) else { continue };
        let kind = v.get("SHUTDOWN").and_then(|x| x.as_str()).unwrap_or("").to_string();
        out.insert(id.to_string(), kind);
    }
    out
}

/// Fill `clean_shutdown` from the logged shutdown markers. A verdict is only
/// given when this host has logged the marker at least once — otherwise its
/// systemd may simply not emit it and "none logged" would be a false alarm.
fn apply_shutdown_markers(boots: &mut [BootEntry], markers: &HashMap<String, String>) {
    let ids: HashSet<&str> = boots.iter().map(|b| b.boot_id.as_str()).collect();
    let host_logs_marker = markers.keys().any(|k| ids.contains(k.as_str()));
    for b in boots.iter_mut() {
        if b.index == 0 { continue; } // still running
        match markers.get(&b.boot_id) {
            Some(kind) => {
                b.clean_shutdown = Some(true);
                if !kind.is_empty() { b.shutdown_kind = Some(kind.clone()); }
            }
            None if host_logs_marker => b.clean_shutdown = Some(false),
            None => {}
        }
    }
}

pub fn list_boots() -> BootReport {
    let status = journal_status();
    if !status.journald {
        return BootReport {
            error: Some(if status.unraid {
                "This server has no systemd journal (Unraid keeps its syslog in RAM, so it is lost on every reboot). To keep logs across a crash, turn on the syslog server's 'mirror syslog to flash' option or send syslog to another server in Unraid's Syslog Server settings.".into()
            } else {
                "This server has no systemd journal (journalctl not found), so logs from earlier boots are not available.".into()
            }),
            status,
            boots: vec![],
        };
    }
    match raw_boot_list() {
        Ok(mut boots) => {
            apply_shutdown_markers(&mut boots, &shutdown_markers());
            BootReport { status, boots, error: None }
        }
        Err(e) => BootReport { status, boots: vec![], error: Some(e) },
    }
}

/// Install the persistence drop-in, restart journald and flush the runtime
/// journal to disk, then report the resulting state.
pub fn enable_persistent_journal() -> Result<JournalStatus, String> {
    if !journalctl_available() {
        return Err("This server has no systemd journal (journalctl not found).".into());
    }
    std::fs::create_dir_all(PERSIST_DROPIN_DIR)
        .map_err(|e| format!("create {}: {}", PERSIST_DROPIN_DIR, e))?;
    std::fs::write(PERSIST_DROPIN_FILE,
        "# Written by WolfStack: keep the system journal on disk so the logs\n\
         # from before a crash or reboot survive (journalctl -b -1).\n\
         [Journal]\nStorage=persistent\n")
        .map_err(|e| format!("write {}: {}", PERSIST_DROPIN_FILE, e))?;
    let restart = Command::new("systemctl").args(["restart", "systemd-journald"]).output()
        .map_err(|e| format!("systemctl: {}", e))?;
    if !restart.status.success() {
        return Err(format!("Restarting systemd-journald failed: {}",
            String::from_utf8_lossy(&restart.stderr).trim()));
    }
    // Move what is in /run/log/journal (this boot so far) onto disk.
    let _ = Command::new("journalctl").arg("--flush").output();
    let status = journal_status();
    if !status.persistent {
        return Err(format!(
            "The setting was written to {} and journald restarted, but it is still not writing to {}. Another journald setting is overriding it — check `systemd-analyze cat-config systemd/journald.conf` for a later Storage= line.",
            PERSIST_DROPIN_FILE, PERSISTENT_JOURNAL_DIR));
    }
    Ok(status)
}

#[derive(Debug, Clone, Serialize)]
pub struct PstoreFile {
    pub path: String,
    pub size: u64,
    pub modified: Option<u64>,
}

/// Files under the pstore roots (one directory level deep — systemd-pstore
/// archives into `<root>/<timestamp>/`). Missing/unreadable roots are skipped.
pub fn list_pstore() -> Vec<PstoreFile> {
    let mut out = Vec::new();
    for root in PSTORE_ROOTS {
        let Ok(rd) = std::fs::read_dir(root) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if let Ok(inner) = std::fs::read_dir(&p) {
                    for f in inner.flatten() { push_pstore(&mut out, &f.path()); }
                }
            } else {
                push_pstore(&mut out, &p);
            }
        }
    }
    out.sort_by_key(|f| std::cmp::Reverse(f.modified));
    out
}

fn push_pstore(out: &mut Vec<PstoreFile>, p: &std::path::Path) {
    let Ok(md) = std::fs::metadata(p) else { return };
    if !md.is_file() { return; }
    out.push(PstoreFile {
        path: p.to_string_lossy().into_owned(),
        size: md.len(),
        modified: md.modified().ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs()),
    });
}

/// Read one pstore file as text, bounded. The path must resolve (after
/// symlinks) inside a pstore root — this is not a general file reader.
pub fn read_pstore_file(path: &str) -> Result<(String, bool), String> {
    use std::io::Read;
    let canon = std::fs::canonicalize(path).map_err(|_| "File not found".to_string())?;
    let allowed = PSTORE_ROOTS.iter().any(|r| {
        std::fs::canonicalize(r).map(|root| canon.starts_with(root)).unwrap_or(false)
    });
    if !allowed { return Err("Not a pstore file".into()); }
    let f = std::fs::File::open(&canon).map_err(|e| format!("open: {}", e))?;
    let mut buf = Vec::new();
    f.take(PSTORE_READ_MAX + 1).read_to_end(&mut buf).map_err(|e| format!("read: {}", e))?;
    let truncated = buf.len() as u64 > PSTORE_READ_MAX;
    buf.truncate(PSTORE_READ_MAX as usize);
    Ok((String::from_utf8_lossy(&buf).into_owned(), truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot(index: i64, id: &str) -> BootEntry {
        BootEntry { index, boot_id: id.into(), first_entry: None, last_entry: None, clean_shutdown: None, shutdown_kind: None }
    }

    #[test]
    fn selector_validation() {
        assert_eq!(validate_boot_selector("-1"), Some("-1".into()));
        assert_eq!(validate_boot_selector("0"), Some("0".into()));
        assert_eq!(validate_boot_selector("1"), None);
        assert_eq!(validate_boot_selector("-1000"), None);
        assert_eq!(validate_boot_selector("317bfce06b2e4a658f3a0ff1c50be60f"), Some("317bfce06b2e4a658f3a0ff1c50be60f".into()));
        assert_eq!(validate_boot_selector("--since=x"), None);
        assert_eq!(validate_boot_selector("317bfce06b2e4a658f3a0ff1c50be60g"), None);
    }

    #[test]
    fn usec_parsing_both_shapes() {
        assert_eq!(usec_to_secs(&serde_json::json!(1789505311455258u64)), Some(1789505311));
        assert_eq!(usec_to_secs(&serde_json::json!("1789505311455258")), Some(1789505311));
        assert_eq!(usec_to_secs(&serde_json::json!(null)), None);
    }

    #[test]
    fn shutdown_verdicts() {
        let a = "a".repeat(32); let b = "b".repeat(32); let c = "c".repeat(32);
        let mut boots = vec![boot(0, &c), boot(-1, &b), boot(-2, &a)];
        let mut m = HashMap::new();
        m.insert(a.clone(), "reboot".to_string());
        apply_shutdown_markers(&mut boots, &m);
        assert_eq!(boots[0].clean_shutdown, None);           // current boot
        assert_eq!(boots[1].clean_shutdown, Some(false));    // crashed
        assert_eq!(boots[2].clean_shutdown, Some(true));
        assert_eq!(boots[2].shutdown_kind.as_deref(), Some("reboot"));
    }

    #[test]
    fn no_verdict_when_host_never_logs_marker() {
        let a = "a".repeat(32); let b = "b".repeat(32);
        let mut boots = vec![boot(0, &b), boot(-1, &a)];
        apply_shutdown_markers(&mut boots, &HashMap::new());
        assert_eq!(boots[1].clean_shutdown, None);
    }
}
