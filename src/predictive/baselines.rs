// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Per-host security baselines.
//!
//! A *baseline* is the SHA-256 of a sensitive file's content at the
//! moment WolfStack first observed it. Subsequent ticks compute the
//! current SHA-256 and compare. A mismatch means the file changed
//! since baseline — which is either operator-intended (in which
//! case the operator runs `/api/predictive/baselines/reseed/<name>`)
//! or the work of an attacker (in which case it's a finding).
//!
//! The cluster-replicated tamper-protection analyzers (sshd_config,
//! authorized_keys, sudoers, passwd, fail2ban) all share this layer.
//!
//! ## Design rules
//!
//! * **Auto-seed on first run.** The very first sample on a host
//!   captures the *current* state as the baseline. This prevents
//!   false-positive alerts on a fresh install: "wolfstack just got
//!   installed and now claims sshd_config is tampered" would be
//!   incorrect. The trade-off is that if WolfStack is installed on
//!   an already-compromised box, the compromise gets baselined —
//!   but the per-attack-pattern detectors in
//!   `compromise_indicators` still fire on the obvious IoCs
//!   (locker binary, root shell hijack, masked services) regardless
//!   of baseline state.
//!
//! * **Stored on disk under `/var/lib/wolfstack/baselines/`.**
//!   Persistent across reboots and process restarts. JSON file per
//!   baselined path holding the SHA-256 plus a "captured at"
//!   timestamp, and a `<slug>.content` companion holding the exact
//!   bytes at seed time (`save_with_content`) — without those bytes
//!   tamper detection could only DETECT drift, never revert it. Both
//!   are mode 0600.
//!
//! * **Operator can reseed.** When the operator legitimately changes
//!   `/etc/ssh/sshd_config`, they hit the "Reseed baseline" button
//!   in the inbox card or call the API. The reseed records WHO
//!   triggered it and WHEN, so the audit trail stays honest.
//!
//! * **Per-host, NOT cluster-replicated.** Two reasons. First,
//!   Proxmox hosts and WolfStack natives legitimately differ in
//!   their default sshd_config. Second, cluster gossip could itself
//!   be the attack vector — pushing a poisoned baseline to peers
//!   would defeat the protection. Each node observes itself.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Where per-file baselines live on disk. One JSON file per baselined
/// path, named by a safe slug derived from the path. The env var
/// override is for tests so we never touch the real /var/lib state.
pub fn baselines_dir() -> PathBuf {
    if let Ok(p) = std::env::var("WOLFSTACK_BASELINES_DIR") {
        return PathBuf::from(p);
    }
    PathBuf::from("/var/lib/wolfstack/baselines")
}

/// On-disk record. JSON-serialized to `<baselines_dir>/<slug>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// The path this baseline tracks. Stored even though it's also
    /// implied by the filename, so an operator inspecting the dir
    /// can read the JSON directly without slug-decoding.
    pub path: String,
    /// Lowercase hex SHA-256 of the file's contents at seed time.
    pub sha256: String,
    /// File size in bytes — a cheap pre-check before computing SHA
    /// when comparing. If size differs, content differs.
    pub size: u64,
    /// Unix-epoch seconds when the baseline was first established.
    pub seeded_at: u64,
    /// Who triggered the seed. "auto" for first-run auto-seed,
    /// otherwise a user identifier from the API endpoint.
    pub seeded_by: String,
    /// Free-text reason, when reseeded via the API. Empty for the
    /// initial auto-seed.
    pub reason: String,
}

/// Comparison verdict between a current file state and its
/// recorded baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The file's SHA-256 matches the baseline. No tampering.
    Match,
    /// The file's SHA-256 differs from the baseline. Tamper indicator.
    /// Includes both hashes so the proposal can show them side-by-side.
    Drift {
        current_sha256: String,
        baseline_sha256: String,
    },
    /// File exists but baseline doesn't yet. Caller should auto-seed
    /// (first-observation case) — not a finding.
    NoBaseline,
    /// Baseline says file existed at seed time but it's gone now.
    /// This is also tampering — the attacker deleted the file (e.g.
    /// removed a `[sshd] enabled` jail.local stanza by deleting the
    /// whole file).
    FileMissing { baseline_sha256: String },
    /// Couldn't read the file (permission, transient). Sample
    /// should treat as "unknown", not "tampered".
    ReadError(String),
}

/// Compute SHA-256 of file contents + size. Returns None on read
/// error so callers can map to `Verdict::ReadError`.
fn hash_and_size(path: &str) -> Option<(String, u64)> {
    let bytes = std::fs::read(path).ok()?;
    let size = bytes.len() as u64;
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&bytes);
    Some((format!("{:x}", h.finalize()), size))
}

/// Path → safe slug. Replaces `/` with `__` and strips a leading
/// underscore, so `/etc/ssh/sshd_config` becomes
/// `etc__ssh__sshd_config`. Deterministic round-trip is not required
/// (the Baseline JSON carries the original path).
pub fn slug_for(path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    trimmed.replace('/', "__").replace(' ', "_")
}

fn baseline_file_for(path: &str) -> PathBuf {
    baselines_dir().join(format!("{}.json", slug_for(path)))
}

/// Load the baseline for a path, if any. None when no baseline has
/// been seeded yet (first-observation case).
pub fn load(path: &str) -> Option<Baseline> {
    let bp = baseline_file_for(path);
    let body = std::fs::read_to_string(&bp).ok()?;
    serde_json::from_str(&body).ok()
}

/// Save (or replace) a baseline for `path` with the given hash + size.
/// Writes atomically via a tmp-file + rename. Creates the baselines
/// directory if missing. Also saves a `.content` companion file with
/// the file's actual bytes at seed time — used by the tamper-
/// detection restore path. Without that snapshot we can only DETECT
/// drift, not REVERT it.
pub fn save_with_content(b: &Baseline, content: &[u8]) -> Result<(), String> {
    let dir = baselines_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return Err(format!("create {:?}: {}", dir, e));
    }
    let final_path = baseline_file_for(&b.path);
    let tmp = final_path.with_extension("json.tmp");
    let body = serde_json::to_string_pretty(b)
        .map_err(|e| format!("serialize: {}", e))?;
    std::fs::write(&tmp, &body).map_err(|e| format!("write {:?}: {}", tmp, e))?;
    // 0o600 so only root can read — baselines themselves are not
    // secrets but they reveal which files we're watching, which is
    // useful intel for an attacker.
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    std::fs::rename(&tmp, &final_path).map_err(|e| format!("rename: {}", e))?;
    // Content snapshot. Atomic via tmp + rename. Same 0o600 perm —
    // contains potentially sensitive material (sshd_config,
    // authorized_keys, sudoers).
    let content_path = dir.join(format!("{}.content", slug_for(&b.path)));
    let content_tmp = content_path.with_extension("content.tmp");
    std::fs::write(&content_tmp, content)
        .map_err(|e| format!("write content {:?}: {}", content_tmp, e))?;
    let _ = std::fs::set_permissions(&content_tmp, std::fs::Permissions::from_mode(0o600));
    std::fs::rename(&content_tmp, &content_path)
        .map_err(|e| format!("rename content: {}", e))?;
    Ok(())
}

/// Save a baseline metadata record only (no content snapshot). Used
/// in tests and for upgrade paths from versions that didn't store
/// content. Production code should call `save_with_content`.
#[allow(dead_code)]
pub fn save(b: &Baseline) -> Result<(), String> {
    let dir = baselines_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return Err(format!("create {:?}: {}", dir, e));
    }
    let final_path = baseline_file_for(&b.path);
    let tmp = final_path.with_extension("json.tmp");
    let body = serde_json::to_string_pretty(b)
        .map_err(|e| format!("serialize: {}", e))?;
    std::fs::write(&tmp, &body).map_err(|e| format!("write {:?}: {}", tmp, e))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    std::fs::rename(&tmp, &final_path).map_err(|e| format!("rename: {}", e))?;
    Ok(())
}

/// Auto-seed a baseline from the current state of `path` AND save
/// the content snapshot so the tamper-detection restore path can
/// actually revert drift. Caller should only invoke this when
/// `load(path)` returned None (the "first observation" path) —
/// calling it on an existing baseline would silently overwrite,
/// which is what `reseed` is for.
pub fn auto_seed(path: &str) -> Option<Baseline> {
    let bytes = std::fs::read(path).ok()?;
    let size = bytes.len() as u64;
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&bytes);
    let sha = format!("{:x}", h.finalize());
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    let b = Baseline {
        path: path.to_string(),
        sha256: sha,
        size,
        seeded_at: now,
        seeded_by: "auto".to_string(),
        reason: String::new(),
    };
    if save_with_content(&b, &bytes).is_err() { return None; }
    Some(b)
}

/// Path of the one-shot marker recording that tamper detection has
/// already auto-restored `path` from the current baseline anchor.
fn autofix_marker_for(path: &str) -> PathBuf {
    baselines_dir().join(format!("{}.autofixed", slug_for(path)))
}

/// True when tamper detection has already auto-restored `path` since
/// the baseline was last seeded.
///
/// Auto-restore is deliberately ONE-SHOT per baseline anchor. The
/// first time a security-critical file drifts we revert it — that
/// undoes an attacker's edit without waiting for a human to read the
/// inbox. If the same file drifts *again* we detect and alert but do
/// NOT revert, because a second drift after a revert is nearly always
/// intentional (an operator re-adding the SSH key we just deleted),
/// and reverting on every 5-minute tick fights that operator forever
/// with no way out. It buys little against a real attacker either: a
/// root-level intruder can re-apply the change, stop WolfStack, or
/// rewrite the baseline snapshot outright. Detection and alerting is
/// the durable protection; the destructive revert is a one-time
/// courtesy.
///
/// `reseed` clears the marker — re-anchoring is the operator saying
/// "this content is correct now", which re-arms one-shot protection
/// against the *next* change.
pub fn autofix_already_applied(path: &str) -> bool {
    autofix_marker_for(path).exists()
}

/// Record that we auto-restored `path`, disarming further automatic
/// restores of it until the baseline is reseeded. Best-effort: if the
/// marker can't be written we log and carry on — the cost is that the
/// next tick may restore once more, which is the pre-existing
/// behaviour, not a new failure mode.
pub fn record_autofix(path: &str) {
    let dir = baselines_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!("baselines: create {:?} for autofix marker: {}", dir, e);
        return;
    }
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    let marker = autofix_marker_for(path);
    match std::fs::write(&marker, format!("{}\n", ts)) {
        Ok(()) => {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600));
        }
        Err(e) => tracing::warn!("baselines: write autofix marker {:?}: {}", marker, e),
    }
}

/// Clear the one-shot auto-restore marker for `path`. Called by
/// `reseed` so an intentional re-anchor re-arms auto-restore.
pub fn clear_autofix(path: &str) {
    let marker = autofix_marker_for(path);
    match std::fs::remove_file(&marker) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!("baselines: remove autofix marker {:?}: {}", marker, e),
    }
}

/// Drop the baseline, content snapshot and auto-restore marker for
/// `path` — accepting that an operator deliberately deleted the file.
/// The next scan re-seeds it if the file ever comes back.
pub fn forget(path: &str) -> Result<(), String> {
    let slug = slug_for(path);
    let dir = baselines_dir();
    for f in [format!("{}.json", slug), format!("{}.content", slug), format!("{}.autofixed", slug)] {
        match std::fs::remove_file(dir.join(&f)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("remove baseline {}: {}", f, e)),
        }
    }
    Ok(())
}

/// Re-seed an existing baseline because the operator made an
/// intentional change. Captures the new content snapshot so future
/// restores use the corrected version. Records who and why for the
/// audit trail. Also re-arms one-shot auto-restore (see
/// `autofix_already_applied`).
pub fn reseed(path: &str, by: &str, reason: &str) -> Result<Baseline, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("read {}: {}", path, e))?;
    let size = bytes.len() as u64;
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&bytes);
    let sha = format!("{:x}", h.finalize());
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    let b = Baseline {
        path: path.to_string(),
        sha256: sha,
        size,
        seeded_at: now,
        seeded_by: by.to_string(),
        reason: reason.to_string(),
    };
    save_with_content(&b, &bytes)?;
    clear_autofix(path);
    Ok(b)
}

/// Compare `path`'s current state against its baseline. Auto-seeds
/// when no baseline exists and returns `NoBaseline` so callers know
/// to skip alerting on first observation.
pub fn check(path: &str) -> Verdict {
    let existing = load(path);
    let cur = hash_and_size(path);

    match (existing, cur) {
        (Some(b), Some((cur_sha, _cur_size))) => {
            if cur_sha == b.sha256 {
                Verdict::Match
            } else {
                Verdict::Drift {
                    current_sha256: cur_sha,
                    baseline_sha256: b.sha256,
                }
            }
        }
        (Some(b), None) => Verdict::FileMissing { baseline_sha256: b.sha256 },
        (None, Some(_)) => {
            // Auto-seed on first observation. Operator can reseed
            // later via API if they didn't want this exact moment
            // to be the baseline. The first-observation file
            // contents are saved on disk anyway (this is the box's
            // current /etc/passwd, /etc/sudoers, etc.).
            let _ = auto_seed(path);
            Verdict::NoBaseline
        }
        (None, None) => {
            // File doesn't exist AND we have no baseline. Not a
            // finding — the file simply isn't present on this host
            // (e.g. /etc/fail2ban/jail.local on a host without
            // fail2ban installed).
            Verdict::ReadError("file not present and no baseline".into())
        }
    }
}

/// Capture the file's CURRENT content to the forensics directory
/// before any restore operation. Returns the path on success. We
/// keep BOTH the current (suspected-tampered) version AND the file
/// the restore writes back — the audit trail then shows exactly
/// what changed.
pub fn capture_current(path: &str, forensics_subdir: &str) -> Result<String, String> {
    let dir = std::path::Path::new("/var/lib/wolfstack/forensics").join(forensics_subdir);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return Err(format!("create {:?}: {}", dir, e));
    }
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    let captured = dir.join(format!("{}-{}.captured", slug_for(path), ts));
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;
    std::fs::write(&captured, &bytes).map_err(|e| format!("write {:?}: {}", captured, e))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&captured, std::fs::Permissions::from_mode(0o400));
    Ok(captured.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize the baselines-tests because they all share one
    /// process-wide env var (WOLFSTACK_BASELINES_DIR). Without this,
    /// `cargo test` parallel scheduling lets one test wipe the env
    /// var while another is mid-call and the path collapses back to
    /// `/var/lib/wolfstack/baselines` (permission-denied in CI /
    /// developer machines).
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn temp_root() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wolfstack-baselines-test-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn slug_replaces_slashes() {
        assert_eq!(slug_for("/etc/ssh/sshd_config"), "etc__ssh__sshd_config");
        assert_eq!(slug_for("etc/passwd"), "etc__passwd");
        assert_eq!(slug_for("/"), "");
    }

    #[test]
    fn auto_seed_then_match() {
        let _g = TEST_LOCK.lock().unwrap();
        let root = temp_root();
        let baselines = root.join("baselines");
        let target = root.join("target.txt");
        std::fs::write(&target, b"hello\n").unwrap();

        unsafe { std::env::set_var("WOLFSTACK_BASELINES_DIR", &baselines); }
        let target_str = target.to_string_lossy().into_owned();

        // First check → no baseline yet, auto-seeds.
        let v = check(&target_str);
        assert_eq!(v, Verdict::NoBaseline);

        // Second check on unchanged file → Match.
        let v = check(&target_str);
        assert_eq!(v, Verdict::Match);

        unsafe { std::env::remove_var("WOLFSTACK_BASELINES_DIR"); }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn drift_detected_after_modification() {
        let _g = TEST_LOCK.lock().unwrap();
        let root = temp_root();
        let baselines = root.join("baselines");
        let target = root.join("target.txt");
        std::fs::write(&target, b"original\n").unwrap();

        unsafe { std::env::set_var("WOLFSTACK_BASELINES_DIR", &baselines); }
        let target_str = target.to_string_lossy().into_owned();

        // Seed.
        check(&target_str);

        // Modify.
        std::fs::write(&target, b"TAMPERED\n").unwrap();

        // Should detect drift.
        let v = check(&target_str);
        match v {
            Verdict::Drift { current_sha256, baseline_sha256 } => {
                assert_ne!(current_sha256, baseline_sha256);
            }
            other => panic!("expected Drift, got {:?}", other),
        }

        unsafe { std::env::remove_var("WOLFSTACK_BASELINES_DIR"); }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn file_missing_after_baseline() {
        let _g = TEST_LOCK.lock().unwrap();
        let root = temp_root();
        let baselines = root.join("baselines");
        let target = root.join("target.txt");
        std::fs::write(&target, b"will be deleted\n").unwrap();

        unsafe { std::env::set_var("WOLFSTACK_BASELINES_DIR", &baselines); }
        let target_str = target.to_string_lossy().into_owned();

        check(&target_str); // seed
        std::fs::remove_file(&target).unwrap();

        let v = check(&target_str);
        assert!(matches!(v, Verdict::FileMissing { .. }));

        unsafe { std::env::remove_var("WOLFSTACK_BASELINES_DIR"); }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reseed_updates_baseline() {
        let _g = TEST_LOCK.lock().unwrap();
        let root = temp_root();
        let baselines = root.join("baselines");
        let target = root.join("target.txt");
        std::fs::write(&target, b"v1\n").unwrap();

        unsafe { std::env::set_var("WOLFSTACK_BASELINES_DIR", &baselines); }
        let target_str = target.to_string_lossy().into_owned();

        check(&target_str); // seed v1
        std::fs::write(&target, b"v2\n").unwrap();
        // Without reseed: drift.
        assert!(matches!(check(&target_str), Verdict::Drift { .. }));

        let b = reseed(&target_str, "operator", "intentional change").unwrap();
        assert_eq!(b.seeded_by, "operator");
        assert_eq!(b.reason, "intentional change");

        // After reseed: match.
        assert_eq!(check(&target_str), Verdict::Match);

        unsafe { std::env::remove_var("WOLFSTACK_BASELINES_DIR"); }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The one-shot auto-restore latch: set once we've reverted a
    /// file, cleared when the operator re-anchors the baseline. This
    /// is what stops tamper detection reverting an operator's change
    /// on every 5-minute tick forever.
    #[test]
    fn autofix_marker_is_one_shot_and_reseed_rearms_it() {
        let _g = TEST_LOCK.lock().unwrap();
        let root = temp_root();
        let baselines = root.join("baselines");
        let target = root.join("target.txt");
        std::fs::write(&target, b"v1\n").unwrap();

        unsafe { std::env::set_var("WOLFSTACK_BASELINES_DIR", &baselines); }
        let target_str = target.to_string_lossy().into_owned();

        check(&target_str); // seed v1
        assert!(!autofix_already_applied(&target_str),
            "a freshly seeded baseline has not auto-restored anything yet");

        // Pretend tamper detection reverted it once.
        record_autofix(&target_str);
        assert!(autofix_already_applied(&target_str),
            "after one auto-restore the latch must hold off further reverts");

        // Reseeding is the operator accepting the current content —
        // it re-arms one-shot protection for the NEXT change.
        std::fs::write(&target, b"v2\n").unwrap();
        reseed(&target_str, "operator", "intentional change").unwrap();
        assert!(!autofix_already_applied(&target_str),
            "reseed must clear the latch or auto-restore never fires again");

        // Clearing an already-clear latch is not an error.
        clear_autofix(&target_str);
        assert!(!autofix_already_applied(&target_str));

        unsafe { std::env::remove_var("WOLFSTACK_BASELINES_DIR"); }
        let _ = std::fs::remove_dir_all(&root);
    }
}
