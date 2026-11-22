// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! New SSH keys authorised in a container, or for a non-root account on
//! the host.
//!
//! The kit added its own key (`root@localhost`) to the container's
//! `/root/.ssh/authorized_keys` on 2026-11-16 — a door that stays open
//! after every password is rotated. The host's root key file is already
//! baselined by `predictive::tamper_detection`; this covers every
//! account in every running container, and the host's other accounts.
//!
//! ## Baseline
//!
//! The first time a target is seen its current keys are recorded
//! silently — WolfStack cannot know which of a pre-existing install's
//! keys are legitimate, and alarming on all of them would teach the
//! operator to dismiss the card. From then on, any key not in the
//! baseline is a finding, Critical, until the operator either removes
//! the key (the card resolves) or dismisses the card (the key is then
//! folded into the baseline as trusted — see [`fold_trusted`]).
//!
//! The known operator key of the 2026-11-16 kit is reported even on
//! first sight: an infected container must not be baselined clean.
//!
//! What a key IS, and its fingerprint, come from [`crate::ssh_keys`] —
//! the single definition the host key manager and tamper detection
//! share. Certificate and options-carrying lines are outside that
//! definition and are tracked as raw lines, as tamper detection does.

use super::rootfs::RootFs;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// One authorised entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    /// Account name.
    pub user: String,
    /// Target-absolute file the entry is in.
    pub file: String,
    /// Stable id: `key:<sha256-hex of blob>` or `line:<sha256-hex of line>`.
    pub id: String,
    /// Display text: type, short fingerprint, comment.
    pub summary: String,
    /// The decoded key blob (base64) for plain keys.
    pub blob: Option<String>,
}

fn entry_for(user: &str, file: &str, line: &str) -> Option<KeyEntry> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') { return None; }
    Some(match crate::ssh_keys::parse_line(t) {
        Some(k) => {
            let fp = k.fingerprint();
            KeyEntry {
                user: user.into(),
                file: file.into(),
                id: format!("key:{}", fp),
                summary: format!("{} sha256:{} {}", k.key_type, crate::ssh_keys::short_fp(&fp),
                    if k.comment.is_empty() { "(no comment)" } else { k.comment.as_str() }),
                blob: Some(k.blob),
            }
        }
        None => KeyEntry {
            user: user.into(),
            file: file.into(),
            id: format!("line:{}", super::sysfiles::sha256_hex(t.as_bytes())),
            // Options-carrying lines can be long (command="…"); show the head.
            summary: format!("non-plain entry: {}", t.chars().take(120).collect::<String>()),
            blob: None,
        },
    })
}

/// Parse an authorized_keys body into entries.
pub fn parse_file(user: &str, file: &str, body: &str) -> Vec<KeyEntry> {
    body.lines().filter_map(|l| entry_for(user, file, l)).collect()
}

/// Expand sshd's AuthorizedKeysFile tokens (sshd_config(5): `%h` home,
/// `%u` user, `%%` literal; relative paths are relative to the home).
pub fn expand_keys_file(pattern: &str, user: &str, home: &str) -> String {
    let mut out = String::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.next() {
                Some('h') => out.push_str(home),
                Some('u') => out.push_str(user),
                Some('%') => out.push('%'),
                Some(o) => { out.push('%'); out.push(o); }
                None => out.push('%'),
            }
        } else {
            out.push(c);
        }
    }
    if out.starts_with('/') { out } else { format!("{}/{}", home.trim_end_matches('/'), out) }
}

/// Split an sshd_config line into (keyword, value). sshd_config(5):
/// keyword and arguments separated by whitespace or an optional `=`.
fn sshd_kv(line: &str) -> Option<(&str, &str)> {
    let l = line.trim();
    if l.is_empty() || l.starts_with('#') { return None; }
    let i = l.find(|c: char| c.is_whitespace() || c == '=')?;
    let v = l[i..].trim_start_matches(|c: char| c.is_whitespace() || c == '=');
    Some((&l[..i], v.trim()))
}

/// Expand an sshd `Include` argument to target-relative files.
/// sshd_config(5): relative paths are under /etc/ssh; glob(7) wildcards
/// are allowed — the filename component's `*` is handled (the form
/// every distro ships, `/etc/ssh/sshd_config.d/*.conf`), files sorted
/// lexically as glob(3) returns them.
fn include_files(root: &RootFs, arg: &str) -> Vec<String> {
    let mut out = Vec::new();
    for pat in arg.split_whitespace() {
        let abs = if pat.starts_with('/') { pat.to_string() } else { format!("/etc/ssh/{}", pat) };
        let (dir, file) = abs.rsplit_once('/').unwrap_or(("", &abs));
        match file.split_once('*') {
            None => out.push(abs.trim_start_matches('/').to_string()),
            Some((pre, post)) => {
                for e in root.list_dir(dir) {
                    if e.meta.is_file() && e.name.starts_with(pre) && e.name.ends_with(post)
                        && e.name.len() >= pre.len() + post.len() {
                        out.push(format!("{}/{}", dir.trim_start_matches('/'), e.name));
                    }
                }
            }
        }
    }
    out
}

/// First effective value of an sshd keyword (sshd is first-match-wins).
/// `Include` lines are followed where they appear, as sshd does. A
/// `Match` block ends the search: values set only inside Match blocks
/// are per-connection and not evaluated here — the global value (or the
/// built-in default the caller applies) always is.
pub fn sshd_keyword(root: &RootFs, keyword: &str) -> Option<String> {
    /// Total files one lookup may read. A container controls its own
    /// sshd_config: 100 `Include` lines each re-including the file would
    /// otherwise be ~100^depth reads.
    const MAX_FILES: usize = 32;
    fn search(root: &RootFs, file: &str, keyword: &str, depth: u8,
              seen: &mut std::collections::HashSet<String>) -> Result<Option<String>, ()> {
        // Err(()) = a Match block was reached, or the budget is spent.
        if !seen.insert(file.to_string()) { return Ok(None); }
        if seen.len() > MAX_FILES { return Err(()); }
        let Some(body) = root.read_string(file, 1 << 20) else { return Ok(None) };
        for line in body.lines() {
            let Some((k, v)) = sshd_kv(line) else { continue };
            if k.eq_ignore_ascii_case("match") { return Err(()); }
            if k.eq_ignore_ascii_case("include") && depth < 4 {
                for f in include_files(root, v).into_iter().take(MAX_FILES) {
                    if let Some(found) = search(root, &f, keyword, depth + 1, seen)? { return Ok(Some(found)); }
                }
                continue;
            }
            if k.eq_ignore_ascii_case(keyword) { return Ok(Some(v.to_string())); }
        }
        Ok(None)
    }
    let mut seen = std::collections::HashSet::new();
    search(root, "etc/ssh/sshd_config", keyword, 0, &mut seen).ok().flatten()
}

/// (user, home) for accounts that can hold keys. Same account rule as
/// the start-up file scan.
fn accounts(root: &RootFs) -> Vec<(String, String)> {
    let passwd = root.read_string("etc/passwd", 4 << 20).unwrap_or_default();
    let homes = super::hooks::account_homes(root);
    passwd.lines().filter_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 { return None; }
        let home = f[5].trim_start_matches('/').trim_end_matches('/').to_string();
        homes.contains(&home).then(|| (f[0].to_string(), format!("/{}", home)))
    }).collect()
}

/// Every key authorised on the target. `skip_host_root` drops the host's
/// root key file, which tamper detection owns.
///
/// None when any key file exists but could not be read in full (read
/// error, or larger than the cap): a partial view must neither prune the
/// baseline nor count as "evaluated", or legitimate keys would re-page as
/// new on the next clean read — and padding the file would hide a key.
pub fn collect(root: &RootFs, skip_host_root: bool) -> Option<Vec<KeyEntry>> {
    let patterns: Vec<String> = sshd_keyword(root, "AuthorizedKeysFile")
        .filter(|v| !v.eq_ignore_ascii_case("none"))
        .map(|v| v.split_whitespace().map(|s| s.to_string()).collect())
        .unwrap_or_else(|| vec![".ssh/authorized_keys".into(), ".ssh/authorized_keys2".into()]);
    let mut out = Vec::new();
    let mut seen_files = BTreeSet::new();
    for (user, home) in accounts(root) {
        for p in &patterns {
            let file = expand_keys_file(p, &user, &home);
            if skip_host_root && user == "root" && file == "/root/.ssh/authorized_keys" { continue; }
            if !seen_files.insert(file.clone()) { continue; }
            match root.read_checked(&file, 1 << 20) {
                Ok(body) => out.extend(parse_file(&user, &file, &String::from_utf8_lossy(&body))),
                Err(super::rootfs::ReadErr::Missing) => {}
                Err(_) => return None,
            }
        }
    }
    Some(out)
}

// ─── Baseline store ────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// target key → set of `user|entry-id` accepted as normal.
    #[serde(default)]
    pub targets: BTreeMap<String, BTreeSet<String>>,
}

pub fn baseline_key(e: &KeyEntry) -> String {
    format!("{}|{}", e.user, e.id)
}

/// Stored beside the other first-run baselines (`predictive::baselines`),
/// so the same directory (and its test override) holds every baseline.
fn baseline_path() -> std::path::PathBuf {
    crate::predictive::baselines::baselines_dir().join("intrusion-ssh-keys.json")
}

static BASELINE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn load() -> Baseline {
    std::fs::read_to_string(baseline_path()).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save(b: &Baseline) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::io::Write;
    let path = baseline_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    let mut f = std::fs::OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(serde_json::to_string_pretty(b).unwrap_or_default().as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, &path)
}

/// Apply one tick's observations to the baseline and return the entries
/// that are NOT accepted (the findings).
///
/// * unseen target → seed with everything, report nothing (except a
///   known-bad key, which is never accepted);
/// * `trusted` (keys whose cards the operator dismissed) are folded in;
/// * accepted entries that have disappeared are pruned, so re-adding a
///   removed key is noticed.
pub fn reconcile(
    target_key: &str,
    current: &[KeyEntry],
    trusted: &BTreeSet<String>,
) -> Vec<KeyEntry> {
    let _g = BASELINE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut b = load();
    let (findings, changed) = reconcile_in(&mut b, target_key, current, trusted);
    if changed && let Err(e) = save(&b) {
        tracing::warn!("intrusion: could not save SSH key baseline: {}", e);
    }
    findings
}

/// Pure core of [`reconcile`]: mutates `b`, returns (findings, changed).
pub fn reconcile_in(
    b: &mut Baseline,
    target_key: &str,
    current: &[KeyEntry],
    trusted: &BTreeSet<String>,
) -> (Vec<KeyEntry>, bool) {
    let first_sight = !b.targets.contains_key(target_key);
    let set = b.targets.entry(target_key.to_string()).or_default();
    let present: BTreeSet<String> = current.iter().map(baseline_key).collect();
    let before = set.clone();
    if first_sight {
        for e in current.iter().filter(|e| known_bad_label(e).is_none()) {
            set.insert(baseline_key(e));
        }
    }
    for t in trusted {
        if present.contains(t) { set.insert(t.clone()); }
    }
    set.retain(|k| present.contains(k));
    let findings: Vec<KeyEntry> = current.iter()
        .filter(|e| known_bad_label(e).is_some() || !set.contains(&baseline_key(e)))
        .cloned()
        .collect();
    let changed = first_sight || *set != before;
    (findings, changed)
}

/// Is this entry the known kit key?
pub fn known_bad_label(e: &KeyEntry) -> Option<&'static str> {
    let bl = e.blob.as_deref()?;
    super::sysfiles::KNOWN_BAD_SSH_KEY_BLOBS.iter().find(|(k, _)| *k == bl).map(|(_, d)| *d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_option_lines() {
        let body = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPGfgb9OgwNn9P736FRhvFEVFAt0waxe+cbAIj7Ami6t root@localhost\n\
                    # comment\n\
                    command=\"/bin/true\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPGfgb9OgwNn9P736FRhvFEVFAt0waxe+cbAIj7Ami6t x\n";
        let e = parse_file("root", "/root/.ssh/authorized_keys", body);
        assert_eq!(e.len(), 2);
        assert!(e[0].id.starts_with("key:"));
        assert_eq!(known_bad_label(&e[0]), Some("LILITH_VITE_V3 operator key (root@localhost)"));
        assert!(e[1].id.starts_with("line:"));
        assert!(e[1].blob.is_none());
    }

    fn key(user: &str, n: u8) -> KeyEntry {
        KeyEntry { user: user.into(), file: "/root/.ssh/authorized_keys".into(),
            id: format!("key:{}", n), summary: String::new(), blob: Some(format!("blob{}", n)) }
    }

    #[test]
    fn first_sight_seeds_then_new_keys_are_findings() {
        let mut b = Baseline::default();
        let (f, changed) = reconcile_in(&mut b, "lxc:web", &[key("root", 1)], &BTreeSet::new());
        assert!(f.is_empty() && changed, "first sight is silent");
        let (f, _) = reconcile_in(&mut b, "lxc:web", &[key("root", 1), key("root", 2)], &BTreeSet::new());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "key:2");
    }

    #[test]
    fn trusted_keys_fold_in_and_removed_keys_are_pruned() {
        let mut b = Baseline::default();
        reconcile_in(&mut b, "t", &[key("root", 1)], &BTreeSet::new());
        let trusted: BTreeSet<String> = [baseline_key(&key("root", 2))].into();
        let (f, _) = reconcile_in(&mut b, "t", &[key("root", 1), key("root", 2)], &trusted);
        assert!(f.is_empty(), "a dismissed key is trusted");
        // Key 1 removed, then re-added: noticed again.
        reconcile_in(&mut b, "t", &[key("root", 2)], &BTreeSet::new());
        let (f, _) = reconcile_in(&mut b, "t", &[key("root", 1), key("root", 2)], &BTreeSet::new());
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn known_bad_key_is_never_baselined() {
        let bad = KeyEntry {
            user: "root".into(), file: "/root/.ssh/authorized_keys".into(), id: "key:bad".into(),
            summary: String::new(),
            blob: Some(super::super::sysfiles::KNOWN_BAD_SSH_KEY_BLOBS[0].0.into()),
        };
        let mut b = Baseline::default();
        let (f, _) = reconcile_in(&mut b, "t", std::slice::from_ref(&bad), &BTreeSet::new());
        assert_eq!(f.len(), 1, "an infected target must not be seeded clean");
        let trusted: BTreeSet<String> = [baseline_key(&bad)].into();
        let (f, _) = reconcile_in(&mut b, "t", &[bad], &trusted);
        assert_eq!(f.len(), 1, "not even when dismissed");
    }

    #[test]
    fn sshd_kv_forms() {
        assert_eq!(sshd_kv("AuthorizedKeysFile .ssh/authorized_keys .ssh/k2"),
            Some(("AuthorizedKeysFile", ".ssh/authorized_keys .ssh/k2")));
        assert_eq!(sshd_kv("AuthorizedKeysCommand=/usr/bin/x %u"),
            Some(("AuthorizedKeysCommand", "/usr/bin/x %u")));
        assert_eq!(sshd_kv("  # comment"), None);
    }

    #[test]
    fn keys_file_tokens() {
        assert_eq!(expand_keys_file(".ssh/authorized_keys", "bob", "/home/bob"), "/home/bob/.ssh/authorized_keys");
        assert_eq!(expand_keys_file("/etc/ssh/keys/%u", "bob", "/home/bob"), "/etc/ssh/keys/bob");
        assert_eq!(expand_keys_file("%h/.ssh/k%%", "bob", "/home/bob"), "/home/bob/.ssh/k%");
    }
}
