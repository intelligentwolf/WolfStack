// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! "Does a package own this file?" for a scan target of any distro.
//!
//! Package ownership is the false-positive gate for the system-file
//! checks: dpkg extracts every file with its *build-time* mtime and an
//! install-time ctime — byte-for-byte the "old mtime, fresh ctime"
//! shape a `touch -r` timestomp leaves — so a timestamp heuristic that
//! didn't first exclude package files would flag every package upgrade.
//!
//! Containers can run any distribution regardless of the host, so each
//! package manager's on-disk database is read from the target's own
//! filesystem:
//!
//! | manager   | database read                                    |
//! |-----------|--------------------------------------------------|
//! | dpkg      | `var/lib/dpkg/info/*.list` + `var/lib/dpkg/diversions` |
//! | apk       | `lib/apk/db/installed` (`F:` dir / `R:` file)     |
//! | pacman    | `var/lib/pacman/local/*/files` (`%FILES%`)        |
//! | slackware | `var/lib/pkgtools/packages/*` or `var/log/packages/*` (`FILE LIST:`) |
//! | rpm       | `rpm --root <target> -qal` (the rpmdb is a binary DB) |
//!
//! Memory: lists are streamed and matched against the (small) candidate
//! set instead of being loaded whole — a Debian install lists ~100k
//! paths, and a node may have dozens of containers.

use super::rootfs::RootFs;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Dpkg,
    Rpm,
    Apk,
    Pacman,
    Slackware,
}

impl Manager {
    pub fn name(self) -> &'static str {
        match self {
            Manager::Dpkg => "dpkg",
            Manager::Rpm => "rpm",
            Manager::Apk => "apk",
            Manager::Pacman => "pacman",
            Manager::Slackware => "slackware",
        }
    }
}

/// Detect the target's package manager from its database files.
pub fn detect(root: &RootFs) -> Option<Manager> {
    if root.lstat("var/lib/dpkg/status").is_some_and(|m| m.is_file()) { return Some(Manager::Dpkg); }
    if root.lstat("lib/apk/db/installed").is_some_and(|m| m.is_file()) { return Some(Manager::Apk); }
    if root.lstat("var/lib/pacman/local").is_some_and(|m| m.is_dir()) { return Some(Manager::Pacman); }
    if root.lstat("var/lib/rpm").is_some_and(|m| m.is_dir())
        || root.lstat("usr/lib/sysimage/rpm").is_some_and(|m| m.is_dir()) {
        return Some(Manager::Rpm);
    }
    if root.lstat("var/lib/pkgtools/packages").is_some_and(|m| m.is_dir())
        || root.lstat("var/log/packages").is_some_and(|m| m.is_dir()) {
        return Some(Manager::Slackware);
    }
    None
}

/// The usr-merge aliases of a path. Debian 12+ (and most distros now)
/// make /bin, /sbin, /lib* symlinks into /usr, but package lists still
/// record whichever spelling the package was built with — so ownership
/// of `/usr/lib/systemd/x` may be recorded as `/lib/systemd/x`.
pub fn aliases(path: &str) -> Vec<String> {
    const MERGED: &[&str] = &["/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"];
    let mut out = vec![path.to_string()];
    for m in MERGED {
        if path.starts_with(&format!("{}/", m)) {
            out.push(format!("/usr{}", path));
        } else if let Some(rest) = path.strip_prefix("/usr")
            && rest.starts_with(&format!("{}/", m)) {
            out.push(rest.to_string());
        }
    }
    out
}

/// Feed one listed path into the match set: every alias of a wanted
/// path maps back to it.
fn mark(listed: &str, want: &HashMap<String, String>, found: &mut HashSet<String>) {
    let listed = listed.trim_end_matches('/');
    if let Some(orig) = want.get(listed) {
        found.insert(orig.clone());
    }
}

/// Parse dpkg's diversions file: repeating triples of
/// (original path, diverted-to path, diverting package), per
/// dpkg-divert(1)'s on-disk format. The diverted-to path holds a
/// package's file, so it is owned.
pub fn parse_dpkg_diversions(body: &str) -> Vec<String> {
    body.lines().collect::<Vec<_>>()
        .chunks(3)
        .filter(|c| c.len() == 3)
        .map(|c| c[1].to_string())
        .collect()
}

/// Parse apk's `installed` database: `F:` sets the current directory
/// (no leading slash), `R:` names a file in it (apk-tools db format).
pub fn parse_apk_installed(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut dir = String::new();
    for line in body.lines() {
        if let Some(d) = line.strip_prefix("F:") {
            dir = d.to_string();
        } else if let Some(f) = line.strip_prefix("R:") {
            out.push(if dir.is_empty() { format!("/{}", f) } else { format!("/{}/{}", dir, f) });
        }
    }
    out
}

/// Parse a pacman `local/<pkg>/files` file: paths (no leading slash)
/// under the `%FILES%` header until the next `%SECTION%`.
pub fn parse_pacman_files(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_files = false;
    for line in body.lines() {
        if line.starts_with('%') && line.ends_with('%') {
            in_files = line == "%FILES%";
            continue;
        }
        if in_files && !line.is_empty() {
            out.push(format!("/{}", line));
        }
    }
    out
}

/// Parse a Slackware package record: paths (no leading slash) after the
/// `FILE LIST:` line; `./` is the package root itself.
pub fn parse_slackware_record(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_list = false;
    for line in body.lines() {
        if line.trim() == "FILE LIST:" { in_list = true; continue; }
        if in_list && !line.is_empty() && line != "./" {
            out.push(format!("/{}", line));
        }
    }
    out
}

/// Remaining read budget for one ownership query.
struct Budget { bytes: usize, lists: usize }

impl Budget {
    /// Read one list within budget. None = budget spent or unreadable
    /// (the query then answers "cannot tell").
    fn read(&mut self, root: &RootFs, path: &str, cap: usize) -> Option<String> {
        if self.lists == 0 { return None; }
        self.lists -= 1;
        let body = root.read(path, cap.min(self.bytes))?;
        self.bytes -= body.len();
        Some(String::from_utf8_lossy(&body).into_owned())
    }
}

/// For each candidate path, is it owned by a package? Returns None when
/// the target has no recognisable package database — callers must then
/// skip ownership-based findings for that target rather than treat
/// every file as unowned.
pub fn owned(root: &RootFs, root_path_for_rpm: &str, candidates: &[String]) -> Option<(Manager, HashSet<String>)> {
    let manager = detect(root)?;
    let mut want: HashMap<String, String> = HashMap::new();
    for c in candidates {
        for a in aliases(c) { want.insert(a, c.clone()); }
    }
    let mut found = HashSet::new();
    if want.is_empty() { return Some((manager, found)); }
    // A container controls its own package database, so reading it is
    // budgeted: per list, in total, and by number of lists. Running out of
    // budget means "cannot tell" (None) — never "unowned".
    const LIST_CAP: usize = 16 << 20;
    const TOTAL_CAP: usize = 512 << 20;
    const MAX_LISTS: usize = 20_000;
    let mut budget = Budget { bytes: TOTAL_CAP, lists: MAX_LISTS };
    match manager {
        Manager::Dpkg => {
            for ent in root.list_dir("var/lib/dpkg/info") {
                if !ent.name.ends_with(".list") || !ent.meta.is_file() { continue; }
                let body = budget.read(root, &format!("var/lib/dpkg/info/{}", ent.name), LIST_CAP)?;
                for line in body.lines() { mark(line, &want, &mut found); }
                if found.len() == candidates.len() { break; }
            }
            if let Some(body) = root.read_string("var/lib/dpkg/diversions", LIST_CAP) {
                for p in parse_dpkg_diversions(&body) { mark(&p, &want, &mut found); }
            }
        }
        Manager::Apk => {
            let body = budget.read(root, "lib/apk/db/installed", 256 << 20)?;
            for p in parse_apk_installed(&body) { mark(&p, &want, &mut found); }
        }
        Manager::Pacman => {
            for ent in root.list_dir("var/lib/pacman/local") {
                if !ent.meta.is_dir() { continue; }
                let path = format!("var/lib/pacman/local/{}/files", ent.name);
                if root.lstat(&path).is_none() { continue; }
                let body = budget.read(root, &path, LIST_CAP)?;
                for p in parse_pacman_files(&body) { mark(&p, &want, &mut found); }
            }
        }
        Manager::Slackware => {
            for dir in ["var/lib/pkgtools/packages", "var/log/packages"] {
                for ent in root.list_dir(dir) {
                    if !ent.meta.is_file() { continue; }
                    let body = budget.read(root, &format!("{}/{}", dir, ent.name), LIST_CAP)?;
                    for p in parse_slackware_record(&body) { mark(&p, &want, &mut found); }
                }
            }
        }
        Manager::Rpm => {
            // The rpmdb is a binary (sqlite/bdb/ndb) store only `rpm` can
            // read. On the HOST that is fine. Against a CONTAINER it is not:
            // `rpm --root /proc/<pid>/root` resolves the container's paths
            // (and its /etc/rpm macros, which can relocate %_dbpath) with
            // ordinary kernel lookups — absolute symlinks land on the host
            // — and parses a database the container wrote, as root. So
            // container rpm ownership is reported as unknown: the
            // ownership-based checks are skipped for that target.
            if root_path_for_rpm != "/" { return None; }
            // capped_exec::run_ok drains stdout while waiting (a full
            // `-qal` is several MB) and kills rpm at the deadline.
            let out = crate::predictive::capped_exec::run_ok(
                "rpm", &["--root", root_path_for_rpm, "-qal"],
                std::time::Duration::from_secs(30),
            )?;
            for line in out.lines() { mark(line, &want, &mut found); }
        }
    }
    Some((manager, found))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usr_merge_aliases_both_ways() {
        let a = aliases("/usr/lib/systemd/systemd-sysconf-sync");
        assert!(a.contains(&"/lib/systemd/systemd-sysconf-sync".to_string()));
        let b = aliases("/bin/dash");
        assert!(b.contains(&"/usr/bin/dash".to_string()));
        assert_eq!(aliases("/etc/cron.d/php"), vec!["/etc/cron.d/php".to_string()]);
    }

    #[test]
    fn diversions_triples() {
        let body = "/usr/bin/foo\n/usr/bin/foo.distrib\nmypkg\n/etc/x\n/etc/x.orig\nother\n";
        assert_eq!(parse_dpkg_diversions(body),
            vec!["/usr/bin/foo.distrib".to_string(), "/etc/x.orig".to_string()]);
    }

    #[test]
    fn apk_installed_format() {
        let body = "P:openssh\nF:usr/lib/ssh\nR:sftp-server\nR:ssh-keysign\nF:etc\nR:motd\n";
        assert_eq!(parse_apk_installed(body), vec![
            "/usr/lib/ssh/sftp-server".to_string(),
            "/usr/lib/ssh/ssh-keysign".to_string(),
            "/etc/motd".to_string(),
        ]);
    }

    #[test]
    fn pacman_files_section() {
        let body = "%FILES%\nusr/\nusr/lib/ssh/sshd-session\n\n%BACKUP%\netc/ssh/sshd_config\tabc\n";
        assert_eq!(parse_pacman_files(body),
            vec!["/usr/".to_string(), "/usr/lib/ssh/sshd-session".to_string()]);
    }

    #[test]
    fn slackware_file_list() {
        let body = "PACKAGE NAME: openssh\nFILE LIST:\n./\netc/\netc/ssh/sshd_config.new\n";
        assert_eq!(parse_slackware_record(body),
            vec!["/etc/".to_string(), "/etc/ssh/sshd_config.new".to_string()]);
    }

    #[test]
    fn marking_resolves_aliases_back_to_candidate() {
        let mut want = HashMap::new();
        for a in aliases("/usr/lib/openssh/sshd-session") {
            want.insert(a, "/usr/lib/openssh/sshd-session".to_string());
        }
        let mut found = HashSet::new();
        mark("/usr/lib/openssh/sshd-session", &want, &mut found);
        assert!(found.contains("/usr/lib/openssh/sshd-session"));
    }
}
