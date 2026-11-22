// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Unpackaged and timestamp-forged files in system directories, plus
//! the literal indicators of the LILITH_VITE_V3 kit (November 2026).
//!
//! The kit hid its persistence where an admin would never look twice:
//!
//! * `/usr/lib/systemd/systemd-sysconf-sync` — a Python C2 client named
//!   like a systemd helper, run by `/etc/cron.d/sysconf-sync` and a
//!   `systemd-sysconf-sync.service` unit;
//! * `/usr/lib/openssh/ssh-key-helper` — an AuthorizedKeysCommand that
//!   prints the attacker's key;
//!
//! and backdated every file with `touch -r /usr/bin/dash`, so `ls -l`
//! showed 2025-02-04 14:14:42 — the same second as the stock `dash`
//! binary — on files created on 2026-11-16. The inode change time
//! (ctime) cannot be set from userspace, so it still said 2026-11-16.
//!
//! ## The two rules
//!
//! 1. **Package-only directories** (OpenSSH's helper dir, PAM module
//!    dirs, systemd's own top-level binaries): nothing legitimate puts
//!    an unpackaged file there. Any unowned regular file is Critical.
//! 2. **Admin-writable system directories** (cron, unit, init, profile,
//!    sudoers, bin): unowned files are normal here, so only the forged-
//!    timestamp shape is flagged — content timestamp (mtime) more than
//!    [`FORGE_GAP_SECS`] older than the inode change time (ctime), with
//!    the ctime inside the last [`RECENT_SECS`].
//!
//! ## Why the bulk guard
//!
//! Restoring a backup with `tar`/`rsync -a`, or migrating a container
//! between hosts, gives EVERY file the forged-timestamp shape at once.
//! A file is therefore skipped when at least [`BULK_NEIGHBOURS`] other
//! files in the same directory share its shape and their ctime is
//! within [`BULK_WINDOW_SECS`] of its own: a mass event, not a planted
//! file. The attacker's drops were alone in their directories.

use super::rootfs::{Meta, RootFs};

/// Directories whose files all come from packages.
pub const PACKAGE_ONLY_DIRS: &[&str] = &[
    "usr/lib/openssh",
    "usr/libexec/openssh",
    "usr/lib/ssh",
    "usr/lib/systemd",
    "usr/lib/x86_64-linux-gnu/security",
    "usr/lib/aarch64-linux-gnu/security",
    "usr/lib64/security",
    "usr/lib/security",
    // Non-usr spellings, only scanned when they are real directories
    // (not usr-merge symlinks, which would double-report).
    "lib/x86_64-linux-gnu/security",
    "lib/aarch64-linux-gnu/security",
    "lib64/security",
    "lib/security",
    "lib/systemd",
];

/// Directories where only the forged-timestamp shape is flagged.
pub const FORGE_DIRS: &[&str] = &[
    "etc/cron.d", "etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly",
    "etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system",
    "etc/init.d", "etc/profile.d", "etc/update-motd.d", "etc/sudoers.d", "etc/ld.so.conf.d",
    "usr/local/bin", "usr/local/sbin", "usr/bin", "usr/sbin",
];

/// mtime older than ctime by more than a week.
pub const FORGE_GAP_SECS: i64 = 7 * 86400;
/// Only changes in the last 30 days are reported — the window the
/// finding stays actionable in, and what keeps a decade-old restored
/// file from alerting forever.
pub const RECENT_SECS: i64 = 30 * 86400;
pub const BULK_WINDOW_SECS: i64 = 600;
pub const BULK_NEIGHBOURS: usize = 3;

/// Stock binaries whose exact mtime an attacker copies with `touch -r`.
pub const TIMESTAMP_DONORS: &[&str] = &[
    "usr/bin/dash", "usr/bin/bash", "usr/bin/ls", "usr/bin/cp", "usr/sbin/sshd",
    "usr/bin/systemctl", "usr/bin/python3", "usr/bin/cron", "usr/sbin/cron",
];

#[derive(Debug, Clone, PartialEq)]
pub enum Reason {
    /// Unowned file in a package-only directory.
    PackageOnlyDir,
    /// Unowned file whose mtime was set back; `cloned_from` names the
    /// stock binary whose exact mtime it carries, when one matches.
    ForgedTimestamp { cloned_from: Option<String> },
}

#[derive(Debug, Clone)]
pub struct Candidate {
    /// Absolute path inside the target.
    pub path: String,
    pub meta: Meta,
    pub reason: Reason,
}

/// Pure forged-timestamp test.
pub fn forged_shape(m: &Meta, now: i64) -> bool {
    m.ctime - m.mtime > FORGE_GAP_SECS && now - m.ctime <= RECENT_SECS && now >= m.ctime
}

/// Pure bulk-event test over one directory's entries (`siblings`
/// includes the candidate). A restore or migration rewrites the whole
/// directory at once, so it is "bulk" only when MORE than
/// [`BULK_NEIGHBOURS`] other files share the shape AND they are at least
/// half the directory — an attacker dropping a few lookalike decoys next
/// to a planted file does not get it excused.
pub fn is_bulk(candidate: &Meta, siblings: &[Meta], now: i64) -> bool {
    let alike = siblings.iter()
        .filter(|s| forged_shape(s, now) && (s.ctime - candidate.ctime).abs() <= BULK_WINDOW_SECS)
        .count();
    alike > BULK_NEIGHBOURS && alike * 2 >= siblings.len()
}

/// A directory variant is scanned only when NO component of its path is a
/// symlink. usr-merge aliases (`/lib -> usr/lib`, and on Arch
/// `/usr/lib64 -> lib`) would otherwise list the same files under a name the
/// package database never records — every PAM module on an Arch host showed
/// up "unpackaged" under /usr/lib64/security until this checked every
/// component, not just the first.
fn real_dir(root: &RootFs, dir: &str) -> bool {
    let mut prefix = String::new();
    for comp in dir.split('/').filter(|c| !c.is_empty()) {
        if !prefix.is_empty() { prefix.push('/'); }
        prefix.push_str(comp);
        match root.lstat(&prefix) {
            Some(m) if m.is_symlink() => return false,
            Some(m) if m.is_dir() => {}
            _ => return false,
        }
    }
    true
}

fn donor_mtimes(root: &RootFs) -> Vec<(String, i64, i64)> {
    TIMESTAMP_DONORS.iter()
        .filter_map(|d| root.lstat(d).filter(|m| m.is_file())
            .map(|m| (format!("/{}", d), m.mtime, m.mtime_nsec)))
        .collect()
}

/// Gather candidates (ownership not yet checked).
pub fn collect(root: &RootFs, now: i64) -> Vec<Candidate> {
    let mut out = Vec::new();
    for dir in PACKAGE_ONLY_DIRS {
        if !real_dir(root, dir) { continue; }
        for e in root.list_dir(dir) {
            // Symlinks too: packages own their symlinks, and a planted one
            // (pointing at a payload elsewhere) is just as unpackaged.
            if !e.meta.is_file() && !e.meta.is_symlink() { continue; }
            out.push(Candidate {
                path: format!("/{}/{}", dir, e.name),
                meta: e.meta,
                reason: Reason::PackageOnlyDir,
            });
        }
    }
    let donors = donor_mtimes(root);
    for dir in FORGE_DIRS {
        if !real_dir(root, dir) { continue; }
        let ents = root.list_dir(dir);
        let metas: Vec<Meta> = ents.iter().filter(|e| e.meta.is_file()).map(|e| e.meta).collect();
        for e in &ents {
            if !e.meta.is_file() || !forged_shape(&e.meta, now) { continue; }
            let path = format!("/{}/{}", dir, e.name);
            let cloned_from = donors.iter()
                .find(|(p, s, ns)| *p != path && *s == e.meta.mtime && *ns == e.meta.mtime_nsec)
                .map(|(p, _, _)| p.clone());
            // An exact copy of a stock binary's timestamp is deliberate —
            // never excused as part of a mass restore.
            if cloned_from.is_none() && is_bulk(&e.meta, &metas, now) { continue; }
            out.push(Candidate { path, meta: e.meta, reason: Reason::ForgedTimestamp { cloned_from } });
        }
    }
    out
}

// ─── Literal indicators of the 2026-11-16 compromise ───────────────

/// Paths the LILITH_VITE_V3 kit writes.
pub const KNOWN_IOC_PATHS: &[(&str, &str)] = &[
    ("etc/node-telemetry-preload.cjs", "Node webshell preload (LILITH_VITE_V3)"),
    ("root/.config/node-telemetry-preload.cjs", "Node webshell preload, second copy (LILITH_VITE_V3)"),
    ("usr/lib/systemd/systemd-sysconf-sync", "Python C2 client posing as a systemd helper"),
    ("etc/cron.d/sysconf-sync", "cron entry that launches the C2 client"),
    ("etc/systemd/system/systemd-sysconf-sync.service", "systemd unit that keeps the C2 client running"),
    ("usr/lib/openssh/ssh-key-helper", "AuthorizedKeysCommand that hands out the attacker's SSH key"),
    ("tmp/.uvicorn_sysconf_metrics.lck", "lock file of the running C2 client"),
];

/// SHA-256 of the kit's files, from evidence quarantined off a
/// compromised container.
/// A renamed copy anywhere is still matched by content.
pub const KNOWN_BAD_SHA256: &[(&str, &str)] = &[
    ("748f6ac1635acf11b4577c2a5ddc26ccab4f3971075126b376a9a18fec9b0c49", "Python C2 client (systemd-sysconf-sync)"),
    ("50ae999e014644cd006cef5c0399f27cd73ee52c1fc0f9b3276cda529b887c67", "Node webshell preload (node-telemetry-preload.cjs)"),
    ("cc6324eeb66169d9123c78a5c9ce669ffec7f925572867e15604b2e16e0a8f6c", "SSH key helper (ssh-key-helper)"),
    ("b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49", "xmrig 6.26.0 miner as deployed by the kit"),
];

/// The attacker's SSH public key blob (ed25519, comment `root@localhost`),
/// as printed by the kit's ssh-key-helper.
pub const KNOWN_BAD_SSH_KEY_BLOBS: &[(&str, &str)] = &[
    ("AAAAC3NzaC1lZDI1NTE5AAAAIPGfgb9OgwNn9P736FRhvFEVFAt0waxe+cbAIj7Ami6t",
     "LILITH_VITE_V3 operator key (root@localhost)"),
];

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

pub fn known_bad_hash(sha: &str) -> Option<&'static str> {
    KNOWN_BAD_SHA256.iter().find(|(h, _)| *h == sha).map(|(_, d)| *d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(mtime: i64, ctime: i64) -> Meta {
        Meta { mode: libc::S_IFREG | 0o755, size: 2390, mtime, mtime_nsec: 0, ctime }
    }

    // 2025-02-04 14:14:42 +0100 and 2026-11-16 04:18:35 +0100, the real
    // mtime/ctime pair of the kit's systemd-sysconf-sync.
    // Verified: `date -d "2025-02-04 14:14:42 +0100" +%s`.
    const KIT_MTIME: i64 = 1738674882;
    // Verified: `date -d "2026-11-16 04:18:35 +0100" +%s`.
    const KIT_CTIME: i64 = 1794799115;

    #[test]
    fn kit_file_has_the_forged_shape() {
        let now = KIT_CTIME + 6 * 86400; // found six days later
        assert!(forged_shape(&meta(KIT_MTIME, KIT_CTIME), now));
    }

    #[test]
    fn ordinary_files_do_not() {
        let now = 1_800_000_000;
        // Edited normally: mtime == ctime.
        assert!(!forged_shape(&meta(now - 100, now - 100), now));
        // Old, untouched install: both old.
        assert!(!forged_shape(&meta(now - 400 * 86400, now - 300 * 86400), now));
        // Restored months ago: outside the recent window.
        assert!(!forged_shape(&meta(now - 900 * 86400, now - 60 * 86400), now));
    }

    #[test]
    fn lone_file_is_not_bulk_but_a_restore_is() {
        let now = KIT_CTIME + 86400;
        let kit = meta(KIT_MTIME, KIT_CTIME);
        let normal = meta(KIT_CTIME - 10, KIT_CTIME - 10);
        assert!(!is_bulk(&kit, &[kit, normal, normal], now));
        // Five files restored in the same minute with old mtimes.
        let restored: Vec<Meta> = (0..5).map(|i| meta(KIT_MTIME - i, KIT_CTIME + i)).collect();
        assert!(is_bulk(&restored[0], &restored, now));
    }

    #[test]
    fn decoys_do_not_excuse_a_planted_file() {
        let now = KIT_CTIME + 86400;
        let normal = meta(KIT_CTIME - 500 * 86400, KIT_CTIME - 400 * 86400);
        // 5 forged-looking files (planted + 4 decoys) in a directory of 30.
        let mut dir: Vec<Meta> = (0..5).map(|i| meta(KIT_MTIME, KIT_CTIME + i)).collect();
        dir.extend(std::iter::repeat_n(normal, 25));
        assert!(!is_bulk(&dir[0], &dir, now));
    }

    #[test]
    fn known_indicators_match() {
        assert!(known_bad_hash("748f6ac1635acf11b4577c2a5ddc26ccab4f3971075126b376a9a18fec9b0c49").is_some());
        assert!(known_bad_hash(&sha256_hex(b"hello")).is_none());
    }
}
