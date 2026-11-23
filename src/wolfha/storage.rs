// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Where a WolfHA container copy lives, and whether it fits there.
//!
//! Until 2026-11-23 a new standby copy always went to `/var/lib/lxc` and its
//! upload was staged under `/var/lib/wolfstack/wolfha` — both on the root
//! disk — with no free-space check anywhere. Protecting a 172 GB container
//! onto a node whose 436 GB root disk was already 50 % full packed for an
//! hour, sent 84 GB, then filled that root disk during the unpack while a
//! 3.6 TB drive sat registered as LXC storage right beside it.
//!
//! Now: every registered LXC storage location (`containers::lxc_storage_paths`)
//! is offered with its free space, the operator picks one per standby (the
//! default is the one with the most room), the upload is staged on that same
//! drive, and both ends check the copy fits BEFORE anything is packed, sent
//! or unpacked.

use serde::{Deserialize, Serialize};

/// Staging folder for uploads, inside a storage location so the archive
/// lands on the same drive as the copy it becomes. A dot-directory with no
/// `config` file, which every container scan and `lxc-ls` already skip.
pub const STAGING_DIR_NAME: &str = ".wolfha-staging";

/// Free space a seed must leave behind. Filling a drive to the last byte
/// stops every container that writes to it — the failure this guards.
pub const HEADROOM_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// One place a container copy can live on a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageOption {
    pub path: String,
    pub free_bytes: u64,
    pub total_bytes: u64,
    /// The location with the most free space — what is used when the
    /// operator doesn't choose.
    #[serde(default)]
    pub default: bool,
}

/// (free, total) bytes of the filesystem holding `path`, read with
/// statvfs. Free is what an unprivileged writer can use (`f_bavail`), the
/// figure that decides whether a copy fits. Walks up to the nearest
/// existing ancestor so a not-yet-created target still resolves.
pub fn fs_space(path: &str) -> Option<(u64, u64)> {
    let mut p = std::path::Path::new(path);
    while !p.exists() {
        p = p.parent()?;
    }
    let c = std::ffi::CString::new(p.to_string_lossy().as_bytes()).ok()?;
    // SAFETY: zero-init is valid for libc::statvfs (POD struct); the pointer
    // is a valid NUL-terminated string for the duration of the call.
    let mut sv: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut sv) } != 0 {
        return None;
    }
    let frsize = sv.f_frsize as u64;
    Some(((sv.f_bavail as u64).saturating_mul(frsize), (sv.f_blocks as u64).saturating_mul(frsize)))
}

/// Device id of the filesystem holding `path` (nearest existing ancestor),
/// so a caller can tell whether two paths share a drive.
pub fn fs_device(path: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    let mut p = std::path::Path::new(path);
    while !p.exists() {
        p = p.parent()?;
    }
    std::fs::metadata(p).ok().map(|m| m.dev())
}

/// Where VM seed images are staged (VM copies keep their definition's disk
/// folder, so only the room is checked, not the location).
pub const VM_STAGE_DIR: &str = "/var/lib/wolfstack/wolfha";

/// Every registered LXC storage location that exists, with its free space.
/// The one with the most free space is marked `default`.
pub fn storage_options() -> Vec<StorageOption> {
    let mut out: Vec<StorageOption> = crate::containers::lxc_storage_paths()
        .into_iter()
        .filter(|p| std::path::Path::new(p).is_dir())
        .filter_map(|path| {
            let (free_bytes, total_bytes) = fs_space(&path)?;
            Some(StorageOption { path, free_bytes, total_bytes, default: false })
        })
        .collect();
    mark_default(&mut out);
    out
}

fn mark_default(opts: &mut [StorageOption]) {
    if let Some(best) = opts.iter().enumerate().max_by_key(|(_, o)| o.free_bytes).map(|(i, _)| i) {
        opts[best].default = true;
    }
}

/// Resolve the storage location a copy should go to. A requested path must
/// be one of this node's registered LXC storage locations — never an
/// arbitrary path from the network. None picks the default.
pub fn resolve_target(requested: Option<&str>) -> Result<String, String> {
    let opts = storage_options();
    match requested.map(str::trim).filter(|s| !s.is_empty()) {
        Some(req) => {
            let req = req.trim_end_matches('/');
            opts.iter()
                .find(|o| o.path.trim_end_matches('/') == req)
                .map(|o| o.path.clone())
                .ok_or_else(|| format!(
                    "'{}' is not a container storage location on this node (available: {})",
                    req, opts.iter().map(|o| o.path.as_str()).collect::<Vec<_>>().join(", ")))
        }
        None => opts.iter().find(|o| o.default).map(|o| o.path.clone())
            .ok_or_else(|| "this node has no usable container storage location".to_string()),
    }
}

/// Where uploads are staged for a copy going to `base`.
pub fn staging_dir(base: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), STAGING_DIR_NAME)
}

/// Space a container seed needs on the drive that receives it: the staged
/// upload plus the unpacked copy. The compressed upload is never larger
/// than the files it holds, so the rootfs size bounds both.
pub fn seed_need_bytes(rootfs_bytes: u64) -> u64 {
    rootfs_bytes.saturating_mul(2)
}

/// Decimal gigabytes, as drive labels and `df -H` print them.
pub fn gb(bytes: u64) -> String {
    format!("{:.0} GB", bytes as f64 / 1e9)
}

/// Ok when `need` bytes fit on the drive holding `path` with
/// `HEADROOM_BYTES` to spare; otherwise a sentence the operator can act on.
pub fn check_fits(path: &str, need: u64, what: &str) -> Result<(), String> {
    let (free, _) = fs_space(path)
        .ok_or_else(|| format!("could not read the free space of {}", path))?;
    fits(free, need).map_err(|short| format!(
        "{} needs {} on {} (plus {} kept free), but only {} is free there — {} short",
        what, gb(need), path, gb(HEADROOM_BYTES), gb(free), gb(short)))
}

/// Ok, or how many bytes are missing.
fn fits(free: u64, need: u64) -> Result<(), u64> {
    let want = need.saturating_add(HEADROOM_BYTES);
    if free >= want { Ok(()) } else { Err(want - free) }
}

/// Bytes used by a directory tree on its own filesystem (`du -sx`). Blocking:
/// minutes on a very large rootfs — call from a blocking thread.
pub fn dir_bytes(path: &str) -> Result<u64, String> {
    let out = std::process::Command::new("du")
        .args(["-sx", "--block-size=1", path])
        .output()
        .map_err(|e| format!("du: {}", e))?;
    // du exits non-zero when some file vanished mid-walk (a running
    // container) yet still prints the total — take the total if present.
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .and_then(|n| n.parse::<u64>().ok())
        .ok_or_else(|| format!("du could not size {}: {}", path,
            String::from_utf8_lossy(&out.stderr).trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_the_location_with_the_most_free_space() {
        let mut opts = vec![
            StorageOption { path: "/var/lib/lxc".into(), free_bytes: 224_000_000_000, total_bytes: 436_000_000_000, default: false },
            StorageOption { path: "/data/glusterfs/shared/lxc".into(), free_bytes: 3_600_000_000_000, total_bytes: 3_800_000_000_000, default: false },
        ];
        mark_default(&mut opts);
        assert!(!opts[0].default);
        assert!(opts[1].default);
    }

    /// The 2026-11-23 case: a 172 GB rootfs onto a root disk with 224 GB
    /// free must be refused before anything is packed.
    #[test]
    fn nodejs_onto_the_root_disk_is_refused_and_onto_the_big_drive_fits() {
        let need = seed_need_bytes(172_000_000_000);
        assert!(fits(224_000_000_000, need).is_err());
        assert!(fits(3_600_000_000_000, need).is_ok());
    }

    #[test]
    fn headroom_is_always_kept() {
        assert_eq!(fits(HEADROOM_BYTES + 5, 5), Ok(()));
        assert_eq!(fits(HEADROOM_BYTES + 4, 5), Err(1));
    }

    #[test]
    fn fs_space_resolves_a_path_that_does_not_exist_yet() {
        let (free, total) = fs_space("/tmp/wolfha-storage-test/does/not/exist").unwrap();
        assert!(total > 0 && free <= total);
    }

    #[test]
    fn staging_sits_inside_the_storage_location() {
        assert_eq!(staging_dir("/data/glusterfs/shared/lxc/"), "/data/glusterfs/shared/lxc/.wolfha-staging");
    }
}
