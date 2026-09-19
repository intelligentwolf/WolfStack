// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Backup & Restore — Docker, LXC, VM, and config backup management
//!
//! Supports storage targets: local path, S3, remote WolfStack node, WolfDisk
//! Includes scheduling with retention policies


//! backup needs lxcs to have more information

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{LazyLock, Mutex};
use tracing::{error, info, warn};
use chrono::{Utc, Datelike};
use uuid::Uuid;

fn backup_config_path() -> String { crate::paths::get().backup_config }
fn backup_staging_dir() -> String { crate::paths::get().backup_staging_dir }

// ─── Data Types ───

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BackupTargetType {
    Docker,
    Lxc,
    Vm,
    Config,
    /// Arbitrary host system folder (e.g. /etc, /home, app data). The
    /// folder path travels in `BackupTarget::system_path`; `name` carries
    /// an operator-supplied label used in the backup filename.
    SystemPath,
}

impl std::fmt::Display for BackupTargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Docker => write!(f, "docker"),
            Self::Lxc => write!(f, "lxc"),
            Self::Vm => write!(f, "vm"),
            Self::Config => write!(f, "config"),
            Self::SystemPath => write!(f, "systempath"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupTarget {
    #[serde(rename = "type")]
    pub target_type: BackupTargetType,
    /// Name of the container/VM (empty for Config type)
    pub name: String,
    /// Actual hostname (e.g. Proxmox LXC where name is a numeric VMID)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Running state (running, stopped, etc.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Brief spec summary (e.g. "2 cores, 2GB RAM, Ubuntu 22.04")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub specs: Option<String>,
    /// Host source paths (bind mounts / system sub-paths) and named-volume
    /// names to SKIP when backing this target up. Empty (the default for
    /// every existing config) preserves the original "back everything up"
    /// behaviour exactly. Matched exactly, or as a trailing-slash prefix
    /// (`/mnt/media` excludes `/mnt/media/...`).
    #[serde(default)]
    pub exclude_mounts: Vec<String>,
    /// For `SystemPath` targets: the absolute host directory to archive.
    /// Empty for every other target type.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub system_path: String,
    /// Docker targets that belong to a Docker Compose project carry the
    /// project name (the `com.docker.compose.project` label). The UI groups
    /// these into "stacks" so an operator can select a whole compose stack —
    /// every service, each with its binds/volumes and the shared compose
    /// definition — as one action (klasSponsor 2026-07-23). None for
    /// non-compose targets; absent from older configs (serde default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_project: Option<String>,
    /// Native-LXC targets only: stop the container for the duration of the
    /// tar (fully consistent archive, at the cost of downtime AND a restart
    /// whose clean boot is the container's problem — wolfscale-3 2026-07-05:
    /// the implicit nightly stop/start left a broken-boot container's
    /// database down until manual repair). OFF by default: the container
    /// keeps running and the tarball is crash-consistent, like a power-loss
    /// snapshot. `#[serde(default)]` so every existing config gets the
    /// non-disruptive behaviour. Proxmox LXC ignores this (vzdump snapshots).
    #[serde(default)]
    pub stop_for_backup: bool,
}

impl Default for BackupTarget {
    fn default() -> Self {
        Self {
            target_type: BackupTargetType::Config,
            name: String::new(),
            hostname: None,
            state: None,
            specs: None,
            exclude_mounts: Vec::new(),
            system_path: String::new(),
            compose_project: None,
            stop_for_backup: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StorageType {
    Local,
    S3,
    Remote,
    Wolfdisk,
    Pbs,
    /// NFS export — direct backup destination. Mounted on-demand at
    /// /mnt/wolfstack-backup/<id>/ and written through like Local.
    Nfs,
    /// SMB/CIFS share — as Nfs but for Synology/QNAP and Windows NAS boxes.
    Smb,
}

impl std::fmt::Display for StorageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::S3 => write!(f, "s3"),
            Self::Remote => write!(f, "remote"),
            Self::Wolfdisk => write!(f, "wolfdisk"),
            Self::Pbs => write!(f, "pbs"),
            Self::Nfs => write!(f, "nfs"),
            Self::Smb => write!(f, "smb"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupStorage {
    #[serde(rename = "type")]
    pub storage_type: StorageType,
    /// Local path or WolfDisk mount point
    #[serde(default)]
    pub path: String,
    /// S3 bucket name
    #[serde(default)]
    pub bucket: String,
    /// S3 region
    #[serde(default)]
    pub region: String,
    /// S3 endpoint URL
    #[serde(default)]
    pub endpoint: String,
    /// S3 access key
    #[serde(default)]
    pub access_key: String,
    /// S3 secret key
    #[serde(default)]
    pub secret_key: String,
    /// Remote WolfStack node URL
    #[serde(default)]
    pub remote_url: String,
    /// PBS server hostname/IP
    #[serde(default)]
    pub pbs_server: String,
    /// PBS datastore name
    #[serde(default)]
    pub pbs_datastore: String,
    /// PBS user (e.g. backup@pbs)
    #[serde(default)]
    pub pbs_user: String,
    /// PBS API token name
    #[serde(default)]
    pub pbs_token_name: String,
    /// PBS API token secret
    #[serde(default)]
    pub pbs_token_secret: String,
    /// PBS password (alternative to API token)
    #[serde(default)]
    pub pbs_password: String,
    /// PBS server TLS fingerprint (optional)
    #[serde(default)]
    pub pbs_fingerprint: String,
    /// PBS namespace (optional, for organizing backups)
    #[serde(default)]
    pub pbs_namespace: String,
    /// Which saved PBS destination this backup goes to. Empty means the
    /// primary connection (`/etc/wolfstack/pbs/config.json`) — which is
    /// every pre-existing config, so absent field → empty → byte-identical
    /// behaviour. A non-empty id selects one of the additional destinations
    /// in `/etc/wolfstack/pbs/targets.json`, letting one schedule write to
    /// an S3-backed datastore while others keep going to the NAS-backed one
    /// (klasSponsor 2026-07-28).
    #[serde(default)]
    pub pbs_target_id: String,
    /// PBS file-level (pxar) backup. When false (the default, and what every
    /// existing config has) WolfStack uploads its `.tar.gz` wrapped in a
    /// single `backup.pxar` — opaque, restorable only as a whole. When true,
    /// the workload's CONTENT directory is uploaded as native pxar archives so
    /// PBS's per-file restore works. Golden-Rule safe: absent field → false →
    /// byte-identical to the original behaviour.
    #[serde(default)]
    pub pbs_file_level: bool,
    /// True when the caller EXPLICITLY chose `pbs_file_level` for this backup
    /// (the per-backup override), so `merge_pbs_secrets` must keep it verbatim —
    /// including an explicit `false` against an on-by-default connection. Absent
    /// field → false → fall back to the old "adopt the saved default unless the
    /// request set it true" behaviour, so older callers are byte-identical.
    #[serde(default)]
    pub pbs_file_level_set: bool,
    // ── NFS direct backup destination ─────────────────
    /// `server:/export` — same syntax as `mount -t nfs`.
    #[serde(default)]
    pub nfs_source: String,
    /// Mount options; empty string uses the default `rw,soft,timeo=50`.
    #[serde(default)]
    pub nfs_options: String,
    // ── SMB/CIFS direct backup destination ────────────
    /// `//server/share` (Windows-style `\\server\share` is normalised).
    #[serde(default)]
    pub smb_source: String,
    /// Subdirectory under the share root to write backups into.
    #[serde(default)]
    pub smb_subpath: String,
    #[serde(default)]
    pub smb_username: String,
    #[serde(default)]
    pub smb_password: String,
    #[serde(default)]
    pub smb_domain: String,
    /// Extra CIFS mount options, e.g. `vers=2.1` for older NAS.
    #[serde(default)]
    pub smb_options: String,
    /// Subdirectory under the WolfDisk mount point to write backups
    /// into. Empty means write to the mount root (default, original
    /// behaviour). Sanitized at write time — leading/trailing
    /// slashes are trimmed, `..` segments are rejected so a
    /// misconfigured destination can't escape the mount root.
    #[serde(default)]
    pub wolfdisk_subpath: String,
}

#[allow(dead_code)]
impl BackupStorage {
    pub fn local(path: &str) -> Self {
        Self {
            storage_type: StorageType::Local,
            path: path.to_string(),
            ..Self::default()
        }
    }

    pub fn s3(bucket: &str, region: &str, endpoint: &str, key: &str, secret: &str) -> Self {
        Self {
            storage_type: StorageType::S3,
            bucket: bucket.to_string(),
            region: region.to_string(),
            endpoint: endpoint.to_string(),
            access_key: key.to_string(),
            secret_key: secret.to_string(),
            ..Self::default()
        }
    }

    pub fn remote(url: &str) -> Self {
        Self {
            storage_type: StorageType::Remote,
            remote_url: url.to_string(),
            ..Self::default()
        }
    }

    pub fn wolfdisk(path: &str) -> Self {
        Self {
            storage_type: StorageType::Wolfdisk,
            path: path.to_string(),
            ..Self::default()
        }
    }

    pub fn pbs(server: &str, datastore: &str, user: &str, token_name: &str, token_secret: &str) -> Self {
        Self {
            storage_type: StorageType::Pbs,
            pbs_server: server.to_string(),
            pbs_datastore: datastore.to_string(),
            pbs_user: user.to_string(),
            pbs_token_name: token_name.to_string(),
            pbs_token_secret: token_secret.to_string(),
            ..Self::default()
        }
    }
}

impl Default for BackupStorage {
    fn default() -> Self {
        Self {
            storage_type: StorageType::Local,
            path: String::new(),
            bucket: String::new(),
            region: String::new(),
            endpoint: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
            remote_url: String::new(),
            pbs_server: String::new(),
            pbs_datastore: String::new(),
            pbs_user: String::new(),
            pbs_token_name: String::new(),
            pbs_token_secret: String::new(),
            pbs_password: String::new(),
            pbs_fingerprint: String::new(),
            pbs_namespace: String::new(),
            pbs_target_id: String::new(),
            pbs_file_level: false,
            pbs_file_level_set: false,
            nfs_source: String::new(),
            nfs_options: String::new(),
            smb_source: String::new(),
            smb_subpath: String::new(),
            smb_username: String::new(),
            smb_password: String::new(),
            smb_domain: String::new(),
            smb_options: String::new(),
            wolfdisk_subpath: String::new(),
        }
    }
}

impl BackupStorage {
    /// Resolve the local-filesystem write path for a Local or
    /// WolfDisk destination, joining the WolfDisk subpath under the
    /// mount root when set. For non-Local/Wolfdisk types the
    /// configured `path` is returned unchanged.
    ///
    /// Sanitization:
    ///   - Trims trailing slashes from the base path.
    ///   - Trims leading/trailing slashes from the subpath.
    ///   - Drops empty / `.` / `..` segments. The save-time API
    ///     check rejects `..` outright, but this defence-in-depth
    ///     filter ensures an older config file (or a hand-edited
    ///     `/etc/wolfstack/backup.json`) can't escape the mount.
    pub fn resolved_local_path(&self) -> String {
        let base = self.path.trim_end_matches('/').to_string();
        if !matches!(self.storage_type, StorageType::Wolfdisk) {
            return self.path.clone();
        }
        let raw = self.wolfdisk_subpath.trim().trim_matches('/');
        if raw.is_empty() { return base; }
        let safe: Vec<&str> = raw.split('/')
            .filter(|s| !s.is_empty() && *s != "." && *s != "..")
            .collect();
        if safe.is_empty() { return base; }
        format!("{}/{}", base, safe.join("/"))
    }

    /// Return a copy with an empty Local `path` filled in from the configured
    /// default backup directory. Called when a backup entry is created so the
    /// concrete destination is baked into the stored entry — restore then reads
    /// exactly where the backup was written, independent of any later change to
    /// the default. Non-Local types and already-set paths are returned as-is.
    fn with_concrete_local(&self, default_dir: &str) -> BackupStorage {
        let mut s = self.clone();
        if matches!(s.storage_type, StorageType::Local) && s.path.trim().is_empty() {
            s.path = default_dir.to_string();
        }
        s
    }

    /// Validate a WolfDisk subpath at the API save boundary. Strict
    /// — any `..` or `.` segment is rejected (vs the lenient
    /// resolver which silently strips them). Empty subpath is
    /// allowed (it means "use the mount root", the default).
    ///
    /// `.` is rejected even though it's harmless, because keeping
    /// the validator and resolver consistent avoids the surprise
    /// where an operator types `./backups` and the storage label
    /// shows `backups` — a silent normalisation that looks like
    /// the system "ate" their input.
    pub fn validate_wolfdisk_subpath(sub: &str) -> Result<(), String> {
        let s = sub.trim().trim_matches('/');
        if s.is_empty() { return Ok(()); }
        for seg in s.split('/') {
            if seg.is_empty() {
                return Err("WolfDisk subpath has empty segment (consecutive slashes)".into());
            }
            if seg == ".." {
                return Err("WolfDisk subpath must not contain '..' segments".into());
            }
            if seg == "." {
                return Err("WolfDisk subpath must not contain '.' segments — drop it".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_discriminator_distinguishes_case_and_parent() {
        // The whole point: case-only-differing paths must get DIFFERENT
        // discriminators so they don't collide on a case-insensitive dest.
        assert_ne!(short_path_discriminator("/data/temp"),
                   short_path_discriminator("/data/Temp"));
        // Same basename under different parents must differ too.
        assert_ne!(short_path_discriminator("/a/x"),
                   short_path_discriminator("/b/x"));
        // Stable + hex (8 lowercase hex chars).
        let d = short_path_discriminator("/data/temp");
        assert_eq!(d, short_path_discriminator("/data/temp"));
        assert_eq!(d.len(), 8);
        assert!(d.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    /// wabil 2026-07-06 EXACT repro: back up /mnt/docker, exclude
    /// /mnt/docker/plex. End-to-end through the REAL backup_system_path
    /// (pattern generation + tar), not a hand-built tar command. Proves
    /// whether the backend honours the exclude for his precise inputs.
    #[test]
    fn backup_system_path_excludes_wabil_case_end_to_end() {
        use std::io::Write;
        let root = std::env::temp_dir().join(format!("wsfx-{}", uuid::Uuid::new_v4().simple()));
        // Point staging at a writable temp dir (the real default,
        // /tmp/wolfstack-backups, is root-owned on dev boxes from live runs).
        let mut locs = crate::paths::get();
        let staging = root.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        locs.backup_staging_dir = staging.to_string_lossy().to_string();
        crate::paths::set_for_test(locs);
        let docker = root.join("docker");
        std::fs::create_dir_all(docker.join("plex/config")).unwrap();
        std::fs::create_dir_all(docker.join("keep")).unwrap();
        std::fs::File::create(docker.join("plex/config/f")).unwrap().write_all(b"p").unwrap();
        std::fs::File::create(docker.join("keep/f")).unwrap().write_all(b"k").unwrap();

        let folder = docker.to_string_lossy().to_string();
        let exclude = docker.join("plex").to_string_lossy().to_string();
        let (tar_path, _size) = backup_system_path("docker", &folder, &[exclude])
            .expect("backup_system_path failed");

        let listing = std::process::Command::new("tar")
            .args(["-tzf", &tar_path.to_string_lossy()])
            .output().unwrap();
        let members = String::from_utf8_lossy(&listing.stdout);
        let _ = std::fs::remove_file(&tar_path);
        let _ = std::fs::remove_dir_all(&root);

        assert!(members.contains("docker/keep"), "keep must be present: {}", members);
        assert!(!members.contains("plex"), "plex MUST be excluded but was present:\n{}", members);
    }

    /// klas 2026-08-19: a large Docker container's backup filled the system
    /// drive, failed, and left its partial archive in staging. The guard now
    /// refuses before writing — these pin the arithmetic it refuses on.
    #[test]
    fn staging_refuses_only_when_the_archive_plus_headroom_cannot_fit() {
        const GIB: u64 = 1024 * 1024 * 1024;
        // 10 GiB of data needs 10 GiB + 1 GiB headroom.
        assert_eq!(staging_shortfall(10 * GIB, 12 * GIB), None, "comfortable fit");
        assert_eq!(staging_shortfall(10 * GIB, 11 * GIB), None, "exactly enough");
        assert_eq!(
            staging_shortfall(10 * GIB, 10 * GIB),
            Some(GIB),
            "free == data leaves no headroom, so it is short by the headroom",
        );
        assert_eq!(staging_shortfall(40 * GIB, 5 * GIB), Some(36 * GIB));
        // An empty target never blocks.
        assert_eq!(staging_shortfall(0, 2 * GIB), None);
        // Absurd sizes must saturate rather than overflow into a pass.
        assert!(staging_shortfall(u64::MAX, 1024).is_some());
    }

    #[test]
    fn excluded_paths_are_not_counted_against_staging() {
        let root = std::env::temp_dir().join(format!("wsstage-{}", uuid::Uuid::new_v4().simple()));
        let big = root.join("media");
        let small = root.join("config");
        std::fs::create_dir_all(&big).unwrap();
        std::fs::create_dir_all(&small).unwrap();
        std::fs::write(big.join("blob"), vec![7u8; 512 * 1024]).unwrap();
        std::fs::write(small.join("cfg"), b"x").unwrap();

        let total = quick_dir_size_bytes(&root.to_string_lossy());
        assert!(total > 512 * 1024, "du should see the blob: {}", total);

        // Excluding the big directory takes its bytes off the requirement.
        let excluded = vec![big.to_string_lossy().to_string()];
        let after = subtract_excluded_bytes(total, &excluded);
        assert!(after < total - 400 * 1024, "expected the blob to be discounted: {} -> {}", total, after);

        // A named volume (no leading slash) has no measurable path, so it
        // discounts nothing rather than silently subtracting zero-sized noise.
        assert_eq!(subtract_excluded_bytes(total, &["some_volume".to_string()]), total);
        // Over-subtraction floors at zero instead of wrapping.
        assert_eq!(subtract_excluded_bytes(1, &excluded), 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_refusal_names_the_numbers_and_the_way_out() {
        // The message is the whole user-facing fix, so its content is asserted:
        // an operator seeing it must learn what was too big, what was free, and
        // what to change.
        let staging = std::env::temp_dir();
        let free = filesystem_free_bytes(&staging).expect("df should answer for /tmp");
        let err = ensure_staging_space(
            "Docker container 'plex'",
            Some(free.saturating_add(64 * 1024 * 1024 * 1024)),
            &staging,
        ).expect_err("an archive 64 GiB larger than free space must be refused");
        assert!(err.contains("plex"), "must name the target: {}", err);
        assert!(err.contains("Nothing was written"), "must say no data was staged: {}", err);
        assert!(err.contains("staging directory"), "must point at the setting: {}", err);
        assert!(err.contains("exclude the large mounts"), "must offer the exclusion route: {}", err);

        // A target that fits, and an unmeasurable one, both proceed.
        assert!(ensure_staging_space("tiny", Some(1024), &staging).is_ok());
        assert!(ensure_staging_space("unknown", None, &staging).is_ok());
    }

    #[test]
    fn classify_folder_excludes_flags_out_of_folder() {
        // Leaf-mode folder: in-folder excludes apply, cross-root ones drop.
        let (applied, dropped) = classify_folder_excludes(
            "/mnt/user/appdata",
            &[
                "/mnt/user/appdata/plex".to_string(),   // in-folder abs
                "plex/cache".to_string(),               // in-folder rel
                "/mnt/cache/appdata/plex".to_string(),  // Unraid cache path — different string, dropped
                "/etc/ssl".to_string(),                 // unrelated root — dropped
                "   ".to_string(),                      // blank — ignored entirely
            ],
        );
        assert_eq!(applied, vec!["/mnt/user/appdata/plex".to_string(), "plex/cache".to_string()]);
        assert_eq!(dropped, vec!["/mnt/cache/appdata/plex".to_string(), "/etc/ssl".to_string()]);
        // Contents-mode (trailing slash) behaves the same for classification.
        let (a2, d2) = classify_folder_excludes("/data/", &["/data/tmp".to_string(), "/other".to_string()]);
        assert_eq!(a2, vec!["/data/tmp".to_string()]);
        assert_eq!(d2, vec!["/other".to_string()]);
    }

    /// wabil 2026-07-06: excludes worked for local tarball but NOT PBS
    /// file-level. The pxar path now translates them to anchored globs.
    /// Covers his four attempts against folder /mnt/docker.
    #[test]
    fn pxar_exclude_pattern_wabil_attempts() {
        // Absolute in-folder → anchored to archive root.
        assert_eq!(pxar_exclude_pattern("/mnt/docker/plex", "/mnt/docker"), Some("/plex".into()));
        // Relative name → same anchored glob.
        assert_eq!(pxar_exclude_pattern("plex", "/mnt/docker"), Some("/plex".into()));
        // Trailing slash trimmed.
        assert_eq!(pxar_exclude_pattern("plex/", "/mnt/docker"), Some("/plex".into()));
        // Leading-slash-but-not-under-folder → dropped (his '/plex' attempt,
        // which reads as an absolute path outside /mnt/docker).
        assert_eq!(pxar_exclude_pattern("/plex", "/mnt/docker"), None);
        // Nested sub-path keeps its depth.
        assert_eq!(pxar_exclude_pattern("/mnt/docker/plex/config", "/mnt/docker"), Some("/plex/config".into()));
        // Wholly outside the folder → dropped.
        assert_eq!(pxar_exclude_pattern("/etc/ssl", "/mnt/docker"), None);
    }

    #[test]
    fn folder_exclude_patterns_absolute_and_relative() {
        // Leaf mode (no trailing slash): members are "<leaf>/...".
        assert_eq!(folder_exclude_pattern("/srv/data/big", "/srv/data", "data", false), Some("data/big".into()));
        assert_eq!(folder_exclude_pattern("big", "/srv/data", "data", false), Some("data/big".into()));
        assert_eq!(folder_exclude_pattern("big/sub", "/srv/data", "data", false), Some("data/big/sub".into()));
        // Contents-only mode (trailing slash): members are "./..." → bare rel.
        assert_eq!(folder_exclude_pattern("/srv/data/big", "/srv/data", "data", true), Some("big".into()));
        assert_eq!(folder_exclude_pattern("./big", "/srv/data", "data", true), Some("big".into()));
        // Out-of-folder, the folder itself, and empties are ignored.
        assert_eq!(folder_exclude_pattern("/etc/ssl", "/srv/data", "data", false), None);
        assert_eq!(folder_exclude_pattern("/srv/data", "/srv/data", "data", false), None);
        assert_eq!(folder_exclude_pattern("  ", "/srv/data", "data", false), None);
    }

    #[test]
    fn pbs_file_level_override_both_directions_and_legacy() {
        // Per-backup override explicitly set → wins verbatim, BOTH directions.
        assert!(!resolve_pbs_file_level(true, false, true), "explicit OFF beats on-default");
        assert!(resolve_pbs_file_level(true, true, false), "explicit ON beats off-default");
        // Not explicitly set → legacy: adopt saved unless request already true.
        assert!(resolve_pbs_file_level(false, false, true), "unset adopts saved (on)");
        assert!(!resolve_pbs_file_level(false, false, false), "unset adopts saved (off)");
        assert!(resolve_pbs_file_level(false, true, false), "legacy: request-true still wins");
    }

    // ── Additional PBS destinations ──────────────────────────────
    //
    // The inheritance order is per-backup value → destination →
    // primary connection. Get it wrong and a backup silently lands in
    // a different datastore than the operator picked, which is the
    // exact failure this feature exists to prevent (klasSponsor).

    fn pbs_target_fixture() -> PbsTarget {
        PbsTarget {
            id: "t1".into(),
            name: "S3 cold".into(),
            pbs_datastore: "s3-cold".into(),
            ..PbsTarget::default()
        }
    }

    #[test]
    fn pbs_target_fills_only_empty_fields() {
        // The common case: a second datastore on the SAME server, so
        // the destination carries a datastore and nothing else.
        let mut storage = BackupStorage {
            storage_type: StorageType::Pbs,
            ..BackupStorage::default()
        };
        apply_pbs_target(&mut storage, &pbs_target_fixture());
        assert_eq!(storage.pbs_datastore, "s3-cold");
        assert!(storage.pbs_server.is_empty(),
            "server stays empty so it inherits from the primary connection");
    }

    #[test]
    fn per_backup_datastore_beats_the_destination() {
        let mut storage = BackupStorage {
            storage_type: StorageType::Pbs,
            pbs_datastore: "explicit-store".into(),
            ..BackupStorage::default()
        };
        apply_pbs_target(&mut storage, &pbs_target_fixture());
        assert_eq!(storage.pbs_datastore, "explicit-store",
            "a value already on the backup must never be overwritten");
    }

    #[test]
    fn destination_can_point_at_a_different_server() {
        let target = PbsTarget {
            pbs_server: "pbs2.example".into(),
            pbs_datastore: "offsite".into(),
            pbs_user: "backup@pbs".into(),
            ..pbs_target_fixture()
        };
        let mut storage = BackupStorage {
            storage_type: StorageType::Pbs,
            ..BackupStorage::default()
        };
        apply_pbs_target(&mut storage, &target);
        assert_eq!(storage.pbs_server, "pbs2.example");
        assert_eq!(storage.pbs_datastore, "offsite");
        assert_eq!(storage.pbs_user, "backup@pbs");
    }

    #[test]
    fn destination_file_level_applies_only_when_deliberate() {
        // Not deliberately set → leave the flag alone so the primary
        // connection's default still decides.
        let mut storage = BackupStorage {
            storage_type: StorageType::Pbs,
            ..BackupStorage::default()
        };
        apply_pbs_target(&mut storage, &PbsTarget {
            pbs_file_level: true, pbs_file_level_set: false, ..pbs_target_fixture()
        });
        assert!(!storage.pbs_file_level_set, "must not claim an explicit choice");

        // Deliberately set → adopt it AND mark it explicit, otherwise an
        // off-by-default primary connection would override the choice.
        let mut storage = BackupStorage {
            storage_type: StorageType::Pbs,
            ..BackupStorage::default()
        };
        apply_pbs_target(&mut storage, &PbsTarget {
            pbs_file_level: true, pbs_file_level_set: true, ..pbs_target_fixture()
        });
        assert!(storage.pbs_file_level && storage.pbs_file_level_set);
    }

    #[test]
    fn per_backup_file_level_choice_beats_the_destination() {
        let mut storage = BackupStorage {
            storage_type: StorageType::Pbs,
            pbs_file_level: false,
            pbs_file_level_set: true,
            ..BackupStorage::default()
        };
        apply_pbs_target(&mut storage, &PbsTarget {
            pbs_file_level: true, pbs_file_level_set: true, ..pbs_target_fixture()
        });
        assert!(!storage.pbs_file_level,
            "an explicit per-backup OFF must survive a destination set to ON");
    }

    #[test]
    fn storage_without_a_target_id_is_unchanged_by_default() {
        // Golden Rule: every pre-existing config deserialises with an
        // empty pbs_target_id and must behave exactly as before.
        let json = r#"{"type":"pbs","pbs_server":"nas","pbs_datastore":"store"}"#;
        let storage: BackupStorage = serde_json::from_str(json).unwrap();
        assert!(storage.pbs_target_id.is_empty());
        assert_eq!(storage.pbs_datastore, "store");
    }

    #[test]
    fn archive_leaf_vs_contents_classification() {
        use std::collections::HashSet;
        let set = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<HashSet<_>>();

        // Leaf-style: every top member is the folder's leaf name (how all
        // pre-trailing-slash backups were made) → restore into the PARENT.
        assert!(archive_is_leaf_style(&set(&["temp"]), "temp"));
        // Contents-only: bare children → restore into the FOLDER itself.
        assert!(!archive_is_leaf_style(&set(&["a", "b", "sub"]), "temp"));
        // A different single dir is not leaf-style for this folder.
        assert!(!archive_is_leaf_style(&set(&["other"]), "temp"));
        // Empty listing must not be mistaken for leaf-style.
        assert!(!archive_is_leaf_style(&HashSet::new(), "temp"));
    }

    #[test]
    fn pbs_file_level_skip_note_only_for_inapplicable_pbs() {
        let mut pbs = BackupStorage { storage_type: StorageType::Pbs, pbs_file_level: true, ..Default::default() };
        let vm = BackupTarget { target_type: BackupTargetType::Vm, ..Default::default() };
        let docker = BackupTarget { target_type: BackupTargetType::Docker, ..Default::default() };
        // VM can't do file-level → a note.
        assert!(pbs_file_level_skip_note(&vm, &pbs).is_some());
        // Docker WILL use pxar → no note.
        assert!(pbs_file_level_skip_note(&docker, &pbs).is_none());
        // file-level off → never a note, even for VM.
        pbs.pbs_file_level = false;
        assert!(pbs_file_level_skip_note(&vm, &pbs).is_none());
        // non-PBS storage → never a note.
        let local = BackupStorage { storage_type: StorageType::Local, pbs_file_level: true, ..Default::default() };
        assert!(pbs_file_level_skip_note(&vm, &local).is_none());
    }

    #[test]
    fn config_backups_do_file_level_pxar() {
        // wabil 2026-07-08: "I want to use PBS to grab that one file" — config
        // backups must honour the file-level option, not silently fall back.
        let cfg = BackupTarget { target_type: BackupTargetType::Config, ..Default::default() };
        assert!(pbs_file_level_applies(&cfg));
        let pbs = BackupStorage { storage_type: StorageType::Pbs, pbs_file_level: true, ..Default::default() };
        assert!(pbs_file_level_skip_note(&cfg, &pbs).is_none(), "no fallback note — config uses pxar now");
        assert!(backup_format_explainer(&cfg, &pbs).contains("pxar file-level"));
        // Flag off → still the tarball wrapped in PBS, stated as such.
        let pbs_off = BackupStorage { storage_type: StorageType::Pbs, pbs_file_level: false, ..Default::default() };
        assert!(backup_format_explainer(&cfg, &pbs_off).contains("tar.gz"));
    }

    #[test]
    fn config_pxar_backup_id_is_stable_and_sanitized() {
        // Backup writes with the local hostname; restore re-derives from the
        // hostname recorded in the entry — the two must be identical, and odd
        // hostnames must sanitize the same way every time.
        assert_eq!(config_pxar_backup_id("ninni"), config_pxar_backup_id("ninni"));
        let id = config_pxar_backup_id("my host.local");
        assert!(id.starts_with("wolfstack-config-"), "got: {}", id);
        assert!(!id.contains(' '), "sanitized: {}", id);
    }

    /// Every node used to emit `config-wolfstack-<ts>.tar.gz`, so all of them
    /// landed in the single PBS group `host/wolfstack` (67 snapshots from four
    /// machines, live fleet 2026-08-25). The node must be part of the id.
    #[test]
    fn config_archive_id_is_node_scoped() {
        assert_ne!(config_archive_node_id("wolfstack-1"), config_archive_node_id("wolfstack-2"));
        assert_eq!(config_archive_node_id("wolfstack-1"), "wolfstack-1");
        // Round-trips through the filename back to a per-node PBS group.
        let f1 = format!("config-{}-20260825-020530.tar.gz", config_archive_node_id("wolfstack-1"));
        let f2 = format!("config-{}-20260825-020530.tar.gz", config_archive_node_id("wolfstack-2"));
        assert_eq!(pbs_group_for_filename(&f1), "host/wolfstack-1");
        assert_eq!(pbs_group_for_filename(&f2), "host/wolfstack-2");
    }

    /// `extract_backup_id_from_filename` stops at the first 8-digit segment,
    /// treating it as the timestamp. A hostname that IS eight digits would be
    /// eaten, collapsing every node back onto one group.
    #[test]
    fn config_archive_id_survives_an_all_digit_hostname() {
        let id = config_archive_node_id("12345678");
        let f = format!("config-{}-20260825-020530.tar.gz", id);
        assert_eq!(pbs_group_for_filename(&f), format!("host/{}", id));
        assert_ne!(pbs_group_for_filename(&f), "host/");
    }

    /// Store and restore derive the PBS type from the same helper. They had
    /// drifted: `docker-…` was stored as "ct" but looked up as "host".
    #[test]
    fn pbs_backup_type_covers_docker_on_every_path() {
        assert_eq!(pbs_backup_type_for_filename("docker-myapp-20260825-1.tar.gz"), "ct");
        assert_eq!(pbs_backup_type_for_filename("vzdump-docker-myapp-20260825-1.tar.zst"), "ct");
        assert_eq!(pbs_backup_type_for_filename("vzdump-lxc-131-2026_08_25-03_00_00.tar.zst"), "ct");
        assert_eq!(pbs_backup_type_for_filename("lxc-myct-20260825-1.tar.gz"), "ct");
        assert_eq!(pbs_backup_type_for_filename("vm-myvm-20260825-1.tar.gz"), "vm");
        assert_eq!(pbs_backup_type_for_filename("vzdump-qemu-101-2026_08_25-03_00_00.vma.zst"), "vm");
        assert_eq!(pbs_backup_type_for_filename("config-wolfstack-1-20260825-020530.tar.gz"), "host");
        assert_eq!(pbs_group_for_filename("vzdump-lxc-131-2026_08_25-03_00_00.tar.zst"), "ct/131");
    }

    #[test]
    fn pbs_notes_positionals_never_emit_dashdash_separator() {
        // The PBS CLI (proxmox-router) does NOT honour `--` as an end-of-options
        // separator — passing one made it the <snapshot> positional and pushed
        // the real notes text into "got additional arguments", failing every
        // snapshot-notes call (wabil 2026-06-21). Guard the exact argv: two
        // positionals, in order, and no `--`.
        let snap = "host/test-318c10c7/2026-06-21T18:18:21Z";
        let notes = "Cluster: mycluster | Node: mypm | [mycluster] System folder: test (/mnt/x/test/)";
        let p = pbs_notes_positionals(snap, notes);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0], snap);
        assert_eq!(p[1], notes);
        assert!(!p.iter().any(|a| a == "--"),
            "no `--` separator: PBS CLI treats it as a literal positional");
    }

    fn wd(path: &str, sub: &str) -> BackupStorage {
        BackupStorage {
            storage_type: StorageType::Wolfdisk,
            path: path.to_string(),
            wolfdisk_subpath: sub.to_string(),
            ..BackupStorage::default()
        }
    }

    #[test]
    fn resolved_local_path_no_subpath_returns_mount_root() {
        let s = wd("/mnt/wolfdisk-data", "");
        assert_eq!(s.resolved_local_path(), "/mnt/wolfdisk-data");
    }

    #[test]
    fn pbs_fingerprint_gets_colons_when_pasted_without_them() {
        // 64 hex chars, no separators → colon-separated (what the client needs).
        let raw = "650b69e1c2d3a4b5e6f70819202122232425262728292a2b2c2d2e2f30313233";
        let out = format_pbs_fingerprint(raw);
        assert_eq!(out, "65:0b:69:e1:c2:d3:a4:b5:e6:f7:08:19:20:21:22:23:24:25:26:27:28:29:2a:2b:2c:2d:2e:2f:30:31:32:33");
        assert_eq!(out.matches(':').count(), 31); // 32 bytes → 31 separators
    }

    #[test]
    fn pbs_fingerprint_already_coloned_is_idempotent() {
        let coloned = "65:0b:69:e1:c2:d3:a4:b5:e6:f7:08:19:20:21:22:23:24:25:26:27:28:29:2a:2b:2c:2d:2e:2f:30:31:32:33";
        assert_eq!(format_pbs_fingerprint(coloned), coloned);
        // Whitespace/newlines from a paste are tolerated too.
        assert_eq!(format_pbs_fingerprint(&format!("  {coloned}\n")), coloned);
    }

    fn pbs(user: &str, token: &str) -> BackupStorage {
        BackupStorage {
            storage_type: StorageType::Pbs,
            pbs_user: user.to_string(),
            pbs_token_name: token.to_string(),
            pbs_server: "pbs.example.com".to_string(),
            pbs_datastore: "store".to_string(),
            ..BackupStorage::default()
        }
    }

    #[test]
    fn pbs_repo_token_form_when_user_has_realm_only() {
        assert_eq!(pbs_repo_string(&pbs("root@pam", "wolfstack-backup")),
                   "root@pam!wolfstack-backup@pbs.example.com:store");
    }

    #[test]
    fn pbs_repo_does_not_double_the_token_when_user_already_has_it() {
        // Operator pasted the whole `root@pam!wolfstack-backup` into the user
        // field AND set the token name — must not produce a doubled `!token`.
        assert_eq!(pbs_repo_string(&pbs("root@pam!wolfstack-backup", "wolfstack-backup")),
                   "root@pam!wolfstack-backup@pbs.example.com:store");
    }

    #[test]
    fn pbs_repo_full_principal_in_token_field() {
        // Livid's case: user=root@pam, and the WHOLE `root@pam!wolfstack-backup`
        // (the form the PBS UI shows) pasted into the token-NAME field. Must not
        // double the user prefix.
        assert_eq!(pbs_repo_string(&pbs("root@pam", "root@pam!wolfstack-backup")),
                   "root@pam!wolfstack-backup@pbs.example.com:store");
    }

    #[test]
    fn pbs_repo_full_token_in_user_with_no_token_name() {
        assert_eq!(pbs_repo_string(&pbs("root@pam!wolfstack-backup", "")),
                   "root@pam!wolfstack-backup@pbs.example.com:store");
    }

    #[test]
    fn pbs_repo_password_auth_no_token() {
        assert_eq!(pbs_repo_string(&pbs("root@pam", "")),
                   "root@pam@pbs.example.com:store");
    }

    #[test]
    fn pbs_fingerprint_non_sha256_passes_through_untouched() {
        // Not a clean 64-char hex string → returned trimmed, never mangled.
        assert_eq!(format_pbs_fingerprint("  not-a-fingerprint  "), "not-a-fingerprint");
        assert_eq!(format_pbs_fingerprint(""), "");
    }

    #[test]
    fn resolved_local_path_joins_subpath() {
        let s = wd("/mnt/wolfdisk-data", "backups/prod");
        assert_eq!(s.resolved_local_path(), "/mnt/wolfdisk-data/backups/prod");
    }

    #[test]
    fn resolved_local_path_strips_leading_trailing_slashes() {
        let s = wd("/mnt/wolfdisk-data/", "/backups/prod/");
        assert_eq!(s.resolved_local_path(), "/mnt/wolfdisk-data/backups/prod");
    }

    #[test]
    fn resolved_local_path_drops_dot_dot_segments() {
        // The lenient resolver is defence in depth — the API save
        // boundary rejects `..` outright, but if a hand-edited
        // config file makes it past, we still don't escape the mount.
        let s = wd("/mnt/wolfdisk-data", "../../etc/passwd");
        assert_eq!(s.resolved_local_path(), "/mnt/wolfdisk-data/etc/passwd");
    }

    #[test]
    fn resolved_local_path_for_local_returns_path_unchanged() {
        let s = BackupStorage {
            storage_type: StorageType::Local,
            path: "/var/lib/wolfstack/backups".into(),
            wolfdisk_subpath: "ignored".into(),  // shouldn't apply for Local
            ..BackupStorage::default()
        };
        assert_eq!(s.resolved_local_path(), "/var/lib/wolfstack/backups");
    }

    #[test]
    fn with_concrete_local_fills_empty_local_path() {
        let s = BackupStorage {
            storage_type: StorageType::Local,
            path: String::new(),
            ..BackupStorage::default()
        };
        // An empty Local path is concretized to the configured default, so the
        // stored entry is self-sufficient at restore time.
        assert_eq!(s.with_concrete_local("/mnt/r2-backups").path, "/mnt/r2-backups");
    }

    #[test]
    fn with_concrete_local_keeps_nonempty_local_path() {
        let s = BackupStorage {
            storage_type: StorageType::Local,
            path: "/data/backups".into(),
            ..BackupStorage::default()
        };
        assert_eq!(s.with_concrete_local("/mnt/r2-backups").path, "/data/backups");
    }

    #[test]
    fn with_concrete_local_ignores_non_local_types() {
        let s = BackupStorage {
            storage_type: StorageType::S3,
            path: String::new(),
            ..BackupStorage::default()
        };
        assert_eq!(s.with_concrete_local("/mnt/r2-backups").path, "");
    }

    #[test]
    fn validate_subpath_rejects_dot_dot() {
        assert!(BackupStorage::validate_wolfdisk_subpath("../etc").is_err());
        assert!(BackupStorage::validate_wolfdisk_subpath("backups/../../etc").is_err());
    }

    #[test]
    fn validate_subpath_rejects_single_dot() {
        // Resolver silently strips `.` segments; the validator
        // rejects them so the operator gets clear feedback rather
        // than a surprise normalisation.
        assert!(BackupStorage::validate_wolfdisk_subpath("./backups").is_err());
        assert!(BackupStorage::validate_wolfdisk_subpath("backups/./prod").is_err());
    }

    #[test]
    fn validate_subpath_rejects_consecutive_slashes() {
        assert!(BackupStorage::validate_wolfdisk_subpath("backups//prod").is_err());
    }

    #[test]
    fn validate_subpath_accepts_empty_and_normal() {
        assert!(BackupStorage::validate_wolfdisk_subpath("").is_ok());
        assert!(BackupStorage::validate_wolfdisk_subpath("   ").is_ok());
        assert!(BackupStorage::validate_wolfdisk_subpath("backups").is_ok());
        assert!(BackupStorage::validate_wolfdisk_subpath("backups/prod").is_ok());
        assert!(BackupStorage::validate_wolfdisk_subpath("/backups/prod/").is_ok());
    }

    // ── Feature 1: mount exclusion matching ──

    #[test]
    fn mount_exclude_exact_match() {
        let ex = vec!["/mnt/media".to_string()];
        assert!(mount_is_excluded("/mnt/media", &ex));
        assert!(mount_is_excluded("/mnt/media/", &ex)); // trailing slash normalised
    }

    #[test]
    fn mount_exclude_prefix_match() {
        let ex = vec!["/mnt/media".to_string()];
        assert!(mount_is_excluded("/mnt/media/tv", &ex));
        assert!(mount_is_excluded("/mnt/media/movies/4k", &ex));
    }

    #[test]
    fn mount_exclude_no_false_prefix() {
        // "/mnt/media2" must NOT be caught by an exclude of "/mnt/media".
        let ex = vec!["/mnt/media".to_string()];
        assert!(!mount_is_excluded("/mnt/media2", &ex));
        assert!(!mount_is_excluded("/mnt/other", &ex));
    }

    #[test]
    fn mount_exclude_volume_name() {
        let ex = vec!["pgdata".to_string()];
        assert!(mount_is_excluded("pgdata", &ex));
        assert!(!mount_is_excluded("pgdata-backup", &ex));
    }

    #[test]
    fn mount_exclude_empty_list_matches_nothing() {
        // Golden Rule: no exclusions configured → nothing skipped, so existing
        // targets back up byte-identically.
        assert!(!mount_is_excluded("/mnt/media", &[]));
        assert!(!mount_is_excluded("anyvol", &[]));
    }

    #[test]
    fn mount_exclude_ignores_empty_entries() {
        // An empty exclude entry must NOT match everything.
        let ex = vec!["".to_string(), "   ".to_string()];
        assert!(!mount_is_excluded("/mnt/media", &ex));
    }

    #[test]
    fn mount_exclude_trailing_slash_on_entry() {
        let ex = vec!["/mnt/media/".to_string()];
        assert!(mount_is_excluded("/mnt/media", &ex));
        assert!(mount_is_excluded("/mnt/media/tv", &ex));
    }

    // ── Feature 3: system-path validation ──

    #[test]
    fn system_path_rejects_relative() {
        assert!(validate_system_path("etc").is_err());
        assert!(validate_system_path("").is_err());
    }

    #[test]
    fn system_path_rejects_dangerous_roots() {
        assert!(validate_system_path("/").is_err());
        assert!(validate_system_path("/proc").is_err());
        assert!(validate_system_path("/sys").is_err());
        assert!(validate_system_path("/dev").is_err());
        assert!(validate_system_path("/proc/1").is_err());
        assert!(validate_system_path("/sys/kernel").is_err());
    }

    #[test]
    fn system_path_accepts_existing_dir() {
        // /tmp always exists and is a directory on a Linux test host.
        assert!(validate_system_path("/tmp").is_ok());
        assert!(validate_system_path("/tmp/").is_ok());
    }

    #[test]
    fn system_path_rejects_nonexistent() {
        assert!(validate_system_path("/this/does/not/exist/anywhere-xyz").is_err());
    }

    // ── Feature 2: PBS file-level entry detection ──

    #[test]
    fn file_level_entry_detected_by_prefix_and_type() {
        let mut e = BackupEntry {
            id: "x".into(),
            target: BackupTarget { target_type: BackupTargetType::Lxc, name: "ct1".into(), ..Default::default() },
            storage: BackupStorage { storage_type: StorageType::Pbs, ..BackupStorage::default() },
            filename: "pbsfl-ct-ct1-20260620-101010.pxar".into(),
            size_bytes: 0, created_at: String::new(), status: BackupStatus::Completed,
            error: String::new(), schedule_id: String::new(), comments: String::new(),
            node_hostname: String::new(), docker_config: String::new(), mounts: Vec::new(),
        };
        assert!(is_pbs_file_level_entry(&e));
        // A tarball-in-pxar PBS entry is NOT file-level.
        e.filename = "lxc-ct1-20260620-101010.tar.gz".into();
        assert!(!is_pbs_file_level_entry(&e));
        // A local backup with a pbsfl-ish name is NOT file-level (wrong storage).
        e.filename = "pbsfl-ct-ct1-20260620-101010.pxar".into();
        e.storage.storage_type = StorageType::Local;
        assert!(!is_pbs_file_level_entry(&e));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BackupFrequency {
    Daily,
    Weekly,
    Monthly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSchedule {
    pub id: String,
    pub name: String,
    pub frequency: BackupFrequency,
    /// Time of day to run (HH:MM format)
    pub time: String,
    /// Number of backups to keep (0 = unlimited)
    pub retention: u32,
    /// Backup all targets or specific list
    pub backup_all: bool,
    /// The targets to back up when `backup_all` is false.
    ///
    /// When `backup_all` is true the list is resolved live at each run, and
    /// any entries here are per-container OVERRIDES for that live set: a
    /// Docker/LXC entry whose `exclude_mounts` is non-empty keeps those mounts
    /// out of that container's archive (`mount_overrides_for`). Nothing else
    /// on an override is read. Before this, "back up everything" had nowhere
    /// to store an exclusion at all — the modal offered "Choose mounts",
    /// accepted the unticks, then saved `targets: []` and lost them (JJ
    /// 2026-09-18: unticking a storage mount, then Save, changed nothing).
    #[serde(default)]
    pub targets: Vec<BackupTarget>,
    /// Where to store backups
    pub storage: BackupStorage,
    pub enabled: bool,
    /// Last time this schedule ran (ISO 8601)
    #[serde(default)]
    pub last_run: String,
    /// When this schedule was created (ISO 8601). Lets the freshness analyzer
    /// give a brand-new schedule one full interval before alarming that it has
    /// "never run" — otherwise a schedule created at 21:06 flags instantly even
    /// though its first nightly run is hours away (wabil 2026-06-22). Empty on
    /// schedules created before this field existed → treated as "unknown age",
    /// which preserves the prior (fire-immediately) behaviour for them.
    #[serde(default)]
    pub created_at: String,
    /// Shell command run on this node BEFORE the backup starts (empty = none).
    /// Non-zero exit or timeout aborts the run — no backups are taken — and a
    /// Failed entry records the output so the abort is visible in the Backups
    /// list (wabil 2026-07-02: quiesce databases / take a ZFS snapshot first).
    #[serde(default)]
    pub pre_command: String,
    /// Shell command run on this node AFTER the backup finishes (empty = none).
    /// Always runs — even when the backup or the pre-command failed — because
    /// it is the cleanup path (restart containers, drop the snapshot) and
    /// skipping it would leave the system in the "quiesced" state forever.
    /// Its failure is recorded as a Failed entry but never un-completes
    /// backups that already succeeded.
    #[serde(default)]
    pub post_command: String,
    /// `Weekly` schedules: which weekday to run on, ISO-numbered
    /// (1 = Monday … 7 = Sunday, matching `Weekday::number_from_monday`).
    /// `None` on every schedule saved before day pinning existed (JJ
    /// 2026-08-19: weekly/monthly offered a time but no day), and those keep
    /// the original behaviour — "any day, once seven days have passed" — so no
    /// existing schedule changes when it is picked up.
    #[serde(default)]
    pub day_of_week: Option<u8>,
    /// `Monthly` schedules: which day of the month to run on (1–31). A day
    /// past the end of a short month runs on that month's LAST day (31 in
    /// February fires on the 28th/29th) rather than being skipped. `None`
    /// keeps the original behaviour — the first time-of-day match in a
    /// calendar month.
    #[serde(default)]
    pub day_of_month: Option<u8>,
    /// `backup_all` schedules: stop each container for the duration of its
    /// backup (a cold, fully consistent archive) instead of backing it up
    /// live. Per-target `BackupTarget::stop_for_backup` cannot express this
    /// when the target list is resolved at run time, so a schedule-wide flag
    /// carries it (JJ 2026-08-19: ticking the per-container box under "back up
    /// everything" was silently discarded — `targets` is empty there).
    /// Ignored when `backup_all` is false; the per-target flag governs then.
    #[serde(default)]
    pub stop_containers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BackupStatus {
    Completed,
    Failed,
    InProgress,
}

/// One Docker mount captured into a backup. Lets the UI show what's in
/// each backup ("3 volumes, 2 binds") without re-reading the tarball,
/// and the restore path knows where to put each piece back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    /// "volume" | "bind" | "tmpfs" (tmpfs is recorded for visibility but
    /// never actually backed up — it's by definition ephemeral).
    #[serde(rename = "type")]
    pub mount_type: String,
    /// For volume: the named-volume name. For bind: the host source path.
    pub source: String,
    /// Where the container sees this mounted (e.g. "/var/lib/postgresql/data").
    pub destination: String,
    /// Filename inside the wrapper tarball (`volumes/vol-foo.tar.gz` or
    /// `binds/bind-0.tar.gz`). Empty when this mount was skipped (tmpfs,
    /// missing source, or refused by the safety deny-list).
    #[serde(default)]
    pub archive_path: String,
    /// On-disk size of the tarball (uncompressed source size hint).
    #[serde(default)]
    pub size_bytes: u64,
    /// Reason this mount was skipped, if any (deny-list, missing source,
    /// tmpfs, etc.). Empty when the mount was successfully archived.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub skipped_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    pub id: String,
    pub target: BackupTarget,
    pub storage: BackupStorage,
    pub filename: String,
    pub size_bytes: u64,
    pub created_at: String,
    pub status: BackupStatus,
    #[serde(default)]
    pub error: String,
    /// Schedule ID that created this, if any
    #[serde(default)]
    pub schedule_id: String,
    /// Description of what was backed up (e.g. container image, LXC rootfs, VM disks)
    #[serde(default)]
    pub comments: String,
    /// Hostname of the node that performed the backup
    #[serde(default)]
    pub node_hostname: String,
    /// Docker container config (docker inspect JSON) for restoring with original settings
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub docker_config: String,
    /// Mounts captured into this backup (Docker only). Empty for non-
    /// Docker entries and for legacy backups created before v20.11.0
    /// (those used a flat `docker save | gzip` with no volume capture).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountInfo>,
}

/// Permissive deny-list of host paths we refuse to back up via bind
/// mounts. Backing these up is either catastrophic (root, /var/lib/docker
/// recursion, kernel virtual filesystems) or pointlessly dangerous —
/// the user almost certainly did not mean to capture these into a user-
/// accessible tarball. Subpaths of /etc, /sys, /proc, /dev, /boot are
/// blocked too (their content is system state, not application data).
/// Everything else is allowed — admins binding /opt/myapp, /srv/data,
/// /home/x/stuff, /var/www, /var/log/myapp, /mnt/disk, etc. all work.
fn bind_source_safe(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("source path is empty".into());
    }
    let canonical = path.trim_end_matches('/');
    if canonical.is_empty() || canonical.is_empty() {
        return Err("refusing to back up the host root filesystem '/'".into());
    }
    let exact_deny: &[&str] = &[
        "/", "/usr", "/lib", "/lib64", "/bin", "/sbin", "/var", "/run", "/tmp",
    ];
    if exact_deny.contains(&canonical) {
        return Err(format!("refusing to back up system path '{}' — bind a specific subdirectory instead", canonical));
    }
    let prefix_deny: &[&str] = &[
        "/etc", "/sys", "/proc", "/dev", "/boot", "/var/lib/docker",
    ];
    for p in prefix_deny {
        if canonical == *p || canonical.starts_with(&format!("{}/", p)) {
            return Err(format!(
                "refusing to back up '{}' — paths under {} are system state and not safe to archive",
                canonical, p
            ));
        }
    }
    Ok(())
}

/// Does `candidate` (a bind source path or a named-volume name) match any
/// entry in the operator's exclude list? Match is either exact, or a
/// trailing-slash prefix so excluding `/mnt/media` also excludes
/// `/mnt/media/tv`. Trailing slashes on the exclude entry itself are
/// normalised away so `/mnt/media/` and `/mnt/media` behave the same.
/// Empty exclude entries are ignored (they'd otherwise match everything).
fn mount_is_excluded(candidate: &str, exclude_mounts: &[String]) -> bool {
    let cand = candidate.trim_end_matches('/');
    exclude_mounts.iter().any(|raw| {
        let ex = raw.trim().trim_end_matches('/');
        if ex.is_empty() {
            return false;
        }
        cand == ex || cand.starts_with(&format!("{}/", ex))
    })
}

/// One bind/volume mount discovered on a container, for the UI's
/// "choose what to exclude" checklist. Distinct from `MountInfo` (which
/// records what actually went INTO a backup) — this is a pre-backup
/// inventory with no archive yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredMount {
    /// "volume" | "bind"
    #[serde(rename = "type")]
    pub mount_type: String,
    /// Named-volume name (volume) or host source path (bind). This is the
    /// value the operator puts in `exclude_mounts` to skip it.
    pub source: String,
    /// Mount point inside the container.
    pub destination: String,
    /// On-disk size of the source in bytes. 0 when `size_basis` says there was
    /// nothing to measure ("missing") or it could not be measured ("unknown").
    #[serde(default)]
    pub size_bytes: u64,
    /// How `size_bytes` was arrived at, so nothing downstream has to guess
    /// whether it is a measurement or a bound:
    ///   "walked"     — a full `du` of the tree completed: exact.
    ///   "filesystem" — the source IS a filesystem root, so its used bytes
    ///                  are the filesystem's used bytes. Instant, and an
    ///                  upper bound if anything else shares that filesystem.
    ///   "declared"   — the size the container config declares for a
    ///                  storage-backed volume (Proxmox `size=8G`): provisioned,
    ///                  not used, so an upper bound.
    ///   "missing"    — the source is not on this host, so it holds nothing.
    ///   "unknown"    — too big to walk inside the deadline, or unstattable.
    ///                  `size_bytes` is 0 and `fs_used_bytes`, when non-zero,
    ///                  is the only ceiling available.
    #[serde(default)]
    pub size_basis: String,
    /// Used bytes of the filesystem the source lives on, 0 when `df` could not
    /// say. The one number available for an unmeasurable tree — a mount whose
    /// size is unknown cannot hold more than this.
    #[serde(default)]
    pub fs_used_bytes: u64,
    /// Absolute path whose contents this mount contributes to an archive: the
    /// host source for a bind, the resolved `_data` directory for a named
    /// volume, empty for a storage-backed Proxmox volume that has no host path.
    /// Internal plumbing (the size guard and the pxar packer both need it);
    /// the browser has no use for it, so it is not serialized.
    #[serde(default, skip_serializing)]
    pub data_path: String,
}

/// Exact directory size, by walking the whole tree. Slow on a big one by
/// definition — every caller of this must be somewhere minutes of `du` is
/// acceptable (the pre-backup staging guard, which is followed by an archive
/// of the same tree). The inventory and warning paths use
/// `measure_mount_size` instead. Failure (missing path, permission) → 0.
fn quick_dir_size_bytes(path: &str) -> u64 {
    // `du -sb` reports apparent total bytes for the whole tree. It's the
    // same tool the rest of the codebase shells out to and avoids a manual
    // recursive walk here.
    let out = match Command::new("du").args(["-sb", path]).output() {
        Ok(o) if o.status.success() => o,
        _ => return 0,
    };
    let s = String::from_utf8_lossy(&out.stdout);
    s.split_whitespace().next()
        .and_then(|first| first.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Wall-clock cap on measuring ONE mount for the inventory / warning paths.
/// Those run while an operator waits on a click, so a tree that cannot be
/// walked in this long is reported as unmeasured rather than holding the
/// request open. 5s walks millions of inodes on a warm cache.
const MOUNT_SIZE_DEADLINE_SECS: u64 = 5;

/// `du -sb`, abandoned (and the child killed) if it outlives `deadline`.
/// `None` on timeout, failure, or unparseable output.
fn dir_size_bytes_within(path: &str, deadline: std::time::Duration) -> Option<u64> {
    use std::io::Read;
    use std::process::Stdio;

    let mut child = Command::new("du")
        .args(["-sb", path])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                // `du -sb` writes one short line, so this read cannot block on
                // a full pipe — and the child has already exited.
                let mut out = String::new();
                child.stdout.as_mut()?.read_to_string(&mut out).ok()?;
                return out.split_whitespace().next()?.parse::<u64>().ok();
            }
            Ok(None) => {
                if started.elapsed() >= deadline {
                    // Killed rather than left running: it would keep churning
                    // the page cache on a 20 TB array for nothing.
                    let _ = child.kill();
                    let _ = child.wait();
                    warn!(
                        "backup: gave up measuring {} after {}s — reported as unmeasured",
                        path, deadline.as_secs()
                    );
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
}

/// Mount point and used bytes of the filesystem holding `path`.
/// `--output=used,target` puts the number first, so the remainder of the line
/// is the mount point even when it contains spaces.
fn filesystem_usage(path: &str) -> Option<(String, u64)> {
    let out = Command::new("df")
        .args(["-B1", "--output=used,target"])
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().nth(1)?.trim();
    let (used, target) = line.split_once(char::is_whitespace)?;
    Some((target.trim().to_string(), used.parse::<u64>().ok()?))
}

/// True when the two paths are the same directory, comparing what the
/// filesystem resolves them to (`df` prints the canonical mount point, the
/// bind source may reach it through a symlink).
fn same_directory(a: &str, b: &str) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// Fast, bounded size estimate for one mount source: `(bytes, basis,
/// filesystem used bytes)` as described on `DiscoveredMount::size_basis`.
///
/// Deliberately NOT what the staging-space guard uses. The guard refuses
/// backups, so it needs the true size and takes the slow walk; this one feeds
/// a checklist and a warning dialog, where a bound the operator can see the
/// basis of beats a spinner. The filesystem-root shortcut is the case that
/// matters: a 20 TB datastore bound into a container (klas 2026-08-20) is a
/// mounted array, and walking it is minutes of disk churn for a number `df`
/// already knows.
fn measure_mount_size(path: &str) -> (u64, &'static str, u64) {
    if path.is_empty() {
        return (0, "missing", 0);
    }
    match Path::new(path).try_exists() {
        Ok(true) => {}
        // Not on this host: an absent bind source (Docker creates it on start)
        // holds nothing. Distinct from "unknown" so it is never warned about
        // as an unmeasurable mount — a distinction the live probe forced, since
        // every unreadable volume directory looked like a 20 TB array.
        Ok(false) => return (0, "missing", 0),
        // Cannot even stat it — permission, or a hung network mount. Genuinely
        // unknown, and worth saying so rather than calling it empty.
        Err(_) => return (0, "unknown", 0),
    }
    let usage = filesystem_usage(path);
    let fs_used = usage.as_ref().map(|(_, used)| *used).unwrap_or(0);
    if let Some((_, used)) = usage.as_ref().filter(|(mp, _)| same_directory(mp, path)) {
        return (*used, "filesystem", fs_used);
    }
    match dir_size_bytes_within(path, std::time::Duration::from_secs(MOUNT_SIZE_DEADLINE_SECS)) {
        Some(bytes) => (bytes, "walked", fs_used),
        None => (0, "unknown", fs_used),
    }
}

/// Enumerate a Docker container's bind/volume mounts (no backup performed).
/// Reuses the same `docker inspect` Mounts[] parsing as `backup_docker`.
pub fn discover_docker_mounts(name: &str) -> Result<Vec<DiscoveredMount>, String> {
    let inspect = Command::new("docker")
        .args(["inspect", name])
        .output()
        .map_err(|e| format!("Failed to run docker inspect: {}", e))?;
    if !inspect.status.success() {
        return Err(format!(
            "docker inspect {} failed: {}",
            name,
            String::from_utf8_lossy(&inspect.stderr).trim()
        ));
    }
    let inspect_val: serde_json::Value =
        serde_json::from_slice(&inspect.stdout).unwrap_or(serde_json::Value::Null);
    let mounts_arr = inspect_val
        .get(0)
        .and_then(|c| c.get("Mounts"))
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();

    let mut out = Vec::new();
    for m in &mounts_arr {
        let mtype = m.get("Type").and_then(|v| v.as_str()).unwrap_or("");
        let source = m.get("Source").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let destination = m.get("Destination").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let vol_name = m.get("Name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        match mtype {
            "volume" => {
                let label = if !vol_name.is_empty() { vol_name.clone() } else { source.clone() };
                let data_dir = if !source.is_empty() && Path::new(&source).is_dir() {
                    source.clone()
                } else if !vol_name.is_empty() {
                    format!("/var/lib/docker/volumes/{}/_data", vol_name)
                } else {
                    String::new()
                };
                let (size, basis, fs_used) = measure_mount_size(&data_dir);
                out.push(DiscoveredMount {
                    mount_type: "volume".into(),
                    source: label,
                    destination,
                    size_bytes: size,
                    size_basis: basis.into(),
                    fs_used_bytes: fs_used,
                    data_path: data_dir,
                });
            }
            "bind" => {
                let (size, basis, fs_used) = measure_mount_size(&source);
                out.push(DiscoveredMount {
                    mount_type: "bind".into(),
                    data_path: source.clone(),
                    source,
                    destination,
                    size_bytes: size,
                    size_basis: basis.into(),
                    fs_used_bytes: fs_used,
                });
            }
            _ => { /* tmpfs/npipe — never backed up, omit from the checklist */ }
        }
    }
    Ok(out)
}

/// Enumerate an LXC container's bind mounts (no backup performed).
/// Native LXC: parse `lxc.mount.entry` lines in the container config.
/// Proxmox: parse `mp<N>:` mountpoints from `pct config`.
pub fn discover_lxc_mounts(name: &str) -> Result<Vec<DiscoveredMount>, String> {
    // The native path builds a filesystem path out of this name, so it is
    // validated here rather than trusted: a container name is a name, and a
    // caller-supplied `../..` has no business reaching `read_to_string`.
    if name.is_empty() || name.contains('/') || name.contains("..") {
        return Err(format!("Invalid container name '{}'", name));
    }
    let mut out = Vec::new();
    if crate::containers::is_proxmox() {
        // `pct config <vmid>` → lines like `mp0: storage:vm-105-disk-1,mp=/data,size=8G`
        // or bind form `mp0: /host/path,mp=/data`. We expose the host source
        // (the part before the first comma) when it's an absolute path bind.
        let cfg = Command::new("pct").args(["config", name]).output()
            .map_err(|e| format!("Failed to run pct config: {}", e))?;
        if !cfg.status.success() {
            return Err(format!("pct config {} failed: {}", name,
                String::from_utf8_lossy(&cfg.stderr).trim()));
        }
        let text = String::from_utf8_lossy(&cfg.stdout);
        for line in text.lines() {
            let line = line.trim();
            // Match mp0:, mp1:, … (mountpoints). rootfs is excluded — it's the
            // container's own rootfs, always backed up.
            let rest = match line.strip_prefix("mp") {
                Some(r) => r, None => continue,
            };
            let colon = match rest.find(':') {
                Some(c) => c, None => continue,
            };
            let idx_part = &rest[..colon];
            if idx_part.is_empty() || !idx_part.chars().all(|c| c.is_ascii_digit()) { continue; }
            let spec = rest[colon + 1..].trim();
            let volume = spec.split(',').next().unwrap_or("").trim();
            // Bind mount form: the volume part is an absolute host path.
            let mut mountpoint = String::new();
            for opt in spec.split(',') {
                if let Some(mp) = opt.trim().strip_prefix("mp=") {
                    mountpoint = mp.to_string();
                }
            }
            if volume.starts_with('/') {
                let (size, basis, fs_used) = measure_mount_size(volume);
                out.push(DiscoveredMount {
                    mount_type: "bind".into(),
                    source: volume.to_string(),
                    destination: mountpoint,
                    size_bytes: size,
                    size_basis: basis.into(),
                    fs_used_bytes: fs_used,
                    data_path: volume.to_string(),
                });
            } else {
                // Storage-backed mountpoint (ZFS/LVM/dir volume). It IS part of
                // the vzdump backup; expose it so the operator can exclude it
                // by its volume id. There is no host path to walk, but `pct
                // config` states what was provisioned for it (`size=8G`) — an
                // upper bound, and the only figure available. Without even
                // that, the size is honestly unknown: with no filesystem
                // figure either, `mount_is_large` leaves it alone rather than
                // warning about every such mountpoint forever.
                let declared = spec.split(',')
                    .filter_map(|opt| opt.trim().strip_prefix("size="))
                    .find_map(crate::containers::lxc_storage::parse_size);
                out.push(DiscoveredMount {
                    mount_type: "volume".into(),
                    source: volume.to_string(),
                    destination: mountpoint,
                    size_bytes: declared.unwrap_or(0),
                    size_basis: if declared.is_some() { "declared" } else { "unknown" }.into(),
                    fs_used_bytes: 0,
                    data_path: String::new(),
                });
            }
        }
        return Ok(out);
    }

    // Native LXC — parse the container config for `lxc.mount.entry` lines.
    let base = crate::containers::lxc_base_dir(name);
    let cfg_path = format!("{}/{}/config", base, name);
    let text = fs::read_to_string(&cfg_path)
        .map_err(|e| format!("Failed to read LXC config {}: {}", cfg_path, e))?;
    for line in text.lines() {
        let line = line.trim();
        // lxc.mount.entry = <source> <mountpoint> <fstype> <options> <dump> <pass>
        if let Some(rest) = line.strip_prefix("lxc.mount.entry") {
            let rest = rest.trim_start_matches('=').trim();
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() < 2 { continue; }
            let source = parts[0];
            let mountpoint = parts[1];
            // Only host-path bind mounts are interesting — skip the kernel
            // pseudo-filesystems (proc/sysfs/etc.) whose source isn't a path.
            if !source.starts_with('/') { continue; }
            let (size, basis, fs_used) = measure_mount_size(source);
            out.push(DiscoveredMount {
                mount_type: "bind".into(),
                source: source.to_string(),
                destination: mountpoint.to_string(),
                size_bytes: size,
                size_basis: basis.into(),
                fs_used_bytes: fs_used,
                data_path: source.to_string(),
            });
        }
    }
    Ok(out)
}

// ─── Large-mount warning ────────────────────────────────────────────────────
//
// A container can be two gigabytes of application and twenty terabytes of
// bind-mounted array, and nothing in the picker said so until the backup was
// already running: the mount inventory is only opened by operators who already
// suspect a problem (klas 2026-08-20 — "I have one docker connected to a
// datastore that is 20TB in size. I obviously do not want to back that up").
// The staging-space guard eventually refuses such a backup, but only at run
// time, once a night, from a schedule saved days earlier. This is the same
// question asked while the operator is still looking at the screen.

/// A mount big enough that including it in a backup is more likely an
/// oversight than a decision.
///
/// 50 GB, not the 1 GB the report suggested: application volumes in the 1-20 GB
/// range are the *normal* thing to back up, and a dialog that fires on every
/// save is a dialog operators learn to dismiss without reading — which would
/// cost exactly the protection this exists to give. Anything past 50 GB is an
/// array, a media library or a dataset, and worth one question.
///
/// Binary, because the web UI's `formatBytes` divides by 1024 while labelling
/// the result "GB": 50 GiB is the value that prints as the "50 GB" the dialog
/// and the docs both promise. A decimal 50_000_000_000 rendered as "46.6 GB"
/// — verified in the browser, which is how this came to be a comment.
pub const LARGE_MOUNT_WARN_BYTES: u64 = 50 * 1024 * 1024 * 1024;

/// Total wall-clock budget for one mount-check request. Each mount is capped
/// by `MOUNT_SIZE_DEADLINE_SECS`, but a fleet-wide selection has many, and an
/// operator clicking Save is waiting on this. Targets not reached inside the
/// budget are reported as unchecked rather than silently dropped.
const MOUNT_CHECK_BUDGET_SECS: u64 = 15;

/// True when this mount is big enough to warn about.
fn mount_is_large(m: &DiscoveredMount) -> bool {
    match m.size_basis.as_str() {
        // Unmeasured: the filesystem it sits on is the only ceiling available,
        // and that ceiling is the warning — a tree that outran a 5s `du` on a
        // 20 TB array is exactly the case to flag. With no filesystem figure
        // either (a storage-backed volume with no host path) nothing is known
        // at all, and a warning with no number in it is noise, not protection.
        "unknown" => m.fs_used_bytes >= LARGE_MOUNT_WARN_BYTES,
        // Not on this host: it holds nothing, whatever its filesystem holds.
        "missing" => false,
        _ => m.size_bytes >= LARGE_MOUNT_WARN_BYTES,
    }
}

/// One target's large mounts, as the warning dialog needs them.
#[derive(Debug, Clone, Serialize)]
pub struct LargeMountFinding {
    #[serde(rename = "type")]
    pub target_type: String,
    pub name: String,
    /// Large mounts this backup WOULD include (exclusions already applied).
    pub mounts: Vec<DiscoveredMount>,
    /// Why this target could not be inspected, when it could not be. A
    /// stopped/removed container is not an error worth blocking a save over,
    /// so it is reported and the save continues.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Large mounts across `targets`, each `(type, name, already-excluded)`.
///
/// Only `docker` and `lxc` carry mounts; every other target type is skipped
/// silently so callers can pass a whole selection. Returns the findings and
/// the names of any targets the time budget did not reach.
pub fn large_mounts_for_targets(
    targets: &[(String, String, Vec<String>)],
) -> (Vec<LargeMountFinding>, Vec<String>) {
    let started = std::time::Instant::now();
    let budget = std::time::Duration::from_secs(MOUNT_CHECK_BUDGET_SECS);
    let mut findings = Vec::new();
    let mut unchecked = Vec::new();

    for (kind, name, exclude) in targets {
        if kind != "docker" && kind != "lxc" {
            continue;
        }
        if started.elapsed() >= budget {
            unchecked.push(name.clone());
            continue;
        }
        let discovered = if kind == "docker" {
            discover_docker_mounts(name)
        } else {
            discover_lxc_mounts(name)
        };
        match discovered {
            Ok(mounts) => {
                let large: Vec<DiscoveredMount> = mounts
                    .into_iter()
                    .filter(|m| !mount_is_excluded(&m.source, exclude))
                    .filter(mount_is_large)
                    .collect();
                if !large.is_empty() {
                    findings.push(LargeMountFinding {
                        target_type: kind.clone(),
                        name: name.clone(),
                        mounts: large,
                        error: None,
                    });
                }
            }
            Err(e) => findings.push(LargeMountFinding {
                target_type: kind.clone(),
                name: name.clone(),
                mounts: Vec::new(),
                error: Some(e),
            }),
        }
    }
    if !unchecked.is_empty() {
        warn!(
            "backup: mount check ran out of its {}s budget with {} target(s) unchecked: {}",
            MOUNT_CHECK_BUDGET_SECS,
            unchecked.len(),
            unchecked.join(", ")
        );
    }
    (findings, unchecked)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct BackupConfig {
    #[serde(default)]
    pub schedules: Vec<BackupSchedule>,
    #[serde(default)]
    pub entries: Vec<BackupEntry>,
}


// ─── Config Persistence ───

pub fn load_config() -> BackupConfig {
    match fs::read_to_string(backup_config_path()) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => BackupConfig::default(),
    }
}

pub fn save_config(config: &BackupConfig) -> Result<(), String> {
    let path = backup_config_path();
    let dir = Path::new(&path).parent().unwrap();
    fs::create_dir_all(dir).map_err(|e| format!("Failed to create config dir: {}", e))?;
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize backup config: {}", e))?;
    // 0600, not whatever the umask happens to be. This file holds
    // `pbs_password`, `smb_password`, `secret_key`, `access_key` and
    // `pbs_token_secret` in cleartext, and a plain `fs::write` shipped it
    // 0644 root:root — any local user could read the backup server's password
    // (production report, 3-node "wolf" cluster, 2026-07-30). `write_secure`
    // also re-chmods a file that already exists with looser permissions, so an
    // install that has been leaking since v18 is fixed by its next write;
    // `paths::harden_existing` catches the ones that never write again.
    crate::paths::write_secure(&path, json)
        .map_err(|e| format!("Failed to write backup config: {}", e))
}

// ─── Backup Functions ───

/// Staging paths belonging to a backup that is running right now. The sweeper
/// refuses to touch these however old they look, so a genuinely long job can
/// never have its own work deleted out from under it.
static ACTIVE_STAGING: LazyLock<Mutex<std::collections::HashSet<PathBuf>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

/// A staging file or directory that is deleted when it goes out of scope,
/// unless the backup completed and called `keep()`.
///
/// Backups leaked disk on every failure before this existed: `tar` leaves the
/// partial archive behind when it exits non-zero (verified: a failed tar still
/// leaves its bytes on disk), the Docker path returned early through `?` after
/// a multi-gigabyte `docker save`, and nothing ever swept staging afterwards.
/// The worst of it was that the errors which skipped cleanup — write failures
/// mid-archive — are exactly what a full disk produces, so a filling disk made
/// itself fill faster. A guard is used rather than cleanup calls on each exit
/// path because the leaking paths were precisely the ones nobody remembered to
/// add a cleanup call to.
struct StagedPath {
    path: PathBuf,
    keep: bool,
}

impl StagedPath {
    /// Register a path as in-progress staging work.
    fn new(path: PathBuf) -> Self {
        ACTIVE_STAGING.lock().unwrap().insert(path.clone());
        StagedPath { path, keep: false }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// The work succeeded — hand the path to the caller and stop guarding it.
    fn keep(mut self) -> PathBuf {
        self.keep = true;
        self.path.clone()
    }
}

impl Drop for StagedPath {
    fn drop(&mut self) {
        ACTIVE_STAGING.lock().unwrap().remove(&self.path);
        if self.keep {
            return;
        }
        let leftover = match fs::metadata(&self.path) {
            Ok(m) => m,
            Err(_) => return, // never created, or already gone
        };
        // Log either way: a stranded work directory costs more disk than the
        // archive would have, so it should never disappear silently.
        if leftover.is_dir() {
            warn!("backup: discarding work directory {} left by a failed backup",
                self.path.display());
            let _ = fs::remove_dir_all(&self.path);
        } else {
            warn!("backup: discarding {} ({} bytes) left by a failed backup",
                self.path.display(), leftover.len());
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Age after which an unreferenced staging entry is considered abandoned.
///
/// Generous on purpose: a slow whole-VM archive to a slow disk can run for
/// hours, and the in-progress registry already protects anything this process
/// is actively writing. This threshold only has to catch work orphaned by a
/// crash or a kill, where the registry did not survive.
const STAGING_ORPHAN_AGE_SECS: u64 = 24 * 60 * 60;

/// Delete abandoned staging files left by backups that died before they could
/// clean up — a crash, an OOM kill, or a `systemctl restart` mid-archive.
///
/// Returns (files removed, bytes reclaimed). Never touches anything a backup
/// in this process is currently working on, and never touches anything younger
/// than `STAGING_ORPHAN_AGE_SECS`.
pub fn sweep_staging_orphans() -> (usize, u64) {
    let configured = backup_staging_dir();
    let mut total = (0usize, 0u64);
    // The legacy default is swept too, so an upgraded node reclaims whatever
    // its old tmpfs staging was still holding — otherwise moving the default
    // would strand exactly the files this is meant to clear.
    const LEGACY_STAGING_DIR: &str = "/tmp/wolfstack-backups";
    let mut dirs = vec![configured.clone()];
    if configured != LEGACY_STAGING_DIR {
        dirs.push(LEGACY_STAGING_DIR.to_string());
    }
    for dir in dirs {
        let (n, b) = sweep_staging_dir(&PathBuf::from(dir));
        total.0 += n;
        total.1 += b;
    }
    total
}

fn sweep_staging_dir(dir: &Path) -> (usize, u64) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return (0, 0), // no staging dir yet — nothing to sweep
    };
    let active = ACTIVE_STAGING.lock().unwrap().clone();
    let (mut count, mut bytes) = (0usize, 0u64);

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if active.contains(&path) {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let age_ok = meta.modified().ok()
            .and_then(|m| m.elapsed().ok())
            .is_some_and(|age| age.as_secs() > STAGING_ORPHAN_AGE_SECS);
        if !age_ok {
            continue;
        }
        let size = if meta.is_dir() { quick_dir_size_bytes(&path.to_string_lossy()) } else { meta.len() };
        let removed = if meta.is_dir() {
            fs::remove_dir_all(&path).is_ok()
        } else {
            fs::remove_file(&path).is_ok()
        };
        if removed {
            count += 1;
            bytes += size;
            warn!("backup: swept abandoned staging entry {} ({} bytes)", path.display(), size);
        }
    }
    if count > 0 {
        info!("backup: reclaimed {} bytes from {} abandoned staging entries in {}",
            bytes, count, dir.display());
    }
    (count, bytes)
}

/// Warn once per process when staging sits on a RAM-backed filesystem.
///
/// A whole-container archive is built here before it ships, so on tmpfs it is
/// competing with the machine's memory: wolfstack-1 staged a 32 GB LXC tarball
/// into a 32 GB /tmp on 2026-07-21, filled it, and every later container
/// backup returned 0 bytes. The default now avoids tmpfs, but an operator can
/// still point paths.json at one, so say so rather than letting them find out
/// the way we did.
fn warn_if_staging_on_memory(path: &Path) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    let dir = path.to_string_lossy().to_string();
    if !crate::paths::dir_is_memory_backed(&dir) {
        return;
    }
    WARNED.call_once(|| {
        warn!("backup staging {} is on a RAM-backed filesystem (tmpfs/ramfs). A backup \
               larger than free memory will fail and can wedge the node — set \
               backup_staging_dir in /etc/wolfstack/paths.json to a disk-backed path.", dir);
    });
}

/// Headroom kept free in staging on top of the archive itself.
///
/// The archive is not the only thing that needs the disk while a backup runs:
/// journald, the containers still serving traffic, and the backup's own metadata
/// all write to it. Filling a system disk to the last byte takes a host down in
/// ways a failed backup does not, so the guard reserves a gigabyte it will never
/// hand out.
const STAGING_HEADROOM_BYTES: u64 = 1024 * 1024 * 1024;

/// Bytes actually available on the filesystem holding `dir` (not the total, and
/// not counting root's reserve — `df` already accounts for both).
///
/// `None` when df can't answer, which the caller treats as "don't block": a
/// backup must not be refused because a size check failed.
fn filesystem_free_bytes(dir: &Path) -> Option<u64> {
    let out = Command::new("df")
        .args(["-B1", "--output=avail"])
        .arg(dir)
        .output()
        .ok()?;
    if !out.status.success() { return None; }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// How many bytes short staging is for an archive of `uncompressed` bytes, or
/// `None` when it fits.
///
/// Compares against the UNCOMPRESSED size and assumes NO compression. That is
/// deliberate: a container full of media, encrypted volumes or already-gzipped
/// data compresses by nothing, and this guard exists for the case where staging
/// sits on the system disk — where being wrong fills the root filesystem and
/// takes the host with it (klas 2026-08-19: a large Docker container filled the
/// system drive, the backup failed, and the partial archive was left behind).
/// A backup that would in fact have compressed to fit is refused with a message
/// naming both numbers, which is recoverable; a filled root is not.
fn staging_shortfall(uncompressed: u64, free: u64) -> Option<u64> {
    let needed = uncompressed.saturating_add(STAGING_HEADROOM_BYTES);
    (needed > free).then(|| needed - free)
}

/// Refuse a backup that cannot fit in staging, before a byte is written.
///
/// `uncompressed` is the size of what will be archived, as measured from the
/// source (`du`, `docker inspect -s`, the disk image's own length). `None` means
/// it could not be measured, and the backup proceeds — a guard that blocks
/// backups on its own failure to measure would be worse than the problem.
fn ensure_staging_space(
    what: &str,
    uncompressed: Option<u64>,
    staging: &Path,
) -> Result<(), String> {
    let (Some(size), Some(free)) = (uncompressed, filesystem_free_bytes(staging)) else {
        return Ok(());
    };
    let Some(short) = staging_shortfall(size, free) else {
        // Comfortable case still worth a line in the log: when a backup DOES
        // fill the disk despite this, the numbers it was working from are the
        // first thing to look at.
        info!(
            "backup: staging {} has {} free for {} of {} data",
            staging.display(), format_size_human(free), what, format_size_human(size),
        );
        return Ok(());
    };
    Err(format!(
        "Not enough room in backup staging: {} holds about {} of data, and {} has {} \
         free ({} short, including the {} kept free for the rest of the system). \
         Nothing was written. Either point the backup staging directory (Settings -> \
         File Locations) at a disk with room, exclude the large mounts from this \
         target in the backup picker, or free space on that filesystem. Sizes are \
         measured uncompressed, so a compressible target may well fit once staging \
         has room.",
        what,
        format_size_human(size),
        staging.display(),
        format_size_human(free),
        format_size_human(short),
        format_size_human(STAGING_HEADROOM_BYTES),
    ))
}

/// `total` minus the size of each excluded path, floored at zero.
///
/// The excludes are real directories the archive will skip, so counting them
/// would refuse a backup for data it was never going to stage — the exact reason
/// the mount-exclusion feature exists (a 4 TB media bind next to a 2 GB config
/// volume).
fn subtract_excluded_bytes(total: u64, exclude_mounts: &[String]) -> u64 {
    let excluded: u64 = exclude_mounts
        .iter()
        .map(|e| e.trim())
        .filter(|e| e.starts_with('/'))   // volume names have no size on their own
        .map(quick_dir_size_bytes)
        .sum();
    total.saturating_sub(excluded)
}

/// Uncompressed bytes a Docker container's archive will hold: its image +
/// writable layer (`docker inspect -s`) plus every mount that isn't excluded.
///
/// `None` when docker can't be asked at all — the guard then stands down rather
/// than blocking the backup.
fn docker_content_bytes(name: &str, exclude_mounts: &[String]) -> Option<u64> {
    let out = Command::new("docker")
        .args(["inspect", "-s", "--format", "{{.SizeRootFs}}", name])
        .output()
        .ok()?;
    if !out.status.success() { return None; }
    let root_fs: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;

    // Mounts are separate archives inside the wrapper, so they add to it. The
    // same exclusion list the backup itself honours applies here — otherwise
    // excluding a 4 TB media bind would still be refused for its size.
    // Re-measured here rather than taken from the inventory: discovery reports
    // a fast BOUND (`measure_mount_size`), and this guard REFUSES backups, so
    // it must work from the true figure. A wrong number either blocks a backup
    // that would have fit or lets one fill the disk.
    let mounts = discover_docker_mounts(name).unwrap_or_default();
    let mount_bytes: u64 = mounts
        .iter()
        .filter(|m| !mount_is_excluded(&m.source, exclude_mounts))
        .filter(|m| !m.data_path.is_empty())
        .map(|m| quick_dir_size_bytes(&m.data_path))
        .sum();
    Some(root_fs.saturating_add(mount_bytes))
}

/// Uncompressed bytes a native VM's archive will hold.
///
/// Two on-disk layouts exist and both are backed up: a per-VM subdirectory
/// (`vms/<name>/`, used when a VM has extra volumes) and the common flat layout
/// (`vms/<name>.json` + `vms/<name>.qcow2` beside each other). `None` when
/// neither can be measured.
fn vm_content_bytes(name: &str) -> Option<u64> {
    const VM_BASE: &str = "/var/lib/wolfstack/vms";
    let dir = format!("{}/{}", VM_BASE, name);
    if Path::new(&dir).is_dir() {
        return match quick_dir_size_bytes(&dir) { 0 => None, n => Some(n) };
    }
    // Flat layout: every entry whose name is `<name>` or starts with `<name>.`
    // belongs to this VM (`.json` config, `.qcow2` disks, extra volumes).
    let prefix = format!("{}.", name);
    let total: u64 = fs::read_dir(VM_BASE)
        .ok()?
        .flatten()
        .filter(|e| {
            e.file_name().to_str()
                .map(|f| f == name || f.starts_with(&prefix))
                .unwrap_or(false)
        })
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum();
    (total > 0).then_some(total)
}

/// Create staging directory
fn ensure_staging_dir() -> Result<PathBuf, String> {
    let path = PathBuf::from(backup_staging_dir());
    fs::create_dir_all(&path).map_err(|e| format!("Failed to create staging dir: {}", e))?;
    warn_if_staging_on_memory(&path);
    Ok(path)
}

/// Backup a Docker container — commit + save + gzip
/// Returns (path, size, docker_inspect_json)
/// Back up a Docker container including its volumes and bind mounts.
///
/// The output tarball is a *wrapper* containing:
///   inspect.json              ← `docker inspect` output (the original docker_config)
///   mounts.json               ← list of MountInfo, telling restore where each archive goes
///   image.tar.gz              ← `docker commit` + `docker save | gzip` (existing v20.10.x behaviour)
///   volumes/vol-{name}.tar.gz ← per named volume, content of /var/lib/docker/volumes/{name}/_data
///   binds/bind-{idx}.tar.gz   ← per bind mount, content of the host source path
///
/// Legacy v20.10.x backups (just `docker save | gzip`) are still
/// restorable — `restore_docker` detects the format by looking for
/// `inspect.json` inside the outer tarball.
///
/// Bind mounts to system paths (/, /etc, /var/lib/docker, etc.) are
/// refused with a recorded skipped_reason so the user can tell from the
/// backup metadata what was excluded and why.
/// Restarts a container that we stopped for a consistent backup, on
/// EVERY exit path (`?` error returns, panics) via Drop. Same guarantee
/// as backup_lxc's stop/restart, without threading restart calls
/// through every early return in the long docker backup body.
struct DockerRestartGuard {
    name: String,
}
impl Drop for DockerRestartGuard {
    fn drop(&mut self) {
        // The guard exists ONLY when we confirmed the container stopped,
        // so its mere existence means "restart on the way out".
        let _ = Command::new("docker").args(["start", &self.name]).output();
    }
}

pub fn backup_docker(name: &str, exclude_mounts: &[String], stop_for_backup: bool) -> Result<(PathBuf, u64, String, Vec<MountInfo>), String> {
    let staging = ensure_staging_dir()?;
    // Refuse before writing anything if the archive cannot fit: this is the path
    // that filled a system disk (klas 2026-08-19), because a container's image
    // plus its volumes and binds all land in staging first.
    ensure_staging_space(
        &format!("Docker container '{}'", name),
        docker_content_bytes(name, exclude_mounts),
        &staging,
    )?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
    let filename = format!("docker-{}-{}.tar.gz", name, timestamp);
    // Guarded from here: every early return below — including the `?` exits
    // that used to leak a multi-gigabyte work dir and a partial tarball —
    // removes what it had produced.
    let staged_archive = StagedPath::new(staging.join(&filename));
    let final_path = staged_archive.path().to_path_buf();
    let temp_image = format!("wolfstack-backup/{}", name);

    // Optional cold backup: stop the container so volume/bind data and
    // the committed image layer are captured at rest (quiesced DBs, no
    // half-written files). Off by default — the default hot backup
    // commits + tars the live container. Restart is guaranteed by the
    // RAII guard below even if any step errors out. `docker commit`
    // works fine on a stopped container.
    let _restart_guard = if stop_for_backup && docker_is_running(name) {
        let _ = Command::new("docker").args(["stop", name]).output();
        // Verify the stop actually took before we treat this as a cold
        // backup — mirror backup_lxc. If the container is somehow still
        // running (hung stop, daemon busy), don't claim consistency and
        // don't restart something we didn't stop: fall through hot.
        if docker_is_running(name) {
            warn!("backup_docker: 'docker stop {}' did not stop the container; proceeding with a hot backup", name);
            None
        } else {
            Some(DockerRestartGuard { name: name.to_string() })
        }
    } else {
        None
    };

    // Per-backup work area we'll tar up at the end.
    let work_id = Uuid::new_v4().to_string();
    // Guarded too: this holds a full `docker save` image export, so leaking it
    // costs more disk than the finished backup would have.
    let staged_work = StagedPath::new(staging.join(format!("docker-work-{}", work_id)));
    let work_dir = staged_work.path().to_path_buf();
    fs::create_dir_all(work_dir.join("volumes"))
        .map_err(|e| format!("Failed to create work dir: {}", e))?;
    fs::create_dir_all(work_dir.join("binds"))
        .map_err(|e| format!("Failed to create binds dir: {}", e))?;

    // Save container config (docker inspect) for restore.
    let docker_config = Command::new("docker")
        .args(["inspect", name])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    // Parse the Mounts[] array — populated by docker for every
    // -v / --mount on the container, regardless of whether the source
    // is a named volume or a host bind.
    let inspect_val: serde_json::Value = serde_json::from_str(&docker_config)
        .unwrap_or(serde_json::Value::Null);
    let mounts_arr = inspect_val.get(0)
        .and_then(|c| c.get("Mounts"))
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();

    let mut mounts: Vec<MountInfo> = Vec::new();
    for (idx, m) in mounts_arr.iter().enumerate() {
        let mtype = m.get("Type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let source = m.get("Source").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let destination = m.get("Destination").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let vol_name = m.get("Name").and_then(|v| v.as_str()).unwrap_or("").to_string();

        match mtype.as_str() {
            "volume" => {
                // Operator-excluded? Match on the volume name OR its host
                // source path. Record it as skipped (empty archive) so the
                // backup metadata shows what was deliberately left out.
                if mount_is_excluded(&vol_name, exclude_mounts)
                    || (!source.is_empty() && mount_is_excluded(&source, exclude_mounts))
                {
                    mounts.push(MountInfo {
                        mount_type: "volume".into(),
                        source: vol_name.clone(),
                        destination: destination.clone(),
                        archive_path: String::new(),
                        size_bytes: 0,
                        skipped_reason: "excluded by operator".into(),
                    });
                    continue;
                }
                // Named volume — find its data dir on the host. Source
                // is usually /var/lib/docker/volumes/{name}/_data already.
                let data_dir = if !source.is_empty() && Path::new(&source).is_dir() {
                    source.clone()
                } else if !vol_name.is_empty() {
                    format!("/var/lib/docker/volumes/{}/_data", vol_name)
                } else {
                    String::new()
                };
                let label = if !vol_name.is_empty() { vol_name.clone() } else { format!("idx{}", idx) };
                let archive_rel = format!("volumes/vol-{}.tar.gz", sanitize_archive_name(&label));
                let archive_abs = work_dir.join(&archive_rel);

                if data_dir.is_empty() || !Path::new(&data_dir).is_dir() {
                    mounts.push(MountInfo {
                        mount_type: "volume".into(),
                        source: vol_name.clone(),
                        destination: destination.clone(),
                        archive_path: String::new(),
                        size_bytes: 0,
                        skipped_reason: format!("volume data directory not found ({})", data_dir),
                    });
                    continue;
                }
                match tar_dir_to_gz(&data_dir, &archive_abs) {
                    Ok(size) => {
                        mounts.push(MountInfo {
                            mount_type: "volume".into(),
                            source: vol_name,
                            destination,
                            archive_path: archive_rel,
                            size_bytes: size,
                            skipped_reason: String::new(),
                        });
                    }
                    Err(e) => {
                        mounts.push(MountInfo {
                            mount_type: "volume".into(),
                            source: vol_name,
                            destination,
                            archive_path: String::new(),
                            size_bytes: 0,
                            skipped_reason: format!("tar failed: {}", e),
                        });
                    }
                }
            }
            "bind" => {
                // Operator-excluded? Match on the host source path (exact or
                // prefix). This is the headline use case — sonarr/radarr media
                // arrays bind-mounted in that would blow up the staging dir.
                if mount_is_excluded(&source, exclude_mounts) {
                    mounts.push(MountInfo {
                        mount_type: "bind".into(),
                        source,
                        destination,
                        archive_path: String::new(),
                        size_bytes: 0,
                        skipped_reason: "excluded by operator".into(),
                    });
                    continue;
                }
                if let Err(reason) = bind_source_safe(&source) {
                    warn!("backup_docker: skipping bind mount {} -> {}: {}", source, destination, reason);
                    mounts.push(MountInfo {
                        mount_type: "bind".into(),
                        source,
                        destination,
                        archive_path: String::new(),
                        size_bytes: 0,
                        skipped_reason: reason,
                    });
                    continue;
                }
                if !Path::new(&source).exists() {
                    mounts.push(MountInfo {
                        mount_type: "bind".into(),
                        source,
                        destination,
                        archive_path: String::new(),
                        size_bytes: 0,
                        skipped_reason: "host source path does not exist".into(),
                    });
                    continue;
                }
                let archive_rel = format!("binds/bind-{}.tar.gz", idx);
                let archive_abs = work_dir.join(&archive_rel);
                match tar_path_to_gz(&source, &archive_abs) {
                    Ok(size) => {
                        mounts.push(MountInfo {
                            mount_type: "bind".into(),
                            source,
                            destination,
                            archive_path: archive_rel,
                            size_bytes: size,
                            skipped_reason: String::new(),
                        });
                    }
                    Err(e) => {
                        mounts.push(MountInfo {
                            mount_type: "bind".into(),
                            source,
                            destination,
                            archive_path: String::new(),
                            size_bytes: 0,
                            skipped_reason: format!("tar failed: {}", e),
                        });
                    }
                }
            }
            _ => {
                // tmpfs / npipe / unknown — record but don't archive.
                mounts.push(MountInfo {
                    mount_type: mtype,
                    source,
                    destination,
                    archive_path: String::new(),
                    size_bytes: 0,
                    skipped_reason: "tmpfs/unsupported mount type — not archived".into(),
                });
            }
        }
    }

    // Commit + save the image into work_dir/image.tar.gz. Same as
    // pre-v20.11.0 behaviour, just in a subdirectory now.
    let image_path = work_dir.join("image.tar.gz");
    let commit = Command::new("docker")
        .env("DOCKER_CONTENT_TRUST", "0")
        .args(["commit", name, &temp_image])
        .output()
        .map_err(|e| format!("Failed to commit container: {}", e))?;
    if !commit.status.success() {
        return Err(format!("Docker commit failed: {}", String::from_utf8_lossy(&commit.stderr)));
    }
    let save = Command::new("sh")
        .args(["-c", &format!("docker save '{}' | gzip > '{}'", temp_image, image_path.display())])
        .output()
        .map_err(|e| format!("Failed to save image: {}", e))?;
    let _ = Command::new("docker").args(["rmi", &temp_image]).output();
    if !save.status.success() {
        return Err(format!("Docker save failed: {}", String::from_utf8_lossy(&save.stderr)));
    }

    // inspect.json + mounts.json — the metadata restore will read.
    fs::write(work_dir.join("inspect.json"), &docker_config)
        .map_err(|e| format!("Failed to write inspect.json: {}", e))?;
    let mounts_json = serde_json::to_string_pretty(&mounts)
        .map_err(|e| format!("Failed to serialise mounts: {}", e))?;
    fs::write(work_dir.join("mounts.json"), &mounts_json)
        .map_err(|e| format!("Failed to write mounts.json: {}", e))?;

    // Wrap the whole work_dir into the final backup tarball.
    let wrap = Command::new("tar")
        .arg("czf")
        .arg(&final_path)
        .arg("-C")
        .arg(&work_dir)
        .arg(".")
        .output()
        .map_err(|e| format!("Failed to wrap backup tarball: {}", e))?;
    if !wrap.status.success() {
        return Err(format!("tar wrap failed: {}", String::from_utf8_lossy(&wrap.stderr)));
    }

    let size = fs::metadata(&final_path).map(|m| m.len()).unwrap_or(0);
    Ok((staged_archive.keep(), size, docker_config, mounts))
}

/// Sanitize a string for use as a filename component. Volume names are
/// usually fine but compose can produce `myproject_data` which is OK,
/// while user-supplied names could contain slashes / spaces.
fn sanitize_archive_name(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect()
}

/// Short, case-insensitive-safe discriminator derived from the FULL source
/// path: the first 8 hex chars of SHA-256(path). Two paths that differ only by
/// case (or share a basename under different parents) get DIFFERENT
/// discriminators, so their backup filenames never collide — even on a
/// case-insensitive destination filesystem. Hex is itself case-insensitive,
/// so the discriminator can't re-introduce a case collision.
fn short_path_discriminator(path: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(8);
    use std::fmt::Write;
    for b in digest.iter().take(4) {
        let _ = write!(out, "{:02x}", b);
    }
    out
}

/// tar.gz a directory's contents (NOT the directory itself) into the
/// given archive path. Returns the resulting archive size in bytes.
fn tar_dir_to_gz(src_dir: &str, archive: &Path) -> Result<u64, String> {
    let out = Command::new("tar")
        .arg("czf")
        .arg(archive)
        .arg("-C")
        .arg(src_dir)
        .arg(".")
        .output()
        .map_err(|e| format!("tar spawn failed: {}", e))?;
    if !out.status.success() {
        // tar leaves whatever it had written when it failed — drop it here so
        // a failing target can't accumulate a partial archive per run.
        let _ = fs::remove_file(archive);
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(fs::metadata(archive).map(|m| m.len()).unwrap_or(0))
}

/// tar.gz an arbitrary path (file or dir). Used for bind mounts where
/// `Source` may be a file (e.g. a single config) or a directory.
fn tar_path_to_gz(src: &str, archive: &Path) -> Result<u64, String> {
    let p = Path::new(src);
    let (parent, name) = if p.is_dir() {
        // tar -C parent name → archive contains a "name" entry at the root.
        let parent = p.parent().map(|x| x.to_string_lossy().to_string()).unwrap_or_else(|| "/".into());
        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| ".".into());
        (parent, name)
    } else {
        let parent = p.parent().map(|x| x.to_string_lossy().to_string()).unwrap_or_else(|| ".".into());
        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        (parent, name)
    };
    let out = Command::new("tar")
        .arg("czf")
        .arg(archive)
        .arg("-C")
        .arg(&parent)
        .arg(&name)
        .output()
        .map_err(|e| format!("tar spawn failed: {}", e))?;
    if !out.status.success() {
        let _ = fs::remove_file(archive);
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(fs::metadata(archive).map(|m| m.len()).unwrap_or(0))
}

/// Backup an LXC container — tar rootfs + config
/// How to clean up a filesystem snapshot of the container tree. Held by
/// SnapshotGuard so EVERY exit path (tar failure, layout mismatch, early
/// return) removes the snapshot via Drop — no manual bookkeeping.
enum SnapshotKind {
    Zfs { dataset: String, snap: String },
    Btrfs { path: PathBuf },
}

struct SnapshotGuard {
    /// Directory inside the snapshot that mirrors `lxc_base` — tar runs
    /// `-C` here exactly as it would against the live tree, producing an
    /// identical archive layout (`<name>/rootfs/...` + `<name>/config`).
    tar_base: PathBuf,
    kind: SnapshotKind,
}

impl Drop for SnapshotGuard {
    fn drop(&mut self) {
        match &self.kind {
            SnapshotKind::Zfs { dataset, snap } => {
                let _ = Command::new("zfs")
                    .args(["destroy", &format!("{}@{}", dataset, snap)]).output();
            }
            SnapshotKind::Btrfs { path } => {
                let _ = Command::new("btrfs")
                    .args(["subvolume", "delete", &path.to_string_lossy()]).output();
            }
        }
    }
}

/// Take a point-in-time filesystem snapshot covering `<lxc_base>/<name>`,
/// when the storage supports it (ZFS dataset or btrfs subvolume).
///
/// Returns Ok(None) when the tree isn't snapshot-capable OR the layout
/// defeats snapshots: a per-container child dataset / nested subvolume is
/// NOT captured by its parent's snapshot — it shows up as an EMPTY
/// directory inside the snapshot. The rootfs-has-content sanity check
/// below catches that; backing it up anyway would produce a config-only
/// tarball that looks like a real backup until someone tries to restore.
fn try_lxc_snapshot(lxc_base: &str, name: &str) -> Result<Option<SnapshotGuard>, String> {
    // Which filesystem is the container tree on, and where is it rooted?
    // findmnt -T resolves the CONTAINING mount for a path.
    let out = Command::new("findmnt")
        .args(["-no", "FSTYPE,SOURCE,TARGET", "-T", lxc_base])
        .output().map_err(|e| format!("findmnt: {}", e))?;
    let line = String::from_utf8_lossy(&out.stdout);
    let mut it = line.split_whitespace();
    let (Some(fstype), Some(source), Some(target)) = (it.next(), it.next(), it.next()) else {
        return Ok(None);
    };
    // lxc_base relative to the filesystem root, so we can find the same
    // subtree inside the snapshot.
    let rel = Path::new(lxc_base).strip_prefix(target)
        .unwrap_or_else(|_| Path::new("")).to_path_buf();
    let stamp = Utc::now().format("%Y%m%d-%H%M%S");
    let guard = match fstype {
        "zfs" => {
            let snap = format!("wolfstack-backup-{}", stamp);
            let full = format!("{}@{}", source, snap);
            let o = Command::new("zfs").args(["snapshot", &full]).output()
                .map_err(|e| format!("zfs: {}", e))?;
            if !o.status.success() {
                return Err(format!("zfs snapshot {}: {}", full, String::from_utf8_lossy(&o.stderr)));
            }
            // Snapshots are exposed read-only at <mountpoint>/.zfs/snapshot/<name>/
            // (reachable by direct path even with snapdir=hidden).
            let tar_base = Path::new(target).join(".zfs/snapshot").join(&snap).join(&rel);
            SnapshotGuard { tar_base, kind: SnapshotKind::Zfs { dataset: source.to_string(), snap } }
        }
        "btrfs" => {
            // Read-only snapshot of the mounted subvolume, created on the
            // same filesystem (btrfs snapshots can't cross filesystems).
            let snap_path = Path::new(target).join(format!(".wolfstack-backup-snap-{}", stamp));
            let o = Command::new("btrfs")
                .args(["subvolume", "snapshot", "-r", target, &snap_path.to_string_lossy()])
                .output().map_err(|e| format!("btrfs: {}", e))?;
            if !o.status.success() {
                return Err(format!("btrfs snapshot: {}", String::from_utf8_lossy(&o.stderr)));
            }
            let tar_base = snap_path.join(&rel);
            SnapshotGuard { tar_base, kind: SnapshotKind::Btrfs { path: snap_path } }
        }
        _ => return Ok(None),
    };
    // Layout sanity check (see doc comment): refuse an empty rootfs.
    let snap_rootfs = guard.tar_base.join(name).join("rootfs");
    let has_content = fs::read_dir(&snap_rootfs).map(|mut d| d.next().is_some()).unwrap_or(false);
    if !has_content {
        return Ok(None); // guard drops here → snapshot removed
    }
    Ok(Some(guard))
}

// ─── Freezer recovery ───
//
// Snapshot backups DO NOT freeze containers any more.
//
// 2026-08-26, container `legolas` on wolfstack-3: the backup path used to run
// `lxc-freeze` around the snapshot instant. On cgroup2 the freezer can sit in
// FREEZING forever when a task cannot be frozen — the classic case is a
// container running its own FUSE mount (rclone here): the mount's client
// tasks can't freeze until the FUSE daemon answers, and the daemon is being
// frozen with them. `lxc-freeze` waits for FROZEN with no timeout, so the
// backup thread blocked at `.output()` for 70+ minutes with the container
// paused, the unfreeze after it never ran, and the service restart left both
// the frozen container and the hung `lxc-freeze` client behind (systemd's
// KillMode keeps unit children alive across a restart).
//
// The freeze only ever bought write-quiesce for the snapshot instant. A ZFS/
// btrfs snapshot is atomic and point-in-time WITHOUT it — hot, it is crash-
// consistent, which is exactly the guarantee the hot-tar fallback below has
// always accepted. A container staying online outranks quiesced writes, so
// the freeze is gone entirely; what remains here is recovery machinery that
// thaws containers an OLDER binary (or anything else) left stuck frozen with
// a hung lxc-freeze client attached.

/// Bound on lxc-unfreeze/lxc-info during recovery — the cgroup files
/// involved have already proved capable of wedging a caller forever.
const LXC_THAW_TIMEOUT_SECS: u64 = 30;

/// Run a short command, killing it if it exceeds `timeout_secs`.
/// Ok(Some(output)) = it finished; Ok(None) = it hung and was killed.
fn run_bounded(mut cmd: Command, timeout_secs: u64) -> Result<Option<std::process::Output>, String> {
    use std::process::Stdio;
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {}", e))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait().map_err(|e| format!("wait: {}", e))? {
            // try_wait() has already reaped the status; wait_with_output()
            // returns that stored status and drains the pipes.
            Some(_) => return Ok(Some(child.wait_with_output().map_err(|e| format!("wait: {}", e))?)),
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait(); // reap — no zombie
                return Ok(None);
            }
            None => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
}

/// Container state word from `lxc-info -s` (RUNNING / FROZEN / FREEZING /
/// STOPPED / ...), or empty when lxc-info itself fails.
fn lxc_state(name: &str) -> String {
    Command::new("lxc-info")
        .args(["-n", name, "-s"])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .last()
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default()
}

/// Thaw a container and VERIFY it actually came back — a failed thaw must
/// never be invisible. Bounded (paranoia: it touches the same cgroup files
/// that just proved capable of wedging).
fn thaw_lxc(name: &str) -> bool {
    for attempt in 1..=2 {
        let mut cmd = Command::new("lxc-unfreeze");
        cmd.args(["-n", name]);
        match run_bounded(cmd, LXC_THAW_TIMEOUT_SECS) {
            Ok(Some(_)) => {}
            Ok(None) => warn!("thaw {}: lxc-unfreeze hung and was killed (attempt {})", name, attempt),
            Err(e) => warn!("thaw {}: lxc-unfreeze failed to run: {} (attempt {})", name, e, attempt),
        }
        match lxc_state(name).as_str() {
            "FROZEN" | "FREEZING" => {} // not thawed yet — retry
            _ => return true,           // RUNNING (or stopped/gone — nothing frozen)
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    error!("thaw {}: container is STILL FROZEN after lxc-unfreeze — manual `lxc-unfreeze -n {}` needed", name, name);
    false
}

/// Containers with a hung `lxc-freeze -n <name>` client currently attached.
/// argv is matched exactly (basename `lxc-freeze`, then `-n <name>`) — the
/// invocation the old backup path used. `lxc-freeze` exits the moment a
/// freeze SUCCEEDS, so a lingering client means the freezer is stuck in
/// FREEZING — a deliberate operator freeze never looks like this.
fn stray_lxc_freeze_clients() -> Vec<(u32, String)> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else { return found };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
        let Ok(raw) = fs::read(format!("/proc/{}/cmdline", pid)) else { continue };
        let argv: Vec<&str> = raw.split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .filter_map(|s| std::str::from_utf8(s).ok())
            .collect();
        if let Some(name) = lxc_freeze_target(&argv) {
            found.push((pid, name.to_string()));
        }
    }
    found
}

/// The container a process's argv is freezing, if the process is an
/// `lxc-freeze -n <name>` invocation (binary may appear as a full path).
fn lxc_freeze_target<'a>(argv: &[&'a str]) -> Option<&'a str> {
    if argv.len() == 3
        && Path::new(argv[0]).file_name().map(|f| f == "lxc-freeze").unwrap_or(false)
        && argv[1] == "-n"
    {
        Some(argv[2])
    } else {
        None
    }
}

/// Recover containers stuck frozen by a hung `lxc-freeze`: kill the stray
/// client, thaw the container, verify. Covers state left behind by a
/// pre-v25.20.x binary across an upgrade (the hung client and the frozen
/// container both survive a service restart) — and acts as a backstop
/// should anything ever freeze-and-die again. Runs at boot and hourly.
pub fn sweep_frozen_orphans() {
    for (pid, name) in stray_lxc_freeze_clients() {
        warn!("freeze sweep: killing hung lxc-freeze client (pid {}) for container {}", pid, name);
        unsafe { libc::kill(pid as i32, libc::SIGTERM); }
        match lxc_state(&name).as_str() {
            "FROZEN" | "FREEZING" => {
                warn!("freeze sweep: container {} left frozen by a dead backup — thawing", name);
                thaw_lxc(&name);
            }
            _ => {}
        }
    }
}

pub fn backup_lxc(name: &str, exclude_mounts: &[String], stop_for_backup: bool) -> Result<(PathBuf, u64), String> {

    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");

    // Proxmox: use vzdump which properly handles ZFS/LVM/Ceph storage backends
    if crate::containers::is_proxmox() {
        return backup_lxc_proxmox(name, &staging, &timestamp.to_string(), exclude_mounts);
    }

    // Native LXC: tar the container directory (rootfs + config)
    //
    // Sized from the container directory itself; excluded mounts are subtracted
    // because the archive won't contain them either.
    let lxc_dir = format!("/var/lib/lxc/{}", name);
    let lxc_bytes = match quick_dir_size_bytes(&lxc_dir) {
        0 => None, // du couldn't read it — don't block the backup on that
        total => Some(subtract_excluded_bytes(total, exclude_mounts)),
    };
    ensure_staging_space(&format!("LXC container '{}'", name), lxc_bytes, &staging)?;
    let filename = format!("lxc-{}-{}.tar.gz", name, timestamp);
    // Guarded: any error below deletes the half-written archive instead of
    // leaving it in staging forever.
    let staged = StagedPath::new(staging.join(&filename));
    let tar_path = staged.path().to_path_buf();

    // Cold backup is opt-in per target (stop_for_backup). The old
    // unconditional stop turned every scheduled backup into a silent
    // outage — and a restart the container has to survive (wolfscale-3
    // 2026-07-05: broken container boot left mariadb down after each
    // nightly backup).
    let running = is_lxc_running(name);
    let mut stopped_for_backup = stop_for_backup && running;
    if stopped_for_backup {
        let _ = Command::new("lxc-stop").args(["-n", name]).output();
        std::thread::sleep(std::time::Duration::from_secs(3));
        if is_lxc_running(name) {
            // Stop didn't take (hung init / D-state children). Carry on as
            // a hot backup: the tar keeps its changed-file tolerance and
            // the restart gates stay off — the container never stopped.
            warn!("backup {}: lxc-stop did not stop the container; falling back to hot backup", name);
            stopped_for_backup = false;
        }
    }

    // Check LXC path — could be /var/lib/lxc/{name} or custom storage
    let lxc_base = crate::containers::lxc_base_dir(name);
    let lxc_path = format!("{}/{}", lxc_base, name);
    if !Path::new(&lxc_path).exists() {
        if stopped_for_backup {
            let _ = Command::new("lxc-start").args(["-n", name]).output();
        }
        return Err(format!("LXC container path not found: {}", lxc_path));
    }

    // Preferred: a point-in-time filesystem snapshot (ZFS/btrfs) —
    // atomic AND fast, taken HOT with no freeze: the container is never
    // paused, and the snapshot is crash-consistent (the same guarantee as
    // the hot-tar fallback). The path used to `lxc-freeze` around the
    // snapshot instant for write-quiesce; that deadlocked the cgroup2
    // freezer on a container with an internal FUSE mount and left it
    // paused for hours (legolas, 2026-08-26) — see the freezer-recovery
    // block above. A stopped-for-backup container is restarted the moment
    // the snapshot exists, shrinking downtime from the whole tar duration
    // to seconds. No snapshot support → tar the live tree directly
    // (crash-consistent hot tar, or the full cold tar when the operator
    // opted into stop_for_backup).
    let snapshot = match try_lxc_snapshot(&lxc_base, name) {
        Ok(s) => s,
        Err(e) => {
            warn!("backup {}: snapshot failed, falling back to direct tar: {}", name, e);
            None
        }
    };
    if stopped_for_backup && snapshot.is_some() {
        // Snapshot secured — the container doesn't need to stay down
        // while we tar; bring it back now.
        let _ = Command::new("lxc-start").args(["-n", name]).output();
    }
    // Hot smear (files changing under tar) only applies when tarring the
    // LIVE tree of a running container.
    let hot = snapshot.is_none() && running && !stopped_for_backup;

    // Create tar.gz of the entire container directory (rootfs + config).
    // Honour operator exclusions: only paths that actually fall UNDER the
    // backed-up tree (`lxc_path`) make sense as `tar --exclude` args — a
    // native LXC bind mount whose source lives elsewhere on the host isn't
    // inside the rootfs tarball anyway. We rewrite each excluded absolute
    // path to one relative to `lxc_base` (tar's -C dir) so the glob matches.
    let mut tar_cmd = Command::new("tar");
    let lxc_prefix = format!("{}/", lxc_path);
    for raw in exclude_mounts {
        let ex = raw.trim().trim_end_matches('/');
        if ex.is_empty() { continue; }
        // Under the container tree? (the rootfs sits at lxc_path)
        if ex != lxc_path && !ex.starts_with(&lxc_prefix) { continue; }
        if let Ok(rel) = Path::new(ex).strip_prefix(&lxc_base) {
            // GNU tar's `--exclude=<dir>` skips the directory AND its whole
            // subtree (no trailing glob needed — and a `/*` glob would
            // require `--wildcards` to even work). Match the archived
            // member name, which is `name/rootfs/...` here.
            tar_cmd.arg(format!("--exclude={}", rel.to_string_lossy()));
        }
    }
    // Hot backup of a running container: files WILL change or vanish while
    // tar reads the tree — that's the crash-consistency trade-off, not a
    // failure. Quiet the per-file warnings and don't die on a file that
    // disappeared between scan and read. (man tar: exit 1 = "some files
    // were changed while being archived... the resulting archive does not
    // contain the exact copy" — the archive is still written; 2 = fatal.)
    if hot {
        tar_cmd.args(["--warning=no-file-changed", "--warning=no-file-removed", "--ignore-failed-read"]);
    }
    // `-czf` (dashed): the `--exclude` flags above precede the operation, so the
    // old-style bare `czf` (which must be the first argument) made tar abort
    // whenever an exclusion was present. Same fix as backup_system_path.
    // With a snapshot, -C into the snapshot's mirror of lxc_base — member
    // names (and the exclude globs rewritten above) are identical.
    let tar_base = snapshot.as_ref()
        .map(|s| s.tar_base.to_string_lossy().into_owned())
        .unwrap_or_else(|| lxc_base.clone());
    tar_cmd.args(["-czf", &tar_path.to_string_lossy(), "-C", &tar_base, name]);
    let output = tar_cmd.output();

    // Restart if we stopped it and the snapshot path didn't already —
    // BEFORE bailing on a tar spawn failure, so no error path leaves the
    // container down.
    if stopped_for_backup && snapshot.is_none() {
        let _ = Command::new("lxc-start").args(["-n", name]).output();
    }
    let output = output.map_err(|e| format!("Failed to tar LXC container: {}", e))?;

    let soft_ok = hot && output.status.code() == Some(1);
    if !output.status.success() && !soft_ok {
        return Err(format!("LXC tar failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);
    Ok((staged.keep(), size))
}

/// Append operator mount-exclusions to a vzdump command. vzdump takes
/// `--exclude-path <path>` (repeatable) — the path is the mountpoint as
/// seen INSIDE the container, or a host path/glob. We pass each excluded
/// entry through verbatim; the operator picked these from the discovered
/// mount list which already reports container-relative mountpoints.
/// Source: pve-docs vzdump.1 — `--exclude-path <string>` "Exclude certain
/// files/directories", may be specified multiple times.
fn vzdump_apply_excludes(cmd: &mut Command, exclude_mounts: &[String]) {
    for raw in exclude_mounts {
        let ex = raw.trim();
        // vzdump `--exclude-path` expects a filesystem path/glob, not a storage
        // volume id (`local-lvm:vm-105-disk-0`). discover_lxc_mounts exposes
        // both; only forward the path-shaped ones so a volume id can't become a
        // bogus exclude arg that vzdump rejects.
        if ex.is_empty() || !ex.starts_with('/') { continue; }
        cmd.arg("--exclude-path").arg(ex);
    }
}

/// Proxmox LXC backup using vzdump — handles ZFS, LVM, Ceph, and directory storage
fn backup_lxc_proxmox(vmid: &str, staging: &Path, timestamp: &str, exclude_mounts: &[String]) -> Result<(PathBuf, u64), String> {
    // vzdump creates a full container backup including rootfs on any storage backend
    // --mode snapshot uses LVM/ZFS snapshots for live backup when available,
    // falls back to suspend mode, then stop mode
    let mut cmd = Command::new("vzdump");
    cmd.args([
        vmid,
        "--dumpdir", &staging.to_string_lossy(),
        "--mode", "snapshot",
        "--compress", "zstd",
    ]);
    vzdump_apply_excludes(&mut cmd, exclude_mounts);
    let output = cmd
        .output()
        .map_err(|e| format!("vzdump failed to start: {}", e))?;

    // Combine stdout+stderr — vzdump may log the archive path to either
    let all_output = format!("{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr));

    if !output.status.success() {
        // Clear the failed attempt's partial archive before retrying, or a
        // node that fails both modes keeps two sets of debris per run.
        purge_vzdump_leftovers(staging, vmid, None);
        // Snapshot mode may not be supported (e.g. directory storage) — retry with stop mode
        let mut cmd2 = Command::new("vzdump");
        cmd2.args([
            vmid,
            "--dumpdir", &staging.to_string_lossy(),
            "--mode", "stop",
            "--compress", "zstd",
        ]);
        vzdump_apply_excludes(&mut cmd2, exclude_mounts);
        let output2 = cmd2
            .output()
            .map_err(|e| format!("vzdump (stop mode) failed to start: {}", e))?;

        if !output2.status.success() {
            let stderr2 = String::from_utf8_lossy(&output2.stderr);
            purge_vzdump_leftovers(staging, vmid, None);
            return Err(format!("vzdump failed: {}", stderr2.trim()));
        }

        let all_output2 = format!("{}{}",
            String::from_utf8_lossy(&output2.stdout),
            String::from_utf8_lossy(&output2.stderr));
        let found = find_vzdump_result(&all_output2, staging, vmid, timestamp);
        purge_vzdump_leftovers(staging, vmid, found.as_ref().ok().map(|(p, _)| p.as_path()));
        return found;
    }

    let found = find_vzdump_result(&all_output, staging, vmid, timestamp);
    purge_vzdump_leftovers(staging, vmid, found.as_ref().ok().map(|(p, _)| p.as_path()));
    found
}

/// Remove vzdump leftovers for one container from the dump directory.
///
/// A failed vzdump leaves its partial `.tar.zst` (and `.dat`/`.tmp` working
/// files) in the dump dir, and the stop-mode retry below then adds a second
/// set. Nothing else reclaims them: the guard used elsewhere can't help here
/// because vzdump, not WolfStack, chooses the filenames. Scoped to this VMID
/// so a concurrent backup of another container is untouched, and anything a
/// running backup has registered is left alone.
fn purge_vzdump_leftovers(staging: &Path, vmid: &str, keep: Option<&Path>) {
    let prefixes = [format!("vzdump-lxc-{}-", vmid), format!("vzdump-qemu-{}-", vmid)];
    let active = ACTIVE_STAGING.lock().unwrap().clone();
    let entries = match fs::read_dir(staging) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if Some(path.as_path()) == keep || active.contains(&path) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !prefixes.iter().any(|p| name.starts_with(p.as_str())) {
            continue;
        }
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        let removed = if entry.metadata().map(|m| m.is_dir()).unwrap_or(false) {
            fs::remove_dir_all(&path).is_ok()
        } else {
            fs::remove_file(&path).is_ok()
        };
        if removed {
            warn!("backup: removed vzdump leftover {} ({} bytes)", path.display(), size);
        }
    }
}

/// Locate the vzdump archive and return its path + size
fn find_vzdump_result(stdout: &str, staging: &Path, vmid: &str, _timestamp: &str) -> Result<(PathBuf, u64), String> {
    // Try to find the archive from vzdump output
    for line in stdout.lines() {
        if line.contains("creating") && line.contains("vzdump")
            && let Some(start) = line.find('\'')
                && let Some(end) = line.rfind('\'')
                    && start < end {
                        let path = PathBuf::from(&line[start+1..end]);
                        if path.exists() {
                            let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                            return Ok((path, size));
                        }
                    }
    }

    // Fallback: search staging dir for the newest vzdump file for this VMID
    if let Ok(entries) = fs::read_dir(staging) {
        let mut best: Option<(PathBuf, std::time::SystemTime)> = None;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&format!("vzdump-lxc-{}-", vmid))
                && let Ok(meta) = entry.metadata()
                    && let Ok(modified) = meta.modified()
                        && best.as_ref().map(|(_, t)| modified > *t).unwrap_or(true) {
                            best = Some((entry.path(), modified));
                        }
        }
        if let Some((path, _)) = best {
            let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            return Ok((path, size));
        }
    }

    Err(format!("vzdump completed but could not find archive for VMID {}", vmid))
}

/// Check if an LXC container is running
fn is_lxc_running(name: &str) -> bool {
    Command::new("lxc-info")
        .args(["-n", name, "-s"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
        .unwrap_or(false)
}

/// True if the named Docker container is currently running. `docker
/// inspect -f {{.State.Running}}` prints `true`/`false`; a missing
/// container / dockerless host yields non-zero and we treat it as
/// not-running (nothing to stop or restart).
fn docker_is_running(name: &str) -> bool {
    Command::new("docker")
        .args(["inspect", "-f", "{{.State.Running}}", name])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
        .unwrap_or(false)
}

/// Backup a KVM/QEMU VM — copy disk images + JSON config.
///
/// Platform dispatch:
///   • **Proxmox** → `backup_vm_proxmox` (vzdump-style: stop VM, read
///     `/etc/pve/qemu-server/<vmid>.conf`, convert every disk to qcow2
///     via `pvesm path` + `qemu-img convert`, write portable JSON
///     config, tar everything). Output matches the native WolfStack
///     archive format so `restore_vm_local` works on any host.
///   • **libvirt** → `backup_vm_libvirt` (stop VM, read disks via
///     `virsh domblklist --details`, convert each to qcow2 via
///     `qemu-img convert`, write portable JSON config, tar everything).
///     Same archive format as the Proxmox + native paths.
///   • **native** → existing in-place tar.gz with the RAII restart
///     guard from A.1.
pub fn backup_vm(name: &str) -> Result<(PathBuf, u64), String> {
    if crate::containers::is_proxmox() {
        return backup_vm_proxmox(name);
    }
    if crate::containers::is_libvirt() {
        return backup_vm_libvirt(name);
    }
    backup_vm_native(name)
}

/// Backup a libvirt-managed VM. Same pattern as Proxmox: stop with
/// RAII restart guard, delegate the export to the shared helper in
/// vms::manager. Output matches the native WolfStack format so
/// `restore_vm_local` works on any host.
fn backup_vm_libvirt(name: &str) -> Result<(PathBuf, u64), String> {
    let manager = crate::vms::manager::VmManager::new();
    let vm = manager.list_vms().into_iter()
        .find(|v| v.name == name)
        .ok_or_else(|| format!("libvirt VM '{}' not found", name))?;

    // Same C1 fix as Proxmox: graceful stop + poll + force fallback.
    // virsh shutdown is fire-and-forget too — must wait for the VM
    // to actually power down before qemu-img convert touches the disk.
    let was_running = vm.running;
    if was_running {
        stop_vm_and_wait_for_stop(&manager, name, 60)?;
    }
    let _restart_guard = VmRestartGuard { name: name.to_string(), should_restart: was_running };

    let staging = ensure_staging_dir()?;
    let staging_str = staging.to_string_lossy().to_string();
    let archive = crate::vms::manager::export_libvirt_vm_with_staging(name, Some(&staging_str))?;
    let size = fs::metadata(&archive).map(|m| m.len()).unwrap_or(0);
    Ok((archive, size))
}

/// RAII guard that restarts a VM on Drop. Used by every backup_vm_*
/// path to ensure we restart the VM on EVERY exit (success, error,
/// panic). Pre-fix this struct was duplicated inline in three
/// functions; reviewer rightly flagged the maintenance risk.
struct VmRestartGuard {
    name: String,
    should_restart: bool,
}
impl Drop for VmRestartGuard {
    fn drop(&mut self) {
        if !self.should_restart { return; }
        let m = crate::vms::manager::VmManager::new();
        if let Err(e) = m.start_vm(&self.name) {
            tracing::error!(target: "backup",
                "VM backup: failed to restart {} after backup: {} \
                 — operator must start the VM manually", self.name, e);
        } else {
            tracing::info!(target: "backup",
                "VM backup: restarted {} after backup", self.name);
        }
    }
}

/// Graceful stop with poll-until-stopped + force fallback. Pre-fix
/// the backup paths called `stop_vm(name, false)` and slept 2 s —
/// but on Proxmox/libvirt that's fire-and-forget (qm shutdown / virsh
/// shutdown run detached). The 2 s sleep was nowhere near enough for
/// the VM to actually power down, so `qemu-img convert` ran against a
/// LIVE disk → corrupt backup. Now we initiate graceful, poll for
/// `running=false`, force-stop after `grace_secs` if needed.
///
/// `max_wait_secs` budgets the graceful phase. After that we send
/// the force signal (qm stop / virsh destroy) and wait another 5s.
/// Returns Err only if even the force-stop fails or the VM is not
/// known. Returns Ok if VM is already stopped at entry.
fn stop_vm_and_wait_for_stop(
    manager: &crate::vms::manager::VmManager,
    name: &str,
    max_wait_secs: u64,
) -> Result<(), String> {
    // N2: no initial `list_vms()` check — callers gate on their own
    // `was_running` already. Saves a per-backup directory scan on
    // Proxmox + closes a TOCTOU window between callers and the helper.
    //
    // Initiate graceful shutdown.
    manager.stop_vm(name, false)
        .map_err(|e| format!("graceful stop of '{}' failed to start: {}", name, e))?;

    // Poll until stopped or until deadline.
    //
    // A1 fix: tri-state interpretation of list_vms. The previous
    // `.unwrap_or(false)` collapsed two very different outcomes into
    // "stopped":
    //   • VM not in list (deleted, renamed, OR list_vms failed because
    //     `qm list` / `virsh list` errored transiently) → None
    //   • VM in list with running=true → Some(true)
    //   • VM in list with running=false → Some(false)
    // Only `Some(false)` is genuine confirmation that the VM is stopped.
    // A transient subprocess failure used to silently false-positive
    // here, letting `qemu-img convert` run against a still-live disk.
    // Now we keep polling on `None` (don't assume stopped); only
    // `Some(false)` exits the loop early.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(max_wait_secs);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let state: Option<bool> = manager.list_vms().into_iter()
            .find(|v| v.name == name)
            .map(|v| v.running);
        match state {
            Some(false) => {
                // Brief settle so qemu-img doesn't race storage unmount.
                std::thread::sleep(std::time::Duration::from_secs(1));
                return Ok(());
            }
            Some(true) | None => {
                // Keep polling. None means VM not listed — could be
                // a transient list_vms error, or the VM was deleted
                // out from under us. Either way, don't assume stopped.
            }
        }
    }

    // Force stop — guest didn't ACPI-shutdown in time.
    tracing::warn!(target: "backup",
        "VM '{}' did not gracefully stop within {}s — forcing power off \
         for backup consistency. Filesystem inside the guest may need fsck on next boot.",
        name, max_wait_secs);
    manager.stop_vm(name, true)
        .map_err(|e| format!("force stop of '{}' failed after graceful timeout: {}", name, e))?;

    // A2 fix: actually verify the VM stopped after the force-stop,
    // don't just sleep and trust it. `qm stop` is documented as
    // synchronous, but races have been reported, and `virsh destroy`
    // returns before the QEMU process necessarily exits on some
    // libvirt versions. Three 1-second polls is enough to catch the
    // common case without lengthening the worst-case backup time.
    for _ in 0..3 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if let Some(false) = manager.list_vms().into_iter()
            .find(|v| v.name == name)
            .map(|v| v.running)
        {
            return Ok(());
        }
    }
    Err(format!(
        "force-stop of '{}' returned Ok but the VM is still listed as running 3 s later \
         — refusing to back up a live disk", name))
}

/// Native WolfStack VM backup — the original path. KVM/QEMU process
/// spawned by `wolfstack-vm-<name>`, config + disk in
/// `/var/lib/wolfstack/vms/`. Stop the VM, archive its files, restart
/// via the RAII guard so it never stays stopped silently.
fn backup_vm_native(name: &str) -> Result<(PathBuf, u64), String> {
    // The VM name flows into a shell string (the socat socket path) and
    // into tar/JSON filenames. Refuse anything that isn't filename-safe so
    // a crafted name can't inject shell here. Real VM names are already
    // filename-safe (used as vm-<name>.tar.gz / <name>.json), so this
    // never rejects a legitimate VM.
    if !crate::auth::is_safe_name(name) {
        return Err(format!("refusing to back up VM with unsafe name: {:?}", name));
    }

    let staging = ensure_staging_dir()?;
    // A VM's qcow2 images are the largest thing WolfStack ever stages, so the
    // space check matters most here.
    ensure_staging_space(&format!("VM '{}'", name), vm_content_bytes(name), &staging)?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
    let filename = format!("vm-{}-{}.tar.gz", name, timestamp);
    // Guarded: any error below deletes the half-written archive instead of
    // leaving it in staging forever.
    let staged = StagedPath::new(staging.join(&filename));
    let tar_path = staged.path().to_path_buf();

    let vm_base = "/var/lib/wolfstack/vms";
    let config_file = format!("{}.json", name);
    let config_path = format!("{}/{}", vm_base, config_file);
    if !Path::new(&config_path).exists() {
        return Err(format!("VM config not found: {}", config_path));
    }

    // Check if VM is running (check for QEMU process)
    let was_running = is_vm_running(name);
    if was_running {

        // Send ACPI shutdown
        let _ = Command::new("sh")
            .args(["-c", &format!(
                "echo 'system_powerdown' | socat - UNIX-CONNECT:/var/run/wolfstack-vm-{}.sock 2>/dev/null || true", name
            )])
            .output();
        // N1 fix: poll until stopped instead of a fixed 5s sleep that
        // could be too short for a slow guest. Cap at 60s, then
        // pkill -9 if the guest still hasn't powered down. Matches
        // the budget the Proxmox/libvirt paths use via
        // stop_vm_and_wait_for_stop.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut stopped_gracefully = false;
        while std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if !is_vm_running(name) {
                stopped_gracefully = true;
                break;
            }
        }
        if !stopped_gracefully {
            tracing::warn!(target: "backup",
                "VM '{}' did not gracefully ACPI-shutdown within 60s — forcing pkill \
                 for backup consistency. Guest filesystem may need fsck on next boot.", name);
            let _ = Command::new("pkill")
                .args(["-f", &format!("wolfstack-vm-{}", name)])
                .output();
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }

    // RAII guard: restart on EVERY exit path (success, tar-failure
    // early return, panic). Shared `VmRestartGuard` is defined
    // module-level so all three backup_vm_* paths use the same logic.
    let _restart_guard = VmRestartGuard {
        name: name.to_string(),
        should_restart: was_running,
    };

    // Collect all files belonging to this VM:
    // - {name}.json (config - required)
    // - {name}.qcow2 (OS disk)
    // - {name}.log, {name}.runtime.json (optional)
    // - {name}/ subdirectory (extra volumes, if exists)
    let mut tar_items: Vec<String> = vec![config_file];
    
    // Add OS disk image
    let disk_file = format!("{}.qcow2", name);
    if Path::new(&format!("{}/{}", vm_base, disk_file)).exists() {
        tar_items.push(disk_file);
    }
    
    // Add optional files (log, runtime)
    for ext in &["log", "runtime.json"] {
        let f = format!("{}.{}", name, ext);
        if Path::new(&format!("{}/{}", vm_base, f)).exists() {
            tar_items.push(f);
        }
    }
    
    // Add VM subdirectory if it exists (extra volumes stored here)
    if Path::new(&format!("{}/{}", vm_base, name)).is_dir() {
        tar_items.push(name.to_string());
    }

    let output = Command::new("tar")
        .arg("czf")
        .arg(tar_path.to_string_lossy().to_string())
        .arg("-C")
        .arg(vm_base)
        .args(&tar_items)
        .output()
        .map_err(|e| format!("Failed to tar VM: {}", e))?;

    if !output.status.success() {
        return Err(format!("VM tar failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Restart handled by RestartGuard's Drop above — fires on success
    // here OR on any earlier `?`/`return`. Don't add a manual restart
    // call below; we'd double-start.

    let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);

    Ok((staged.keep(), size))
}

/// Backup a Proxmox-managed VM. Stops the VM (with an RAII restart
/// guard so it never stays stopped silently), then delegates the
/// actual export to `vms::manager::export_proxmox_vm_with_staging`
/// (also called by the migration path — single source of truth for
/// the per-platform export format). Output is a WolfStack-format
/// tar.gz that restores cleanly on any host.
fn backup_vm_proxmox(name: &str) -> Result<(PathBuf, u64), String> {
    let manager = crate::vms::manager::VmManager::new();
    let vm = manager.list_vms().into_iter()
        .find(|v| v.name == name)
        .ok_or_else(|| format!("Proxmox VM '{}' not found", name))?;

    // Stop VM for consistent export. C1 fix: graceful stop + poll-
    // until-stopped + force fallback (pre-fix was stop_vm(false) which
    // is fire-and-forget on Proxmox — qemu-img would have run against
    // a live disk → corrupt backup). Shared VmRestartGuard ensures we
    // always restart afterwards.
    let was_running = vm.running;
    if was_running {
        stop_vm_and_wait_for_stop(&manager, name, 60)?;
    }
    let _restart_guard = VmRestartGuard { name: name.to_string(), should_restart: was_running };

    // Delegate the export. The shared helper lives in vms::manager so
    // migration uses the exact same archive format.
    let staging = ensure_staging_dir()?;
    let staging_str = staging.to_string_lossy().to_string();
    let archive = crate::vms::manager::export_proxmox_vm_with_staging(name, Some(&staging_str))?;
    let size = fs::metadata(&archive).map(|m| m.len()).unwrap_or(0);
    Ok((archive, size))
}

/// Check if a VM is running
fn is_vm_running(name: &str) -> bool {
    Command::new("pgrep")
        .args(["-f", &format!("wolfstack-vm-{}", name)])
        .output()
        .ok()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Recursively copy a config directory into the backup bundle, skipping any
/// subdirectory whose name is in `exclude_dirs` (matched at ANY depth). A
/// symlink to a regular file is backed up by copying its target's CONTENT — so
/// certbot/Let's-Encrypt-style symlinked certs (`cert.pem` → `/etc/letsencrypt/…`)
/// are captured rather than silently dropped. A symlinked directory is warned
/// and skipped (never followed — avoids cycles and escaping the tree). A failure
/// to copy a *real* config file aborts the whole backup rather than shipping a
/// silent hole that a restore would later reveal as missing config.
fn copy_config_tree(src: &Path, dest: &Path, exclude_dirs: &[&str]) -> Result<(), String> {
    fs::create_dir_all(dest).map_err(|e| format!("create {}: {}", dest.display(), e))?;
    for entry in fs::read_dir(src).map_err(|e| format!("read {}: {}", src.display(), e))? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => { warn!("config backup: unreadable entry in {} ({})", src.display(), e); continue; }
        };
        let from = entry.path();
        let name = entry.file_name();
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(e) => { warn!("config backup: skipped {} (type unknown: {})", from.display(), e); continue; }
        };
        if ft.is_symlink() {
            // Follow the link to classify the target: copy a linked regular
            // file's content; never recurse into a linked directory.
            match fs::metadata(&from) {
                Ok(m) if m.is_file() => {
                    fs::copy(&from, dest.join(&name))
                        .map_err(|e| format!("copy {}: {}", from.display(), e))?;
                }
                Ok(_) => warn!("config backup: skipped symlinked directory {}", from.display()),
                Err(e) => warn!("config backup: skipped broken symlink {} ({})", from.display(), e),
            }
        } else if ft.is_dir() {
            if exclude_dirs.iter().any(|e| std::ffi::OsStr::new(e) == name) { continue; }
            copy_config_tree(&from, &dest.join(&name), exclude_dirs)?;
        } else if ft.is_file() {
            fs::copy(&from, dest.join(&name))
                .map_err(|e| format!("copy {}: {}", from.display(), e))?;
        }
    }
    Ok(())
}

/// Backup WolfStack configuration files
pub fn backup_config() -> Result<(PathBuf, u64), String> {

    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
    // Node-scoped: see `config_archive_node_id`. A fleet-wide constant here put
    // every node's config into the one PBS group `host/wolfstack`.
    let filename = format!("config-{}-{}.tar.gz",
        config_archive_node_id(&local_hostname()), timestamp);
    // Guarded: any error below deletes the half-written archive instead of
    // leaving it in staging forever.
    let staged = StagedPath::new(staging.join(&filename));
    let tar_path = staged.path().to_path_buf();

    let temp_dir = stage_config_bundle()?;

    // Tar the bundle
    let output = Command::new("tar")
        .args(["czf", &tar_path.to_string_lossy(), "-C", &temp_dir.to_string_lossy(), "."])
        .output()
        .map_err(|e| format!("Failed to tar config: {}", e))?;

    let _ = fs::remove_dir_all(&temp_dir);

    if !output.status.success() {
        return Err(format!("Config tar failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);

    Ok((staged.keep(), size))
}

/// Assemble the config-backup tree in a staging directory and return it.
/// Shared by `backup_config` (which tars it) and the PBS file-level path
/// (which uploads it as a pxar archive so single files are browsable and
/// restorable in PBS — wabil 2026-07-08: "I want to use PBS to grab that
/// one file", not download-extract-delete a whole tarball). The caller
/// owns cleanup of the returned directory.
fn stage_config_bundle() -> Result<PathBuf, String> {
    let staging = ensure_staging_dir()?;
    // Unique per call: the tarball path and the PBS pxar path (and a scheduled
    // vs manual run) can each stage concurrently without racing on one dir.
    let temp_dir = staging.join(format!("config-bundle-{}", Uuid::new_v4().simple()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).map_err(|e| format!("Failed to create temp dir: {}", e))?;

    // Back up the WHOLE /etc/wolfstack tree, not a hardcoded file list. The old
    // list captured 4 files; WolfStack has since grown ~50 config files/dirs
    // (router, dns-providers, wolfflow/workflows, statuspage, users, alerting,
    // cluster-secret, certs, sql-connections, …) — a "config backup" silently
    // omitted almost all of it, so a reinstall lost nearly everything (wabil,
    // 2026-06-30). Walking the directory auto-includes anything added in future.
    //
    // Skip only what shouldn't be in a config backup:
    //   • icon-packs    — large, re-downloadable from GitHub on demand.
    //   • config-backups — the config backups themselves (avoid nesting them).
    let etc_dir = Path::new("/etc/wolfstack");
    if etc_dir.exists() {
        let bundle_etc = temp_dir.join("etc/wolfstack");
        copy_config_tree(etc_dir, &bundle_etc, &["icon-packs", "config-backups"])?;

        // Drop operational *history* that isn't configuration — it can be many
        // MB of per-step command output / event logs and is pointless in a
        // config backup. The workflow/service *definitions* (workflows.json,
        // services.json) are kept; only the run/event logs are dropped.
        for noisy in &["wolfflow/runs.json", "wolfrun/failover-events.json"] {
            let _ = fs::remove_file(bundle_etc.join(noisy));
        }
    }

    // Sibling Wolf components keep their config outside /etc/wolfstack. Back up
    // each WHOLE dir — WolfNet has more than config.toml (keys / peer state) and
    // WolfUSB keeps wolfusb.env; the old code grabbed only wolfnet/config.toml,
    // so a reinstall lost the rest (Gary, 2026-06-30).
    for comp_dir in &["/etc/wolfnet", "/etc/wolfusb"] {
        let p = Path::new(comp_dir);
        // strip_prefix must succeed (these are absolute literals); skip rather
        // than fall back to an absolute `rel`, which `temp_dir.join` would
        // resolve to the real /etc path and copy a dir onto itself.
        let Ok(rel) = p.strip_prefix("/") else { continue };
        if p.exists() {
            copy_config_tree(p, &temp_dir.join(rel), &[])?;
        }
    }

    // Also include VM configs (JSON only, not disk images)
    let vm_config_dir = Path::new("/var/lib/wolfstack/vms");
    if vm_config_dir.exists()
        && let Ok(entries) = fs::read_dir(vm_config_dir) {
            for entry in entries.flatten() {
                let config_file = entry.path().join("config.json");
                if config_file.exists() {
                    let dest = temp_dir.join(format!("var/lib/wolfstack/vms/{}/config.json",
                        entry.file_name().to_string_lossy()));
                    if let Some(parent) = dest.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let _ = fs::copy(&config_file, &dest);
                }
            }
        }

    Ok(temp_dir)
}

/// Refuse the filesystem root and the kernel virtual filesystems (and any
/// sub-path of them). Shared by backup + restore validation. `for_backup`
/// tunes the message; `/` itself is always refused.
fn reject_dangerous_root(path: &str, for_backup: bool) -> Result<(), String> {
    let canonical = path.trim_end_matches('/');
    let canonical = if canonical.is_empty() { "/" } else { canonical };
    let kernel_fs: &[&str] = &["/proc", "/sys", "/dev"];
    // "/" is refused as a BACKUP source (it would pull the whole host into
    // staging) but is a LEGITIMATE RESTORE target: a top-level folder like
    // /etc is archived with leaf member `etc/`, so extracting into "/" lands
    // it back in place and writes only under /etc — nothing else at the root
    // is touched. So allow "/" for restore, refuse it for backup.
    if canonical == "/" {
        return if for_backup {
            Err("Refusing to back up '/' — it's the system root; \
                 pick a specific folder like /etc or /home".to_string())
        } else {
            Ok(())
        };
    }
    if kernel_fs.contains(&canonical) {
        return Err(if for_backup {
            format!("Refusing to back up '{}' — kernel filesystem; \
                     pick a specific folder like /etc or /home", canonical)
        } else {
            format!("Refusing to restore into '{}' — kernel filesystem", canonical)
        });
    }
    for d in kernel_fs {
        if canonical.starts_with(&format!("{}/", d)) {
            return Err(format!("'{}' is under {} — kernel state, not application data", canonical, d));
        }
    }
    Ok(())
}

/// Reject system-folder backup targets that point at dangerous roots.
/// The path must be absolute, exist, and be a directory; the kernel
/// virtual filesystems and the filesystem root are refused outright —
/// archiving them is either meaningless (/proc, /sys, /dev) or a
/// foot-gun (`/` would try to pull the entire host into staging).
/// The path is canonicalised (symlinks resolved) before the deny-check so a
/// `/data/evil -> /proc` symlink can't sneak past it.
pub fn validate_system_path(path: &str) -> Result<(), String> {
    let p = path.trim();
    if p.is_empty() {
        return Err("System folder path is required".into());
    }
    if !p.starts_with('/') {
        return Err("System folder path must be absolute (start with '/')".into());
    }
    // Check the literal path first (catches `/proc` typed directly).
    reject_dangerous_root(p, true)?;
    // Then resolve symlinks and re-check — a symlinked path that resolves to a
    // forbidden root must also be rejected. canonicalize() also confirms the
    // path exists.
    let resolved = fs::canonicalize(p)
        .map_err(|e| format!("Cannot access '{}': {}", p, e))?;
    let resolved_str = resolved.to_string_lossy().to_string();
    reject_dangerous_root(&resolved_str, true)?;
    let meta = fs::metadata(&resolved)
        .map_err(|e| format!("Cannot access '{}': {}", resolved_str, e))?;
    if !meta.is_dir() {
        return Err(format!("'{}' is not a directory", resolved_str));
    }
    Ok(())
}

/// Backup an arbitrary host system folder — tar.gz the directory to staging.
/// `label` is the operator-supplied name baked into the filename so several
/// folder backups are distinguishable; `path` is the absolute directory.
/// `exclude_mounts` skips sub-paths (same exact/prefix matching as binds).
/// Turn one operator exclusion into the `tar --exclude=<pattern>` value for a
/// system-folder backup, or `None` if it doesn't apply. Accepts an absolute
/// sub-path of the folder ("/srv/data/big") OR a path relative to it ("big",
/// "big/sub"). The pattern is built to match the archive member names for the
/// mode: contents-only members are `./<rel>` (GNU tar matches the bare `<rel>`),
/// leaf members are `<leaf>/<rel>`. Pure so the matching is unit-testable.
/// Split operator folder-exclusions into those that apply (they're
/// genuinely sub-paths of the backed-up folder) and those dropped
/// because they point OUTSIDE it. The dropped set is the silent
/// failure mode wabil hit (2026-07-05): an exclude like
/// `/mnt/cache/appdata/x` typed against a folder backed up as
/// `/mnt/user/appdata` (Unraid's user-share vs cache-disk paths point
/// at the same data but are different path strings) matches no member
/// and is discarded with no feedback. Surfacing the dropped list turns
/// "exclusions ignored, no idea why" into an actionable log line.
/// Pure, so it's unit-testable and reusable by both the immediate and
/// scheduled backup log paths.
pub fn classify_folder_excludes(path: &str, excludes: &[String]) -> (Vec<String>, Vec<String>) {
    let contents_only = path.ends_with('/');
    let src = path.trim_end_matches('/');
    // `leaf` is empty only when `src` has no final component (path == "/"),
    // which `validate_system_path` rejects before any real backup reaches
    // here — so this matches backup_system_path's own `leaf` for every
    // path that actually gets archived, keeping the "applied" list truthful.
    let leaf = Path::new(src).file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut applied = Vec::new();
    let mut dropped = Vec::new();
    for raw in excludes {
        if raw.trim().is_empty() { continue; }
        if folder_exclude_pattern(raw, src, &leaf, contents_only).is_some() {
            applied.push(raw.trim().to_string());
        } else {
            dropped.push(raw.trim().to_string());
        }
    }
    (applied, dropped)
}

/// Convert one operator folder-exclusion into a `proxmox-backup-client
/// --exclude` glob for a SystemPath file-level (pxar) backup, or None
/// if it's not inside the folder (same drop rule as the tarball path).
///
/// The pxar archive's root IS the backed-up folder, so a path inside it
/// is relative to that root. Per pbs.proxmox.com/docs/backup-client.html
/// a leading `/` anchors the glob to the archive root (matches only
/// there, not in subdirectories) — which is exactly tar's top-level
/// exclusion semantics, so `/mnt/docker` + exclude `/mnt/docker/plex`
/// becomes `/plex`. We reuse folder_exclude_pattern's contents-mode
/// relativiser (archive root = folder, no leaf wrapper) and anchor it.
fn pxar_exclude_pattern(raw: &str, src: &str) -> Option<String> {
    let rel = folder_exclude_pattern(raw, src, "", true)?;
    Some(format!("/{}", rel))
}

fn folder_exclude_pattern(raw: &str, src: &str, leaf: &str, contents_only: bool) -> Option<String> {
    let ex = raw.trim().trim_end_matches('/');
    if ex.is_empty() { return None; }
    let rel_to_src: String = if ex.starts_with('/') {
        if ex == src { return None; } // excluding the whole folder is degenerate
        let prefix = format!("{}/", src);
        if !ex.starts_with(&prefix) { return None; } // outside the folder
        Path::new(ex).strip_prefix(src).ok()?.to_string_lossy().to_string()
    } else {
        ex.trim_start_matches("./").to_string()
    };
    if rel_to_src.is_empty() { return None; }
    Some(if contents_only { rel_to_src } else { format!("{}/{}", leaf, rel_to_src) })
}

pub fn backup_system_path(label: &str, path: &str, exclude_mounts: &[String]) -> Result<(PathBuf, u64), String> {
    validate_system_path(path)?;
    let staging = ensure_staging_dir()?;
    let folder_bytes = match quick_dir_size_bytes(path) {
        0 => None,
        total => Some(subtract_excluded_bytes(total, exclude_mounts)),
    };
    ensure_staging_space(&format!("folder '{}'", path), folder_bytes, &staging)?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
    // Filename uses the SAME `systempath-` prefix the scanner/guesser key off.
    let safe_label = sanitize_archive_name(if label.trim().is_empty() {
        Path::new(path).file_name().and_then(|n| n.to_str()).unwrap_or("folder")
    } else { label.trim() });
    // Disambiguator derived from the FULL source path. Without it, two folders
    // whose names differ only by case ("temp" vs "Temp") — or that share a
    // basename under different parents ("/a/x" vs "/b/x") — collide on a
    // case-insensitive backup destination (SMB / exFAT / APFS), so one
    // overwrites the other (wabil 2026-06-21). A short hex hash of the exact
    // path is case-insensitive-safe and unique per source, while the readable
    // label is preserved.
    let path_disc = short_path_discriminator(path);
    let filename = format!("systempath-{}-{}-{}.tar.gz", safe_label, path_disc, timestamp);
    // Guarded: any error below deletes the half-written archive instead of
    // leaving it in staging forever.
    let staged = StagedPath::new(staging.join(&filename));
    let tar_path = staged.path().to_path_buf();

    // Trailing-slash semantics (rsync-style, wabil 2026-06-22): "/data/temp"
    // archives the folder itself (top entry `temp/`), so restore lands it back
    // where it was. "/data/temp/" archives only the folder's CONTENTS (no
    // wrapper dir). The two are distinct backups — the discriminator already
    // hashes the raw path, so their filenames never collide.
    let contents_only = path.ends_with('/');
    let src = path.trim_end_matches('/');
    let p = Path::new(src);
    let parent = p.parent().map(|x| x.to_string_lossy().to_string()).unwrap_or_else(|| "/".into());
    let leaf = p.file_name().map(|n| n.to_string_lossy().to_string())
        .ok_or_else(|| format!("Cannot determine folder name from '{}'", src))?;

    // Warn (to the journal) about excludes that don't sit under this
    // folder — they silently do nothing, which is what made folder
    // exclusions look broken (wabil 2026-07-05). This is the single
    // choke point every caller hits (Backup Now, scheduled, streamed),
    // so scheduled runs — which have no live log channel — still get
    // the diagnostic in `journalctl -u wolfstack`.
    let (_applied, dropped) = classify_folder_excludes(path, exclude_mounts);
    if !dropped.is_empty() {
        warn!(
            "backup_system_path: {} exclude(s) IGNORED for folder '{}' — not sub-paths of it: {}. \
             Exclusions must live inside the backed-up folder (on Unraid, use the SAME /mnt/user or /mnt/cache prefix).",
            dropped.len(), path, dropped.join(", ")
        );
    }

    let mut tar_cmd = Command::new("tar");
    for raw in exclude_mounts {
        if let Some(pattern) = folder_exclude_pattern(raw, src, &leaf, contents_only) {
            tar_cmd.arg(format!("--exclude={}", pattern));
        }
    }
    // `-czf` (dashed) — old-style `czf` must be the FIRST argument, but the
    // `--exclude` flags above precede it, so the bare form made tar abort the
    // moment any exclusion was present (the root of wabil's "exclude ignored").
    if contents_only {
        tar_cmd.args(["-czf", &tar_path.to_string_lossy(), "-C", src, "."]);
    } else {
        tar_cmd.args(["-czf", &tar_path.to_string_lossy(), "-C", &parent, &leaf]);
    }
    let output = tar_cmd
        .output()
        .map_err(|e| format!("Failed to tar system folder: {}", e))?;
    if !output.status.success() {
        return Err(format!("System folder tar failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    let size = fs::metadata(&tar_path).map(|m| m.len()).unwrap_or(0);
    Ok((staged.keep(), size))
}

/// True when every top-level member of the archive is the folder's leaf name —
/// i.e. the archive wraps the folder itself (`leaf/...`) rather than holding its
/// bare contents. Pure so the leaf-vs-contents decision is unit-testable.
/// `top_components` is the set of first path components (with any leading `./`
/// stripped) seen in the tarball listing.
fn archive_is_leaf_style(top_components: &std::collections::HashSet<String>, leaf: &str) -> bool {
    !top_components.is_empty() && top_components.iter().all(|c| c == leaf)
}

/// Restore a system-folder backup. The archive is either *leaf-style* (top
/// member is the folder's leaf name, e.g. `etc/...` — the default and how every
/// pre-v24.55.11 backup was made) or *contents-only* (the folder's bare
/// contents, produced when the source path carried a trailing slash). We read
/// the actual tarball structure to tell which, so historical archives restore
/// correctly regardless of how the stored path looks today.
///
/// `target_dir` empty → restore IN PLACE: a leaf-style archive unpacks into the
/// folder's PARENT (recreating it where it was); a contents-only archive unpacks
/// into the FOLDER itself. A non-empty `target_dir` is an operator-chosen
/// extraction directory used verbatim. Destructive over existing data — callers
/// must require explicit confirmation.
pub fn restore_system_path(entry: &BackupEntry, target_dir: &str) -> Result<String, String> {
    let src = entry.target.system_path.trim_end_matches('/');
    let leaf = Path::new(src).file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
    let parent = Path::new(src).parent()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/".to_string());

    // A valid backup never has a root/empty source (validate_system_path blocks
    // "/"), but refuse it defensively before fetching anything: an empty leaf
    // would misclassify as contents-only and could extract into "/".
    if leaf.is_empty() {
        return Err(format!(
            "Cannot restore system folder: invalid source path '{}'",
            entry.target.system_path
        ));
    }

    let local_path = retrieve_backup(entry)?;

    // Inspect the archive's top-level members to classify leaf-style vs
    // contents-only. This is the source of truth for where the bytes go —
    // never inferred from the (possibly trailing-slash-trimmed) stored path.
    let list = Command::new("tar")
        .args(["tzf", &local_path.to_string_lossy()])
        .output();
    let leaf_style = match list {
        Ok(o) if o.status.success() => {
            let top_components: std::collections::HashSet<String> = String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.trim_start_matches("./").trim_start_matches('/'))
                .filter_map(|l| l.split('/').next())
                .filter(|c| !c.is_empty())
                .map(|c| c.to_string())
                .collect();
            archive_is_leaf_style(&top_components, &leaf)
        }
        // Listing failed (rare — a readable archive lists fine, and if it
        // can't the extract below will fail too). Assume leaf-style: that's how
        // every backup made before trailing-slash support was built, so the
        // common case still restores into the correct place.
        _ => true,
    };

    // Decide the extraction directory.
    let dest_owned: String;
    let dest = if target_dir.trim().is_empty() {
        // In-place: leaf-style → parent; contents-only → the folder itself.
        dest_owned = if leaf_style { parent } else { src.to_string() };
        dest_owned.as_str()
    } else {
        target_dir.trim()
    };

    if dest.is_empty() || !dest.starts_with('/') {
        let _ = fs::remove_file(&local_path);
        return Err("Restore target directory must be an absolute path".into());
    }
    // Refuse the kernel filesystems (/proc, /sys, /dev). "/" is allowed: a
    // leaf-style top-level folder (e.g. `etc/`) extracted into "/" lands back
    // in place and touches only its own subtree. Destructive over existing
    // data, so callers must require explicit confirmation.
    if let Err(e) = reject_dangerous_root(dest, false) {
        let _ = fs::remove_file(&local_path);
        return Err(e);
    }
    if let Err(e) = fs::create_dir_all(dest) {
        let _ = fs::remove_file(&local_path);
        return Err(format!("Cannot create restore target '{}': {}", dest, e));
    }
    let output = Command::new("tar")
        .args(["xzf", &local_path.to_string_lossy(), "-C", dest])
        .output();
    // Always drop the staging copy, on success and on every error path.
    let _ = fs::remove_file(&local_path);
    let output = output.map_err(|e| format!("Failed to extract system folder backup: {}", e))?;
    if !output.status.success() {
        return Err(format!("System folder extract failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(format!("System folder restored into {}", dest))
}

/// The mount exclusions a "back up everything" run applies to the container
/// `(kind, name)`, from the schedule's stored overrides. Matched on type AND
/// name: a Docker container and an LXC container may share a name and their
/// mounts have nothing to do with each other. No override, or an override with
/// nothing excluded, means the container archives in full.
fn mount_overrides_for(overrides: &[BackupTarget], kind: &BackupTargetType, name: &str) -> Vec<String> {
    overrides
        .iter()
        .find(|t| &t.target_type == kind && t.name == name)
        .map(|t| t.exclude_mounts.clone())
        .unwrap_or_default()
}

/// Backup everything on the server.
///
/// `stop_containers` makes every Docker/LXC container a COLD backup — stopped
/// for the duration of its archive, then restarted — which is the only way a
/// "back up everything" schedule can ask for consistent container archives:
/// its target list is resolved here, at run time, so there are no per-target
/// `stop_for_backup` flags to read (JJ 2026-08-19). VMs and the config target
/// are unaffected by it.
///
/// `overrides` are the schedule's stored `targets` (see
/// `BackupSchedule::targets`): the one per-container setting that DOES have to
/// survive run-time resolution is the mount exclusion list, because "everything
/// except that 20 TB array" is the whole reason it exists. A live container
/// with a matching override archives without those mounts; one without an
/// override archives in full, as before. On-demand "everything" passes none.
pub fn backup_all(
    storage: &BackupStorage,
    stop_containers: bool,
    overrides: &[BackupTarget],
) -> Vec<BackupEntry> {
    let mut entries = Vec::new();

    // Backup all Docker containers
    if let Ok(output) = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}"])
        .output()
    {
        let names: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect();
        for name in names {
            let exclude_mounts = mount_overrides_for(overrides, &BackupTargetType::Docker, &name);
            entries.push(create_backup_entry(
                BackupTarget {
                    target_type: BackupTargetType::Docker,
                    name: name.clone(),
                    exclude_mounts,
                    stop_for_backup: stop_containers,
                    ..Default::default()
                },
                storage,
            ));
        }
    }

    // Backup all LXC containers.
    //
    // Enumerated through `containers::lxc_list_all()` — the same source of
    // truth the Containers page uses — NOT a bare `lxc-ls`. `lxc-ls` reports
    // whatever holds a config under the default lxcpath, which is wrong on
    // both platforms:
    //
    //   * On Proxmox it lists leftover `/var/lib/lxc/<vmid>` directories for
    //     containers that were migrated to another node or destroyed. wolf1
    //     carried a phantom CT 104 that way: `lxc-ls` listed it, `pct list`
    //     did not, and every nightly run spent a target on a `vzdump 104`
    //     that could not produce an archive — one guaranteed
    //     "Backup failed for Lxc" in the log every night (2026-09-03).
    //     `lxc_list_all()` goes through `pct list`, so only containers
    //     Proxmox actually owns on THIS node are enumerated.
    //   * On native LXC it MISSES containers on any non-default storage path,
    //     which `lxc_list_all()` scans (`lxc_storage_paths()`) and which
    //     `backup_lxc` then resolves via `lxc_base_dir()`. Those were
    //     silently absent from every "back up everything" run.
    //
    // `ContainerInfo::name` is exactly the identifier `backup_lxc` wants on
    // each platform: the VMID on Proxmox (what `vzdump` takes) and the
    // container name natively.
    for container in crate::containers::lxc_list_all() {
        if container.name.is_empty() { continue; }
        let exclude_mounts = mount_overrides_for(overrides, &BackupTargetType::Lxc, &container.name);
        entries.push(create_backup_entry(
            BackupTarget {
                target_type: BackupTargetType::Lxc,
                name: container.name.clone(),
                hostname: if container.hostname.is_empty() { None } else { Some(container.hostname.clone()) },
                exclude_mounts,
                stop_for_backup: stop_containers,
                ..Default::default()
            },
            storage,
        ));
    }

    // Backup all VMs — native WolfStack VMs only at this stage.
    //
    // A.2 fix: the pre-fix code filtered `is_dir()` in /var/lib/wolfstack/vms,
    // which only matched the extra-volumes-subdir layout (rare). The
    // common case is a flat `name.json + name.qcow2` layout, and those
    // were silently invisible to "backup all". Now we parse .json
    // config files — same source of truth as VmManager::list_vms()'s
    // native scan path. Proxmox + libvirt branches below enumerate
    // via VmManager which dispatches to the platform-correct path
    // (qm/virsh).
    if crate::containers::is_proxmox() || crate::containers::is_libvirt() {
        // Enumerate Proxmox / libvirt VMs via VmManager (same source
        // the dashboard uses — /etc/pve/qemu-server/*.conf on Proxmox,
        // `virsh list --all` on libvirt). backup_vm dispatches by
        // platform so all three types (native / Proxmox / libvirt) get
        // the correct backup path.
        let manager = crate::vms::manager::VmManager::new();
        for vm in manager.list_vms() {
            entries.push(create_backup_entry(
                BackupTarget {
                    target_type: BackupTargetType::Vm,
                    name: vm.name.clone(),
                    ..Default::default()
                },
                storage,
            ));
        }
    } else {
        // Native WolfStack VMs — parse .json configs from /var/lib/wolfstack/vms.
        let vm_dir = Path::new("/var/lib/wolfstack/vms");
        if vm_dir.exists()
            && let Ok(read) = fs::read_dir(vm_dir) {
                for entry in read.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
                    let file_name = match path.file_name().and_then(|n| n.to_str()) {
                        Some(n) => n, None => continue,
                    };
                    if file_name.ends_with(".runtime.json") { continue; }
                    let name = file_name.trim_end_matches(".json").to_string();
                    if name.is_empty() { continue; }
                    entries.push(create_backup_entry(
                        BackupTarget {
                            target_type: BackupTargetType::Vm,
                            name, ..Default::default()
                        },
                        storage,
                    ));
                }
            }
    }

    // Backup config
    entries.push(create_backup_entry(
        BackupTarget { target_type: BackupTargetType::Config, name: String::new(), ..Default::default() },
        storage,
    ));

    entries
}

/// Get the local hostname for backup entries
fn local_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Get the local cluster name from /etc/wolfstack/self_cluster.json
/// Used as fallback when cluster name isn't passed from the API layer
pub fn local_cluster_name() -> String {
    std::fs::read_to_string(&crate::paths::get().self_cluster_config)
        .ok()
        .and_then(|data| serde_json::from_str::<String>(&data).ok())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "WolfStack".to_string())
}

/// Generate a descriptive comment for a backup target, prefixed with cluster name
fn backup_comments(target: &BackupTarget) -> String {
    backup_comments_with_cluster(target, &local_cluster_name())
}

fn backup_comments_with_cluster(target: &BackupTarget, cluster: &str) -> String {
    let detail = match target.target_type {
        BackupTargetType::Docker => {
            let image = Command::new("docker")
                .args(["inspect", "--format", "{{.Config.Image}}", &target.name])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            if image.is_empty() {
                format!("Docker container: {}", target.name)
            } else {
                format!("Docker container: {} (image: {})", target.name, image)
            }
        }
        BackupTargetType::Lxc => {
            if crate::containers::is_proxmox() {
                let hostname = target.hostname.as_deref().unwrap_or("");
                if hostname.is_empty() || hostname == target.name {
                    format!("LXC container: {} (vzdump full backup)", target.name)
                } else {
                    format!("LXC container: {} ({}) (vzdump full backup)", target.name, hostname)
                }
            } else {
                format!("LXC container: {} (rootfs + config)", target.name)
            }
        }
        BackupTargetType::Vm => {
            let config_path = format!("/var/lib/wolfstack/vms/{}.json", target.name);
            if let Ok(data) = std::fs::read_to_string(&config_path)
                && let Ok(vm) = serde_json::from_str::<serde_json::Value>(&data) {
                    let os = vm.get("os").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let mem = vm.get("memory_mb").and_then(|v| v.as_u64()).unwrap_or(0);
                    return format!("[{}] VM: {} (OS: {}, {}MB RAM, disks + config)", cluster, target.name, os, mem);
                }
            format!("VM: {} (disks + config)", target.name)
        }
        BackupTargetType::Config => "WolfStack configuration files".to_string(),
        BackupTargetType::SystemPath => {
            if target.system_path.is_empty() {
                format!("System folder: {}", target.name)
            } else {
                format!("System folder: {} ({})", target.name, target.system_path)
            }
        }
    };
    format!("[{}] {}", cluster, detail)
}

/// What to call a target in a log line.
///
/// `BackupTargetType::Config` carries a deliberately empty `name` (there is
/// only ever one of it), and `SystemPath` can too. Interpolating `target.name`
/// straight into the log then produced `Backup  → PBS: ...` with a hole where
/// the subject should be — the last line of every scheduled run on wolf1, and
/// indistinguishable from a target whose name had gone missing.
fn target_log_label(target: &BackupTarget) -> String {
    if !target.name.is_empty() {
        return target.name.clone();
    }
    match &target.target_type {
        BackupTargetType::Config => "WolfStack config".to_string(),
        BackupTargetType::SystemPath if !target.system_path.is_empty() => {
            target.system_path.clone()
        }
        other => format!("{:?}", other),
    }
}

/// Create a single backup entry — performs the backup and stores it
fn create_backup_entry(target: BackupTarget, storage: &BackupStorage) -> BackupEntry {
    // Bake the concrete Local directory into the entry up front so the stored
    // destination is self-sufficient (restore reads it back unchanged).
    let storage = &storage.with_concrete_local(&crate::paths::get().backup_local_dir);
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let hostname = local_hostname();
    let mut comments = backup_comments(&target);
    // Scheduled path has no live log, so record the format reason via tracing —
    // parity with the streaming path's on-screen explainer (wabil 2026-06-21).
    info!("Backup {} → {}: {}", target_log_label(&target), storage_label(storage),
        backup_format_explainer(&target, storage));
    // Make a file-level→tarball fallback (e.g. Proxmox LXC → vzdump) visible.
    if let Some(note) = pbs_file_level_skip_note(&target, storage) {
        comments = format!("{} | {}", comments, note);
    }
    let cluster = local_cluster_name();

    // PBS file-level (pxar) path — see create_backup_with_log for the rationale.
    if storage.storage_type == StorageType::Pbs && storage.pbs_file_level
        && let Some(res) = make_pbs_file_level_entry(&target, storage, &comments, &cluster, &hostname, None) {
            match res {
                Ok(entry) => return entry,
                Err(e) => {
                    error!("PBS file-level backup failed for {:?}: {}", target.target_type, e);
                    return BackupEntry {
                        id, target, storage: storage.clone(),
                        filename: String::new(), size_bytes: 0, created_at: now,
                        status: BackupStatus::Failed, error: e,
                        schedule_id: String::new(), comments, node_hostname: hostname,
                        docker_config: String::new(), mounts: Vec::new(),
                    };
                }
            }
        }
        // else: fall through to the tarball path (VM/Proxmox-LXC).

    let (result, docker_config, mounts) = match target.target_type {
        BackupTargetType::Docker => {
            match backup_docker(&target.name, &target.exclude_mounts, target.stop_for_backup) {
                Ok((path, size, config, m)) => (Ok((path, size)), config, m),
                Err(e) => (Err(e), String::new(), Vec::new()),
            }
        }
        BackupTargetType::Lxc => (backup_lxc(&target.name, &target.exclude_mounts, target.stop_for_backup), String::new(), Vec::new()),
        BackupTargetType::Vm => (backup_vm(&target.name), String::new(), Vec::new()),
        BackupTargetType::Config => (backup_config(), String::new(), Vec::new()),
        BackupTargetType::SystemPath => (
            backup_system_path(&target.name, &target.system_path, &target.exclude_mounts),
            String::new(), Vec::new(),
        ),
    };

    match result {
        Ok((local_path, size)) => {
            // Store to target location
            let filename = local_path.file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| format!("backup-{}.tar.gz", id));

            let pbs_notes = format!("Cluster: {} | Node: {} | {}", local_cluster_name(), hostname, comments);

            match store_backup_with_notes(&local_path, storage, &filename, Some(&pbs_notes)) {
                Ok(_) => {
                    // Remove staging file after successful store
                    let _ = fs::remove_file(&local_path);
                    BackupEntry {
                        id,
                        target,
                        storage: storage.clone(),
                        filename,
                        size_bytes: size,
                        created_at: now,
                        status: BackupStatus::Completed,
                        error: String::new(),
                        schedule_id: String::new(),
                        comments,
                        node_hostname: hostname,
                        docker_config,
                        mounts,
                    }
                },
                Err(e) => {
                    let _ = fs::remove_file(&local_path);
                    error!("Failed to store backup: {}", e);
                    BackupEntry {
                        id,
                        target,
                        storage: storage.clone(),
                        filename,
                        size_bytes: size,
                        created_at: now,
                        status: BackupStatus::Failed,
                        error: e,
                        schedule_id: String::new(),
                        comments,
                        node_hostname: hostname,
                        docker_config: String::new(),
                        mounts: Vec::new(),
                    }
                }
            }
        },
        Err(e) => {
            error!("Backup failed for {:?}: {}", target.target_type, e);
            BackupEntry {
                id,
                target,
                storage: storage.clone(),
                filename: String::new(),
                size_bytes: 0,
                created_at: now,
                status: BackupStatus::Failed,
                error: e,
                schedule_id: String::new(),
                comments,
                node_hostname: hostname,
                docker_config: String::new(),
                mounts: Vec::new(),
            }
        }
    }
}

// ─── Storage Functions ───

/// Store a backup file to the configured storage target
fn store_backup_with_notes(local_path: &Path, storage: &BackupStorage, filename: &str, notes: Option<&str>) -> Result<(), String> {
    match storage.storage_type {
        StorageType::Local => store_local(local_path, &storage.path, filename),
        StorageType::S3 => store_s3(local_path, storage, filename),
        StorageType::Remote => store_remote(local_path, &storage.remote_url, filename),
        StorageType::Wolfdisk => store_local(local_path, &storage.resolved_local_path(), filename),
        StorageType::Pbs => store_pbs_with_notes(local_path, storage, filename, notes),
        StorageType::Nfs => {
            let dir = ensure_nfs_mounted(storage)?;
            store_local(local_path, &dir, filename)
        }
        StorageType::Smb => {
            let dir = ensure_smb_mounted(storage)?;
            store_local(local_path, &dir, filename)
        }
    }
}

/// Build the stable per-destination mount point. Destinations are
/// identified by the source spec so two backup configs pointing at the
/// same share reuse one mount.
fn nas_mount_dir(kind: &str, source: &str, subpath: &str) -> String {
    // Slashes and colons can't live in a dirname — replace with `_`.
    let key: String = source.chars().map(|c| match c {
        '/' | ':' | '\\' | ' ' => '_',
        _ => c,
    }).collect();
    let mut p = format!("/mnt/wolfstack-backup/{}-{}", kind, key);
    if !subpath.is_empty() {
        p.push('/');
        p.push_str(subpath.trim_matches('/'));
    }
    p
}

/// Check whether the helper package that provides a userspace mount tool
/// (`mount.nfs`, `mount.cifs`) is installed. When missing, emit the
/// standard MISSING_PACKAGE marker (see storage::MISSING_PACKAGE_MARKER)
/// so the API + UI can prompt the user and run the install in a live
/// terminal instead of doing it silently from a mount request.
fn ensure_mount_helper(binary: &str, debian_pkg: &str, redhat_pkg: &str) -> Result<(), String> {
    if std::path::Path::new(&format!("/sbin/{}", binary)).exists()
        || std::path::Path::new(&format!("/usr/sbin/{}", binary)).exists()
    {
        return Ok(());
    }
    Err(format!(
        "{}{}|{}|{}",
        crate::storage::MISSING_PACKAGE_MARKER, binary, debian_pkg, redhat_pkg
    ))
}

/// Mount (idempotently) an NFS export for backups and return the local
/// path that store_local should write into. Reuses the existing export
/// if already mounted.
/// Validate a backup storage config by exercising whatever setup step the
/// type actually needs. Used by the "test destination" endpoint so the UI
/// can catch problems (missing mount helper, bad credentials) at save time
/// rather than letting a scheduled backup fail in the background hours
/// later. Returns Ok on success; on failure the error string may carry the
/// standard MISSING_PACKAGE marker that the frontend knows how to prompt
/// on.
pub fn test_storage(storage: &BackupStorage) -> Result<String, String> {
    match storage.storage_type {
        StorageType::Nfs => ensure_nfs_mounted(storage).map(|p| format!("NFS mount OK at {}", p)),
        StorageType::Smb => ensure_smb_mounted(storage).map(|p| format!("SMB mount OK at {}", p)),
        StorageType::Local | StorageType::Wolfdisk => {
            if storage.path.is_empty() {
                return Err("path is required".into());
            }
            if matches!(storage.storage_type, StorageType::Wolfdisk) {
                BackupStorage::validate_wolfdisk_subpath(&storage.wolfdisk_subpath)?;
            }
            let target = storage.resolved_local_path();
            std::fs::create_dir_all(&target)
                .map_err(|e| format!("Failed to create {}: {}", target, e))?;
            Ok(format!("OK — writes will go to {}", target))
        }
        // S3 / Remote / PBS each have their own connectivity concerns; they
        // aren't wired through this check yet because their failure modes
        // don't benefit from the MISSING_PACKAGE install prompt.
        StorageType::S3 | StorageType::Remote | StorageType::Pbs => {
            Ok(format!("{} destinations are not pre-tested", storage.storage_type))
        }
    }
}

fn ensure_nfs_mounted(storage: &BackupStorage) -> Result<String, String> {
    if storage.nfs_source.is_empty() {
        return Err("NFS source is not configured (expected `server:/export`)".into());
    }
    ensure_mount_helper("mount.nfs", "nfs-common", "nfs-utils")?;
    let dir = nas_mount_dir("nfs", &storage.nfs_source, "");
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create mount dir {}: {}", dir, e))?;
    if is_mounted(&dir) {
        return Ok(dir);
    }
    let options = if storage.nfs_options.is_empty() { "rw,soft,timeo=50" } else { storage.nfs_options.as_str() };
    let output = std::process::Command::new("mount")
        .args(["-t", "nfs", "-o", options, &storage.nfs_source, &dir])
        .output()
        .map_err(|e| format!("Failed to run mount: {}", e))?;
    if !output.status.success() {
        return Err(format!("NFS mount failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(dir)
}

/// SMB/CIFS equivalent of ensure_nfs_mounted. Handles optional subpath
/// so a single share can host multiple backup trees.
fn ensure_smb_mounted(storage: &BackupStorage) -> Result<String, String> {
    if storage.smb_source.is_empty() {
        return Err("SMB source is not configured (expected `//server/share`)".into());
    }
    ensure_mount_helper("mount.cifs", "cifs-utils", "cifs-utils")?;
    // Normalise Windows-style backslashes.
    let source = storage.smb_source.replace('\\', "/");
    let source = if source.starts_with("//") { source } else { format!("//{}", source.trim_start_matches('/')) };

    let root = nas_mount_dir("smb", &source, "");
    fs::create_dir_all(&root).map_err(|e| format!("Failed to create mount dir {}: {}", root, e))?;
    if !is_mounted(&root) {
        let mut opt_parts: Vec<String> = Vec::new();
        if !storage.smb_username.is_empty() {
            opt_parts.push(format!("username={}", storage.smb_username));
            opt_parts.push(format!("password={}", storage.smb_password));
            if !storage.smb_domain.is_empty() {
                opt_parts.push(format!("domain={}", storage.smb_domain));
            }
        } else {
            opt_parts.push("guest".into());
        }
        opt_parts.push("uid=0".into());
        opt_parts.push("gid=0".into());
        opt_parts.push("file_mode=0660".into());
        opt_parts.push("dir_mode=0770".into());
        opt_parts.push("vers=3.0".into());
        if !storage.smb_options.is_empty() {
            opt_parts.push(storage.smb_options.clone());
        }
        let options = opt_parts.join(",");
        let output = std::process::Command::new("mount")
            .args(["-t", "cifs", "-o", &options, &source, &root])
            .output()
            .map_err(|e| format!("Failed to run mount: {}", e))?;
        if !output.status.success() {
            return Err(format!("SMB mount failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
        }
    }
    // Optional subpath inside the share — create if missing.
    let dest = if storage.smb_subpath.is_empty() {
        root
    } else {
        let sub = storage.smb_subpath.trim_matches('/');
        let p = format!("{}/{}", root, sub);
        fs::create_dir_all(&p).map_err(|e| format!("Failed to create subpath {}: {}", p, e))?;
        p
    };
    Ok(dest)
}

fn is_mounted(path: &str) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|s| s.lines().any(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            parts.len() >= 2 && parts[1] == path
        }))
        .unwrap_or(false)
}

/// Store backup to local path
fn store_local(local_path: &Path, dest_dir: &str, filename: &str) -> Result<(), String> {
    fs::create_dir_all(dest_dir)
        .map_err(|e| format!("Failed to create backup dir {}: {}", dest_dir, e))?;
    let dest = Path::new(dest_dir).join(filename);
    fs::copy(local_path, &dest)
        .map_err(|e| format!("Failed to copy backup to {}: {}", dest.display(), e))?;

    Ok(())
}

/// Store backup to S3
fn store_s3(local_path: &Path, storage: &BackupStorage, filename: &str) -> Result<(), String> {


    // Use tokio runtime for the async S3 upload
    let _rt = tokio::runtime::Handle::try_current()
        .map_err(|_| "No tokio runtime available".to_string())?;

    let data = fs::read(local_path)
        .map_err(|e| format!("Failed to read backup file: {}", e))?;

    let bucket_name = storage.bucket.clone();
    let region_str = storage.region.clone();
    let endpoint_str = storage.endpoint.clone();
    let access_key = storage.access_key.clone();
    let secret_key = storage.secret_key.clone();
    let key = format!("wolfstack-backups/{}", filename);

    // Spawn blocking to avoid nested runtime issues
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Honour the operator's configured region for the AWS endpoint
            // (empty endpoint = real AWS). A blank region falls back to
            // us-east-1 so the host never becomes "https://s3..amazonaws.com".
            let aws_region = if region_str.trim().is_empty() {
                "us-east-1".to_string()
            } else {
                region_str.clone()
            };
            // A custom endpoint goes through the storage module's normaliser:
            // it supplies the scheme a bare hostname needs and strips a
            // trailing slash, which `Region::host()` would otherwise put in
            // the Host header and make every request a 400 (see
            // storage::endpoint_url). Real AWS keeps the derived host.
            let region = if endpoint_str.is_empty() {
                s3::Region::Custom {
                    region: aws_region.clone(),
                    endpoint: format!("https://s3.{}.amazonaws.com", aws_region),
                }
            } else {
                crate::storage::s3_custom_region(&endpoint_str, &aws_region)?
            };

            let credentials = s3::creds::Credentials::new(
                Some(&access_key),
                Some(&secret_key),
                None, None, None,
            ).map_err(|e| format!("S3 credentials error: {}", e))?;

            let bucket = s3::Bucket::new(&bucket_name, region, credentials)
                .map_err(|e| format!("S3 bucket error: {}", e))?;

            bucket.put_object(&key, &data).await
                .map_err(|e| format!("S3 upload error: {}", e))?;


            Ok::<(), String>(())
        })
    }).join().map_err(|_| "S3 upload thread panicked".to_string())?
}

/// Store backup to remote WolfStack node
fn store_remote(local_path: &Path, remote_url: &str, filename: &str) -> Result<(), String> {

    let import_url = format!("{}/api/backups/import?filename={}",
        remote_url.trim_end_matches('/'), urlencoding::encode(filename));
    // The receiving node's /api/backups/import requires auth. Sending a backup
    // to another node is an inter-node operation, so authenticate with the
    // cluster secret (require_auth's X-WolfStack-Secret path) — without this the
    // upload is rejected 401. delete_remote_backup uses the same header.
    let secret = crate::auth::load_cluster_secret();
    let auth_hdrs = crate::node_identity::curl_headers_padded(&secret, &import_url);

    let output = Command::new("curl")
        .args([
            // -s silences the progress meter; -S keeps error text on stderr so
            // a 4xx/5xx isn't reported as a blank message.
            "-s", "-S", "-f",
            // Stall detection rather than a hard ceiling — 600s fails a healthy
            // large backup purely for being big. Under 1 KB/s for 60s means the
            // peer is gone, whatever the size.
            "--speed-limit", "1024",
            "--speed-time", "60",
            "-X", "POST",
            "-H", "Content-Type: application/octet-stream",
            "-H", &auth_hdrs[0], "-H", &auth_hdrs[1], "-H", &auth_hdrs[2],
            "-H", &auth_hdrs[3], "-H", &auth_hdrs[4], "-H", &auth_hdrs[5],
            // -T streams; `--data-binary @file` buffers the entire archive in
            // curl's memory and dies with "out of memory" on a big one.
            "-T", &local_path.display().to_string(),
            &import_url,
        ])
        .output()
        .map_err(|e| format!("Failed to send to remote: {}", e))?;

    if !output.status.success() {
        return Err(format!("Remote transfer failed: {}", 
            String::from_utf8_lossy(&output.stderr)));
    }


    Ok(())
}

/// Build the PBS repository string: user!token@server:datastore
fn pbs_repo_string(storage: &BackupStorage) -> String {
    // PBS token-auth repo form: `user@realm!tokenid@server:datastore`.
    // The principal is `user@realm!tokenid`. Operators paste the token in
    // assorted ways: the bare id (`wolfstack-backup`) in the token field, OR the
    // WHOLE `root@pam!wolfstack-backup` that the PBS UI shows — into either the
    // token field or the user field. We must NOT re-prepend the user when a
    // field already carries the full principal, or we get the doubled
    // `root@pam!root@pam!wolfstack-backup` PBS rejects as "token disabled".
    let user = storage.pbs_user.trim();
    let token = storage.pbs_token_name.trim();
    let principal = if token.is_empty() {
        user.to_string()
    } else if token.contains('!') || token.contains('@') {
        // The token field already holds the full `user@realm!tokenid`.
        token.to_string()
    } else if user.contains('!') {
        // The user field already holds the full principal; token is the bare id.
        user.to_string()
    } else {
        format!("{}!{}", user, token)
    };
    format!("{}@{}:{}", principal, storage.pbs_server, storage.pbs_datastore)
}

/// Normalize a PBS server TLS fingerprint to the colon-separated form
/// `proxmox-backup-client` expects (`65:0b:69:…`). Operators paste it in either
/// form (the PBS UI and `proxmox-backup-manager cert info` show different ones);
/// passed un-coloned, the client can't match it and drops to an interactive
/// y/n prompt the daemon can't answer, so the connection just fails. We strip
/// any separators, then re-insert a colon every byte. A value that isn't a
/// clean 64-char SHA-256 hex string is returned trimmed-but-unchanged rather
/// than mangled — a faithful pass-through beats a corrupted fingerprint.
pub fn format_pbs_fingerprint(fp: &str) -> String {
    let hex: String = fp.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 64 {
        return fp.trim().to_string();
    }
    hex.as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(":")
}

/// Store backup to Proxmox Backup Server
fn store_pbs_with_notes(local_path: &Path, storage: &BackupStorage, filename: &str, notes: Option<&str>) -> Result<(), String> {
    store_pbs_with_notes_and_log(local_path, storage, filename, notes, None)
}

fn store_pbs_with_notes_and_log(local_path: &Path, storage: &BackupStorage, filename: &str, notes: Option<&str>, log: Option<&std::sync::mpsc::Sender<String>>) -> Result<(), String> {
    let repo = pbs_repo_string(storage);

    // Extract the actual VMID/container name from the filename
    // Formats: "vzdump-lxc-131-2026..." → "131", "lxc-myct-2026..." → "myct",
    //          "docker-myapp-2026..." → "myapp", "vm-myvm-2026..." → "myvm"
    let backup_id = extract_backup_id_from_filename(filename);

    // Determine backup type from filename prefix. Docker archives
    // (`docker-<name>-…`, or a vzdump-style `vzdump-docker-…`) are typed "ct"
    // — the same as the live file-level Docker path (see build_pxar_pairs's
    // Docker arm) — so they list as a Container, not a Host. Without the
    // docker- case they fell into the `else` and were stored as "host", which
    // then made the PBS-list restore refuse them ("host snapshot isn't
    // supported here"). The container name is still parsed correctly by
    // extract_backup_id_from_filename, which already understands `docker-`.
    let backup_type = pbs_backup_type_for_filename(filename);

    // Isolate this one backup file in its own subdirectory before
    // handing the directory to `proxmox-backup-client backup …pxar:DIR`.
    // The shared staging dir (`/tmp/wolfstack-backups/`) can contain
    // stale files from previous runs (e.g. from a backup that failed
    // before cleanup), and backup_all() runs many targets in sequence
    // — without isolation each snapshot's pxar archive pulls in every
    // file currently sitting in staging, which wastes PBS space and
    // makes per-snapshot restore nonsensical.
    let parent = local_path.parent().unwrap_or(Path::new("/tmp"));
    let isolate = parent.join(format!(".pbs-stage-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&isolate)
        .map_err(|e| format!("PBS stage dir: {}", e))?;
    let file_name = local_path.file_name()
        .ok_or_else(|| "local_path has no filename".to_string())?;
    let isolate_file = isolate.join(file_name);
    // Hardlink when possible so a 5 GB vzdump archive doesn't
    // double its disk footprint just for the PBS upload.
    if std::fs::hard_link(local_path, &isolate_file).is_err() {
        std::fs::copy(local_path, &isolate_file)
            .map_err(|e| {
                let _ = std::fs::remove_dir_all(&isolate);
                format!("PBS stage copy: {}", e)
            })?;
    }

    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("backup")
       .arg(format!("backup.pxar:{}", isolate.display()))
       .arg("--repository").arg(&repo)
       .arg("--backup-id").arg(&backup_id)
       .arg("--backup-type").arg(backup_type);

    if !storage.pbs_fingerprint.is_empty() {
        cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
    }
    if !storage.pbs_namespace.is_empty() {
        cmd.arg("--ns").arg(&storage.pbs_namespace);
    }

    let pbs_pw = if !storage.pbs_token_secret.is_empty() { &storage.pbs_token_secret }
                 else { &storage.pbs_password };
    if !pbs_pw.is_empty() {
        cmd.env("PBS_PASSWORD", pbs_pw);
    }

    // Stream stderr for progress when log channel is available
    if let Some(log_tx) = log {
        use std::process::Stdio;
        use std::io::BufReader;
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn()
            .map_err(|e| format!("Failed to start proxmox-backup-client: {}", e))?;

        if let Some(stderr) = child.stderr.take() {
            use std::io::Read;
            let mut reader = BufReader::new(stderr);
            let mut buf = [0u8; 1];
            let mut line_buf = String::new();
            while reader.read(&mut buf).unwrap_or(0) > 0 {
                let ch = buf[0] as char;
                if ch == '\n' || ch == '\r' {
                    let trimmed = line_buf.trim().to_string();
                    if !trimmed.is_empty() {
                        let _ = log_tx.send(format!("  PBS: {}", trimmed));
                    }
                    line_buf.clear();
                } else {
                    line_buf.push(ch);
                }
            }
            let trimmed = line_buf.trim().to_string();
            if !trimmed.is_empty() {
                let _ = log_tx.send(format!("  PBS: {}", trimmed));
            }
        }

        let status = child.wait()
            .map_err(|e| {
                let _ = std::fs::remove_dir_all(&isolate);
                format!("PBS backup wait failed: {}", e)
            })?;
        if !status.success() {
            let _ = std::fs::remove_dir_all(&isolate);
            return Err("PBS backup failed (see log above)".to_string());
        }
    } else {
        let output = cmd.output()
            .map_err(|e| {
                let _ = std::fs::remove_dir_all(&isolate);
                format!("Failed to run proxmox-backup-client: {}", e)
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let _ = std::fs::remove_dir_all(&isolate);
            return Err(format!("PBS backup failed: {}", stderr.trim()));
        }
    }
    // Drop the per-backup isolation dir now that the upload succeeded.
    // The snapshot-notes API call below only needs repo+snapshot info.
    let _ = std::fs::remove_dir_all(&isolate);

    // Set snapshot notes with cluster/node/container metadata for identification
    if let Some(notes_text) = notes {
        // Find the snapshot we just created — latest one matching our backup-type/id
        let mut list_cmd = Command::new("proxmox-backup-client");
        list_cmd.args(["snapshot", "list", "--output-format", "json", "--repository", &repo]);
        if !storage.pbs_fingerprint.is_empty() {
            list_cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
        }
        if !storage.pbs_namespace.is_empty() {
            list_cmd.arg("--ns").arg(&storage.pbs_namespace);
        }
        if !pbs_pw.is_empty() {
            list_cmd.env("PBS_PASSWORD", pbs_pw);
        }

        if let Ok(snap_out) = list_cmd.output()
            && let Ok(snaps) = serde_json::from_slice::<serde_json::Value>(&snap_out.stdout)
                && let Some(arr) = snaps.as_array() {
                    let mut best_time: i64 = 0;
                    let mut best_snap = String::new();
                    for s in arr {
                        let st = s.get("backup-type").and_then(|v| v.as_str()).unwrap_or("");
                        let si = s.get("backup-id").and_then(|v| v.as_str()).unwrap_or("");
                        let stime = s.get("backup-time").and_then(|v| v.as_i64()).unwrap_or(0);
                        if st == backup_type && si == backup_id && stime > best_time {
                            // The snapshot's time component must be an RFC3339
                            // string (e.g. "ct/131/2026-05-21T09:35:01Z"): the
                            // PBS CLI parses the <snapshot> argument as a
                            // BackupDir and rejects a raw unix epoch.
                            // `snapshot list --output-format json` reports
                            // `backup-time` as an epoch, so convert it here —
                            // without this, `snapshot notes update` fails and
                            // the snapshot lands on PBS with an empty comment.
                            // Source: pbs.proxmox.com/docs/backup-client.html
                            //   — snapshot paths shown as host/elsa/2019-12-03T09:35:01Z
                            if let Some(ts) = chrono::DateTime::from_timestamp(stime, 0) {
                                best_time = stime;
                                best_snap = format!("{}/{}/{}", st, si,
                                    ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
                            }
                        }
                    }
                    if !best_snap.is_empty() {
                        // proxmox-backup-client snapshot notes update [OPTIONS] <snapshot> <notes>
                        //
                        // Both `snapshot` and `notes` are POSITIONAL — pass them
                        // in order, NOT as a `--notes` flag (older clients
                        // rejected the flag form with "parameter verification
                        // failed - 'notes': missing argument", reported
                        // 2026-05-05).
                        //
                        // Do NOT insert a `--` end-of-options separator: the PBS
                        // CLI (proxmox-router, not getopt/clap) does NOT treat
                        // `--` as a separator. It consumes `--` as the first
                        // positional (snapshot), shifts `best_snap` into the
                        // notes slot, and reports the real notes text as
                        // "got additional arguments" — so the notes call failed
                        // on every PBS backup (wabil 2026-06-21). Both our
                        // positionals are option-safe without it: the snapshot
                        // is always `type/id/RFC3339` and the notes text always
                        // begins with "Cluster:", so neither can be mistaken for
                        // an option. Each arg reaches the child as one execve
                        // argv element — spaces preserved, no shell expansion.
                        let mut notes_cmd = Command::new("proxmox-backup-client");
                        notes_cmd.args(["snapshot", "notes", "update", "--repository", &repo]);
                        if !storage.pbs_fingerprint.is_empty() {
                            notes_cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
                        }
                        if !storage.pbs_namespace.is_empty() {
                            notes_cmd.arg("--ns").arg(&storage.pbs_namespace);
                        }
                        notes_cmd.args(pbs_notes_positionals(&best_snap, notes_text));
                        if !pbs_pw.is_empty() {
                            notes_cmd.env("PBS_PASSWORD", pbs_pw);
                        }
                        match notes_cmd.output() {
                            Ok(out) if out.status.success() => {
                                if let Some(log_tx) = log {
                                    let _ = log_tx.send(
                                        "  PBS: snapshot notes set".to_string());
                                }
                            }
                            Ok(out) => {
                                let err = String::from_utf8_lossy(&out.stderr);
                                warn!("Failed to set PBS snapshot notes for {}: {}",
                                    best_snap, err.trim());
                                if let Some(log_tx) = log {
                                    let _ = log_tx.send(format!(
                                        "  PBS: warning — could not set snapshot \
                                         notes: {}", err.trim()));
                                }
                            }
                            Err(e) => {
                                warn!("Failed to run `proxmox-backup-client \
                                       snapshot notes update`: {}", e);
                                if let Some(log_tx) = log {
                                    let _ = log_tx.send(format!(
                                        "  PBS: warning — could not run snapshot \
                                         notes update: {}", e));
                                }
                            }
                        }
                    } else {
                        warn!("PBS snapshot notes: no snapshot matching {}/{} \
                               found — comment not set", backup_type, backup_id);
                        if let Some(log_tx) = log {
                            let _ = log_tx.send(format!(
                                "  PBS: warning — uploaded snapshot {}/{} not \
                                 found, comment not set", backup_type, backup_id));
                        }
                    }
                }
    }

    Ok(())
}

/// Return an Err carrying the standard MISSING_PACKAGE marker when
/// `proxmox-backup-client` isn't installed, so the UI shows its install
/// prompt instead of a raw spawn error.
/// Source: storage::MISSING_PACKAGE_MARKER = "MISSING_PACKAGE|"; format is
/// `MISSING_PACKAGE|<binary>|<debian_pkg>|<redhat_pkg>`.
fn ensure_pbs_client_installed() -> Result<(), String> {
    let present = Command::new("which")
        .arg("proxmox-backup-client")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if present {
        return Ok(());
    }
    Err(format!(
        "{}{}|{}|{}",
        crate::storage::MISSING_PACKAGE_MARKER,
        "proxmox-backup-client",
        "proxmox-backup-client",
        "proxmox-backup-client",
    ))
}

/// Apply the shared PBS auth/connection env + flags to a backup-client
/// command. Centralises the fingerprint / namespace / password handling
/// every PBS invocation repeats, so file-level backup + restore can't
/// drift from the tarball path. `pbs_pw` chooses token-secret over
/// password, exactly as `store_pbs_with_notes_and_log` does.
fn pbs_apply_common(cmd: &mut Command, storage: &BackupStorage) {
    if !storage.pbs_fingerprint.is_empty() {
        cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
    }
    if !storage.pbs_namespace.is_empty() {
        cmd.arg("--ns").arg(&storage.pbs_namespace);
    }
    let pbs_pw = if !storage.pbs_token_secret.is_empty() { &storage.pbs_token_secret }
                 else { &storage.pbs_password };
    if !pbs_pw.is_empty() {
        cmd.env("PBS_PASSWORD", pbs_pw);
    }
}

/// One `name.pxar:dir` pair for a file-level PBS snapshot.
struct PxarPair {
    /// Archive name as it appears in the snapshot, e.g. "root.pxar".
    archive: String,
    /// Absolute host directory to archive.
    dir: PathBuf,
    /// Cleaned up after the snapshot (true for the docker `docker export`
    /// staging tree we materialise; false for paths we don't own such as a
    /// live rootfs or a system folder).
    ephemeral: bool,
}

/// Does PBS file-level apply to this target type, without performing any
/// side-effecting work (no docker export)? Used to decide whether to take
/// the file-level path or fall back to the tarball path. Docker / native LXC
/// / SystemPath qualify; VM / Proxmox-LXC / Config do not.
fn pbs_file_level_applies(target: &BackupTarget) -> bool {
    match target.target_type {
        BackupTargetType::Docker => true,
        BackupTargetType::Lxc => !crate::containers::is_proxmox(),
        BackupTargetType::SystemPath => true,
        // Config is a file tree like any other — as pxar, PBS can browse and
        // restore a single config file from any snapshot (wabil 2026-07-08).
        BackupTargetType::Config => true,
        BackupTargetType::Vm => false,
    }
}

/// When PBS file-level is ENABLED but a target can't use it, return a plain-
/// English reason. Makes the tarball/vzdump fallback visibly intentional in the
/// backup's details + live log instead of looking like "file-level is broken"
/// (wabil 2026-06-21: "file level not implemented … lxc is tar.zst"). Returns
/// None when file-level isn't requested or the target WILL use pxar.
/// Prefix used by `pbs_file_level_skip_note`; shared so `backup_format_explainer`
/// can strip it back off without the two drifting out of sync.
const PBS_FL_SKIP_PREFIX: &str = "PBS file-level not applicable: ";

fn pbs_file_level_skip_note(target: &BackupTarget, storage: &BackupStorage) -> Option<String> {
    if storage.storage_type != StorageType::Pbs || !storage.pbs_file_level || pbs_file_level_applies(target) {
        return None;
    }
    let why = match target.target_type {
        BackupTargetType::Lxc =>
            "Proxmox LXC rootfs is on block storage (ZFS/LVM) — pxar file-level isn't possible, using vzdump image",
        BackupTargetType::Vm =>
            "VMs back up as a disk image, not per-file — pxar file-level doesn't apply",
        _ => "pxar file-level isn't available for this target — using image/tarball backup",
    };
    Some(format!("{}{}", PBS_FL_SKIP_PREFIX, why))
}

/// Short destination noun for operator-facing log lines ("Local folder",
/// "NFS share", …) — distinct from `storage_label`, which includes the path.
fn storage_kind_noun(storage: &BackupStorage) -> &'static str {
    match storage.storage_type {
        StorageType::Local => "Local folder",
        StorageType::S3 => "S3",
        StorageType::Remote => "remote",
        StorageType::Wolfdisk => "WolfDisk",
        StorageType::Pbs => "PBS",
        StorageType::Nfs => "NFS share",
        StorageType::Smb => "SMB share",
    }
}

/// One concise, ALWAYS-logged line stating the archive format a backup will
/// produce and why — so a `.tar.gz` is never mistaken for a broken feature
/// (wabil 2026-06-21: "all backups tar.gz… I can't see the reason in the logs.
/// Don't know why even a straight backup of a local folder has to be tar.gz").
/// pxar file-level is a PBS-only format, so every non-PBS destination is a
/// compressed archive by nature — this spells that out instead of leaving the
/// operator guessing.
fn backup_format_explainer(target: &BackupTarget, storage: &BackupStorage) -> String {
    // Genuine pxar file-level: PBS destination + flag on + applicable target.
    if storage.storage_type == StorageType::Pbs
        && storage.pbs_file_level
        && pbs_file_level_applies(target)
    {
        return "Format: pxar file-level — PBS per-file restore is available".to_string();
    }
    if storage.storage_type == StorageType::Pbs {
        // PBS, but not pxar. Either file-level is off, or it can't apply here.
        if let Some(note) = pbs_file_level_skip_note(target, storage) {
            return format!("Format: image/tarball into PBS — {}",
                note.trim_start_matches(PBS_FL_SKIP_PREFIX));
        }
        return "Format: compressed tar.gz stored in PBS — tick 'File-level (pxar)' \
                in PBS settings for per-file restore".to_string();
    }
    // Non-PBS destination: pxar needs a PBS datastore, so it's always a tarball.
    let dest = storage_kind_noun(storage);
    if storage.pbs_file_level {
        return format!("Format: compressed tar.gz — file-level (pxar) needs a Proxmox \
                        Backup Server destination, not {}", dest);
    }
    format!("Format: compressed tar.gz — {} keeps each backup as one compressed archive", dest)
}

/// Build the pxar source pairs for a file-level PBS backup of `target`.
/// Returns (backup_type, backup_id, pairs). For Docker the container's
/// filesystem is materialised into a staging tree via `docker export`;
/// volumes/binds become their own pxar archives. For LXC the live rootfs
/// directory is used directly. For SystemPath the folder is used directly.
/// VMs return Err — disk images aren't a file tree (caller falls back to
/// the image backup).
/// If a container is compose-managed, return (config_files_csv, working_dir)
/// from its compose labels so the backup can capture the stack definition, not
/// just the rebuildable rootfs (wabil 2026-06-22). None for non-compose.
fn docker_compose_project(name: &str) -> Option<(String, String)> {
    let out = Command::new("docker")
        .args([
            "inspect", "--format",
            "{{index .Config.Labels \"com.docker.compose.project.config_files\"}}|{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}",
            name,
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let (cf, wd) = line.split_once('|')?;
    // A missing label renders as "<no value>" in Go templates — treat as empty.
    let clean = |s: &str| -> String {
        let s = s.trim();
        if s == "<no value>" { String::new() } else { s.to_string() }
    };
    let (cf, wd) = (clean(cf), clean(wd));
    if cf.is_empty() && wd.is_empty() {
        return None;
    }
    Some((cf, wd))
}

/// Returns (backup_type, backup_id, pxar pairs, command-level pxar
/// `--exclude` globs). Only SystemPath populates the excludes (its
/// single archive is the folder itself); Docker already excludes at the
/// volume/bind level and returns none. The excludes are command-level
/// because `proxmox-backup-client --exclude` is a per-command flag and
/// the populated case is always a single-archive backup.
fn build_pxar_pairs(target: &BackupTarget) -> Result<(String, String, Vec<PxarPair>, Vec<String>), String> {
    let staging = ensure_staging_dir()?;
    match target.target_type {
        BackupTargetType::Docker => {
            let mut pairs: Vec<PxarPair> = Vec::new();
            // Materialise the container filesystem. `docker export` streams the
            // flattened container fs as a tar; pipe it into a fresh dir.
            let work = staging.join(format!("pbs-fl-docker-{}", Uuid::new_v4().simple()));
            fs::create_dir_all(&work)
                .map_err(|e| format!("file-level staging dir: {}", e))?;
            let rootfs = work.join("rootfs");
            fs::create_dir_all(&rootfs)
                .map_err(|e| format!("file-level rootfs dir: {}", e))?;
            // No shell — pipe `docker export <name>` directly into `tar -x`.
            // Using two Command processes with an OS pipe avoids any shell
            // metacharacter interpretation of the container name (a name like
            // `$(rm -rf /)` is just an argv element to docker, never evaluated).
            use std::process::Stdio;
            // stderr is sent to null rather than piped: nothing drains it while
            // we block on tar consuming stdout, and a full stderr pipe buffer
            // would deadlock docker. `docker export` stderr is trivial anyway;
            // the exit code is the signal we act on.
            let mut exporter = Command::new("docker")
                .arg("export")
                .arg(&target.name)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| { let _ = fs::remove_dir_all(&work); format!("docker export failed to start: {}", e) })?;
            let export_stdout = exporter.stdout.take()
                .ok_or_else(|| { let _ = fs::remove_dir_all(&work); "docker export produced no stdout".to_string() })?;
            let tar_status = Command::new("tar")
                .arg("-x")
                .arg("-C").arg(&rootfs)
                .stdin(Stdio::from(export_stdout))
                .status()
                .map_err(|e| { let _ = fs::remove_dir_all(&work); format!("tar extract failed to start: {}", e) })?;
            let exporter_status = exporter.wait()
                .map_err(|e| { let _ = fs::remove_dir_all(&work); format!("docker export wait failed: {}", e) })?;
            if !exporter_status.success() {
                let _ = fs::remove_dir_all(&work);
                return Err(format!("docker export failed (exit {})",
                    exporter_status.code().unwrap_or(-1)));
            }
            if !tar_status.success() {
                let _ = fs::remove_dir_all(&work);
                return Err("docker export tar extract failed".to_string());
            }
            pairs.push(PxarPair { archive: "root.pxar".into(), dir: rootfs, ephemeral: false });
            // The whole `work` dir is the ephemeral owner — track it via a
            // sentinel pair so cleanup removes it once.
            pairs.push(PxarPair { archive: String::new(), dir: work.clone(), ephemeral: true });

            // Volumes + binds as separate pxar archives, honouring exclusions.
            if let Ok(mounts) = discover_docker_mounts(&target.name) {
                let mut vol_idx = 0usize;
                let mut bind_idx = 0usize;
                for m in mounts {
                    if mount_is_excluded(&m.source, &target.exclude_mounts) { continue; }
                    match m.mount_type.as_str() {
                        "volume" => {
                            // Resolved once, by discovery.
                            let data_dir = m.data_path.clone();
                            if Path::new(&data_dir).is_dir() {
                                pairs.push(PxarPair {
                                    archive: format!("volume-{}.pxar", vol_idx),
                                    dir: PathBuf::from(data_dir),
                                    ephemeral: false,
                                });
                                vol_idx += 1;
                            }
                        }
                        "bind"
                            if bind_source_safe(&m.source).is_ok() && Path::new(&m.source).is_dir() => {
                                pairs.push(PxarPair {
                                    archive: format!("bind-{}.pxar", bind_idx),
                                    dir: PathBuf::from(&m.source),
                                    ephemeral: false,
                                });
                                bind_idx += 1;
                            }
                        _ => {}
                    }
                }
            }

            // Compose stack definition: for a compose-managed container also
            // capture the compose file(s) + the project's `.env` as `compose.pxar`
            // so the stack can be recreated, not just its rebuildable rootfs
            // (wabil 2026-06-22). Additive — rootfs/volumes/binds are unchanged.
            // Lives under `work`, which the ephemeral sentinel already cleans up.
            if let Some((config_files, working_dir)) = docker_compose_project(&target.name) {
                let compose_stage = work.join("compose");
                if fs::create_dir_all(&compose_stage).is_ok() {
                    let mut copied = 0usize;
                    for (i, f) in config_files.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).enumerate() {
                        let src = Path::new(f);
                        if let Some(fname) = src.file_name() {
                            // Prefix an index on basename collision (e.g. two
                            // `docker-compose.yml` overrides) so neither is
                            // silently overwritten.
                            let mut dest = compose_stage.join(fname);
                            if dest.exists() {
                                dest = compose_stage.join(format!("{}-{}", i, fname.to_string_lossy()));
                            }
                            if fs::copy(src, &dest).is_ok() {
                                copied += 1;
                            }
                        }
                    }
                    if !working_dir.is_empty() {
                        let env = Path::new(&working_dir).join(".env");
                        if env.is_file() && fs::copy(&env, compose_stage.join(".env")).is_ok() {
                            copied += 1;
                        }
                    }
                    if copied > 0 {
                        pairs.push(PxarPair {
                            archive: "compose.pxar".into(),
                            dir: compose_stage,
                            ephemeral: false,
                        });
                    }
                }
            }
            Ok(("ct".to_string(), target.name.clone(), pairs, Vec::new()))
        }
        BackupTargetType::Lxc => {
            if crate::containers::is_proxmox() {
                // Proxmox rootfs commonly lives on ZFS/LVM (block) — not a
                // plain directory we can hand to pxar. File-level isn't
                // available there; caller falls back to the vzdump image.
                return Err("PBS file-level backup isn't available for Proxmox LXC \
                    (rootfs is on block storage) — using vzdump image backup instead".into());
            }
            let base = crate::containers::lxc_base_dir(&target.name);
            let rootfs = format!("{}/{}/rootfs", base, target.name);
            if !Path::new(&rootfs).is_dir() {
                return Err(format!("LXC rootfs not found at {}", rootfs));
            }
            Ok(("ct".to_string(), target.name.clone(),
                vec![PxarPair { archive: "root.pxar".into(), dir: PathBuf::from(rootfs), ephemeral: false }],
                Vec::new()))
        }
        BackupTargetType::SystemPath => {
            validate_system_path(&target.system_path)?;
            let dir = target.system_path.trim_end_matches('/').to_string();
            // Translate operator folder-exclusions into anchored pxar
            // globs (the SystemPath file-level path previously ignored
            // exclude_mounts entirely — wabil 2026-07-06: excludes worked
            // for tarball but not PBS file-level). Out-of-folder entries
            // drop, mirroring the tarball path.
            let excludes: Vec<String> = target.exclude_mounts.iter()
                .filter_map(|e| pxar_exclude_pattern(e, &dir))
                .collect();
            Ok(("host".to_string(),
                sanitize_archive_name(if target.name.trim().is_empty() {
                    Path::new(&dir).file_name().and_then(|n| n.to_str()).unwrap_or("folder")
                } else { target.name.trim() }),
                vec![PxarPair { archive: "root.pxar".into(), dir: PathBuf::from(dir), ephemeral: false }],
                excludes))
        }
        BackupTargetType::Config => {
            // Same tree the tarball path archives, uploaded as pxar so PBS
            // can browse/restore a single config file from any snapshot
            // (wabil 2026-07-08). Hostname in the backup-id: every node has
            // "the" config target, so a shared datastore would otherwise
            // interleave snapshots from different nodes under one id.
            let bundle = stage_config_bundle()?;
            Ok((
                "host".to_string(),
                config_pxar_backup_id(&local_hostname()),
                vec![PxarPair { archive: "root.pxar".into(), dir: bundle, ephemeral: true }],
                Vec::new(),
            ))
        }
        BackupTargetType::Vm => {
            Err("PBS file-level backup isn't available for VMs (disk images are \
                 not a file tree) — using the disk-image backup instead".into())
        }
    }
}

/// Perform a file-level (pxar) PBS backup for `target`. Uploads the
/// workload's content directory as native pxar archives so PBS per-file
/// restore works. `notes` becomes the snapshot comment. Returns the
/// snapshot's backup-type/backup-id so the caller can record a matching
/// BackupEntry (filename uses a `pbsfl-` marker so restore routes to the
/// file-level path). On VM/Proxmox-LXC the caller falls back to the
/// tarball path — those return Err from build_pxar_pairs.
fn backup_pbs_file_level(
    target: &BackupTarget,
    storage: &BackupStorage,
    notes: Option<&str>,
    log: Option<&std::sync::mpsc::Sender<String>>,
) -> Result<(String, String), String> {
    ensure_pbs_client_installed()?;
    let repo = pbs_repo_string(storage);
    let (backup_type, backup_id, pairs, pxar_excludes) = build_pxar_pairs(target)?;

    // Owners we must clean up regardless of outcome.
    let ephemeral_dirs: Vec<PathBuf> = pairs.iter()
        .filter(|p| p.ephemeral)
        .map(|p| p.dir.clone())
        .collect();
    let cleanup = |dirs: &[PathBuf]| { for d in dirs { let _ = fs::remove_dir_all(d); } };

    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("backup");
    let mut archive_count = 0;
    for p in &pairs {
        if p.archive.is_empty() { continue; } // sentinel cleanup-only pair
        cmd.arg(format!("{}:{}", p.archive, p.dir.display()));
        archive_count += 1;
    }
    if archive_count == 0 {
        cleanup(&ephemeral_dirs);
        return Err("file-level backup produced no archives to upload".into());
    }
    // Folder exclusions (SystemPath). `--exclude` is a command-level flag
    // and the populated case is always a single archive, so there's no
    // cross-archive ambiguity. Source: pbs.proxmox.com/docs/backup-client.html.
    for pat in &pxar_excludes {
        cmd.arg("--exclude").arg(pat);
    }
    cmd.arg("--repository").arg(&repo)
       .arg("--backup-id").arg(&backup_id)
       .arg("--backup-type").arg(&backup_type);
    pbs_apply_common(&mut cmd, storage);

    if let Some(log_tx) = log {
        let _ = log_tx.send(format!("  PBS file-level: {} archive(s) → {}/{}",
            archive_count, backup_type, backup_id));
        if !pxar_excludes.is_empty() {
            // Show the operator's raw entry alongside the pxar glob it became
            // (e.g. `/mnt/docker/plex → /plex`) so the transformed pattern is
            // recognisable as what they typed (review 2026-07-06).
            if target.target_type == BackupTargetType::SystemPath {
                let (applied, _dropped) = classify_folder_excludes(&target.system_path, &target.exclude_mounts);
                let shown: Vec<String> = applied.iter().zip(pxar_excludes.iter())
                    .map(|(raw, pat)| format!("{} → {}", raw, pat))
                    .collect();
                let _ = log_tx.send(format!("  Excluding {} sub-path(s): {}",
                    pxar_excludes.len(), shown.join(", ")));
            } else {
                let _ = log_tx.send(format!("  Excluding {} sub-path(s): {}",
                    pxar_excludes.len(), pxar_excludes.join(", ")));
            }
        }
        // Surface out-of-folder excludes that were dropped, matching the
        // tarball path's diagnostic (a SystemPath target only).
        if target.target_type == BackupTargetType::SystemPath && !target.exclude_mounts.is_empty() {
            let (_applied, dropped) = classify_folder_excludes(&target.system_path, &target.exclude_mounts);
            if !dropped.is_empty() {
                let _ = log_tx.send(format!(
                    "  ⚠ {} exclude(s) IGNORED — not inside '{}': {}. Exclusions must be sub-paths of the backed-up folder.",
                    dropped.len(), target.system_path, dropped.join(", ")));
            }
        }
    }

    let output = cmd.output()
        .map_err(|e| { cleanup(&ephemeral_dirs); format!("Failed to run proxmox-backup-client: {}", e) })?;
    cleanup(&ephemeral_dirs);
    if !output.status.success() {
        return Err(format!("PBS file-level backup failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()));
    }
    if let Some(log_tx) = log {
        let _ = log_tx.send("  PBS file-level: upload complete".to_string());
    }

    // Set snapshot notes — reuse the same "find latest matching snapshot"
    // logic the tarball path uses.
    if let Some(notes_text) = notes {
        set_pbs_snapshot_notes(storage, &repo, &backup_type, &backup_id, notes_text, log);
    }
    Ok((backup_type, backup_id))
}

/// Filename marker that flags a BackupEntry as a PBS file-level (pxar)
/// snapshot rather than a tarball-in-pxar. Restore keys off this prefix to
/// route to the file-level restore path.
const PBS_FILE_LEVEL_PREFIX: &str = "pbsfl-";

/// PBS backup-id for a file-level CONFIG snapshot of `hostname`. One helper so
/// the backup side (local hostname) and the restore side (the hostname
/// recorded in the entry) can never drift apart.
fn config_pxar_backup_id(hostname: &str) -> String {
    sanitize_archive_name(&format!("wolfstack-config-{}", hostname))
}

/// True if this entry is a PBS file-level (pxar) snapshot.
fn is_pbs_file_level_entry(entry: &BackupEntry) -> bool {
    entry.storage.storage_type == StorageType::Pbs
        && entry.filename.starts_with(PBS_FILE_LEVEL_PREFIX)
}

/// Run a file-level PBS backup for `target` and build the resulting
/// BackupEntry. `None` means file-level doesn't apply to this target
/// (VM/Proxmox-LXC) — the caller falls back to the tarball path.
/// `Some(Err)` means file-level applied but failed.
fn make_pbs_file_level_entry(
    target: &BackupTarget,
    storage: &BackupStorage,
    comments: &str,
    cluster: &str,
    hostname: &str,
    log: Option<&std::sync::mpsc::Sender<String>>,
) -> Option<Result<BackupEntry, String>> {
    // Probe applicability without side effects first (build_pxar_pairs does a
    // real `docker export` for Docker, so we must NOT call it just to test).
    if !pbs_file_level_applies(target) {
        return None;
    }
    let pbs_notes = format!("Cluster: {} | Node: {} | {}", cluster, hostname, comments);
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();
    match backup_pbs_file_level(target, storage, Some(&pbs_notes), log) {
        Ok((btype, bid)) => {
            let ts = Utc::now().format("%Y%m%d-%H%M%S");
            let filename = format!("{}{}-{}-{}.pxar", PBS_FILE_LEVEL_PREFIX, btype, bid, ts);
            Some(Ok(BackupEntry {
                id,
                target: target.clone(),
                storage: storage.clone(),
                filename,
                size_bytes: 0, // PBS dedups; per-snapshot byte size isn't reported here
                created_at: now,
                status: BackupStatus::Completed,
                error: String::new(),
                schedule_id: String::new(),
                comments: comments.to_string(),
                node_hostname: hostname.to_string(),
                docker_config: String::new(),
                mounts: Vec::new(),
            }))
        }
        Err(e) => Some(Err(e)),
    }
}

/// Full-archive restore of a PBS file-level (pxar) snapshot. Extracts the
/// `root.pxar` filesystem tree into `target_dir` using
/// `proxmox-backup-client restore <snapshot> <archive> <target>`.
/// Per-FILE restore (picking one file out of the tree) is done through PBS's
/// own web UI / `proxmox-backup-client catalog` + interactive restore — this
/// function does the complete-archive case end to end.
///
/// `target_override` (non-empty) chooses where the tree lands; empty applies
/// a type-appropriate default:
///   • native LXC  → the container rootfs (`<base>/<name>/rootfs`)
///   • SystemPath  → the original folder
///   • Docker      → a staging dir under the restore area (operator then has
///                   the files; container re-creation from a flat fs isn't
///                   automatic — surfaced in the returned message)
fn restore_pbs_file_level_entry(entry: &BackupEntry, target_override: &str) -> Result<String, String> {
    ensure_pbs_client_installed()?;
    let storage = &entry.storage;
    let repo = pbs_repo_string(storage);

    // Re-derive the snapshot type/id from the entry's target — robust against
    // any filename-parsing fragility. These mirror exactly what
    // build_pxar_pairs produced at backup time.
    let backup_type = match entry.target.target_type {
        BackupTargetType::SystemPath | BackupTargetType::Config => "host",
        _ => "ct",
    }.to_string();
    let backup_id = match entry.target.target_type {
        BackupTargetType::SystemPath => sanitize_archive_name(if entry.target.name.trim().is_empty() {
            Path::new(entry.target.system_path.trim_end_matches('/'))
                .file_name().and_then(|n| n.to_str()).unwrap_or("folder")
        } else { entry.target.name.trim() }),
        // Use the hostname RECORDED at backup time, not the local one — a
        // new-machine restore runs on a different host by definition.
        BackupTargetType::Config => config_pxar_backup_id(&entry.node_hostname),
        _ => entry.target.name.clone(),
    };

    // Find the newest snapshot matching type/id.
    let mut list_cmd = Command::new("proxmox-backup-client");
    list_cmd.args(["snapshot", "list", "--output-format", "json", "--repository", &repo]);
    pbs_apply_common(&mut list_cmd, storage);
    let list_out = list_cmd.output()
        .map_err(|e| format!("Failed to list PBS snapshots: {}", e))?;
    if !list_out.status.success() {
        return Err(format!("PBS snapshot list failed: {}",
            String::from_utf8_lossy(&list_out.stderr).trim()));
    }
    let snaps: serde_json::Value = serde_json::from_slice(&list_out.stdout)
        .unwrap_or(serde_json::Value::Array(vec![]));
    let mut best_time: i64 = 0;
    let mut snapshot = String::new();
    if let Some(arr) = snaps.as_array() {
        for s in arr {
            let st = s.get("backup-type").and_then(|v| v.as_str()).unwrap_or("");
            let si = s.get("backup-id").and_then(|v| v.as_str()).unwrap_or("");
            let stime = s.get("backup-time").and_then(|v| v.as_i64()).unwrap_or(0);
            if st != backup_type || si != backup_id || stime <= best_time { continue; }
            if let Some(ts) = chrono::DateTime::from_timestamp(stime, 0) {
                best_time = stime;
                snapshot = format!("{}/{}/{}", st, si,
                    ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
            }
        }
    }
    if snapshot.is_empty() {
        return Err(format!("No PBS file-level snapshot found for {}/{}", backup_type, backup_id));
    }

    // Decide the target directory.
    let target_dir = if !target_override.trim().is_empty() {
        target_override.trim().to_string()
    } else {
        match entry.target.target_type {
            BackupTargetType::Lxc => {
                let base = crate::containers::lxc_base_dir(&entry.target.name);
                format!("{}/{}/rootfs", base, entry.target.name)
            }
            BackupTargetType::SystemPath => entry.target.system_path.trim_end_matches('/').to_string(),
            _ => ensure_staging_dir()?
                .join(format!("pbs-fl-restore-{}", Uuid::new_v4().simple()))
                .to_string_lossy().to_string(),
        }
    };
    // Guard the filesystem root + kernel filesystems as a restore destination.
    // (A native-LXC rootfs target like `<base>/<name>/rootfs` is fine.)
    reject_dangerous_root(&target_dir, false)?;
    fs::create_dir_all(&target_dir)
        .map_err(|e| format!("Cannot create restore target '{}': {}", target_dir, e))?;

    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("restore")
       .arg(&snapshot)
       .arg("root.pxar")
       .arg(&target_dir)
       .arg("--repository").arg(&repo);
    pbs_apply_common(&mut cmd, storage);
    let out = cmd.output()
        .map_err(|e| format!("PBS file-level restore failed: {}", e))?;
    if !out.status.success() {
        return Err(format!("PBS file-level restore error: {}",
            String::from_utf8_lossy(&out.stderr).trim()));
    }

    let note = match entry.target.target_type {
        BackupTargetType::Docker =>
            " — container filesystem extracted; rebuild the container from these \
             files or use PBS's per-file restore for individual files.",
        _ => "",
    };
    Ok(format!("PBS file-level snapshot '{}' restored into {}{}", snapshot, target_dir, note))
}

/// The two trailing positionals for `proxmox-backup-client snapshot notes
/// update`: `<snapshot> <notes>`, in that order, with NO `--` separator.
///
/// The PBS CLI is built on proxmox-router, which does not implement the
/// getopt/clap `--` end-of-options convention — it treats a literal `--` as the
/// first positional (snapshot), pushing the real snapshot into the notes slot
/// and the real notes into "got additional arguments", so every notes call
/// failed (wabil 2026-06-21). Both values are option-safe anyway: the snapshot
/// is always `type/id/RFC3339` and the notes always begin with "Cluster:", so
/// neither can be mistaken for an option. Centralised so both notes-setters
/// stay in lock-step and the regression is unit-guarded.
fn pbs_notes_positionals(snapshot: &str, notes: &str) -> [String; 2] {
    [snapshot.to_string(), notes.to_string()]
}

/// Find the latest snapshot matching backup-type/id and set its notes.
/// Extracted so both the tarball and file-level paths share it.
fn set_pbs_snapshot_notes(
    storage: &BackupStorage,
    repo: &str,
    backup_type: &str,
    backup_id: &str,
    notes_text: &str,
    log: Option<&std::sync::mpsc::Sender<String>>,
) {
    let mut list_cmd = Command::new("proxmox-backup-client");
    list_cmd.args(["snapshot", "list", "--output-format", "json", "--repository", repo]);
    pbs_apply_common(&mut list_cmd, storage);
    let snap_out = match list_cmd.output() { Ok(o) => o, Err(_) => return };
    let snaps: serde_json::Value = match serde_json::from_slice(&snap_out.stdout) {
        Ok(v) => v, Err(_) => return,
    };
    let arr = match snaps.as_array() { Some(a) => a, None => return };
    let mut best_time: i64 = 0;
    let mut best_snap = String::new();
    for s in arr {
        let st = s.get("backup-type").and_then(|v| v.as_str()).unwrap_or("");
        let si = s.get("backup-id").and_then(|v| v.as_str()).unwrap_or("");
        let stime = s.get("backup-time").and_then(|v| v.as_i64()).unwrap_or(0);
        if st != backup_type || si != backup_id || stime <= best_time { continue; }
        if let Some(ts) = chrono::DateTime::from_timestamp(stime, 0) {
            best_time = stime;
            best_snap = format!("{}/{}/{}", st, si,
                ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        }
    }
    if best_snap.is_empty() { return; }
    let mut notes_cmd = Command::new("proxmox-backup-client");
    notes_cmd.args(["snapshot", "notes", "update", "--repository", repo]);
    // pbs_apply_common adds --ns + the auth env (all options).
    pbs_apply_common(&mut notes_cmd, storage);
    // Positional <snapshot> <notes>, NO `--` separator (see
    // pbs_notes_positionals). Matches the inline notes-setter in
    // store_pbs_with_notes.
    notes_cmd.args(pbs_notes_positionals(&best_snap, notes_text));
    match notes_cmd.output() {
        Ok(out) if out.status.success() => {
            if let Some(log_tx) = log { let _ = log_tx.send("  PBS: snapshot notes set".to_string()); }
        }
        Ok(out) => warn!("Failed to set PBS snapshot notes for {}: {}",
            best_snap, String::from_utf8_lossy(&out.stderr).trim()),
        Err(e) => warn!("Failed to run snapshot notes update: {}", e),
    }
}

/// Extract the container/VM ID from a backup filename
fn extract_backup_id_from_filename(filename: &str) -> String {
    // "vzdump-lxc-131-2026..." → "131"
    if filename.starts_with("vzdump-lxc-") || filename.starts_with("vzdump-qemu-") {
        let rest = filename.splitn(3, '-').nth(2).unwrap_or("");
        return rest.split('-').next().unwrap_or("unknown").to_string();
    }
    // "lxc-myct-2026..." → "myct", "docker-myapp-2026..." → "myapp", "vm-myvm-2026..." → "myvm"
    if let Some(rest) = filename.split_once('-') {
        // rest.1 = "myct-20260316-123456.tar.gz" — take everything before the timestamp
        let parts: Vec<&str> = rest.1.split('-').collect();
        // Find where the timestamp starts (8 digits)
        for (i, part) in parts.iter().enumerate() {
            if part.len() == 8 && part.chars().all(|c| c.is_ascii_digit()) {
                return parts[..i].join("-");
            }
        }
        return parts[0].to_string();
    }
    filename.split('.').next().unwrap_or("unknown").to_string()
}

/// PBS `backup-type` for a stored archive filename.
///
/// Single source of truth: store, restore and retention-prune must all derive
/// the SAME type for a given filename or they address different groups. This
/// was previously inlined in two places that had already drifted — the store
/// path typed `docker-…` archives as "ct" while the restore path fell through
/// to "host", so Docker PBS backups uploaded fine and then could not be found
/// again.
fn pbs_backup_type_for_filename(filename: &str) -> &'static str {
    if filename.starts_with("vzdump-lxc-") || filename.starts_with("lxc-")
        || filename.starts_with("vzdump-docker-") || filename.starts_with("docker-") {
        "ct"
    } else if filename.starts_with("vm-") || filename.starts_with("vzdump-qemu-") {
        "vm"
    } else {
        "host"
    }
}

/// PBS group (`<backup-type>/<backup-id>`) that a stored archive belongs to.
fn pbs_group_for_filename(filename: &str) -> String {
    format!("{}/{}", pbs_backup_type_for_filename(filename),
            extract_backup_id_from_filename(filename))
}

/// Node component of the config-archive filename.
///
/// Every node used to emit the literal `config-wolfstack-<ts>.tar.gz`, which
/// `extract_backup_id_from_filename` maps to the backup-id "wolfstack" — so
/// EVERY node in a fleet wrote its own `/etc/wolfstack` into the single shared
/// PBS group `host/wolfstack`. Observed 2026-08-25 on a 4-node fleet: 67
/// snapshots in one group from four different machines, which makes a restore
/// ambiguous and makes any per-group retention destructive (pruning it from one
/// node deletes the other three nodes' config backups). The PBS *file-level*
/// path already got this right via `config_pxar_backup_id`; the archive path
/// did not. Scoping by hostname gives each node its own group.
fn config_archive_node_id(hostname: &str) -> String {
    let host = sanitize_archive_name(hostname);
    let host = if host.is_empty() { "unknown".to_string() } else { host };
    // `extract_backup_id_from_filename` treats the first 8-digit segment as the
    // start of the timestamp. A hostname that is itself exactly 8 digits would
    // be swallowed as that timestamp, collapsing every node back onto one
    // group — precisely the collision this id exists to prevent.
    if host.len() == 8 && host.chars().all(|c| c.is_ascii_digit()) {
        format!("{}n", host)
    } else {
        host
    }
}

/// Retrieve a backup file from storage for restore
fn retrieve_backup(entry: &BackupEntry) -> Result<PathBuf, String> {
    let staging = ensure_staging_dir()?;
    let local_path = staging.join(&entry.filename);

    match entry.storage.storage_type {
        StorageType::Local | StorageType::Wolfdisk => {
            let source = Path::new(&entry.storage.resolved_local_path()).join(&entry.filename);
            if !source.exists() {
                return Err(format!("Backup file not found: {}", source.display()));
            }
            fs::copy(&source, &local_path)
                .map_err(|e| format!("Failed to copy backup: {}", e))?;
        },
        StorageType::S3 => {
            retrieve_from_s3(entry, &local_path)?;
        },
        StorageType::Remote => {
            return Err("Cannot restore from remote node storage directly — download the backup file first".to_string());
        },
        StorageType::Pbs => {
            retrieve_from_pbs(entry, &local_path)?;
        },
        StorageType::Nfs => {
            let dir = ensure_nfs_mounted(&entry.storage)?;
            let source = Path::new(&dir).join(&entry.filename);
            if !source.exists() {
                return Err(format!("Backup file not found: {}", source.display()));
            }
            fs::copy(&source, &local_path)
                .map_err(|e| format!("Failed to copy backup: {}", e))?;
        },
        StorageType::Smb => {
            let dir = ensure_smb_mounted(&entry.storage)?;
            let source = Path::new(&dir).join(&entry.filename);
            if !source.exists() {
                return Err(format!("Backup file not found: {}", source.display()));
            }
            fs::copy(&source, &local_path)
                .map_err(|e| format!("Failed to copy backup: {}", e))?;
        },
    }

    Ok(local_path)
}

/// Download a backup from S3
fn retrieve_from_s3(entry: &BackupEntry, dest: &Path) -> Result<(), String> {
    let storage = &entry.storage;
    let key = format!("wolfstack-backups/{}", entry.filename);

    let bucket_name = storage.bucket.clone();
    let region_str = storage.region.clone();
    let endpoint_str = storage.endpoint.clone();
    let access_key = storage.access_key.clone();
    let secret_key = storage.secret_key.clone();
    let dest_path = dest.to_path_buf();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // A blank region falls back to us-east-1 so the AWS host never
            // becomes "https://s3..amazonaws.com" (mirrors the upload path).
            let aws_region = if region_str.trim().is_empty() {
                "us-east-1".to_string()
            } else {
                region_str.clone()
            };
            // A custom endpoint goes through the storage module's normaliser:
            // it supplies the scheme a bare hostname needs and strips a
            // trailing slash, which `Region::host()` would otherwise put in
            // the Host header and make every request a 400 (see
            // storage::endpoint_url). Real AWS keeps the derived host.
            let region = if endpoint_str.is_empty() {
                s3::Region::Custom {
                    region: aws_region.clone(),
                    endpoint: format!("https://s3.{}.amazonaws.com", aws_region),
                }
            } else {
                crate::storage::s3_custom_region(&endpoint_str, &aws_region)?
            };

            let credentials = s3::creds::Credentials::new(
                Some(&access_key),
                Some(&secret_key),
                None, None, None,
            ).map_err(|e| format!("S3 credentials error: {}", e))?;

            let bucket = s3::Bucket::new(&bucket_name, region, credentials)
                .map_err(|e| format!("S3 bucket error: {}", e))?;

            let response = bucket.get_object(&key).await
                .map_err(|e| format!("S3 download error: {}", e))?;

            fs::write(&dest_path, response.bytes())
                .map_err(|e| format!("Failed to write downloaded backup: {}", e))?;

            Ok::<(), String>(())
        })
    }).join().map_err(|_| "S3 download thread panicked".to_string())?
}

// ─── Restore Functions ───

/// Restore a Docker container from backup
/// Build docker run arguments from a docker inspect JSON
fn docker_run_args_from_inspect(inspect: &serde_json::Value) -> Vec<String> {
    let mut args = Vec::new();
    let container = if inspect.is_array() { &inspect[0] } else { inspect };
    let config = &container["Config"];
    let host_config = &container["HostConfig"];

    // Port bindings: HostConfig.PortBindings
    if let Some(bindings) = host_config["PortBindings"].as_object() {
        for (container_port, host_ports) in bindings {
            if let Some(arr) = host_ports.as_array() {
                for hp in arr {
                    let host_ip = hp["HostIp"].as_str().unwrap_or("");
                    let host_port = hp["HostPort"].as_str().unwrap_or("");
                    if !host_port.is_empty() {
                        let binding = if !host_ip.is_empty() && host_ip != "0.0.0.0" {
                            format!("{}:{}:{}", host_ip, host_port, container_port)
                        } else {
                            format!("{}:{}", host_port, container_port)
                        };
                        args.push("-p".to_string());
                        args.push(binding);
                    }
                }
            }
        }
    }

    // Environment variables: Config.Env
    if let Some(env) = config["Env"].as_array() {
        for e in env {
            if let Some(s) = e.as_str() {
                // Skip common default vars that come from the image
                if s.starts_with("PATH=") || s.starts_with("HOME=") || s.starts_with("HOSTNAME=") {
                    continue;
                }
                args.push("-e".to_string());
                args.push(s.to_string());
            }
        }
    }

    // Volume mounts: HostConfig.Binds
    if let Some(binds) = host_config["Binds"].as_array() {
        for b in binds {
            if let Some(s) = b.as_str() {
                args.push("-v".to_string());
                args.push(s.to_string());
            }
        }
    }

    // Restart policy: HostConfig.RestartPolicy
    let restart_name = host_config["RestartPolicy"]["Name"].as_str().unwrap_or("");
    if !restart_name.is_empty() && restart_name != "no" {
        let max_retry = host_config["RestartPolicy"]["MaximumRetryCount"].as_u64().unwrap_or(0);
        if restart_name == "on-failure" && max_retry > 0 {
            args.push("--restart".to_string());
            args.push(format!("on-failure:{}", max_retry));
        } else {
            args.push("--restart".to_string());
            args.push(restart_name.to_string());
        }
    } else {
        args.push("--restart".to_string());
        args.push("unless-stopped".to_string());
    }

    // Network mode: HostConfig.NetworkMode
    let network = host_config["NetworkMode"].as_str().unwrap_or("default");
    if network != "default" && network != "bridge" && !network.is_empty() {
        args.push("--network".to_string());
        args.push(network.to_string());
    }

    // Hostname
    if let Some(hostname) = config["Hostname"].as_str()
        && !hostname.is_empty() {
            args.push("--hostname".to_string());
            args.push(hostname.to_string());
        }

    // Working dir
    if let Some(workdir) = config["WorkingDir"].as_str()
        && !workdir.is_empty() {
            args.push("-w".to_string());
            args.push(workdir.to_string());
        }

    // Entrypoint override (only if different from image default)
    if let Some(ep) = config["Entrypoint"].as_array()
        && !ep.is_empty() {
            args.push("--entrypoint".to_string());
            args.push(ep[0].as_str().unwrap_or("").to_string());
        }

    // TTY and stdin (needed for interactive containers like debian, ubuntu)
    if config["Tty"].as_bool().unwrap_or(false) {
        args.push("-t".to_string());
    }
    if config["OpenStdin"].as_bool().unwrap_or(false) {
        args.push("-i".to_string());
    }

    // Privileged
    if host_config["Privileged"].as_bool().unwrap_or(false) {
        args.push("--privileged".to_string());
    }

    // Memory limit
    if let Some(mem) = host_config["Memory"].as_u64()
        && mem > 0 {
            args.push("-m".to_string());
            args.push(format!("{}b", mem));
        }

    // CPU quota
    if let Some(cpus) = host_config["NanoCpus"].as_u64()
        && cpus > 0 {
            args.push("--cpus".to_string());
            args.push(format!("{:.2}", cpus as f64 / 1_000_000_000.0));
        }

    args
}

pub fn restore_docker(entry: &BackupEntry, overwrite: bool) -> Result<String, String> {
    let container_name = &entry.target.name;

    // Check if a container with this name already exists before downloading.
    let check = Command::new("docker")
        .args(["container", "inspect", container_name])
        .output();
    let exists = check.map(|o| o.status.success()).unwrap_or(false);

    if exists && !overwrite {
        return Err(format!("CONTAINER_EXISTS:{}", container_name));
    }

    // Saved docker inspect from the backup entry — used for restoring the
    // original `docker run` flags. New-format backups also embed an
    // inspect.json inside the wrapper tarball; either source works.
    let mut inspect_json: Option<serde_json::Value> = if !entry.docker_config.is_empty() {
        serde_json::from_str(&entry.docker_config).ok()
    } else {
        None
    };

    let local_path = retrieve_backup(entry)?;

    // Detect format. New v20.11.0+ backups are a wrapper tarball that
    // contains `inspect.json` + `image.tar.gz` + per-mount tarballs.
    // Pre-v20.11.0 backups are a flat `docker save | gzip`. Detect by
    // extracting the outer archive to a temp dir and checking what's
    // there. If `inspect.json` is present, new format; else fall back
    // to the legacy `docker load` path so old backups still restore.
    let work_dir = ensure_staging_dir()?.join(format!("docker-restore-{}", Uuid::new_v4()));
    fs::create_dir_all(&work_dir).map_err(|e| format!("Failed to create restore work dir: {}", e))?;

    let xt = Command::new("tar")
        .arg("xzf").arg(&local_path)
        .arg("-C").arg(&work_dir)
        .output();
    let extracted_ok = xt.as_ref().map(|o| o.status.success()).unwrap_or(false);

    let new_format = extracted_ok && work_dir.join("inspect.json").exists();
    let mut restored_mounts: Vec<String> = Vec::new();
    let mut skipped_mounts: Vec<String> = Vec::new();

    let image_load_path: PathBuf = if new_format {
        // Read the wrapper's inspect.json (overrides entry.docker_config
        // if entry didn't have it for some reason).
        if inspect_json.is_none()
            && let Ok(text) = fs::read_to_string(work_dir.join("inspect.json")) {
                inspect_json = serde_json::from_str(&text).ok();
            }

        // Restore each mount BEFORE creating the container — so when
        // docker run mounts them, the data's already in place.
        let mounts_text = fs::read_to_string(work_dir.join("mounts.json")).unwrap_or_default();
        let mounts: Vec<MountInfo> = serde_json::from_str(&mounts_text).unwrap_or_default();
        for m in &mounts {
            if m.archive_path.is_empty() {
                if !m.skipped_reason.is_empty() {
                    skipped_mounts.push(format!("{} {} ({})", m.mount_type, m.destination, m.skipped_reason));
                }
                continue;
            }
            let archive_abs = work_dir.join(&m.archive_path);
            if !archive_abs.exists() {
                skipped_mounts.push(format!("{} {} (archive missing inside backup)", m.mount_type, m.destination));
                continue;
            }
            match m.mount_type.as_str() {
                "volume" => {
                    if m.source.is_empty() {
                        skipped_mounts.push(format!("volume {} (no name)", m.destination));
                        continue;
                    }
                    // Idempotent — if the volume already exists docker
                    // returns its name and we just write into it.
                    let _ = Command::new("docker").args(["volume", "create", &m.source]).output();
                    let data_dir = format!("/var/lib/docker/volumes/{}/_data", m.source);
                    if !Path::new(&data_dir).is_dir() {
                        skipped_mounts.push(format!("volume {} (data dir not created: {})", m.source, data_dir));
                        continue;
                    }
                    let xv = Command::new("tar")
                        .arg("xzf").arg(&archive_abs)
                        .arg("-C").arg(&data_dir)
                        .output();
                    match xv {
                        Ok(o) if o.status.success() => {
                            restored_mounts.push(format!("volume {}", m.source));
                        }
                        Ok(o) => {
                            skipped_mounts.push(format!("volume {} (extract failed: {})", m.source, String::from_utf8_lossy(&o.stderr).trim()));
                        }
                        Err(e) => skipped_mounts.push(format!("volume {} (tar spawn: {})", m.source, e)),
                    }
                }
                "bind" => {
                    // Ensure parent dir exists; tar can extract into it.
                    let target = Path::new(&m.source);
                    if let Some(parent) = target.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    // tar archive_path was created with `tar -C {parent}
                    // {basename}`, so it contains an entry at the root
                    // named after the basename. Extract into the parent
                    // dir so it lands at the original Source path.
                    let parent = target.parent().map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| "/".into());
                    let xb = Command::new("tar")
                        .arg("xzf").arg(&archive_abs)
                        .arg("-C").arg(&parent)
                        .output();
                    match xb {
                        Ok(o) if o.status.success() => {
                            restored_mounts.push(format!("bind {}", m.source));
                        }
                        Ok(o) => {
                            skipped_mounts.push(format!("bind {} (extract failed: {})", m.source, String::from_utf8_lossy(&o.stderr).trim()));
                        }
                        Err(e) => skipped_mounts.push(format!("bind {} (tar spawn: {})", m.source, e)),
                    }
                }
                _ => {
                    // tmpfs etc. — not archived, nothing to restore.
                }
            }
        }

        work_dir.join("image.tar.gz")
    } else {
        // Legacy backup — the file at `local_path` IS the `docker save |
        // gzip` output. docker load reads it directly.
        local_path.clone()
    };

    // Load the image from the (legacy or new-format) tarball.
    let output = Command::new("sh")
        .args(["-c", &format!("gunzip -c '{}' | docker load", image_load_path.display())])
        .output()
        .map_err(|e| {
            let _ = fs::remove_dir_all(&work_dir);
            let _ = fs::remove_file(&local_path);
            format!("Failed to load Docker image: {}", e)
        })?;

    // Tarball + work dir done. Clean up.
    let _ = fs::remove_dir_all(&work_dir);
    let _ = fs::remove_file(&local_path);

    if !output.status.success() {
        return Err(format!("Docker load failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    let load_result = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Extract the loaded image name from "Loaded image: <name>".
    let image_name = load_result
        .lines()
        .find_map(|line| line.strip_prefix("Loaded image: "))
        .unwrap_or(&format!("wolfstack-backup/{}", entry.target.name))
        .to_string();

    // If overwriting, stop and remove the existing container.
    if exists {
        let _ = Command::new("docker").args(["stop", container_name]).output();
        let _ = Command::new("docker").args(["rm", "-f", container_name]).output();
    }

    // Build docker run args from inspect config, or use defaults.
    let extra_args = inspect_json.as_ref()
        .map(docker_run_args_from_inspect)
        .unwrap_or_else(|| vec!["--restart".to_string(), "unless-stopped".to_string()]);

    let mut run_args = vec!["run".to_string(), "-d".to_string(), "--name".to_string(), container_name.to_string()];
    run_args.extend(extra_args);
    run_args.push(image_name.clone());

    let create = Command::new("docker")
        .args(&run_args)
        .output()
        .map_err(|e| format!("Image loaded but failed to create container: {}", e))?;

    if !create.status.success() {
        let err = String::from_utf8_lossy(&create.stderr);
        return Ok(format!("Docker image restored ({}). Could not auto-create container: {}",
            image_name, err.trim()));
    }

    let config_note = if inspect_json.is_some() { " (with original config)" } else { " (default config)" };
    let mut msg = format!("Docker container '{}' restored and started{}", container_name, config_note);
    if !restored_mounts.is_empty() {
        msg.push_str(&format!(" — restored data: {}", restored_mounts.join(", ")));
    }
    if !skipped_mounts.is_empty() {
        msg.push_str(&format!(" (skipped: {})", skipped_mounts.join(", ")));
    }
    Ok(msg)
}

/// Restore an LXC container from backup
pub fn restore_lxc(entry: &BackupEntry, storage: &str, overwrite: bool, new_name: &str) -> Result<String, String> {
    // Fast-fail an obviously bad restore-as name before the (possibly
    // large, remote) archive download. restore_lxc_local re-validates,
    // so callers that bypass this wrapper (PBS restore) are still covered.
    let trimmed = new_name.trim();
    if !trimmed.is_empty() && !crate::auth::is_safe_name(trimmed) {
        return Err(format!(
            "'{}' is not a valid container name — use letters, digits, '-', '_' and '.' only, with no '..'.",
            trimmed));
    }
    if !trimmed.is_empty()
        && entry.filename.contains("vzdump")
        && crate::containers::is_proxmox()
        && trimmed.parse::<u32>().map(|n| n < 100).unwrap_or(true)
    {
        return Err(format!(
            "'{}' is not a valid Proxmox container ID — it must be a whole number, 100 or higher.",
            trimmed));
    }

    let local_path = retrieve_backup(entry)?;
    restore_lxc_local(&local_path, &entry.target.name, storage, overwrite, new_name)
}

/// Restore an LXC container from an archive that is ALREADY on local disk.
/// Shared core: `restore_lxc` calls it after downloading from backup
/// storage; the PBS snapshot restore calls it after un-wrapping the
/// snapshot's `backup.pxar`. `local_path` is consumed (removed on both
/// success and failure). `new_name` empty = keep `original_name`.
pub fn restore_lxc_local(
    local_path: &Path,
    original_name: &str,
    storage: &str,
    overwrite: bool,
    new_name: &str,
) -> Result<String, String> {
    let new_name = new_name.trim();
    if !new_name.is_empty() && !crate::auth::is_safe_name(new_name) {
        let _ = fs::remove_file(local_path);
        return Err(format!(
            "'{}' is not a valid container name — use letters, digits, '-', '_' and '.' only, with no '..'.",
            new_name));
    }
    let container_name: &str = if new_name.is_empty() { original_name } else { new_name };
    // Validate the EFFECTIVE name. When new_name is empty it falls back to
    // `original_name`, which on the PBS path is the snapshot id ("ct/<id>/..")
    // and has NOT been through is_safe_name — a crafted id like "../../etc"
    // would otherwise escape /var/lib/lxc on the native restore paths.
    if !crate::auth::is_safe_name(container_name) {
        let _ = fs::remove_file(local_path);
        return Err(format!(
            "'{}' is not a valid container name/id — use letters, digits, '-', '_' and '.' only, with no '..'.",
            container_name));
    }

    // Detect whether this is a Proxmox vzdump archive vs a native WolfStack
    // rootfs tar, and which platform we're restoring ONTO. All four
    // combinations are routed independently so a backup taken on one platform
    // restores correctly on the other — PBS snapshots and exported archives
    // move freely between Proxmox and native WolfStack nodes.
    let is_vzdump = crate::containers::lxc_archive_is_vzdump(&local_path.to_string_lossy());
    let proxmox_host = crate::containers::is_proxmox();

    if is_vzdump {
        if proxmox_host {
            // vzdump → Proxmox: `pct restore` handles it natively.
            return restore_lxc_proxmox(local_path, storage, overwrite, container_name);
        }
        // vzdump → native host: `pct restore` is unavailable, so unwrap the
        // rootfs and stand it up as a native LXC with a synthesised config.
        return restore_lxc_vzdump_native(local_path, container_name, overwrite);
    }
    // Below: a native WolfStack archive (`<name>/config` + `<name>/rootfs/`).
    // On a native host it installs directly; on a Proxmox host it is adopted
    // into PVE at the end of this function.

    // Native LXC restore. `backup_lxc` archives the container directory with
    // its ORIGINAL name at the archive's top level (`<orig>/config`,
    // `<orig>/rootfs/...`). Extract into a temp dir UNDER /var/lib/lxc — same
    // filesystem, so the final install is an atomic rename — then verify the
    // contents before declaring success.
    let extract_root = PathBuf::from(format!("/var/lib/lxc/.wolfstack-restore-{}", Uuid::new_v4().simple()));
    let _ = fs::remove_dir_all(&extract_root);
    fs::create_dir_all(&extract_root)
        .map_err(|e| format!("Failed to create restore staging dir: {}", e))?;

    let output = Command::new("tar")
        .args(["xzf", &local_path.to_string_lossy(), "-C", &extract_root.to_string_lossy()])
        .output()
        .map_err(|e| format!("Failed to extract LXC backup: {}", e))?;
    let _ = fs::remove_file(local_path);
    if !output.status.success() {
        let _ = fs::remove_dir_all(&extract_root);
        return Err(format!("LXC extract failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // The archive should yield exactly one top-level container directory.
    let extracted = fs::read_dir(&extract_root).ok()
        .and_then(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).find(|p| p.is_dir()));
    let extracted = match extracted {
        Some(d) => d,
        None => {
            let _ = fs::remove_dir_all(&extract_root);
            return Err("Backup archive did not contain an LXC container directory".to_string());
        }
    };

    // Verify the backup actually carries a root filesystem AND a config.
    // Without this the container starts and instantly dies with
    // "Failed to exec /sbin/init" — better to fail the restore loudly here.
    let src_rootfs = extracted.join("rootfs");
    let rootfs_ok = ["sbin", "etc", "bin", "usr"].iter().any(|d| src_rootfs.join(d).exists());
    if !rootfs_ok {
        let _ = fs::remove_dir_all(&extract_root);
        return Err(format!(
            "Backup is incomplete — no root filesystem inside it (rootfs/ has no sbin, etc or bin). \
             Nothing was restored for '{}'.", container_name));
    }
    if !extracted.join("config").exists() {
        let _ = fs::remove_dir_all(&extract_root);
        return Err(format!(
            "Backup is incomplete — no LXC config inside it. Nothing was restored for '{}'.", container_name));
    }

    // Install under the requested name. An existing container is only
    // replaced when the operator ticked "replace" — otherwise refuse,
    // because silently merging two rootfs trees is worse than failing.
    let container_dir = format!("/var/lib/lxc/{}", container_name);
    if Path::new(&container_dir).exists() {
        if !overwrite {
            let _ = fs::remove_dir_all(&extract_root);
            return Err(format!(
                "A container already exists at {} — re-run the restore with \"replace\" enabled to overwrite it.",
                container_dir));
        }
        // Operator consented to replace it: stop it if still running, then
        // drop the old directory so the rename below lands cleanly.
        let _ = Command::new("lxc-stop").args(["-n", container_name, "-k"]).output();
        if let Err(e) = fs::remove_dir_all(&container_dir) {
            let _ = fs::remove_dir_all(&extract_root);
            return Err(format!("Failed to remove the existing container at {}: {}", container_dir, e));
        }
    }
    if let Err(e) = fs::rename(&extracted, &container_dir) {
        let _ = fs::remove_dir_all(&extract_root);
        return Err(format!("Failed to install restored container at {}: {}", container_dir, e));
    }
    let _ = fs::remove_dir_all(&extract_root);

    let config_path = format!("{}/config", container_dir);
    let rootfs_path = format!("{}/rootfs", container_dir);

    // Rewrite the config for THIS node: correct rootfs path, the restored
    // name, and a permissive apparmor profile (the backed-up profile name
    // may not exist on the new host).
    let config = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Restored container config could not be read: {}", e))?;
    let mut lines: Vec<String> = config.lines()
        .filter(|l| {
            let t = l.trim();
            !t.starts_with("lxc.rootfs.path") && !t.starts_with("lxc.uts.name")
        })
        .map(|l| l.to_string())
        .collect();
    lines.insert(0, format!("lxc.rootfs.path = dir:{}", rootfs_path));
    lines.insert(1, format!("lxc.uts.name = {}", container_name));
    if !lines.iter().any(|l| l.contains("lxc.apparmor.profile")) {
        lines.push("lxc.apparmor.profile = unconfined".to_string());
    }
    std::fs::write(&config_path, lines.join("\n") + "\n")
        .map_err(|e| format!("Failed to write restored config: {}", e))?;

    // Own the container directory and its config file as root — but DO NOT
    // recurse. The rootfs files keep the ownership `tar` restored from the
    // archive; a `chown -R root:root` here would flatten every non-root file
    // inside the rootfs and break the container (fatally so for an
    // unprivileged container, whose files are owned by shifted UIDs).
    let _ = Command::new("chown").args(["root:root", &container_dir]).output();
    let _ = Command::new("chown").args(["root:root", &config_path]).output();
    let _ = Command::new("chmod").args(["755", &container_dir]).output();

    // Restore copies the source's lxc.net.N.hwaddr verbatim — there is
    // no clone-style MAC rewrite. The operator may have intentionally
    // pinned a specific MAC for upstream router/firewall whitelisting
    // (Hetzner vSwitch, MAC-based DHCP reservations, license dongles
    // keyed off MAC), so silently re-randomising would break those
    // setups. Instead, surface a loud warning — and if another local
    // container is already using one of these MACs, name it. The
    // operator can then edit the NIC in Settings → Resources to mint
    // a fresh MAC if they need one.
    //
    // Cross-node duplicates (e.g. restoring the same backup on two
    // nodes for HA) are not detectable here without trusting the
    // cluster cache; the generic warning covers that case.
    let mac_warning = build_mac_duplication_warning(&config_path, container_name);

    // A native WolfStack backup restored onto a Proxmox host lands as a
    // native /var/lib/lxc container PVE can't see. Adopt it into PVE now so
    // it's a first-class container immediately (fresh VMID), instead of
    // waiting for the next startup reconciliation. Adoption re-tars the rootfs
    // into a new PVE container with fresh networking, so the carried-MAC note
    // no longer applies on success.
    if proxmox_host {
        return match crate::containers::pct_adopt_native_orphan(container_name) {
            Ok(vmid) => Ok(format!(
                "LXC container '{}' restored and adopted into Proxmox as VMID {} — start it from the Containers page.",
                container_name, vmid
            )),
            Err(e) => {
                // Surface it in the log too — if the cause is permanent
                // (e.g. no free VMID) a restart won't fix it and the operator
                // needs to see why.
                tracing::warn!(target: "backup",
                    "PVE adoption of restored container '{}' failed: {} — left as a native /var/lib/lxc container",
                    container_name, e);
                Ok(format!(
                    "LXC container '{}' restored as a native container, but Proxmox adoption failed ({}). \
                     It will be adopted automatically on the next WolfStack restart.{}",
                    container_name, e, mac_warning
                ))
            }
        };
    }

    Ok(format!(
        "LXC container '{}' restored and verified — start it from the Containers page.{}",
        container_name, mac_warning
    ))
}

/// Restore a Proxmox vzdump LXC archive onto a NATIVE (non-Proxmox) host.
///
/// `pct restore` isn't available here, so unwrap the vzdump's root filesystem
/// and stand it up as a native LXC container under /var/lib/lxc. The carried
/// `etc/vzdump/pct.conf` is Proxmox-specific and can't be used verbatim, so a
/// fresh bootable config is synthesised from the rootfs (systemd / privilege
/// auto-detected). `local_path` (the extracted archive) is consumed.
fn restore_lxc_vzdump_native(archive: &Path, container_name: &str, overwrite: bool) -> Result<String, String> {
    let container_dir = format!("/var/lib/lxc/{}", container_name);

    // Replace an existing container only with explicit consent.
    if Path::new(&container_dir).exists() {
        if !overwrite {
            let _ = fs::remove_file(archive);
            return Err(format!(
                "A container already exists at {} — re-run the restore with \"replace\" enabled to overwrite it.",
                container_dir));
        }
        let _ = Command::new("lxc-stop").args(["-n", container_name, "-k"]).output();
        if let Err(e) = fs::remove_dir_all(&container_dir) {
            let _ = fs::remove_file(archive);
            return Err(format!("Failed to remove the existing container at {}: {}", container_dir, e));
        }
    }

    let rootfs_target = format!("{}/rootfs", container_dir);
    if let Err(e) = fs::create_dir_all(&rootfs_target) {
        let _ = fs::remove_file(archive);
        return Err(format!("Failed to create container directory {}: {}", container_dir, e));
    }

    // Shared extractor: handles zstd, flattens a nested rootfs/, strips
    // etc/vzdump (salvaging pct.conf for the limits translation below).
    // Leaves the container's root filesystem in `rootfs_target`.
    let archive_str = archive.to_string_lossy().to_string();
    let pct_conf = match crate::containers::lxc_extract_archive_to_rootfs(&archive_str, &rootfs_target) {
        Ok(c) => c,
        Err(e) => {
            let _ = fs::remove_dir_all(&container_dir);
            let _ = fs::remove_file(archive);
            return Err(format!("Failed to unpack vzdump archive for '{}': {}", container_name, e));
        }
    };
    // Verify a real root filesystem actually landed — otherwise the container
    // would start and instantly die with "Failed to exec /sbin/init". Keep the
    // (ephemeral) archive until this passes so a failed restore is recoverable.
    let rootfs_ok = ["sbin", "etc", "bin", "usr"]
        .iter()
        .any(|d| Path::new(&format!("{}/{}", rootfs_target, d)).exists());
    if !rootfs_ok {
        let _ = fs::remove_dir_all(&container_dir);
        let _ = fs::remove_file(archive);
        return Err(format!(
            "The vzdump archive contained no usable root filesystem (no sbin, etc or bin). \
             Nothing was restored for '{}'.", container_name));
    }
    let _ = fs::remove_file(archive);

    // Synthesise a bootable native config from the rootfs. The carried
    // pct.conf is Proxmox-format and unusable verbatim, but its resource
    // limits, autostart flag and (where this host has the same bridge)
    // network settings translate — pass it through so the restored
    // container keeps its envelope.
    let net_warning = crate::containers::lxc_write_bootable_config(
        &container_dir, container_name, None, pct_conf.as_deref(), None);

    // Own the container dir + config as root — NOT recursive, so the rootfs
    // keeps the UIDs tar restored (recursing would break an unprivileged
    // container whose files are owned by shifted UIDs).
    let config_path = format!("{}/config", container_dir);
    let _ = Command::new("chown").args(["root:root", &container_dir]).output();
    let _ = Command::new("chown").args(["root:root", &config_path]).output();
    let _ = Command::new("chmod").args(["755", &container_dir]).output();

    let mut message = format!(
        "Proxmox container restored as native LXC '{}' — start it from the Containers page.",
        container_name
    );
    // The network either carried (same bridge exists here) or fell back to
    // lxcbr0 — in the fallback case say so explicitly rather than the old
    // blanket "reset to lxcbr0" text.
    if let Some(w) = net_warning {
        message.push_str(" WARNING: ");
        message.push_str(&w);
    }
    Ok(message)
}

/// Build a human-readable warning about MAC-address duplication risk
/// for a freshly restored container. Always warns generically (since
/// we can't reliably scan cluster-wide MACs from this call site); also
/// names local conflicts when the restored container shares a MAC with
/// another container already on this node.
fn build_mac_duplication_warning(restored_config_path: &str, restored_name: &str) -> String {
    // Pull the restored container's MACs from its newly-installed config.
    let restored_macs = read_hwaddrs(restored_config_path);
    if restored_macs.is_empty() {
        // No MACs to worry about (very unusual — most LXC configs pin
        // hwaddr) — just the generic warning.
        return "\n\nNOTE: restore copies the source's network settings verbatim. \
                Check that this container's MAC addresses, hostname, and any pinned \
                IPs don't clash with other containers — especially important on \
                vSwitches and shared L2 networks, where duplicate MACs cause silent \
                connectivity failures."
            .to_string();
    }

    // Walk every other LXC container's config for matching MACs.
    let mut local_conflicts: Vec<(String, String)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/var/lib/lxc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip the container we just restored, hidden dirs, and the
            // restore staging directory pattern.
            if name == restored_name || name.starts_with('.') {
                continue;
            }
            let other_config = format!("/var/lib/lxc/{}/config", name);
            if !std::path::Path::new(&other_config).exists() {
                continue;
            }
            for mac in read_hwaddrs(&other_config) {
                if restored_macs.iter().any(|m| m.eq_ignore_ascii_case(&mac)) {
                    local_conflicts.push((name.clone(), mac));
                }
            }
        }
    }

    let mut warning = String::from(
        "\n\nNOTE: restore copies the source's network settings verbatim, including \
         MAC addresses. Check for duplicates — especially on vSwitches and shared \
         L2 networks, where two containers with the same MAC cause silent \
         connectivity failures (flapping switch FDB, traffic to the wrong host).",
    );
    if !local_conflicts.is_empty() {
        warning.push_str("\n\nDUPLICATE MAC DETECTED on this node:");
        for (other, mac) in &local_conflicts {
            warning.push_str(&format!(
                "\n  - '{}' also uses MAC {} — edit one of them in Settings → Resources.",
                other, mac
            ));
        }
    } else {
        warning.push_str(
            "\n\nNo duplicates on this node; verify across the cluster too if you \
             restored this from a backup of a container that's still running elsewhere.",
        );
    }
    warning
}

/// Extract every `lxc.net.N.hwaddr` value from an LXC config file.
/// Tolerates `key = value` and `key=value`. Returns lowercase MACs.
fn read_hwaddrs(config_path: &str) -> Vec<String> {
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut macs = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        // Match lxc.net.<N>.hwaddr — N is any digit run.
        let stripped = trimmed.strip_prefix("lxc.net.").unwrap_or("");
        if stripped.is_empty() {
            continue;
        }
        // Skip past the digits to find ".hwaddr".
        let rest = stripped.trim_start_matches(|c: char| c.is_ascii_digit());
        let rest = match rest.strip_prefix(".hwaddr") {
            Some(r) => r.trim_start(),
            None => continue,
        };
        let rest = match rest.strip_prefix('=') {
            Some(r) => r.trim(),
            None => continue,
        };
        if !rest.is_empty() {
            macs.push(rest.to_ascii_lowercase());
        }
    }
    macs
}

/// Restore a Proxmox LXC container from a vzdump archive using pct restore
fn restore_lxc_proxmox(archive_path: &Path, storage: &str, overwrite: bool, vmid: &str) -> Result<String, String> {
    // Proxmox VMIDs are whole numbers, 100 or higher. A restore-as name
    // typed in the dialog reaches here — reject anything that isn't a
    // usable VMID rather than letting `pct` fail cryptically.
    if vmid.parse::<u32>().map(|n| n < 100).unwrap_or(true) {
        let _ = fs::remove_file(archive_path);
        return Err(format!(
            "'{}' is not a valid Proxmox container ID — it must be a whole number, 100 or higher.", vmid));
    }

    // Check if the VMID already exists — pct restore will fail if it does
    let exists = Command::new("pct").args(["status", vmid]).output()
        .map(|o| o.status.success()).unwrap_or(false);

    if exists {
        // `pct destroy` purges the container's disks — never do that
        // without the operator explicitly asking to replace it.
        if !overwrite {
            let _ = fs::remove_file(archive_path);
            return Err(format!(
                "Container {} already exists — re-run the restore with \"replace\" enabled to overwrite it.", vmid));
        }
        // Container exists — stop it first if running, then destroy and recreate
        let _ = Command::new("pct").args(["stop", vmid]).output();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let destroy = match Command::new("pct").args(["destroy", vmid, "--force", "1"]).output() {
            Ok(d) => d,
            Err(e) => {
                let _ = fs::remove_file(archive_path);
                return Err(format!("Failed to destroy existing container {}: {}", vmid, e));
            }
        };
        if !destroy.status.success() {
            let _ = fs::remove_file(archive_path);
            return Err(format!("Failed to destroy existing container {}: {}",
                vmid, String::from_utf8_lossy(&destroy.stderr)));
        }
    }

    // Restore using pct restore — handles all storage backends. When the
    // operator picked a target storage, pass it through; pct args go
    // straight to execve (no shell), but reject anything that is not a
    // plausible PVE storage id as defence in depth.
    let mut args: Vec<String> = vec![
        "restore".to_string(), vmid.to_string(),
        archive_path.to_string_lossy().to_string(),
    ];
    let storage = storage.trim();
    if !storage.is_empty() {
        if !storage.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
            let _ = fs::remove_file(archive_path);
            return Err(format!("Invalid Proxmox storage id: '{}'", storage));
        }
        args.push("--storage".to_string());
        args.push(storage.to_string());
    }
    let output = match Command::new("pct").args(&args).output() {
        Ok(o) => o,
        Err(e) => {
            let _ = fs::remove_file(archive_path);
            return Err(format!("pct restore failed to start: {}", e));
        }
    };

    let _ = fs::remove_file(archive_path);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("pct restore failed: {}", stderr.trim()));
    }

    Ok(format!("Proxmox LXC container {} restored from vzdump backup — you can now start it from the Containers page", vmid))
}

/// Restore a VM from backup
pub fn restore_vm(entry: &BackupEntry) -> Result<String, String> {
    let local_path = retrieve_backup(entry)?;
    // Backups-list VM restore keeps Proxmox's default storage (local-lvm);
    // the PBS path threads an operator-picked storage instead.
    restore_vm_local(&local_path, &entry.target.name, None)
}

/// Restore a VM from an archive already on local disk. Shared by
/// `restore_vm` (after download from backup storage) and the PBS
/// snapshot restore (after it un-wraps the snapshot's `backup.pxar`).
/// `local_path` is consumed.
///
/// Platform-dispatched:
///   • Proxmox host → `restore_vm_to_proxmox` (qm create + qm importdisk)
///   • libvirt host → `restore_vm_to_libvirt` (move disks into
///     /var/lib/libvirt/images, generate minimal domain XML, `virsh define`)
///   • native host → existing in-place extraction to /var/lib/wolfstack/vms
///
/// The archive format produced by `backup_vm` (Stage B) is the same
/// across platforms — flat tar.gz with `<name>.json` (portable VmConfig)
/// + `<name>.qcow2` (OS disk) + optional `<name>-<slot>.qcow2` extra
///   disks. Restore reads the JSON, then routes to the per-platform
///   creation primitives.
pub fn restore_vm_local(local_path: &Path, vm_name: &str, target_storage: Option<&str>) -> Result<String, String> {
    if crate::containers::is_proxmox() {
        return restore_vm_to_proxmox(local_path, vm_name, target_storage);
    }
    if crate::containers::is_libvirt() {
        return restore_vm_to_libvirt(local_path, vm_name);
    }
    restore_vm_to_native(local_path, vm_name)
}

/// Extract a tar.gz to `dest` after verifying NO entry contains a path
/// traversal vector. The portable backup archive comes from operator-
/// controlled storage (S3 / NFS / SSHFS / PBS); a crafted archive with
/// entries like `../../../etc/cron.d/evil` could climb out of the
/// `dest` work-dir on extraction.
///
/// Two-step strategy:
///   1. `tar tzf <archive>` lists entries; we reject any that start
///      with `/`, contain a `..` path component, or carry a NUL.
///   2. Only after validation do we extract.
///
/// This costs an extra tar invocation but is small overhead for our
/// portable VM archives (which contain only a JSON config and a
/// handful of qcow2 files), and it's the correct defence on top of
/// whatever GNU tar's default behaviour happens to be on the host.
fn safe_extract_tar(archive: &Path, dest: &Path) -> Result<(), String> {
    let list = Command::new("tar")
        .args(["tzf", &archive.to_string_lossy()])
        .output()
        .map_err(|e| format!("tar list failed to start: {}", e))?;
    if !list.status.success() {
        return Err(format!(
            "tar listing failed: {}",
            String::from_utf8_lossy(&list.stderr).trim()
        ));
    }
    let listing = String::from_utf8_lossy(&list.stdout);
    for raw in listing.lines() {
        let entry = raw.trim_end_matches('/').trim();
        if entry.is_empty() { continue; }
        if entry.starts_with('/') {
            return Err(format!(
                "archive contains absolute path entry '{}' — refusing to extract", entry));
        }
        if entry.split('/').any(|c| c == "..") {
            return Err(format!(
                "archive entry '{}' contains '..' — refusing to extract", entry));
        }
        if entry.contains('\0') {
            return Err("archive entry contains NUL byte — refusing to extract".into());
        }
    }
    // All entries safe — extract.
    let extract = Command::new("tar")
        .args(["xzf", &archive.to_string_lossy(),
               "-C", &dest.to_string_lossy()])
        .output()
        .map_err(|e| format!("tar extract failed to start: {}", e))?;
    if !extract.status.success() {
        return Err(format!(
            "tar extract failed: {}",
            String::from_utf8_lossy(&extract.stderr).trim()));
    }
    Ok(())
}

/// XML-escape the five characters that change meaning inside attribute
/// values or element text. Used everywhere libvirt XML is constructed
/// from values that originated in the portable backup archive (which
/// is operator-supplied content and therefore untrusted at restore
/// time). A crafted backup containing `bus="virtio'/></disk><foo"` or
/// a `vm_name` with `<`/`>` would otherwise break out of the
/// surrounding markup and inject arbitrary XML — `virsh define` would
/// reject the result, but the failure mode (restore aborts mid-flow)
/// is worse than catching it here.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Validate a disk bus name against the allowlist libvirt accepts.
/// Rejects anything else with a clear error rather than letting it
/// flow into the XML (defence-in-depth alongside `xml_escape`).
fn validate_libvirt_bus(bus: &str) -> Result<&str, String> {
    match bus {
        "virtio" | "scsi" | "ide" | "sata" => Ok(bus),
        other => Err(format!(
            "invalid disk bus '{}' in backup archive — libvirt accepts only \
             virtio / scsi / ide / sata", other)),
    }
}

/// N2: validate fields from the portable VmConfig's `extra_disks`
/// entries before they're interpolated into filesystem paths. Same
/// shape as the VM-name check but allowed against the field name in
/// errors so the operator can locate the bad entry.
fn validate_archive_path_field(value: &str, what: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("archive field `{}` is empty", what));
    }
    if value.contains('/') || value.contains('\\') || value.contains('\0')
        || value.contains("..") || value.starts_with('.')
    {
        return Err(format!(
            "archive field `{}` value '{}' contains a path-traversal character — refused",
            what, value));
    }
    if !value.chars().all(|c| c.is_ascii_alphanumeric()
        || c == '_' || c == '-' || c == '.' || c == '+' || c == ':')
    {
        return Err(format!(
            "archive field `{}` value '{}' contains characters outside [A-Za-z0-9_.+:-]",
            what, value));
    }
    Ok(())
}

/// N3: validate a MAC address against `AA:BB:CC:DD:EE:FF`. Pre-fix
/// the value flowed from the portable archive straight into a
/// `qm create --net0 virtio={mac},bridge=vmbr0` arg — and qm parses
/// --net0 as comma-separated key=value pairs. A crafted MAC value of
/// `DE:AD:BE:EF:00:01,firewall=1,queues=65535` would inject extra qm
/// network options from the archive. Strict regex check eliminates
/// the vector entirely.
fn validate_mac_address(mac: &str) -> Result<(), String> {
    if mac.len() != 17 {
        return Err(format!("MAC '{}' must be 17 chars (AA:BB:CC:DD:EE:FF)", mac));
    }
    for (i, c) in mac.chars().enumerate() {
        let is_separator = i % 3 == 2;
        if is_separator {
            if c != ':' {
                return Err(format!("MAC '{}' separator at position {} must be ':'", mac, i));
            }
        } else if !c.is_ascii_hexdigit() {
            return Err(format!("MAC '{}' has non-hex char '{}' at position {}", mac, c, i));
        }
    }
    Ok(())
}

/// Reject VM names that would either break out of file paths or break
/// libvirt's element-name validation. Mirrors the check
/// `export_vm_with_staging` uses at the export side.
fn validate_vm_name_for_restore(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("VM name is empty".into());
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0')
        || name.contains("..") || name.starts_with('.') || name.starts_with('-')
    {
        // Leading `-` rejected for the same reason as
        // validate_clone_vm_name: a name like `--full` becomes a flag
        // when passed as an argv positional to qm/virsh.
        return Err(format!(
            "invalid VM name '{}' — must not contain /, \\, NUL, '..' or start with '.' or '-'", name));
    }
    // libvirt domain names: letters, digits, _, -, +, ., :.
    // Be a touch stricter and refuse anything not in [A-Za-z0-9_.+:-].
    if !name.chars().all(|c| c.is_ascii_alphanumeric()
        || c == '_' || c == '-' || c == '.' || c == '+' || c == ':')
    {
        return Err(format!(
            "invalid VM name '{}' — only A-Z a-z 0-9 _ . - + : are allowed", name));
    }
    Ok(())
}

/// libvirt restore: extract the archive into the libvirt images dir,
/// translate the portable VmConfig into a minimal domain XML, then
/// `virsh define` it. Disk(s) end up at /var/lib/libvirt/images/<name>.qcow2.
fn restore_vm_to_libvirt(local_path: &Path, vm_name: &str) -> Result<String, String> {
    // Validate name before any filesystem or XML work — refuses crafted
    // archives whose VmConfig.name would escape the libvirt images
    // dir or inject XML. Same check applied to the Proxmox path below.
    validate_vm_name_for_restore(vm_name)?;
    use crate::vms::manager::VmConfig;

    let images_dir = Path::new("/var/lib/libvirt/images");
    fs::create_dir_all(images_dir)
        .map_err(|e| format!("create libvirt images dir: {}", e))?;

    // Extract into a per-restore work dir; move disks to images_dir at
    // the end so a half-failed extract doesn't pollute libvirt's
    // storage pool.
    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let work_dir = staging.join(format!("libvirt-restore-{}-{}", vm_name, timestamp));
    fs::create_dir_all(&work_dir).map_err(|e| format!("create work dir: {}", e))?;
    struct WorkDirGuard(PathBuf);
    impl Drop for WorkDirGuard {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }
    let _work_guard = WorkDirGuard(work_dir.clone());

    // N1: path-traversal hardening — refuse absolute or `..` paths in
    // the archive before extracting. Operator-controlled backup storage
    // means the archive content is untrusted at restore time.
    safe_extract_tar(local_path, &work_dir)?;
    let _ = fs::remove_file(local_path);

    let config_path = work_dir.join(format!("{}.json", vm_name));
    if !config_path.exists() {
        return Err(format!("archive did not contain {}.json — cannot restore", vm_name));
    }
    let config_text = fs::read_to_string(&config_path)
        .map_err(|e| format!("read config: {}", e))?;
    let config: VmConfig = serde_json::from_str(&config_text)
        .map_err(|e| format!("parse config: {}", e))?;

    // Move OS disk to libvirt images dir.
    let os_disk_src = work_dir.join(format!("{}.qcow2", vm_name));
    if !os_disk_src.exists() {
        return Err(format!("archive contained no OS disk ({}.qcow2)", vm_name));
    }
    let os_disk_dest = images_dir.join(format!("{}.qcow2", vm_name));
    if os_disk_dest.exists() {
        return Err(format!(
            "{} already exists — refuse to overwrite. Delete it manually or restore under a different name.",
            os_disk_dest.display()));
    }
    fs::rename(&os_disk_src, &os_disk_dest)
        .or_else(|_| {
            // Cross-filesystem move falls back to copy + remove.
            fs::copy(&os_disk_src, &os_disk_dest)?;
            fs::remove_file(&os_disk_src)?;
            Ok::<(), std::io::Error>(())
        })
        .map_err(|e| format!("move OS disk: {}", e))?;

    // Move each extra disk too, tracking final paths for XML generation.
    //
    // N4 fix: device letter uses a counter for SUCCESSFULLY placed
    // disks rather than the source-array index. Pre-fix, if one extra
    // disk was skipped (missing in archive OR dest already exists),
    // the next disk got a letter with a gap (e.g. vdd when vdb/vdc
    // were skipped) — some guests fail to boot on non-sequential
    // target dev names.
    let mut extra_disk_paths: Vec<(String, String, String)> = Vec::new();  // (path, target, bus)
    let mut placed_count: u32 = 0;
    for extra in config.extra_disks.iter() {
        // N2: validate every archive-derived field before using it in a
        // filesystem path. A crafted VmConfig with extra.name like
        // `../../etc/cron.d/evil` would escape work_dir / images_dir
        // on the fs::rename / fs::copy below.
        if let Err(e) = validate_archive_path_field(&extra.name, "extra_disks[].name") {
            warn!("libvirt restore: skipping extra disk — {}", e);
            continue;
        }
        if let Err(e) = validate_archive_path_field(&extra.format, "extra_disks[].format") {
            warn!("libvirt restore: skipping extra disk '{}' — {}", extra.name, e);
            continue;
        }
        let src = work_dir.join(format!("{}.{}", extra.name, extra.format));
        if !src.exists() {
            warn!("extra disk {} listed in config but not in archive — skipped", extra.name);
            continue;
        }
        let dest = images_dir.join(format!("{}-{}.qcow2", vm_name, extra.name));
        if dest.exists() {
            warn!("extra disk dest {} already exists — skipped", dest.display());
            continue;
        }
        if fs::rename(&src, &dest).is_err() {
            fs::copy(&src, &dest).map_err(|e| format!("copy extra disk {}: {}", extra.name, e))?;
            let _ = fs::remove_file(&src);
        }
        // A4: validate bus against the libvirt allowlist BEFORE it
        // flows into XML. The portable archive's VmConfig is untrusted
        // (operator-supplied content); a bus value like
        // `virtio'/></disk><foo` would break out of the attribute.
        let safe_bus = match validate_libvirt_bus(&extra.bus) {
            Ok(b) => b,
            Err(e) => {
                warn!("libvirt restore: skipping extra disk {} — {}", extra.name, e);
                continue;
            }
        };
        // libvirt target dev: vdb, vdc… for virtio bus; sdb, sdc… for scsi.
        let prefix = match safe_bus {
            "scsi" => "sd",
            "ide" => "hd",
            _ => "vd",
        };
        // 'a' is OS disk; extras start at 'b'. Cap at 'z' (26 extras) —
        // beyond that libvirt's single-letter dev naming doesn't apply
        // anyway, and the operator should be using a custom XML.
        if placed_count >= 25 {
            warn!("libvirt restore: more than 25 extra disks ({}); skipping {} — \
                   operator must edit XML to attach beyond vdz.", extra.name, extra.name);
            continue;
        }
        let letter = (b'b' + placed_count as u8) as char;
        let target = format!("{}{}", prefix, letter);
        placed_count += 1;
        extra_disk_paths.push((dest.to_string_lossy().to_string(), target, safe_bus.to_string()));
    }

    // Build a minimal libvirt domain XML. Operator can customise after
    // `virsh edit <name>` if they need machine type / NIC bridge changes.
    let machine = if config.bios_type == "ovmf" || config.bios_type == "uefi" {
        "q35"
    } else {
        "pc"
    };
    // A4: XML-escape every string that originates from operator-supplied
    // content (the portable archive's VmConfig). vm_name was already
    // shape-validated above by `validate_vm_name_for_restore`, so the
    // escape is defence-in-depth — same for the file paths, which
    // embed vm_name plus chrono timestamps.
    let safe_name = xml_escape(vm_name);
    let safe_os_disk = xml_escape(&os_disk_dest.to_string_lossy());
    let mut xml = format!(
        "<domain type='kvm'>\n  \
         <name>{}</name>\n  \
         <memory unit='MiB'>{}</memory>\n  \
         <vcpu>{}</vcpu>\n  \
         <os>\n    <type arch='x86_64' machine='{}'>hvm</type>\n    <boot dev='hd'/>\n  </os>\n  \
         <features>\n    <acpi/>\n    <apic/>\n  </features>\n  \
         <clock offset='utc'/>\n  \
         <devices>\n    \
         <disk type='file' device='disk'>\n      \
         <driver name='qemu' type='qcow2'/>\n      \
         <source file='{}'/>\n      \
         <target dev='vda' bus='virtio'/>\n    </disk>\n",
        safe_name, config.memory_mb, config.cpus, machine,
        safe_os_disk,
    );
    // Append extra disks — `bus` has already passed `validate_libvirt_bus`
    // (allowlist), `target` is constructed from hardcoded prefix + a
    // single letter, and `path` is escaped here.
    for (path, target, bus) in &extra_disk_paths {
        let safe_path = xml_escape(path);
        // target and bus are from our allowlist/prefix construction so
        // escape is redundant but cheap; keep for consistency.
        xml.push_str(&format!(
            "    <disk type='file' device='disk'>\n      \
             <driver name='qemu' type='qcow2'/>\n      \
             <source file='{}'/>\n      \
             <target dev='{}' bus='{}'/>\n    </disk>\n",
            safe_path, xml_escape(target), xml_escape(bus),
        ));
    }
    // Network — virbr0 is libvirt's default NAT bridge.
    // N3: validate MAC shape AND xml_escape — defence in depth.
    // If validation fails we drop the MAC and let libvirt assign one
    // rather than aborting restore for a cosmetic mismatch.
    let mac_line = if let Some(mac) = &config.mac_address {
        match validate_mac_address(mac) {
            Ok(()) => format!("      <mac address='{}'/>\n", xml_escape(mac)),
            Err(e) => {
                warn!("libvirt restore: ignoring invalid MAC from archive — {}", e);
                String::new()
            }
        }
    } else { String::new() };
    xml.push_str(&format!(
        "    <interface type='network'>\n      \
         <source network='default'/>\n{}\
         <model type='virtio'/>\n    </interface>\n    \
         <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'/>\n    \
         <console type='pty'/>\n  </devices>\n</domain>\n",
        mac_line,
    ));

    // Write the XML to a temp file and virsh define.
    let xml_path = work_dir.join(format!("{}.xml", vm_name));
    fs::write(&xml_path, &xml).map_err(|e| format!("write XML: {}", e))?;
    let define = Command::new("virsh")
        .args(["define", &xml_path.to_string_lossy()])
        .output()
        .map_err(|e| format!("virsh define failed to start: {}", e))?;
    if !define.status.success() {
        // Roll back: remove the disks we just placed.
        let _ = fs::remove_file(&os_disk_dest);
        for (path, _, _) in &extra_disk_paths {
            let _ = fs::remove_file(path);
        }
        return Err(format!(
            "virsh define failed: {} — disks rolled back",
            String::from_utf8_lossy(&define.stderr).trim()));
    }

    Ok(format!(
        "VM '{}' restored to libvirt (disk: {}, {} extra disk(s)). \
         Start it with `virsh start {}` or via the WolfStack VM list. \
         W5: NIC is attached to libvirt's 'default' network. If your \
         libvirt setup uses a custom bridge (virbr1, br0, etc.) or has \
         'default' disabled, edit with `virsh edit {}` before starting \
         or the VM will have no network connectivity.",
        vm_name, os_disk_dest.display(), extra_disk_paths.len(), vm_name, vm_name))
}

/// Native restore — extract the tar.gz to /var/lib/wolfstack/vms/ and
/// verify the config landed at the expected flat path. Handles legacy
/// archives that wrap the config inside a subdirectory.
fn restore_vm_to_native(local_path: &Path, vm_name: &str) -> Result<String, String> {
    // Same name-shape validation as the libvirt/Proxmox paths — refuse
    // crafted archives whose VmConfig.name would let extracted files
    // land outside /var/lib/wolfstack/vms.
    validate_vm_name_for_restore(vm_name)?;

    let vm_base = "/var/lib/wolfstack/vms";
    fs::create_dir_all(vm_base).map_err(|e| format!("Failed to create VM dir: {}", e))?;

    // Extract to /var/lib/wolfstack/vms/. Uses the same path-traversal-
    // safe helper as the libvirt and Proxmox restore paths: lists
    // archive entries first and refuses absolute / `..` / NUL paths
    // before extracting. Pre-fix this used raw `tar xzf` which would
    // have allowed a crafted archive to write `../../../etc/cron.d/evil`.
    safe_extract_tar(local_path, Path::new(vm_base))?;
    let _ = fs::remove_file(local_path);

    // Verify the config JSON was restored
    let config_path = format!("{}/{}.json", vm_base, vm_name);
    if !Path::new(&config_path).exists() {
        // Legacy backup format: config might be inside a subdirectory
        let legacy_config = format!("{}/{}/config.json", vm_base, vm_name);
        if Path::new(&legacy_config).exists() {
            // Move it to the expected flat location
            let _ = fs::copy(&legacy_config, &config_path);
        } else {
            warn!("VM config not found after restore: {} — VM may not appear in list until config is recreated", config_path);
        }
    }

    Ok(format!("VM '{}' restored to /var/lib/wolfstack/vms/ as a native KVM VM", vm_name))
}

/// Proxmox restore — extract the portable archive to a work dir,
/// read the JSON config, allocate a free VMID, create the VM via
/// `qm create`, and import each disk via `qm importdisk`. The OS
/// disk lands at scsi0; extras at scsi1, scsi2, … (or their original
/// bus name when StorageVolume.bus is set).
///
/// `target_storage = None` (operator left the picker blank) auto-selects
/// the first ACTIVE images-capable PVE storage, falling back to `local-lvm`
/// only if none is found. An explicit pick is validated and used as-is.
fn restore_vm_to_proxmox(
    local_path: &Path,
    vm_name: &str,
    target_storage: Option<&str>,
) -> Result<String, String> {
    use crate::vms::manager::VmConfig;

    // Same validation as the libvirt restore — refuse names that
    // would escape paths or break `qm create` arg passing.
    validate_vm_name_for_restore(vm_name)?;

    // `qm importdisk` REQUIRES a target storage (unlike `pct restore
    // --storage`, which is optional and lets PVE pick its own default). So
    // when the operator left the picker blank we must choose one ourselves —
    // the first ACTIVE images-capable PVE storage, rather than blindly
    // assuming `local-lvm`, which doesn't exist on ZFS-only / custom hosts
    // (that assumption was itself a restore-failure source). Any explicit
    // pick is validated the same way the LXC path validates its storage id —
    // it becomes a `qm` execve arg, so reject anything that isn't a plausible
    // PVE storage id as defence in depth.
    let storage_owned: String = match target_storage.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => {
            if !s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
                return Err(format!("Invalid Proxmox storage id: '{}'", s));
            }
            s.to_string()
        }
        None => crate::containers::pvesm_list_storage().into_iter()
            .find(|st| st.status == "active" && st.content.iter().any(|c| c == "images"))
            .map(|st| st.id)
            .unwrap_or_else(|| "local-lvm".to_string()),
    };
    let storage = storage_owned.as_str();

    // 1) Extract the portable archive into a per-restore work dir so
    //    we don't pollute staging if the qm step fails halfway.
    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let work_dir = staging.join(format!("pmx-restore-{}-{}", vm_name, timestamp));
    fs::create_dir_all(&work_dir)
        .map_err(|e| format!("create work dir: {}", e))?;
    struct WorkDirGuard(PathBuf);
    impl Drop for WorkDirGuard {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }
    let _work_guard = WorkDirGuard(work_dir.clone());

    // N1: same path-traversal hardening as the libvirt restore path.
    safe_extract_tar(local_path, &work_dir)?;
    let _ = fs::remove_file(local_path);

    // 2) Read the portable VmConfig.
    let config_path = work_dir.join(format!("{}.json", vm_name));
    if !config_path.exists() {
        return Err(format!(
            "archive did not contain {}.json — operator may have an old-format \
             backup that needs manual conversion. Nothing was created.", vm_name));
    }
    let config_text = fs::read_to_string(&config_path)
        .map_err(|e| format!("read config: {}", e))?;
    let config: VmConfig = serde_json::from_str(&config_text)
        .map_err(|e| format!("parse config: {}", e))?;

    // 3) Allocate a free VMID via the cluster-safe Proxmox API. C2 fix:
    //    pre-fix this used a local-filesystem scan which races other
    //    cluster nodes during concurrent restore (or against the PVE
    //    HA manager). `pvesh get /cluster/nextid` is the cluster-wide
    //    primitive.
    let vmid = crate::vms::manager::next_pve_vmid()?;

    // 4) Create the VM with `qm create`. Use BIOS / cores / memory from
    //    the config; default to virtio NIC on vmbr0 if a MAC is present.
    let bios_arg = match config.bios_type.as_str() {
        "ovmf" | "uefi" => "ovmf",
        _ => "seabios",
    };
    let mut qm_args: Vec<String> = vec![
        "create".to_string(),
        vmid.to_string(),
        "--name".to_string(), vm_name.to_string(),
        "--cores".to_string(), config.cpus.to_string(),
        "--memory".to_string(), config.memory_mb.to_string(),
        "--bios".to_string(), bios_arg.to_string(),
        // No disks yet — qm importdisk attaches them below. Without
        // any disk, `--ostype l26` is a safe default for Linux guests;
        // Windows users will edit it post-restore.
        "--ostype".to_string(), "l26".to_string(),
    ];
    // N3: validate MAC before it flows into qm's comma-separated arg.
    // A crafted archive MAC like `DE:AD:BE:EF:00:01,firewall=1` would
    // inject extra --net0 options. On validation failure we drop the
    // MAC and fall back to qm picking one, rather than aborting the
    // restore — the operator can fix the MAC post-restore.
    let safe_mac = config.mac_address.as_ref().and_then(|m| {
        match validate_mac_address(m) {
            Ok(()) => Some(m.clone()),
            Err(e) => {
                warn!("Proxmox restore: ignoring invalid MAC from archive — {}", e);
                None
            }
        }
    });
    if let Some(mac) = safe_mac {
        qm_args.push("--net0".to_string());
        qm_args.push(format!("virtio={},bridge=vmbr0", mac));
    } else {
        qm_args.push("--net0".to_string());
        qm_args.push("virtio,bridge=vmbr0".to_string());
    }

    let create = Command::new("qm").args(&qm_args).output()
        .map_err(|e| format!("qm create failed to start: {}", e))?;
    if !create.status.success() {
        return Err(format!(
            "qm create {} failed: {}",
            vmid, String::from_utf8_lossy(&create.stderr).trim()));
    }

    // 5) Import the OS disk first (lands at unused0 after import, then
    //    we move it to scsi0).
    let os_disk = work_dir.join(format!("{}.qcow2", vm_name));
    if !os_disk.exists() {
        // Roll back the half-created VM so the operator isn't left
        // with a husk to clean up by hand.
        let _ = Command::new("qm").args(["destroy", &vmid.to_string()]).output();
        return Err(format!(
            "archive contained no OS disk ({}.qcow2). VM {} created+destroyed; \
             nothing to attach.", vm_name, vmid));
    }
    // C3 fix: use the shared `pve_import_and_attach_disk` helper from
    // vms::manager — it CORRECTLY omits `--format qcow2` (forcing that
    // breaks LVM-thin and ZFS, the most common production PVE storage
    // layouts). The buggy local copy `import_disk_to_proxmox` is gone.
    crate::vms::manager::pve_import_and_attach_disk(vmid, &os_disk, storage, "scsi0")
        .map_err(|e| {
            let _ = Command::new("qm").args(["destroy", &vmid.to_string()]).output();
            format!("OS disk import failed: {}. VM {} rolled back.", e, vmid)
        })?;

    // Set boot device to the imported OS disk.
    let boot = Command::new("qm")
        .args(["set", &vmid.to_string(), "--boot", "order=scsi0"])
        .output()
        .map_err(|e| format!("qm set boot failed to start: {}", e))?;
    if !boot.status.success() {
        // Non-fatal — VM exists and has a disk, operator can set boot
        // manually. Log instead of failing the whole restore.
        warn!("qm set --boot for {} failed: {} — operator may need to set boot device manually",
            vmid, String::from_utf8_lossy(&boot.stderr).trim());
    }

    // 6) Import extra disks (scsi1, scsi2, …). The slot name comes
    //    from the portable config's extra_disks entries — bus is
    //    preserved where possible.
    let mut next_slot_by_bus: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    next_slot_by_bus.insert("scsi".into(), 1);  // scsi0 already used by OS disk
    next_slot_by_bus.insert("virtio".into(), 0);
    next_slot_by_bus.insert("ide".into(), 0);
    next_slot_by_bus.insert("sata".into(), 0);
    for extra in &config.extra_disks {
        // N2: same archive-field validation as the libvirt restore path.
        if let Err(e) = validate_archive_path_field(&extra.name, "extra_disks[].name") {
            warn!("Proxmox restore: skipping extra disk — {}", e);
            continue;
        }
        if let Err(e) = validate_archive_path_field(&extra.format, "extra_disks[].format") {
            warn!("Proxmox restore: skipping extra disk '{}' — {}", extra.name, e);
            continue;
        }
        let extra_path = work_dir.join(format!("{}.{}", extra.name, extra.format));
        if !extra_path.exists() {
            warn!("extra disk {} listed in config but not present in archive — skipped",
                extra.name);
            continue;
        }
        let bus = if next_slot_by_bus.contains_key(extra.bus.as_str()) {
            extra.bus.clone()
        } else {
            "scsi".to_string()
        };
        let slot_num = next_slot_by_bus.get(bus.as_str()).copied().unwrap_or(0);
        let slot_name = format!("{}{}", bus, slot_num);
        next_slot_by_bus.insert(bus.clone(), slot_num + 1);
        if let Err(e) = crate::vms::manager::pve_import_and_attach_disk(
            vmid, &extra_path, storage, &slot_name)
        {
            warn!("extra disk {} import failed: {} — operator must attach manually",
                extra.name, e);
        }
    }

    Ok(format!(
        "VM '{}' restored to Proxmox as VMID {} on storage '{}' (boot device: scsi0). \
         Start it with `qm start {}` or via the WolfStack VM list.",
        vm_name, vmid, storage, vmid))
}

// `import_disk_to_proxmox` and `allocate_free_proxmox_vmid` were
// removed in the C2/C3 fix round — both duplicated logic that already
// existed (correctly) in vms::manager, and both had subtle bugs:
//   • allocate_free_proxmox_vmid scanned local files and raced the
//     cluster — replaced by `next_pve_vmid` (uses `pvesh /cluster/nextid`)
//   • import_disk_to_proxmox passed `--format qcow2` which breaks
//     LVM-thin and ZFS — replaced by `pve_import_and_attach_disk`

/// Restore WolfStack configuration from backup
/// Config files that pin a backup to ONE physical machine — node identity,
/// cluster membership, TLS material and network position. On a "new machine"
/// restore these are dropped so the fresh host generates its own (and doesn't
/// collide with the machine the backup came from); everything else (app/service
/// config — storage, AI, workflows, status pages, users, alerting, the cluster
/// secret so it can rejoin) is restored. Paths are archive-relative (rooted at
/// `etc/…`, matching how `backup_config` stored them).
const MACHINE_SPECIFIC_CONFIG: &[&str] = &[
    "etc/wolfstack/node_id",
    "etc/wolfstack/nodes.json",
    "etc/wolfstack/deleted_nodes.json",
    "etc/wolfstack/pending_identity.json",
    "etc/wolfstack/self_cluster.json",
    "etc/wolfstack/self_site.json",
    "etc/wolfstack/self_display_name.json",
    "etc/wolfstack/cert.pem",
    "etc/wolfstack/key.pem",
    "etc/wolfstack/ip-mappings.json",
    "etc/wolfstack/router.json",
    "etc/wolfstack/router",
    "etc/wolfstack/vlan-attachments.json",
    "etc/wolfstack/vlan-learner",
    "etc/wolfstack/docker-wolfnet.json",
    "etc/wolfstack/wolfnet-tombstones.json",
    "etc/wolfstack/join-token",
    // Host-layout / port config — wrong on a box with different mounts, pools
    // or NICs (restoring paths.json/lxc-paths.json onto a different storage
    // layout makes backups/LXC ops fail with ENOENT; ports.json could silently
    // move the listen port).
    "etc/wolfstack/paths.json",
    "etc/wolfstack/lxc-paths.json",
    "etc/wolfstack/ports.json",
    "etc/wolfnet",
];

/// Restore a WolfStack config backup. `new_machine = false` does a full restore
/// (same host); `true` drops the machine-specific identity/TLS/networking files
/// (`MACHINE_SPECIFIC_CONFIG`) so the config can be carried onto a different box
/// without clashing identities or wrong-NIC networking (wabil's request).
pub fn restore_config_backup(entry: &BackupEntry, new_machine: bool) -> Result<String, String> {
    // PBS file-level (pxar) config snapshot: materialise the tree into the
    // same private staging the tarball path uses, then apply identically —
    // so both formats honour the same-/new-machine choice. (Single-FILE
    // restores are what pxar is for; those happen in PBS's own UI.)
    if is_pbs_file_level_entry(entry) {
        let staging = make_config_restore_staging()?;
        if let Err(e) = restore_pbs_file_level_entry(entry, &staging.to_string_lossy()) {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
        return apply_config_staging(&staging, new_machine);
    }

    let local_path = retrieve_backup(entry)?;

    if !new_machine {
        // Same-machine: extract straight to / (files carry their relative paths).
        let output = Command::new("tar")
            .args(["xzf", &local_path.to_string_lossy(), "-C", "/"])
            .output()
            .map_err(|e| format!("Failed to extract config backup: {}", e))?;
        let _ = fs::remove_file(&local_path);
        if !output.status.success() {
            return Err(format!("Config extract failed: {}", String::from_utf8_lossy(&output.stderr)));
        }
        return Ok("WolfStack configuration restored. Restart services to apply changes.".to_string());
    }

    // New-machine: extract to a staging dir, drop the machine-specific paths,
    // then merge the remainder into place. Staging avoids tar --exclude glob
    // ambiguity (e.g. wolfnet vs wolfnet-tombstones) and lets us delete dirs
    // and files uniformly.
    let staging = make_config_restore_staging()?;

    let output = Command::new("tar")
        .args(["xzf", &local_path.to_string_lossy(), "-C", &staging.to_string_lossy()])
        .output()
        .map_err(|e| format!("Failed to extract config backup: {}", e))?;
    let _ = fs::remove_file(&local_path);
    if !output.status.success() {
        let _ = fs::remove_dir_all(&staging);
        return Err(format!("Config extract failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    apply_config_staging(&staging, new_machine)
}

/// Private (0o700) staging dir for a config restore. Restrict to root: the
/// default staging base is under /tmp and this dir briefly holds TLS key
/// material + /etc/wolfstack before the cp into place, so don't let any other
/// local user read or plant files in it. Create with mode 0o700 in the
/// mkdir(2) call itself (DirBuilder) rather than chmod-ing after — that closes
/// the window where the dir is world-readable. umask can only clear bits,
/// never add them, so 0o700 is guaranteed regardless of it.
fn make_config_restore_staging() -> Result<PathBuf, String> {
    let staging = ensure_staging_dir()?.join("config-restore");
    let _ = fs::remove_dir_all(&staging);
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&staging)
        .map_err(|e| format!("Failed to create restore staging: {}", e))?;
    Ok(staging)
}

/// Apply a staged config tree to this host. `new_machine = true` first drops
/// the machine-specific identity/TLS/networking files (`MACHINE_SPECIFIC_
/// CONFIG`). Consumes (deletes) the staging dir. Shared by the tarball and
/// PBS-pxar restore paths so the two can't drift.
fn apply_config_staging(staging: &Path, new_machine: bool) -> Result<String, String> {
    if new_machine {
        for rel in MACHINE_SPECIFIC_CONFIG {
            let p = staging.join(rel);
            // It may be a file or a directory; try both, ignore "not present".
            let _ = fs::remove_file(&p);
            let _ = fs::remove_dir_all(&p);
        }
    }

    // Merge staging into / (cp -a preserves perms/ownership; `staging/.` copies
    // the contents, so `staging/etc/...` lands at `/etc/...`).
    let cp = Command::new("cp")
        .args(["-a", &format!("{}/.", staging.to_string_lossy()), "/"])
        .output()
        .map_err(|e| format!("Failed to copy restored config into place: {}", e))?;
    let _ = fs::remove_dir_all(staging);
    if !cp.status.success() {
        return Err(format!("Config restore copy failed: {}", String::from_utf8_lossy(&cp.stderr)));
    }

    Ok(if new_machine {
        "WolfStack configuration restored (new-machine mode: node identity, TLS \
         and networking left untouched). Restart services to apply changes.".to_string()
    } else {
        "WolfStack configuration restored. Restart services to apply changes.".to_string()
    })
}

/// Restore from a backup entry (auto-detects type). Non-streaming path:
/// an LXC restore here uses the node's default storage — the streaming
/// restore (`restore_by_id_with_log`) is the one that honours a storage
/// the operator picked in the restore dialog.
pub fn restore_backup(entry: &BackupEntry, overwrite: bool) -> Result<String, String> {
    // PBS file-level (pxar) snapshots restore by extracting the tree, not via
    // the tarball-based per-type restore paths. Config is the exception: its
    // restore must APPLY the tree (same-/new-machine rules), so it goes
    // through restore_config_backup, which is pxar-aware.
    if is_pbs_file_level_entry(entry) && entry.target.target_type != BackupTargetType::Config {
        return restore_pbs_file_level_entry(entry, "");
    }
    match entry.target.target_type {
        BackupTargetType::Docker => restore_docker(entry, overwrite),
        BackupTargetType::Lxc => restore_lxc(entry, "", overwrite, ""),
        BackupTargetType::Vm => restore_vm(entry),
        // Non-streaming path has no restore-mode UI → full (same-machine) restore.
        BackupTargetType::Config => restore_config_backup(entry, false),
        // System-folder restore defaults to IN PLACE — restore_system_path
        // inspects the archive and picks the parent (leaf-style) or the folder
        // itself (contents-only). The streaming/targeted path
        // (restore_entry_with_log) lets the operator choose an explicit dir.
        BackupTargetType::SystemPath => restore_system_path(entry, ""),
    }
}

// ─── Public API Functions ───

/// List all backup entries
pub fn list_backups() -> Vec<BackupEntry> {
    load_config().entries
}

/// Create a backup (single target or all)
pub fn create_backup(target: Option<BackupTarget>, storage: BackupStorage) -> Vec<BackupEntry> {
    let mut config = load_config();

    let new_entries = match target {
        Some(t) => vec![create_backup_entry(t, &storage)],
        // On-demand "everything" from the UI: live (crash-consistent) container
        // archives, as it always has been — cold backups are a scheduling
        // decision, made per schedule.
        None => backup_all(&storage, false, &[]),
    };

    config.entries.extend(new_entries.clone());
    let _ = save_config(&config);

    new_entries
}

/// Create a backup with real-time log output via a sender channel
pub fn create_backup_with_log(
    target: Option<BackupTarget>,
    storage: BackupStorage,
    log: std::sync::mpsc::Sender<String>,
    cluster_name: Option<String>,
) -> Vec<BackupEntry> {
    // Bake the concrete Local directory in up front (see with_concrete_local)
    // so restore is independent of any later default-dir change.
    let storage = storage.with_concrete_local(&crate::paths::get().backup_local_dir);
    let targets = match target {
        Some(t) => vec![t],
        None => list_available_targets(),
    };

    let mut entries = Vec::new();
    let total = targets.len();
    let cluster = cluster_name.unwrap_or_else(local_cluster_name);
    let _ = log.send(format!("Cluster: {} | Node: {}", cluster, local_hostname()));

    for (i, t) in targets.iter().enumerate() {
        let type_name = t.target_type.to_string().to_uppercase();
        let display_name = if let Some(h) = &t.hostname {
            format!("{} ({})", t.name, h)
        } else {
            t.name.clone()
        };

        let _ = log.send(format!("[{}/{}] Starting {} backup: {}",
            i + 1, total, type_name, display_name));

        let mut comments = backup_comments_with_cluster(t, &cluster);
        // Always state the resulting archive format + reason in the live log so
        // a .tar.gz is never mistaken for a broken file-level feature (wabil
        // 2026-06-21: "I can't see the reason in the logs"). The fallback note
        // is still folded into the persisted entry comments for the
        // file-level-requested-but-inapplicable case only (unchanged on-disk
        // behaviour — Golden Rule).
        let _ = log.send(format!("  {}", backup_format_explainer(t, &storage)));
        if let Some(note) = pbs_file_level_skip_note(t, &storage) {
            comments = format!("{} | {}", comments, note);
        }
        let hostname = local_hostname();

        // PBS file-level (pxar) path — upload the workload's content directory
        // directly so PBS per-file restore works. Applies to Docker, native
        // LXC, SystemPath and Config; for VM / Proxmox-LXC make_pbs_file_
        // level_entry returns None and we fall through to the tarball path.
        if storage.storage_type == StorageType::Pbs && storage.pbs_file_level {
            let _ = log.send("  PBS file-level backup requested...".to_string());
            if let Some(res) = make_pbs_file_level_entry(t, &storage, &comments, &cluster, &hostname, Some(&log)) {
                match res {
                    Ok(entry) => {
                        let _ = log.send(format!("  ✓ {} file-level backup complete", type_name));
                        entries.push(entry);
                    }
                    Err(e) => {
                        let _ = log.send(format!("  ✗ PBS file-level backup failed: {}", e));
                        entries.push(BackupEntry {
                            id: Uuid::new_v4().to_string(),
                            target: t.clone(),
                            storage: storage.clone(),
                            filename: String::new(),
                            size_bytes: 0,
                            created_at: Utc::now().to_rfc3339(),
                            status: BackupStatus::Failed,
                            error: e,
                            schedule_id: String::new(),
                            comments,
                            node_hostname: hostname,
                            docker_config: String::new(),
                            mounts: Vec::new(),
                        });
                    }
                }
                continue;
            }
            let _ = log.send("  (file-level not applicable to this target — using image backup)".to_string());
        }

        // Run the backup with line-by-line output for vzdump
        let (result, docker_config, mounts) = match t.target_type {
            BackupTargetType::Docker => {
                let _ = log.send(format!("  Exporting Docker container '{}'{}...",
                    t.name,
                    if t.stop_for_backup { " — stopping for a cold backup" } else { " while it runs" }));
                if !t.exclude_mounts.is_empty() {
                    let _ = log.send(format!("  Excluding {} mount(s): {}",
                        t.exclude_mounts.len(), t.exclude_mounts.join(", ")));
                }
                match backup_docker(&t.name, &t.exclude_mounts, t.stop_for_backup) {
                    Ok((path, size, config, m)) => {
                        if !m.is_empty() {
                            let archived = m.iter().filter(|x| !x.archive_path.is_empty()).count();
                            let skipped  = m.iter().filter(|x|  x.archive_path.is_empty()).count();
                            let _ = log.send(format!("  + {} mount(s) captured ({} archived, {} skipped)", m.len(), archived, skipped));
                            for x in m.iter().filter(|x| !x.skipped_reason.is_empty()) {
                                let _ = log.send(format!("    skipped {} {}: {}", x.mount_type, x.destination, x.skipped_reason));
                            }
                        }
                        (Ok((path, size)), config, m)
                    },
                    Err(e) => (Err(e), String::new(), Vec::new()),
                }
            }
            BackupTargetType::Lxc => {
                if !t.exclude_mounts.is_empty() {
                    let _ = log.send(format!("  Excluding {} mount(s): {}",
                        t.exclude_mounts.len(), t.exclude_mounts.join(", ")));
                }
                let r = if crate::containers::is_proxmox() {
                    let _ = log.send(format!("  Running vzdump for container {}...", t.name));
                    backup_lxc_proxmox_with_log(&t.name, &t.exclude_mounts, &log)
                } else {
                    let _ = log.send(format!("  Tarring LXC '{}'{} (snapshot used automatically when the storage supports it)...",
                        t.name,
                        if t.stop_for_backup { " — stopping for a cold backup" } else { " while it runs" }));
                    backup_lxc(&t.name, &t.exclude_mounts, t.stop_for_backup)
                };
                (r, String::new(), Vec::new())
            }
            BackupTargetType::Vm => {
                let _ = log.send(format!("  Backing up VM '{}'...", t.name));
                (backup_vm(&t.name), String::new(), Vec::new())
            }
            BackupTargetType::Config => {
                let _ = log.send("  Archiving WolfStack config files...".to_string());
                (backup_config(), String::new(), Vec::new())
            }
            BackupTargetType::SystemPath => {
                let _ = log.send(format!("  Archiving system folder '{}'...", t.system_path));
                if !t.exclude_mounts.is_empty() {
                    let (applied, dropped) = classify_folder_excludes(&t.system_path, &t.exclude_mounts);
                    if !applied.is_empty() {
                        let _ = log.send(format!("  Excluding {} sub-path(s): {}",
                            applied.len(), applied.join(", ")));
                    }
                    // Loudly flag excludes that don't sit under this folder —
                    // they do nothing, and silence is what made this look like
                    // a bug (wabil 2026-07-05).
                    if !dropped.is_empty() {
                        let _ = log.send(format!(
                            "  ⚠ {} exclude(s) IGNORED — not inside '{}': {}. \
                             Exclusions must be sub-paths of the folder being backed up \
                             (e.g. on Unraid use the SAME /mnt/user or /mnt/cache prefix as the folder).",
                            dropped.len(), t.system_path, dropped.join(", ")));
                    }
                }
                (backup_system_path(&t.name, &t.system_path, &t.exclude_mounts), String::new(), Vec::new())
            }
        };

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        let entry = match result {
            Ok((local_path, size)) => {
                let _ = log.send(format!("  Backup created: {} ({})",
                    local_path.file_name().unwrap_or_default().to_string_lossy(),
                    format_size_human(size)));

                let filename = local_path.file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| format!("backup-{}.tar.gz", id));

                let _ = log.send(format!("  Storing to {}...", storage_label(&storage)));
                let pbs_notes = format!("Cluster: {} | Node: {} | {}", cluster, hostname, comments);

                let store_result = if storage.storage_type == StorageType::Pbs {
                    store_pbs_with_notes_and_log(&local_path, &storage, &filename, Some(&pbs_notes), Some(&log))
                } else {
                    store_backup_with_notes(&local_path, &storage, &filename, Some(&pbs_notes))
                };
                match store_result {
                    Ok(_) => {
                        let _ = fs::remove_file(&local_path);
                        let _ = log.send(format!("  ✓ {} backup complete ({})", type_name, format_size_human(size)));
                        BackupEntry {
                            id, target: t.clone(), storage: storage.clone(), filename,
                            size_bytes: size, created_at: now, status: BackupStatus::Completed,
                            error: String::new(), schedule_id: String::new(),
                            comments, node_hostname: hostname, docker_config,
                            mounts: mounts.clone(),
                        }
                    }
                    Err(e) => {
                        let _ = fs::remove_file(&local_path);
                        let _ = log.send(format!("  ✗ Storage failed: {}", e));
                        BackupEntry {
                            id, target: t.clone(), storage: storage.clone(), filename,
                            size_bytes: size, created_at: now, status: BackupStatus::Failed,
                            error: e, schedule_id: String::new(),
                            comments, node_hostname: hostname, docker_config: String::new(),
                            mounts: Vec::new(),
                        }
                    }
                }
            }
            Err(e) => {
                let _ = log.send(format!("  ✗ Backup failed: {}", e));
                BackupEntry {
                    id, target: t.clone(), storage: storage.clone(),
                    filename: String::new(), size_bytes: 0, created_at: now,
                    status: BackupStatus::Failed, error: e,
                    schedule_id: String::new(), comments, node_hostname: hostname,
                    docker_config: String::new(),
                    mounts: Vec::new(),
                }
            }
        };
        entries.push(entry);
    }

    let ok = entries.iter().filter(|e| e.status == BackupStatus::Completed).count();
    let fail = entries.iter().filter(|e| e.status == BackupStatus::Failed).count();
    let _ = log.send(format!("\nDone: {} succeeded, {} failed", ok, fail));

    // WolfFunctions backup triggers — one event per job run, on the node
    // that ran it.
    let backup_event = serde_json::json!({
        "succeeded": ok,
        "failed": fail,
        "items": entries.iter().map(|e| serde_json::json!({
            "filename": e.filename, "status": format!("{:?}", e.status),
        })).collect::<Vec<_>>(),
    });
    if fail > 0 {
        crate::wolffunctions::fire_event_global(
            crate::wolffunctions::TriggerEvent::BackupFailed, backup_event, true);
    } else if ok > 0 {
        crate::wolffunctions::fire_event_global(
            crate::wolffunctions::TriggerEvent::BackupCompleted, backup_event, true);
    }

    let mut config = load_config();
    config.entries.extend(entries.clone());
    let _ = save_config(&config);

    entries
}

/// Drain a vzdump pipe while retaining the valid lines used to locate its archive.
fn collect_vzdump_output(reader: impl std::io::BufRead, log: &std::sync::mpsc::Sender<String>) -> String {
    let mut all = String::new();
    for result in reader.lines() {
        match result {
            Ok(line) => {
                let _ = log.send(format!("  {}", line));
                all.push_str(&line);
                all.push('\n');
            }
            // BufRead::read_line consumes the malformed line before rejecting
            // its UTF-8. Keep draining so later archive paths are still found.
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => continue,
            Err(e) => {
                warn!("Failed to read vzdump output: {}", e);
                let _ = log.send(format!("  Failed to read vzdump output: {}", e));
                break;
            }
        }
    }
    all
}

/// Proxmox vzdump with real-time log output
fn backup_lxc_proxmox_with_log(
    vmid: &str,
    exclude_mounts: &[String],
    log: &std::sync::mpsc::Sender<String>,
) -> Result<(PathBuf, u64), String> {
    let staging = ensure_staging_dir()?;
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();

    // Try snapshot mode first, then stop mode
    for mode in &["snapshot", "stop"] {
        let _ = log.send(format!("  vzdump --mode {} ...", mode));

        let mut cmd = Command::new("vzdump");
        cmd.args([
                vmid,
                "--dumpdir", &staging.to_string_lossy(),
                "--mode", mode,
                "--compress", "zstd",
            ]);
        vzdump_apply_excludes(&mut cmd, exclude_mounts);
        let mut child = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("vzdump failed to start: {}", e))?;

        // Read stdout and stderr in parallel threads to avoid pipe deadlock
        // (vzdump writes to both — if one pipe buffer fills while we block on
        // the other, the process hangs)
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let log_clone = log.clone();
        let stdout_handle = std::thread::spawn(move || {
            match stdout {
                Some(stdout) => collect_vzdump_output(std::io::BufReader::new(stdout), &log_clone),
                None => String::new(),
            }
        });

        let log_clone2 = log.clone();
        let stderr_handle = std::thread::spawn(move || {
            match stderr {
                Some(stderr) => collect_vzdump_output(std::io::BufReader::new(stderr), &log_clone2),
                None => String::new(),
            }
        });

        let all_stdout = stdout_handle.join().unwrap_or_default();
        let all_stderr = stderr_handle.join().unwrap_or_default();
        // Combine stdout+stderr — vzdump may log the archive path to either
        let all_output = format!("{}{}", all_stdout, all_stderr);

        let status = child.wait().map_err(|e| format!("vzdump wait failed: {}", e))?;
        if status.success() {
            return find_vzdump_result(&all_output, &staging, vmid, &timestamp);
        }

        if *mode == "snapshot" {
            let _ = log.send("  Snapshot mode not supported, trying stop mode...".to_string());
        }
    }

    Err("vzdump failed in all modes".to_string())
}


fn storage_label(storage: &BackupStorage) -> String {
    match storage.storage_type {
        StorageType::Local => format!("local: {}", storage.path),
        StorageType::S3 => format!("S3: {}", storage.bucket),
        StorageType::Remote => format!("remote: {}", storage.remote_url),
        StorageType::Wolfdisk => {
            let sub = storage.wolfdisk_subpath.trim().trim_matches('/');
            if sub.is_empty() {
                format!("WolfDisk: {}", storage.path)
            } else {
                format!("WolfDisk: {}/{}", storage.path.trim_end_matches('/'), sub)
            }
        }
        StorageType::Pbs => format!("PBS: {}", storage.pbs_server),
        StorageType::Nfs => format!("NFS: {}", storage.nfs_source),
        StorageType::Smb => {
            if storage.smb_subpath.is_empty() {
                format!("SMB: {}", storage.smb_source)
            } else {
                format!("SMB: {}/{}", storage.smb_source, storage.smb_subpath.trim_matches('/'))
            }
        }
    }
}

/// Delete a backup object from S3. Mirrors `store_s3`'s key layout
/// (`wolfstack-backups/<filename>`) and its thread-with-own-runtime pattern:
/// `rust-s3` is async, so we drive it on a throwaway runtime inside a spawned
/// thread and join it, which works whether or not a tokio runtime is already
/// active on the caller.
fn delete_s3_object(storage: &BackupStorage, filename: &str) -> Result<(), String> {
    let bucket_name = storage.bucket.clone();
    let region_str = storage.region.clone();
    let endpoint_str = storage.endpoint.clone();
    let access_key = storage.access_key.clone();
    let secret_key = storage.secret_key.clone();
    // Same key the upload wrote (store_s3): wolfstack-backups/<filename>.
    let key = format!("wolfstack-backups/{}", filename);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| format!("S3 delete runtime: {}", e))?;
        rt.block_on(async {
            let aws_region = if region_str.trim().is_empty() {
                "us-east-1".to_string()
            } else {
                region_str.clone()
            };
            // A custom endpoint goes through the storage module's normaliser:
            // it supplies the scheme a bare hostname needs and strips a
            // trailing slash, which `Region::host()` would otherwise put in
            // the Host header and make every request a 400 (see
            // storage::endpoint_url). Real AWS keeps the derived host.
            let region = if endpoint_str.is_empty() {
                s3::Region::Custom {
                    region: aws_region.clone(),
                    endpoint: format!("https://s3.{}.amazonaws.com", aws_region),
                }
            } else {
                crate::storage::s3_custom_region(&endpoint_str, &aws_region)?
            };
            let credentials = s3::creds::Credentials::new(
                Some(&access_key), Some(&secret_key), None, None, None,
            ).map_err(|e| format!("S3 credentials error: {}", e))?;
            let bucket = s3::Bucket::new(&bucket_name, region, credentials)
                .map_err(|e| format!("S3 bucket error: {}", e))?;
            bucket.delete_object(&key).await
                .map_err(|e| format!("S3 delete error: {}", e))?;
            Ok::<(), String>(())
        })
    }).join().map_err(|_| "S3 delete thread panicked".to_string())?
}

/// Best-effort removal of a backup replicated to another WolfStack node by
/// `store_remote`. Calls the receiver's `DELETE /api/backups/import`, authed
/// with the cluster secret — the same inter-node model `store_remote`'s upload
/// uses. The remote copy is an independent, visible local backup on that node,
/// so failure to reach an older or offline peer is not fatal; the caller logs
/// and moves on.
fn delete_remote_backup(remote_url: &str, filename: &str) -> Result<(), String> {
    let url = format!("{}/api/backups/import?filename={}",
        remote_url.trim_end_matches('/'), urlencoding::encode(filename));
    let secret = crate::auth::load_cluster_secret();
    let auth_hdrs = crate::node_identity::curl_headers_padded(&secret, &url);

    let output = Command::new("curl")
        .args([
            // -S keeps curl's error text on stderr (see store_remote) so the
            // caller's warn! logs a real message on failure, not a blank.
            "-s", "-S", "-f",
            "--max-time", "60",
            "-X", "DELETE",
            "-H", &auth_hdrs[0], "-H", &auth_hdrs[1], "-H", &auth_hdrs[2],
            "-H", &auth_hdrs[3], "-H", &auth_hdrs[4], "-H", &auth_hdrs[5],
            &url,
        ])
        .output()
        .map_err(|e| format!("Failed to reach remote for delete: {}", e))?;

    if !output.status.success() {
        return Err(format!("Remote delete failed: {}",
            String::from_utf8_lossy(&output.stderr)));
    }
    Ok(())
}

/// Best-effort removal of a backup's stored artifact from wherever it lives.
/// Local/WolfDisk/NFS/SMB remove the file; S3 deletes the object; Remote calls
/// the peer node's delete endpoint. PBS is deliberately left to its own
/// GC/prune (see the `Pbs` arm) — matching `prune_schedule_backups`, the
/// retention path, which this function is now the single implementation for.
/// The match is exhaustive (no catch-all) so a new `StorageType` can't silently
/// re-introduce the orphaning bug. Shared by single-, bulk-, and retention
/// delete so the paths can't drift.
fn delete_backup_file(entry: &BackupEntry) {
    match entry.storage.storage_type {
        StorageType::Local | StorageType::Wolfdisk => {
            let path = Path::new(&entry.storage.resolved_local_path()).join(&entry.filename);
            if path.exists() {
                let _ = fs::remove_file(&path);
            }
        },
        StorageType::Nfs => {
            if let Ok(dir) = ensure_nfs_mounted(&entry.storage) {
                let path = Path::new(&dir).join(&entry.filename);
                if path.exists() { let _ = fs::remove_file(&path); }
            }
        },
        StorageType::Smb => {
            if let Ok(dir) = ensure_smb_mounted(&entry.storage) {
                let path = Path::new(&dir).join(&entry.filename);
                if path.exists() { let _ = fs::remove_file(&path); }
            }
        },
        StorageType::S3 => {
            if let Err(e) = delete_s3_object(&entry.storage, &entry.filename) {
                warn!("S3 backup object not deleted for {}: {}", entry.filename, e);
            }
        },
        StorageType::Remote => {
            if let Err(e) = delete_remote_backup(&entry.storage.remote_url, &entry.filename) {
                warn!("Remote backup copy not deleted for {} on {}: {}",
                    entry.filename, entry.storage.remote_url, e);
            }
        },
        // No per-ENTRY forget for PBS. A `BackupEntry` records the archive
        // filename but not the PBS snapshot timestamp the server assigned, so
        // there is no way to name the exact snapshot this entry produced —
        // forgetting "the oldest in the group" instead can delete a snapshot
        // another node wrote. Retention is applied at GROUP level in
        // `prune_pbs_groups_for_schedule`, which is safe because a group has a
        // single writer (see `config_archive_node_id`). An explicit one-off
        // delete therefore removes the index entry and leaves the snapshot to
        // the next retention pass.
        StorageType::Pbs => {},
    }
}

pub fn delete_backup(id: &str) -> Result<String, String> {
    let mut config = load_config();
    let idx = config.entries.iter().position(|e| e.id == id)
        .ok_or_else(|| format!("Backup not found: {}", id))?;

    let entry = config.entries.remove(idx);
    delete_backup_file(&entry);

    save_config(&config)?;
    Ok(format!("Backup {} deleted", id))
}

/// Delete every backup whose status is `Failed` — a one-click cleanup for the
/// dead-entry clutter that builds up from interrupted or erroring jobs. Only
/// `Failed` entries are touched: `Completed` and `InProgress` are left alone
/// (never wipe a finished backup or a running job's record). Files are removed
/// best-effort and the index is rewritten ONCE (not once per entry). Returns
/// the number removed.
pub fn delete_failed_backups() -> Result<usize, String> {
    let mut config = load_config();
    let mut removed = 0usize;
    let mut kept = Vec::with_capacity(config.entries.len());
    for entry in std::mem::take(&mut config.entries) {
        if entry.status == BackupStatus::Failed {
            delete_backup_file(&entry);
            removed += 1;
        } else {
            kept.push(entry);
        }
    }
    config.entries = kept;
    if removed > 0 {
        save_config(&config)?;
    }
    Ok(removed)
}

/// Restore from a backup by ID
pub fn restore_by_id(id: &str, overwrite: bool) -> Result<String, String> {
    let config = load_config();
    let entry = config.entries.iter().find(|e| e.id == id)
        .ok_or_else(|| format!("Backup not found: {}", id))?;
    restore_backup(entry, overwrite)
}

/// Restore from a backup by ID with streaming log output
// Each parameter is an independent restore knob (id, overwrite, target storage,
// rename target, config new-machine mode, progress sink) — not incidental state
// that a wrapper struct would meaningfully tidy; bundling them would add
// indirection without removing a real argument. Allowed deliberately.
#[allow(clippy::too_many_arguments)]
pub fn restore_by_id_with_log(id: &str, overwrite: bool, storage: &str, new_name: &str, new_machine: bool, log: std::sync::mpsc::Sender<String>) -> Result<String, String> {
    let config = load_config();
    let entry = config.entries.iter().find(|e| e.id == id)
        .ok_or_else(|| format!("Backup not found: {}", id))?;
    restore_entry_with_log(entry, overwrite, storage, new_name, new_machine, log)
}

/// Restore one backup entry — shared by id-based restore and the folder /
/// disaster-recovery restore (which builds an ephemeral entry, see
/// `restore_from_path`). Everything below operates purely on `entry`.
fn restore_entry_with_log(entry: &BackupEntry, overwrite: bool, storage: &str, new_name: &str, new_machine: bool, log: std::sync::mpsc::Sender<String>) -> Result<String, String> {
    let type_name = entry.target.target_type.to_string().to_uppercase();
    let display_name = entry.target.hostname.as_deref()
        .map(|h| format!("{} ({})", entry.target.name, h))
        .unwrap_or_else(|| entry.target.name.clone());

    let _ = log.send(format!("Starting {} restore: {}", type_name, display_name));

    // PBS file-level (pxar) snapshot — extract the tree directly. `new_name`
    // carries an optional target directory override (LXC rootfs / system
    // folder / docker staging are the per-type defaults when empty). Config
    // is the exception: its restore must APPLY the tree (same-/new-machine
    // rules), so it falls through to the Config arm below, whose
    // restore_config_backup is pxar-aware.
    if is_pbs_file_level_entry(entry) && entry.target.target_type != BackupTargetType::Config {
        let _ = log.send("Restoring PBS file-level snapshot...".to_string());
        let result = restore_pbs_file_level_entry(entry, new_name);
        match &result {
            Ok(msg) => { let _ = log.send(format!("✅ {}", msg)); }
            Err(e) => { let _ = log.send(format!("❌ {}", e)); }
        }
        return result;
    }

    // Check for container existence before downloading
    if entry.target.target_type == BackupTargetType::Docker {
        let check = Command::new("docker")
            .args(["container", "inspect", &entry.target.name])
            .output();
        let exists = check.map(|o| o.status.success()).unwrap_or(false);
        if exists && !overwrite {
            return Err(format!("CONTAINER_EXISTS:{}", entry.target.name));
        }
        // When overwrite is set, restore_docker stops and removes the
        // existing container itself — no need to duplicate that here.
    }

    match entry.target.target_type {
        BackupTargetType::Docker => {
            // The streaming path used to run `docker load` on the
            // v20.11+ wrapper tarball (image + volumes + binds), which
            // `docker load` rejects. Delegate to restore_docker, which
            // unpacks the wrapper and restores the mounts correctly.
            let _ = log.send("Restoring Docker container...".to_string());
            let result = restore_docker(entry, overwrite);
            match &result {
                Ok(msg) => { let _ = log.send(format!("✅ {}", msg)); }
                Err(e) => { let _ = log.send(format!("❌ {}", e)); }
            }
            result
        }
        BackupTargetType::Lxc => {
            let _ = log.send("Restoring LXC container...".to_string());
            let result = restore_lxc(entry, storage, overwrite, new_name);
            match &result {
                Ok(msg) => { let _ = log.send(format!("✅ {}", msg)); }
                Err(e) => { let _ = log.send(format!("❌ {}", e)); }
            }
            result
        }
        BackupTargetType::Vm => {
            let _ = log.send("Restoring VM...".to_string());
            let result = restore_vm(entry);
            match &result {
                Ok(msg) => { let _ = log.send(format!("✅ {}", msg)); }
                Err(e) => { let _ = log.send(format!("❌ {}", e)); }
            }
            result
        }
        BackupTargetType::Config => {
            let _ = log.send(if new_machine {
                "Restoring WolfStack configuration (new-machine mode: keeping this host's identity, TLS & networking)...".to_string()
            } else {
                "Restoring WolfStack configuration...".to_string()
            });
            let result = restore_config_backup(entry, new_machine);
            match &result {
                Ok(msg) => { let _ = log.send(format!("✅ {}", msg)); }
                Err(e) => { let _ = log.send(format!("❌ {}", e)); }
            }
            result
        }
        BackupTargetType::SystemPath => {
            // `new_name` carries an optional operator-chosen restore-target
            // directory, used verbatim. Empty = restore in place, where
            // restore_system_path inspects the archive to land a leaf-style
            // backup in its parent or a contents-only backup in the folder.
            let target_dir = new_name.trim().to_string();
            if target_dir.is_empty() {
                let _ = log.send("Restoring system folder in place...".to_string());
            } else {
                let _ = log.send(format!("Restoring system folder into {}...", target_dir));
            }
            let result = restore_system_path(entry, &target_dir);
            match &result {
                Ok(msg) => { let _ = log.send(format!("✅ {}", msg)); }
                Err(e) => { let _ = log.send(format!("❌ {}", e)); }
            }
            result
        }
    }
}

/// Restore a backup directly from a folder + filename, WITHOUT a backups.json
/// entry — for disaster recovery: restore onto a surviving node from a shared
/// mount when the original server (and its entry) is gone. Builds an ephemeral
/// entry and reuses the normal restore dispatch. The file must be reachable at
/// `source_path`/`filename` on THIS node; the frontend proxies the request to
/// the chosen target node so the workload is recreated there.
pub fn restore_from_path(
    source_path: &str,
    filename: &str,
    overwrite: bool,
    storage: &str,
    new_name: &str,
    log: std::sync::mpsc::Sender<String>,
) -> Result<String, String> {
    if filename.trim().is_empty() || filename.contains('/') || filename.contains("..") {
        return Err("Invalid backup filename (must be a bare file name)".into());
    }
    let target_type = guess_target_type(filename);
    // Config backups extract via `tar xzf -C /` (can touch any path); restoring
    // one from an ARBITRARY folder would be a write-anywhere vector. Folder /
    // disaster-recovery restore is for workloads (Docker/LXC/VM) only.
    if matches!(target_type, BackupTargetType::Config) {
        return Err("Config backups can't be restored from a folder — restore them from the Backups list.".into());
    }
    // System-folder backups don't carry their original target path in the
    // filename, and extracting them touches arbitrary host paths — same
    // write-anywhere concern as Config. Restore them from the Backups list.
    if matches!(target_type, BackupTargetType::SystemPath) {
        return Err("System-folder backups can't be restored from a folder — restore them from the Backups list.".into());
    }
    let size_bytes = fs::metadata(Path::new(source_path).join(filename))
        .map(|m| m.len()).unwrap_or(0);
    let entry = BackupEntry {
        id: Uuid::new_v4().to_string(),
        target: BackupTarget {
            target_type,
            name: extract_name_from_filename(filename),
            ..Default::default()
        },
        storage: BackupStorage::local(source_path),
        filename: filename.to_string(),
        size_bytes,
        created_at: Utc::now().to_rfc3339(),
        status: BackupStatus::Completed,
        error: String::new(),
        schedule_id: String::new(),
        comments: String::new(),
        node_hostname: local_hostname(),
        docker_config: String::new(),
        mounts: Vec::new(),
    };
    // Folder/DR restore is workloads-only (Config is rejected above), so the
    // new-machine config filter never applies here.
    restore_entry_with_log(&entry, overwrite, storage, new_name, false, log)
}

/// A backup file discovered by scanning a folder (no backups.json needed).
#[derive(Debug, Clone, Serialize)]
pub struct ScannedBackup {
    pub filename: String,
    pub target_type: String,
    pub name: String,
    pub size_bytes: u64,
    pub modified: String,
}

/// List WolfStack backup files (`{docker,lxc,vm,config}-*.tar.gz`) in a folder,
/// identifying each from its filename alone — powers "restore from a folder".
pub fn scan_backup_folder(path: &str) -> Result<Vec<ScannedBackup>, String> {
    let dir = Path::new(path);
    if !dir.is_dir() {
        return Err(format!("Not a folder: {}", path));
    }
    let rd = fs::read_dir(dir).map_err(|e| format!("Cannot read folder: {}", e))?;
    let mut out = Vec::new();
    for ent in rd.flatten() {
        let p = ent.path();
        if !p.is_file() { continue; }
        let fname = match p.file_name().and_then(|n| n.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        // Workload backups only — config backups are intentionally excluded:
        // they can't be restored from a folder (see restore_from_path).
        let is_backup = fname.ends_with(".tar.gz")
            && (fname.starts_with("docker-") || fname.starts_with("lxc-")
                || fname.starts_with("vm-"));
        if !is_backup { continue; }
        let meta = ent.metadata().ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified = meta.as_ref()
            .and_then(|m| m.modified().ok())
            .map(|t| chrono::DateTime::<Utc>::from(t).to_rfc3339())
            .unwrap_or_default();
        let type_str = match guess_target_type(&fname) {
            BackupTargetType::Docker => "docker",
            BackupTargetType::Lxc => "lxc",
            BackupTargetType::Vm => "vm",
            BackupTargetType::Config => "config",
            // SystemPath files are filtered out above by `is_backup`, but the
            // match must stay exhaustive.
            BackupTargetType::SystemPath => "systempath",
        }.to_string();
        let name = extract_name_from_filename(&fname);
        out.push(ScannedBackup { filename: fname, target_type: type_str, name, size_bytes: size, modified });
    }
    out.sort_by(|a, b| b.modified.cmp(&a.modified));
    Ok(out)
}

// ─── Schedule Management ───

/// List all schedules
pub fn list_schedules() -> Vec<BackupSchedule> {
    load_config().schedules
}

/// Create or update a schedule
pub fn save_schedule(schedule: BackupSchedule) -> Result<BackupSchedule, String> {
    let mut config = load_config();

    // Update existing or insert new
    if let Some(existing) = config.schedules.iter_mut().find(|s| s.id == schedule.id) {
        *existing = schedule.clone();
    } else {
        config.schedules.push(schedule.clone());
    }

    save_config(&config)?;
    Ok(schedule)
}

/// Delete a schedule
pub fn delete_schedule(id: &str) -> Result<String, String> {
    let mut config = load_config();
    let len_before = config.schedules.len();
    config.schedules.retain(|s| s.id != id);

    if config.schedules.len() == len_before {
        return Err(format!("Schedule not found: {}", id));
    }

    save_config(&config)?;
    Ok(format!("Schedule {} deleted", id))
}

/// Enable or disable a schedule without rewriting the whole thing (Gary 2026-06-25).
pub fn set_schedule_enabled(id: &str, enabled: bool) -> Result<String, String> {
    let mut config = load_config();
    let s = config.schedules.iter_mut().find(|s| s.id == id)
        .ok_or_else(|| format!("Schedule not found: {}", id))?;
    s.enabled = enabled;
    let name = s.name.clone();
    save_config(&config)?;
    Ok(format!("Schedule '{}' {}", name, if enabled { "enabled" } else { "disabled" }))
}

/// Identity that a retention policy counts against: one target = one series.
/// Two backups of the same container are the same series; a container and a VM
/// that happen to share a name are not.
fn retention_target_key(e: &BackupEntry) -> String {
    format!("{:?}\u{1}{}", e.target.target_type, e.target.name)
}

/// Prune a schedule's completed backups down to `retention` **per target**,
/// deleting the oldest files + entries first. Shared by the nightly scheduler
/// and the on-demand "Run Now" so both prune identically.
///
/// Retention is PER TARGET, not per schedule. It used to keep `retention`
/// entries for the schedule as a whole, so a schedule covering 11 containers
/// with `retention: 7` kept 7 records TOTAL and could not hold even one
/// complete night. Observed on a live fleet 2026-08-25: the surviving set was
/// 3 containers from one night plus 4 from the night before, and the other
/// containers' archives had already been deleted. "Keep 7" means seven backups
/// of each thing — which is what the UI offers.
fn prune_schedule_backups(config: &mut BackupConfig, schedule_id: &str, retention: usize) {
    use std::collections::HashMap;

    let mut by_target: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, e) in config.entries.iter().enumerate() {
        if e.schedule_id == schedule_id && e.status == BackupStatus::Completed {
            by_target.entry(retention_target_key(e)).or_default().push(i);
        }
    }

    let mut to_remove: Vec<usize> = Vec::new();
    for idxs in by_target.values_mut() {
        // Newest first; anything past `retention` is removed.
        idxs.sort_by(|a, b| config.entries[*b].created_at.cmp(&config.entries[*a].created_at));
        if idxs.len() > retention {
            to_remove.extend_from_slice(&idxs[retention..]);
        }
    }

    if !to_remove.is_empty() {
        // Remove strictly highest-index-first: `Vec::remove` shifts every
        // later element down, so any other order leaves stale indices that
        // panic (observed 2026-07-05: "len is 9 but the index is 9") or —
        // worse — silently delete the WRONG backup's file. Collected across
        // per-target buckets, so this is NOT index order and must be sorted.
        to_remove.sort_unstable_by(|a, b| b.cmp(a));
        to_remove.dedup();
        for &idx in &to_remove {
            // Single source of truth for removing a backup's stored artifact
            // (local file / S3 object / remote copy). PBS is handled
            // separately, per group, immediately below.
            delete_backup_file(&config.entries[idx]);
            config.entries.remove(idx);
        }
    }

    // The index prune above does not touch PBS (see `delete_backup_file`'s Pbs
    // arm — a per-entry forget cannot be done safely). Without this call the
    // operator's `retention` silently means "keep forever" on a PBS datastore.
    prune_pbs_groups_for_schedule(config, schedule_id, retention);
}

/// Apply `retention` to the PBS datastore itself for every group this schedule
/// writes to.
///
/// WolfStack used to leave this entirely to "PBS's own prune + GC schedule".
/// That assumption holds for a self-managed PBS where the operator configured a
/// prune job, and fails completely on a hosted datastore that has none: a fleet
/// running `retention: 7` was found on 2026-08-25 holding 15-19 snapshots per
/// group across 18 days, having filled a 2 TB datastore to 100% and failed
/// every backup for the previous 8 days.
///
/// Derived from the entries that SURVIVED the index prune, so a group is only
/// touched while this schedule still owns backups in it.
///
/// NOTE: `prune` unlinks snapshot indexes; PBS only returns the underlying
/// chunks to free space when garbage collection runs. GC is a datastore-admin
/// operation and is frequently NOT granted to a backup token on hosted PBS
/// (`permission check failed`), so WolfStack deliberately does not attempt it —
/// on such a datastore GC remains the provider's scheduled job.
fn prune_pbs_groups_for_schedule(config: &BackupConfig, schedule_id: &str, retention: usize) {
    if retention == 0 {
        return;
    }
    // Distinct (repository, group) pairs this schedule writes to.
    let mut groups: Vec<(String, String, BackupStorage)> = Vec::new();
    for e in config.entries.iter() {
        if e.schedule_id != schedule_id
            || e.storage.storage_type != StorageType::Pbs
            || e.status != BackupStatus::Completed
        {
            continue;
        }
        let group = pbs_group_for_filename(&e.filename);
        let repo = pbs_repo_string(&e.storage);
        if groups.iter().any(|(r, g, _)| r == &repo && g == &group) {
            continue;
        }
        groups.push((repo, group, e.storage.clone()));
    }

    for (repo, group, storage) in groups {
        let keep = pbs_group_keep_count(config, &repo, &group, retention);
        if let Err(err) = pbs_prune_group(&storage, &group, keep) {
            warn!("PBS retention prune failed for group {}: {}", group, err);
        }
    }
}

/// How many snapshots to keep in one PBS group.
///
/// Two schedules on the SAME node can legitimately write the same group — two
/// schedules that both include the `config` target is the ordinary case, and
/// was present on a live node (schedules `8b4106ae…` and `7163fba1…`). Pruning
/// such a group to just the retention of whichever schedule happens to run
/// would let the stricter one silently delete snapshots the looser one is still
/// keeping. Take the LARGEST retention asked for by any schedule that owns
/// backups in the group.
///
/// This keeps more than a single schedule asked for rather than less: with a
/// 7-day and a 30-day schedule sharing a group, the group holds 30 snapshots
/// covering both. Erring long is recoverable (disk); erring short destroys
/// backups. Giving each schedule its own group — or its own PBS namespace —
/// is the only way to honour both numbers exactly.
fn pbs_group_keep_count(
    config: &BackupConfig,
    repo: &str,
    group: &str,
    own_retention: usize,
) -> usize {
    config.entries.iter()
        .filter(|e| {
            e.storage.storage_type == StorageType::Pbs
                && e.status == BackupStatus::Completed
                && pbs_group_for_filename(&e.filename) == group
                && pbs_repo_string(&e.storage) == repo
        })
        // An entry whose schedule has since been deleted contributes nothing.
        .filter_map(|e| config.schedules.iter().find(|s| s.id == e.schedule_id))
        .map(|s| s.retention as usize)
        .chain(std::iter::once(own_retention))
        .max()
        .unwrap_or(own_retention)
}

/// Prune one PBS group down to the `keep` most recent snapshots.
fn pbs_prune_group(storage: &BackupStorage, group: &str, keep: usize) -> Result<(), String> {
    let repo = pbs_repo_string(storage);
    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("prune")
       .arg(group)
       .arg("--keep-last").arg(keep.to_string())
       .arg("--repository").arg(&repo);

    if !storage.pbs_fingerprint.is_empty() {
        cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
    }
    if !storage.pbs_namespace.is_empty() {
        cmd.arg("--ns").arg(&storage.pbs_namespace);
    }
    let pbs_pw = if !storage.pbs_token_secret.is_empty() { &storage.pbs_token_secret }
                 else { &storage.pbs_password };
    if !pbs_pw.is_empty() {
        cmd.env("PBS_PASSWORD", pbs_pw);
    }

    let out = cmd.output()
        .map_err(|e| format!("Failed to run proxmox-backup-client prune: {}", e))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(())
}

#[cfg(test)]
mod prune_tests {
    use super::*;

    fn mk(filename: &str, created_at: &str, schedule_id: &str) -> BackupEntry {
        mk_for(filename, filename, created_at, schedule_id)
    }

    /// Like `mk`, but pins the TARGET name independently of the entry id so a
    /// test can build several backups of the SAME target (one retention series)
    /// or of different targets (separate series).
    fn mk_for(target: &str, id: &str, created_at: &str, schedule_id: &str) -> BackupEntry {
        BackupEntry {
            id: id.to_string(),
            target: BackupTarget { target_type: BackupTargetType::Lxc, name: target.into(), ..Default::default() },
            storage: BackupStorage::default(),
            filename: format!("{}.tar.gz", id),
            size_bytes: 0,
            created_at: created_at.to_string(),
            status: BackupStatus::Completed,
            error: String::new(),
            schedule_id: schedule_id.to_string(),
            comments: String::new(),
            node_hostname: String::new(),
            docker_config: String::new(),
            mounts: Vec::new(),
        }
    }

    /// 2026-07-05 regression: entries interleave, so timestamp order ≠ index
    /// order. The old prune removed by stale indices after each shift —
    /// panicking ("len is 9 but the index is 9") or deleting the WRONG entry.
    /// All five belong to ONE target so they form a single retention series;
    /// keep = the `retention` newest.
    #[test]
    fn prune_survives_interleaved_entry_order() {
        let mut config = BackupConfig {
            entries: vec![
                mk_for("ct1", "a-old",    "2026-07-01T03:00:00Z", "s"),
                mk_for("ct9", "other",    "2026-07-10T03:00:00Z", "different-schedule"),
                mk_for("ct1", "b-new",    "2026-07-05T03:00:00Z", "s"),
                mk_for("ct1", "c-mid",    "2026-07-03T03:00:00Z", "s"),
                mk_for("ct1", "d-newest", "2026-07-06T03:00:00Z", "s"),
                mk_for("ct1", "e-oldest", "2026-06-30T03:00:00Z", "s"),
            ],
            ..Default::default()
        };
        prune_schedule_backups(&mut config, "s", 2);
        let names: Vec<&str> = config.entries.iter().map(|e| e.id.as_str()).collect();
        // Newest two of schedule "s" survive; the other schedule is untouched.
        assert!(names.contains(&"d-newest"), "newest kept: {:?}", names);
        assert!(names.contains(&"b-new"), "second-newest kept: {:?}", names);
        assert!(names.contains(&"other"), "other schedule untouched: {:?}", names);
        assert_eq!(names.len(), 3, "exactly retention + unrelated remain: {:?}", names);
    }

    /// Retention is PER TARGET. A schedule covering many containers with
    /// `retention: 2` keeps two of EACH — not two across the whole schedule.
    /// The old per-schedule behaviour deleted most of a night's backups the
    /// moment the run finished (live fleet, 2026-08-25: 11 targets, retention
    /// 7, index held 3 containers from one night and 4 from the night before).
    #[test]
    fn retention_is_per_target_not_per_schedule() {
        let mut config = BackupConfig { entries: vec![
            mk_for("web1", "web1-d1", "2026-08-01T03:00:00Z", "s"),
            mk_for("web1", "web1-d2", "2026-08-02T03:00:00Z", "s"),
            mk_for("web1", "web1-d3", "2026-08-03T03:00:00Z", "s"),
            mk_for("db1",  "db1-d1",  "2026-08-01T03:00:00Z", "s"),
            mk_for("db1",  "db1-d2",  "2026-08-02T03:00:00Z", "s"),
            mk_for("db1",  "db1-d3",  "2026-08-03T03:00:00Z", "s"),
        ], ..Default::default() };
        prune_schedule_backups(&mut config, "s", 2);
        let names: Vec<&str> = config.entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(names.len(), 4, "two per target, not two overall: {:?}", names);
        for kept in ["web1-d3", "web1-d2", "db1-d3", "db1-d2"] {
            assert!(names.contains(&kept), "{} kept: {:?}", kept, names);
        }
        for gone in ["web1-d1", "db1-d1"] {
            assert!(!names.contains(&gone), "{} pruned: {:?}", gone, names);
        }
    }

    /// Two schedules sharing one PBS group (both backing up `config`, seen
    /// live on wolfstack-1) must not let the stricter one delete what the
    /// looser one still keeps. The group keeps the LARGEST retention asked.
    #[test]
    fn shared_pbs_group_keeps_the_largest_retention() {
        let pbs = BackupStorage {
            storage_type: StorageType::Pbs,
            pbs_server: "pbs.example".into(),
            pbs_datastore: "ds".into(),
            pbs_user: "u@pbs".into(),
            ..Default::default()
        };
        let mk_pbs = |sched: &str, when: &str| {
            let mut e = mk_for("", "config-wolfstack-1-20260825-020530", when, sched);
            e.filename = "config-wolfstack-1-20260825-020530.tar.gz".into();
            e.storage = pbs.clone();
            e
        };
        let mut config = BackupConfig {
            entries: vec![
                mk_pbs("short", "2026-08-25T03:00:00Z"),
                mk_pbs("long",  "2026-08-25T04:00:00Z"),
            ],
            ..Default::default()
        };
        let sched = |id: &str, retention: u32| -> BackupSchedule {
            serde_json::from_str(&format!(
                r#"{{"id":"{}","name":"{}","frequency":"daily","time":"02:00",
                    "retention":{},"backup_all":false,
                    "storage":{{"type":"local"}},"enabled":true}}"#,
                id, id, retention,
            )).unwrap()
        };
        config.schedules = vec![sched("short", 7), sched("long", 30)];
        let repo = pbs_repo_string(&pbs);
        let group = pbs_group_for_filename("config-wolfstack-1-20260825-020530.tar.gz");
        assert_eq!(group, "host/wolfstack-1");
        // Whichever schedule triggers the prune, the group keeps 30.
        assert_eq!(pbs_group_keep_count(&config, &repo, &group, 7), 30);
        assert_eq!(pbs_group_keep_count(&config, &repo, &group, 30), 30);
        // An unrelated group is unaffected and falls back to the caller's own.
        assert_eq!(pbs_group_keep_count(&config, &repo, "ct/other", 7), 7);
    }

    /// A target whose name repeats under a DIFFERENT type is a different
    /// series — a container "159" and a VM "159" must not prune each other.
    #[test]
    fn retention_key_separates_types_with_the_same_name() {
        let mut ct = mk_for("159", "ct-159", "2026-08-01T03:00:00Z", "s");
        ct.target.target_type = BackupTargetType::Lxc;
        let mut vm = mk_for("159", "vm-159", "2026-08-01T03:00:00Z", "s");
        vm.target.target_type = BackupTargetType::Vm;
        assert_ne!(retention_target_key(&ct), retention_target_key(&vm));
    }

    /// Retention edge: nothing to prune when at/below the cap, including 0
    /// completed entries — must not panic on the empty slice path.
    #[test]
    fn prune_noop_at_or_below_retention() {
        let mut config = BackupConfig {
            entries: vec![
                mk("a", "2026-07-01T03:00:00Z", "s"),
                mk("b", "2026-07-02T03:00:00Z", "s"),
            ],
            ..Default::default()
        };
        prune_schedule_backups(&mut config, "s", 2);
        assert_eq!(config.entries.len(), 2);
        prune_schedule_backups(&mut config, "missing-schedule", 0);
        assert_eq!(config.entries.len(), 2);
    }
}

/// Run a scheduled backup on demand (Gary 2026-06-25 "Run Now"), ignoring the
/// time-of-day / already-ran-this-period gate. Same path as the nightly
/// scheduler: runs the schedule's targets (or all), tags the new entries with the
/// schedule id, stamps last_run, and prunes by retention. Runs synchronously —
/// the API handler wraps it in web::block.
/// Outcome of one schedule run, for callers that need more than a message
/// string — WolfFlow's "Run Backup Schedule" step exposes these counts as
/// step outputs so flows can branch on them.
pub struct ScheduleRunSummary {
    pub name: String,
    /// Entries produced this run, including synthetic hook-failure entries.
    pub total: usize,
    pub completed: usize,
    pub failed: usize,
    pub message: String,
}

/// Hard cap on pre/post hook commands so a hung script can't wedge the
/// scheduler thread forever. Generous because "dump the database first" is a
/// legitimate hook; `timeout` SIGTERMs at the cap and SIGKILLs 30s later.
const HOOK_TIMEOUT_SECS: u64 = 3600;

/// Run a schedule's pre or post command via `bash -c` under coreutils
/// `timeout` (same pattern as containers/proxy_runtime). The command sees
/// WOLFSTACK_SCHEDULE / WOLFSTACK_HOOK_PHASE / WOLFSTACK_BACKUP_STATUS so one
/// script can serve both phases. Returns combined output on success, and an
/// exit-code + output-tail description on failure (124 = timed out).
fn run_hook_command(phase: &str, command: &str, schedule_name: &str, backup_status: &str) -> Result<String, String> {
    let timeout_arg = HOOK_TIMEOUT_SECS.to_string();
    let output = Command::new("timeout")
        .args(["--kill-after=30", &timeout_arg, "bash", "-c", command])
        .env("WOLFSTACK_SCHEDULE", schedule_name)
        .env("WOLFSTACK_HOOK_PHASE", phase)
        .env("WOLFSTACK_BACKUP_STATUS", backup_status)
        .output()
        .map_err(|e| format!("failed to launch {}-command: {}", phase, e))?;
    let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        if !combined.is_empty() { combined.push('\n'); }
        combined.push_str(&stderr);
    }
    // Keep only a tail — hook output lands inside BackupEntry.error / logs and
    // a chatty script must not bloat backup.json. The cut point must land on a
    // char boundary: hook output is user-controlled UTF-8 and a mid-codepoint
    // slice would panic the scheduler thread.
    let tail = |s: &str| {
        let t = s.trim();
        if t.len() > 2000 {
            let mut start = t.len() - 2000;
            while !t.is_char_boundary(start) { start += 1; }
            format!("…{}", &t[start..])
        } else {
            t.to_string()
        }
    };
    if output.status.success() {
        Ok(tail(&combined))
    } else {
        let code = output.status.code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "killed by signal".to_string());
        let timed_out = output.status.code() == Some(124);
        Err(format!(
            "{}-command failed (exit {}{}): {}",
            phase, code,
            if timed_out { format!(", timed out after {}s", HOOK_TIMEOUT_SECS) } else { String::new() },
            tail(&combined)
        ))
    }
}

/// Synthetic Failed entry that surfaces a hook failure in the Backups list —
/// hooks have no tarball, but the operator manages backups there and must see
/// "the pre-command aborted last night's run" without reading server logs.
fn hook_failure_entry(schedule: &BackupSchedule, phase: &str, err: &str) -> BackupEntry {
    BackupEntry {
        id: Uuid::new_v4().to_string(),
        target: BackupTarget {
            name: format!("{} ({}-command)", schedule.name, phase),
            ..Default::default() // Config target type; no container/VM behind a hook
        },
        storage: schedule.storage.clone(),
        filename: String::new(),
        size_bytes: 0,
        created_at: Utc::now().to_rfc3339(),
        status: BackupStatus::Failed,
        error: err.to_string(),
        schedule_id: schedule.id.clone(),
        comments: format!("{}-command hook", phase),
        node_hostname: local_hostname(),
        docker_config: String::new(),
        mounts: Vec::new(),
    }
}

/// Run one schedule end-to-end: pre-command → backups → post-command.
/// Shared by the nightly scheduler (`check_schedules`) and the on-demand path
/// (`run_schedule_now_summary`) so hook semantics can never drift between
/// them. Returned entries are already tagged with the schedule id and include
/// synthetic entries for hook failures.
fn execute_schedule_run(schedule: &BackupSchedule) -> (Vec<BackupEntry>, ScheduleRunSummary) {
    let mut entries: Vec<BackupEntry> = Vec::new();
    let mut pre_ok = true;

    if !schedule.pre_command.trim().is_empty() {
        match run_hook_command("pre", &schedule.pre_command, &schedule.name, "") {
            Ok(out) => info!("Schedule '{}' pre-command ok: {}", schedule.name, out),
            Err(e) => {
                error!("Schedule '{}': {} — backup run aborted", schedule.name, e);
                entries.push(hook_failure_entry(schedule, "pre", &e));
                pre_ok = false;
            }
        }
    }

    let mut backups_made = 0usize;
    if pre_ok {
        // Scheduler form may have saved storage as `{type:"pbs"}` only; fill in
        // saved server/credentials (same as both pre-existing call sites did).
        let mut storage = schedule.storage.clone();
        merge_pbs_secrets(&mut storage);
        let backups: Vec<BackupEntry> = if schedule.backup_all {
            backup_all(&storage, schedule.stop_containers, &schedule.targets)
        } else {
            schedule.targets.iter()
                .map(|t| create_backup_entry(t.clone(), &storage))
                .collect()
        };
        backups_made = backups.len();
        entries.extend(backups);
    }

    let backups_failed = entries.iter().filter(|e| e.status == BackupStatus::Failed).count();
    if !schedule.post_command.trim().is_empty() {
        let status_env = if !pre_ok {
            "aborted"
        } else if backups_failed > 0 {
            "failed"
        } else {
            "completed"
        };
        match run_hook_command("post", &schedule.post_command, &schedule.name, status_env) {
            Ok(out) => info!("Schedule '{}' post-command ok: {}", schedule.name, out),
            Err(e) => {
                error!("Schedule '{}': {}", schedule.name, e);
                entries.push(hook_failure_entry(schedule, "post", &e));
            }
        }
    }

    for entry in entries.iter_mut() {
        entry.schedule_id = schedule.id.clone();
    }
    let total = entries.len();
    let completed = entries.iter().filter(|e| e.status == BackupStatus::Completed).count();
    let failed = total - completed;
    // Message counts BACKUPS, not entries — a post-hook failure adds a synthetic
    // entry but must not inflate "N backup(s) created" (and matches the exact
    // pre-hooks wording for schedules that don't use hooks).
    let message = if !pre_ok {
        format!("Schedule '{}' aborted by pre-command — no backups taken", schedule.name)
    } else {
        format!("Ran scheduled backup '{}' — {} backup(s) created", schedule.name, backups_made)
    };
    let summary = ScheduleRunSummary { name: schedule.name.clone(), total, completed, failed, message };
    (entries, summary)
}

/// On-demand schedule run returning the full summary (WolfFlow step).
pub fn run_schedule_now_summary(id: &str) -> Result<ScheduleRunSummary, String> {
    let mut config = load_config();
    let idx = config.schedules.iter().position(|s| s.id == id)
        .ok_or_else(|| format!("Schedule not found: {}", id))?;

    let schedule = config.schedules[idx].clone();
    let (new_entries, summary) = execute_schedule_run(&schedule);
    // Only count the run as "ran" (which gates the nightly auto-run) if at least
    // one backup actually completed — a fully-failed on-demand run must not
    // suppress tonight's scheduled run.
    let any_ok = new_entries.iter().any(|e| e.status == BackupStatus::Completed);
    config.entries.extend(new_entries);
    if any_ok {
        config.schedules[idx].last_run = Utc::now().to_rfc3339();
    }
    if schedule.retention > 0 {
        prune_schedule_backups(&mut config, &schedule.id, schedule.retention as usize);
    }
    save_config(&config)?;
    Ok(summary)
}

/// On-demand schedule run — message-string façade kept for the existing
/// `POST /api/backups/schedules/{id}/run` handler (behaviour unchanged).
pub fn run_schedule_now(id: &str) -> Result<String, String> {
    run_schedule_now_summary(id).map(|s| s.message)
}

// ─── Available Targets ───

/// List all available backup targets on the system with full details
pub fn list_available_targets() -> Vec<BackupTarget> {
    let mut targets = Vec::new();

    // Docker containers — include image, state, and (for compose-managed
    // containers) the compose project so the UI can group them into stacks.
    if let Ok(output) = Command::new("docker")
        .args(["ps", "-a", "--format",
            "{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Label \"com.docker.compose.project\"}}"])
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            let name = parts.first().unwrap_or(&"").to_string();
            if name.is_empty() { continue; }
            let image = parts.get(1).unwrap_or(&"").to_string();
            let state = parts.get(2).map(|s| s.to_string());
            let compose_project = parts.get(3)
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            targets.push(BackupTarget {
                target_type: BackupTargetType::Docker,
                name,
                hostname: None,
                state,
                specs: if image.is_empty() { None } else { Some(image) },
                compose_project,
                ..Default::default()
            });
        }
    }

    // LXC containers — detect Proxmox (pct) vs native LXC and gather full details
    let is_proxmox = Command::new("which").arg("pct").output()
        .map(|o| o.status.success()).unwrap_or(false);

    if is_proxmox {
        // Proxmox: use pct list + pct config for hostname, cores, memory
        if let Ok(output) = Command::new("pct").arg("list").output()
            && output.status.success() {
                let listing = String::from_utf8_lossy(&output.stdout);
                let entries: Vec<(String, String, String)> = listing.lines()
                    .skip(1)
                    .filter(|l| !l.trim().is_empty())
                    .filter_map(|line| {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        let vmid = parts.first()?.to_string();
                        let state = parts.get(1).unwrap_or(&"stopped").to_lowercase();
                        // Name may have a "Lock" column before it on locked containers
                        let pct_name = parts.last().map(|s| s.to_string()).unwrap_or_default();
                        Some((vmid, state, pct_name))
                    })
                    .collect();

                // Fetch configs in parallel
                let configs: Vec<String> = std::thread::scope(|s| {
                    let handles: Vec<_> = entries.iter().map(|(vmid, _, _)| {
                        let vmid = vmid.clone();
                        s.spawn(move || {
                            Command::new("pct").args(["config", &vmid]).output().ok()
                                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                                .unwrap_or_default()
                        })
                    }).collect();
                    handles.into_iter().map(|h| h.join().unwrap_or_default()).collect()
                });

                for ((vmid, state, pct_name), cfg) in entries.iter().zip(configs.iter()) {
                    let mut hostname = if pct_name.is_empty() { None } else { Some(pct_name.clone()) };
                    let mut memory_mb: u64 = 0;
                    let mut cores: u64 = 0;
                    let mut os_type = String::new();

                    for cline in cfg.lines() {
                        let cline = cline.trim();
                        if cline.starts_with("hostname:") {
                            hostname = cline.split(':').nth(1).map(|s| s.trim().to_string());
                        } else if cline.starts_with("memory:") {
                            memory_mb = cline.split(':').nth(1)
                                .and_then(|s| s.trim().parse().ok()).unwrap_or(0);
                        } else if cline.starts_with("cores:") {
                            cores = cline.split(':').nth(1)
                                .and_then(|s| s.trim().parse().ok()).unwrap_or(0);
                        } else if cline.starts_with("ostype:") {
                            os_type = cline.split(':').nth(1).unwrap_or("").trim().to_string();
                        }
                    }

                    let mut spec_parts = Vec::new();
                    if cores > 0 { spec_parts.push(format!("{} core{}", cores, if cores > 1 { "s" } else { "" })); }
                    if memory_mb > 0 {
                        if memory_mb >= 1024 { spec_parts.push(format!("{}GB RAM", memory_mb / 1024)); }
                        else { spec_parts.push(format!("{}MB RAM", memory_mb)); }
                    }
                    if !os_type.is_empty() { spec_parts.push(os_type); }

                    targets.push(BackupTarget {
                        target_type: BackupTargetType::Lxc,
                        name: vmid.clone(),
                        hostname,
                        state: Some(state.clone()),
                        specs: if spec_parts.is_empty() { None } else { Some(spec_parts.join(", ")) },
                        ..Default::default()
                    });
                }
            }
    } else {
        // Native LXC. Enumerated through `containers::lxc_list_all()` rather
        // than a bare `lxc-ls -f`, which only sees the default lxcpath and so
        // never offered containers living on any other registered storage
        // path. `backup_all` reads the same source, so what a scheduled "back
        // up everything" run actually archives and what this picker offers
        // cannot drift apart.
        for container in crate::containers::lxc_list_all() {
            if container.name.is_empty() { continue; }
            let hostname = if container.hostname.is_empty() {
                lxc_config_hostname(&container.name)
            } else {
                Some(container.hostname.clone())
            };
            targets.push(BackupTarget {
                target_type: BackupTargetType::Lxc,
                name: container.name.clone(),
                hostname,
                state: Some(container.state.to_lowercase()),
                specs: None,
                ..Default::default()
            });
        }
    }

    // VMs — enumerated via VmManager so Proxmox (`qm list`) and libvirt
    // (`virsh list --all`) hosts surface their VMs in the backup picker
    // too. Before v24.6.0 this scanned only `/var/lib/wolfstack/vms/*.json`
    // (the native-KVM layout), so Proxmox/libvirt operators saw zero VMs
    // in the Backups page even though backup_vm_proxmox / backup_vm_libvirt
    // are perfectly capable of backing them up.
    let vm_manager = crate::vms::manager::VmManager::new();
    for vm in vm_manager.list_vms() {
        let mut spec_parts: Vec<String> = Vec::new();
        if vm.cpus > 0 { spec_parts.push(format!("{} vCPU", vm.cpus)); }
        if vm.memory_mb > 0 {
            if vm.memory_mb >= 1024 {
                spec_parts.push(format!("{} GB RAM", vm.memory_mb / 1024));
            } else {
                spec_parts.push(format!("{} MB RAM", vm.memory_mb));
            }
        }
        let specs = if spec_parts.is_empty() { None } else { Some(spec_parts.join(", ")) };
        let state = Some(if vm.running { "running".to_string() } else { "stopped".to_string() });
        targets.push(BackupTarget {
            target_type: BackupTargetType::Vm,
            name: vm.name,
            hostname: None,
            state,
            specs,
            ..Default::default()
        });
    }

    // Config is always available
    targets.push(BackupTarget {
        target_type: BackupTargetType::Config,
        name: String::new(),
        ..Default::default()
    });

    targets
}

/// Read hostname from native LXC config file
fn lxc_config_hostname(name: &str) -> Option<String> {
    for base in &["/var/lib/lxc", "/var/snap/lxd/common/lxd/storage-pools"] {
        let config_path = format!("{}/{}/config", base, name);
        if let Ok(content) = fs::read_to_string(&config_path)
            && let Some(line) = content.lines().find(|l| l.trim().starts_with("lxc.uts.name")) {
                return line.split('=').nth(1).map(|s| s.trim().to_string());
            }
    }
    None
}

// ─── Scheduling ───

/// Days in `month` of `year` — used to clamp a monthly schedule pinned to a day
/// the month doesn't have (the 31st in February).
fn days_in_month(year: i32, month: u32) -> u32 {
    let (next_year, next_month) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };
    chrono::NaiveDate::from_ymd_opt(next_year, next_month, 1)
        .and_then(|first_of_next| first_of_next.pred_opt())
        .map(|last| last.day())
        .unwrap_or(28)
}

/// The day a monthly schedule pinned to `day_of_month` actually runs in the
/// month containing `now`: the chosen day, or the month's last day when the
/// month is too short for it. Never skips a month.
fn effective_day_of_month(day_of_month: u8, now: chrono::DateTime<Utc>) -> u32 {
    let wanted = day_of_month.clamp(1, 31) as u32;
    wanted.min(days_in_month(now.year(), now.month()))
}

/// Whether `schedule` should fire at `now`.
///
/// Split out of `check_schedules` so the day-pinning rules are unit-testable
/// without touching config on disk, docker, or tar.
///
/// Three gates, in order: the schedule is enabled, the time-of-day matches to
/// the minute (the caller ticks once a minute), and the calendar day is one this
/// schedule runs on. Then the already-ran-this-period guard stops a second run
/// within the same day/week/month.
fn schedule_is_due(schedule: &BackupSchedule, now: chrono::DateTime<Utc>) -> bool {
    if !schedule.enabled {
        return false;
    }
    if now.format("%H:%M").to_string() != schedule.time {
        return false;
    }

    // Day pinning. `None` (every pre-existing schedule) means "no pinned day",
    // which leaves the interval guard below as the only constraint — exactly the
    // behaviour before these fields existed.
    let day_pinned = match schedule.frequency {
        BackupFrequency::Daily => false,
        BackupFrequency::Weekly => match schedule.day_of_week {
            Some(dow) => {
                if now.weekday().number_from_monday() as u8 != dow.clamp(1, 7) {
                    return false;
                }
                true
            }
            None => false,
        },
        BackupFrequency::Monthly => match schedule.day_of_month {
            Some(dom) => {
                if now.day() != effective_day_of_month(dom, now) {
                    return false;
                }
                true
            }
            None => false,
        },
    };

    // Never ran → due now.
    let last_utc = match chrono::DateTime::parse_from_rfc3339(&schedule.last_run) {
        Ok(last) => last.with_timezone(&Utc),
        Err(_) => return true, // empty or unparseable last_run
    };

    // With a pinned day the day itself is the period marker, so "already ran
    // today" is the whole guard — a rolling 7-day window would push a Monday
    // schedule to Tuesday whenever a run started a minute late.
    if day_pinned {
        return last_utc.date_naive() != now.date_naive();
    }

    match schedule.frequency {
        BackupFrequency::Daily => last_utc.date_naive() != now.date_naive(),
        BackupFrequency::Weekly => (now - last_utc).num_days() >= 7,
        BackupFrequency::Monthly => {
            last_utc.month() != now.month() || last_utc.year() != now.year()
        }
    }
}

/// Check all schedules and run any that are due
/// Called from background task loop in main.rs
pub fn check_schedules() {
    let mut config = load_config();
    let now = Utc::now();
    let mut changed = false;
    // (schedule_id, retention) for schedules that ran this pass — pruned AFTER the
    // loop, since prune_schedule_backups needs &mut config and we can't borrow that
    // while config.schedules.iter_mut() is still live.
    let mut to_prune: Vec<(String, usize)> = Vec::new();

    for schedule in config.schedules.iter_mut() {
        // Enabled + time-of-day + pinned day + not-already-run-this-period.
        if !schedule_is_due(schedule, now) {
            continue;
        }

        // Time to run this schedule! Hooks + backups share one code path with
        // the on-demand runner (execute_schedule_run) — entries come back
        // already tagged with the schedule id.
        let (new_entries, _summary) = execute_schedule_run(&*schedule);
        config.entries.extend(new_entries);

        schedule.last_run = now.to_rfc3339();
        changed = true;

        // Queue retention pruning for after the loop (shared helper, see above).
        if schedule.retention > 0 {
            to_prune.push((schedule.id.clone(), schedule.retention as usize));
        }
    }

    for (schedule_id, retention) in to_prune {
        prune_schedule_backups(&mut config, &schedule_id, retention);
    }

    if changed {
        let _ = save_config(&config);
    }
}

/// Receive a backup file from a remote node — save to local storage
/// Resolve a received-backup filename to a safe absolute path inside the
/// received dir, rejecting anything that isn't a bare basename (no `/`, no
/// `..`, not absolute). The filename arrives from an authenticated inter-node
/// caller, but path-traversal defence is cheap and must not be assumed away.
/// Shared by `import_backup` (write) and `delete_imported_backup` (remove) so
/// the two agree on both the sanitisation and the directory.
fn received_backup_path(filename: &str) -> Result<(String, std::path::PathBuf), String> {
    let base = Path::new(filename).file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "invalid backup filename".to_string())?;
    if base != filename {
        return Err("backup filename must not contain path separators".to_string());
    }
    let dir = crate::paths::get().backup_received_dir;
    let path = Path::new(&dir).join(base);
    Ok((dir, path))
}

pub fn import_backup(data: &[u8], filename: &str) -> Result<String, String> {
    let (dest_dir, dest) = received_backup_path(filename)?;
    fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("Failed to create import dir: {}", e))?;

    fs::write(&dest, data)
        .map_err(|e| format!("Failed to write imported backup: {}", e))?;

    let size = data.len();


    // Add to config as an entry
    let mut config = load_config();
    config.entries.push(BackupEntry {
        id: Uuid::new_v4().to_string(),
        target: BackupTarget {
            target_type: guess_target_type(filename),
            name: extract_name_from_filename(filename),
            ..Default::default()
        },
        storage: BackupStorage::local(&dest_dir),
        filename: filename.to_string(),
        size_bytes: size as u64,
        created_at: Utc::now().to_rfc3339(),
        status: BackupStatus::Completed,
        error: String::new(),
        schedule_id: String::new(),
        comments: format!("[{}] Imported backup: {}", local_cluster_name(), filename),
        node_hostname: local_hostname(),
        docker_config: String::new(),
        mounts: Vec::new(),
    });
    let _ = save_config(&config);

    Ok(format!("Backup imported: {}", filename))
}

/// Remove a backup previously received via `import_backup`: deletes the file
/// from the received dir and drops the matching local index entry that import
/// created. Counterpart to `import_backup`, called by the `DELETE
/// /api/backups/import` handler when a source node deletes a `Remote` backup so
/// the replicated copy here doesn't orphan. Idempotent: a missing file/entry is
/// a successful no-op (the source may retry, or the operator may have already
/// cleaned up on this node).
pub fn delete_imported_backup(filename: &str) -> Result<String, String> {
    let (dir, path) = received_backup_path(filename)?;
    // received_backup_path guarantees filename is already a bare basename
    // (it errored otherwise), so filename IS the stored entry's filename.
    let base = filename.to_string();

    // Drop the index entry and persist it BEFORE touching the filesystem, so a
    // save_config failure can't leave a ghost entry pointing at an already-
    // deleted file. Match on the received dir + filename + Local type so we
    // never remove an unrelated local backup that happens to share a name.
    let mut config = load_config();
    let before = config.entries.len();
    config.entries.retain(|e| !(
        e.filename == base
        && e.storage.storage_type == StorageType::Local
        && e.storage.resolved_local_path() == dir
    ));
    if config.entries.len() != before {
        save_config(&config)?;
    }

    if path.exists() {
        fs::remove_file(&path)
            .map_err(|e| format!("Failed to remove imported backup: {}", e))?;
    }

    Ok(format!("Imported backup removed: {}", base))
}

/// Guess the backup target type from filename prefix
fn guess_target_type(filename: &str) -> BackupTargetType {
    if filename.starts_with("docker-") { BackupTargetType::Docker }
    else if filename.starts_with("lxc-") { BackupTargetType::Lxc }
    else if filename.starts_with("vm-") { BackupTargetType::Vm }
    else if filename.starts_with("systempath-") { BackupTargetType::SystemPath }
    else { BackupTargetType::Config }
}

/// Extract the target name from a backup filename
fn extract_name_from_filename(filename: &str) -> String {
    // Format: type-name-timestamp.tar.gz
    let parts: Vec<&str> = filename.splitn(3, '-').collect();
    if parts.len() >= 2 {
        // Remove timestamp and extension from the last part
        let name_and_rest = parts[1..].join("-");
        if let Some(idx) = name_and_rest.rfind('-') {
            return name_and_rest[..idx].to_string();
        }
        return name_and_rest;
    }
    filename.to_string()
}

// ─── Proxmox Backup Server (PBS) Integration ───

/// Retrieve a backup from PBS — restore a specific archive from a snapshot
fn retrieve_from_pbs(entry: &BackupEntry, dest: &Path) -> Result<(), String> {
    let storage = &entry.storage;
    let repo = pbs_repo_string(storage);

    let backup_id = extract_backup_id_from_filename(&entry.filename);
    // Shared with the store path — these two had drifted, and the missing
    // `docker-` arm here meant Docker archives were written as "ct" but looked
    // up as "host" on restore.
    let backup_type = pbs_backup_type_for_filename(&entry.filename);

    let pbs_pw = if !storage.pbs_token_secret.is_empty() { &storage.pbs_token_secret }
                 else { &storage.pbs_password };

    // List snapshots to find the latest matching one (PBS needs exact timestamp, not "latest")
    let mut list_cmd = Command::new("proxmox-backup-client");
    list_cmd.args(["snapshot", "list", "--output-format", "json", "--repository", &repo]);
    if !storage.pbs_fingerprint.is_empty() { list_cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint)); }
    if !storage.pbs_namespace.is_empty() { list_cmd.arg("--ns").arg(&storage.pbs_namespace); }
    if !pbs_pw.is_empty() { list_cmd.env("PBS_PASSWORD", pbs_pw); }

    let list_output = list_cmd.output()
        .map_err(|e| format!("Failed to list PBS snapshots: {}", e))?;

    let snapshot = if list_output.status.success() {
        let snaps: serde_json::Value = serde_json::from_slice(&list_output.stdout)
            .unwrap_or(serde_json::Value::Array(vec![]));
        if let Some(arr) = snaps.as_array() {
            let mut best_time: i64 = 0;
            let mut best_snap = String::new();
            for s in arr {
                let st = s.get("backup-type").and_then(|v| v.as_str()).unwrap_or("");
                let si = s.get("backup-id").and_then(|v| v.as_str()).unwrap_or("");
                let stime = s.get("backup-time").and_then(|v| v.as_i64()).unwrap_or(0);
                if st == backup_type && si == backup_id && stime > best_time {
                    // PBS needs the snapshot's time component as RFC3339 (e.g.
                    // host/newt/2026-06-22T10:21:09Z), NOT the raw epoch that
                    // `snapshot list --output-format json` reports. Passing the
                    // epoch made `restore` fail with "unable to parse backup
                    // snapshot path 'host/newt/1782104469'" (wabil 2026-06-22).
                    // Mirrors the conversion already done on the notes path.
                    if let Some(ts) = chrono::DateTime::from_timestamp(stime, 0) {
                        best_time = stime;
                        best_snap = format!("{}/{}/{}", st, si,
                            ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
                    }
                }
            }
            if best_snap.is_empty() {
                return Err(format!("No PBS snapshot found for {}/{}", backup_type, backup_id));
            }
            best_snap
        } else {
            return Err("Failed to parse PBS snapshot list".to_string());
        }
    } else {
        return Err(format!("PBS snapshot list failed: {}", String::from_utf8_lossy(&list_output.stderr)));
    };

    // `proxmox-backup-client restore` extracts backup.pxar into the target
    // directory and REFUSES to overwrite an existing file (EEXIST). A previous
    // FAILED restore leaves the staged archive (`dest`) behind, so every retry
    // then dies with `failed to create file "…": EEXIST: File exists` and the
    // backup can never be restored. Clear the stale staged file first (other
    // storage paths use fs::copy, which overwrites — only PBS needs this).
    // wabil 2026-06-29.
    let _ = std::fs::remove_file(dest);

    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("restore")
       .arg(&snapshot)
       .arg("backup.pxar")
       .arg(dest.parent().unwrap_or(Path::new("/tmp")).to_string_lossy().to_string())
       .arg("--repository").arg(&repo);

    if !storage.pbs_fingerprint.is_empty() {
        cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
    }
    if !storage.pbs_namespace.is_empty() {
        cmd.arg("--ns").arg(&storage.pbs_namespace);
    }
    if !pbs_pw.is_empty() {
        cmd.env("PBS_PASSWORD", pbs_pw);
    }

    let output = cmd.output()
        .map_err(|e| format!("PBS restore failed: {}", e))?;

    if !output.status.success() {
        return Err(format!("PBS restore error: {}",
            String::from_utf8_lossy(&output.stderr)));
    }

    Ok(())
}

/// List all snapshots on a Proxmox Backup Server
pub fn list_pbs_snapshots(storage: &BackupStorage) -> Result<serde_json::Value, String> {
    if storage.pbs_server.is_empty() || storage.pbs_datastore.is_empty() {
        return Err("PBS server and datastore must be configured".to_string());
    }

    let repo = pbs_repo_string(storage);

    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("snapshot").arg("list")
       .arg("--output-format").arg("json")
       .arg("--repository").arg(&repo);

    if !storage.pbs_fingerprint.is_empty() {
        cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
    }
    if !storage.pbs_namespace.is_empty() {
        cmd.arg("--ns").arg(&storage.pbs_namespace);
    }
    let pbs_pw = if !storage.pbs_token_secret.is_empty() { &storage.pbs_token_secret }
                 else { &storage.pbs_password };
    if !pbs_pw.is_empty() {
        cmd.env("PBS_PASSWORD", pbs_pw);
    }

    let output = cmd.output()
        .map_err(|e| format!("Failed to run proxmox-backup-client: {}", e))?;

    if !output.status.success() {
        // Surface the exact repository (no secret — just user!token@host:store
        // and the auth method) so a connection failure is self-diagnosing.
        let auth = if !storage.pbs_token_secret.is_empty() { "API token" }
                   else if !storage.pbs_password.is_empty() { "password" }
                   else { "no credentials" };
        return Err(format!("PBS snapshot list failed [repo {}, auth {}]: {}",
            repo, auth, String::from_utf8_lossy(&output.stderr).trim()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let snapshots: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("Failed to parse PBS output: {}", e))?;

    Ok(snapshots)
}

/// Enrich PBS snapshots with local container/VM details (hostname, specs)
pub fn enrich_pbs_snapshots(snapshots: serde_json::Value) -> serde_json::Value {
    let arr = match snapshots.as_array() {
        Some(a) => a,
        None => return snapshots,
    };

    // Build a lookup of VMID → (hostname, specs) from pct list + pct config
    let ct_info = build_pct_lookup();

    let enriched: Vec<serde_json::Value> = arr.iter().map(|snap| {
        let mut s = snap.clone();
        let btype = s.get("backup-type").or_else(|| s.get("backup_type"))
            .and_then(|v| v.as_str()).unwrap_or("").to_string();
        let bid = s.get("backup-id").or_else(|| s.get("backup_id"))
            .and_then(|v| v.as_str()).unwrap_or("").to_string();

        if (btype == "ct" || btype == "lxc")
            && let Some((hostname, specs)) = ct_info.get(&bid)
                && let Some(obj) = s.as_object_mut() {
                    if !hostname.is_empty() {
                        obj.insert("hostname".to_string(), serde_json::json!(hostname));
                    }
                    if !specs.is_empty() {
                        obj.insert("specs".to_string(), serde_json::json!(specs));
                    }
                }
        s
    }).collect();

    serde_json::json!(enriched)
}

/// Build a VMID → (hostname, specs) lookup from Proxmox pct list/config
fn build_pct_lookup() -> std::collections::HashMap<String, (String, String)> {
    let mut map = std::collections::HashMap::new();

    let output = match Command::new("pct").arg("list").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return map,
    };

    let entries: Vec<(String, String)> = output.lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let vmid = parts.first()?.to_string();
            let pct_name = parts.last().map(|s| s.to_string()).unwrap_or_default();
            Some((vmid, pct_name))
        })
        .collect();

    // Fetch configs in parallel
    let configs: Vec<String> = std::thread::scope(|s| {
        let handles: Vec<_> = entries.iter().map(|(vmid, _)| {
            let vmid = vmid.clone();
            s.spawn(move || {
                Command::new("pct").args(["config", &vmid]).output().ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_default()
            })
        }).collect();
        handles.into_iter().map(|h| h.join().unwrap_or_default()).collect()
    });

    for ((vmid, pct_name), cfg) in entries.iter().zip(configs.iter()) {
        let mut hostname = pct_name.clone();
        let mut memory_mb: u64 = 0;
        let mut cores: u64 = 0;
        let mut os_type = String::new();

        for cline in cfg.lines() {
            let cline = cline.trim();
            if cline.starts_with("hostname:") {
                hostname = cline.split(':').nth(1).unwrap_or("").trim().to_string();
            } else if cline.starts_with("memory:") {
                memory_mb = cline.split(':').nth(1).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            } else if cline.starts_with("cores:") {
                cores = cline.split(':').nth(1).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            } else if cline.starts_with("ostype:") {
                os_type = cline.split(':').nth(1).unwrap_or("").trim().to_string();
            }
        }

        let mut spec_parts = Vec::new();
        if cores > 0 { spec_parts.push(format!("{} core{}", cores, if cores > 1 { "s" } else { "" })); }
        if memory_mb > 0 {
            if memory_mb >= 1024 { spec_parts.push(format!("{}GB RAM", memory_mb / 1024)); }
            else { spec_parts.push(format!("{}MB RAM", memory_mb)); }
        }
        if !os_type.is_empty() { spec_parts.push(os_type); }

        map.insert(vmid.clone(), (hostname, spec_parts.join(", ")));
    }

    map
}

pub struct PbsRestoreOptions<'a> {
    pub overwrite: bool,
    pub new_name: &'a str,
    pub target_storage: &'a str,
}

/// Restore with real-time progress tracking via callback
pub fn restore_from_pbs_with_progress<F>(
    storage: &BackupStorage,
    snapshot: &str,
    archive: &str,
    _target_dir: &str,
    on_progress: F,
    options: PbsRestoreOptions<'_>,
) -> Result<String, String>
where
    F: Fn(String, Option<f64>),
{
    let PbsRestoreOptions { overwrite, new_name, target_storage } = options;
    let repo = pbs_repo_string(storage);

    // Parse snapshot "type/id/timestamp" to determine backup kind and ID
    let parts: Vec<&str> = snapshot.split('/').collect();
    let snap_type = parts.first().copied().unwrap_or("");
    let snap_id = parts.get(1).copied().unwrap_or("");

    if snap_id.is_empty() {
        return Err(format!("Malformed PBS snapshot id: '{}'", snapshot));
    }

    // A WolfStack PBS snapshot is a `backup.pxar` that wraps exactly ONE
    // WolfStack archive file. Extract the pxar into a private staging
    // dir, then hand that archive to the SAME restore code the Backups
    // list uses. The old code reimplemented restore here and got it
    // wrong — it left the archive un-extracted and wrote a stub config.
    // Stage under the backup staging dir (operator-controlled, sized for
    // backup archives) rather than /tmp, which may be a small tmpfs.
    let stage = ensure_staging_dir()?
        .join(format!("pbs-restore-{}", Uuid::new_v4().simple()));
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(&stage)
        .map_err(|e| format!("Failed to create PBS restore staging dir: {}", e))?;

    let snapshot_fixed = fix_pbs_snapshot_timestamp(snapshot);

    on_progress("Detecting archive...".to_string(), Some(1.0));

    // Detect the archive kind. A WolfStack *tarball* snapshot wraps its
    // .tar.gz as `backup.pxar`; a WolfStack *file-level* snapshot stores the
    // content tree as `root.pxar` (+ volume-*/bind-* pxars). The caller may
    // request a specific archive; otherwise we sniff the snapshot's files.
    let detected = detect_pbs_archive(storage, &snapshot_fixed);
    let actual_archive = if !archive.is_empty() && archive != "root.pxar" {
        archive.to_string()
    } else {
        detected.clone().unwrap_or_else(|| "backup.pxar".to_string())
    };

    // File-level snapshot: extract the `root.pxar` tree directly. There's no
    // inner WolfStack archive to hand to restore_lxc_local — the snapshot IS
    // the filesystem. Restore the whole tree into a clearly-named directory
    // under the restore area; per-FILE restore is done from PBS's own UI.
    let is_file_level = actual_archive == "root.pxar";
    if is_file_level {
        on_progress(format!("Restoring file-level tree {}...", actual_archive), Some(2.0));
        let out_dir = ensure_staging_dir().unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("pbs-fl-restore-{}-{}", snap_id, Uuid::new_v4().simple()));
        let _ = fs::remove_dir_all(&stage); // not used on this branch
        fs::create_dir_all(&out_dir)
            .map_err(|e| format!("Failed to create restore dir: {}", e))?;
        let mut cmd = Command::new("proxmox-backup-client");
        cmd.arg("restore")
           .arg(&snapshot_fixed)
           .arg("root.pxar")
           .arg(&out_dir)
           .arg("--repository").arg(&repo)
           .arg("--ignore-ownership").arg("true");
        pbs_apply_common(&mut cmd, storage);
        let out = cmd.output()
            .map_err(|e| { let _ = fs::remove_dir_all(&out_dir); format!("PBS file-level restore failed: {}", e) })?;
        if !out.status.success() {
            let _ = fs::remove_dir_all(&out_dir);
            return Err(format!("PBS file-level restore error: {}",
                String::from_utf8_lossy(&out.stderr).trim()));
        }
        on_progress("File-level restore complete".to_string(), Some(100.0));
        return Ok(format!(
            "File-level snapshot '{}' restored into {} — the container/folder \
             filesystem is there; use PBS's per-file restore for individual files.",
            snapshot, out_dir.display()));
    }

    on_progress(format!("Downloading {}...", actual_archive), Some(2.0));

    let pbs_pw = if !storage.pbs_token_secret.is_empty() { &storage.pbs_token_secret }
                 else { &storage.pbs_password };

    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("restore")
       .arg(&snapshot_fixed)
       .arg(&actual_archive)
       .arg(&stage)
       .arg("--repository").arg(&repo)
       .arg("--ignore-ownership").arg("true");

    if !storage.pbs_fingerprint.is_empty() {
        cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
    }
    if !storage.pbs_namespace.is_empty() {
        cmd.arg("--ns").arg(&storage.pbs_namespace);
    }
    if !pbs_pw.is_empty() {
        cmd.env("PBS_PASSWORD", pbs_pw);
    }

    // Capture stderr for error reporting — stdout can be null since we monitor dir size
    use std::process::Stdio;
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = fs::remove_dir_all(&stage);
            return Err(format!("Failed to start proxmox-backup-client: {}", e));
        }
    };

    // Monitor staging-dir size growth while the download runs
    let target_path = stage.to_string_lossy().to_string();
    let progress_fn = &on_progress;

    loop {
        // Check if child is still running
        match child.try_wait() {
            Ok(Some(_status)) => break,  // Process finished
            Ok(None) => {},               // Still running
            Err(_) => break,
        }

        // Measure directory size
        let dir_size = dir_size_bytes(&target_path);
        let size_str = format_size_human(dir_size);
        progress_fn(format!("Downloaded: {}", size_str), None);

        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    let status = match child.wait() {
        Ok(s) => s,
        Err(e) => {
            let _ = fs::remove_dir_all(&stage);
            return Err(format!("PBS restore wait failed: {}", e));
        }
    };

    if !status.success() {
        // Read stderr for the actual error message
        let stderr_output = if let Some(stderr) = child.stderr.take() {
            use std::io::Read;
            let mut buf = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            let _ = reader.read_to_string(&mut buf);
            buf
        } else {
            String::new()
        };
        let err_detail = if stderr_output.trim().is_empty() {
            format!("exit code {}", status.code().unwrap_or(-1))
        } else {
            stderr_output.trim().to_string()
        };
        let _ = fs::remove_dir_all(&stage);
        return Err(format!("PBS restore failed for '{}': {}", snapshot_fixed, err_detail));
    }

    // The pxar yielded the WolfStack archive — the single regular file
    // now sitting in the staging dir.
    on_progress("Unpacking restored backup...".to_string(), Some(90.0));
    let archive_file = fs::read_dir(&stage).ok()
        .and_then(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).find(|p| p.is_file()));
    let archive_file = match archive_file {
        Some(f) => f,
        None => {
            let _ = fs::remove_dir_all(&stage);
            return Err(format!(
                "Snapshot '{}' contains no WolfStack backup archive — it may be a \
                 native Proxmox backup; restore those from a Proxmox host.", snapshot));
        }
    };

    // Hand the archive to the SAME restore path the Backups list uses —
    // it un-archives the rootfs properly and restores the real config,
    // instead of leaving a compressed file behind under a stub config.
    // The operator-picked Proxmox storage (empty = let Proxmox default)
    // flows into both `pct restore --storage` (LXC) and `qm` restore (VM).
    let pve_storage = if target_storage.trim().is_empty() { None } else { Some(target_storage.trim()) };
    let result = match snap_type {
        "ct" => restore_lxc_local(&archive_file, snap_id, pve_storage.unwrap_or(""), overwrite, new_name),
        "vm" => restore_vm_local(&archive_file, snap_id, pve_storage),
        other => {
            let _ = fs::remove_file(&archive_file);
            Err(format!(
                "Restoring a '{}' snapshot from the PBS list isn't supported here — \
                 restore it from the Backups list instead.", other))
        }
    };
    let _ = fs::remove_dir_all(&stage);
    result
}

/// Recursively calculate directory size in bytes
fn dir_size_bytes(path: &str) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                total += dir_size_bytes(&p.to_string_lossy());
            } else if let Ok(meta) = p.metadata() {
                total += meta.len();
            }
        }
    }
    total
}

/// Format bytes as human-readable size
fn format_size_human(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.0} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Convert Unix epoch timestamps in snapshot IDs to ISO format
/// Input:  "ct/105/1707600000" -> "ct/105/2024-02-11T04:00:00Z"
/// If already in ISO format (contains 'T'), pass through unchanged
fn fix_pbs_snapshot_timestamp(snapshot: &str) -> String {
    let parts: Vec<&str> = snapshot.splitn(3, '/').collect();
    if parts.len() != 3 {
        return snapshot.to_string();
    }
    let timestamp_part = parts[2];
    // If it already contains 'T' or '-', it's probably already in ISO format
    if timestamp_part.contains('T') || timestamp_part.contains('-') {
        return snapshot.to_string();
    }
    // Try to parse as Unix epoch
    if let Ok(epoch) = timestamp_part.parse::<i64>()
        && let Some(dt) = chrono::DateTime::from_timestamp(epoch, 0) {
            return format!("{}/{}/{}", parts[0], parts[1], dt.format("%Y-%m-%dT%H:%M:%SZ"));
        }
    snapshot.to_string()
}

/// Try to detect the correct archive name by listing snapshot files
fn detect_pbs_archive(storage: &BackupStorage, snapshot: &str) -> Option<String> {
    let repo = pbs_repo_string(storage);
    let mut cmd = Command::new("proxmox-backup-client");
    cmd.arg("snapshot").arg("files")
       .arg(snapshot)
       .arg("--output-format").arg("json")
       .arg("--repository").arg(&repo);

    if !storage.pbs_fingerprint.is_empty() {
        cmd.env("PBS_FINGERPRINT", format_pbs_fingerprint(&storage.pbs_fingerprint));
    }
    if !storage.pbs_namespace.is_empty() {
        cmd.arg("--ns").arg(&storage.pbs_namespace);
    }
    let pbs_pw = if !storage.pbs_token_secret.is_empty() { &storage.pbs_token_secret }
                 else { &storage.pbs_password };
    if !pbs_pw.is_empty() {
        cmd.env("PBS_PASSWORD", pbs_pw);
    }

    let output = cmd.output().ok()?;
    if !output.status.success() {
        warn!("Failed to list snapshot files: {}", String::from_utf8_lossy(&output.stderr));
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let files: serde_json::Value = serde_json::from_str(&stdout).ok()?;
    
    // Look for .pxar or .img archives (skip index.json and catalog)
    if let Some(arr) = files.as_array() {
        // Prefer the well-known WolfStack archive names first so a file-level
        // snapshot (root.pxar + volume-*/bind-*) resolves to `root.pxar` and a
        // tarball snapshot to `backup.pxar`, regardless of PBS listing order.
        for preferred in ["root.pxar", "backup.pxar"] {
            for f in arr {
                let filename = f.get("filename").and_then(|v| v.as_str()).unwrap_or("");
                let name = filename.trim_end_matches(".didx");
                if name == preferred {
                    return Some(name.to_string());
                }
            }
        }
        for f in arr {
            let filename = f.get("filename").and_then(|v| v.as_str()).unwrap_or("");
            // Prefer .pxar (filesystem backup), then .img (disk image)
            if filename.ends_with(".pxar.didx") || filename.ends_with(".pxar") {
                let name = filename.trim_end_matches(".didx");

                return Some(name.to_string());
            }
        }
        // Fallback to .img
        for f in arr {
            let filename = f.get("filename").and_then(|v| v.as_str()).unwrap_or("");
            if filename.ends_with(".img.fidx") || filename.ends_with(".img") {
                let name = filename.trim_end_matches(".fidx");

                return Some(name.to_string());
            }
        }
    }
    None
}

/// Check if PBS is reachable and proxmox-backup-client is installed
pub fn check_pbs_status(storage: &BackupStorage) -> serde_json::Value {
    let client_installed = Command::new("which")
        .arg("proxmox-backup-client")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !client_installed {
        return serde_json::json!({
            "installed": false,
            "connected": false,
            "error": "proxmox-backup-client not installed"
        });
    }

    if storage.pbs_server.is_empty() {
        return serde_json::json!({
            "installed": true,
            "connected": false,
            "error": "PBS not configured"
        });
    }

    // Try to list snapshots as a connectivity test
    match list_pbs_snapshots(storage) {
        Ok(snapshots) => {
            let count = snapshots.as_array().map(|a| a.len()).unwrap_or(0);
            serde_json::json!({
                "installed": true,
                "connected": true,
                "server": storage.pbs_server,
                "datastore": storage.pbs_datastore,
                "snapshot_count": count
            })
        },
        Err(e) => serde_json::json!({
            "installed": true,
            "connected": false,
            "server": storage.pbs_server,
            "error": e
        })
    }
}

/// Fill any empty PBS connection/credential fields on `storage` from the
/// saved PBS config. The cluster-wide scheduler form only sends
/// `{type:"pbs"}` — without this merge, scheduled runs invoke
/// proxmox-backup-client with no PBS_PASSWORD and fail with
/// "no password input mechanism".
pub fn merge_pbs_secrets(storage: &mut BackupStorage) {
    if storage.storage_type != StorageType::Pbs { return; }
    // A backup bound to an additional destination takes that
    // destination's fields first; anything the destination leaves
    // blank still inherits from the primary connection below. Order
    // matters — per-backup value, then destination, then primary.
    if !storage.pbs_target_id.is_empty() {
        match find_pbs_target(&storage.pbs_target_id) {
            Some(t) => apply_pbs_target(storage, &t),
            None => {
                // Falling through to the primary connection would send
                // this backup to a DIFFERENT datastore than the operator
                // chose. Blank the server instead so the run fails loudly
                // — a failed backup is recoverable, one silently written
                // to the wrong place is not.
                tracing::error!(
                    "backup: PBS destination '{}' no longer exists — refusing to \
                     fall back to the primary datastore",
                    storage.pbs_target_id,
                );
                storage.pbs_server.clear();
                storage.pbs_datastore.clear();
                return;
            }
        }
    }
    let saved = load_pbs_config();
    if storage.pbs_server.is_empty()      { storage.pbs_server      = saved.pbs_server; }
    if storage.pbs_datastore.is_empty()   { storage.pbs_datastore   = saved.pbs_datastore; }
    if storage.pbs_user.is_empty()        { storage.pbs_user        = saved.pbs_user; }
    if storage.pbs_token_name.is_empty()  { storage.pbs_token_name  = saved.pbs_token_name; }
    if storage.pbs_token_secret.is_empty(){ storage.pbs_token_secret= saved.pbs_token_secret; }
    if storage.pbs_password.is_empty()    { storage.pbs_password    = saved.pbs_password; }
    if storage.pbs_fingerprint.is_empty() { storage.pbs_fingerprint = saved.pbs_fingerprint; }
    if storage.pbs_namespace.is_empty()   { storage.pbs_namespace   = saved.pbs_namespace; }
    storage.pbs_file_level =
        resolve_pbs_file_level(storage.pbs_file_level_set, storage.pbs_file_level, saved.pbs_file_level);
}

/// Resolve a PBS backup's effective file-level (pxar) flag from the per-backup
/// override and the connection default. Pure so the precedence is unit-testable.
///
/// * `explicitly_set` true → the caller used the per-backup toggle, so its
///   `requested` value wins verbatim — including an explicit `false` against an
///   on-by-default connection (the half of the override a bare bool can't do).
/// * `explicitly_set` false → legacy behaviour: adopt the saved default unless
///   the request already asked for `true`. Keeps older callers byte-identical.
fn resolve_pbs_file_level(explicitly_set: bool, requested: bool, saved: bool) -> bool {
    if !explicitly_set && !requested { saved } else { requested }
}

/// PBS configuration — stored in /etc/wolfstack/pbs/config.json
pub fn load_pbs_config() -> BackupStorage {
    let path = "/etc/wolfstack/pbs/config.json";
    if let Ok(content) = fs::read_to_string(path)
        && let Ok(storage) = serde_json::from_str::<BackupStorage>(&content) {
            return storage;
        }
    BackupStorage {
        storage_type: StorageType::Pbs,
        ..BackupStorage::default()
    }
}

// ─── Additional PBS destinations ──────────────────────────────────
//
// PBS 4 can back a datastore with external S3 as well as local/NAS
// storage, and operators want that per-workload: the important things
// to the S3-backed datastore, everything else to the NAS-backed one
// (klasSponsor 2026-07-28). A datastore is chosen by the repository
// string, so "another destination" is just another set of PBS fields.
//
// Empty fields on a target INHERIT from the primary connection. That
// is the common case by a wide margin — a second datastore on the
// same server needs only a name and a datastore, not a re-typed set
// of credentials — and it means rotating the token in one place still
// fixes every destination.
//
// Note we cannot offer a datastore picker: `proxmox-backup-client`
// (the only PBS interface WolfStack uses) has no command that lists
// datastores — every subcommand is scoped to one repository. So the
// operator types the name, and `test_pbs_target` proves it works
// before they rely on it.

/// One saved PBS destination beyond the primary connection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PbsTarget {
    /// Stable id used by `BackupStorage::pbs_target_id`.
    pub id: String,
    /// Operator-facing name, shown in the destination dropdown.
    pub name: String,
    #[serde(default)]
    pub pbs_server: String,
    #[serde(default)]
    pub pbs_datastore: String,
    #[serde(default)]
    pub pbs_user: String,
    #[serde(default)]
    pub pbs_token_name: String,
    #[serde(default)]
    pub pbs_token_secret: String,
    #[serde(default)]
    pub pbs_password: String,
    #[serde(default)]
    pub pbs_fingerprint: String,
    #[serde(default)]
    pub pbs_namespace: String,
    /// Store content as native pxar for backups sent here.
    #[serde(default)]
    pub pbs_file_level: bool,
    /// True when this target sets `pbs_file_level` deliberately, so an
    /// explicit `false` survives against an on-by-default primary
    /// connection. Same distinction `pbs_file_level_set` draws on a
    /// per-backup override.
    #[serde(default)]
    pub pbs_file_level_set: bool,
}

const PBS_TARGETS_PATH: &str = "/etc/wolfstack/pbs/targets.json";

/// Every additional PBS destination. Missing or unreadable file → no
/// extra destinations, which is exactly the pre-feature state.
pub fn load_pbs_targets() -> Vec<PbsTarget> {
    match fs::read_to_string(PBS_TARGETS_PATH) {
        Ok(content) => serde_json::from_str::<Vec<PbsTarget>>(&content).unwrap_or_else(|e| {
            // Don't silently behave as "no targets" — a parse error here
            // would send scheduled backups to the primary datastore
            // without anyone noticing they'd moved.
            tracing::error!(
                "backup: {} is unreadable ({}); additional PBS destinations are \
                 UNAVAILABLE and backups selecting one will fail rather than \
                 silently write to the primary datastore",
                PBS_TARGETS_PATH, e,
            );
            Vec::new()
        }),
        Err(_) => Vec::new(),
    }
}

/// Persist the full set of additional destinations. Mode 0600 — these
/// carry PBS tokens.
pub fn save_pbs_targets(targets: &[PbsTarget]) -> Result<(), String> {
    fs::create_dir_all("/etc/wolfstack/pbs")
        .map_err(|e| format!("Failed to create PBS config dir: {}", e))?;
    let json = serde_json::to_string_pretty(targets)
        .map_err(|e| format!("Failed to serialize PBS destinations: {}", e))?;
    let tmp = format!("{}.tmp", PBS_TARGETS_PATH);
    fs::write(&tmp, json).map_err(|e| format!("Failed to write PBS destinations: {}", e))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    fs::rename(&tmp, PBS_TARGETS_PATH)
        .map_err(|e| format!("Failed to install PBS destinations: {}", e))?;
    Ok(())
}

pub fn find_pbs_target(id: &str) -> Option<PbsTarget> {
    load_pbs_targets().into_iter().find(|t| t.id == id)
}

// ─── Removing a backup server, fleet-wide ─────────────────────────
//
// There was no way to remove one. After migrating off an old PBS
// (node3.dreamhosting.at:8007) its hostname, datastore, user and PLAINTEXT
// password stayed behind on every node — in backups.json history entries (6 of
// 7 on wolf1, 7 of 7 on wolf2, 2 of 2 on wolf3), in ~12 config snapshots under
// /etc/wolfstack/config-backups/, and in /etc/wolfstack/pbs/config.json. The
// operator purged three nodes by hand (production report, 2026-07-30).
//
// Everything here is idempotent: a second run over an already-clean node
// reports zeroes and succeeds. That matters because this is fanned out across
// the fleet and a partial failure is retried by re-running it.

/// Which backup server to remove. Named by host because that is the one thing
/// every storage type spells the same way — the field it lives in varies
/// (`pbs_server`, `endpoint`, `remote_url`, an NFS/SMB `path`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupServerRef {
    /// Host, optionally with a port: "node3.dreamhosting.at:8007".
    pub server: String,
    /// Narrow the match to one datastore/bucket/share. Absent removes every
    /// reference to the host.
    #[serde(default)]
    pub datastore: String,
}

/// Reduce a field that might be a bare host, a `host:port`, a URL, or an
/// NFS-style `host:/export` to just its host, lowercased.
///
/// Comparing raw strings would miss the obvious cases: the same server is
/// written `node3.dreamhosting.at:8007` in one field and
/// `https://node3.dreamhosting.at:8007/` in another, and an operator asked to
/// name the server will type whichever they remember.
fn host_of(field: &str) -> String {
    let s = field.trim();
    // Strip scheme.
    let s = s.split("://").last().unwrap_or(s);
    // Strip any path / export component.
    let s = s.split('/').next().unwrap_or(s);
    // Strip userinfo.
    let s = s.rsplit('@').next().unwrap_or(s);
    // Strip port. Guard IPv6 literals, which are bracketed and full of colons.
    let s = if s.starts_with('[') {
        s.split(']').next().unwrap_or(s).trim_start_matches('[')
    } else {
        s.split(':').next().unwrap_or(s)
    };
    s.trim().to_ascii_lowercase()
}

/// True when `storage` points at the server described by `target`.
pub fn storage_references_server(storage: &BackupStorage, target: &BackupServerRef) -> bool {
    let want = host_of(&target.server);
    if want.is_empty() { return false; }
    let hosts = [
        host_of(&storage.pbs_server),
        host_of(&storage.endpoint),
        host_of(&storage.remote_url),
        // NFS/SMB destinations carry the server in the path ("nas:/vol/backups",
        // "//nas/backups").
        host_of(storage.path.trim_start_matches('/')),
    ];
    if !hosts.iter().any(|h| !h.is_empty() && *h == want) {
        return false;
    }
    if target.datastore.is_empty() {
        return true;
    }
    // Narrowed to one datastore/bucket/share.
    let ds = target.datastore.trim().to_ascii_lowercase();
    [&storage.pbs_datastore, &storage.bucket]
        .iter()
        .any(|f| f.trim().to_ascii_lowercase() == ds)
}

/// What removing a server actually did on this node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerRemovalReport {
    /// Schedules still pointing at this server. Populated only when the removal
    /// was REFUSED — the operator either repoints them or confirms.
    #[serde(default)]
    pub blocking_schedules: Vec<String>,
    /// The primary PBS connection was this server and has been cleared.
    #[serde(default)]
    pub primary_config_cleared: bool,
    /// Saved PBS destinations removed from targets.json.
    #[serde(default)]
    pub pbs_targets_removed: usize,
    /// History entries whose embedded credentials were scrubbed.
    #[serde(default)]
    pub history_entries_scrubbed: usize,
    /// Config snapshots rewritten with the credentials removed.
    #[serde(default)]
    pub snapshots_scrubbed: usize,
    /// Schedules deleted (only ever with `force`).
    #[serde(default)]
    pub schedules_removed: usize,
    /// Human-readable trail, one line per thing changed.
    #[serde(default)]
    pub details: Vec<String>,
}

impl ServerRemovalReport {
    /// True when nothing on this node referenced the server. A second run
    /// reports this, which is what makes the action safe to retry.
    pub fn is_noop(&self) -> bool {
        !self.primary_config_cleared
            && self.pbs_targets_removed == 0
            && self.history_entries_scrubbed == 0
            && self.snapshots_scrubbed == 0
            && self.schedules_removed == 0
    }
}

/// Blank every credential-looking field of a storage block in place, leaving
/// the non-secret parts (hostname, datastore) so history still says WHERE a
/// backup went. Uses the same substring rule as the API redaction, so a storage
/// field added later is scrubbed without anyone remembering to list it.
fn scrub_storage_secrets(storage: &mut BackupStorage) -> bool {
    let before = match serde_json::to_value(&*storage) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut after = before.clone();
    if let serde_json::Value::Object(map) = &mut after {
        for (key, val) in map.iter_mut() {
            if crate::secrets::is_secret_field(key)
                && let serde_json::Value::String(s) = val {
                    s.clear();
                }
        }
    }
    if after == before { return false; }
    match serde_json::from_value::<BackupStorage>(after) {
        Ok(cleaned) => { *storage = cleaned; true }
        Err(_) => false,
    }
}

/// Remove every trace of `target` from THIS node.
///
/// Refuses while a schedule still targets the server unless `force` — deleting
/// the credentials out from under a live schedule would leave it failing every
/// night with an auth error instead of telling the operator now. With `force`
/// those schedules are deleted, which is the only coherent alternative: a
/// schedule pointing at a server with no credentials is not a backup.
pub fn remove_backup_server(target: &BackupServerRef, force: bool) -> Result<ServerRemovalReport, String> {
    if host_of(&target.server).is_empty() {
        return Err("A server hostname is required".to_string());
    }
    let mut report = ServerRemovalReport::default();

    let mut config = load_config();

    // (d) Refuse while schedules still point at it.
    let blocking: Vec<String> = config.schedules.iter()
        .filter(|s| storage_references_server(&s.storage, target))
        .map(|s| s.name.clone())
        .collect();
    if !blocking.is_empty() && !force {
        report.blocking_schedules = blocking;
        return Ok(report);
    }

    let mut config_dirty = false;

    // Delete the schedules that pointed at it (force path only — the refusal
    // above is the non-force outcome).
    if !blocking.is_empty() {
        let before = config.schedules.len();
        config.schedules.retain(|s| !storage_references_server(&s.storage, target));
        let removed = before - config.schedules.len();
        if removed > 0 {
            report.schedules_removed = removed;
            report.details.push(format!(
                "removed {} schedule(s) targeting {}: {}",
                removed, target.server, blocking.join(", "),
            ));
            config_dirty = true;
        }
    }

    // (b) Scrub credentials out of history entries. The entries themselves stay
    // — they are the record of what was backed up and when, and deleting that
    // to remove a password would be destroying an audit trail to fix a leak.
    for entry in config.entries.iter_mut() {
        if storage_references_server(&entry.storage, target)
            && scrub_storage_secrets(&mut entry.storage)
        {
            report.history_entries_scrubbed += 1;
            config_dirty = true;
        }
    }
    if report.history_entries_scrubbed > 0 {
        report.details.push(format!(
            "scrubbed credentials from {} backup history entr{}",
            report.history_entries_scrubbed,
            if report.history_entries_scrubbed == 1 { "y" } else { "ies" },
        ));
    }

    if config_dirty {
        save_config(&config)?;
    }

    // (a) The primary PBS connection.
    let primary = load_pbs_config();
    if storage_references_server(&primary, target) {
        // Clear rather than delete the file: an absent config and a cleared one
        // load identically (load_pbs_config defaults), but clearing leaves the
        // file at its hardened permissions instead of recreating it later.
        save_pbs_config(&BackupStorage {
            storage_type: StorageType::Pbs,
            ..BackupStorage::default()
        })?;
        report.primary_config_cleared = true;
        report.details.push(format!("cleared primary PBS connection to {}", target.server));
    }

    // (a) Saved PBS destinations.
    let targets = load_pbs_targets();
    let kept: Vec<PbsTarget> = targets.iter()
        .filter(|t| {
            let as_storage = BackupStorage {
                storage_type: StorageType::Pbs,
                pbs_server: t.pbs_server.clone(),
                pbs_datastore: t.pbs_datastore.clone(),
                ..BackupStorage::default()
            };
            !storage_references_server(&as_storage, target)
        })
        .cloned()
        .collect();
    if kept.len() != targets.len() {
        report.pbs_targets_removed = targets.len() - kept.len();
        save_pbs_targets(&kept)?;
        report.details.push(format!(
            "removed {} saved PBS destination(s)", report.pbs_targets_removed,
        ));
    }

    // (c) Config snapshots. They are plain JSON at 0600 and each embeds a whole
    // copy of the config, so the credential survives in every daily snapshot
    // long after the live config is clean.
    report.snapshots_scrubbed = scrub_config_snapshots(target)?;
    if report.snapshots_scrubbed > 0 {
        report.details.push(format!(
            "scrubbed credentials from {} config snapshot(s)", report.snapshots_scrubbed,
        ));
    }

    Ok(report)
}

/// Walk every config snapshot and blank credential fields inside any object
/// that references the removed server. Returns how many files were rewritten.
///
/// Objects are matched by looking for the host in the SAME object that carries
/// the secret, so a snapshot mentioning two different backup servers only loses
/// the credentials of the one being removed.
fn scrub_config_snapshots(target: &BackupServerRef) -> Result<usize, String> {
    let dir = "/etc/wolfstack/config-backups";
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        // No snapshots yet is not a failure — this runs on fresh nodes too.
        Err(_) => return Ok(0),
    };
    let want = host_of(&target.server);
    let mut rewritten = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let content = match fs::read_to_string(&path) { Ok(c) => c, Err(_) => continue };
        let mut value: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if scrub_value_for_host(&mut value, &want) {
            let json = serde_json::to_string_pretty(&value)
                .map_err(|e| format!("Failed to re-serialize snapshot: {}", e))?;
            crate::paths::write_secure(&path.to_string_lossy(), json)
                .map_err(|e| format!("Failed to rewrite snapshot {}: {}", path.display(), e))?;
            rewritten += 1;
        }
    }
    Ok(rewritten)
}

#[cfg(test)]
mod existing_config_compatibility_tests {
    use super::*;

    /// A real pre-upgrade `/etc/wolfstack/backups.json`, shaped like the one
    /// found on wolf1: one PBS schedule and one history entry, written by a
    /// version that had never heard of fleet scope or credential redaction.
    const V25_6_7_BACKUPS_JSON: &str = r#"{
      "schedules": [
        {
          "id": "b3f1c2de-0000-4444-8888-abcdef012345",
          "name": "Nightly",
          "frequency": "daily",
          "time": "02:00",
          "retention": 7,
          "backup_all": true,
          "targets": [],
          "storage": {
            "type": "pbs",
            "pbs_server": "node3.dreamhosting.at:8007",
            "pbs_datastore": "store1",
            "pbs_user": "backup@pbs",
            "pbs_password": "hunter2",
            "pbs_fingerprint": "aa:bb:cc"
          },
          "enabled": true,
          "last_run": "2026-07-30T08:21:00Z",
          "created_at": "2026-07-30T08:19:56Z"
        }
      ],
      "entries": [
        {
          "id": "entry-1",
          "target": { "type": "docker", "name": "web" },
          "storage": {
            "type": "pbs",
            "pbs_server": "node3.dreamhosting.at:8007",
            "pbs_datastore": "store1",
            "pbs_password": "hunter2"
          },
          "filename": "web-20260730.tar.gz",
          "size_bytes": 1234,
          "created_at": "2026-07-30T08:21:00Z",
          "status": "completed"
        }
      ]
    }"#;

    /// The upgrade must not change how an existing config is understood. This
    /// is the guard against the whole class of "it worked until they upgraded".
    #[test]
    fn an_existing_config_still_loads_with_every_value_intact() {
        let cfg: BackupConfig = serde_json::from_str(V25_6_7_BACKUPS_JSON)
            .expect("a config written before this release must still load");

        assert_eq!(cfg.schedules.len(), 1);
        let s = &cfg.schedules[0];
        assert_eq!(s.id, "b3f1c2de-0000-4444-8888-abcdef012345", "ids must be stable");
        assert_eq!(s.name, "Nightly");
        assert_eq!(s.time, "02:00");
        assert_eq!(s.retention, 7);
        assert!(s.backup_all);
        assert!(s.enabled);
        assert_eq!(s.last_run, "2026-07-30T08:21:00Z", "freshness clock preserved");
        assert_eq!(s.created_at, "2026-07-30T08:19:56Z");
        // The credential is still THERE on disk — redaction is a display
        // concern. A schedule that lost its password on upgrade would fail at
        // 02:00 with an auth error.
        assert_eq!(s.storage.pbs_password, "hunter2");
        assert_eq!(s.storage.pbs_server, "node3.dreamhosting.at:8007");
        assert_eq!(s.storage.pbs_datastore, "store1");
        // Fields this release did not add still default sanely.
        assert_eq!(s.pre_command, "");
        assert_eq!(s.storage.pbs_target_id, "", "absent field → primary connection");

        assert_eq!(cfg.entries.len(), 1);
        assert_eq!(cfg.entries[0].storage.pbs_password, "hunter2");
    }

    /// Re-saving an untouched config must not drop or alter anything — the
    /// permissions change is a mode change, not a content change.
    #[test]
    fn re_saving_an_existing_config_preserves_every_field() {
        let cfg: BackupConfig = serde_json::from_str(V25_6_7_BACKUPS_JSON).unwrap();
        let round_tripped: BackupConfig =
            serde_json::from_str(&serde_json::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(round_tripped.schedules.len(), cfg.schedules.len());
        assert_eq!(round_tripped.entries.len(), cfg.entries.len());
        let a = &cfg.schedules[0];
        let b = &round_tripped.schedules[0];
        assert_eq!(a.id, b.id);
        assert_eq!(a.storage.pbs_password, b.storage.pbs_password);
        assert_eq!(a.storage.pbs_server, b.storage.pbs_server);
        assert_eq!(a.last_run, b.last_run);
        assert_eq!(a.created_at, b.created_at);
    }

    /// Removal must be an explicit operator action and nothing else. A config
    /// that mentions some OTHER server has to come through a removal untouched.
    #[test]
    fn removing_one_server_leaves_an_unrelated_one_alone() {
        let cfg: BackupConfig = serde_json::from_str(V25_6_7_BACKUPS_JSON).unwrap();
        let unrelated = BackupServerRef {
            server: "pbs.somewhere-else.example".into(),
            datastore: String::new(),
        };
        assert!(!storage_references_server(&cfg.schedules[0].storage, &unrelated));
        assert!(!storage_references_server(&cfg.entries[0].storage, &unrelated));
    }
}

#[cfg(test)]
mod remove_backup_server_tests {
    use super::*;

    fn pbs(server: &str, datastore: &str, password: &str) -> BackupStorage {
        BackupStorage {
            storage_type: StorageType::Pbs,
            pbs_server: server.into(),
            pbs_datastore: datastore.into(),
            pbs_password: password.into(),
            pbs_user: "backup@pbs".into(),
            ..BackupStorage::default()
        }
    }

    /// The operator will type whichever form they remember. All of these name
    /// the server that was left behind in production.
    #[test]
    fn a_server_is_matched_however_it_is_written() {
        let stored = pbs("node3.dreamhosting.at:8007", "store1", "hunter2");
        for typed in [
            "node3.dreamhosting.at",
            "node3.dreamhosting.at:8007",
            "https://node3.dreamhosting.at:8007",
            "https://node3.dreamhosting.at:8007/",
            "NODE3.DreamHosting.AT",
            "root@node3.dreamhosting.at:8007",
        ] {
            let target = BackupServerRef { server: typed.into(), datastore: String::new() };
            assert!(
                storage_references_server(&stored, &target),
                "{} should match the stored server", typed,
            );
        }
    }

    #[test]
    fn a_different_server_is_not_matched() {
        let stored = pbs("node3.dreamhosting.at:8007", "store1", "hunter2");
        let target = BackupServerRef { server: "pbs.newhost.example".into(), datastore: String::new() };
        assert!(!storage_references_server(&stored, &target));
        // An empty target must never match everything — that would wipe the lot.
        let empty = BackupServerRef { server: "  ".into(), datastore: String::new() };
        assert!(!storage_references_server(&stored, &empty));
    }

    #[test]
    fn a_datastore_narrows_the_match() {
        let a = pbs("nas.example", "store1", "p");
        let b = pbs("nas.example", "store2", "p");
        let target = BackupServerRef { server: "nas.example".into(), datastore: "store1".into() };
        assert!(storage_references_server(&a, &target));
        assert!(!storage_references_server(&b, &target), "other datastores on the same host survive");
    }

    #[test]
    fn nfs_and_smb_servers_are_matched_through_the_path() {
        let mut nfs = BackupStorage { storage_type: StorageType::Nfs, ..BackupStorage::default() };
        nfs.path = "nas.example:/volume1/backups".into();
        let mut smb = BackupStorage { storage_type: StorageType::Smb, ..BackupStorage::default() };
        smb.path = "//nas.example/backups".into();
        let target = BackupServerRef { server: "nas.example".into(), datastore: String::new() };
        assert!(storage_references_server(&nfs, &target));
        assert!(storage_references_server(&smb, &target));
    }

    /// Scrubbing keeps the record of WHERE a backup went and drops only the
    /// credential — deleting history to fix a leak destroys an audit trail.
    #[test]
    fn scrubbing_a_storage_block_keeps_location_and_drops_secrets() {
        let mut s = pbs("node3.dreamhosting.at:8007", "store1", "hunter2");
        s.pbs_token_secret = "tok".into();
        s.secret_key = "sk".into();
        assert!(scrub_storage_secrets(&mut s));
        assert_eq!(s.pbs_password, "");
        assert_eq!(s.pbs_token_secret, "");
        assert_eq!(s.secret_key, "");
        assert_eq!(s.pbs_server, "node3.dreamhosting.at:8007", "history still says where it went");
        assert_eq!(s.pbs_datastore, "store1");
        assert_eq!(s.pbs_user, "backup@pbs", "the user is not a credential");
        // Idempotent: a second scrub changes nothing and reports so.
        assert!(!scrub_storage_secrets(&mut s));
    }

    #[test]
    fn snapshot_scrubbing_only_touches_the_removed_server() {
        let mut snapshot = serde_json::json!({
            "backups": {
                "schedules": [
                    { "name": "old", "storage": {
                        "pbs_server": "node3.dreamhosting.at:8007",
                        "pbs_password": "hunter2", "pbs_datastore": "store1" } },
                    { "name": "new", "storage": {
                        "pbs_server": "pbs.newhost.example",
                        "pbs_password": "keepme", "pbs_datastore": "store1" } }
                ]
            }
        });
        let changed = scrub_value_for_host(&mut snapshot, &host_of("node3.dreamhosting.at:8007"));
        assert!(changed);
        let scheds = &snapshot["backups"]["schedules"];
        assert_eq!(scheds[0]["storage"]["pbs_password"], "", "removed server's password gone");
        assert_eq!(scheds[0]["storage"]["pbs_server"], "node3.dreamhosting.at:8007");
        assert_eq!(scheds[1]["storage"]["pbs_password"], "keepme",
            "the server we still use keeps its credentials");
    }

    #[test]
    fn snapshot_scrubbing_is_idempotent() {
        let mut snapshot = serde_json::json!({
            "storage": { "pbs_server": "nas.example", "pbs_password": "p" }
        });
        let host = host_of("nas.example");
        assert!(scrub_value_for_host(&mut snapshot, &host), "first pass changes it");
        assert!(!scrub_value_for_host(&mut snapshot, &host), "second pass is a no-op");
    }

    #[test]
    fn a_report_with_nothing_to_do_is_a_noop() {
        assert!(ServerRemovalReport::default().is_noop());
        let r = ServerRemovalReport { history_entries_scrubbed: 1, ..Default::default() };
        assert!(!r.is_noop());
    }

    #[test]
    fn removing_without_a_server_name_is_rejected() {
        let target = BackupServerRef { server: "   ".into(), datastore: String::new() };
        assert!(remove_backup_server(&target, false).is_err());
    }
}

/// Blank credential fields in any object that also names `host`. Returns true
/// if anything changed.
fn scrub_value_for_host(value: &mut serde_json::Value, host: &str) -> bool {
    let mut changed = false;
    match value {
        serde_json::Value::Object(map) => {
            // Does THIS object reference the host? Check the fields a server
            // name can live in, plus a bare `path` for NFS/SMB.
            let references = ["pbs_server", "endpoint", "remote_url", "path", "server"]
                .iter()
                .any(|k| map.get(*k)
                    .and_then(|v| v.as_str())
                    .map(|s| host_of(s.trim_start_matches('/')) == host)
                    .unwrap_or(false));
            if references {
                for (key, val) in map.iter_mut() {
                    if crate::secrets::is_secret_field(key)
                        && let serde_json::Value::String(s) = val
                            && !s.is_empty() {
                                s.clear();
                                changed = true;
                            }
                }
            }
            for (_k, val) in map.iter_mut() {
                if scrub_value_for_host(val, host) { changed = true; }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                if scrub_value_for_host(item, host) { changed = true; }
            }
        }
        _ => {}
    }
    changed
}

/// Fill empty fields on `storage` from a saved destination.
///
/// Pure and separated from disk access so the inheritance order —
/// per-backup value, then destination, then primary connection — is
/// unit-testable. Getting this order wrong sends someone's backup to
/// the wrong datastore, which is the exact failure this feature is
/// supposed to prevent.
fn apply_pbs_target(storage: &mut BackupStorage, target: &PbsTarget) {
    if storage.pbs_server.is_empty()      { storage.pbs_server      = target.pbs_server.clone(); }
    if storage.pbs_datastore.is_empty()   { storage.pbs_datastore   = target.pbs_datastore.clone(); }
    if storage.pbs_user.is_empty()        { storage.pbs_user        = target.pbs_user.clone(); }
    if storage.pbs_token_name.is_empty()  { storage.pbs_token_name  = target.pbs_token_name.clone(); }
    if storage.pbs_token_secret.is_empty(){ storage.pbs_token_secret= target.pbs_token_secret.clone(); }
    if storage.pbs_password.is_empty()    { storage.pbs_password    = target.pbs_password.clone(); }
    if storage.pbs_fingerprint.is_empty() { storage.pbs_fingerprint = target.pbs_fingerprint.clone(); }
    if storage.pbs_namespace.is_empty()   { storage.pbs_namespace   = target.pbs_namespace.clone(); }
    // The destination's file-level choice counts as an explicit one for
    // any backup that didn't make its own — otherwise a target set to
    // pxar would be overridden by an off-by-default primary connection.
    if !storage.pbs_file_level_set && target.pbs_file_level_set {
        storage.pbs_file_level = target.pbs_file_level;
        storage.pbs_file_level_set = true;
    }
}

/// A PBS destination with every inherited field resolved, ready to
/// build a repository string from.
///
/// `pbs_target_id` is deliberately left empty while merging: the
/// target's fields are applied from the value in hand, so re-looking
/// it up on disk would be redundant — and would break `test_pbs_target`
/// for a destination the operator is testing BEFORE saving it, which
/// is precisely when testing is most useful. The id is stamped on
/// afterwards.
pub fn resolve_pbs_target(target: &PbsTarget) -> BackupStorage {
    let mut storage = BackupStorage {
        storage_type: StorageType::Pbs,
        ..BackupStorage::default()
    };
    apply_pbs_target(&mut storage, target);
    merge_pbs_secrets(&mut storage);
    storage.pbs_target_id = target.id.clone();
    storage
}

/// Prove a destination works before anyone schedules a backup to it.
/// Uses the same snapshot listing the primary connection's test uses,
/// so a wrong datastore name fails here rather than at 3am.
pub fn test_pbs_target(target: &PbsTarget) -> Result<usize, String> {
    let storage = resolve_pbs_target(target);
    if storage.pbs_server.is_empty() {
        return Err("No PBS server — set one on this destination or on the primary connection".into());
    }
    if storage.pbs_datastore.is_empty() {
        return Err("No datastore set for this destination".into());
    }
    let snapshots = list_pbs_snapshots(&storage)?;
    Ok(snapshots.as_array().map(|a| a.len()).unwrap_or(0))
}

/// Save PBS configuration
pub fn save_pbs_config(storage: &BackupStorage) -> Result<(), String> {
    let path = "/etc/wolfstack/pbs/config.json";
    fs::create_dir_all("/etc/wolfstack/pbs")
        .map_err(|e| format!("Failed to create PBS config dir: {}", e))?;
    let json = serde_json::to_string_pretty(storage)
        .map_err(|e| format!("Failed to serialize PBS config: {}", e))?;
    // 0600 — this file holds `pbs_token_secret` and `pbs_password`. A plain
    // fs::write left it at the umask's mercy, the same way backups.json shipped
    // world-readable. `save_pbs_targets` next door already does this.
    crate::paths::write_secure(path, json)
        .map_err(|e| format!("Failed to write PBS config: {}", e))?;
    Ok(())
}

// ─── Proxmox Config Translation (for migration) ───

/// Parse a Proxmox VE VM .conf file into a WolfStack-compatible JSON config
/// Proxmox format: key: value (one per line), with comments starting with #
#[allow(dead_code)]
pub fn proxmox_conf_to_vm_config(conf: &str, vm_name: &str) -> serde_json::Value {
    let mut cpus: u32 = 1;
    let mut memory_mb: u32 = 1024;
    let mut disk_size_gb: u32 = 10;
    let mut net_model = "virtio".to_string();
    let mut os_disk_bus = "virtio".to_string();
    let mut iso_path: Option<String> = None;

    for line in conf.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }

        let key = parts[0].trim();
        let value = parts[1].trim();

        match key {
            "cores" => { cpus = value.parse().unwrap_or(1); },
            "sockets" => {
                let sockets: u32 = value.parse().unwrap_or(1);
                cpus *= sockets; // total = cores * sockets
            },
            "memory" => { memory_mb = value.parse().unwrap_or(1024); },
            "ide0" | "ide1" | "ide2" | "scsi0" | "sata0" | "virtio0" => {
                // Parse disk: local:vm-100-disk-0,size=32G
                if !value.contains("media=cdrom") {
                    for part in value.split(',') {
                        if part.starts_with("size=") {
                            let size_str = part.trim_start_matches("size=");
                            disk_size_gb = size_str.trim_end_matches('G')
                                .trim_end_matches('T')
                                .parse().unwrap_or(10);
                            if size_str.ends_with('T') {
                                disk_size_gb *= 1024;
                            }
                        }
                    }
                    // Detect bus type from key
                    if key.starts_with("ide") || key.starts_with("sata") { os_disk_bus = "ide".to_string(); } // QEMU maps sata to ide
                    else if key.starts_with("scsi") { os_disk_bus = "scsi".to_string(); }
                    else { os_disk_bus = "virtio".to_string(); }
                }
                // Check for ISO (cdrom)
                if value.contains("media=cdrom") {
                    let iso = value.split(',').next().unwrap_or("");
                    if !iso.is_empty() && iso != "none" {
                        iso_path = Some(iso.to_string());
                    }
                }
            },
            "net0" => {
                // Parse network: virtio=XX:XX:XX:XX:XX:XX,bridge=vmbr0
                if value.starts_with("virtio") { net_model = "virtio".to_string(); }
                else if value.starts_with("e1000") { net_model = "e1000".to_string(); }
                else if value.starts_with("rtl8139") { net_model = "rtl8139".to_string(); }
            },
            _ => {}
        }
    }

    serde_json::json!({
        "name": vm_name,
        "cpus": cpus,
        "memory_mb": memory_mb,
        "disk_size_gb": disk_size_gb,
        "running": false,
        "auto_start": false,
        "os_disk_bus": os_disk_bus,
        "net_model": net_model,
        "iso_path": iso_path,
        "extra_disks": [],
        "source": "proxmox"
    })
}

/// Parse a Proxmox LXC .conf into key info for recreation
#[allow(dead_code)]
pub fn proxmox_lxc_conf_to_config(conf: &str) -> serde_json::Value {
    let mut hostname = String::new();
    let mut memory_mb: u32 = 512;
    let mut cpus: u32 = 1;
    let mut rootfs_size = String::new();
    let mut net_config = String::new();
    let mut ostype = "ubuntu".to_string();

    for line in conf.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }

        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 { continue; }

        let key = parts[0].trim();
        let value = parts[1].trim();

        match key {
            "hostname" => { hostname = value.to_string(); },
            "memory" => { memory_mb = value.parse().unwrap_or(512); },
            "cores" => { cpus = value.parse().unwrap_or(1); },
            "rootfs" => {
                for part in value.split(',') {
                    if part.starts_with("size=") {
                        rootfs_size = part.trim_start_matches("size=").to_string();
                    }
                }
            },
            "net0" => { net_config = value.to_string(); },
            "ostype" => { ostype = value.to_string(); },
            _ => {}
        }
    }

    serde_json::json!({
        "hostname": hostname,
        "memory_mb": memory_mb,
        "cpus": cpus,
        "rootfs_size": rootfs_size,
        "net_config": net_config,
        "ostype": ostype,
        "source": "proxmox"
    })
}

#[cfg(test)]
mod restore_warning_tests {
    use super::read_hwaddrs;
    use std::io::Write;

    fn write_tmp(content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "wolfstack-hwaddr-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn extracts_every_lxc_net_hwaddr_line() {
        let p = write_tmp(
            "lxc.uts.name = foo\n\
             lxc.net.0.type = veth\n\
             lxc.net.0.hwaddr = 00:16:3e:aa:bb:cc\n\
             lxc.net.1.hwaddr=00:16:3e:DD:EE:FF\n\
             # commented = 11:22:33:44:55:66\n\
             lxc.net.2.type = veth\n",
        );
        let mut macs = read_hwaddrs(p.to_str().unwrap());
        macs.sort();
        let _ = std::fs::remove_file(&p);
        assert_eq!(
            macs,
            vec!["00:16:3e:aa:bb:cc".to_string(), "00:16:3e:dd:ee:ff".to_string()]
        );
    }

    #[test]
    fn returns_empty_for_missing_or_macless_config() {
        // Nonexistent path → empty.
        assert!(read_hwaddrs("/nonexistent/wolfstack/test/config").is_empty());
        // Config without any hwaddr lines → empty.
        let p = write_tmp("lxc.uts.name = bar\nlxc.net.0.type = veth\n");
        let macs = read_hwaddrs(p.to_str().unwrap());
        let _ = std::fs::remove_file(&p);
        assert!(macs.is_empty());
    }

    #[test]
    fn does_not_confuse_other_keys_containing_hwaddr_substring() {
        // Hypothetical comment line + look-alike key. Neither should match.
        let p = write_tmp(
            "# lxc.net.0.hwaddr = ff:ff:ff:ff:ff:ff\n\
             lxc.net.x.hwaddr = aa:bb:cc:dd:ee:ff\n",
        );
        let macs = read_hwaddrs(p.to_str().unwrap());
        let _ = std::fs::remove_file(&p);
        assert!(macs.is_empty(), "matched a non-numeric net index: {:?}", macs);
    }

    #[test]
    fn copy_config_tree_recurses_and_excludes() {
        let base = std::env::temp_dir().join(format!("wolfstack-cfgtree-{}", std::process::id()));
        let src = base.join("src");
        let dest = base.join("dest");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(src.join("router")).unwrap();
        std::fs::create_dir_all(src.join("icon-packs/breeze")).unwrap();
        std::fs::create_dir_all(src.join("config-backups")).unwrap();
        std::fs::write(src.join("router.json"), "{}").unwrap();
        std::fs::write(src.join("router/firewall.json"), "{}").unwrap();
        std::fs::write(src.join("icon-packs/breeze/index.theme"), "x").unwrap();
        std::fs::write(src.join("config-backups/old.tar.gz"), "x").unwrap();

        super::copy_config_tree(&src, &dest, &["icon-packs", "config-backups"]).unwrap();

        assert!(dest.join("router.json").exists(), "top-level file copied");
        assert!(dest.join("router/firewall.json").exists(), "nested file copied recursively");
        assert!(!dest.join("icon-packs").exists(), "icon-packs excluded");
        assert!(!dest.join("config-backups").exists(), "config-backups excluded");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn copy_config_tree_follows_symlinked_file() {
        // A certbot-style symlinked cert (cert.pem -> real file) must be backed
        // up by its CONTENT, not silently skipped.
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join(format!("wolfstack-cfgsym-{}", std::process::id()));
        let src = base.join("src");
        let dest = base.join("dest");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(base.join("real-cert.pem"), "CERTDATA").unwrap();
        symlink(base.join("real-cert.pem"), src.join("cert.pem")).unwrap();

        super::copy_config_tree(&src, &dest, &[]).unwrap();

        assert_eq!(std::fs::read_to_string(dest.join("cert.pem")).unwrap(), "CERTDATA",
            "symlinked cert must be backed up by content");
        let _ = std::fs::remove_dir_all(&base);
    }
}

#[cfg(test)]
mod schedule_hook_tests {
    use super::*;

    /// A schedule with NO targets and backup_all=false runs zero backups —
    /// execute_schedule_run then exercises ONLY the hook path, which is what
    /// makes these tests safe to run anywhere (no docker/tar/storage I/O).
    fn hook_only_schedule(pre: &str, post: &str) -> BackupSchedule {
        BackupSchedule {
            id: "test-schedule-id".to_string(),
            name: "hook-test".to_string(),
            frequency: BackupFrequency::Daily,
            time: "02:00".to_string(),
            retention: 0,
            backup_all: false,
            targets: Vec::new(),
            storage: BackupStorage::default(),
            enabled: true,
            last_run: String::new(),
            created_at: String::new(),
            pre_command: pre.to_string(),
            post_command: post.to_string(),
            day_of_week: None,
            day_of_month: None,
            stop_containers: false,
        }
    }

    #[test]
    fn hook_command_success_returns_output() {
        let out = run_hook_command("pre", "echo mithril", "s", "").unwrap();
        assert!(out.contains("mithril"));
    }

    #[test]
    fn hook_command_failure_reports_exit_code_and_output() {
        let err = run_hook_command("pre", "echo doom >&2; exit 3", "s", "").unwrap_err();
        assert!(err.contains("exit 3"), "missing exit code: {}", err);
        assert!(err.contains("doom"), "missing stderr tail: {}", err);
        assert!(err.starts_with("pre-command failed"), "missing phase: {}", err);
    }

    #[test]
    fn hook_command_exposes_env_vars() {
        // The script itself asserts on the env — non-zero exit fails the test.
        run_hook_command(
            "pre",
            "test \"$WOLFSTACK_SCHEDULE\" = moria && test \"$WOLFSTACK_HOOK_PHASE\" = pre",
            "moria",
            "",
        ).unwrap();
    }

    #[test]
    fn pre_failure_aborts_run_and_records_failed_entry() {
        let s = hook_only_schedule("exit 7", "");
        let (entries, summary) = execute_schedule_run(&s);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, BackupStatus::Failed);
        assert!(entries[0].target.name.contains("(pre-command)"));
        assert_eq!(entries[0].schedule_id, "test-schedule-id");
        assert!(entries[0].filename.is_empty(), "hook entries have no tarball");
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.completed, 0);
        assert!(summary.message.contains("aborted"), "message: {}", summary.message);
    }

    #[test]
    fn post_runs_after_pre_failure_with_aborted_status() {
        // Post asserts it sees WOLFSTACK_BACKUP_STATUS=aborted; if the env or
        // the always-run guarantee broke, post would fail and a SECOND
        // synthetic entry would appear.
        let s = hook_only_schedule("false", "test \"$WOLFSTACK_BACKUP_STATUS\" = aborted");
        let (entries, _) = execute_schedule_run(&s);
        assert_eq!(entries.len(), 1, "post must succeed (only the pre entry): {:?}",
            entries.iter().map(|e| &e.target.name).collect::<Vec<_>>());
    }

    #[test]
    fn post_failure_is_recorded_but_message_stays_normal() {
        let s = hook_only_schedule("", "exit 9");
        let (entries, summary) = execute_schedule_run(&s);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].target.name.contains("(post-command)"));
        assert_eq!(summary.failed, 1);
        assert!(!summary.message.contains("aborted"));
    }

    #[test]
    fn no_hooks_no_targets_is_a_clean_empty_run() {
        let s = hook_only_schedule("", "");
        let (entries, summary) = execute_schedule_run(&s);
        assert!(entries.is_empty());
        assert_eq!(summary.total, 0);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn post_sees_completed_status_when_nothing_failed() {
        let s = hook_only_schedule("", "test \"$WOLFSTACK_BACKUP_STATUS\" = completed");
        let (entries, _) = execute_schedule_run(&s);
        assert!(entries.is_empty(), "post asserting status=completed must pass: {:?}",
            entries.iter().map(|e| &e.error).collect::<Vec<_>>());
    }
}

#[cfg(test)]
mod staging_cleanup_tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ws-staging-test-{}-{}", name, Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn dropping_a_guard_removes_a_partial_archive() {
        let dir = scratch("partial");
        let archive = dir.join("lxc-db-20260727-000000.tar.gz");
        {
            let staged = StagedPath::new(archive.clone());
            // Stand in for tar writing part of an archive and then failing.
            fs::write(staged.path(), vec![0u8; 4096]).unwrap();
            assert!(archive.exists());
        }
        assert!(!archive.exists(), "a failed backup must not leave its partial archive behind");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn keeping_a_guard_preserves_a_finished_archive() {
        let dir = scratch("keep");
        let archive = dir.join("lxc-db-20260727-000001.tar.gz");
        let kept = {
            let staged = StagedPath::new(archive.clone());
            fs::write(staged.path(), b"complete").unwrap();
            staged.keep()
        };
        assert_eq!(kept, archive);
        assert!(archive.exists(), "a successful backup must keep its archive for upload");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dropping_a_guard_removes_a_whole_work_directory() {
        let dir = scratch("workdir");
        let work = dir.join("docker-work-abc");
        {
            let staged = StagedPath::new(work.clone());
            fs::create_dir_all(staged.path().join("volumes")).unwrap();
            fs::write(work.join("image.tar.gz"), vec![0u8; 2048]).unwrap();
        }
        assert!(!work.exists(), "a failed docker backup must not strand its image export");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_guard_registers_and_releases_its_path() {
        let dir = scratch("active");
        let archive = dir.join("vm-win-20260727.tar.gz");
        {
            let _staged = StagedPath::new(archive.clone());
            assert!(ACTIVE_STAGING.lock().unwrap().contains(&archive),
                "an in-flight backup must be visible to the sweeper so it is skipped");
        }
        assert!(!ACTIVE_STAGING.lock().unwrap().contains(&archive),
            "a finished backup must not leak a registry entry");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tar_failure_leaves_nothing_behind() {
        // The real leak, end to end: tar exits non-zero after writing part of
        // an archive. Before the fix that partial file stayed in staging, one
        // per failed run, until someone noticed the disk was full.
        let dir = scratch("tarfail");
        let src = dir.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("payload.bin"), vec![7u8; 512 * 1024]).unwrap();
        let archive = dir.join("out.tar.gz");

        let result = tar_path_to_gz("/definitely/not/a/real/path/xyz", &archive);
        assert!(result.is_err(), "tar over a missing source must report failure");
        assert!(!archive.exists(), "a failed tar must not leave a partial archive in staging");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweeper_spares_fresh_and_active_entries() {
        // Nothing here is a day old, so the sweeper must leave it all alone —
        // including a file an in-flight backup is still writing.
        let dir = scratch("sweep");
        let fresh = dir.join("fresh.tar.gz");
        fs::write(&fresh, b"in progress").unwrap();
        let _staged = StagedPath::new(fresh.clone());
        assert!(fresh.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod vzdump_cleanup_tests {
    use super::*;

    #[test]
    fn purge_removes_only_this_containers_debris() {
        let dir = std::env::temp_dir().join(format!("ws-vzdump-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();

        let keep = dir.join("vzdump-lxc-105-2026_07_27-03_00_00.tar.zst");
        let partial = dir.join("vzdump-lxc-105-2026_07_27-02_00_00.tar.zst");
        let other_ct = dir.join("vzdump-lxc-106-2026_07_27-03_00_00.tar.zst");
        let unrelated = dir.join("lxc-web-20260727-030000.tar.gz");
        for f in [&keep, &partial, &other_ct, &unrelated] {
            fs::write(f, b"x").unwrap();
        }

        purge_vzdump_leftovers(&dir, "105", Some(keep.as_path()));

        assert!(keep.exists(), "the archive we are about to upload must survive");
        assert!(!partial.exists(), "a failed run's partial archive must be removed");
        assert!(other_ct.exists(), "another container's backup must not be touched");
        assert!(unrelated.exists(), "non-vzdump files must not be touched");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn purge_spares_an_in_flight_backup() {
        let dir = std::env::temp_dir().join(format!("ws-vzdump-active-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        let in_flight = dir.join("vzdump-lxc-105-2026_07_27-04_00_00.tar.zst");
        fs::write(&in_flight, b"still writing").unwrap();

        let _guard = StagedPath::new(in_flight.clone());
        purge_vzdump_leftovers(&dir, "105", None);

        assert!(in_flight.exists(), "a registered in-flight archive must never be purged");
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod sweeper_tests {
    use super::*;

    /// Backdate a path so the sweeper sees it as abandoned. Uses `touch`
    /// rather than pulling in a crate just to set an mtime in a test.
    fn age_out(path: &Path) {
        let status = Command::new("touch")
            .arg("-d").arg("3 days ago")
            .arg(path)
            .status()
            .expect("touch must be available to run this test");
        assert!(status.success(), "failed to backdate {}", path.display());
    }

    #[test]
    fn sweeper_removes_abandoned_work_but_spares_fresh_and_active() {
        let dir = std::env::temp_dir().join(format!("ws-sweep-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();

        let abandoned = dir.join("lxc-db-20260101-000000.tar.gz");
        fs::write(&abandoned, vec![0u8; 8192]).unwrap();
        age_out(&abandoned);

        let abandoned_dir = dir.join("docker-work-dead");
        fs::create_dir_all(&abandoned_dir).unwrap();
        fs::write(abandoned_dir.join("image.tar.gz"), vec![0u8; 4096]).unwrap();
        age_out(&abandoned_dir);

        let fresh = dir.join("lxc-db-20260727-030000.tar.gz");
        fs::write(&fresh, b"just written").unwrap();

        // Old, but a running backup owns it — must survive regardless of age.
        let old_but_running = dir.join("vm-win-20260101-000000.tar.gz");
        fs::write(&old_but_running, vec![0u8; 1024]).unwrap();
        age_out(&old_but_running);
        let _guard = StagedPath::new(old_but_running.clone());

        let (count, bytes) = sweep_staging_dir(&dir);

        assert!(!abandoned.exists(), "an abandoned archive must be reclaimed");
        assert!(!abandoned_dir.exists(), "an abandoned work dir must be reclaimed");
        assert!(fresh.exists(), "a recent file must not be touched");
        assert!(old_but_running.exists(), "an in-flight backup must never be swept");
        assert_eq!(count, 2);
        assert!(bytes >= 8192, "reclaimed bytes should account for the archive");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweeping_a_missing_directory_is_harmless() {
        let missing = std::env::temp_dir().join(format!("ws-sweep-absent-{}", Uuid::new_v4().simple()));
        assert_eq!(sweep_staging_dir(&missing), (0, 0));
    }
}

/// Day-pinned weekly/monthly schedules (JJ 2026-08-19: "when you select Backup
/// Frequency — weekly or monthly you don't get to choose the day it will run").
///
/// These exercise `schedule_is_due` directly: no config on disk, no docker, no
/// tar, so they run anywhere. The unpinned cases are the regression guard —
/// every schedule saved before these fields existed carries `None` and must
/// behave exactly as it did before.
#[cfg(test)]
mod schedule_day_tests {
    use super::*;
    use chrono::TimeZone;

    fn at(y: i32, m: u32, d: u32, hh: u32, mm: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, hh, mm, 0).unwrap()
    }

    fn schedule(frequency: BackupFrequency) -> BackupSchedule {
        BackupSchedule {
            id: "sched".to_string(),
            name: "test".to_string(),
            frequency,
            time: "02:00".to_string(),
            retention: 0,
            backup_all: false,
            targets: Vec::new(),
            storage: BackupStorage::default(),
            enabled: true,
            last_run: String::new(),
            created_at: String::new(),
            pre_command: String::new(),
            post_command: String::new(),
            day_of_week: None,
            day_of_month: None,
            stop_containers: false,
        }
    }

    #[test]
    fn lxc_freeze_target_matches_only_the_exact_freeze_invocation() {
        // The invocation the pre-v25.20.x backup path spawned, both as the
        // bare name and the PATH-resolved binary.
        assert_eq!(lxc_freeze_target(&["lxc-freeze", "-n", "legolas"]), Some("legolas"));
        assert_eq!(lxc_freeze_target(&["/usr/bin/lxc-freeze", "-n", "legolas"]), Some("legolas"));
        // Anything else — different tool, extra flags, missing name — is
        // NOT ours to kill.
        assert_eq!(lxc_freeze_target(&["lxc-unfreeze", "-n", "legolas"]), None);
        assert_eq!(lxc_freeze_target(&["lxc-freeze", "-n"]), None);
        assert_eq!(lxc_freeze_target(&["lxc-freeze", "--name=legolas"]), None);
        assert_eq!(lxc_freeze_target(&["lxc-freeze", "-n", "legolas", "-q"]), None);
        assert_eq!(lxc_freeze_target(&["grep", "-n", "lxc-freeze"]), None);
        assert_eq!(lxc_freeze_target(&[]), None);
    }

    #[test]
    fn a_disabled_or_off_time_schedule_is_never_due() {
        let mut s = schedule(BackupFrequency::Daily);
        s.enabled = false;
        assert!(!schedule_is_due(&s, at(2026, 8, 17, 2, 0)));
        s.enabled = true;
        assert!(schedule_is_due(&s, at(2026, 8, 17, 2, 0)));
        assert!(!schedule_is_due(&s, at(2026, 8, 17, 2, 1)));
    }

    #[test]
    fn weekly_pinned_to_monday_fires_only_on_monday() {
        let mut s = schedule(BackupFrequency::Weekly);
        s.day_of_week = Some(1); // Monday, ISO
        assert!(schedule_is_due(&s, at(2026, 8, 17, 2, 0)), "Monday must fire");
        assert!(!schedule_is_due(&s, at(2026, 8, 18, 2, 0)), "Tuesday must not fire");
        s.day_of_week = Some(7); // Sunday
        assert!(!schedule_is_due(&s, at(2026, 8, 17, 2, 0)));
        assert!(schedule_is_due(&s, at(2026, 8, 16, 2, 0)), "Sunday must fire");
    }

    #[test]
    fn a_pinned_weekly_schedule_stays_on_its_weekday_after_a_late_run() {
        // The drift this fixes: an unpinned weekly schedule uses a rolling
        // 7×24h window, so a run that started a minute late pushes the next one
        // to the following DAY, and a week later it has walked across the week.
        let mut s = schedule(BackupFrequency::Weekly);
        s.last_run = at(2026, 8, 17, 2, 1).to_rfc3339(); // last Monday, a minute late
        let next_monday = at(2026, 8, 24, 2, 0);
        assert!(!schedule_is_due(&s, next_monday), "unpinned: 6d23h59m — drifts to Tuesday");
        s.day_of_week = Some(1);
        assert!(schedule_is_due(&s, next_monday), "pinned: fires on Monday regardless");
    }

    #[test]
    fn a_pinned_weekly_schedule_runs_once_on_its_day() {
        let mut s = schedule(BackupFrequency::Weekly);
        s.day_of_week = Some(1);
        s.last_run = at(2026, 8, 17, 2, 0).to_rfc3339();
        // Same Monday (the minute matcher can only fire once, but a restart
        // inside that minute must not double-run).
        assert!(!schedule_is_due(&s, at(2026, 8, 17, 2, 0)));
        assert!(schedule_is_due(&s, at(2026, 8, 24, 2, 0)), "next Monday");
    }

    #[test]
    fn unpinned_weekly_and_monthly_keep_their_original_behaviour() {
        let mut weekly = schedule(BackupFrequency::Weekly);
        weekly.last_run = at(2026, 8, 17, 2, 0).to_rfc3339();
        assert!(!schedule_is_due(&weekly, at(2026, 8, 23, 2, 0)), "6 days — too soon");
        assert!(schedule_is_due(&weekly, at(2026, 8, 24, 2, 0)), "7 days — due, any weekday");

        let mut monthly = schedule(BackupFrequency::Monthly);
        monthly.last_run = at(2026, 8, 3, 2, 0).to_rfc3339();
        assert!(!schedule_is_due(&monthly, at(2026, 8, 28, 2, 0)), "already ran this month");
        assert!(schedule_is_due(&monthly, at(2026, 9, 1, 2, 0)), "new month — first match wins");
    }

    #[test]
    fn monthly_pinned_to_the_15th_fires_only_on_the_15th() {
        let mut s = schedule(BackupFrequency::Monthly);
        s.day_of_month = Some(15);
        assert!(schedule_is_due(&s, at(2026, 8, 15, 2, 0)));
        assert!(!schedule_is_due(&s, at(2026, 8, 14, 2, 0)));
        assert!(!schedule_is_due(&s, at(2026, 9, 1, 2, 0)));
        s.last_run = at(2026, 8, 15, 2, 0).to_rfc3339();
        assert!(!schedule_is_due(&s, at(2026, 8, 15, 2, 0)), "no second run the same day");
        assert!(schedule_is_due(&s, at(2026, 9, 15, 2, 0)), "next month");
    }

    #[test]
    fn monthly_pinned_past_the_end_of_a_short_month_fires_on_its_last_day() {
        let mut s = schedule(BackupFrequency::Monthly);
        s.day_of_month = Some(31);
        // February 2026 has 28 days — the 28th is the run day, not "skip February".
        assert!(schedule_is_due(&s, at(2026, 2, 28, 2, 0)));
        assert!(!schedule_is_due(&s, at(2026, 2, 27, 2, 0)));
        // A leap February moves it to the 29th.
        assert!(schedule_is_due(&s, at(2028, 2, 29, 2, 0)));
        assert!(!schedule_is_due(&s, at(2028, 2, 28, 2, 0)));
        // A 31-day month still fires on the 31st.
        assert!(schedule_is_due(&s, at(2026, 3, 31, 2, 0)));
        assert!(!schedule_is_due(&s, at(2026, 3, 30, 2, 0)));
    }

    #[test]
    fn days_in_month_covers_every_month_length() {
        assert_eq!(days_in_month(2026, 1), 31);
        assert_eq!(days_in_month(2026, 2), 28);
        assert_eq!(days_in_month(2028, 2), 29);
        assert_eq!(days_in_month(2026, 4), 30);
        assert_eq!(days_in_month(2026, 12), 31);
        assert_eq!(effective_day_of_month(31, at(2026, 2, 10, 0, 0)), 28);
        assert_eq!(effective_day_of_month(15, at(2026, 2, 10, 0, 0)), 15);
        // Out-of-range values are clamped rather than skipping the month
        // outright — the API rejects them at save time, so this only ever
        // guards a hand-edited backups.json.
        assert_eq!(effective_day_of_month(0, at(2026, 2, 10, 0, 0)), 1);
        assert_eq!(effective_day_of_month(99, at(2026, 4, 10, 0, 0)), 30);
    }

    /// The whole point of JJ's first report: what the operator ticked has to
    /// survive the trip to disk and back. `save_config`/`load_config` are plain
    /// serde over this struct, so a JSON round trip is the persistence contract.
    #[test]
    fn a_schedule_round_trips_its_day_pinning_and_cold_backup_flags() {
        let mut s = schedule(BackupFrequency::Weekly);
        s.day_of_week = Some(3);
        s.backup_all = true;
        s.stop_containers = true;
        let json = serde_json::to_string(&s).unwrap();
        let back: BackupSchedule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.day_of_week, Some(3));
        assert!(back.stop_containers);

        // And a schedule written before these fields existed still loads, with
        // the pre-existing behaviour (no pinned day, live container backups).
        let legacy = r#"{"id":"x","name":"old","frequency":"daily","time":"02:00",
            "retention":7,"backup_all":true,"storage":{"type":"local"},"enabled":true}"#;
        let old: BackupSchedule = serde_json::from_str(legacy).unwrap();
        assert_eq!(old.day_of_week, None);
        assert_eq!(old.day_of_month, None);
        assert!(!old.stop_containers);
    }

    /// Per-target cold-backup flags survive the same round trip — this is the
    /// path that already worked, kept honest so a future refactor can't quietly
    /// drop the field again.
    #[test]
    fn a_target_round_trips_its_stop_for_backup_flag() {
        let t = BackupTarget {
            target_type: BackupTargetType::Docker,
            name: "plex".to_string(),
            stop_for_backup: true,
            ..Default::default()
        };
        let back: BackupTarget = serde_json::from_str(&serde_json::to_string(&t).unwrap()).unwrap();
        assert!(back.stop_for_backup);
        assert_eq!(back.target_type, BackupTargetType::Docker);
    }
}

#[cfg(test)]
mod large_mount_tests {
    use super::*;

    fn override_for(kind: BackupTargetType, name: &str, excludes: &[&str]) -> BackupTarget {
        BackupTarget {
            target_type: kind,
            name: name.to_string(),
            exclude_mounts: excludes.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    /// JJ 2026-09-18: a "back up everything" schedule's per-container mount
    /// exclusions have to reach the container they were set on — and only it.
    #[test]
    fn backup_all_overrides_apply_by_type_and_name() {
        let overrides = vec![
            override_for(BackupTargetType::Docker, "nextcloud", &["/mnt/media"]),
            override_for(BackupTargetType::Lxc, "nextcloud", &["/mnt/lxc-array"]),
            override_for(BackupTargetType::Docker, "plain", &[]),
        ];
        assert_eq!(
            mount_overrides_for(&overrides, &BackupTargetType::Docker, "nextcloud"),
            vec!["/mnt/media".to_string()],
        );
        // Same name, other type: its own override, never the Docker one.
        assert_eq!(
            mount_overrides_for(&overrides, &BackupTargetType::Lxc, "nextcloud"),
            vec!["/mnt/lxc-array".to_string()],
        );
        // An override with nothing excluded, and a container with no override
        // at all, both archive in full.
        assert!(mount_overrides_for(&overrides, &BackupTargetType::Docker, "plain").is_empty());
        assert!(mount_overrides_for(&overrides, &BackupTargetType::Docker, "other").is_empty());
        assert!(mount_overrides_for(&[], &BackupTargetType::Docker, "nextcloud").is_empty());
    }

    /// The overrides ride in `targets` next to `backup_all: true` — the same
    /// JSON the schedule editor already re-reads to show "(1 excluded)", so
    /// this is the persistence contract for both directions.
    #[test]
    fn a_backup_all_schedule_round_trips_its_mount_overrides() {
        let json = r#"{"id":"x","name":"all","frequency":"daily","time":"02:00",
            "retention":7,"backup_all":true,"storage":{"type":"local"},"enabled":true,
            "targets":[{"type":"docker","name":"nextcloud","exclude_mounts":["/mnt/media"]}]}"#;
        let s: BackupSchedule = serde_json::from_str(json).unwrap();
        assert!(s.backup_all);
        assert_eq!(
            mount_overrides_for(&s.targets, &BackupTargetType::Docker, "nextcloud"),
            vec!["/mnt/media".to_string()],
        );
        let back: BackupSchedule = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back.targets[0].exclude_mounts, vec!["/mnt/media".to_string()]);
    }

    fn mount(basis: &str, size: u64, fs_used: u64) -> DiscoveredMount {
        DiscoveredMount {
            mount_type: "bind".into(),
            source: "/mnt/data".into(),
            destination: "/data".into(),
            size_bytes: size,
            size_basis: basis.into(),
            fs_used_bytes: fs_used,
            data_path: "/mnt/data".into(),
        }
    }

    const GIB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn measured_mounts_warn_only_past_the_threshold() {
        assert!(!mount_is_large(&mount("walked", 2 * GIB, 0)));
        assert!(!mount_is_large(&mount("walked", LARGE_MOUNT_WARN_BYTES - 1, 0)));
        assert!(mount_is_large(&mount("walked", LARGE_MOUNT_WARN_BYTES, 0)));
        assert!(mount_is_large(&mount("filesystem", 20_000 * GIB, 20_000 * GIB)));
    }

    /// The 20 TB array case: `du` cannot finish, so the mount's own size is
    /// unknown and the filesystem's used bytes are the only figure. Warn on it.
    /// The inverse matters just as much — an unmeasurable mount on a small
    /// filesystem CANNOT be large, and warning about it would be noise.
    #[test]
    fn unmeasurable_mounts_warn_only_on_a_large_filesystem() {
        assert!(mount_is_large(&mount("unknown", 0, 20_000 * GIB)));
        assert!(!mount_is_large(&mount("unknown", 0, 3 * GIB)));
        // Nothing measurable AND no filesystem behind it: silence. Found by
        // running the check against live containers, where every volume
        // directory the process could not stat looked like a 20 TB array.
        assert!(!mount_is_large(&mount("unknown", 0, 0)));
    }

    /// A mount source that is not on this host holds nothing — never a warning,
    /// however little we know about it.
    #[test]
    fn absent_sources_are_never_large() {
        assert!(!mount_is_large(&mount("missing", 0, 0)));
        assert!(!mount_is_large(&mount("missing", 0, 20_000 * GIB)));
    }

    /// A Proxmox storage-backed volume has no host path to walk, so the size
    /// its config declares is the figure — provisioned, and treated as the
    /// upper bound it is.
    #[test]
    fn declared_volume_sizes_are_used() {
        assert!(!mount_is_large(&mount("declared", 8 * GIB, 0)));
        assert!(mount_is_large(&mount("declared", 800 * GIB, 0)));
    }

    #[test]
    fn size_basis_survives_the_api_round_trip() {
        let json = serde_json::to_string(&mount("filesystem", 7 * GIB, 9 * GIB)).unwrap();
        assert!(json.contains("\"size_basis\":\"filesystem\""));
        assert!(json.contains("\"fs_used_bytes\""));
        // Internal plumbing stays out of the browser's copy.
        assert!(!json.contains("data_path"), "{}", json);
    }

    /// `df --output=used,target` puts the number first precisely so a mount
    /// point containing spaces still parses.
    #[test]
    fn filesystem_usage_reads_the_root_filesystem() {
        let (mountpoint, used) = filesystem_usage("/").expect("df knows about /");
        assert_eq!(mountpoint, "/");
        assert!(used > 0);
    }

    /// The bounded walk returns a real figure for a small tree, and the
    /// mountpoint shortcut avoids walking a filesystem root at all.
    #[test]
    fn sizing_is_bounded_and_takes_the_filesystem_shortcut() {
        let dir = std::env::temp_dir().join(format!(
            "wolfstack-mount-size-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("payload"), vec![7u8; 4096]).unwrap();
        let walked = dir_size_bytes_within(
            dir.to_str().unwrap(),
            std::time::Duration::from_secs(MOUNT_SIZE_DEADLINE_SECS),
        );
        let _ = fs::remove_dir_all(&dir);
        assert!(walked.unwrap_or(0) >= 4096, "{:?}", walked);

        // "/" is its own mount point, so this must come back from df, not du.
        let (bytes, basis, fs_used) = measure_mount_size("/");
        assert_eq!(basis, "filesystem");
        assert!(bytes > 0);
        assert_eq!(bytes, fs_used);

        // A path that is not there is reported as absent — not as an
        // unmeasurable mount, which would warn about nothing.
        assert_eq!(measure_mount_size("/nonexistent-wolfstack-test-path"), (0, "missing", 0));
    }
}

#[cfg(test)]
mod target_label_tests {
    use super::*;

    fn target(t: BackupTargetType, name: &str) -> BackupTarget {
        BackupTarget { target_type: t, name: name.to_string(), ..Default::default() }
    }

    #[test]
    fn a_named_target_logs_its_name() {
        assert_eq!(target_log_label(&target(BackupTargetType::Lxc, "100")), "100");
        assert_eq!(target_log_label(&target(BackupTargetType::Docker, "web")), "web");
    }

    /// The config target carries no name by design, and the scheduled-run log
    /// used to render it as `Backup  → PBS` — a blank subject on the last line
    /// of every nightly run.
    #[test]
    fn the_config_target_is_never_blank() {
        let label = target_log_label(&target(BackupTargetType::Config, ""));
        assert!(!label.trim().is_empty());
        assert_eq!(label, "WolfStack config");
    }

    #[test]
    fn an_unnamed_system_path_falls_back_to_its_path() {
        let mut t = target(BackupTargetType::SystemPath, "");
        t.system_path = "/srv/data".to_string();
        assert_eq!(target_log_label(&t), "/srv/data");
        // Nothing to fall back to — still not blank.
        let bare = target(BackupTargetType::SystemPath, "");
        assert!(!target_log_label(&bare).trim().is_empty());
    }

    #[test]
    fn no_target_type_ever_renders_blank() {
        for t in [BackupTargetType::Docker, BackupTargetType::Lxc, BackupTargetType::Vm,
                  BackupTargetType::Config, BackupTargetType::SystemPath] {
            let label = target_log_label(&target(t.clone(), ""));
            assert!(!label.trim().is_empty(), "{:?} rendered blank", t);
        }
    }
}

#[cfg(test)]
mod vzdump_output_tests {
    use super::collect_vzdump_output;

    #[test]
    fn malformed_utf8_does_not_hide_a_later_archive_path() {
        let (tx, rx) = std::sync::mpsc::channel();
        let output = b"good\r\n\xff\ncreating archive '/path/archive.tar.zst'\n";
        let captured = collect_vzdump_output(std::io::Cursor::new(output), &tx);
        assert_eq!(captured, "good\ncreating archive '/path/archive.tar.zst'\n");
        assert_eq!(rx.try_iter().collect::<Vec<_>>(), vec![
            "  good", "  creating archive '/path/archive.tar.zst'",
        ]);
    }

    #[test]
    fn persistent_read_error_stops_and_reports_once() {
        struct FailingReader<'a>(&'a std::cell::Cell<usize>);
        impl std::io::Read for FailingReader<'_> {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                self.0.set(self.0.get() + 1);
                assert_eq!(self.0.get(), 1, "must not retry a persistent read error");
                Err(std::io::Error::other("pipe read failed"))
            }
        }
        let reads = std::cell::Cell::new(0);
        let (tx, rx) = std::sync::mpsc::channel();
        let captured = collect_vzdump_output(std::io::BufReader::new(FailingReader(&reads)), &tx);
        assert!(captured.is_empty());
        assert_eq!(reads.get(), 1);
        assert_eq!(rx.try_iter().collect::<Vec<_>>(), vec![
            "  Failed to read vzdump output: pipe read failed",
        ]);
    }
}
