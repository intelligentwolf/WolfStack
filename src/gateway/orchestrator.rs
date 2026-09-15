// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Per-gateway lifecycle: mount sources → bind to share/ → write
//! daemon configs → reload daemons. Tear-down is the reverse.
//!
//! v1.0 mode is `Single`: exactly one source, bound directly into
//! `share/`. `Failover`/`Aggregate`/`Sharded` are config-modeled but
//! return `unsupported_mode` from `apply` until their phases land.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{nfs, samba, sources, Gateway, GatewayMode, GatewayRuntime, Protocol};

#[derive(Debug)]
pub enum ApplyError {
    Validation(Vec<String>),
    Source(String, sources::SourceError),
    Samba(samba::SambaError),
    Nfs(nfs::NfsError),
    UnsupportedMode(&'static str),
    Io(std::io::Error),
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyError::Validation(v)   => write!(f, "validation failed: {}", v.join("; ")),
            ApplyError::Source(scope, e) => write!(f, "source [{}]: {}", scope, e),
            ApplyError::Samba(e)         => write!(f, "samba: {}", e),
            ApplyError::Nfs(e)           => write!(f, "nfs: {}", e),
            ApplyError::UnsupportedMode(m) => write!(f, "{} mode is reserved for a future release", m),
            ApplyError::Io(e)            => write!(f, "io: {}", e),
        }
    }
}

impl From<std::io::Error> for ApplyError {
    fn from(e: std::io::Error) -> Self { ApplyError::Io(e) }
}

/// Bring a gateway up: mount its source(s), bind to share/, write
/// Samba+NFS configs, reload. Idempotent — calling apply twice is
/// safe and (modulo reload churn) cheap.
pub fn apply(g: &Gateway) -> Result<GatewayRuntime, ApplyError> {
    if g.disabled {
        return Ok(disabled_runtime(g));
    }
    super::validate(g).map_err(ApplyError::Validation)?;

    let share = sources::share_path(&g.id);
    std::fs::create_dir_all(&share)?;

    let mut last_error: Option<String> = None;

    let active_index = match g.mode {
        GatewayMode::Single => {
            // Mount source 0 and bind it to share/.
            let s = &g.sources[0];
            let mounted = sources::mount(&g.id, 0, s)
                .map_err(|e| ApplyError::Source("source-0".into(), e))?;
            // share/ is a bind-mount of the resolved source path so
            // Samba/NFS see a stable path that survives source-mount
            // reconfigs.
            ensure_bind(&mounted, &share)?;
            0
        }
        GatewayMode::Failover  => return Err(ApplyError::UnsupportedMode("failover")),
        GatewayMode::Aggregate => return Err(ApplyError::UnsupportedMode("aggregate")),
        GatewayMode::Sharded   => return Err(ApplyError::UnsupportedMode("sharded")),
    };

    // Daemon configs.
    if g.protocols.contains(&Protocol::Smb) {
        if let Err(e) = samba::write_gateway_snippet(g, &share) {
            return Err(ApplyError::Samba(e));
        }
    } else {
        // Operator removed SMB from the protocol list — clean up.
        let _ = samba::remove_gateway_snippet(&g.id);
    }
    if g.protocols.contains(&Protocol::Nfs) {
        if let Err(e) = nfs::write_gateway_export(g, &share) {
            // NfsError::Skipped is "configured but not exported"
            // (e.g. users/AD auth) — surface but don't fail.
            match e {
                nfs::NfsError::Skipped(reason) => {
                    last_error = Some(format!("nfs skipped: {}", reason));
                }
                other => return Err(ApplyError::Nfs(other)),
            }
        }
    } else {
        let _ = nfs::remove_gateway_export(&g.id);
    }

    Ok(GatewayRuntime {
        gateway_id: g.id.clone(),
        node_id: hostname(),
        serving: true,
        healthy: true,
        active_source_index: active_index,
        last_error,
        last_health_check_unix: now_unix(),
        bytes_in: 0,
        bytes_out: 0,
        active_sessions: 0,
        performance_tier: super::performance_tier(g).into(),
        mount_path: Some(share.to_string_lossy().to_string()),
    })
}

/// Tear down a gateway. Removes daemon configs, unmounts the share/
/// bind, unmounts sources, removes the per-gateway directory tree.
/// Best-effort — errors are logged but never block delete.
pub fn teardown(g: &Gateway) {
    let _ = samba::remove_gateway_snippet(&g.id);
    let _ = nfs::remove_gateway_export(&g.id);
    let share = sources::share_path(&g.id);
    let _ = unmount_force(&share);
    for (i, s) in g.sources.iter().enumerate() {
        let _ = sources::unmount(&g.id, i, s);
    }
    let root = PathBuf::from("/var/lib/wolfstack/gateways").join(&g.id);
    if root.exists() {
        // Don't recursively delete share/ contents — they live on the
        // backing source. Just remove the per-gateway dir; mounts are
        // already detached.
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// Run a quick health check and update the runtime row.
#[allow(dead_code)]
pub fn health_check(g: &Gateway, rt: &mut GatewayRuntime) {
    rt.last_health_check_unix = now_unix();
    if g.disabled {
        rt.serving = false;
        rt.healthy = false;
        return;
    }
    let active_idx = rt.active_source_index;
    let source_ok = sources::health_check(&g.id, active_idx);
    rt.healthy = source_ok;
    if !source_ok {
        rt.last_error = Some("source mount unhealthy".into());
    }
}

// ─── Helpers ───

fn ensure_bind(src: &std::path::Path, dst: &std::path::Path) -> Result<(), ApplyError> {
    use std::process::Command;
    if !dst.exists() { std::fs::create_dir_all(dst)?; }
    // Already bound? If /proc/mounts shows dst, no-op.
    if let Ok(content) = std::fs::read_to_string("/proc/mounts") {
        let dst_str = dst.to_string_lossy().to_string();
        if content.lines().any(|l| {
            let mut it = l.split_whitespace();
            let _ = it.next();
            it.next() == Some(&dst_str)
        }) {
            return Ok(());
        }
    }
    // Recursive + rslave, mirroring the Local source mount: a plain
    // --bind drops filesystems mounted below src (ZFS child datasets
    // arrived at source-0 via its own rbind and must survive this
    // second hop into share/), and rslave stops a later lazy unmount
    // of share/ from back-propagating and unmounting the real nested
    // mounts (see sources::mount). Safe for every source type — for
    // container-backed sources source-0 is a plain bind, so there is
    // nothing extra here for --rbind to pick up.
    let out = Command::new("mount")
        .args(["--rbind", "--make-rslave", &src.to_string_lossy(), &dst.to_string_lossy()])
        .output()?;
    if !out.status.success() {
        return Err(ApplyError::Io(std::io::Error::other(format!(
            "bind mount {} -> {} failed: {}",
            src.display(), dst.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))));
    }
    Ok(())
}

fn unmount_force(p: &std::path::Path) -> std::io::Result<()> {
    use std::process::Command;
    let _ = Command::new("umount").arg("-l").arg(p).status();
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn hostname() -> String {
    hostname::get().ok().and_then(|h| h.into_string().ok()).unwrap_or_default()
}

fn disabled_runtime(g: &Gateway) -> GatewayRuntime {
    GatewayRuntime {
        gateway_id: g.id.clone(),
        node_id: hostname(),
        serving: false,
        healthy: false,
        active_source_index: 0,
        last_error: Some("gateway is disabled".into()),
        last_health_check_unix: now_unix(),
        bytes_in: 0,
        bytes_out: 0,
        active_sessions: 0,
        performance_tier: super::performance_tier(g).into(),
        mount_path: None,
    }
}
