// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! /boot partition health — kernel-sized free-space headroom and
//! orphaned-kernel detection.
//!
//! ## Why this module exists (wolf1, 2026-08-01)
//!
//! The legacy rule ("skip /boot unless >99 % used", `collect_issues`
//! and later `threshold::should_skip_disk`) alerted only once /boot
//! was already effectively full. On wolf1 a 975 MB /boot accumulated
//! nine kernels and hit 100 %: the operator's first signal was not a
//! warning but a broken host — dpkg failed mid-unpack leaving 21
//! packages half-installed (systemd, dbus, libc-bin, pve-manager
//! among them). Worse, at zero free bytes the obvious remediation
//! (purge a kernel) runs `update-grub`, which can write a truncated
//! `grub.cfg` and leave the machine unbootable.
//!
//! So: alert while there is still **room to act**. The threshold is
//! sized from the filesystem itself — the largest installed kernel
//! set (vmlinuz + initrd + System.map + config for one version) is
//! measured from /boot, and we want at least two of those free:
//! one for the next kernel the distro will unpack, and one of slack
//! so the purge/regenerate cycle never runs at zero bytes.
//!
//! ## The root cause branch: orphaned kernels
//!
//! wolf1's pile could never be `apt autoremove`d because the RUNNING
//! kernel had no owning package at all — the package was removed
//! while that kernel was booted, stranding its files in /boot with
//! no handle for the package manager. We detect that explicitly:
//! every kernel image in /boot is resolved to its owning package
//! (dpkg or rpm), and images with no *installed* owner are reported,
//! with a special callout when one of them is the running kernel.
//!
//! ## Placement
//!
//! This is a predictive analyzer (5-min tick) rather than a security
//! check: it's capacity/lifecycle, not posture. Severity High fires
//! the notification channels via the first-appearance dispatch —
//! that's the "with room to act" part. The old >99 % rule lived in a
//! path whose alert loop had already been retired (main.rs threshold
//! loop, `triggered` permanently empty), which is why wolf1 saw
//! nothing at all.

use std::collections::HashMap;
use std::time::Duration;

use crate::predictive::{
    Context,
    proposal::{
        Evidence, Proposal, ProposalScope, RemediationPlan, Severity,
    },
    ack::AckStore,
};

pub const FINDING_BOOT_SPACE: &str = "boot_partition_low_space";
pub const FINDING_BOOT_ORPHANS: &str = "boot_orphaned_kernels";

/// Whether a kernel image file in /boot has an owning package that
/// is actually installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelOwnership {
    /// A package owns the file and that package's status word is
    /// `installed`.
    Owned,
    /// No package owns the file, or the owning package is no longer
    /// in `installed` state (removed-but-not-purged). Either way the
    /// package manager has no working handle on this kernel.
    Orphaned,
    /// No dpkg/rpm on this host, or the query failed — we don't
    /// know, so we say nothing rather than guess.
    Unknown,
}

/// Everything the analyzer needs, gathered up front by the sampler
/// so `analyze()` itself touches no filesystem and no subprocess —
/// which is what makes the decision logic unit-testable.
#[derive(Debug, Clone, Default)]
pub struct BootFacts {
    /// True only when /boot is its own mounted filesystem. A /boot
    /// that's just a directory on / is sized by the root-disk checks.
    pub present: bool,
    pub total_bytes: u64,
    pub avail_bytes: u64,
    /// (file name, size in bytes) for every regular file in /boot.
    pub files: Vec<(String, u64)>,
    /// Contents of /proc/sys/kernel/osrelease, e.g. "6.8.12-1-pve".
    pub running_kernel: Option<String>,
    /// kernel-image file name → ownership, resolved by the sampler.
    pub ownership: HashMap<String, KernelOwnership>,
}

/// Sample /boot state. `df` (not statvfs) for consistency with
/// `disk_fill::sample_disks_now_async`, and because a hung network
/// mount elsewhere can't stall a targeted `df /boot`. The whole
/// sampler is timeout-bounded by the orchestrator's join.
pub async fn sample_now_async(timeout: Duration) -> BootFacts {
    let fut = tokio::task::spawn_blocking(sample_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(f)) => f,
        _ => BootFacts::default(),
    }
}

fn sample_now() -> BootFacts {
    // `df <path>` reports the filesystem CONTAINING the path; the
    // target column tells us whether /boot is its own mount. Only a
    // real /boot partition gets this analysis.
    let df = match std::process::Command::new("df")
        .args(["-B1", "--output=target,size,avail", "/boot"])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return BootFacts::default(),
    };
    let (total_bytes, avail_bytes) = match parse_df_boot(&df) {
        Some(t) => t,
        None => return BootFacts::default(),
    };

    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/boot") {
        for e in entries.flatten() {
            if let Ok(meta) = e.metadata() && meta.is_file() {
                files.push((e.file_name().to_string_lossy().to_string(), meta.len()));
            }
        }
    }

    let running_kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Resolve ownership for each kernel image (not every file — a
    // 9-kernel /boot would mean ~36 dpkg calls for the same answer
    // the images alone give us).
    let mut ownership = HashMap::new();
    for (name, _) in &files {
        if kernel_image_version(name).is_some() {
            ownership.insert(name.clone(), query_ownership(&format!("/boot/{}", name)));
        }
    }

    BootFacts { present: true, total_bytes, avail_bytes, files, running_kernel, ownership }
}

/// Parse `df -B1 --output=target,size,avail /boot`. Returns
/// (total, avail) only when the containing mount IS /boot.
fn parse_df_boot(text: &str) -> Option<(u64, u64)> {
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 { continue; }
        if cols[0] != "/boot" { return None; }
        let total: u64 = cols[1].parse().ok()?;
        let avail: u64 = cols[2].parse().ok()?;
        return Some((total, avail));
    }
    None
}

/// If `name` is a kernel image file, return the kernel version it
/// carries. Debian/Proxmox install `vmlinuz-<ver>`; some arches use
/// `vmlinux-<ver>`. (RHEL also uses `vmlinuz-<ver>`.)
pub fn kernel_image_version(name: &str) -> Option<&str> {
    for prefix in ["vmlinuz-", "vmlinux-"] {
        if let Some(v) = name.strip_prefix(prefix) && !v.is_empty() {
            return Some(v);
        }
    }
    None
}

/// Map any /boot file name to the kernel version it belongs to, or
/// None for non-kernel files (grub directories are filtered out by
/// the is_file() gate; loose files like `memtest86+x64.bin` land
/// here as None and are ignored).
///
/// Name shapes, verified against real /boot listings:
///   Debian/Proxmox:  vmlinuz-<v>  initrd.img-<v>  System.map-<v>  config-<v>
///   RHEL-family:     vmlinuz-<v>  initramfs-<v>.img  System.map-<v>  config-<v>
pub fn kernel_file_version(name: &str) -> Option<&str> {
    if let Some(v) = kernel_image_version(name) { return Some(v); }
    for prefix in ["initrd.img-", "System.map-", "config-"] {
        if let Some(v) = name.strip_prefix(prefix) && !v.is_empty() {
            return Some(v);
        }
    }
    if let Some(rest) = name.strip_prefix("initramfs-")
        && let Some(v) = rest.strip_suffix(".img")
        && !v.is_empty()
    {
        return Some(v);
    }
    None
}

/// Group /boot files into per-kernel-version byte totals. Only
/// versions that have an actual kernel image count as a "kernel
/// set" — a stray initrd with no vmlinuz is leftover data, not an
/// installable kernel's footprint.
pub fn kernel_sets(files: &[(String, u64)]) -> HashMap<String, u64> {
    let mut sizes: HashMap<String, u64> = HashMap::new();
    let mut has_image: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (name, size) in files {
        if let Some(v) = kernel_file_version(name) {
            *sizes.entry(v.to_string()).or_insert(0) += size;
            if kernel_image_version(name).is_some() {
                has_image.insert(v.to_string());
            }
        }
    }
    sizes.retain(|v, _| has_image.contains(v));
    sizes
}

/// The decision core, pure so the wolf1 scenario is a unit test.
#[derive(Debug, Clone, Default)]
pub struct BootAssessment {
    /// None = healthy. Some(sev) = the space finding fires.
    pub space_severity: Option<Severity>,
    /// 2 × largest kernel set — the free-space floor. 0 when /boot
    /// carries no kernels (fallback >99 % rule applied instead).
    pub needed_bytes: u64,
    pub largest_set_bytes: u64,
    pub kernel_count: usize,
    /// Kernel image file names with no installed owning package.
    pub orphaned_images: Vec<String>,
    /// True when the RUNNING kernel's image is among the orphans —
    /// the exact wolf1 root cause.
    pub running_kernel_orphaned: bool,
}

pub fn evaluate(facts: &BootFacts) -> BootAssessment {
    let sets = kernel_sets(&facts.files);
    let largest = sets.values().copied().max().unwrap_or(0);
    let needed = largest.saturating_mul(2);

    let space_severity = if largest > 0 {
        if facts.avail_bytes < largest {
            // Not even one kernel's worth free: the very next kernel
            // update fails mid-unpack (wolf1's end state).
            Some(Severity::Critical)
        } else if facts.avail_bytes < needed {
            Some(Severity::High)
        } else {
            None
        }
    } else {
        // No kernels on this /boot (unusual layout). Fall back to
        // the historical intent: only a nearly-full /boot is a
        // problem, but now it actually notifies.
        let used_pct = if facts.total_bytes > 0 {
            100.0 * (facts.total_bytes - facts.avail_bytes) as f64 / facts.total_bytes as f64
        } else { 0.0 };
        if used_pct > 99.0 { Some(Severity::High) } else { None }
    };

    let mut orphaned_images: Vec<String> = facts.ownership.iter()
        .filter(|(_, o)| **o == KernelOwnership::Orphaned)
        .map(|(name, _)| name.clone())
        .collect();
    orphaned_images.sort();

    let running_kernel_orphaned = match &facts.running_kernel {
        Some(ver) => orphaned_images.iter().any(|img|
            kernel_image_version(img) == Some(ver.as_str())),
        None => false,
    };

    BootAssessment {
        space_severity,
        needed_bytes: needed,
        largest_set_bytes: largest,
        kernel_count: sets.len(),
        orphaned_images,
        running_kernel_orphaned,
    }
}

// ── Package ownership (dpkg / rpm) ──────────────────────────────

/// Resolve whether an installed package owns `path`.
///
/// dpkg: `dpkg-query -S <path>` prints "pkg1, pkg2: pathname" per
/// dpkg-query(1) (--search output format), exit 1 when nothing
/// matches. A match is NOT enough: a removed-but-not-purged package
/// still appears in the file database, so each owner is then checked
/// with `dpkg-query -W -f=${db:Status-Status}` — the package status
/// word (dpkg-query(1), since dpkg 1.17.11) — which must be exactly
/// `installed`.
///
/// rpm: `rpm -qf <path>` exits 0 only when an installed package owns
/// the file (the rpm database only contains installed packages), so
/// no second query is needed.
fn query_ownership(path: &str) -> KernelOwnership {
    if binary_exists("dpkg-query") {
        let out = match std::process::Command::new("dpkg-query")
            .args(["-S", path]).output()
        {
            Ok(o) => o,
            Err(_) => return KernelOwnership::Unknown,
        };
        if !out.status.success() {
            // Exit 1 = "no file or package found" per dpkg-query(1).
            return KernelOwnership::Orphaned;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let owners = parse_dpkg_search_owners(&stdout, path);
        if owners.is_empty() { return KernelOwnership::Orphaned; }
        for pkg in owners {
            let st = std::process::Command::new("dpkg-query")
                .args(["-W", "-f=${db:Status-Status}", &pkg]).output();
            if let Ok(o) = st
                && o.status.success()
                && String::from_utf8_lossy(&o.stdout).trim() == "installed"
            {
                return KernelOwnership::Owned;
            }
        }
        return KernelOwnership::Orphaned;
    }
    if binary_exists("rpm") {
        return match std::process::Command::new("rpm").args(["-qf", path]).output() {
            Ok(o) if o.status.success() => KernelOwnership::Owned,
            Ok(_) => KernelOwnership::Orphaned,
            Err(_) => KernelOwnership::Unknown,
        };
    }
    KernelOwnership::Unknown
}

/// Parse `dpkg-query -S` output for the packages owning exactly
/// `path`. Format per dpkg-query(1): "pkgname1, pkgname2: pathname".
/// Diversion lines ("diversion by ... from/to: path") are skipped —
/// they describe a rename, not ownership.
pub fn parse_dpkg_search_owners(stdout: &str, path: &str) -> Vec<String> {
    let mut owners = Vec::new();
    for line in stdout.lines() {
        if line.starts_with("diversion by ") { continue; }
        if let Some((pkgs, matched_path)) = line.rsplit_once(": ")
            && matched_path.trim() == path
        {
            for p in pkgs.split(',') {
                // "pkg:arch" qualifiers pass through dpkg-query -W fine.
                let p = p.trim();
                if !p.is_empty() { owners.push(p.to_string()); }
            }
        }
    }
    owners
}

fn binary_exists(name: &str) -> bool {
    ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]
        .iter()
        .any(|d| std::path::Path::new(d).join(name).exists())
}

// ── Analyzer ────────────────────────────────────────────────────

fn human_mb(bytes: u64) -> String {
    format!("{:.0} MB", bytes as f64 / (1024.0 * 1024.0))
}

pub fn analyze(
    ctx: &Context,
    facts: &BootFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    if !facts.present { return Vec::new(); }
    // Same operator toggle as the generic disk checks (threshold.rs
    // loads it the same way): /boot findings are disk findings.
    if !crate::alerting::AlertConfig::load().alert_disk { return Vec::new(); }

    let a = evaluate(facts);
    let mut out = Vec::new();
    let scope = || ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some("/boot".into()),
    };

    // ── Space finding ──
    if let Some(sev) = a.space_severity {
        let s = scope();
        if !acks.suppresses(FINDING_BOOT_SPACE, &s)
            && !proposals.is_suppressed(FINDING_BOOT_SPACE, &s)
        {
            let (title, why) = if a.largest_set_bytes > 0 {
                (
                    format!(
                        "/boot has {} free — less than {} kernel{}' worth",
                        human_mb(facts.avail_bytes),
                        if facts.avail_bytes < a.largest_set_bytes { "one" } else { "two" },
                        if facts.avail_bytes < a.largest_set_bytes { "" } else { "s" },
                    ),
                    format!(
                        "/boot has {} free of {}, holding {} kernel version(s); the largest \
                         kernel set (vmlinuz + initrd + System.map + config) is {}. A kernel \
                         update needs at least that much free to unpack, and the cleanup that \
                         follows (`update-grub` / initramfs regeneration) needs headroom of its \
                         own — at ZERO free bytes a kernel purge can write a truncated grub.cfg \
                         and leave this machine unbootable. dpkg failing mid-unpack here leaves \
                         packages half-installed (seen live: 21 packages including systemd and \
                         libc-bin). Act now, while there is still room to act safely.",
                        human_mb(facts.avail_bytes), human_mb(facts.total_bytes),
                        a.kernel_count, human_mb(a.largest_set_bytes),
                    ),
                )
            } else {
                (
                    format!("/boot is {} full", human_mb(facts.total_bytes - facts.avail_bytes)),
                    format!(
                        "/boot has {} free of {} and holds no recognisable kernel images — \
                         something else is filling it. A full /boot breaks every future \
                         kernel and bootloader update.",
                        human_mb(facts.avail_bytes), human_mb(facts.total_bytes),
                    ),
                )
            };
            out.push(Proposal::new_rule(
                FINDING_BOOT_SPACE, sev,
                title, why,
                vec![
                    Evidence {
                        label: "Free".into(),
                        value: human_mb(facts.avail_bytes),
                        detail: Some(format!(
                            "{} total; floor is {} (2× largest kernel set of {})",
                            human_mb(facts.total_bytes),
                            human_mb(a.needed_bytes),
                            human_mb(a.largest_set_bytes),
                        )),
                        links: Vec::new(),
                    },
                    Evidence {
                        label: "Kernels".into(),
                        value: format!("{}", a.kernel_count),
                        detail: None,
                        links: Vec::new(),
                    },
                ],
                RemediationPlan::Manual {
                    instructions:
                        "Remove old kernels the SAFE way. 1) If /boot is at or near zero \
                         free bytes, first move (not delete) one OLD kernel's initrd off the \
                         partition to create working room — never run a kernel purge at zero \
                         bytes, because the update-grub it triggers can truncate grub.cfg. \
                         2) Purge old kernel packages (keep the running kernel and one \
                         fallback). 3) Verify grub.cfg is intact before any reboot. If \
                         `apt autoremove` reports nothing to do despite the pile, the \
                         kernels are likely orphaned from their packages — see the \
                         companion orphaned-kernels finding."
                        .into(),
                    commands: vec![
                        "df -B1M /boot && ls -lS /boot | head -20".into(),
                        "uname -r    # NEVER remove this version".into(),
                        "mv /boot/initrd.img-<oldest-version> /root/   # only if free space is ~0".into(),
                        "apt purge linux-image-<oldest-version>    # Debian/Proxmox".into(),
                        "test -s /boot/grub/grub.cfg && grep -c menuentry /boot/grub/grub.cfg   # must be >0 before rebooting".into(),
                    ],
                },
                s,
            ));
        }
    }

    // ── Orphaned kernels finding ──
    if !a.orphaned_images.is_empty() {
        let s = scope();
        if !acks.suppresses(FINDING_BOOT_ORPHANS, &s)
            && !proposals.is_suppressed(FINDING_BOOT_ORPHANS, &s)
        {
            // Orphans block the normal cleanup path, so they escalate
            // to High whenever space is also tight; on a roomy /boot
            // they're Warn-level hygiene.
            let sev = if a.space_severity.is_some() { Severity::High } else { Severity::Warn };
            let list = a.orphaned_images.join(", ");
            let mut why = format!(
                "{} kernel image(s) in /boot have no installed owning package: {}. \
                 The package manager has no handle on these files — `apt autoremove` \
                 will never reclaim them, so they accumulate until /boot fills.",
                a.orphaned_images.len(), list,
            );
            if a.running_kernel_orphaned {
                why.push_str(&format!(
                    " The RUNNING kernel ({}) is one of them — its package was removed \
                     while it was booted, which is how this situation usually starts. \
                     Reinstall a matching kernel package so future updates and removals \
                     go through the package manager again.",
                    facts.running_kernel.as_deref().unwrap_or("?"),
                ));
            }
            out.push(Proposal::new_rule(
                FINDING_BOOT_ORPHANS, sev,
                format!("{} orphaned kernel(s) in /boot", a.orphaned_images.len()),
                why,
                vec![Evidence {
                    label: "Orphaned images".into(),
                    value: format!("{}", a.orphaned_images.len()),
                    detail: Some(list),
                    links: Vec::new(),
                }],
                RemediationPlan::Manual {
                    instructions:
                        "For each orphaned version that is NOT the running kernel: delete \
                         its files (vmlinuz-, initrd.img-, System.map-, config-<version>) \
                         from /boot, then regenerate the boot menu — but only with free \
                         space available (see the /boot space finding for the safe order). \
                         For the RUNNING kernel: reinstall its package (Proxmox: \
                         `apt install proxmox-kernel-<version>`; Debian: \
                         `apt install linux-image-<version>`) so it is managed again."
                        .into(),
                    commands: vec![
                        "uname -r".into(),
                        "for k in /boot/vmlinuz-*; do dpkg -S \"$k\" >/dev/null 2>&1 || echo \"ORPHAN: $k\"; done".into(),
                        "update-grub    # after cleanup, with free space verified".into(),
                    ],
                },
                s,
            ));
        }
    }

    out
}

/// Covered scopes for auto-resolve: whenever /boot was sampled this
/// tick, both finding types are covered — a cleaned-up /boot then
/// auto-resolves its proposals.
pub fn covered_scopes(ctx: &Context, facts: &BootFacts) -> Vec<(String, ProposalScope)> {
    if !facts.present { return Vec::new(); }
    let scope = || ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some("/boot".into()),
    };
    vec![
        (FINDING_BOOT_SPACE.into(), scope()),
        (FINDING_BOOT_ORPHANS.into(), scope()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Debian-style kernel set totalling ~100 MB.
    fn kernel_set(ver: &str, image_mb: u64, initrd_mb: u64) -> Vec<(String, u64)> {
        vec![
            (format!("vmlinuz-{}", ver), image_mb * 1024 * 1024),
            (format!("initrd.img-{}", ver), initrd_mb * 1024 * 1024),
            (format!("System.map-{}", ver), 4 * 1024 * 1024),
            (format!("config-{}", ver), 256 * 1024),
        ]
    }

    fn mb(n: u64) -> u64 { n * 1024 * 1024 }

    // ── name parsing ──

    #[test]
    fn parses_debian_kernel_file_names() {
        assert_eq!(kernel_image_version("vmlinuz-6.8.12-1-pve"), Some("6.8.12-1-pve"));
        assert_eq!(kernel_file_version("initrd.img-6.8.12-1-pve"), Some("6.8.12-1-pve"));
        assert_eq!(kernel_file_version("System.map-6.8.12-1-pve"), Some("6.8.12-1-pve"));
        assert_eq!(kernel_file_version("config-6.8.12-1-pve"), Some("6.8.12-1-pve"));
    }

    #[test]
    fn parses_rhel_initramfs_name() {
        assert_eq!(
            kernel_file_version("initramfs-5.14.0-427.13.1.el9_4.x86_64.img"),
            Some("5.14.0-427.13.1.el9_4.x86_64"),
        );
    }

    #[test]
    fn non_kernel_files_are_ignored() {
        assert_eq!(kernel_file_version("memtest86+x64.bin"), None);
        assert_eq!(kernel_file_version("grub"), None);
        assert_eq!(kernel_image_version("vmlinuz-"), None); // empty version
        // A stray initrd with no matching vmlinuz is not a kernel set.
        let files = vec![("initrd.img-9.9.9".to_string(), mb(80))];
        assert!(kernel_sets(&files).is_empty());
    }

    #[test]
    fn kernel_sets_sum_per_version() {
        let mut files = kernel_set("6.8.12-1-pve", 14, 90);
        files.extend(kernel_set("6.8.4-2-pve", 13, 80));
        let sets = kernel_sets(&files);
        assert_eq!(sets.len(), 2);
        assert_eq!(sets["6.8.12-1-pve"], mb(14) + mb(90) + mb(4) + 256 * 1024);
    }

    // ── df parsing ──

    #[test]
    fn df_output_accepted_only_for_real_boot_mount() {
        let own_mount = "Mounted on       1B-blocks      Avail\n/boot           1022611456  102261145\n";
        assert_eq!(parse_df_boot(own_mount), Some((1022611456, 102261145)));
        // /boot on the root fs: df reports target "/" — not a partition.
        let on_root = "Mounted on       1B-blocks      Avail\n/              4294967296 1073741824\n";
        assert_eq!(parse_df_boot(on_root), None);
    }

    // ── dpkg -S parsing ──

    #[test]
    fn dpkg_search_owner_parsed_and_diversions_skipped() {
        let out = "proxmox-kernel-6.8.12-1-pve-signed: /boot/vmlinuz-6.8.12-1-pve\n";
        assert_eq!(
            parse_dpkg_search_owners(out, "/boot/vmlinuz-6.8.12-1-pve"),
            vec!["proxmox-kernel-6.8.12-1-pve-signed".to_string()],
        );
        let multi = "pkg-a, pkg-b: /boot/vmlinuz-1.0\n";
        assert_eq!(parse_dpkg_search_owners(multi, "/boot/vmlinuz-1.0"),
            vec!["pkg-a".to_string(), "pkg-b".to_string()]);
        let diversion = "diversion by dash from: /boot/vmlinuz-1.0\n";
        assert!(parse_dpkg_search_owners(diversion, "/boot/vmlinuz-1.0").is_empty());
        // A hit for a DIFFERENT path must not count.
        let other = "pkg-c: /boot/vmlinuz-2.0\n";
        assert!(parse_dpkg_search_owners(other, "/boot/vmlinuz-1.0").is_empty());
    }

    // ── evaluation ──

    fn facts(files: Vec<(String, u64)>, total: u64, avail: u64) -> BootFacts {
        BootFacts {
            present: true, total_bytes: total, avail_bytes: avail,
            files, running_kernel: None, ownership: HashMap::new(),
        }
    }

    #[test]
    fn healthy_boot_stays_quiet() {
        // One ~108 MB kernel set, 400 MB free: > 2 sets of headroom.
        let f = facts(kernel_set("6.8.12-1-pve", 14, 90), mb(975), mb(400));
        let a = evaluate(&f);
        assert_eq!(a.space_severity, None);
        assert!(a.orphaned_images.is_empty());
    }

    #[test]
    fn below_two_kernel_sets_is_high() {
        // Largest set ≈ 108 MB → floor ≈ 217 MB; 150 MB free → High.
        let f = facts(kernel_set("6.8.12-1-pve", 14, 90), mb(975), mb(150));
        let a = evaluate(&f);
        assert_eq!(a.space_severity, Some(Severity::High));
        assert!(a.needed_bytes > mb(200));
    }

    #[test]
    fn below_one_kernel_set_is_critical() {
        let f = facts(kernel_set("6.8.12-1-pve", 14, 90), mb(975), mb(50));
        assert_eq!(evaluate(&f).space_severity, Some(Severity::Critical));
    }

    /// The wolf1 scenario: 975 MB /boot, nine kernels, zero free,
    /// running kernel orphaned. Must be Critical + orphan callout.
    #[test]
    fn wolf1_scenario_critical_with_running_orphan() {
        let mut files = Vec::new();
        for i in 0..9 {
            files.extend(kernel_set(&format!("6.8.{}-1-pve", i), 13, 85));
        }
        let mut ownership = HashMap::new();
        for i in 0..9 {
            ownership.insert(
                format!("vmlinuz-6.8.{}-1-pve", i),
                if i == 8 { KernelOwnership::Orphaned } else { KernelOwnership::Owned },
            );
        }
        let f = BootFacts {
            present: true,
            total_bytes: mb(975),
            avail_bytes: 0,
            files,
            running_kernel: Some("6.8.8-1-pve".into()),
            ownership,
        };
        let a = evaluate(&f);
        assert_eq!(a.space_severity, Some(Severity::Critical));
        assert_eq!(a.kernel_count, 9);
        assert_eq!(a.orphaned_images, vec!["vmlinuz-6.8.8-1-pve".to_string()]);
        assert!(a.running_kernel_orphaned, "running-kernel orphan must be called out");
    }

    /// Package-owned kernels must be suppressed from the orphan list —
    /// dpkg-owned files never report as orphans.
    #[test]
    fn owned_kernels_are_not_orphans() {
        let mut ownership = HashMap::new();
        ownership.insert("vmlinuz-6.8.12-1-pve".to_string(), KernelOwnership::Owned);
        let f = BootFacts {
            present: true, total_bytes: mb(975), avail_bytes: mb(400),
            files: kernel_set("6.8.12-1-pve", 14, 90),
            running_kernel: Some("6.8.12-1-pve".into()),
            ownership,
        };
        let a = evaluate(&f);
        assert!(a.orphaned_images.is_empty());
        assert!(!a.running_kernel_orphaned);
    }

    /// Unknown ownership (no dpkg/rpm) must not fabricate orphans.
    #[test]
    fn unknown_ownership_reports_nothing() {
        let mut ownership = HashMap::new();
        ownership.insert("vmlinuz-6.8.12-1-pve".to_string(), KernelOwnership::Unknown);
        let f = BootFacts {
            present: true, total_bytes: mb(975), avail_bytes: mb(400),
            files: kernel_set("6.8.12-1-pve", 14, 90),
            running_kernel: None,
            ownership,
        };
        assert!(evaluate(&f).orphaned_images.is_empty());
    }

    #[test]
    fn no_kernels_falls_back_to_99_pct_rule() {
        // ESP-style /boot with no kernels: quiet at 90 %...
        let f = facts(vec![("BOOTX64.EFI".to_string(), mb(1))], mb(1000), mb(100));
        assert_eq!(evaluate(&f).space_severity, None);
        // ...but fires once >99 % used.
        let f = facts(vec![("BOOTX64.EFI".to_string(), mb(1))], mb(1000), mb(5));
        assert_eq!(evaluate(&f).space_severity, Some(Severity::High));
    }

    #[test]
    fn absent_boot_mount_is_ignored() {
        let ctx = Context {
            node_id: "n".into(),
            network: crate::predictive::NetworkSnapshot::from_parts(vec![], vec![]),
        };
        let f = BootFacts::default();
        assert!(!f.present);
        assert!(covered_scopes(&ctx, &f).is_empty());
    }
}
