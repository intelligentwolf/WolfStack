// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! Unused-package recommender — surfaces packages the operator can
//! safely remove to reduce attack surface and reclaim disk.
//!
//! Suggested by Klas on Discord 2026-05-06: "if there's nothing
//! installed that uses Python → recommend uninstall Python because
//! of CVEs". The principle is more general — every installed
//! package is a potential CVE target, and many were dragged in as
//! transitive dependencies of something the operator no longer
//! uses.
//!
//! This analyzer takes the distro-blessed answer to "what can I
//! safely uninstall?":
//!
//!   * Debian/Ubuntu — `apt-get -s autoremove`
//!   * RHEL/Fedora/Rocky/Alma — `dnf repoquery --unneeded`
//!   * SUSE — `zypper packages --orphaned`
//!   * Arch — `pacman -Qdtq`
//!
//! and cross-references it with the vulnerability + OSV facts the
//! orchestrator already collects. A Critical finding lights up if
//! any removable package has open CVEs — those are double wins,
//! freeing disk AND retiring CVEs in a single `apt-get autoremove`.
//!
//! Never auto-removes anything. Operator decides; we provide the
//! list, the disk impact, the CVE-retire count, and the exact
//! command to run.

use std::process::Command;
use std::time::Duration;
use std::collections::HashMap;

use crate::predictive::{
    Context,
    ack::AckStore,
    proposal::{
        Evidence, EvidenceLink, Proposal, ProposalScope, RemediationPlan, Severity,
    },
    vulnerability::{detect_host_pm, PackageManager, VulnerabilityFacts},
    osv::OsvFacts,
};

/// `host_*` prefix is intentional — picks up the inbox's HOST 🖥️
/// runtime badge automatically (see `predictiveRuntimeBadge` in
/// web/js/app.js). Don't rename without updating the badge map.
pub const FINDING_TYPE: &str = "host_unused_packages";

/// One package the distro has flagged as removable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovablePackage {
    pub name: String,
    /// Best-effort installed size in MB. `None` when the distro's
    /// autoremove output didn't carry sizes (parser fell back to
    /// "names only" mode). Sum of `Some(_)` values is used for the
    /// "would free X MB" line in the inbox card.
    pub size_mb: Option<u64>,
    /// Number of pending security updates / OSV CVEs that target
    /// this exact package. > 0 means uninstalling retires that
    /// many CVEs in one shot — the most operator-actionable signal
    /// the analyzer produces.
    pub open_cves: u32,
}

#[derive(Debug, Clone, Default)]
pub struct UnusedPackagesFacts {
    /// True iff we successfully ran the distro autoremove command.
    /// False means we should not auto-resolve anything.
    pub scanned: bool,
    pub host_pm: PackageManager,
    pub host_removable: Vec<RemovablePackage>,
}

/// Synchronous probe. Picks the distro autoremove path and parses
/// it; the list is RAW (no CVE cross-ref yet). Cross-ref happens in
/// `analyze` so the analyzer can use the orchestrator's already-
/// collected vulnerability + OSV facts without duplicating the work.
pub fn sample_now() -> UnusedPackagesFacts {
    let pm = detect_host_pm();
    let removable = match pm {
        PackageManager::Apt => sample_apt_autoremove(),
        PackageManager::Dnf | PackageManager::Yum => sample_dnf_unneeded(),
        PackageManager::Zypper => sample_zypper_orphaned(),
        PackageManager::Pacman => sample_pacman_orphans(),
        // apk's dependency graph doesn't have a one-shot "orphans"
        // query; skipping until we wire a graph walker. For Alpine
        // hosts we'll surface no recommendations rather than show
        // a wrong list.
        PackageManager::Apk => Vec::new(),
        PackageManager::None => Vec::new(),
    };
    UnusedPackagesFacts {
        scanned: !matches!(pm, PackageManager::None),
        host_pm: pm,
        host_removable: removable,
    }
}

pub async fn sample_now_async(timeout: Duration) -> UnusedPackagesFacts {
    let fut = tokio::task::spawn_blocking(sample_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(f)) => f,
        _ => UnusedPackagesFacts::default(),
    }
}

// ─── Per-distro autoremove parsers ────────────────────────────────

fn sample_apt_autoremove() -> Vec<RemovablePackage> {
    let out = match Command::new("apt-get")
        .args(["-s", "autoremove"])
        .env("LC_ALL", "C")
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    parse_apt_autoremove(&String::from_utf8_lossy(&out.stdout))
}

/// Parse the output of `apt-get -s autoremove`. Format (LC_ALL=C):
///
/// ```text
/// Reading package lists... Done
/// Building dependency tree... Done
/// Reading state information... Done
/// The following packages will be REMOVED:
///   libfoo libbar python3-baz
/// 0 upgraded, 0 newly installed, 3 to remove and 0 not upgraded.
/// Remv libfoo [1.0]
/// Remv libbar [2.3]
/// Remv python3-baz [4.5]
/// ```
///
/// We keep the package names from the "REMOVED" block and ignore
/// the rest. Sizes aren't in this output (apt's `-s autoremove`
/// doesn't include `--print-uris`-style detail) so size_mb stays
/// None and the inbox card shows count rather than MB. Acceptable
/// trade-off vs. shelling out per-package for `apt-cache show`.
pub fn parse_apt_autoremove(text: &str) -> Vec<RemovablePackage> {
    let mut out = Vec::new();
    let mut in_remove_block = false;
    for line in text.lines() {
        let trimmed = line.trim_end();
        if trimmed.contains("The following packages will be REMOVED:") {
            in_remove_block = true;
            continue;
        }
        if in_remove_block {
            // Block ends at the first non-indented line (the
            // "0 upgraded, …" summary).
            if !line.starts_with(' ') && !line.starts_with('\t') {
                in_remove_block = false;
                continue;
            }
            for name in trimmed.split_whitespace() {
                if name.is_empty() { continue; }
                out.push(RemovablePackage {
                    name: name.to_string(),
                    size_mb: None,
                    open_cves: 0,
                });
            }
        }
    }
    out
}

fn sample_dnf_unneeded() -> Vec<RemovablePackage> {
    // `dnf repoquery --unneeded` lists packages installed as deps
    // that nothing user-installed needs anymore. Equivalent to
    // `dnf autoremove --assumeno` minus the interactive prompt.
    let out = match Command::new("dnf")
        .args(["repoquery", "--unneeded", "--qf", "%{name} %{size}"])
        .env("LC_ALL", "C")
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    parse_dnf_unneeded(&String::from_utf8_lossy(&out.stdout))
}

/// Parse `dnf repoquery --unneeded --qf "%{name} %{size}"`. Each
/// line: `name size_in_bytes`. Lines without a parseable size keep
/// the package but leave size_mb None.
pub fn parse_dnf_unneeded(text: &str) -> Vec<RemovablePackage> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        let mut parts = trimmed.split_whitespace();
        let name = match parts.next() {
            Some(n) => n.to_string(),
            None => continue,
        };
        let size_mb = parts.next()
            .and_then(|s| s.parse::<u64>().ok())
            .map(|bytes| bytes / (1024 * 1024));
        out.push(RemovablePackage {
            name,
            size_mb,
            open_cves: 0,
        });
    }
    out
}

fn sample_zypper_orphaned() -> Vec<RemovablePackage> {
    let out = match Command::new("zypper")
        .args(["--non-interactive", "packages", "--orphaned"])
        .env("LC_ALL", "C")
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    parse_zypper_orphaned(&String::from_utf8_lossy(&out.stdout))
}

/// Parse the pipe-separated table emitted by
/// `zypper packages --orphaned`. Format:
///
/// ```text
/// S | Repository | Name | Version | Arch
/// --+------------+------+---------+-----
/// i+|  | libfoo | 1.0 | x86_64
/// i+|  | python3-baz | 4.5 | noarch
/// ```
///
/// First column is status, third is name. Sizes aren't in this
/// view (would need a second `zypper info` per package).
pub fn parse_zypper_orphaned(text: &str) -> Vec<RemovablePackage> {
    let mut out = Vec::new();
    let mut header_seen = false;
    for line in text.lines() {
        // Skip until past the header divider line.
        if line.contains("---") {
            header_seen = true;
            continue;
        }
        if !header_seen { continue; }
        let cols: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
        if cols.len() < 5 { continue; }
        let name = cols[2];
        if name.is_empty() || name == "Name" { continue; }
        out.push(RemovablePackage {
            name: name.to_string(),
            size_mb: None,
            open_cves: 0,
        });
    }
    out
}

fn sample_pacman_orphans() -> Vec<RemovablePackage> {
    // `pacman -Qdtq` lists orphans (installed as deps, no longer
    // needed by anything). Names only — pull sizes with a second
    // pass via `pacman -Qi NAME` since the CSV form is awkward.
    let names_out = match Command::new("pacman")
        .args(["-Qdtq"])
        .env("LC_ALL", "C")
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let names: Vec<String> = String::from_utf8_lossy(&names_out.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if names.is_empty() { return Vec::new(); }

    // One pacman -Qi run with all names — single fork, sizes for
    // every package returned in one go. Output blocks are key/value
    // separated by blank lines.
    let mut args: Vec<&str> = vec!["-Qi"];
    for n in &names { args.push(n.as_str()); }
    let info_out = match Command::new("pacman")
        .args(&args)
        .env("LC_ALL", "C")
        .output()
    {
        Ok(o) => o,
        _ => return names.into_iter().map(|n| RemovablePackage {
            name: n, size_mb: None, open_cves: 0,
        }).collect(),
    };
    parse_pacman_qi(&String::from_utf8_lossy(&info_out.stdout))
}

/// Parse `pacman -Qi pkg1 pkg2 …` output. Each package is a block
/// of `Key : Value` lines separated by blank lines. We need
/// `Name` and `Installed Size`. Size is a string like
/// `"34.66 MiB"`, `"512.00 KiB"`, `"1.20 GiB"`.
pub fn parse_pacman_qi(text: &str) -> Vec<RemovablePackage> {
    let mut out = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_size: Option<u64> = None;
    let flush = |name: Option<String>, size: Option<u64>, out: &mut Vec<RemovablePackage>| {
        if let Some(n) = name {
            out.push(RemovablePackage { name: n, size_mb: size, open_cves: 0 });
        }
    };
    for line in text.lines() {
        if line.trim().is_empty() {
            flush(current_name.take(), current_size.take(), &mut out);
            continue;
        }
        let (key, value) = match line.split_once(':') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };
        match key {
            "Name" => current_name = Some(value.to_string()),
            "Installed Size" => current_size = parse_pacman_size(value),
            _ => {}
        }
    }
    // Final block (no trailing blank line).
    flush(current_name, current_size, &mut out);
    out
}

/// Parse pacman's "Installed Size" string: `"34.66 MiB"`,
/// `"512.00 KiB"`, `"1.20 GiB"`. Returns None on unrecognised
/// shapes rather than guessing.
fn parse_pacman_size(s: &str) -> Option<u64> {
    let mut parts = s.split_whitespace();
    let num: f64 = parts.next()?.parse().ok()?;
    let unit = parts.next()?.to_ascii_lowercase();
    let mb = match unit.as_str() {
        "kib" | "kb" | "k" => num / 1024.0,
        "mib" | "mb" | "m" => num,
        "gib" | "gb" | "g" => num * 1024.0,
        "tib" | "tb" | "t" => num * 1024.0 * 1024.0,
        _ => return None,
    };
    Some(mb.round() as u64)
}

// ─── Analyzer (cross-refs with CVE facts) ─────────────────────────

pub fn analyze(
    ctx: &Context,
    facts: &UnusedPackagesFacts,
    vuln_facts: &VulnerabilityFacts,
    osv_facts: &OsvFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    if !facts.scanned || facts.host_removable.is_empty() {
        return Vec::new();
    }

    // Build a per-package CVE count from the orchestrator's already-
    // collected facts. We're explicit about the unit: this is a
    // count of UNIQUE CVE IDs per package, NOT a sum of "security
    // update" entries. Two reasons:
    //
    //   1. Distro-pocket security updates aren't CVE-granular — a
    //      single `apt-get install python3` can cover 5 CVEs and DA
    //      reports it as one update. Counting it as 1 understates
    //      truth.
    //   2. OSV findings ARE CVE-granular — each finding carries the
    //      CVE id(s) via `vuln.cve_ids()`. That's our source of
    //      truth for "how many CVEs would removing this retire".
    //
    // We dedupe within a package (a single OSV finding can carry
    // multiple aliases for the same CVE; we take the canonical
    // first id only). If the operator has OSV scanning disabled
    // (kev_only or scanner off), this count will be 0 and the
    // analyzer falls back to size-driven Warn/Info severity —
    // honest underclaim rather than dishonest overclaim. Using the
    // distro-pocket entries on top would double-count when both
    // OSV and the distro flag the same CVE; we explicitly do NOT.
    let mut cves_by_pkg: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    for f in &osv_facts.findings {
        // Only count host findings — LXC findings live on their own
        // targets and we're not (yet) scanning containers for
        // unused packages.
        if !matches!(f.target, crate::predictive::osv::ScanTargetOwned::Host) { continue; }
        let entry = cves_by_pkg.entry(f.package.clone()).or_default();
        for cve in f.vuln.cve_ids() {
            entry.insert(cve);
        }
        // Findings without any CVE alias (rare — OSV-only IDs) get
        // counted under their OSV id so they're not silently
        // dropped from the retirement total.
        if f.vuln.cve_ids().is_empty() {
            entry.insert(f.vuln.id.clone());
        }
    }
    // Bridge to the existing display field. The `vuln_facts`
    // parameter is kept on the signature for future use (e.g. a
    // distro that DOES expose per-update CVE ids), and silenced
    // here to make the deliberate choice explicit.
    let _ = vuln_facts;

    // Stamp each removable package with its CVE count, then sort by
    // (CVE count desc, size desc) so the most-actionable items
    // surface first in the inbox card.
    let mut enriched: Vec<RemovablePackage> = facts.host_removable.iter().cloned().map(|mut p| {
        p.open_cves = cves_by_pkg.get(&p.name).map(|s| s.len() as u32).unwrap_or(0);
        p
    }).collect();
    enriched.sort_by(|a, b| {
        b.open_cves.cmp(&a.open_cves)
            .then(b.size_mb.unwrap_or(0).cmp(&a.size_mb.unwrap_or(0)))
            .then(a.name.cmp(&b.name))
    });

    let scope = ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some("host:unused-packages".to_string()),
    };
    if acks.suppresses(FINDING_TYPE, &scope) { return Vec::new(); }
    if proposals.is_suppressed(FINDING_TYPE, &scope) { return Vec::new(); }

    Some(build_proposal(&enriched, facts.host_pm, &scope)).into_iter().collect()
}

pub fn covered_scopes(
    ctx: &Context,
    facts: &UnusedPackagesFacts,
) -> Vec<(String, ProposalScope)> {
    if !facts.scanned { return Vec::new(); }
    vec![(FINDING_TYPE.to_string(), ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some("host:unused-packages".to_string()),
    })]
}

const MAX_PACKAGE_ROWS: usize = 12;

fn build_proposal(packages: &[RemovablePackage], pm: PackageManager, scope: &ProposalScope) -> Proposal {
    let total_count = packages.len();
    let total_size: u64 = packages.iter().filter_map(|p| p.size_mb).sum();
    let total_cves: u32 = packages.iter().map(|p| p.open_cves).sum();
    let risky_count = packages.iter().filter(|p| p.open_cves > 0).count();

    // Severity ladder: Critical when any removable package carries
    // open CVEs (free attack-surface reduction); Warn when there's
    // a meaningful disk reclaim or many packages; Info otherwise.
    let severity = if total_cves > 0 {
        Severity::Critical
    } else if total_count >= 30 || total_size >= 1024 {
        Severity::Warn
    } else {
        Severity::Info
    };

    let title = if total_cves > 0 {
        format!(
            "{} unused package{} on host — removing them retires {} open CVE{}",
            total_count, if total_count == 1 { "" } else { "s" },
            total_cves, if total_cves == 1 { "" } else { "s" },
        )
    } else if total_size > 0 {
        format!(
            "{} unused package{} on host — would free ≈{} MB",
            total_count, if total_count == 1 { "" } else { "s" }, total_size,
        )
    } else {
        format!(
            "{} unused package{} on host",
            total_count, if total_count == 1 { "" } else { "s" },
        )
    };

    let why = format!(
        "The host's package manager ({pm}) flagged these as installed but no \
         longer required by anything else on the system — typically transitive \
         dependencies of software the operator has since removed. Each one is \
         disk space the operator isn't using, and an attack-surface CVE \
         target the operator doesn't need. {risk_summary}\n\
         \n\
         WolfStack does not auto-remove anything — package removal can have \
         subtle effects (a script you forgot about uses python3, a service \
         account binary depends on it, etc.). Review the list, then run the \
         command in the remediation panel to remove them all in one shot. \
         The list comes straight from `{pm} {dryrun_cmd}` so anything the \
         distro itself wouldn't auto-remove is not on this list.",
        pm = pm.label(),
        risk_summary = if total_cves > 0 {
            format!(
                "{} of these packages have {} open CVE{} matching them right now — \
                 uninstalling those is a one-step CVE retirement.",
                risky_count,
                total_cves, if total_cves == 1 { "" } else { "s" },
            )
        } else {
            "None of them currently have open CVEs in this host's findings, \
             but reducing surface area pays off pre-emptively.".to_string()
        },
        dryrun_cmd = match pm {
            PackageManager::Apt => "-s autoremove",
            PackageManager::Dnf | PackageManager::Yum => "repoquery --unneeded",
            PackageManager::Zypper => "packages --orphaned",
            PackageManager::Pacman => "-Qdtq",
            _ => "(distro-specific)",
        },
    );

    let mut evidence = vec![
        Evidence {
            label: "Total".into(),
            value: format!("{} package{}", total_count, if total_count == 1 { "" } else { "s" }),
            detail: if total_size > 0 { Some(format!("≈{} MB reclaimable", total_size)) } else { None },
            links: Vec::new(),
        },
    ];
    if total_cves > 0 {
        evidence.push(Evidence {
            label: "CVEs retired".into(),
            value: format!("{} on {} package{}", total_cves, risky_count, if risky_count == 1 { "" } else { "s" }),
            detail: Some("Removing these is the single most attack-surface-reducing action available right now".into()),
            links: Vec::new(),
        });
    }
    for p in packages.iter().take(MAX_PACKAGE_ROWS) {
        let value = match (p.size_mb, p.open_cves) {
            (Some(mb), 0) => format!("{} MB", mb),
            (Some(mb), n) => format!("{} MB · {} CVE{}", mb, n, if n == 1 { "" } else { "s" }),
            (None, 0)     => "—".to_string(),
            (None, n)     => format!("{} CVE{}", n, if n == 1 { "" } else { "s" }),
        };
        let detail = if p.open_cves > 0 {
            Some("Removing retires this package's open CVEs in one step".into())
        } else {
            None
        };
        let mut links = Vec::new();
        // Repology lookup is the most universal "what is this
        // package and what depends on it?" surface across distros.
        // Lets the operator sanity-check before removing.
        links.push(EvidenceLink {
            label: "Repology".into(),
            url: format!("https://repology.org/project/{}/versions", urlencoding::encode(&p.name)),
        });
        evidence.push(Evidence {
            label: p.name.clone(),
            value,
            detail,
            links,
        });
    }
    if total_count > MAX_PACKAGE_ROWS {
        evidence.push(Evidence {
            label: "More".into(),
            value: format!("+{} additional packages", total_count - MAX_PACKAGE_ROWS),
            detail: Some(format!("Run `{} {}` to see the full list", pm.label(), match pm {
                PackageManager::Apt => "-s autoremove",
                PackageManager::Dnf | PackageManager::Yum => "repoquery --unneeded",
                PackageManager::Zypper => "packages --orphaned",
                PackageManager::Pacman => "-Qdtq",
                _ => "",
            })),
            links: Vec::new(),
        });
    }

    let commands = match pm {
        PackageManager::Apt    => vec!["apt-get autoremove --purge -y".to_string()],
        PackageManager::Dnf    => vec!["dnf autoremove -y".to_string()],
        PackageManager::Yum    => vec!["yum autoremove -y".to_string()],
        PackageManager::Zypper => {
            // zypper has no single autoremove — pass the orphans by name.
            let names: Vec<String> = packages.iter().map(|p| p.name.clone()).collect();
            vec![format!("zypper --non-interactive remove {}", names.join(" "))]
        }
        PackageManager::Pacman => {
            // -Rns removes orphan + its config + its dependencies that
            // nothing else needs. Safe because the input list is
            // already orphans (pacman -Qdtq).
            let names: Vec<String> = packages.iter().map(|p| p.name.clone()).collect();
            vec![format!("pacman -Rns --noconfirm {}", names.join(" "))]
        }
        _ => vec!["# distro-specific — no canonical command available".to_string()],
    };

    Proposal::new_rule(
        FINDING_TYPE,
        severity,
        title,
        why,
        evidence,
        RemediationPlan::Manual {
            instructions: "Review the list above. The command runs the distro's \
                own autoremove path, so it ONLY removes the same packages the \
                analyzer flagged. If you want to keep one specifically (e.g. \
                python3 because of an out-of-band script), `apt-mark manual \
                python3` (or your distro's equivalent) before running the \
                remove command — that pins the package and excludes it from \
                future autoremove sweeps.".into(),
            commands,
        },
        scope.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_apt_autoremove_extracts_packages() {
        let raw = "Reading package lists... Done\n\
                   Building dependency tree... Done\n\
                   Reading state information... Done\n\
                   The following packages will be REMOVED:\n  \
                     libfoo libbar python3-baz libqux\n\
                   0 upgraded, 0 newly installed, 4 to remove and 0 not upgraded.\n\
                   Remv libfoo [1.0]\n";
        let pkgs = parse_apt_autoremove(raw);
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["libfoo", "libbar", "python3-baz", "libqux"]);
        assert!(pkgs.iter().all(|p| p.size_mb.is_none()));
    }

    #[test]
    fn parse_apt_autoremove_handles_multi_line_block() {
        // Real apt wraps long lists across multiple indented lines.
        let raw = "The following packages will be REMOVED:\n  \
                     libfoo libbar libbaz\n  \
                     libqux libquux\n\
                   0 upgraded, 0 newly installed, 5 to remove\n";
        let pkgs = parse_apt_autoremove(raw);
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["libfoo", "libbar", "libbaz", "libqux", "libquux"]);
    }

    #[test]
    fn parse_apt_autoremove_empty_when_no_remove_block() {
        let raw = "Reading package lists... Done\n\
                   0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n";
        assert!(parse_apt_autoremove(raw).is_empty());
    }

    #[test]
    fn parse_dnf_unneeded_extracts_name_and_size() {
        let raw = "libfoo 12345678\nlibbar 999999\nbroken-line\n";
        let pkgs = parse_dnf_unneeded(raw);
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0].name, "libfoo");
        assert_eq!(pkgs[0].size_mb, Some(11)); // 12.3 MB ≈ 11 in integer division
        assert_eq!(pkgs[1].size_mb, Some(0));   // <1 MB rounds to 0
        assert_eq!(pkgs[2].name, "broken-line");
        assert_eq!(pkgs[2].size_mb, None);
    }

    #[test]
    fn parse_zypper_orphaned_skips_header() {
        let raw = "Loading repository data...\n\
                   S | Repository | Name | Version | Arch\n\
                   --+------------+------+---------+-----\n\
                   i+|  | libfoo | 1.0 | x86_64\n\
                   i+|  | libbar | 2.3 | noarch\n";
        let pkgs = parse_zypper_orphaned(raw);
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["libfoo", "libbar"]);
    }

    #[test]
    fn parse_pacman_qi_extracts_name_and_size() {
        let raw = "Name            : libfoo\n\
                   Version         : 1.0-1\n\
                   Installed Size  : 34.66 MiB\n\
                   Description     : a thing\n\
                   \n\
                   Name            : libbar\n\
                   Version         : 2.3-4\n\
                   Installed Size  : 512.00 KiB\n\
                   \n\
                   Name            : libbaz\n\
                   Installed Size  : 1.20 GiB\n";
        let pkgs = parse_pacman_qi(raw);
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0].name, "libfoo");
        assert_eq!(pkgs[0].size_mb, Some(35));   // 34.66 → 35
        assert_eq!(pkgs[1].name, "libbar");
        assert_eq!(pkgs[1].size_mb, Some(1));    // 512 KiB → 0.5 MB → rounds to 1
        assert_eq!(pkgs[2].name, "libbaz");
        assert_eq!(pkgs[2].size_mb, Some(1229)); // 1.20 GiB ≈ 1229 MB
    }

    #[test]
    fn parse_pacman_size_handles_units() {
        assert_eq!(parse_pacman_size("100.00 KiB"), Some(0));
        assert_eq!(parse_pacman_size("100.00 MiB"), Some(100));
        assert_eq!(parse_pacman_size("2.50 GiB"), Some(2560));
        assert_eq!(parse_pacman_size("garbage"), None);
        assert_eq!(parse_pacman_size("100"), None); // no unit
    }

    #[test]
    fn analyze_emits_critical_when_removable_packages_have_cves() {
        use crate::predictive::vulnerability::{VulnerabilityFacts, PackageManager};
        use crate::predictive::osv::{OsvFinding, OsvVuln, ScanTargetOwned};
        let ctx = Context::for_node("n");
        let facts = UnusedPackagesFacts {
            scanned: true,
            host_pm: PackageManager::Apt,
            host_removable: vec![
                RemovablePackage { name: "python3".into(), size_mb: Some(50), open_cves: 0 },
                RemovablePackage { name: "libxml2".into(), size_mb: Some(8), open_cves: 0 },
            ],
        };
        // OSV findings: python3 has 3 distinct CVEs. Analyzer must
        // count them, mark python3 as 3-CVE removable, and bump
        // severity to Critical.
        let mk_osv_finding = |cve: &str| OsvFinding {
            target: ScanTargetOwned::Host,
            ecosystem: "Debian:12".into(),
            package: "python3".into(),
            version: "3.11".into(),
            vuln: OsvVuln {
                id: cve.into(),
                aliases: vec![cve.into()],
                summary: "".into(),
                cvss_score: Some(7.5),
                advisory_url: None,
                modified: None,
                fixed_versions: std::collections::HashMap::new(),
                references: Vec::new(),
                exploit_category: crate::predictive::osv::ExploitCategory::Unknown,
            },
            kev_listed: false,
            fix_available: false,
        };
        let osv = OsvFacts {
            findings: vec![
                mk_osv_finding("CVE-2099-0001"),
                mk_osv_finding("CVE-2099-0002"),
                mk_osv_finding("CVE-2099-0003"),
            ],
            covered_targets: vec![ScanTargetOwned::Host],
            unrecognized_derivatives: Vec::new(),
            kernel_unidentified: Vec::new(),
            config: crate::predictive::osv::OsvConfig::default(),
            kev_cve_count: 0,
            suppressed_no_fix_by_target: std::collections::HashMap::new(),
        };
        let vuln = VulnerabilityFacts {
            host_pm: Some(PackageManager::Apt),
            host_updates: Vec::new(),
            lxc_results: Vec::new(),
            ..Default::default()
        };
        let store = crate::predictive::proposal::ProposalStore::default();
        let acks = AckStore::default();
        let props = analyze(&ctx, &facts, &vuln, &osv, &acks, &store);
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].severity, Severity::Critical);
        assert!(props[0].title.contains("3 open CVE"),
            "title must report 3 distinct CVEs, got {:?}", props[0].title);
        // Python3 must surface FIRST in the evidence — sort key is
        // (CVEs desc, size desc). libxml2 has 0 CVEs so it's lower.
        let cve_pkg_row = props[0].evidence.iter()
            .find(|e| e.label == "python3").expect("python3 row");
        assert!(cve_pkg_row.value.contains("CVE"),
            "package row must show its CVE count");
    }

    #[test]
    fn analyze_dedupes_cve_ids_does_not_double_count() {
        // The exact failure mode the v1 code had: distro-pocket flagged
        // 3 security updates AND OSV flagged 3 CVEs for the same
        // package. The naive sum (6) was misleading. The fix counts
        // unique CVE ids only — and ignores the per-update tally
        // entirely because it's not CVE-granular. So if OSV reports
        // 3 distinct CVEs and the distro pocket reports 5 updates,
        // we still report 3.
        use crate::predictive::vulnerability::{PendingUpdate, VulnerabilityFacts, PackageManager};
        use crate::predictive::osv::{OsvFinding, OsvVuln, ScanTargetOwned};
        let ctx = Context::for_node("n");
        let facts = UnusedPackagesFacts {
            scanned: true,
            host_pm: PackageManager::Apt,
            host_removable: vec![
                RemovablePackage { name: "python3".into(), size_mb: Some(50), open_cves: 0 },
            ],
        };
        let mk = |cve: &str| OsvFinding {
            target: ScanTargetOwned::Host,
            ecosystem: "Debian:12".into(),
            package: "python3".into(),
            version: "3.11".into(),
            vuln: OsvVuln {
                id: cve.into(), aliases: vec![cve.into()],
                summary: "".into(), cvss_score: Some(7.5),
                advisory_url: None, modified: None,
                fixed_versions: std::collections::HashMap::new(),
                references: Vec::new(),
                exploit_category: crate::predictive::osv::ExploitCategory::Unknown,
            },
            kev_listed: false, fix_available: false,
        };
        let osv = OsvFacts {
            findings: vec![
                mk("CVE-2099-0001"),
                mk("CVE-2099-0002"),
                mk("CVE-2099-0003"),
            ],
            covered_targets: vec![ScanTargetOwned::Host],
            unrecognized_derivatives: Vec::new(),
            kernel_unidentified: Vec::new(),
            config: crate::predictive::osv::OsvConfig::default(),
            kev_cve_count: 0,
            suppressed_no_fix_by_target: std::collections::HashMap::new(),
        };
        let vuln = VulnerabilityFacts {
            host_pm: Some(PackageManager::Apt),
            // 5 distro-pocket updates: would have inflated the total
            // to 8 in the buggy version. New code ignores them for
            // CVE counting.
            host_updates: vec![
                PendingUpdate { package: "python3".into(), current_version: None, new_version: None, advisory: None },
                PendingUpdate { package: "python3".into(), current_version: None, new_version: None, advisory: None },
                PendingUpdate { package: "python3".into(), current_version: None, new_version: None, advisory: None },
                PendingUpdate { package: "python3".into(), current_version: None, new_version: None, advisory: None },
                PendingUpdate { package: "python3".into(), current_version: None, new_version: None, advisory: None },
            ],
            lxc_results: Vec::new(),
            ..Default::default()
        };
        let props = analyze(&ctx, &facts, &vuln, &osv, &AckStore::default(),
            &crate::predictive::proposal::ProposalStore::default());
        assert_eq!(props.len(), 1);
        assert!(props[0].title.contains("3 open CVE"),
            "must report 3 distinct CVE IDs, NOT 5+3=8 — anti-double-count: {:?}",
            props[0].title);
    }

    #[test]
    fn analyze_dedupes_same_cve_appearing_under_multiple_aliases() {
        // OSV findings sometimes carry the same CVE under both its
        // CVE-XXX id and an alias — `vuln.cve_ids()` already dedups
        // within one finding. But two separate findings for the same
        // package + same CVE (different OSV records, same alias)
        // must count once, not twice.
        use crate::predictive::vulnerability::{VulnerabilityFacts, PackageManager};
        use crate::predictive::osv::{OsvFinding, OsvVuln, ScanTargetOwned};
        let ctx = Context::for_node("n");
        let facts = UnusedPackagesFacts {
            scanned: true,
            host_pm: PackageManager::Apt,
            host_removable: vec![RemovablePackage { name: "openssl".into(), size_mb: Some(2), open_cves: 0 }],
        };
        let mk = |id: &str, alias: &str| OsvFinding {
            target: ScanTargetOwned::Host,
            ecosystem: "Debian:12".into(),
            package: "openssl".into(),
            version: "3.0".into(),
            vuln: OsvVuln {
                id: id.into(),
                aliases: vec![alias.into()],
                summary: "".into(), cvss_score: Some(7.5),
                advisory_url: None, modified: None,
                fixed_versions: std::collections::HashMap::new(),
                references: Vec::new(),
                exploit_category: crate::predictive::osv::ExploitCategory::Unknown,
            },
            kev_listed: false, fix_available: false,
        };
        let osv = OsvFacts {
            findings: vec![
                mk("OSV-A", "CVE-2099-1234"),
                mk("OSV-B", "CVE-2099-1234"), // same CVE, different OSV record
            ],
            covered_targets: vec![ScanTargetOwned::Host],
            unrecognized_derivatives: Vec::new(),
            kernel_unidentified: Vec::new(),
            config: crate::predictive::osv::OsvConfig::default(),
            kev_cve_count: 0,
            suppressed_no_fix_by_target: std::collections::HashMap::new(),
        };
        let vuln = VulnerabilityFacts { host_pm: Some(PackageManager::Apt), host_updates: Vec::new(), lxc_results: Vec::new(), ..Default::default() };
        let props = analyze(&ctx, &facts, &vuln, &osv, &AckStore::default(),
            &crate::predictive::proposal::ProposalStore::default());
        assert!(props[0].title.contains("1 open CVE"),
            "two OSV records aliasing the same CVE must count as 1, got {:?}",
            props[0].title);
    }

    #[test]
    fn analyze_emits_warn_for_large_disk_reclaim_no_cves() {
        use crate::predictive::vulnerability::{VulnerabilityFacts, PackageManager};
        let ctx = Context::for_node("n");
        let facts = UnusedPackagesFacts {
            scanned: true,
            host_pm: PackageManager::Apt,
            // 35 packages with sizes — over the 30/1024 threshold
            host_removable: (0..35).map(|i| RemovablePackage {
                name: format!("pkg-{}", i),
                size_mb: Some(40),
                open_cves: 0,
            }).collect(),
        };
        let vuln = VulnerabilityFacts { host_pm: Some(PackageManager::Apt), host_updates: Vec::new(), lxc_results: Vec::new(), ..Default::default() };
        let osv = OsvFacts::default();
        let props = analyze(&ctx, &facts, &vuln, &osv, &AckStore::default(),
            &crate::predictive::proposal::ProposalStore::default());
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].severity, Severity::Warn);
        assert!(props[0].title.contains("≈1400 MB"));
    }

    #[test]
    fn analyze_emits_nothing_when_nothing_removable() {
        use crate::predictive::vulnerability::{VulnerabilityFacts, PackageManager};
        let ctx = Context::for_node("n");
        let facts = UnusedPackagesFacts {
            scanned: true,
            host_pm: PackageManager::Apt,
            host_removable: Vec::new(),
        };
        let vuln = VulnerabilityFacts { host_pm: Some(PackageManager::Apt), host_updates: Vec::new(), lxc_results: Vec::new(), ..Default::default() };
        let osv = OsvFacts::default();
        let props = analyze(&ctx, &facts, &vuln, &osv, &AckStore::default(),
            &crate::predictive::proposal::ProposalStore::default());
        assert!(props.is_empty());
    }

    #[test]
    fn covered_scopes_empty_when_not_scanned() {
        let facts = UnusedPackagesFacts::default();
        let cov = covered_scopes(&Context::for_node("n"), &facts);
        assert!(cov.is_empty());
    }

    #[test]
    fn covered_scopes_present_when_scanned_even_with_no_removable() {
        // Crucial: even a "nothing to remove" tick must publish the
        // covered scope so a previously-emitted finding clears once
        // the operator has done the cleanup.
        let facts = UnusedPackagesFacts {
            scanned: true,
            host_pm: PackageManager::Apt,
            host_removable: Vec::new(),
        };
        let cov = covered_scopes(&Context::for_node("n"), &facts);
        assert_eq!(cov.len(), 1);
    }
}
