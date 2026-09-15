// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! VM disk-fill — Item 7 of the predictive plan.
//!
//! Surfaces qcow2 disks that are filling toward their declared
//! allocation. Without `qemu-guest-agent` running inside the guest
//! we can't see filesystem-level usage, but we *can* see how much
//! the sparse qcow2 file has actually been written to on the host —
//! which is a useful proxy: a guest filesystem that's filling its
//! disk shows up as the qcow2 file growing toward its declared
//! `disk_size_gb` allocation.
//!
//! ## What this catches
//!
//! - `/var/lib/wolfstack/vms/<name>.qcow2` growing toward the
//!   `disk_size_gb` set when the VM was created.
//! - Same for `extra_disks` paths configured on the VM.
//!
//! ## What this doesn't (yet)
//!
//! - **Raw disk images** — file size always equals allocation, so
//!   we can't distinguish "0% used" from "99% used". Need
//!   guest-agent for those.
//! - **LVM / ZFS / Ceph backing** — the disk doesn't live as a
//!   regular file. Future work; out of scope for v1.
//! - **In-guest filesystem usage** — needs qemu-guest-agent. The
//!   existing on-host check is a superset signal (filesystem usage
//!   ≤ qcow2 sparse usage, since trim/discard isn't always enabled).
//! - **Proxmox-managed VMs** — they live under `/var/lib/vz/images/<vmid>/`
//!   with a different naming convention. Same pattern, different
//!   path resolution; tracked for the next iteration. For now we
//!   skip them rather than guess wrong.
//!
//! ## Severity tiers (qcow2 actual size as % of allocation)
//!
//! | % allocation used | Severity   |
//! |-------------------|------------|
//! | ≥ 95 %            | `Critical` |
//! | ≥ 90 %            | `High`     |
//! | ≥ 80 %            | `Warn`     |
//! | < 80 %            | suppressed |

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::predictive::{
    Context,
    proposal::{
        Evidence, Proposal, ProposalScope, RemediationPlan, Severity,
    },
    ack::AckStore,
};

pub const FINDING_TYPE: &str = "vm_disk_fill";

const WARN_PCT: f64 = 80.0;
const HIGH_PCT: f64 = 90.0;
const CRITICAL_PCT: f64 = 95.0;

#[derive(Debug, Clone, PartialEq)]
pub struct VmDiskFact {
    pub vm_name: String,
    pub disk_path: PathBuf,
    /// Sparse-aware on-disk size of the qcow2 (`stat -c %s`).
    pub actual_bytes: u64,
    /// Declared allocation from `VmConfig.disk_size_gb` × 1 GiB.
    pub allocated_bytes: u64,
    /// `actual_bytes / allocated_bytes × 100`. Always 0..=100 in
    /// the well-behaved case; can theoretically exceed 100 for
    /// non-qcow2 files we shouldn't be seeing here, hence the
    /// skip-non-qcow2 filter in the sampler.
    pub used_pct: f64,
}

/// Sample VM disk facts from the existing `vms::manager`.
pub fn sample_vm_disks_now() -> Vec<VmDiskFact> {
    let mgr = crate::vms::manager::VmManager::new();
    let mut out = Vec::new();
    for vm in mgr.list_vms() {
        // Proxmox-managed VMs live under their own paths and we
        // skip them in v1 — see module doc.
        if vm.vmid.is_some() { continue; }

        // OS disk path.
        let storage = vm.storage_path.clone()
            .unwrap_or_else(|| "/var/lib/wolfstack/vms".to_string());
        let os_disk = PathBuf::from(&storage).join(format!("{}.qcow2", vm.name));
        if let Some(fact) = file_to_fact(&vm.name, &os_disk, vm.disk_size_gb as u64) {
            out.push(fact);
        }

        // Extra disks.
        for vol in &vm.extra_disks {
            let extra_path = PathBuf::from(&storage)
                .join(format!("{}-{}.qcow2", vm.name, vol.name));
            if let Some(fact) = file_to_fact(&vm.name, &extra_path, vol.size_gb as u64) {
                out.push(fact);
            }
        }
    }
    out
}

pub async fn sample_vm_disks_now_async(timeout: Duration) -> Vec<VmDiskFact> {
    let fut = tokio::task::spawn_blocking(sample_vm_disks_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            tracing::warn!("predictive: vm-disk sampling task panicked: {}", e);
            Vec::new()
        }
        Err(_) => {
            tracing::warn!(
                "predictive: vm-disk sampling timed out after {}s",
                timeout.as_secs(),
            );
            Vec::new()
        }
    }
}

fn file_to_fact(vm_name: &str, path: &Path, allocated_gb: u64) -> Option<VmDiskFact> {
    if !path.exists() { return None; }
    if !is_qcow2(path) { return None; }
    let meta = std::fs::metadata(path).ok()?;
    let actual = meta.len();
    let allocated = allocated_gb * 1_073_741_824;
    if allocated == 0 { return None; }
    let used_pct = (actual as f64 / allocated as f64) * 100.0;
    Some(VmDiskFact {
        vm_name: vm_name.to_string(),
        disk_path: path.to_path_buf(),
        actual_bytes: actual,
        allocated_bytes: allocated,
        used_pct,
    })
}

/// Heuristic — qcow2 files have a `QFI\xfb` magic at byte 0. Reading
/// 4 bytes is cheap and avoids us mis-classifying a raw disk as a
/// candidate.
fn is_qcow2(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else { return false };
    let mut buf = [0u8; 4];
    if f.read_exact(&mut buf).is_err() { return false; }
    buf == [b'Q', b'F', b'I', 0xfb]
}

pub fn severity_for_pct(pct: f64) -> Option<Severity> {
    if pct >= CRITICAL_PCT { Some(Severity::Critical) }
    else if pct >= HIGH_PCT { Some(Severity::High) }
    else if pct >= WARN_PCT { Some(Severity::Warn) }
    else { None }
}

pub fn analyze(
    ctx: &Context,
    current: &[VmDiskFact],
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    for fact in current {
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("vm:{}:{}", fact.vm_name, fact.disk_path.display())),
        };
        if acks.suppresses(FINDING_TYPE, &scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE, &scope) { continue; }
        let Some(severity) = severity_for_pct(fact.used_pct) else { continue; };
        out.push(build_proposal(fact, &scope, severity));
    }
    out
}

pub fn covered_scopes(
    ctx: &Context,
    current: &[VmDiskFact],
) -> Vec<(String, ProposalScope)> {
    current.iter().map(|f| (
        FINDING_TYPE.to_string(),
        ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("vm:{}:{}", f.vm_name, f.disk_path.display())),
        },
    )).collect()
}

fn build_proposal(fact: &VmDiskFact, scope: &ProposalScope, severity: Severity) -> Proposal {
    let used_gb = fact.actual_bytes as f64 / 1_073_741_824.0;
    let alloc_gb = fact.allocated_bytes as f64 / 1_073_741_824.0;
    let title = format!(
        "VM '{}' qcow2 disk at {:.1}% of allocation ({:.1}/{:.1} GB)",
        fact.vm_name, fact.used_pct, used_gb, alloc_gb,
    );
    let why = format!(
        "VM '{}' disk file at {} has grown to {:.1} GB of its \
         {:.0} GB allocation ({:.1}%). qcow2 sparseness means we're \
         seeing how much has actually been written, not the guest's \
         filesystem usage — the latter could be lower if the guest \
         supports TRIM/DISCARD, or higher if a guest log/cache is \
         filling without ever shrinking the qcow2. At ≥95 % of \
         allocation the qcow2 is one workload spike from refusing \
         further writes.",
        fact.vm_name, fact.disk_path.display(), used_gb, alloc_gb, fact.used_pct,
    );
    let evidence = vec![
        Evidence {
            label: "VM".into(),
            value: fact.vm_name.clone(),
            detail: Some(fact.disk_path.display().to_string()),
            links: Vec::new(),
        },
        Evidence {
            label: "qcow2 actual".into(),
            value: format!("{:.1} GB", used_gb),
            detail: Some(format!("of {:.0} GB allocated ({:.1}%)", alloc_gb, fact.used_pct)),
            links: Vec::new(),
        },
    ];
    let remediation = RemediationPlan::Manual {
        instructions: "If guest filesystem usage is genuinely high, expand the \
             VM's disk via `qemu-img resize` (offline) or the live-\
             resize feature in the dashboard. If the qcow2 has \
             ballooned but the guest reports plenty of free space, \
             enabling DISCARD/TRIM and running `fstrim` inside the \
             guest will let the qcow2 shrink. Installing \
             qemu-guest-agent gives the dashboard direct visibility \
             into in-guest usage so this finding gets fine-grained \
             attribution.".to_string(),
        commands: vec![
            format!("qemu-img info {}", fact.disk_path.display()),
            format!("ls -la {}", fact.disk_path.display()),
            "# Inside the guest (if reachable):".into(),
            "df -h".into(),
            "sudo fstrim -av     # reclaim qcow2 space if TRIM enabled".into(),
        ],
    };
    Proposal::new_rule(
        FINDING_TYPE, severity,
        title, why, evidence, remediation, scope.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predictive::NetworkSnapshot;
    use crate::predictive::proposal::ProposalStore;

    fn ctx() -> Context {
        Context {
            node_id: "node-a".into(),
            network: NetworkSnapshot::from_parts(vec![], vec![]),
        }
    }

    fn fact(name: &str, used_pct: f64) -> VmDiskFact {
        let alloc = 100u64 * 1_073_741_824;
        VmDiskFact {
            vm_name: name.into(),
            disk_path: PathBuf::from(format!("/var/lib/wolfstack/vms/{}.qcow2", name)),
            allocated_bytes: alloc,
            actual_bytes: ((used_pct / 100.0) * alloc as f64) as u64,
            used_pct,
        }
    }

    #[test]
    fn severity_thresholds() {
        assert_eq!(severity_for_pct(50.0), None);
        assert_eq!(severity_for_pct(80.0), Some(Severity::Warn));
        assert_eq!(severity_for_pct(90.0), Some(Severity::High));
        assert_eq!(severity_for_pct(95.0), Some(Severity::Critical));
    }

    #[test]
    fn analyzer_emits_for_filling_qcow2() {
        let facts = vec![fact("opnsense", 92.0)];
        let p = analyze(&ctx(), &facts, &AckStore::default(), &ProposalStore::default());
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].severity, Severity::High);
        assert!(p[0].title.contains("opnsense"));
    }

    #[test]
    fn ack_suppresses_specific_vm() {
        let facts = vec![fact("opnsense", 92.0)];
        let mut acks = AckStore::default();
        acks.add(crate::predictive::ack::Ack::new(
            FINDING_TYPE,
            crate::predictive::ack::AckScope::Resource {
                node_id: "node-a".into(),
                resource_id: "vm:opnsense:/var/lib/wolfstack/vms/opnsense.qcow2".into(),
            },
            "Allocated tight on purpose; resize coming next week",
            "paul", None,
        ));
        let p = analyze(&ctx(), &facts, &acks, &ProposalStore::default());
        assert!(p.is_empty());
    }

    #[test]
    fn analyzer_can_stay_quiet() {
        let facts = vec![fact("ok", 30.0)];
        let p = analyze(&ctx(), &facts, &AckStore::default(), &ProposalStore::default());
        assert!(p.is_empty());
    }
}
