// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! WolfNet VM DHCP/gateway health checker.
//!
//! Background: a customer (PapaSchlumpf, 2026-05-06) reported that
//! starting two WolfNet VMs at once silently broke the second one's
//! networking. Root cause: `setup_wolfnet_routing` was assigning the
//! same gateway IP (`subnet.254`) to every TAP and running dnsmasq
//! with `--bind-interfaces`, so the second dnsmasq instance died at
//! bind() with `Address already in use`. The VM started but never
//! got an IP, with no error surfaced anywhere.
//!
//! `vms::manager` now picks unique gateway IPs per TAP and uses
//! `--bind-dynamic` (SO_BINDTODEVICE), AND verifies dnsmasq stayed
//! up after spawn. This analyzer is the third layer of defence: on
//! every orchestrator tick, every running WolfNet VM is probed.
//! Any broken plumbing — dead dnsmasq, missing gateway IP, stale pid
//! file, TAP down — produces a Critical proposal in the inbox the
//! moment it's detected, rather than after a customer reports it.

use std::time::Duration;

use crate::predictive::{
    Context,
    ack::AckStore,
    proposal::{
        Evidence, Proposal, ProposalScope, RemediationPlan, Severity,
    },
};
use crate::vms::manager::{VmManager, WolfnetTapHealth, probe_wolfnet_tap_health};

/// Finding type — one Critical card per VM whose WolfNet plumbing
/// is broken. The scope is keyed on the VM name so dismiss/snooze
/// is per-VM and the resolver collapses cross-tick.
pub const FINDING_TYPE: &str = "wolfnet_vm_dhcp_failed";

#[derive(Debug, Clone, Default)]
pub struct WolfnetDhcpFacts {
    /// True iff we successfully enumerated VMs this tick. False
    /// means we should not auto-resolve anything — the data source
    /// is down (e.g. /etc/wolfstack/vms.json missing). Same pattern
    /// as the port-conflict analyzer.
    pub scanned: bool,
    pub failed: Vec<WolfnetTapHealth>,
    /// Every VM we evaluated this tick (broken or healthy). Drives
    /// auto-resolve: a VM that recovers leaves `failed` but stays
    /// in `evaluated`, so the resolver clears its stale finding.
    pub evaluated: Vec<String>,
}

/// Synchronous probe; runs inside `spawn_blocking` from the
/// orchestrator. Walks the local VM config list, checks the
/// WolfNet plumbing for each running VM, returns the result.
pub fn sample_now() -> WolfnetDhcpFacts {
    let manager = VmManager::new();
    let vms = manager.list_vms();
    let mut facts = WolfnetDhcpFacts {
        scanned: true,
        failed: Vec::new(),
        evaluated: Vec::new(),
    };
    for vm in vms {
        let wolfnet_ip = match vm.wolfnet_ip.as_deref() {
            Some(ip) if !ip.is_empty() => ip.to_string(),
            _ => continue, // VM doesn't use WolfNet; not our concern
        };
        if !vm.running {
            // Stopped VMs WILL have no dnsmasq — that's expected,
            // not a failure. Don't flag, don't mark as evaluated
            // (so a previous "failed" finding only resolves when
            // the VM is up and probed clean).
            continue;
        }
        facts.evaluated.push(vm.name.clone());
        let tap = VmManager::tap_name(&vm.name);
        let health = probe_wolfnet_tap_health(&tap, &wolfnet_ip);
        if !health.ok() {
            facts.failed.push(health);
        }
    }
    facts
}

pub async fn sample_now_async(timeout: Duration) -> WolfnetDhcpFacts {
    let fut = tokio::task::spawn_blocking(sample_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(f)) => f,
        _ => WolfnetDhcpFacts::default(),
    }
}

pub fn analyze(
    ctx: &Context,
    facts: &WolfnetDhcpFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    for h in &facts.failed {
        // VM name is encoded in the TAP name (`tap-<first11chars>`),
        // but we want the actual VM name in the scope so cluster
        // dedup stays clean. Strip the tap prefix back; if the VM's
        // real name is longer than 11 chars we lose the suffix —
        // the analyzer doesn't need to recover the original, the
        // tap name is itself unique-per-VM and that's enough for
        // (finding_type, scope) dedup.
        let vm_label = h.tap.strip_prefix("tap-").unwrap_or(&h.tap);
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("vm:wolfnet:{}", vm_label)),
        };
        if acks.suppresses(FINDING_TYPE, &scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE, &scope) { continue; }
        out.push(build_proposal(h, &scope, vm_label));
    }
    out
}

pub fn covered_scopes(
    ctx: &Context,
    facts: &WolfnetDhcpFacts,
) -> Vec<(String, ProposalScope)> {
    if !facts.scanned { return Vec::new(); }
    facts.evaluated.iter().map(|name| {
        let label = VmManager::tap_name(name).trim_start_matches("tap-").to_string();
        (FINDING_TYPE.to_string(), ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("vm:wolfnet:{}", label)),
        })
    }).collect()
}

fn build_proposal(h: &WolfnetTapHealth, scope: &ProposalScope, vm_label: &str) -> Proposal {
    let title = format!(
        "VM `{}` WolfNet networking is broken — DHCP not serving",
        vm_label,
    );
    let why = format!(
        "WolfStack's per-VM dnsmasq plumbing on `{tap}` (gateway `{gw}`, VM IP `{vmip}`) \
         is in a broken state. The VM will boot but DHCPDISCOVER will get no reply, \
         so it will run with no network. Most common causes: a previous VM's dnsmasq \
         is still holding the gateway IP (the bug PapaSchlumpf reported on 2026-05-06 — \
         fixed by per-VM gateway IPs + `--bind-dynamic` in v22.9.x); a manual `pkill` \
         left a stale pid file; the host's iptables FORWARD chain rejected our TAP. \
         Look at the failures list below — they're ordered with the most-actionable \
         cause first.",
        tap = h.tap, gw = h.gateway_ip, vmip = h.wolfnet_ip,
    );
    let mut evidence = vec![
        Evidence {
            label: "TAP".into(),
            value: h.tap.clone(),
            detail: Some(format!(
                "exists: {}, up: {}",
                if h.tap_exists { "yes" } else { "NO" },
                if h.tap_up { "yes" } else { "NO" },
            )),
            links: Vec::new(),
        },
        Evidence {
            label: "Gateway".into(),
            value: h.gateway_ip.clone(),
            detail: Some(format!(
                "assigned to {}: {}",
                h.tap,
                if h.gateway_assigned { "yes" } else { "NO" },
            )),
            links: Vec::new(),
        },
        Evidence {
            label: "dnsmasq".into(),
            value: match h.dnsmasq_pid {
                Some(p) if h.dnsmasq_alive && h.dnsmasq_owns_tap => format!("pid {} (healthy)", p),
                Some(p) if h.dnsmasq_alive => format!("pid {} (wrong interface)", p),
                Some(p) => format!("pid {} (DEAD)", p),
                None => "no pid file".into(),
            },
            detail: Some("Without a live dnsmasq the VM never gets DHCP".into()),
            links: Vec::new(),
        },
        Evidence {
            label: "DHCP lease".into(),
            value: if h.lease_present { "issued".into() } else { "none".into() },
            detail: Some(
                "Empty for a freshly-booted VM is normal; persistent emptiness with a \
                 running VM means the VM never reached our DHCP server.".into()
            ),
            links: Vec::new(),
        },
    ];
    for (i, fail) in h.failures.iter().enumerate() {
        evidence.push(Evidence {
            label: format!("Failure {}", i + 1),
            value: fail.clone(),
            detail: None,
            links: Vec::new(),
        });
    }
    let commands = vec![
        format!("ip addr show dev {}", h.tap),
        format!("ss -tlnp 'sport = :53' | grep dnsmasq"),
        format!("ss -ulnp 'sport = :67' | grep dnsmasq"),
        format!("cat /run/dnsmasq-{}.pid 2>/dev/null && ps -p \"$(cat /run/dnsmasq-{}.pid)\"", h.tap, h.tap),
        format!("# To force a clean restart of WolfNet plumbing on this VM:"),
        format!("# (stop the VM from the UI, then start it again — WolfStack re-runs setup_wolfnet_routing)"),
    ];
    Proposal::new_rule(
        FINDING_TYPE,
        Severity::Critical,
        title,
        why,
        evidence,
        RemediationPlan::Manual {
            instructions: "Stop the VM and start it again from the WolfStack UI — \
                the start path re-runs the full WolfNet TAP + dnsmasq setup. If the \
                problem persists after restart, check `/var/log/wolfstack.log` for \
                a `DHCP verification FAILED` line right after the VM started; that \
                line names the exact bind() error. Common fixes: (1) confirm no \
                other process is holding port 53/67 on the gateway IP \
                (`ss -tlnp 'sport = :53'`); (2) verify the host has `dnsmasq` \
                installed; (3) on firewalld systems, confirm WolfStack added the \
                TAP to the trusted zone.".into(),
            commands,
        },
        scope.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predictive::proposal::ProposalStore;
    use crate::vms::manager::WolfnetTapHealth;

    fn ctx() -> Context { Context::for_node("n") }

    fn healthy(name: &str) -> WolfnetTapHealth {
        WolfnetTapHealth {
            tap: format!("tap-{}", name),
            gateway_ip: "10.10.10.254".into(),
            wolfnet_ip: "10.10.10.5".into(),
            tap_exists: true,
            tap_up: true,
            gateway_assigned: true,
            dnsmasq_pid: Some(1234),
            dnsmasq_alive: true,
            dnsmasq_owns_tap: true,
            lease_present: true,
            failures: Vec::new(),
        }
    }

    fn broken(name: &str, why: &str) -> WolfnetTapHealth {
        let mut h = healthy(name);
        h.dnsmasq_alive = false;
        h.failures.push(why.into());
        h
    }

    #[test]
    fn analyze_emits_critical_for_each_broken_vm() {
        let facts = WolfnetDhcpFacts {
            scanned: true,
            failed: vec![
                broken("pbs", "dnsmasq pid 1234 not running"),
                broken("homeassistant", "dnsmasq pid 5678 not running"),
            ],
            evaluated: vec!["pbs".into(), "homeassistant".into()],
        };
        let props = analyze(&ctx(), &facts, &AckStore::default(), &ProposalStore::default());
        assert_eq!(props.len(), 2);
        for p in &props {
            assert_eq!(p.severity, Severity::Critical);
            assert_eq!(p.finding_type, FINDING_TYPE);
        }
    }

    #[test]
    fn analyze_emits_nothing_when_all_healthy() {
        let facts = WolfnetDhcpFacts {
            scanned: true,
            failed: Vec::new(),
            evaluated: vec!["pbs".into(), "homeassistant".into()],
        };
        let props = analyze(&ctx(), &facts, &AckStore::default(), &ProposalStore::default());
        assert!(props.is_empty());
    }

    #[test]
    fn covered_scopes_includes_every_evaluated_vm() {
        // Once a VM has been probed (broken or healthy), its scope
        // is "covered" so the resolver can clear a stale finding
        // when the VM later recovers.
        let facts = WolfnetDhcpFacts {
            scanned: true,
            failed: Vec::new(),
            evaluated: vec!["pbs".into(), "ha".into()],
        };
        let cov = covered_scopes(&ctx(), &facts);
        assert_eq!(cov.len(), 2);
        assert!(cov.iter().all(|(t, _)| t == FINDING_TYPE));
    }

    #[test]
    fn covered_scopes_empty_when_not_scanned() {
        let facts = WolfnetDhcpFacts {
            scanned: false,
            ..Default::default()
        };
        assert!(covered_scopes(&ctx(), &facts).is_empty());
    }

    #[test]
    fn proposal_lists_every_failure_message() {
        let mut h = broken("pbs", "dnsmasq pid 1234 not running");
        h.failures.push("TAP tap-pbs operstate is `down`".into());
        let scope = ProposalScope {
            node_id: "n".into(),
            resource_id: Some("vm:wolfnet:pbs".into()),
        };
        let p = build_proposal(&h, &scope, "pbs");
        let labels: Vec<&str> = p.evidence.iter().map(|e| e.label.as_str()).collect();
        assert!(labels.iter().any(|l| l.starts_with("Failure 1")));
        assert!(labels.iter().any(|l| l.starts_with("Failure 2")));
    }
}
