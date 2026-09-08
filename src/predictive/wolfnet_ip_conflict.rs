// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! WolfNet IP conflicts — one address, two owners.
//!
//! ## Why this module exists (klas, 2026-09-07/08)
//!
//! "A container randomly loses connectivity on its WolfNet IP. Ping
//! works, curl to the service does not, host:port works, and the only
//! fix is to change the IP." Every one of those symptoms is what a
//! *second owner* of the same address produces:
//!
//! * **Live on two nodes.** Each node's status poll walks its peers in
//!   hash order and the last claim wins, so the cluster route map for
//!   that IP flips between the two owners on every poll, on every
//!   node, independently. Whichever container the packet reaches
//!   answers ping; only one of them runs the service.
//! * **Shadowed by a WolfNet peer.** wolfnetd delivers to a directly
//!   known peer *before* it consults the container route map
//!   (wolfnet src/main.rs, egress: `with_peer_by_ip` runs first). A
//!   container allocated the address of a peer — a VPN client, a node
//!   that is not in WolfStack's cluster — is unreachable from
//!   everywhere while that peer's tunnel is up: the peer answers ping
//!   and refuses the port. While the tunnel is down the delivery falls
//!   through to the route map and the container works, which is what
//!   makes this one come and go with the peer.
//!
//! Neither could be seen anywhere before. This analyzer names the IP
//! and both holders. The allocation side now skips live peer
//! addresses and the route map no longer claims stopped workloads
//! (see containers::wolfnet_active_ips), so new conflicts need two
//! genuinely running holders — which is exactly what an operator has
//! to resolve by hand, and exactly what this tells them.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::predictive::{
    Context,
    ack::AckStore,
    proposal::{Evidence, Proposal, ProposalScope, ProposalSource, RemediationPlan, Severity},
};

pub const FINDING_TYPE: &str = "wolfnet_ip_conflict";

/// Everything the analyzer needs, gathered by the sampler.
#[derive(Debug, Clone, Default)]
pub struct WolfnetIpConflictFacts {
    /// This node has a WolfNet address (wolfnet0 up).
    pub present: bool,
    pub self_label: String,
    pub self_host_ip: String,
    /// Running workload IPs on this node, host address excluded.
    pub local_active: Vec<String>,
    /// (label, host_ip, running workload IPs) per fresh cluster peer.
    pub remotes: Vec<(String, String, Vec<String>)>,
    /// Every peer wolfnetd currently knows, with its tunnel state.
    pub peers: Vec<crate::containers::WolfnetPeer>,
    /// Addresses that are legitimately held on every node — WolfRun
    /// service VIPs and Kubernetes route IPs — and must not read as a
    /// multi-node conflict.
    pub anycast: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictKind {
    /// Running on all of these nodes at once.
    LiveOnNodes(Vec<String>),
    /// A WolfNet peer owns the address. While its tunnel is up the
    /// local workload never receives a packet; while it is down the
    /// workload works, and goes dark the moment the peer reconnects.
    ShadowedByPeer { peer: String, connected: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub ip: String,
    pub kind: ConflictKind,
}

/// Pure: every IP with more than one live owner. Node holders come from
/// the active sets; peer shadowing is checked for THIS node's
/// workloads only (each node reports its own).
pub fn find_conflicts(facts: &WolfnetIpConflictFacts) -> Vec<Conflict> {
    let anycast: BTreeSet<&str> = facts.anycast.iter().map(|s| s.as_str()).collect();
    let mut holders: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut claims: Vec<(&str, &str, &str)> = Vec::new();
    for ip in &facts.local_active {
        claims.push((ip.as_str(), facts.self_label.as_str(), facts.self_host_ip.as_str()));
    }
    for (label, host, ips) in &facts.remotes {
        for ip in ips {
            claims.push((ip.as_str(), label.as_str(), host.as_str()));
        }
    }
    for (ip, label, host) in claims {
        if ip.is_empty() || ip == host || anycast.contains(ip) {
            continue;
        }
        holders.entry(ip).or_default().insert(label);
    }

    let mut out = Vec::new();
    for (ip, labels) in &holders {
        if labels.len() >= 2 {
            out.push(Conflict {
                ip: ip.to_string(),
                kind: ConflictKind::LiveOnNodes(labels.iter().map(|s| s.to_string()).collect()),
            });
        }
    }
    for ip in &facts.local_active {
        if anycast.contains(ip.as_str()) {
            continue;
        }
        if let Some(p) = facts.peers.iter().find(|p| &p.address == ip) {
            let peer = if p.hostname.is_empty() { ip.clone() } else { p.hostname.clone() };
            out.push(Conflict {
                ip: ip.clone(),
                kind: ConflictKind::ShadowedByPeer { peer, connected: p.connected },
            });
        }
    }
    out
}

/// Scope key. The kind is part of it: an address can be BOTH live on two
/// nodes and shadowed by a peer, and the two are different problems with
/// different fixes — sharing a key made the second silently overwrite the
/// first in the proposal store on every tick.
fn scope_for(ctx: &Context, ip: &str, kind: &str) -> ProposalScope {
    ProposalScope {
        node_id: ctx.node_id.clone(),
        resource_id: Some(format!("wolfnet-ip:{}:{}", ip, kind)),
    }
}

const KIND_NODES: &str = "nodes";
const KIND_PEER: &str = "peer";

fn kind_key(kind: &ConflictKind) -> &'static str {
    match kind {
        ConflictKind::LiveOnNodes(_) => KIND_NODES,
        ConflictKind::ShadowedByPeer { .. } => KIND_PEER,
    }
}

pub async fn sample_now_async(timeout: Duration) -> WolfnetIpConflictFacts {
    let fut = tokio::task::spawn_blocking(sample_now);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(f)) => f,
        _ => WolfnetIpConflictFacts::default(),
    }
}

fn local_hostname() -> String {
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let h = h.trim().to_string();
        if !h.is_empty() {
            return h;
        }
    }
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "this node".to_string())
}

fn sample_now() -> WolfnetIpConflictFacts {
    let mut facts = WolfnetIpConflictFacts::default();
    let active = crate::containers::wolfnet_active_ips_cached();
    let Some(host) = active.first().filter(|h| !h.is_empty()) else {
        return facts;
    };
    facts.present = true;
    facts.self_host_ip = host.clone();
    facts.self_label = local_hostname();
    facts.local_active = active[1..].to_vec();
    facts.remotes = crate::containers::remote_wolfnet_ips()
        .into_iter()
        .map(|r| {
            let ips: Vec<String> = r.active.iter().filter(|ip| **ip != r.host_ip).cloned().collect();
            (r.label, r.host_ip, ips)
        })
        .collect();
    facts.peers = crate::containers::wolfnet_live_peers();
    facts.anycast = crate::containers::wolfnet_anycast_ips();
    facts
}

pub fn analyze(
    ctx: &Context,
    facts: &WolfnetIpConflictFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    if !facts.present {
        return Vec::new();
    }
    let mut out = Vec::new();
    for c in find_conflicts(facts) {
        let scope = scope_for(ctx, &c.ip, kind_key(&c.kind));
        if acks.suppresses(FINDING_TYPE, &scope) || proposals.is_suppressed(FINDING_TYPE, &scope) {
            continue;
        }
        let (severity, title, why, evidence, commands) = match &c.kind {
            ConflictKind::LiveOnNodes(nodes) => (
                Severity::High,
                format!("WolfNet IP {} is live on {} at the same time", c.ip, nodes.join(" and ")),
                format!(
                    "A running workload on each of {} holds {}. The cluster route map keeps one \
                     owner per address and every node re-picks it on every status poll, in hash \
                     order, so traffic to {} lands on a different holder from one ten-second \
                     window to the next and from one node to the next. Whichever container it \
                     reaches answers ping; only one of them runs the service, so curl fails \
                     'randomly' while the published host:port keeps working. Give one of the \
                     workloads a new WolfNet IP — that is the only fix, and it is why changing \
                     the IP has always cleared this.",
                    nodes.join(", "), c.ip, c.ip
                ),
                nodes
                    .iter()
                    .map(|n| Evidence {
                        label: "Holder".into(),
                        value: n.clone(),
                        detail: None,
                        links: Vec::new(),
                    })
                    .collect::<Vec<_>>(),
                vec![
                    format!("# on each holder, find the workload:\ndocker ps -a --filter label=wolfnet.ip={}", c.ip),
                    format!("grep -l '^{}$' /var/lib/lxc/*/.wolfnet/ip 2>/dev/null", c.ip),
                    "# then Containers → the container → WolfNet IP → pick a free address".into(),
                ],
            ),
            // Connected decides whether this is happening or waiting to
            // happen: wolfnetd's `encrypt_and_send` refuses a peer with no
            // endpoint or no signed packet in 120 s, and the packet then
            // falls through to the container route map and reaches the
            // workload. The address is wrong either way — the tunnel
            // coming up is all it takes — but only one of the two states
            // is an outage, so only one of them reads as one.
            ConflictKind::ShadowedByPeer { peer, connected: true } => (
                Severity::High,
                format!("WolfNet IP {} belongs to peer {}; a workload here uses it too", c.ip, peer),
                format!(
                    "wolfnetd delivers to a directly known peer before it looks at the container \
                     route map, so every packet for {} from any node goes to {}, which answers \
                     ping and refuses the service port. The workload on this node holding {} \
                     never receives anything. Change the workload's WolfNet IP; allocation now \
                     skips peer addresses so this cannot be handed out again.",
                    c.ip, peer, c.ip
                ),
                vec![Evidence {
                    label: "Peer".into(),
                    value: peer.clone(),
                    detail: Some("tunnel up — from /var/run/wolfnet/status.json".into()),
                    links: Vec::new(),
                }],
                vec![
                    format!("docker ps -a --filter label=wolfnet.ip={}", c.ip),
                    "# Containers → the container → WolfNet IP → pick a free address".into(),
                ],
            ),
            ConflictKind::ShadowedByPeer { peer, connected: false } => (
                Severity::Warn,
                format!("WolfNet IP {} is peer {}'s address, and a workload here holds it", c.ip, peer),
                format!(
                    "{} has no live tunnel right now, so traffic for {} still falls through to \
                     the container route map and the workload answers. The moment that peer \
                     reconnects, wolfnetd delivers to it instead — it looks up a directly known \
                     peer before the route map — and the workload goes dark everywhere while \
                     still answering ping. Move the workload to a free WolfNet IP before that \
                     happens; allocation now skips peer addresses so this cannot be handed out \
                     again.",
                    peer, c.ip
                ),
                vec![Evidence {
                    label: "Peer".into(),
                    value: peer.clone(),
                    detail: Some("tunnel down — from /var/run/wolfnet/status.json".into()),
                    links: Vec::new(),
                }],
                vec![
                    format!("docker ps -a --filter label=wolfnet.ip={}", c.ip),
                    "# Containers → the container → WolfNet IP → pick a free address".into(),
                ],
            ),
        };
        out.push(Proposal::new(
            FINDING_TYPE,
            ProposalSource::Rule,
            severity,
            title,
            why,
            evidence,
            RemediationPlan::Manual {
                instructions: "Move one holder to a different WolfNet IP. Nothing else repairs this: \
                               one address cannot serve two owners."
                    .into(),
                commands,
            },
            scope,
        ));
    }
    out
}

/// Every IP we evaluated this tick is covered, plus any stored proposal
/// of this type on this node (so a conflict whose IP vanished from
/// every set still resolves).
pub fn covered_scopes(
    ctx: &Context,
    facts: &WolfnetIpConflictFacts,
    store: &crate::predictive::proposal::ProposalStore,
) -> Vec<(String, ProposalScope)> {
    if !facts.present {
        return Vec::new();
    }
    let mut out = Vec::new();
    for ip in &facts.local_active {
        out.push((FINDING_TYPE.to_string(), scope_for(ctx, ip, KIND_NODES)));
        out.push((FINDING_TYPE.to_string(), scope_for(ctx, ip, KIND_PEER)));
    }
    for (_, _, ips) in &facts.remotes {
        for ip in ips {
            out.push((FINDING_TYPE.to_string(), scope_for(ctx, ip, KIND_NODES)));
        }
    }
    for p in &store.proposals {
        if p.finding_type == FINDING_TYPE && p.scope.node_id == ctx.node_id {
            out.push((p.finding_type.clone(), p.scope.clone()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(hostname: &str, address: &str, connected: bool) -> crate::containers::WolfnetPeer {
        crate::containers::WolfnetPeer {
            hostname: hostname.into(),
            address: address.into(),
            connected,
        }
    }

    fn facts() -> WolfnetIpConflictFacts {
        WolfnetIpConflictFacts {
            present: true,
            self_label: "hemulen".into(),
            self_host_ip: "10.10.10.2".into(),
            local_active: vec!["10.10.10.150".into(), "10.10.10.160".into(), "10.10.10.50".into()],
            remotes: vec![
                ("ninni".into(), "10.10.10.3".into(), vec!["10.10.10.150".into(), "10.10.10.50".into()]),
                ("klnet".into(), "10.10.10.4".into(), vec!["10.10.10.170".into(), "10.10.10.50".into()]),
            ],
            peers: vec![
                peer("ninni", "10.10.10.3", true),
                peer("laptop", "10.10.10.160", true),
            ],
            anycast: vec!["10.10.10.50".into()],
        }
    }

    #[test]
    fn an_ip_running_on_two_nodes_is_one_conflict_naming_both() {
        let out = find_conflicts(&facts());
        let live: Vec<&Conflict> = out.iter().filter(|c| c.ip == "10.10.10.150").collect();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].kind, ConflictKind::LiveOnNodes(vec!["hemulen".into(), "ninni".into()]));
    }

    #[test]
    fn a_local_workload_on_a_live_peer_address_is_shadowed() {
        let out = find_conflicts(&facts());
        assert!(out.contains(&Conflict {
            ip: "10.10.10.160".into(),
            kind: ConflictKind::ShadowedByPeer { peer: "laptop".into(), connected: true },
        }));
    }

    #[test]
    fn a_peer_with_no_live_tunnel_is_reported_as_the_latent_case() {
        let mut f = facts();
        f.peers = vec![peer("laptop", "10.10.10.160", false)];
        let out = find_conflicts(&f);
        assert!(out.contains(&Conflict {
            ip: "10.10.10.160".into(),
            kind: ConflictKind::ShadowedByPeer { peer: "laptop".into(), connected: false },
        }), "{:?}", out);
    }

    #[test]
    fn anycast_vips_and_unique_ips_are_not_conflicts() {
        let out = find_conflicts(&facts());
        assert!(out.iter().all(|c| c.ip != "10.10.10.50"), "{:?}", out);
        assert!(out.iter().all(|c| c.ip != "10.10.10.170"), "{:?}", out);
        assert_eq!(out.len(), 2, "{:?}", out);
    }

    #[test]
    fn host_addresses_are_never_workload_claims() {
        let mut f = facts();
        f.local_active = vec!["10.10.10.2".into()];
        f.remotes = vec![("ninni".into(), "10.10.10.3".into(), vec!["10.10.10.2".into()])];
        f.peers.clear();
        assert!(find_conflicts(&f).is_empty());
    }
}
