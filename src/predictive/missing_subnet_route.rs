// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! Missing WolfNet subnet-route detector.
//!
//! Symptom: peers reachable (you can ping `10.100.10.30`), but the VMs /
//! LXC containers / Docker containers behind those peers aren't (you
//! cannot ping `172.17.0.5` on the peer's `docker0`). The WolfRouter
//! reconciliation loop happily applies every subnet_route the operator
//! configured, but nothing currently checks that the configured set is
//! *complete* — i.e. that every workload subnet on every remote peer
//! has a subnet_route from this node pointing at the right gateway.
//!
//! This analyzer closes the loop. Each peer now ships its
//! `workload_subnets` in `StatusReport` (see `agent::Node`); we read
//! those, intersect with this node's WolfRouter `subnet_routes`, and
//! emit a high-severity finding for every remote workload subnet that
//! has no route from this node.
//!
//! klasSponsor 2026-05-11: his klnet-12gb VPS can ping all three
//! peers but cannot ping any of the VMs / LXCs / Dockers behind them.
//! He has one route (`10.10.0.0/16 via 10.100.10.30`) and is missing
//! all the others. This finding tells him exactly which CIDR + gateway
//! to add via WolfRouter so the reconciler can apply it.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::predictive::{
    Context,
    ack::AckStore,
    proposal::{Evidence, Proposal, ProposalScope, RemediationPlan, Severity},
};

/// Finding type emitted by this analyzer.
pub const FINDING_TYPE: &str = "missing_wolfnet_subnet_route";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingRoute {
    /// Peer name from /etc/wolfnet/config.toml (typically the peer's
    /// hostname).
    pub peer_name: String,
    /// Peer's WolfNet IP (the gateway value that a subnet_route would
    /// need to point at).
    pub peer_wolfnet_ip: String,
    /// The workload subnet on the peer that this node has no route to.
    pub subnet_cidr: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MissingSubnetRouteFacts {
    pub missing: Vec<MissingRoute>,
    /// Set to false when we couldn't read either /etc/wolfnet/config.toml,
    /// the cluster nodes file, or the WolfRouter config — in any of those
    /// cases we don't know enough to emit OR clear findings, so the
    /// analyzer no-ops cleanly.
    pub scanned: bool,
}

pub async fn sample_now_async(_timeout: Duration) -> MissingSubnetRouteFacts {
    tokio::task::spawn_blocking(sample_blocking).await.unwrap_or_default()
}

fn sample_blocking() -> MissingSubnetRouteFacts {
    let peers = crate::networking::get_wolfnet_peers_list();
    if peers.is_empty() {
        return MissingSubnetRouteFacts::default();
    }

    let nodes = match load_nodes_from_disk() {
        Some(n) => n,
        None => return MissingSubnetRouteFacts::default(),
    };

    let cfg = crate::networking::router::RouterConfig::load();
    let configured: Vec<(String, String)> = cfg.subnet_routes.iter()
        .filter(|r| r.enabled)
        .map(|r| (r.subnet_cidr.clone(), r.gateway.clone()))
        .collect();

    // IPv6 workload subnets are only flagged when the reconciler on THIS
    // node could actually act on them: the operator opted into IPv6 subnet
    // routing AND this host has a working v6 stack. Off (default) → v6
    // subnets are skipped exactly as before the feature existed, so a
    // v6-disabled node never sees an un-actionable finding.
    let v6_active = cfg.ipv6_subnet_routing
        && crate::networking::router::ipv6_available();

    // What the kernel already routes into WolfNet. A subnet covered here is
    // reachable whether or not WolfRouter has a config entry for it.
    let kernel_routed = kernel_wolfnet_route_cidrs();

    // Subnets this node ALSO owns locally. A peer's copy of one of these can
    // never be usefully routed over WolfNet from here — the kernel's own
    // `proto kernel scope link` route for the local bridge wins/collides —
    // so recommending a route for it is always wrong. Same guard WolfRouter
    // auto-apply applies (see `auto_apply_missing_workload_routes`).
    let local_subnets: HashSet<String> =
        crate::networking::collect_workload_subnets().into_iter().collect();

    let mut missing = Vec::new();
    for peer in &peers {
        let peer_ip_only = peer.ip.split('/').next().unwrap_or(&peer.ip).to_string();
        if peer_ip_only.is_empty() { continue; }

        // Find the cluster Node for this peer. Match by hostname first
        // (most reliable — wolfnet peer names ARE hostnames in every
        // observed deployment). Fall back to matching by an interface
        // IP if the peer's record carries it.
        let node = nodes.iter().find(|n| n.hostname == peer.name);
        let workload_subnets = match node {
            Some(n) => &n.workload_subnets,
            None => continue,
        };
        if workload_subnets.is_empty() { continue; }

        for sub in workload_subnets {
            if !subnet_qualifies(sub, v6_active, &local_subnets) { continue; }
            if subnet_already_covered(sub, &peer_ip_only, &configured) { continue; }
            // Already routed by the kernel — the subnet is reachable, so
            // reporting it unreachable would be false, and the suggested
            // `ip route` command could not apply anyway.
            if kernel_route_covers(sub, &kernel_routed) { continue; }
            missing.push(MissingRoute {
                peer_name: peer.name.clone(),
                peer_wolfnet_ip: peer_ip_only.clone(),
                subnet_cidr: sub.clone(),
            });
        }
    }

    MissingSubnetRouteFacts { missing, scanned: true }
}

/// The per-subnet gate that needs no route context — everything decidable
/// from the CIDR itself plus this node's own state:
///
/// • v4 always qualifies. v6 qualifies only when IPv6 subnet routing is
///   active on this node (see `v6_active`); otherwise the finding could
///   never auto-resolve because the reconciler's v6 apply path is gated
///   the same way. Anything that's neither a well-formed v4 nor v6 CIDR
///   (bare IP, garbage) is skipped. (First-class v6 subnet routing built
///   2026-06-16; was filtered out as a broken command in v24.47.3 —
///   CodeBangZoom.)
/// • Universal default container bridges (docker0 172.17.0.0/16, lxcbr0
///   10.0.3.0/24) never qualify: EVERY Docker/LXC node owns its own copy,
///   so "route it to peer X" is wrong on its face — and used to be emitted
///   once per peer, recommending the same CIDR via several different
///   gateways at once. WolfRouter auto-apply has always skipped these
///   (`DEFAULT_BRIDGE_CIDRS`); the finding now matches, instead of telling
///   the operator to hand-configure the exact route auto-apply refuses to
///   plant (nc cluster report, 2026-08-15).
/// • Subnets this node also owns locally never qualify, for the same
///   collision reason — mirrors auto-apply's `local_subnets` guard.
fn subnet_qualifies(sub: &str, v6_active: bool, local_subnets: &HashSet<String>) -> bool {
    if is_ipv4_cidr(sub) {
        // proceed
    } else if is_ipv6_cidr(sub) {
        if !v6_active { return false; }
    } else {
        return false;
    }
    if crate::networking::router::is_default_bridge_cidr(sub) { return false; }
    !local_subnets.contains(sub)
}

/// Load the persisted cluster nodes (workload_subnets included since the
/// v22.13.0 schema bump). Same path as `ClusterState::save_nodes`.
/// Destination CIDRs this node already routes over the WolfNet interface,
/// read from the kernel.
///
/// The analyzer used to decide "unreachable" purely from WolfRouter's
/// CONFIG. That is a different layer from the kernel table, and when the
/// two disagreed the finding could never clear: the route was already
/// installed (by wolfnetd, by an operator, or by an older build), so the
/// subnet WAS reachable, but with no matching WolfRouter entry the
/// analyzer kept reporting it — and the suggested `ip route add` could only
/// ever answer `RTNETLINK answers: File exists`. Reported by klas,
/// 2026-08-14: "either this is a useless error, or the fix is not working."
/// It was the first.
fn kernel_wolfnet_route_cidrs() -> Vec<String> {
    let mut out = Vec::new();
    for args in [
        vec!["route", "show", "dev", "wolfnet0"],
        vec!["-6", "route", "show", "dev", "wolfnet0"],
    ] {
        let Ok(o) = std::process::Command::new("ip").args(&args).output() else { continue };
        if !o.status.success() {
            continue;
        }
        out.extend(parse_route_destinations(&String::from_utf8_lossy(&o.stdout)));
    }
    out
}

/// Pull destination CIDRs out of `ip route show` output.
///
/// Each line starts with the destination; `default` and any bare address
/// without a prefix are ignored — this is only used to answer "is this
/// CIDR already routed", and a host route or default cannot establish
/// that for a subnet.
fn parse_route_destinations(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|d| *d != "default" && d.contains('/'))
        .map(|d| d.to_string())
        .collect()
}

/// True when one of `routed` (kernel destinations over WolfNet) covers
/// `target_subnet`.
///
/// Gateway-agnostic on purpose: a route pointing into the WolfNet
/// interface means packets for that subnet enter the overlay, which is
/// what "reachable from this node" means here. Which peer ultimately
/// answers is wolfnetd's business, not this analyzer's.
fn kernel_route_covers(target_subnet: &str, routed: &[String]) -> bool {
    if is_ipv6_cidr(target_subnet) {
        let Some((tnet, tprefix)) = parse_cidr_v6(target_subnet) else { return false };
        return routed.iter().any(|r| {
            if !is_ipv6_cidr(r) { return false; }
            let Some((rnet, rprefix)) = parse_cidr_v6(r) else { return false };
            if rprefix > tprefix { return false; }
            let mask: u128 = if rprefix == 0 { 0 }
                else { u128::MAX.checked_shl(128 - rprefix).unwrap_or(0) };
            (tnet & mask) == (rnet & mask)
        });
    }
    let Some((tnet, tprefix)) = parse_cidr(target_subnet) else { return false };
    routed.iter().any(|r| {
        if is_ipv6_cidr(r) { return false; }
        let Some((rnet, rprefix)) = parse_cidr(r) else { return false };
        if rprefix > tprefix { return false; }
        let mask: u32 = if rprefix == 0 { 0 }
            else { 0xFFFF_FFFFu32.checked_shl(32 - rprefix).unwrap_or(0) };
        (tnet & mask) == rnet
    })
}

/// Reading the FILE (not live ClusterState) is deliberate — it keeps this
/// module free of an agent dependency and means the finding and WolfRouter
/// auto-apply (which reads the same file for the same reason) always act on
/// identical data. Freshness is guaranteed by the poll loop: since the
/// stale-nodes.json fix, `poll_remote_nodes` persists within one 10s cycle
/// of any peer's workload_subnets (or other identity fields) changing —
/// see `ClusterState::persistent_peer_fields_changed`.
fn load_nodes_from_disk() -> Option<Vec<crate::agent::Node>> {
    let path = &crate::paths::get().nodes_config;
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<Vec<crate::agent::Node>>(&data).ok()
}

/// True iff the configured routes already cover `target_subnet` through a
/// gateway equal to `peer_ip`. Coverage is satisfied by either an exact
/// CIDR match OR by any configured route that's a strict superset of
/// `target_subnet` and uses the same gateway — e.g. a configured
/// `10.0.0.0/8 via X` covers a peer's `10.0.3.0/24` workload.
fn subnet_already_covered(target_subnet: &str, peer_ip: &str, configured: &[(String, String)]) -> bool {
    // Dispatch on the target's family; a configured route of the other
    // family can never cover it (different address space).
    if is_ipv6_cidr(target_subnet) {
        let (tnet, tprefix) = match parse_cidr_v6(target_subnet) {
            Some(t) => t,
            None => return false,
        };
        for (route_cidr, route_gw) in configured {
            if route_gw.trim() != peer_ip { continue; }
            if !is_ipv6_cidr(route_cidr) { continue; }
            let (rnet, rprefix) = match parse_cidr_v6(route_cidr) { Some(r) => r, None => continue };
            if rprefix > tprefix { continue; }
            let mask: u128 = if rprefix == 0 { 0 }
                else { u128::MAX.checked_shl(128 - rprefix).unwrap_or(0) };
            if (tnet & mask) == (rnet & mask) { return true; }
        }
        return false;
    }

    let target = match parse_cidr(target_subnet) {
        Some(t) => t,
        None => return false, // unparseable — leave it alone, don't flag
    };
    for (route_cidr, route_gw) in configured {
        if route_gw.trim() != peer_ip { continue; }
        if is_ipv6_cidr(route_cidr) { continue; }
        let route = match parse_cidr(route_cidr) {
            Some(r) => r,
            None => continue,
        };
        // Configured route's prefix must be at least as wide as the target
        // (i.e. numerically less or equal). Then check the target's
        // network falls inside the route's mask.
        if route.1 > target.1 { continue; }
        let mask: u32 = if route.1 == 0 { 0 }
            else { 0xFFFF_FFFFu32.checked_shl(32 - route.1).unwrap_or(0) };
        if (target.0 & mask) == route.0 {
            return true;
        }
    }
    false
}

/// True only for a well-formed IPv4 CIDR. The subnet-route feature is
/// IPv4-only (see the skip in `sample_blocking`), so this gates what the
/// analyzer flags — IPv6 CIDRs (which contain `:`) and anything unparseable
/// are excluded.
fn is_ipv4_cidr(cidr: &str) -> bool {
    // Require an explicit `/prefix` (split_once, not split) so a bare IP
    // isn't mistaken for a CIDR — workload subnets are always CIDRs.
    cidr.split_once('/')
        .and_then(|(ip, _)| ip.parse::<Ipv4Addr>().ok())
        .is_some()
}

fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 32 { return None; }
    let mask = if prefix == 0 { 0 }
        else { 0xFFFF_FFFFu32.checked_shl(32 - prefix).unwrap_or(0) };
    Some((u32::from(ip) & mask, prefix))
}

/// True only for a well-formed IPv6 CIDR — network part parses as
/// `Ipv6Addr` with an explicit `/prefix`. Mirrors `is_ipv4_cidr` for the v6
/// family (only acted on when IPv6 subnet routing is active on this node).
fn is_ipv6_cidr(cidr: &str) -> bool {
    cidr.split_once('/')
        .and_then(|(ip, _)| ip.parse::<Ipv6Addr>().ok())
        .is_some()
}

/// Parse an IPv6 CIDR into `(network_u128, prefix)`, network masked to the
/// prefix. None on malformed input or prefix > 128.
fn parse_cidr_v6(cidr: &str) -> Option<(u128, u32)> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let ip: Ipv6Addr = ip_str.parse().ok()?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 128 { return None; }
    let mask: u128 = if prefix == 0 { 0 }
        else { u128::MAX.checked_shl(128 - prefix).unwrap_or(0) };
    Some((u128::from(ip) & mask, prefix))
}

pub fn analyze(
    ctx: &Context,
    facts: &MissingSubnetRouteFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    if !facts.scanned { return out; }
    // Dedup: a peer with five workload subnets could otherwise produce
    // five separate cards in the inbox — collapse to one finding per peer.
    let mut seen_peers: HashSet<String> = HashSet::new();
    for m in &facts.missing {
        if !seen_peers.insert(m.peer_wolfnet_ip.clone()) { continue; }
        let peer_missing: Vec<&MissingRoute> = facts.missing.iter()
            .filter(|r| r.peer_wolfnet_ip == m.peer_wolfnet_ip)
            .collect();
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("wolfnet-peer:{}", m.peer_wolfnet_ip)),
        };
        if acks.suppresses(FINDING_TYPE, &scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE, &scope) { continue; }
        out.push(build_proposal(&peer_missing, &scope));
    }
    out
}

pub fn covered_scopes(
    ctx: &Context,
    facts: &MissingSubnetRouteFacts,
) -> Vec<(String, ProposalScope)> {
    if !facts.scanned { return Vec::new(); }
    // Cover every peer's WolfNet IP — including ones with no missing
    // routes — so when the operator adds the route the finding clears.
    // Done from the (also scanned) peers list rather than just the
    // missing rows so we don't keep stale findings open.
    let peers = crate::networking::get_wolfnet_peers_list();
    peers.iter().filter_map(|p| {
        let ip = p.ip.split('/').next()?.to_string();
        if ip.is_empty() { return None; }
        Some((FINDING_TYPE.to_string(), ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("wolfnet-peer:{}", ip)),
        }))
    }).collect()
}

fn build_proposal(missing: &[&MissingRoute], scope: &ProposalScope) -> Proposal {
    let first = missing[0];
    let title = if missing.len() == 1 {
        format!(
            "WolfNet peer `{}` — workload subnet `{}` is unreachable from this node",
            first.peer_name, first.subnet_cidr,
        )
    } else {
        format!(
            "WolfNet peer `{}` — {} workload subnets are unreachable from this node",
            first.peer_name, missing.len(),
        )
    };

    let subnet_list = missing.iter()
        .map(|m| format!("  • `{}`", m.subnet_cidr))
        .collect::<Vec<_>>()
        .join("\n");

    let why = format!(
        "Peer `{name}` ({gw}) reports {n} workload subnet(s) on its Docker / LXC / VM bridges:\n\n\
         {list}\n\n\
         …but this node has no WolfRouter subnet_route entry whose gateway is `{gw}` covering them. \
         The peer's host is reachable (its WolfNet IP answers), but packets sent to a VM or \
         container on the listed subnets have nowhere to go from here — the kernel doesn't know \
         that those CIDRs live behind `{gw}` until you tell WolfRouter. \
         \n\nThis is the \"peers ping fine, workloads behind them don't\" symptom — adding the \
         route below and waiting one tick for the reconciler is the full fix.",
        name = first.peer_name,
        gw = first.peer_wolfnet_ip,
        n = missing.len(),
        list = subnet_list,
    );

    let evidence: Vec<Evidence> = vec![
        Evidence {
            label: "Peer".into(),
            value: format!("{} ({})", first.peer_name, first.peer_wolfnet_ip),
            detail: Some("Reachable — the missing piece is routing to its workloads.".into()),
            links: Vec::new(),
        },
        Evidence {
            label: "Missing subnets".into(),
            value: missing.iter().map(|m| m.subnet_cidr.clone()).collect::<Vec<_>>().join(", "),
            detail: Some("Advertised via cluster gossip from the peer's local bridges (Docker / LXC / VM).".into()),
            links: Vec::new(),
        },
    ];

    let routes_to_add = missing.iter()
        .map(|m| format!("  subnet_cidr = \"{}\", gateway = \"{}\"", m.subnet_cidr, m.peer_wolfnet_ip))
        .collect::<Vec<_>>()
        .join("\n");

    let instructions = format!(
        "Open WolfRouter on this node, go to Subnet Routes, and add one entry per missing \
         CIDR — gateway always `{}` (the peer's WolfNet IP). Concretely:\n\n{}\n\n\
         The route reconciler from v22.10.6 will apply each route within ~60s and \
         the finding will auto-resolve on the next tick. If you'd rather not configure the \
         routes (the peer's workloads aren't supposed to be cluster-reachable), dismiss this \
         finding — it'll stay dismissed.",
        first.peer_wolfnet_ip,
        routes_to_add,
    );

    let commands = missing.iter().map(|m| {
        if is_ipv6_cidr(&m.subnet_cidr) {
            // v6 is a device route — no `via` (a v4 next-hop is invalid for
            // a v6 dest); wolfnetd resolves the CIDR to the v4 gateway peer.
            // WolfRouter still stores gateway = the peer's WolfNet IP.
            format!(
                "ip -6 route replace {} dev wolfnet0   # one-off; gateway {} is resolved by wolfnetd. WolfRouter is the canonical place",
                m.subnet_cidr, m.peer_wolfnet_ip,
            )
        } else {
            format!(
                "ip route replace {} via {} dev wolfnet0   # one-off; WolfRouter is the canonical place",
                m.subnet_cidr, m.peer_wolfnet_ip,
            )
        }
    }).collect();

    Proposal::new_rule(
        FINDING_TYPE,
        Severity::High,
        title,
        why,
        evidence,
        RemediationPlan::Manual { instructions, commands },
        scope.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// nc cluster report, 2026-08-15: five nodes each own the default Docker
    /// bridge, and the finding recommended `172.17.0.0/16 via pve1`, `via
    /// pve3` AND `via pbs` simultaneously — routes WolfRouter auto-apply
    /// itself refuses to plant. Default bridge CIDRs must never be flagged.
    #[test]
    fn default_bridge_cidrs_are_never_flagged() {
        let no_local = HashSet::new();
        assert!(!subnet_qualifies("172.17.0.0/16", false, &no_local));
        assert!(!subnet_qualifies("10.0.3.0/24", false, &no_local));
        // …while a genuinely unique workload subnet still qualifies.
        assert!(subnet_qualifies("172.23.0.0/24", false, &no_local));
    }

    /// A subnet this node ALSO owns locally collides with the kernel's own
    /// bridge route — same guard as auto-apply's `local_subnets` skip.
    #[test]
    fn locally_owned_subnets_are_never_flagged() {
        let local: HashSet<String> = ["172.30.0.0/16".to_string()].into_iter().collect();
        assert!(!subnet_qualifies("172.30.0.0/16", false, &local));
        assert!(subnet_qualifies("172.31.0.0/16", false, &local));
    }

    /// The family gate carried over from the old inline check: garbage and
    /// bare IPs never qualify; v6 only when v6 routing is active.
    #[test]
    fn family_gate_matches_old_inline_behaviour() {
        let no_local = HashSet::new();
        assert!(!subnet_qualifies("not-a-cidr", true, &no_local));
        assert!(!subnet_qualifies("10.0.0.1", true, &no_local));
        assert!(!subnet_qualifies("fc00:abcd::/48", false, &no_local));
        assert!(subnet_qualifies("fc00:abcd::/48", true, &no_local));
    }

    #[test]
    fn subnet_already_covered_exact_match() {
        let configured = vec![("10.10.0.0/16".into(), "10.100.10.30".into())];
        assert!(subnet_already_covered("10.10.0.0/16", "10.100.10.30", &configured));
    }

    #[test]
    fn ipv4_cidr_filter_excludes_ipv6_and_garbage() {
        // The subnet-route feature is IPv4-only; v6 workload subnets must be
        // skipped so the analyzer never emits a broken `ip route add <v6> via
        // <v4>` command (CodeBangZoom, 2026-06-15).
        assert!(is_ipv4_cidr("10.10.10.0/24"));
        assert!(is_ipv4_cidr("192.168.1.0/24"));
        assert!(!is_ipv4_cidr("fc42:5009:ba4b:5ab0::/64"));
        assert!(!is_ipv4_cidr("fd00::/8"));
        assert!(!is_ipv4_cidr("not-a-cidr"));
        // A bare IP (no /prefix) is not a CIDR.
        assert!(!is_ipv4_cidr("10.0.0.1"));
    }

    #[test]
    fn ipv6_cidr_detection() {
        assert!(is_ipv6_cidr("fc42:5009:ba4b:5ab0::/64"));
        assert!(is_ipv6_cidr("fd00::/8"));
        assert!(!is_ipv6_cidr("10.10.0.0/24")); // v4 is never v6
        assert!(!is_ipv6_cidr("fc00::1")); // no /prefix
        assert!(!is_ipv6_cidr("garbage"));
    }

    #[test]
    fn subnet_already_covered_ipv6() {
        // Same gateway (always the peer's v4 WolfNet IP), exact + wider.
        let configured = vec![("fc00:abcd::/32".to_string(), "10.100.10.30".to_string())];
        assert!(subnet_already_covered("fc00:abcd::/32", "10.100.10.30", &configured));
        assert!(subnet_already_covered("fc00:abcd:1::/48", "10.100.10.30", &configured));
        // Wrong gateway is not covered.
        assert!(!subnet_already_covered("fc00:abcd:1::/48", "10.100.10.99", &configured));
        // A narrower configured v6 route does not cover a wider target.
        let narrow = vec![("fc00:abcd:1::/48".to_string(), "10.100.10.30".to_string())];
        assert!(!subnet_already_covered("fc00:abcd::/32", "10.100.10.30", &narrow));
    }

    #[test]
    fn subnet_coverage_never_crosses_families() {
        // A configured v4 route must never "cover" a v6 target, or the
        // analyzer would wrongly suppress a real v6 finding (and vice versa).
        let v4 = vec![("10.0.0.0/8".to_string(), "10.100.10.30".to_string())];
        assert!(!subnet_already_covered("fc00:abcd::/48", "10.100.10.30", &v4));
        let v6 = vec![("fc00::/16".to_string(), "10.100.10.30".to_string())];
        assert!(!subnet_already_covered("10.10.0.0/16", "10.100.10.30", &v6));
    }

    #[test]
    fn v6_command_is_device_route_not_via() {
        // The remediation command for a v6 missing route must be the device
        // route (`ip -6 route replace … dev wolfnet0`) — never the broken
        // `ip route … <v6> via <v4>` form that v24.47.3 filtered out.
        // `replace` rather than `add`: an `add` that collides with an
        // existing route fails with "File exists" and the operator is left
        // with a correction that cannot be applied (klas, 2026-08-14).
        let missing = MissingRoute {
            peer_name: "ninni".into(),
            peer_wolfnet_ip: "10.100.10.30".into(),
            subnet_cidr: "fc00:abcd::/48".into(),
        };
        let scope = ProposalScope { node_id: "n".into(), resource_id: None };
        let p = build_proposal(&[&missing], &scope);
        if let RemediationPlan::Manual { commands, .. } = &p.remediation {
            assert_eq!(commands.len(), 1);
            assert!(commands[0].starts_with("ip -6 route replace fc00:abcd::/48 dev wolfnet0"),
                "got: {}", commands[0]);
            assert!(!commands[0].contains(" via "), "v6 device route must have no via: {}", commands[0]);
        } else {
            panic!("expected Manual remediation");
        }
    }

    #[test]
    fn subnet_covered_by_wider_route_same_gateway() {
        // Klas's case: he has `10.10.0.0/16 via 10.100.10.30` configured.
        // A peer workload at `10.10.10.0/24` (LAN subnet) IS covered by
        // that wider /16 — should NOT be flagged as missing.
        let configured = vec![("10.10.0.0/16".into(), "10.100.10.30".into())];
        assert!(subnet_already_covered("10.10.10.0/24", "10.100.10.30", &configured),
            "a /24 inside a configured /16 with the same gateway is covered");
    }

    #[test]
    fn subnet_not_covered_by_narrower_route() {
        // A configured /24 does NOT cover a /16 — the operator only has
        // a slice of what's needed.
        let configured = vec![("10.10.10.0/24".into(), "10.100.10.30".into())];
        assert!(!subnet_already_covered("10.10.0.0/16", "10.100.10.30", &configured));
    }

    #[test]
    fn subnet_not_covered_when_gateway_differs() {
        // The route exists but points at a DIFFERENT peer — the workload
        // is still unreachable from this node.
        let configured = vec![("172.17.0.0/16".into(), "10.100.10.20".into())];
        assert!(!subnet_already_covered("172.17.0.0/16", "10.100.10.30", &configured),
            "same subnet but wrong gateway must still flag as missing");
    }

    #[test]
    fn analyze_emits_one_finding_per_peer_even_for_multiple_subnets() {
        let facts = MissingSubnetRouteFacts {
            missing: vec![
                MissingRoute { peer_name: "ninni".into(), peer_wolfnet_ip: "10.100.10.30".into(),
                    subnet_cidr: "172.17.0.0/16".into() },
                MissingRoute { peer_name: "ninni".into(), peer_wolfnet_ip: "10.100.10.30".into(),
                    subnet_cidr: "10.0.3.0/24".into() },
                MissingRoute { peer_name: "ninni".into(), peer_wolfnet_ip: "10.100.10.30".into(),
                    subnet_cidr: "10.0.10.0/24".into() },
            ],
            scanned: true,
        };
        let ctx = Context::for_node("klnet-12gb");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert_eq!(out.len(), 1, "one card per peer regardless of subnet count");
        assert!(out[0].title.contains("ninni"));
        assert!(out[0].title.contains("3 workload subnets"));
        // All three subnets must appear in the body.
        assert!(out[0].why.contains("172.17.0.0/16"));
        assert!(out[0].why.contains("10.0.3.0/24"));
        assert!(out[0].why.contains("10.0.10.0/24"));
    }

    #[test]
    fn analyze_separate_findings_for_different_peers() {
        let facts = MissingSubnetRouteFacts {
            missing: vec![
                MissingRoute { peer_name: "ninni".into(), peer_wolfnet_ip: "10.100.10.30".into(),
                    subnet_cidr: "172.17.0.0/16".into() },
                MissingRoute { peer_name: "lillamy".into(), peer_wolfnet_ip: "10.100.10.20".into(),
                    subnet_cidr: "172.17.0.0/16".into() },
            ],
            scanned: true,
        };
        let ctx = Context::for_node("klnet-12gb");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|p| p.title.contains("ninni")));
        assert!(out.iter().any(|p| p.title.contains("lillamy")));
    }

    #[test]
    fn scanned_false_yields_no_proposals() {
        let facts = MissingSubnetRouteFacts {
            missing: vec![MissingRoute {
                peer_name: "x".into(), peer_wolfnet_ip: "10.100.10.30".into(),
                subnet_cidr: "172.17.0.0/16".into(),
            }],
            scanned: false,
        };
        let ctx = Context::for_node("klnet-12gb");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        assert!(analyze(&ctx, &facts, &acks, &proposals).is_empty());
    }
}

#[cfg(test)]
mod kernel_coverage_tests {
    use super::*;

    /// klas, 2026-08-14: the inbox repeated "workload subnets are
    /// unreachable" while the offered fix always answered "File exists".
    /// Both symptoms are one cause — the route WAS installed, so the
    /// subnet was reachable and `ip route add` had nothing to do. A
    /// destination already routed into WolfNet must not be reported.
    #[test]
    fn a_subnet_already_routed_over_wolfnet_is_not_missing() {
        let routed = vec!["172.18.0.0/16".to_string()];
        assert!(kernel_route_covers("172.18.0.0/16", &routed));
    }

    /// A wider kernel route covers a narrower workload subnet — the same
    /// supernet rule the configured-route check already applies.
    #[test]
    fn a_wider_kernel_route_covers_a_narrower_subnet() {
        let routed = vec!["10.0.0.0/8".to_string()];
        assert!(kernel_route_covers("10.4.3.0/24", &routed));
        // ...but a narrower route does NOT cover a wider subnet.
        let narrow = vec!["10.4.3.0/24".to_string()];
        assert!(!kernel_route_covers("10.0.0.0/8", &narrow));
    }

    /// A genuinely absent route must still be reported, or the fix would
    /// have silenced a real problem instead of a false one.
    #[test]
    fn an_unrouted_subnet_is_still_missing() {
        let routed = vec!["10.0.0.0/8".to_string(), "172.18.0.0/16".to_string()];
        assert!(!kernel_route_covers("192.168.5.0/24", &routed));
        assert!(!kernel_route_covers("10.0.0.0/24", &[]));
    }

    /// Families never cross-cover: a v4 route cannot make a v6 subnet
    /// reachable and vice versa.
    #[test]
    fn address_families_do_not_cross_cover() {
        assert!(!kernel_route_covers("fc00:abcd::/48", &["10.0.0.0/8".to_string()]));
        assert!(!kernel_route_covers("10.0.0.0/8", &["fc00:abcd::/48".to_string()]));
        // A /48 spans only the third group it names: fc00:abcd::/48 covers
        // fc00:abcd:0000::* and NOT fc00:abcd:1::, which is a different /48.
        assert!(!kernel_route_covers("fc00:abcd:1::/64", &["fc00:abcd::/48".to_string()]));
        assert!(kernel_route_covers("fc00:abcd:0:1::/64", &["fc00:abcd::/48".to_string()]));
        // A /32 does span it.
        assert!(kernel_route_covers("fc00:abcd:1::/64", &["fc00:abcd::/32".to_string()]));
    }

    /// `default` and host routes cannot establish that a SUBNET is
    /// routed, so they are not treated as coverage.
    #[test]
    fn default_and_host_routes_are_ignored() {
        let text = "default via 10.100.10.1 dev wolfnet0\n\
                    10.100.10.5 dev wolfnet0 scope link\n\
                    172.18.0.0/16 via 10.100.10.30 dev wolfnet0\n";
        let dests = parse_route_destinations(text);
        assert_eq!(dests, vec!["172.18.0.0/16"]);
    }

    #[test]
    fn route_parsing_tolerates_empty_and_malformed_output() {
        assert!(parse_route_destinations("").is_empty());
        assert!(parse_route_destinations("\n\n").is_empty());
        assert!(!kernel_route_covers("not-a-cidr", &["10.0.0.0/8".to_string()]));
    }
}
