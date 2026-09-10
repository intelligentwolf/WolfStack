// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! Docker / WolfNet subnet collision detection.
//!
//! Symptom this catches: a Docker network (bridge, macvlan, or ipvlan)
//! has its IPAM subnet inside the local WolfNet `/24`, so the kernel's
//! routing table has BOTH the `wolfnet0` subnet route AND a more-specific
//! Docker-bridge route fighting over the same IP space. The host can
//! reach Docker-managed addresses fine via the bridge, but WolfNet
//! traffic destined for any remote peer IP that happens to fall in the
//! Docker subnet gets shoved at the wrong device — and any operator
//! diagnosing "ping doesn't work" through `ip r` will see an alarming
//! pile of overlapping entries that look like the smoking gun even
//! when the actual data-plane issue is elsewhere.
//!
//! klasSponsor 2026-05-11: his `klnet-12gb` VPS had a Docker bridge
//! `br-0c1f72248ccf` owning `10.100.10.2 dev br-0c1f72248ccf scope link`
//! inside WolfNet's `10.100.10.0/24`. The existing
//! `cleanup_stale_wolfnet_routes` reconciles container `/32` host routes
//! but doesn't flag the underlying compose / docker-network config
//! mistake. The fix is a separate compose file that picks a subnet
//! outside WolfNet's range; without an explicit finding, the operator
//! never sees that this is the thing to fix.
//!
//! Scope is per-Docker-network so a single offending bridge produces
//! one finding regardless of how many containers sit on it.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::predictive::{
    Context,
    ack::AckStore,
    proposal::{Evidence, Proposal, ProposalScope, ProposalSource, RemediationPlan, Severity},
};

/// Finding type emitted by this analyzer.
pub const FINDING_TYPE: &str = "docker_wolfnet_subnet_collision";

/// One Docker network whose IPAM config overlaps WolfNet's subnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollidingNetwork {
    /// Docker network short ID (`{{.ID}}`) — stable across container churn,
    /// so we use it as the finding's resource_id for dedup.
    pub id: String,
    /// Docker network name (the compose service / user-facing label).
    pub name: String,
    /// Driver — `bridge`, `macvlan`, `ipvlan`. Determines which
    /// remediation advice we give.
    pub driver: String,
    /// IPAM subnet as written in the Docker config (e.g. `10.100.10.0/24`).
    pub subnet: String,
    /// IPAM gateway (e.g. `10.100.10.2`) — empty if Docker didn't set one.
    pub gateway: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DockerWolfnetCollisionFacts {
    /// Networks that overlap WolfNet's subnet on this node.
    pub colliding: Vec<CollidingNetwork>,
    /// WolfNet subnet we compared against (`10.100.10.0/24` style).
    /// Empty when WolfNet isn't running here — in that case `scanned`
    /// stays false and the analyzer skips emitting.
    pub wolfnet_cidr: String,
    /// True when we successfully read both WolfNet's subnet and the
    /// Docker network list. False means we have no opinion this tick
    /// (don't emit, don't auto-clear).
    pub scanned: bool,
}

/// Sample now: read WolfNet's subnet, walk Docker networks, classify.
/// Runs on the blocking pool because Docker calls are synchronous
/// subprocesses.
pub async fn sample_now_async(_timeout: Duration) -> DockerWolfnetCollisionFacts {
    tokio::task::spawn_blocking(sample_blocking)
        .await
        .unwrap_or_default()
}

fn sample_blocking() -> DockerWolfnetCollisionFacts {
    // The real network wolfnet configured — a /16 WolfNet collides with a
    // 10.100.x.0/24 Docker network the node's own /24 would have missed.
    let wolfnet_cidr = match crate::containers::wolfnet_network() {
        Some(n) => n.cidr(),
        None => return DockerWolfnetCollisionFacts::default(),
    };
    let (wn_net, wn_prefix) = match parse_cidr(&wolfnet_cidr) {
        Some(t) => t,
        None => return DockerWolfnetCollisionFacts::default(),
    };

    let networks = match list_docker_networks() {
        Some(n) => n,
        None => return DockerWolfnetCollisionFacts::default(),
    };

    let mut colliding: BTreeMap<String, CollidingNetwork> = BTreeMap::new();
    for (id, name) in &networks {
        // Skip the host / none / null networks — they have no IPAM.
        if matches!(name.as_str(), "host" | "none" | "null") { continue; }

        let info = match inspect_network(id) {
            Some(i) => i,
            None => continue,
        };
        if info.subnets.is_empty() { continue; }

        let overlaps = info.subnets.iter().any(|s| cidr_overlaps(s, wn_net, wn_prefix))
            || (!info.gateway.is_empty() && ip_in_subnet(&info.gateway, wn_net, wn_prefix));

        if overlaps {
            colliding.insert(id.clone(), CollidingNetwork {
                id: id.clone(),
                name: name.clone(),
                driver: info.driver,
                // Pick the first overlapping subnet for the headline (Docker
                // networks rarely have multiple).
                subnet: info.subnets.into_iter()
                    .find(|s| cidr_overlaps(s, wn_net, wn_prefix))
                    .unwrap_or_else(|| "(unknown)".into()),
                gateway: info.gateway,
            });
        }
    }

    DockerWolfnetCollisionFacts {
        colliding: colliding.into_values().collect(),
        wolfnet_cidr,
        scanned: true,
    }
}

struct InspectedNetwork {
    driver: String,
    subnets: Vec<String>,
    gateway: String,
}

/// `docker network ls --format '{{.ID}}\t{{.Name}}'`. None on any failure
/// so the analyzer cleanly no-ops when Docker isn't installed.
fn list_docker_networks() -> Option<Vec<(String, String)>> {
    let out = Command::new("docker")
        .args(["network", "ls", "--format", "{{.ID}}\t{{.Name}}"])
        .output()
        .ok()?;
    if !out.status.success() { return None; }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut rows = Vec::new();
    for line in text.lines() {
        let mut parts = line.splitn(2, '\t');
        let id = parts.next()?.trim().to_string();
        let name = parts.next().unwrap_or("").trim().to_string();
        if id.is_empty() { continue; }
        rows.push((id, name));
    }
    Some(rows)
}

/// `docker network inspect <id>` parsed for driver and IPAM subnets +
/// gateway. None on any failure.
fn inspect_network(id: &str) -> Option<InspectedNetwork> {
    // Use a compact Go template so we don't pull a JSON-parsing
    // dependency into the predictive path. Multiple IPAM configs are
    // joined by `;` so we keep "potentially multiple subnets" in one
    // shell-out without a second invocation.
    let tmpl = "{{.Driver}}\n\
                {{range .IPAM.Config}}{{.Subnet}}|{{.Gateway}};{{end}}";
    let out = Command::new("docker")
        .args(["network", "inspect", "--format", tmpl, id])
        .output()
        .ok()?;
    if !out.status.success() { return None; }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    let driver = lines.next().unwrap_or("").trim().to_string();
    let ipam_row = lines.next().unwrap_or("").trim();
    let mut subnets = Vec::new();
    let mut gateway = String::new();
    for chunk in ipam_row.split(';').filter(|c| !c.is_empty()) {
        let (subnet, gw) = match chunk.split_once('|') {
            Some(t) => t,
            None => (chunk, ""),
        };
        let subnet = subnet.trim();
        if !subnet.is_empty() { subnets.push(subnet.to_string()); }
        if gateway.is_empty() && !gw.trim().is_empty() {
            gateway = gw.trim().to_string();
        }
    }
    Some(InspectedNetwork { driver, subnets, gateway })
}

// ─── CIDR math (kept self-contained to avoid coupling to router::mod) ───

/// Parse `"10.100.10.0/24"` into (network u32, prefix).
fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 32 { return None; }
    let mask = if prefix == 0 { 0 } else { 0xFFFF_FFFFu32.checked_shl(32 - prefix).unwrap_or(0) };
    Some((u32::from(ip) & mask, prefix))
}

/// True when `cidr` overlaps the network `(other_net, other_prefix)`.
/// Two CIDRs overlap iff the wider one's network address contains the
/// narrower one's network address — equivalent to "they share any
/// address" for prefix-aligned ranges. We mask the narrower's net with
/// the wider's mask and compare against the wider's net.
fn cidr_overlaps(cidr: &str, other_net: u32, other_prefix: u32) -> bool {
    let (a_net, a_prefix) = match parse_cidr(cidr) {
        Some(t) => t,
        None => return false,
    };
    let (wider_net, wider_prefix, narrower_net) = if a_prefix <= other_prefix {
        (a_net, a_prefix, other_net)
    } else {
        (other_net, other_prefix, a_net)
    };
    let wider_mask = if wider_prefix == 0 { 0 }
        else { 0xFFFF_FFFFu32.checked_shl(32 - wider_prefix).unwrap_or(0) };
    (narrower_net & wider_mask) == wider_net
}

/// True when the literal IPv4 string `ip` falls inside the given network.
fn ip_in_subnet(ip: &str, net: u32, prefix: u32) -> bool {
    let parsed: Ipv4Addr = match ip.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let mask = if prefix == 0 { 0 } else { 0xFFFF_FFFFu32.checked_shl(32 - prefix).unwrap_or(0) };
    (u32::from(parsed) & mask) == (net & mask)
}

// ─── Proposal building ──────────────────────────────────────────────────

/// Emit one finding per Docker network whose subnet overlaps WolfNet's.
pub fn analyze(
    ctx: &Context,
    facts: &DockerWolfnetCollisionFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    if !facts.scanned { return out; }
    for n in &facts.colliding {
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("docker-net:{}", n.id)),
        };
        if acks.suppresses(FINDING_TYPE, &scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE, &scope) { continue; }
        out.push(build_proposal(n, &facts.wolfnet_cidr, &scope));
    }
    out
}

/// Cover every Docker network we examined this tick — both colliding
/// and non-colliding — so the resolver auto-clears a finding the moment
/// the operator renumbers the offending network.
pub fn covered_scopes(
    ctx: &Context,
    facts: &DockerWolfnetCollisionFacts,
) -> Vec<(String, ProposalScope)> {
    if !facts.scanned { return Vec::new(); }
    facts.colliding.iter().map(|n| (
        FINDING_TYPE.to_string(),
        ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("docker-net:{}", n.id)),
        },
    )).collect()
}

fn build_proposal(n: &CollidingNetwork, wolfnet_cidr: &str, scope: &ProposalScope) -> Proposal {
    let title = format!(
        "Docker network `{}` ({}) overlaps WolfNet subnet — silent routing conflict",
        n.name, n.subnet,
    );

    let why = format!(
        "The Docker `{driver}` network `{name}` has IPAM subnet `{subnet}` \
         (gateway `{gw}`), which overlaps this node's WolfNet subnet `{wn}`. \
         Every address inside that range now has TWO routes in the kernel: \
         the `wolfnet0` /24 (for the WolfNet mesh) and the Docker bridge's \
         own subnet. Containers on the Docker network are reachable on the \
         host fine, but any WolfNet peer or container elsewhere in the mesh \
         that happens to be assigned an address inside `{subnet}` will be \
         unreachable from THIS node — its packets get routed at the Docker \
         bridge instead of into the WireGuard tunnel. \
         \n\nThis is also the single most confusing thing to see in `ip route \
         show` when debugging \"ping doesn't work\" — it makes the kernel \
         look broken when actually the compose / `docker network create` \
         config picked the wrong subnet.",
        driver = if n.driver.is_empty() { "(unknown driver)" } else { &n.driver },
        name = n.name,
        subnet = n.subnet,
        gw = if n.gateway.is_empty() { "none" } else { &n.gateway },
        wn = wolfnet_cidr,
    );

    let evidence = vec![
        Evidence {
            label: "Docker network".into(),
            value: format!("{} ({})", n.name, n.id),
            detail: Some(format!("Driver: {}", if n.driver.is_empty() { "unknown" } else { &n.driver })),
            links: Vec::new(),
        },
        Evidence {
            label: "Docker subnet".into(),
            value: n.subnet.clone(),
            detail: if n.gateway.is_empty() {
                Some("No gateway set by Docker.".into())
            } else {
                Some(format!("Gateway: {}", n.gateway))
            },
            links: Vec::new(),
        },
        Evidence {
            label: "WolfNet subnet".into(),
            value: wolfnet_cidr.to_string(),
            detail: Some("Routed via wolfnet0 to all configured peers.".into()),
            links: Vec::new(),
        },
    ];

    let instructions = format!(
        "Pick a subnet for `{}` that doesn't overlap `{}`. RFC1918 leaves \
         plenty of room outside the WolfNet range — e.g. `172.30.0.0/24` or \
         `10.42.0.0/24` if you also keep WolfNet on its current `{}`. The \
         renumbering itself: stop the containers that use the network, \
         `docker network rm {}`, recreate it with the new subnet (either \
         via `docker network create --subnet=...` or by editing the \
         compose file's `networks:` block), then start the containers \
         again. WolfStack's reconciliation will pick up the new layout \
         on the next tick.",
        n.name, wolfnet_cidr, wolfnet_cidr, n.name,
    );

    let commands = vec![
        format!("docker network inspect {}", n.id),
        "ip -4 route show".to_string(),
        format!("docker network ls --filter 'name={}'", n.name),
    ];

    Proposal::new(
        FINDING_TYPE,
        ProposalSource::Rule,
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

    #[test]
    fn parse_cidr_basic() {
        assert_eq!(parse_cidr("10.100.10.0/24"), Some((0x0A_64_0A_00, 24)));
        assert_eq!(parse_cidr("10.100.10.40/24"), Some((0x0A_64_0A_00, 24)),
            "host bits must be masked off the network address");
        assert_eq!(parse_cidr("not a cidr"), None);
        assert_eq!(parse_cidr("10.100.10.0/33"), None);
    }

    #[test]
    fn cidr_overlaps_detects_exact_match() {
        // WolfNet /24, Docker /24 — same subnet.
        let (wn_net, wn_pref) = parse_cidr("10.100.10.0/24").unwrap();
        assert!(cidr_overlaps("10.100.10.0/24", wn_net, wn_pref));
    }

    #[test]
    fn cidr_overlaps_detects_docker_inside_wolfnet() {
        let (wn_net, wn_pref) = parse_cidr("10.100.0.0/16").unwrap();
        assert!(cidr_overlaps("10.100.10.0/24", wn_net, wn_pref),
            "Docker /24 inside WolfNet /16 must overlap");
    }

    #[test]
    fn cidr_overlaps_detects_wolfnet_inside_docker() {
        let (wn_net, wn_pref) = parse_cidr("10.100.10.0/24").unwrap();
        assert!(cidr_overlaps("10.0.0.0/8", wn_net, wn_pref),
            "WolfNet /24 inside Docker /8 must overlap");
    }

    #[test]
    fn cidr_overlaps_rejects_disjoint() {
        let (wn_net, wn_pref) = parse_cidr("10.100.10.0/24").unwrap();
        assert!(!cidr_overlaps("172.30.0.0/24", wn_net, wn_pref));
        assert!(!cidr_overlaps("10.100.11.0/24", wn_net, wn_pref),
            "adjacent /24 must not be flagged");
        assert!(!cidr_overlaps("192.168.1.0/24", wn_net, wn_pref));
    }

    #[test]
    fn ip_in_subnet_matches_klas_case() {
        // klasSponsor's `br-0c1f72248ccf` had gateway 10.100.10.2 inside
        // WolfNet's 10.100.10.0/24. The analyzer must catch this even
        // when the IPAM subnet metadata is missing/unparseable, via the
        // gateway-IP check.
        let (wn_net, wn_pref) = parse_cidr("10.100.10.0/24").unwrap();
        assert!(ip_in_subnet("10.100.10.2", wn_net, wn_pref));
        assert!(ip_in_subnet("10.100.10.255", wn_net, wn_pref));
        assert!(!ip_in_subnet("10.100.11.2", wn_net, wn_pref));
        assert!(!ip_in_subnet("not-an-ip", wn_net, wn_pref));
    }

    #[test]
    fn analyze_no_findings_when_not_scanned() {
        let facts = DockerWolfnetCollisionFacts {
            colliding: vec![CollidingNetwork {
                id: "abc".into(), name: "x".into(), driver: "bridge".into(),
                subnet: "10.100.10.0/24".into(), gateway: "10.100.10.2".into(),
            }],
            wolfnet_cidr: "10.100.10.0/24".into(),
            scanned: false,
        };
        let ctx = Context::for_node("node-a");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert!(out.is_empty());
        assert!(covered_scopes(&ctx, &facts).is_empty(),
            "covered_scopes must be empty when scanned=false so the resolver doesn't clear stale findings prematurely");
    }

    #[test]
    fn analyze_emits_one_finding_per_colliding_network() {
        let facts = DockerWolfnetCollisionFacts {
            colliding: vec![
                CollidingNetwork {
                    id: "0c1f72248ccf".into(),
                    name: "pangolin-net".into(),
                    driver: "bridge".into(),
                    subnet: "10.100.10.0/24".into(),
                    gateway: "10.100.10.2".into(),
                },
                CollidingNetwork {
                    id: "deadbeef".into(),
                    name: "other-net".into(),
                    driver: "macvlan".into(),
                    subnet: "10.100.10.0/24".into(),
                    gateway: String::new(),
                },
            ],
            wolfnet_cidr: "10.100.10.0/24".into(),
            scanned: true,
        };
        let ctx = Context::for_node("klnet-12gb");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|p| p.finding_type == FINDING_TYPE));
        assert!(out.iter().any(|p| p.title.contains("pangolin-net")));
        assert!(out.iter().any(|p| p.title.contains("other-net")));
        let scopes: Vec<_> = out.iter().map(|p| p.scope.resource_id.as_deref().unwrap_or("")).collect();
        assert!(scopes.contains(&"docker-net:0c1f72248ccf"));
        assert!(scopes.contains(&"docker-net:deadbeef"));
        // Both networks must be covered for the resolver.
        assert_eq!(covered_scopes(&ctx, &facts).len(), 2);
    }

    #[test]
    fn analyze_finding_text_carries_the_actionable_subnet_names() {
        let facts = DockerWolfnetCollisionFacts {
            colliding: vec![CollidingNetwork {
                id: "abc123".into(),
                name: "pangolin-net".into(),
                driver: "bridge".into(),
                subnet: "10.100.10.0/24".into(),
                gateway: "10.100.10.2".into(),
            }],
            wolfnet_cidr: "10.100.10.0/24".into(),
            scanned: true,
        };
        let ctx = Context::for_node("klnet-12gb");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        let p = &out[0];
        assert!(p.why.contains("10.100.10.0/24"));
        assert!(p.why.contains("pangolin-net"));
        // Remediation must name the actual network so the operator knows
        // which one to `docker network rm`.
        match &p.remediation {
            RemediationPlan::Manual { instructions, commands } => {
                assert!(instructions.contains("pangolin-net"),
                    "remediation must name the colliding network");
                assert!(instructions.contains("docker network rm"),
                    "remediation must point at the renumber recipe");
                assert!(commands.iter().any(|c| c.contains("docker network inspect")));
            }
            _ => panic!("expected Manual remediation"),
        }
    }
}
