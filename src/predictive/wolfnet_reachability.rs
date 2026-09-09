// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! WolfNet peer-reachability health check.
//!
//! Symptom this catches: a node silently loses routing to other WolfNet
//! peers (WireGuard handshake stuck, peer config drift, kernel route
//! table eaten by some other tool, MTU issue, firewall rule injected
//! by an unrelated service). Cluster polling continues to "look" alive
//! at the API level because each node's local cluster state still
//! reports itself fine — but cross-node services (WolfNet-IP-addressed
//! VMs and containers on other peers) silently become unreachable and
//! nothing alerts.
//!
//! What this does: every predictive tick, ping every WolfNet peer
//! configured in `/etc/wolfnet/config.toml` from THIS node. Within a
//! single tick we attempt three pings with a 1s timeout each — a peer
//! is only flagged "unreachable" if all three fail, which gives us
//! useful hysteresis against a single dropped packet without needing
//! cross-tick state. Unreachable peers emit a `wolfnet_peer_unreachable`
//! finding into the Predictive Inbox; the finding auto-resolves on
//! the next tick where the peer answers.
//!
//! Scope is per-peer (resource_id keyed on the peer's WolfNet IP) so
//! a single node going down only produces one finding regardless of
//! how many ticks it's been down.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::predictive::{
    Context,
    ack::AckStore,
    proposal::{Evidence, Proposal, ProposalScope, ProposalSource, RemediationPlan, Severity},
};

/// Finding type for "this node can't ping a configured WolfNet peer".
pub const FINDING_TYPE: &str = "wolfnet_peer_unreachable";

/// Classification of a peer's configured endpoint, used to tailor the
/// remediation advice when the peer can't be reached. `private` covers
/// the RFC1918 / loopback / link-local ranges (see
/// `networking::is_private_ip`). klasSponsor 2026-05-11 hit the
/// `Private` case from a public VPS: peer endpoints in his config were
/// LAN-only addresses like `10.10.10.30:9630`, unreachable from the
/// internet — but the original finding text said "WireGuard handshake
/// stuck / try restarting" and sent him chasing kernel ghosts for an
/// hour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum EndpointKind {
    /// No endpoint configured in /etc/wolfnet/config.toml. Peer can
    /// only join via inbound handshake — common for relay-only nodes.
    #[default]
    Empty,
    /// RFC1918 / loopback / link-local. Reachable only on the same LAN.
    Private,
    /// Routable internet address.
    Public,
    /// Endpoint string doesn't parse as an IPv4 host (probably a DNS name
    /// or IPv6 — we don't reclassify those, just leave room in the model).
    Unparseable,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerProbe {
    pub name: String,
    pub ip: String,
    pub reachable: bool,
    /// Peer's WolfNet endpoint as configured (`host:port`). Empty if
    /// `/etc/wolfnet/config.toml` has no `endpoint = ...` for this peer.
    /// Carried through to the proposal evidence so the operator can see
    /// at a glance whether their config is even reachable from this node.
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub endpoint_kind: EndpointKind,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WolfnetReachabilityFacts {
    pub probes: Vec<PeerProbe>,
    /// Set when we successfully read the WolfNet peer list. False when
    /// `/etc/wolfnet/config.toml` is missing or unreadable — in that
    /// case we have no opinion on reachability and the analyzer should
    /// skip emitting (and the resolver should skip auto-clearing).
    pub scanned: bool,
    /// True when this node has at least one non-RFC1918 (public) IPv4
    /// on a non-overlay interface. Used in combination with
    /// `endpoint_kind == Private` to surface the public-VPS-vs-LAN-peer
    /// mismatch — the single most useful piece of diagnostic context
    /// when WolfNet "says connected" but data won't flow.
    #[serde(default)]
    pub local_has_public_ip: bool,
}

/// Classify an endpoint string by its host's address scope.
/// Empty input → `Empty`. Non-IPv4 (DNS / IPv6) → `Unparseable`.
fn classify_endpoint(endpoint: &str) -> EndpointKind {
    let host = match crate::networking::endpoint_host(endpoint) {
        Some(h) => h,
        None => return EndpointKind::Empty,
    };
    if host.is_empty() { return EndpointKind::Empty; }
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => {
            if crate::networking::is_private_ip(ip) { EndpointKind::Private }
            else { EndpointKind::Public }
        }
        Err(_) => EndpointKind::Unparseable,
    }
}

/// Sample reachability for every configured WolfNet peer. Runs on the
/// blocking pool because `ping` is a synchronous subprocess.
pub async fn sample_now_async(_timeout: Duration) -> WolfnetReachabilityFacts {
    tokio::task::spawn_blocking(|| {
        let peers = crate::networking::get_wolfnet_peers_list();
        if peers.is_empty() {
            // Could be: WolfNet not configured here at all (no
            // config.toml), or a single-node mesh with no peers.
            // Either way, nothing for this analyzer to do — and we
            // don't want to mark `scanned=true` and have the resolver
            // think we just looked at zero peers.
            return WolfnetReachabilityFacts::default();
        }
        let local_has_public_ip = !crate::networking::detect_public_ips().is_empty();
        let mut probes = Vec::with_capacity(peers.len());
        for peer in peers {
            if peer.ip.is_empty() { continue; }
            // Strip CIDR suffix if present (`get_wolfnet_peers_list`
            // returns "10.10.0.5/32" or similar from the config).
            let ip_only = peer.ip.split('/').next().unwrap_or(&peer.ip).to_string();

            // Three attempts, 1s timeout each. A peer is reachable if
            // any of the three succeeds — gives us a free hysteresis
            // pass over single-packet drops and brief MTU/queue blips.
            // Stops early on first success so the steady-state cost is
            // ~1 ping per reachable peer per tick.
            let mut reachable = false;
            for _ in 0..3 {
                let ok = std::process::Command::new("ping")
                    .args(["-c", "1", "-W", "1", &ip_only])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if ok { reachable = true; break; }
            }
            let endpoint_kind = classify_endpoint(&peer.endpoint);
            probes.push(PeerProbe {
                name: peer.name,
                ip: ip_only,
                reachable,
                endpoint: peer.endpoint,
                endpoint_kind,
            });
        }
        WolfnetReachabilityFacts { probes, scanned: true, local_has_public_ip }
    }).await.unwrap_or_default()
}

/// Emit one `wolfnet_peer_unreachable` proposal per peer that failed
/// all three ping attempts this tick. Idempotent across ticks via the
/// proposal store's dedup key + ack-store suppression.
pub fn analyze(
    ctx: &Context,
    facts: &WolfnetReachabilityFacts,
    acks: &AckStore,
    proposals: &crate::predictive::proposal::ProposalStore,
) -> Vec<Proposal> {
    let mut out = Vec::new();
    if !facts.scanned { return out; }
    for p in &facts.probes {
        if p.reachable { continue; }
        let scope = ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("wolfnet-peer:{}", p.ip)),
        };
        if acks.suppresses(FINDING_TYPE, &scope) { continue; }
        if proposals.is_suppressed(FINDING_TYPE, &scope) { continue; }
        out.push(build_proposal(p, facts.local_has_public_ip, &scope));
    }
    out
}

/// Cover every peer we probed this tick — reachable AND unreachable —
/// so the resolver auto-clears findings the moment a peer comes back.
/// Without covering reachable peers, a previously-flagged peer that's
/// now answering would stay open forever.
pub fn covered_scopes(
    ctx: &Context,
    facts: &WolfnetReachabilityFacts,
) -> Vec<(String, ProposalScope)> {
    if !facts.scanned { return Vec::new(); }
    facts.probes.iter().map(|p| (
        FINDING_TYPE.to_string(),
        ProposalScope {
            node_id: ctx.node_id.clone(),
            resource_id: Some(format!("wolfnet-peer:{}", p.ip)),
        },
    )).collect()
}

/// Build the proposal text. The `local_has_public_ip` flag tunes the
/// `Private` endpoint case so we only flag the public-VPS-vs-LAN-peer
/// mismatch when it's actually a mismatch (a LAN node failing to reach
/// a LAN peer doesn't get the "unreachable from the internet" treatment).
fn build_proposal(p: &PeerProbe, local_has_public_ip: bool, scope: &ProposalScope) -> Proposal {
    // The Private-endpoint-from-public-node case is the headline diagnosis:
    // surface it in the title so the operator sees it without expanding.
    let private_endpoint_mismatch = matches!(p.endpoint_kind, EndpointKind::Private)
        && local_has_public_ip;

    let title = if private_endpoint_mismatch {
        format!(
            "WolfNet peer `{}` ({}) advertises a private endpoint — unreachable from this node",
            p.name, p.ip,
        )
    } else {
        format!(
            "WolfNet peer `{}` ({}) is unreachable from this node",
            p.name, p.ip,
        )
    };

    let why = if private_endpoint_mismatch {
        format!(
            "Peer `{name}` ({ip}) advertises endpoint `{ep}` in its config — that's an \
             RFC1918 (private LAN) address. This node has at least one public address \
             and no path to RFC1918 ranges except its own LAN, so handshake UDP \
             packets sent to `{ep}` go nowhere. WolfNet may still report this peer \
             as 'connected' if handshakes occasionally complete via a relay or \
             gateway, but data won't flow end-to-end. \
             \n\nFix: edit `/etc/wolfnet/config.toml` on this node (or re-issue an \
             invite from the peer) so the peer's `endpoint` is its public IP plus \
             the externally-forwarded UDP port — not its LAN address.",
            name = p.name, ip = p.ip, ep = p.endpoint,
        )
    } else {
        format!(
            "This node failed to ping `{name}` ({ip}) three times in a row over the \
             WolfNet mesh. Cross-node services that route via this peer — VMs and \
             containers with WolfNet IPs on the other side, IP mappings whose target \
             is on that peer, anything talking to the peer's wolfnet0 IP — are \
             silently broken until reachability returns. Common causes: WireGuard \
             handshake stuck (peer rebooted, key rotation), kernel route for the \
             WolfNet subnet removed by another tool, firewall rule injected on \
             either end blocking the WolfNet UDP port or the WolfNet subnet, MTU \
             mismatch after a network change, or the peer host is genuinely down.",
            name = p.name, ip = p.ip,
        )
    };

    let endpoint_evidence_detail = match p.endpoint_kind {
        EndpointKind::Empty       => "No endpoint configured for this peer (inbound-only or relay-routed).",
        EndpointKind::Private if local_has_public_ip
                                  => "RFC1918 private address — unreachable from this node's public interface(s).",
        EndpointKind::Private     => "RFC1918 private address — reachable only on the same LAN.",
        EndpointKind::Public      => "Public IPv4 — should be routable from anywhere with internet access.",
        EndpointKind::Unparseable => "Endpoint isn't a literal IPv4 (DNS / IPv6) — classification skipped.",
    };

    let endpoint_evidence_value = if p.endpoint.is_empty() {
        "(none configured)".to_string()
    } else {
        p.endpoint.clone()
    };

    let evidence = vec![
        Evidence {
            label: "Peer".into(),
            value: format!("{} ({})", p.name, p.ip),
            detail: Some("Configured in /etc/wolfnet/config.toml".into()),
            links: Vec::new(),
        },
        Evidence {
            label: "Endpoint".into(),
            value: endpoint_evidence_value,
            detail: Some(endpoint_evidence_detail.into()),
            links: Vec::new(),
        },
        Evidence {
            label: "Probe result".into(),
            value: "3 / 3 pings failed (1s timeout each)".into(),
            detail: Some("Re-probed every predictive tick; this finding clears the moment a ping succeeds.".into()),
            links: Vec::new(),
        },
    ];

    let mut commands = vec![
        format!("ping -c 5 {}", p.ip),
        "sudo wolfnetctl peers".to_string(),
        format!("ip -4 route get {}", p.ip),
        "sudo journalctl -u wolfstack --since '15 minutes ago' | grep -i wolfnet".to_string(),
        // For a peer that is gone for good, deliberately last and clearly
        // labelled: `wolfnetctl purge` reloads the config and drops any peer
        // no longer in it (see the wolfnet CLI's Purge subcommand), so the
        // edit has to come first. The WolfNet page's remove button does both
        // steps plus the subnet-route teardown, which is why the instructions
        // point there first.
        format!(
            "# only if {} is decommissioned for good: delete its [[peers]] block first\n\
             sudoedit /etc/wolfnet/config.toml && sudo wolfnetctl purge",
            p.name,
        ),
    ];
    if private_endpoint_mismatch {
        commands.insert(0, format!(
            "grep -n -B1 -A3 '{}' /etc/wolfnet/config.toml", p.ip
        ));
    }

    let instructions = if private_endpoint_mismatch {
        format!(
            "The peer's endpoint `{}` is an RFC1918 address — your public node can't \
             route to it. Open `/etc/wolfnet/config.toml`, find the `[[peers]]` block \
             whose `allowed_ip` matches `{}`, and change `endpoint` to the peer's \
             public IP + UDP port (the port the peer's home router forwards to it). \
             Then restart wolfstack on this node to pick up the new config. If the \
             peer truly has no public address (CGNAT, no port-forward), you need a \
             relay node — both ends connect outbound to a third node with a public \
             endpoint.",
            p.endpoint, p.ip,
        )
    } else {
        "Start with `wolfnetctl peers` on both ends and look at the latest-handshake \
         time — older than a few minutes means the tunnel is dead. Common fixes: \
         bounce wolfstack on either end (`sudo systemctl restart wolfstack`), \
         check that the WolfNet UDP port isn't being blocked by a recently-applied \
         firewall change, verify the peer's public endpoint hasn't changed (CGNAT \
         renumber, dynamic IP), or confirm the kernel route for the WolfNet subnet \
         still points at wolfnet0. If the peer host is itself down, the finding \
         will auto-resolve when it returns.\
         \n\nIf the host is gone for GOOD — decommissioned, rebuilt, moved out of \
         the cluster — it is still a configured peer here, which is why this keeps \
         being reported. Remove it — WolfNet page → Peers → the trash button on \
         that row, which also tears down the subnet routes pointing at it — and \
         the finding retires on the next analyzer pass. Deleting the node from the \
         cluster evicts its peer entry automatically on every node that was \
         online at the time; a node that was offline then keeps it until you \
         remove it there."
            .to_string()
    };

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

    fn probe(name: &str, ip: &str, reachable: bool) -> PeerProbe {
        PeerProbe {
            name: name.into(),
            ip: ip.into(),
            reachable,
            endpoint: String::new(),
            endpoint_kind: EndpointKind::Empty,
        }
    }

    fn probe_with_endpoint(name: &str, ip: &str, endpoint: &str) -> PeerProbe {
        PeerProbe {
            name: name.into(),
            ip: ip.into(),
            reachable: false,
            endpoint_kind: classify_endpoint(endpoint),
            endpoint: endpoint.into(),
        }
    }

    #[test]
    fn scanned_false_yields_no_proposals() {
        let facts = WolfnetReachabilityFacts {
            probes: vec![probe("test", "10.10.0.5", false)],
            scanned: false,
            local_has_public_ip: false,
        };
        let ctx = Context::for_node("node-a");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert!(out.is_empty(), "scanned=false must produce no proposals — we don't know whether the peers are reachable");
    }

    #[test]
    fn reachable_peers_yield_no_proposals_but_are_covered() {
        let facts = WolfnetReachabilityFacts {
            probes: vec![probe("alpha", "10.10.0.5", true)],
            scanned: true,
            local_has_public_ip: false,
        };
        let ctx = Context::for_node("node-a");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert!(out.is_empty(), "a reachable peer should not emit a finding");
        let covered = covered_scopes(&ctx, &facts);
        assert_eq!(covered.len(), 1, "reachable peers must still be in covered_scopes so the resolver can clear stale findings");
        assert_eq!(covered[0].0, FINDING_TYPE);
    }

    #[test]
    fn unreachable_peer_emits_high_severity_finding() {
        let facts = WolfnetReachabilityFacts {
            probes: vec![probe("bravo", "10.10.0.7", false)],
            scanned: true,
            local_has_public_ip: false,
        };
        let ctx = Context::for_node("node-a");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].finding_type, FINDING_TYPE);
        assert!(matches!(out[0].severity, Severity::High));
        assert!(out[0].title.contains("bravo"));
        assert!(out[0].title.contains("10.10.0.7"));
        let scope_id = out[0].scope.resource_id.as_deref().unwrap_or("");
        assert_eq!(scope_id, "wolfnet-peer:10.10.0.7", "scope keyed on peer IP for stable dedup");
    }

    #[test]
    fn mixed_set_only_flags_the_unreachable() {
        let facts = WolfnetReachabilityFacts {
            probes: vec![
                probe("ok-1", "10.10.0.1", true),
                probe("down", "10.10.0.2", false),
                probe("ok-2", "10.10.0.3", true),
            ],
            scanned: true,
            local_has_public_ip: false,
        };
        let ctx = Context::for_node("node-a");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert_eq!(out.len(), 1, "exactly one finding for the one unreachable peer");
        assert!(out[0].title.contains("down"));
        assert_eq!(covered_scopes(&ctx, &facts).len(), 3,
            "all three peers must be covered so the resolver clears findings as soon as 'down' answers again");
    }

    #[test]
    fn classify_endpoint_recognises_rfc1918() {
        assert_eq!(classify_endpoint("10.10.10.30:9630"),   EndpointKind::Private);
        assert_eq!(classify_endpoint("172.16.5.4:51820"),   EndpointKind::Private);
        assert_eq!(classify_endpoint("192.168.1.10:9600"),  EndpointKind::Private);
        assert_eq!(classify_endpoint("169.254.1.1:9600"),   EndpointKind::Private);
        assert_eq!(classify_endpoint("185.57.4.152:9605"),  EndpointKind::Public);
        assert_eq!(classify_endpoint("1.2.3.4:9600"),       EndpointKind::Public);
        assert_eq!(classify_endpoint(""),                   EndpointKind::Empty);
        assert_eq!(classify_endpoint("peer.example.com:9600"), EndpointKind::Unparseable);
    }

    #[test]
    fn private_endpoint_from_public_node_surfaces_mismatch_diagnosis() {
        // klasSponsor's exact case: VPS with a public IP, peers in his
        // config advertising 10.10.10.x as endpoints.
        let facts = WolfnetReachabilityFacts {
            probes: vec![probe_with_endpoint("ninni", "10.100.10.30", "10.10.10.30:9630")],
            scanned: true,
            local_has_public_ip: true,
        };
        let ctx = Context::for_node("klnet-12gb");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert_eq!(out.len(), 1);
        // Title surfaces the diagnosis without the operator expanding the card.
        assert!(out[0].title.contains("private endpoint"),
            "title must call out the private-endpoint mismatch directly, was: {}",
            out[0].title);
        // Evidence carries the actual endpoint string.
        let ep_evidence = out[0].evidence.iter()
            .find(|e| e.label == "Endpoint")
            .expect("Endpoint evidence row must be present");
        assert!(ep_evidence.value.contains("10.10.10.30"),
            "endpoint evidence should carry the actual endpoint, got: {}", ep_evidence.value);
        // Remediation instructions point at config.toml, not at restarting things.
        match &out[0].remediation {
            RemediationPlan::Manual { instructions, .. } => {
                assert!(instructions.contains("config.toml"),
                    "instructions must direct the operator at the config file");
                assert!(instructions.contains("public IP"),
                    "instructions must explain that endpoint should be public");
            }
            _ => panic!("expected Manual remediation"),
        }
    }

    #[test]
    fn private_endpoint_from_private_node_does_not_diagnose_mismatch() {
        // Two LAN nodes — peer has a private endpoint and the local node
        // also lives on RFC1918 only. That's not a mismatch; ping might
        // be failing for an entirely different reason. Don't mislead.
        let facts = WolfnetReachabilityFacts {
            probes: vec![probe_with_endpoint("ninni", "10.100.10.30", "10.10.10.30:9630")],
            scanned: true,
            local_has_public_ip: false,
        };
        let ctx = Context::for_node("lan-node");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert_eq!(out.len(), 1);
        assert!(!out[0].title.contains("private endpoint"),
            "must not falsely flag mismatch when both ends are private, was: {}",
            out[0].title);
    }

    #[test]
    fn public_endpoint_with_failed_ping_uses_generic_diagnosis() {
        let facts = WolfnetReachabilityFacts {
            probes: vec![probe_with_endpoint("ninni", "10.100.10.30", "185.57.4.152:9605")],
            scanned: true,
            local_has_public_ip: true,
        };
        let ctx = Context::for_node("klnet-12gb");
        let acks = AckStore::default();
        let proposals = crate::predictive::proposal::ProposalStore::default();
        let out = analyze(&ctx, &facts, &acks, &proposals);
        assert_eq!(out.len(), 1);
        assert!(!out[0].title.contains("private endpoint"));
        // Evidence still lists the public endpoint so the operator has it
        // to hand.
        let ep_evidence = out[0].evidence.iter().find(|e| e.label == "Endpoint").unwrap();
        assert_eq!(ep_evidence.value, "185.57.4.152:9605");
    }
    /// The decommissioned-peer path must be spelled out: this is the case
    /// where the host never comes back, so "it'll auto-resolve when it
    /// returns" is not an answer (klas 2026-09-09).
    #[test]
    fn a_permanently_gone_peer_is_told_how_to_retire_the_finding() {
        let facts = WolfnetReachabilityFacts {
            probes: vec![PeerProbe {
                name: "old-node".into(),
                ip: "10.100.10.30".into(),
                reachable: false,
                endpoint: "203.0.113.7:9630".into(),
                endpoint_kind: EndpointKind::Public,
            }],
            scanned: true,
            local_has_public_ip: true,
        };
        let out = analyze(
            &Context::for_node("node-a"), &facts,
            &AckStore::default(), &crate::predictive::proposal::ProposalStore::default(),
        );
        assert_eq!(out.len(), 1);
        let RemediationPlan::Manual { instructions, commands } = &out[0].remediation else {
            panic!("expected a manual remediation plan");
        };
        assert!(
            instructions.contains("decommissioned"),
            "instructions must cover the host that never returns: {}", instructions,
        );
        // The purge command only makes sense after the config edit, and must
        // never read as a routine diagnostic step.
        let purge = commands.iter().find(|c| c.contains("wolfnetctl purge"))
            .expect("the removal path needs a command");
        assert!(purge.contains("/etc/wolfnet/config.toml"), "purge alone drops nothing: {}", purge);
        assert!(purge.starts_with("# only if"), "must be labelled conditional: {}", purge);
    }
}
