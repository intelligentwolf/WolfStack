// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Predictive ops — context-aware analyzers that propose remediations.
//!
//! This module is deliberately thin in v1: it provides the *foundation*
//! every analyzer in the predictive-ops pipeline depends on — a
//! [`NetworkReachability`] classifier and a per-cycle [`Context`]
//! snapshot — without yet defining any analyzers themselves.
//!
//! ## Why this exists
//!
//! A finding like "MariaDB is binding on 0.0.0.0" is a critical
//! security issue on a public-internet VPS but a non-event on a
//! private LAN where the operator deliberately exposes the database
//! to other LAN clients. Reporting both as identical issues teaches
//! operators to ignore the alert entirely. The fix isn't more rules,
//! it's making every rule consult network-reachability context
//! *before* deciding to emit. This module is that consultation point.
//!
//! ## Design rules every analyzer in this pipeline must follow
//!
//! 1. **Take a [`Context`], not raw OS access.** The Context is a
//!    snapshot taken once per analysis cycle so every finding within
//!    a cycle sees a consistent view. An analyzer that calls `ss` or
//!    `ip` directly defeats both testability and snapshot consistency.
//!
//! 2. **Consult [`NetworkReachability`] before emitting** any finding
//!    that depends on whether something is reachable. The convention
//!    is enforced socially, not statically — a rule unit-test should
//!    verify that the same finding produces different (or no)
//!    severity across reachability classes.
//!
//! 3. **No live syscalls in [`classify_bind`].** Pure function of
//!    `(bind_addr, snapshot)`. This is what lets the unit tests
//!    cover IPv4, IPv6, link-local, CGNAT, ULA, and overlay binds
//!    without standing up a network stack.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::networking::NetworkInterface;

pub mod proposal;
pub mod ack;
pub mod metrics;
pub mod disk_verdict;
pub mod disk_fill;
pub mod container_disk;
pub mod container_restart;
pub mod container_boot;
pub mod container_memory;
pub mod threshold;
pub mod boot_partition;
/// Previous-boot emergency-mode detection and fstab lines that can
/// cause it.
pub mod boot_health;
/// One WolfNet IP with two live owners (two nodes, or a node and a peer).
pub mod wolfnet_ip_conflict;
pub mod cert_expiry;
pub mod backup_freshness;
pub mod vm_disk;
pub mod security_posture;
/// Switching an unused portmapper off — the action behind
/// `security_posture`'s rpcbind finding.
pub mod rpcbind;
pub mod vulnerability;
pub mod osv;
pub mod port_conflict;
pub mod wolfnet_dhcp;
pub mod wolfnet_reachability;
pub mod docker_wolfnet_collision;
pub mod missing_subnet_route;
pub mod compromise_indicators;
pub mod baselines;
pub mod tamper_detection;
pub mod threat_intel;
pub mod unused_packages;
pub mod notify;
pub mod cluster;
pub mod orchestrator;

pub use proposal::{
    ApprovalOutcome, Proposal, ProposalScope,
    ProposalStore, RemediationPlan,
};
pub use ack::{Ack, AckScope, AckStore};
pub use metrics::MetricsHistory;

/// How reachable a service binding is from the outside world.
///
/// The classifier never returns more than one variant — a binding's
/// most-permissive interface wins (e.g. `0.0.0.0` on a host with both
/// a public IP and an RFC1918 IP is `PublicInternet`).
///
/// `Unknown` exists for the case where we cannot positively classify
/// (the bind address doesn't match any interface we know about, or
/// `list_interfaces()` returned empty). Analyzers should treat
/// `Unknown` as "downgrade severity one tier" rather than as if it
/// were `PublicInternet` — false-positive avoidance trumps
/// completeness when we genuinely don't know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkReachability {
    /// Binding is reachable from the public internet — at least one
    /// publicly-routable IPv4 or IPv6 address on the host carries
    /// this binding.
    PublicInternet,
    /// Binding is reachable only from RFC1918 / link-local / CGNAT
    /// space (or the IPv6 equivalents: ULA fc00::/7, link-local
    /// fe80::/10).
    LocalNetwork,
    /// Binding is reachable only from a WolfNet / WireGuard /
    /// Tailscale-style overlay. Carries the overlay name when
    /// discoverable so the UI can label it.
    OverlayOnly { network: String },
    /// Binding is on the loopback interface only (127.0.0.0/8 or ::1).
    LoopbackOnly,
    /// Could not classify — the bind address didn't match any known
    /// interface. Analyzers should downgrade severity, not treat
    /// this as worst-case.
    Unknown,
}

/// A listening TCP/UDP socket, preserving the bind address.
///
/// `networking::get_listening_ports()` already enumerates ports but
/// drops the bind address — and the bind address is the *entire*
/// question for reachability, so we need a richer enumeration here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListeningSocket {
    pub bind: IpAddr,
    pub port: u16,
    pub protocol: SocketProtocol,
    pub process: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketProtocol { Tcp, Udp }

/// Per-cycle snapshot of every networking fact an analyzer needs.
///
/// Built once per analysis run, then read-only for the rest of the
/// cycle. Decouples analyzers from live OS calls (testability) and
/// guarantees that every finding in a cycle sees the same view of
/// the world (consistency — without this, finding A could see a
/// public IP and finding B could see it disappeared mid-cycle).
#[derive(Debug, Clone)]
pub struct NetworkSnapshot {
    pub interfaces: Vec<NetworkInterface>,
    pub listening_sockets: Vec<ListeningSocket>,
    /// Public IPv4 addresses currently bound on this host. Computed
    /// from `interfaces` by filtering out overlay/bridge/loopback —
    /// pre-computed so analyzers don't each re-derive it.
    pub public_ipv4: Vec<Ipv4Addr>,
    /// Public IPv6 addresses currently bound on this host.
    pub public_ipv6: Vec<Ipv6Addr>,
}

impl NetworkSnapshot {
    /// Take a snapshot from live OS state. Call once per analysis
    /// cycle, then pass by reference to every analyzer.
    pub fn current() -> Self {
        let interfaces = crate::networking::list_interfaces();
        let listening_sockets = enumerate_listening_sockets();
        let (public_ipv4, public_ipv6) = collect_public_addrs(&interfaces);
        Self { interfaces, listening_sockets, public_ipv4, public_ipv6 }
    }

    /// Construct a snapshot from explicit inputs — used by tests and
    /// by callers that want to analyze a remote node's state.
    pub fn from_parts(
        interfaces: Vec<NetworkInterface>,
        listening_sockets: Vec<ListeningSocket>,
    ) -> Self {
        let (public_ipv4, public_ipv6) = collect_public_addrs(&interfaces);
        Self { interfaces, listening_sockets, public_ipv4, public_ipv6 }
    }
}

/// Per-cycle context handed to every analyzer.
///
/// This is intentionally minimal in v1 — it currently wraps just the
/// network snapshot and the node identifier. As subsequent phases
/// land, this struct will gain fields for acknowledgements,
/// operator-declared intent, per-rule statistics, etc. The Context
/// wrapper exists *now* so analyzers don't need refactoring to pick
/// those up later.
pub struct Context {
    pub node_id: String,
    pub network: NetworkSnapshot,
}

impl Context {
    /// Build a Context for the local node from live OS state.
    /// Blocking — invokes `ip` and `ss`. Use only when the analyzer
    /// genuinely needs [`NetworkReachability`] classification; for
    /// analyzers that only care about node identity (disk-fill,
    /// memory-pressure, certificate-expiry) prefer
    /// [`Context::for_node`] which is ~free.
    pub fn current(node_id: impl Into<String>) -> Self {
        Self { node_id: node_id.into(), network: NetworkSnapshot::current() }
    }

    /// Cheap — node id only, with an empty network snapshot. Use
    /// for analyzers that don't consult `NetworkReachability`. Saves
    /// the orchestrator a couple of subprocess calls per tick when
    /// the live network state isn't needed.
    pub fn for_node(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            network: NetworkSnapshot::from_parts(vec![], vec![]),
        }
    }
}

/// Classify a single bind address against a snapshot.
///
/// Pure function — no syscalls. The result depends entirely on
/// `(bind, snapshot)`, which is what makes the unit tests below
/// possible without standing up a network namespace.
///
/// Wildcard binds (`0.0.0.0` and `::`) take the *most permissive*
/// interface as their effective reachability: a host with both a
/// public IP and an RFC1918 IP that binds on `0.0.0.0` is
/// `PublicInternet`, because the public path exists.
pub fn classify_bind(bind: IpAddr, snap: &NetworkSnapshot) -> NetworkReachability {
    // Loopback first — fastest answer and exclusive.
    if bind.is_loopback() {
        return NetworkReachability::LoopbackOnly;
    }

    // Wildcard binds: the binding inherits whichever interface gives
    // it the broadest reach. `0.0.0.0` and `::` both attach to every
    // address on the host of their respective family.
    if is_wildcard(bind) {
        if !snap.public_ipv4.is_empty() || !snap.public_ipv6.is_empty() {
            return NetworkReachability::PublicInternet;
        }
        // A wildcard (`0.0.0.0` / `::`) binds to EVERY interface, so if the
        // host has any real (non-overlay) LAN interface the service is
        // LAN-exposed — NOT overlay-only. Gary 2026-06-22: postgres on
        // `0.0.0.0:5432` on a node with both a LAN NIC and `wolfnet0` was
        // mislabeled "listening on overlay 'wolfnet0'". OverlayOnly is only
        // correct for a wildcard when the overlay is the SOLE non-loopback
        // interface (checked next); a specific bind to the overlay's own
        // address is handled by the non-wildcard branch below.
        if any_non_overlay_lan_addr(snap) {
            return NetworkReachability::LocalNetwork;
        }
        if let Some(network) = overlay_interface_carrying(bind, snap) {
            // Wildcard and the only non-loopback interface is an overlay.
            return NetworkReachability::OverlayOnly { network };
        }
        // Some non-loopback interface exists but no public addr —
        // must be RFC1918 / link-local only.
        if any_non_loopback_addr(snap) {
            return NetworkReachability::LocalNetwork;
        }
        return NetworkReachability::Unknown;
    }

    // Specific bind: which interface owns this exact address?
    let owning_iface = snap.interfaces.iter().find(|iface| {
        iface.addresses.iter().any(|a| a.address == bind.to_string())
    });

    if let Some(iface) = owning_iface
        && is_overlay_vpn_interface(&iface.name) {
            return NetworkReachability::OverlayOnly { network: iface.name.clone() };
        }

    // Address-class checks irrespective of interface — this catches
    // the case where the interface is a bridge or unusual driver but
    // the bind addr itself is unambiguous.
    match bind {
        IpAddr::V4(v4) => {
            if is_publicly_routable_v4(v4) {
                NetworkReachability::PublicInternet
            } else {
                NetworkReachability::LocalNetwork
            }
        }
        IpAddr::V6(v6) => {
            if is_publicly_routable_v6(v6) {
                NetworkReachability::PublicInternet
            } else {
                NetworkReachability::LocalNetwork
            }
        }
    }
}

// ─── address-class helpers ──────────────────────────────────────────

fn is_wildcard(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4 == Ipv4Addr::UNSPECIFIED,
        IpAddr::V6(v6) => v6 == Ipv6Addr::UNSPECIFIED,
    }
}

/// IPv4 publicly-routable means: NOT in any of the well-known
/// non-routable / private / shared-address ranges.
fn is_publicly_routable_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // Loopback 127.0.0.0/8
    if o[0] == 127 { return false; }
    // RFC1918
    if o[0] == 10 { return false; }
    if o[0] == 172 && (16..=31).contains(&o[1]) { return false; }
    if o[0] == 192 && o[1] == 168 { return false; }
    // Link-local 169.254.0.0/16
    if o[0] == 169 && o[1] == 254 { return false; }
    // CGNAT (RFC 6598) 100.64.0.0/10
    if o[0] == 100 && (64..=127).contains(&o[1]) { return false; }
    // Reserved 0.0.0.0/8 and 240.0.0.0/4 (incl. broadcast)
    if o[0] == 0 { return false; }
    if o[0] >= 240 { return false; }
    // Multicast 224.0.0.0/4
    if (224..=239).contains(&o[0]) { return false; }
    // Documentation ranges (RFC 5737) — treat as non-routable to
    // avoid surprising classification when test fixtures use them.
    if o[0] == 192 && o[1] == 0 && o[2] == 2 { return false; }
    if o[0] == 198 && o[1] == 51 && o[2] == 100 { return false; }
    if o[0] == 203 && o[1] == 0 && o[2] == 113 { return false; }
    true
}

/// IPv6 publicly-routable means: NOT loopback, link-local (fe80::/10),
/// ULA (fc00::/7), or unspecified. Multicast (ff00::/8) treated as
/// non-routable for our purposes.
fn is_publicly_routable_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() { return false; }
    let segs = ip.segments();
    // fe80::/10 — link-local
    if (segs[0] & 0xffc0) == 0xfe80 { return false; }
    // fc00::/7 — unique local addresses
    if (segs[0] & 0xfe00) == 0xfc00 { return false; }
    // ff00::/8 — multicast
    if (segs[0] & 0xff00) == 0xff00 { return false; }
    true
}

/// Strict — VPN/overlay interface names only. Used to classify a
/// binding as `OverlayOnly`. Loopback and host-internal bridges are
/// deliberately *not* in this list; they get skipped from public-IP
/// enumeration via the broader [`is_skip_for_public_addr`] but they
/// are not overlays in the security-relevant sense.
fn is_overlay_vpn_interface(name: &str) -> bool {
    name.starts_with("wn")
        || name.starts_with("wolfnet")
        || name.starts_with("wg")
        || name.starts_with("tailscale")
}

/// Broad — names to skip when collecting publicly-routable IPs on
/// this host. Includes loopback, docker bridges, libvirt bridges,
/// virtual ethernet pairs, and overlay VPNs. Mirrors the existing
/// `networking::detect_public_ips` skiplist so the dashboard and the
/// analyzers agree on what counts as "public".
fn is_skip_for_public_addr(name: &str) -> bool {
    name == "lo"
        || name.starts_with("docker")
        || name.starts_with("br-")
        || name.starts_with("veth")
        || name.starts_with("virbr")
        || is_overlay_vpn_interface(name)
}

fn overlay_interface_carrying(bind: IpAddr, snap: &NetworkSnapshot) -> Option<String> {
    if !is_wildcard(bind) { return None; }
    snap.interfaces.iter()
        .find(|i| is_overlay_vpn_interface(&i.name) && !i.addresses.is_empty())
        .map(|i| i.name.clone())
}

fn any_non_loopback_addr(snap: &NetworkSnapshot) -> bool {
    snap.interfaces.iter().any(|i| {
        i.name != "lo" && i.addresses.iter().any(|a| {
            a.address.parse::<IpAddr>().map(|ip| !ip.is_loopback()).unwrap_or(false)
        })
    })
}

/// True when the host has a non-loopback, NON-overlay interface carrying a real
/// address — i.e. a wildcard bind would actually be reachable on the LAN (or
/// beyond), so it must not be classified as overlay-only.
fn any_non_overlay_lan_addr(snap: &NetworkSnapshot) -> bool {
    snap.interfaces.iter().any(|i| {
        i.name != "lo" && !is_overlay_vpn_interface(&i.name) && i.addresses.iter().any(|a| {
            a.address.parse::<IpAddr>().map(|ip| !ip.is_loopback()).unwrap_or(false)
        })
    })
}

fn collect_public_addrs(interfaces: &[NetworkInterface]) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for iface in interfaces {
        if is_skip_for_public_addr(&iface.name) { continue; }
        for addr in &iface.addresses {
            match addr.family.as_str() {
                "inet" => {
                    if let Ok(ip) = addr.address.parse::<Ipv4Addr>()
                        && is_publicly_routable_v4(ip) { v4.push(ip); }
                }
                "inet6" => {
                    if let Ok(ip) = addr.address.parse::<Ipv6Addr>()
                        && is_publicly_routable_v6(ip) { v6.push(ip); }
                }
                _ => {}
            }
        }
    }
    (v4, v6)
}

// ─── ss-based listening-port enumeration with bind preserved ────────

/// Like `networking::get_listening_ports()` but preserves the bind
/// address — which is the entire question for reachability.
fn enumerate_listening_sockets() -> Vec<ListeningSocket> {
    let mut out = Vec::new();
    for (proto, flag) in [(SocketProtocol::Tcp, "-tlnp"), (SocketProtocol::Udp, "-ulnp")] {
        let Ok(o) = Command::new("ss").arg(flag).output() else { continue; };
        if !o.status.success() { continue; }
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines().skip(1) {
            if let Some(sock) = parse_ss_line(line, proto) {
                out.push(sock);
            }
        }
    }
    out.sort_by(|a, b| a.port.cmp(&b.port).then(a.bind.to_string().cmp(&b.bind.to_string())));
    out
}

/// Parse one line of `ss -tlnp` / `-ulnp` output.
///
/// Format (variable column count):
/// ```text
/// LISTEN  0  128  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=...))
/// LISTEN  0  128  [::]:22     [::]:*     users:(("sshd",pid=...))
/// ```
///
/// The local address column is at index 3 for TCP, 4 for UDP (UDP
/// has an extra column because its state column is `UNCONN`/empty).
/// We pick the column that contains a `:` and is parseable as
/// `addr:port` rather than indexing — robust across small ss
/// formatting differences.
fn parse_ss_line(line: &str, proto: SocketProtocol) -> Option<ListeningSocket> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 4 { return None; }

    // Find the first column that looks like a local-address:port.
    // ss puts peer-address right after, also looks like addr:port,
    // but the local one comes first.
    let local = cols.iter().find(|c| {
        // Must contain a colon and end with a port number.
        if !c.contains(':') { return false; }
        let last = c.rsplit(':').next().unwrap_or("");
        last.parse::<u16>().is_ok()
    })?;

    let (bind, port) = parse_addr_port(local)?;

    let process = cols.iter().find(|c| c.starts_with("users:"))
        .and_then(|p| p.split('"').nth(1).map(|s| s.to_string()));

    Some(ListeningSocket { bind, port, protocol: proto, process })
}

/// Parse `addr:port` into `(IpAddr, u16)`. Handles IPv6 with brackets:
/// `[::]:22`, `[fe80::1]:443`, and IPv4: `0.0.0.0:22`, `127.0.0.1:5432`.
fn parse_addr_port(s: &str) -> Option<(IpAddr, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        // IPv6 bracketed form
        let (addr, port) = rest.rsplit_once("]:")?;
        let port: u16 = port.parse().ok()?;
        let ip: IpAddr = addr.parse().ok()?;
        return Some((ip, port));
    }
    // IPv4: rsplit on ':' (only one colon expected)
    let (addr, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let ip: IpAddr = addr.parse().ok()?;
    Some((ip, port))
}

// ─── tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networking::InterfaceAddress;

    fn iface(name: &str, addrs: &[(&str, &str)]) -> NetworkInterface {
        NetworkInterface {
            name: name.into(),
            mac: "00:00:00:00:00:00".into(),
            state: "up".into(),
            mtu: 1500,
            addresses: addrs.iter().map(|(addr, fam)| InterfaceAddress {
                address: (*addr).into(),
                prefix: if *fam == "inet" { 24 } else { 64 },
                family: (*fam).into(),
                scope: "global".into(),
            }).collect(),
            is_vlan: false, vlan_id: None, parent: None,
            speed: None, driver: None,
        }
    }

    fn snap(interfaces: Vec<NetworkInterface>) -> NetworkSnapshot {
        NetworkSnapshot::from_parts(interfaces, vec![])
    }

    // ── Loopback always wins ───────────────────────────────────────

    #[test]
    fn loopback_v4_is_loopback_only() {
        let s = snap(vec![iface("eth0", &[("203.0.113.5", "inet")])]);
        assert_eq!(
            classify_bind("127.0.0.1".parse().unwrap(), &s),
            NetworkReachability::LoopbackOnly
        );
    }

    #[test]
    fn loopback_v6_is_loopback_only() {
        let s = snap(vec![iface("eth0", &[("2001:db8::1", "inet6")])]);
        assert_eq!(
            classify_bind("::1".parse().unwrap(), &s),
            NetworkReachability::LoopbackOnly
        );
    }

    // ── Wildcard takes most-permissive interface ───────────────────

    #[test]
    fn wildcard_v4_with_public_ip_is_public() {
        // Adam's MariaDB-on-public-VPS scenario: bind 0.0.0.0 on a
        // host with a real public IPv4. Reachability = PublicInternet.
        let s = snap(vec![
            iface("lo", &[("127.0.0.1", "inet")]),
            iface("eth0", &[("145.224.67.239", "inet")]),
        ]);
        assert_eq!(
            classify_bind("0.0.0.0".parse().unwrap(), &s),
            NetworkReachability::PublicInternet
        );
    }

    #[test]
    fn wildcard_v4_with_only_rfc1918_is_local_network() {
        // The exact false-positive the user called out: MariaDB on
        // 0.0.0.0 on a host whose only non-loopback IP is RFC1918.
        // Should NOT be PublicInternet.
        let s = snap(vec![
            iface("lo", &[("127.0.0.1", "inet")]),
            iface("eth0", &[("192.168.1.10", "inet")]),
        ]);
        assert_eq!(
            classify_bind("0.0.0.0".parse().unwrap(), &s),
            NetworkReachability::LocalNetwork
        );
    }

    #[test]
    fn wildcard_v4_with_only_loopback_is_unknown() {
        let s = snap(vec![iface("lo", &[("127.0.0.1", "inet")])]);
        assert_eq!(
            classify_bind("0.0.0.0".parse().unwrap(), &s),
            NetworkReachability::Unknown
        );
    }

    #[test]
    fn wildcard_v4_with_lan_and_overlay_is_local_not_overlay() {
        // Gary 2026-06-22: postgres on 0.0.0.0:5432 on a node with BOTH a LAN
        // NIC and wolfnet0 was wrongly tagged "listening on overlay wolfnet0".
        // A wildcard reaches the LAN too, so it's LocalNetwork, never overlay.
        let s = snap(vec![
            iface("lo", &[("127.0.0.1", "inet")]),
            iface("eth0", &[("192.168.1.10", "inet")]),
            iface("wolfnet0", &[("10.42.0.5", "inet")]),
        ]);
        assert_eq!(
            classify_bind("0.0.0.0".parse().unwrap(), &s),
            NetworkReachability::LocalNetwork
        );
    }

    #[test]
    fn wildcard_v4_overlay_only_when_overlay_is_sole_interface() {
        // No LAN NIC — overlay is the only non-loopback interface, so a
        // wildcard bind genuinely is overlay-only.
        let s = snap(vec![
            iface("lo", &[("127.0.0.1", "inet")]),
            iface("wolfnet0", &[("10.42.0.5", "inet")]),
        ]);
        assert_eq!(
            classify_bind("0.0.0.0".parse().unwrap(), &s),
            NetworkReachability::OverlayOnly { network: "wolfnet0".into() }
        );
    }

    #[test]
    fn wildcard_v4_promotes_when_public_ipv6_present() {
        // Public IPv6 alone is enough to make a wildcard binding
        // public-internet-reachable.
        let s = snap(vec![
            iface("eth0", &[("192.168.1.10", "inet"), ("2a01:4f8:c17:5023::1", "inet6")]),
        ]);
        assert_eq!(
            classify_bind("0.0.0.0".parse().unwrap(), &s),
            NetworkReachability::PublicInternet
        );
    }

    // ── Specific binds ─────────────────────────────────────────────

    #[test]
    fn specific_bind_on_public_v4_is_public() {
        let s = snap(vec![iface("eth0", &[("145.224.67.239", "inet")])]);
        assert_eq!(
            classify_bind("145.224.67.239".parse().unwrap(), &s),
            NetworkReachability::PublicInternet
        );
    }

    #[test]
    fn specific_bind_on_rfc1918_is_local() {
        let s = snap(vec![iface("eth0", &[("10.0.0.5", "inet")])]);
        assert_eq!(
            classify_bind("10.0.0.5".parse().unwrap(), &s),
            NetworkReachability::LocalNetwork
        );
    }

    #[test]
    fn specific_bind_on_cgnat_is_local() {
        // CGNAT (100.64/10) is not publicly routable end-to-end.
        let s = snap(vec![iface("eth0", &[("100.64.5.1", "inet")])]);
        assert_eq!(
            classify_bind("100.64.5.1".parse().unwrap(), &s),
            NetworkReachability::LocalNetwork
        );
    }

    #[test]
    fn specific_bind_on_link_local_v4_is_local() {
        let s = snap(vec![iface("eth0", &[("169.254.5.5", "inet")])]);
        assert_eq!(
            classify_bind("169.254.5.5".parse().unwrap(), &s),
            NetworkReachability::LocalNetwork
        );
    }

    #[test]
    fn specific_bind_on_ula_v6_is_local() {
        let s = snap(vec![iface("eth0", &[("fd00::1", "inet6")])]);
        assert_eq!(
            classify_bind("fd00::1".parse().unwrap(), &s),
            NetworkReachability::LocalNetwork
        );
    }

    #[test]
    fn specific_bind_on_link_local_v6_is_local() {
        let s = snap(vec![iface("eth0", &[("fe80::1", "inet6")])]);
        assert_eq!(
            classify_bind("fe80::1".parse().unwrap(), &s),
            NetworkReachability::LocalNetwork
        );
    }

    #[test]
    fn specific_bind_on_public_v6_is_public() {
        let s = snap(vec![iface("eth0", &[("2a01:4f8:c17:5023::1", "inet6")])]);
        assert_eq!(
            classify_bind("2a01:4f8:c17:5023::1".parse().unwrap(), &s),
            NetworkReachability::PublicInternet
        );
    }

    // ── Overlay detection ──────────────────────────────────────────

    #[test]
    fn bind_on_wolfnet_iface_is_overlay() {
        let s = snap(vec![
            iface("eth0", &[("145.224.67.239", "inet")]),
            iface("wn0", &[("10.42.0.5", "inet")]),
        ]);
        match classify_bind("10.42.0.5".parse().unwrap(), &s) {
            NetworkReachability::OverlayOnly { network } => assert_eq!(network, "wn0"),
            other => panic!("expected OverlayOnly, got {:?}", other),
        }
    }

    #[test]
    fn bind_on_wireguard_iface_is_overlay() {
        let s = snap(vec![
            iface("eth0", &[("145.224.67.239", "inet")]),
            iface("wg0", &[("10.99.0.1", "inet")]),
        ]);
        match classify_bind("10.99.0.1".parse().unwrap(), &s) {
            NetworkReachability::OverlayOnly { network } => assert_eq!(network, "wg0"),
            other => panic!("expected OverlayOnly, got {:?}", other),
        }
    }

    // ── ss line parsing ────────────────────────────────────────────

    #[test]
    fn parse_addr_port_v4() {
        assert_eq!(parse_addr_port("0.0.0.0:22"),
            Some(("0.0.0.0".parse().unwrap(), 22u16)));
        assert_eq!(parse_addr_port("127.0.0.1:5432"),
            Some(("127.0.0.1".parse().unwrap(), 5432u16)));
        assert_eq!(parse_addr_port("192.168.1.10:443"),
            Some(("192.168.1.10".parse().unwrap(), 443u16)));
    }

    #[test]
    fn parse_addr_port_v6() {
        assert_eq!(parse_addr_port("[::]:22"),
            Some(("::".parse().unwrap(), 22u16)));
        assert_eq!(parse_addr_port("[::1]:5432"),
            Some(("::1".parse().unwrap(), 5432u16)));
        assert_eq!(parse_addr_port("[fe80::1]:443"),
            Some(("fe80::1".parse().unwrap(), 443u16)));
    }

    #[test]
    fn parse_addr_port_rejects_garbage() {
        assert_eq!(parse_addr_port("not-a-host"), None);
        assert_eq!(parse_addr_port("1.2.3.4:notaport"), None);
        assert_eq!(parse_addr_port(""), None);
    }

    #[test]
    fn parse_ss_line_extracts_process_name() {
        let line = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1234,fd=3))";
        let sock = parse_ss_line(line, SocketProtocol::Tcp).expect("parse");
        assert_eq!(sock.bind, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(sock.port, 22);
        assert_eq!(sock.protocol, SocketProtocol::Tcp);
        assert_eq!(sock.process.as_deref(), Some("sshd"));
    }

    #[test]
    fn parse_ss_line_handles_v6_brackets() {
        let line = "LISTEN 0 128 [::]:22 [::]:* users:((\"sshd\",pid=1234,fd=3))";
        let sock = parse_ss_line(line, SocketProtocol::Tcp).expect("parse");
        assert_eq!(sock.bind, "::".parse::<IpAddr>().unwrap());
        assert_eq!(sock.port, 22);
    }

    #[test]
    fn parse_ss_line_handles_no_process_column() {
        let line = "LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*";
        let sock = parse_ss_line(line, SocketProtocol::Tcp).expect("parse");
        assert_eq!(sock.process, None);
    }
}
