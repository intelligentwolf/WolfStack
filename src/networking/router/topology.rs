// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! Topology model + live sampling for the rack view.
//!
//! This module walks the local host's state (`ip -j link`, `ip -j addr`,
//! `/proc/net/dev`, bridge membership, WolfStack's own VM/container
//! lists) and emits a `NodeTopology` snapshot. The API layer aggregates
//! one of these per cluster node into a `RouterTopology` for the UI.

use super::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::sync::{LazyLock, RwLock};
use std::time::Instant;

/// Aggregated cluster topology for the rack view.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterTopology {
    pub nodes: Vec<NodeTopology>,
    pub links: Vec<TopologyLink>,
    /// Epoch seconds when this topology was computed.
    pub generated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeTopology {
    pub node_id: String,
    pub node_name: String,
    pub interfaces: Vec<PortState>,
    pub bridges: Vec<BridgeState>,
    pub vlans: Vec<VlanState>,
    /// Short list of VMs on this node with their NIC attachments.
    pub vms: Vec<DeviceAttachment>,
    pub containers: Vec<DeviceAttachment>,
    /// IDs of LAN segments hosted by this node.
    pub lan_segments: Vec<String>,
    /// Upstream routers discovered on this node (default gateways).
    /// Each node in a cluster may have different gateways; the master
    /// deduplicates by IP when building the cluster-wide view.
    #[serde(default)]
    pub routers: Vec<DiscoveredRouter>,
    /// "live" = full topology fetched; "connecting" = retrying;
    /// "unreachable" = retries exhausted. The frontend draws the
    /// chassis immediately for every node in the cluster and fills
    /// it in when the live data arrives.
    #[serde(default = "default_topology_status")]
    pub status: String,
    /// Reason for non-live status (e.g. "connecting…", last error).
    #[serde(default)]
    pub status_note: String,
}

fn default_topology_status() -> String { "live".into() }

impl NodeTopology {
    /// Skeleton entry for a peer we haven't fetched (or couldn't
    /// fetch). The rack view renders this as a chassis with a status
    /// message until the real data arrives on a subsequent poll.
    pub fn stub(node_id: String, node_name: String, status: &str, note: String) -> Self {
        NodeTopology {
            node_id, node_name,
            interfaces: vec![], bridges: vec![], vlans: vec![],
            vms: vec![], containers: vec![], lan_segments: vec![],
            routers: vec![],
            status: status.into(),
            status_note: note,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortState {
    pub name: String,              // enp2s0
    pub slot: u32,                 // rack-order index
    pub mac: String,
    pub link_up: bool,
    pub speed_mbps: Option<u32>,
    pub addresses: Vec<String>,    // "192.168.1.10/24"
    pub zone: Option<Zone>,
    pub role: PortRole,
    pub rx_bps: u64,               // live
    pub tx_bps: u64,
    pub master: Option<String>,    // bridge name if slaved
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortRole { Wan, Lan, Trunk, Management, Wolfnet, Unused }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeState {
    pub name: String,
    pub members: Vec<String>,      // interface names attached
    pub addresses: Vec<String>,
    pub zone: Option<Zone>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlanState {
    pub name: String,              // "eth0.100"
    pub parent: String,
    pub vlan_id: u32,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAttachment {
    pub name: String,              // VM name / container name
    pub kind: String,              // "vm", "docker", "lxc"
    pub attached_to: String,       // interface/bridge/"wolfnet"
    pub ip: Option<String>,
}

/// Logical link between two things in the topology graph. The UI renders
/// these as wires in the rack view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyLink {
    pub from: EndpointRef,
    pub to: EndpointRef,
    pub kind: LinkKind,
    pub bps_live: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EndpointRef {
    Port { node: String, iface: String },
    Bridge { node: String, name: String },
    Lan { id: String },
    Vm { node: String, name: String },
    Container { node: String, name: String },
    Upstream,       // the ISP / "WAN cloud"
    Wolfnet,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    Physical,
    Tap,
    Veth,
    Wireguard,
    Wolfnet,
    Virtual,   // LAN segment ↔ bridge
}

// ── Live BPS tracker ──
//
// /proc/net/dev gives cumulative bytes. We subtract from the previous
// sample to get bits/sec. Cache keyed by (node_id, iface) in a global.

struct BpsSample { bytes: u64, at: Instant }
struct BpsTracker {
    rx: HashMap<String, BpsSample>,
    tx: HashMap<String, BpsSample>,
}
static BPS: LazyLock<RwLock<BpsTracker>> = LazyLock::new(|| RwLock::new(BpsTracker {
    rx: HashMap::new(), tx: HashMap::new(),
}));

/// Sample /proc/net/dev and compute per-iface BPS against the previous
/// sample. Returns a map of iface → (rx_bps, tx_bps).
pub fn sample_bps() -> HashMap<String, (u64, u64)> {
    let mut out = HashMap::new();
    let text = match std::fs::read_to_string("/proc/net/dev") {
        Ok(s) => s,
        Err(_) => return out,
    };
    let now = Instant::now();
    let mut tracker = BPS.write().unwrap();
    for line in text.lines().skip(2) {
        let line = line.trim();
        if let Some((name, rest)) = line.split_once(':') {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() < 9 { continue; }
            let rx_bytes: u64 = parts[0].parse().unwrap_or(0);
            let tx_bytes: u64 = parts[8].parse().unwrap_or(0);
            let iface = name.trim().to_string();

            let rx_bps = delta_bps(&mut tracker.rx, &iface, rx_bytes, now);
            let tx_bps = delta_bps(&mut tracker.tx, &iface, tx_bytes, now);
            out.insert(iface, (rx_bps, tx_bps));
        }
    }
    out
}

fn delta_bps(map: &mut HashMap<String, BpsSample>, iface: &str, bytes: u64, now: Instant) -> u64 {
    let prev = map.insert(iface.to_string(), BpsSample { bytes, at: now });
    match prev {
        Some(p) => {
            let dt = now.saturating_duration_since(p.at);
            if dt.as_millis() < 100 { return 0; } // avoid division spikes
            let dbytes = bytes.saturating_sub(p.bytes);
            dbytes * 8 * 1000 / dt.as_millis().max(1) as u64
        }
        None => 0,
    }
}

// ── System walkers ──

/// Auto-assign zones for WolfStack-managed infrastructure interfaces
/// the user hasn't explicitly zoned yet. WolfNet → Wolfnet zone,
/// WireGuard bridges → Wolfnet (the VPN's whole point is reaching
/// WolfNet), default-route NIC → WAN. Persists once seeded so the
/// user can override later. Returns true if anything changed.
///
/// Called from `compute_local` on every topology poll. Two
/// safety properties matter here:
///   1. **Mutate in-place on the live RouterState** — older
///      versions loaded `RouterConfig` from disk into a local
///      copy and saved that, which meant a parse-error startup
///      where the in-memory config was the empty default would
///      atomic-rename the empty default + auto-zones over the
///      user's last-known-good file. Now we mutate the same
///      `RwLock<RouterConfig>` the API endpoints read from, so
///      a startup that landed in the parse-error state has its
///      in-memory config remain visibly empty without any disk
///      write being attempted.
///   2. **Persistence is gated on `RouterState::may_save`** —
///      `loaded_clean=false` means we skip the save entirely and
///      log once. The in-memory auto-zones are still applied so
///      the running rack view is sensible while the user picks a
///      recovery snapshot.
pub fn ensure_default_zones(state: &RouterState, node_id: &str) -> bool {
    use std::process::Command;
    let text = Command::new("ip").args(["-j", "link"]).output().ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|| "[]".into());
    let links: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap_or_default();
    let primary = crate::networking::detect_primary_interface();

    // First mutate in-place under the write lock. Compute the
    // changes inside the lock so two concurrent topology polls
    // don't race on a stale view of `cfg.zones`.
    let mut changed = false;
    {
        let mut cfg = match state.config.write() {
            Ok(g) => g,
            Err(_) => return false, // poisoned — caller logs separately
        };
        for link in &links {
            let name = match link.get("ifname").and_then(|v| v.as_str()) {
                Some(s) if !s.is_empty() && s != "lo" => s.to_string(),
                _ => continue,
            };
            if cfg.zones.get(node_id, &name).is_some() { continue; }
            let auto_zone = if name.starts_with("wn") || name.starts_with("wolfnet") || name.starts_with("wg-") {
                Some(Zone::Wolfnet)
            } else if name == primary {
                Some(Zone::Wan)
            } else {
                None
            };
            if let Some(z) = auto_zone {
                cfg.zones.set(node_id, &name, z);
                changed = true;
            }
        }
    }

    if changed && state.may_save() {
        // Snapshot under the read lock so save() doesn't hold the
        // write lock during disk I/O.
        let snapshot = state.config.read().map(|g| g.clone()).ok();
        if let Some(s) = snapshot
            && let Err(e) = s.save() {
                tracing::warn!(
                    "WolfRouter: ensure_default_zones could not persist \
                     auto-zones for node {}: {}. In-memory state has the \
                     auto-zones; the next user save will pick them up.",
                    node_id, e,
                );
            }
    } else if changed && !state.may_save() {
        // Loud, but only once per process — the watchdog tick logs
        // at debug to avoid spamming logs while the user is in the
        // recovery flow.
        tracing::debug!(
            "WolfRouter: skipping persist of auto-zones — startup load \
             failed and the recovery flow has not completed yet. Pick a \
             snapshot in the rollback panel to restore persistence.",
        );
    }
    changed
}

/// A router/gateway device discovered on the network — typically the
/// default route target. Shown in the rack view above the server
/// chassis so users see the full path: Internet → router → WAN port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredRouter {
    pub ip: String,
    /// Human name — best-effort from HTTP title, SNMP sysDescr, or
    /// reverse DNS. Falls back to just the IP.
    pub name: String,
    /// Vendor name parsed from probe results (e.g. "MikroTik",
    /// "AVM Fritz!Box", "Ubiquiti", "OpenWrt"). Empty if unidentified.
    pub vendor: String,
    /// Model string if found (e.g. "Fritz!Box 7590", "hAP ac3").
    pub model: String,
    /// URL to the router's admin web UI (if HTTP/HTTPS responded).
    pub web_url: String,
    /// True if the gateway responded to probes within the last poll.
    pub reachable: bool,
}

/// Detect default gateways from the kernel routing table and probe
/// each one to identify vendor/model. Cheap enough to call every poll
/// cycle — `ip route` is a netlink read (<1ms), and the HTTP probes
/// have a 2-second timeout so they don't block for ages when a gateway
/// is down.
pub fn discover_routers() -> Vec<DiscoveredRouter> {
    let out = match std::process::Command::new("ip")
        .args(["-j", "route", "show", "default"])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => return vec![],
    };
    let routes: Vec<serde_json::Value> = serde_json::from_slice(&out).unwrap_or_default();
    // Deduplicate gateways (multiple default routes can point at the
    // same IP via different interfaces).
    let mut seen = std::collections::HashSet::new();
    let mut routers = Vec::new();
    for route in &routes {
        let gw = match route.get("gateway").and_then(|v| v.as_str()) {
            Some(g) if !g.is_empty() => g.to_string(),
            _ => continue,
        };
        // Skip IPv6 link-local gateways (fe80::) — they're per-interface
        // artifacts, not real upstream routers the user wants to see in
        // the rack. They can't be probed via HTTP without %iface scope
        // notation, and they all resolve to the same physical device as
        // the IPv4 gateway anyway.
        if gw.starts_with("fe80") { continue; }
        if !seen.insert(gw.clone()) { continue; }
        routers.push(probe_router(&gw));
    }
    routers
}

/// Probe a single gateway IP to extract vendor/model/web-URL. Tries
/// HTTPS first (most modern routers redirect HTTP→HTTPS), falls back
/// to HTTP, then plain reachability via ping. The whole function is
/// bounded to ~3 seconds worst-case.
fn probe_router(ip: &str) -> DiscoveredRouter {
    let mut router = DiscoveredRouter {
        ip: ip.to_string(),
        name: ip.to_string(),
        vendor: String::new(),
        model: String::new(),
        web_url: String::new(),
        reachable: false,
    };

    // Try HTTP first — most consumer routers (Mecusys, TP-Link,
    // Netgear, etc) only have HTTP; trying HTTPS first wastes the
    // 2s timeout on a connection that will never complete. Use `-i`
    // so curl outputs headers + body together — we need BOTH the
    // Server header AND the <title> tag to identify the vendor.
    // The old `-o /dev/null` approach discarded the body entirely,
    // which meant routers whose identity was only in the page title
    // (not in the Server header) showed as "unknown" or worse, the
    // dig error output leaked through as the name.
    for scheme in &["http", "https"] {
        let url = format!("{}://{}", scheme, ip);
        let out = std::process::Command::new("curl")
            .args(["-skLi", "--max-time", "2", &url])
            .output();
        if let Ok(o) = out {
            // Cap at 8KB — enough for headers + <title>. Avoids
            // buffering a 2MB router firmware-update page.
            let raw = &o.stdout[..o.stdout.len().min(8192)];
            let text = String::from_utf8_lossy(raw).to_string();
            if !text.is_empty() {
                router.reachable = true;
                router.web_url = url.clone();
                identify_vendor(&text, &mut router);
                // Stop probing once we have a name (not just the IP).
                if !router.vendor.is_empty() || (router.name != ip && !router.name.is_empty()) {
                    break;
                }
            }
        }
    }

    // If HTTP didn't work, try a quick ping for reachability.
    if !router.reachable
        && let Ok(o) = std::process::Command::new("ping")
            .args(["-c", "1", "-W", "1", ip])
            .output()
        {
            router.reachable = o.status.success();
        }

    // Reverse DNS as a last-resort name. Filter out dig error
    // messages (lines starting with ";;") which leak through as the
    // router name when the DNS server is unreachable — the user was
    // seeing ";; communications error to xxx ;; no servers could be
    // reached" as the router label in the rack view.
    if router.name == router.ip
        && let Ok(o) = std::process::Command::new("dig")
            .args(["+short", "-x", ip, "+time=1", "+tries=1"])
            .output()
        {
            let rdns: String = String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.trim_start().starts_with(";;"))
                .collect::<Vec<_>>()
                .join("")
                .trim()
                .trim_end_matches('.')
                .to_string();
            if !rdns.is_empty() && rdns != ip {
                router.name = rdns;
            }
        }

    router
}

/// Parse HTTP headers / body for known vendor fingerprints and fill
/// in vendor + model + name on the router struct. Order matters —
/// first match wins.
fn identify_vendor(text: &str, router: &mut DiscoveredRouter) {
    let lower = text.to_ascii_lowercase();

    // Extract <title>...</title> if present (some curl modes capture it).
    let title = text.find("<title>")
        .and_then(|start| {
            let rest = &text[start + 7..];
            rest.find("</title>").map(|end| rest[..end].trim().to_string())
        });
    // Extract Server: header value.
    let server = text.lines()
        .find(|l| l.to_ascii_lowercase().starts_with("server:"))
        .map(|l| l[7..].trim().to_string());

    // Vendor-specific fingerprints — most reliable to least.
    type VendorExtractor = fn(&Option<String>, &Option<String>) -> (String, String);
    let patterns: &[(&str, &str, VendorExtractor)] = &[
        ("fritz", "AVM", |title, _| {
            let model = title.as_deref().unwrap_or("Fritz!Box").to_string();
            ("AVM Fritz!Box".into(), model)
        }),
        ("mikrotik", "MikroTik", |_, server| {
            let model = server.as_deref().unwrap_or("RouterOS").to_string();
            ("MikroTik".into(), model)
        }),
        ("routeros", "MikroTik", |_, server| {
            ("MikroTik".into(), server.as_deref().unwrap_or("RouterOS").to_string())
        }),
        ("ubnt", "Ubiquiti", |title, _| {
            ("Ubiquiti".into(), title.as_deref().unwrap_or("UniFi").to_string())
        }),
        ("unifi", "Ubiquiti", |title, _| {
            ("Ubiquiti".into(), title.as_deref().unwrap_or("UniFi").to_string())
        }),
        ("airos", "Ubiquiti", |_, _| ("Ubiquiti".into(), "airOS".into())),
        ("opnsense", "OPNsense", |_, _| ("OPNsense".into(), "OPNsense".into())),
        ("pfsense", "pfSense", |_, _| ("pfSense".into(), "pfSense".into())),
        ("openwrt", "OpenWrt", |_, _| ("OpenWrt".into(), "OpenWrt".into())),
        ("luci", "OpenWrt", |_, _| ("OpenWrt".into(), "LuCI".into())),
        ("tp-link", "TP-Link", |title, _| {
            ("TP-Link".into(), title.as_deref().unwrap_or("TP-Link").to_string())
        }),
        ("netgear", "Netgear", |title, _| {
            ("Netgear".into(), title.as_deref().unwrap_or("Netgear").to_string())
        }),
        ("asus", "ASUS", |title, _| {
            ("ASUS".into(), title.as_deref().unwrap_or("ASUS Router").to_string())
        }),
        ("linksys", "Linksys", |title, _| {
            ("Linksys".into(), title.as_deref().unwrap_or("Linksys").to_string())
        }),
        ("cisco", "Cisco", |title, _| {
            ("Cisco".into(), title.as_deref().unwrap_or("Cisco").to_string())
        }),
        ("draytek", "DrayTek", |title, _| {
            ("DrayTek".into(), title.as_deref().unwrap_or("DrayTek Vigor").to_string())
        }),
        ("mercusys", "Mercusys", |title, _| {
            ("Mercusys".into(), title.as_deref().unwrap_or("Mercusys").to_string())
        }),
        ("merc", "Mercusys", |title, _| {
            ("Mercusys".into(), title.as_deref().unwrap_or("Mercusys").to_string())
        }),
        ("mwlogin", "Mercusys", |title, _| {
            ("Mercusys".into(), title.as_deref().unwrap_or("Mercusys").to_string())
        }),
        ("ac12", "Mercusys", |title, _| {
            ("Mercusys".into(), format!("Mercusys {}", title.as_deref().unwrap_or("AC12")))
        }),
        ("ac10", "Mercusys", |title, _| {
            ("Mercusys".into(), format!("Mercusys {}", title.as_deref().unwrap_or("AC10")))
        }),
        ("mr70x", "Mercusys", |title, _| {
            ("Mercusys".into(), format!("Mercusys {}", title.as_deref().unwrap_or("MR70X")))
        }),
        ("mr30g", "Mercusys", |title, _| {
            ("Mercusys".into(), format!("Mercusys {}", title.as_deref().unwrap_or("MR30G")))
        }),
        ("tenda", "Tenda", |title, _| {
            ("Tenda".into(), title.as_deref().unwrap_or("Tenda").to_string())
        }),
        ("huawei", "Huawei", |title, _| {
            ("Huawei".into(), title.as_deref().unwrap_or("Huawei").to_string())
        }),
        ("zyxel", "ZyXEL", |title, _| {
            ("ZyXEL".into(), title.as_deref().unwrap_or("ZyXEL").to_string())
        }),
    ];

    for (keyword, _vendor, extract) in patterns {
        if lower.contains(keyword) {
            let (vendor, model) = extract(&title, &server);
            router.vendor = vendor;
            router.model = model.clone();
            router.name = if title.is_some() {
                title.as_deref().unwrap_or(&model).to_string()
            } else {
                model
            };
            return;
        }
    }

    // Fallback: use title or server as-is if we got anything.
    if let Some(t) = &title {
        if !t.is_empty() { router.name = t.clone(); }
    } else if let Some(s) = &server
        && !s.is_empty() { router.name = s.clone(); }
}

/// Compute the local node's topology. API handlers on the master node
/// call this on each worker node via cluster RPC to assemble the
/// cluster-wide view.
pub fn compute_local(
    node_id: &str,
    node_name: &str,
    config: &RouterConfig,
    state: &RouterState,
) -> NodeTopology {
    // Seed defaults for WolfStack-managed interfaces if the user
    // hasn't zoned them yet. Cheap (one ip-link call) and idempotent.
    // Operates on the live `state.config` so the in-memory view
    // stays consistent with what the API endpoints read; persistence
    // is gated inside `ensure_default_zones` on `state.may_save()`.
    //
    // `ensure_default_zones` is the ONLY step that can persist; the VM
    // walk can also self-heal a stale pause marker. The healing build
    // (`passive=false`) keeps both; the observed Network Map calls
    // `compute_local_passive` (`passive=true`) which does neither.
    let _ = ensure_default_zones(state, node_id);
    build_topology(node_id, node_name, config, /*passive=*/false)
}

/// Read-only topology build — identical to [`compute_local`] but does
/// NO writes: it skips `ensure_default_zones` (config persistence) AND
/// uses the read-only VM listing (no stale-pause-marker self-heal).
/// Every step is a passive read: `ip`/`docker`/`lxc` enumeration,
/// `/proc` and `/sys` reads, and cached gateway discovery. The observed
/// **Network Map** uses this so it can be honestly promised as
/// side-effect-free.
pub fn compute_local_passive(
    node_id: &str,
    node_name: &str,
    config: &RouterConfig,
) -> NodeTopology {
    build_topology(node_id, node_name, config, /*passive=*/true)
}

/// Shared topology build for both [`compute_local`] (healing) and
/// [`compute_local_passive`] (read-only). `passive` selects the VM
/// listing: read-only (no marker self-heal) vs the normal healing list.
fn build_topology(
    node_id: &str,
    node_name: &str,
    config: &RouterConfig,
    passive: bool,
) -> NodeTopology {
    let bps = sample_bps();
    let interfaces = walk_interfaces(&bps, config, node_id);
    let bridges = walk_bridges(config, node_id);
    let vlans = walk_vlans();
    let vms = walk_vms(node_id, passive);
    let containers = walk_containers(node_id);
    let lan_segments = config.lans.iter()
        .filter(|l| l.node_id == node_id)
        .map(|l| l.id.clone())
        .collect();

    // Router discovery is expensive (~2s per gateway when probing HTTP).
    // Cache the result and re-probe at most every 60 seconds so the 3s
    // topology poll cycle doesn't stack up probe latency.
    let routers = cached_discover_routers();

    NodeTopology {
        node_id: node_id.into(),
        node_name: node_name.into(),
        interfaces,
        bridges,
        vlans,
        vms,
        containers,
        lan_segments,
        routers,
        status: "live".into(),
        status_note: String::new(),
    }
}

/// Cached router discovery — re-probes at most every 60 seconds.
/// Between probes, returns the previous result so the 3s topology
/// poll doesn't pile up 2s HTTP probes on every tick.
///
/// The mutex is held ONLY for the cache read/write — the actual
/// probe (which can take seconds) runs outside the lock so
/// concurrent callers don't stall waiting for curl to finish.
fn cached_discover_routers() -> Vec<DiscoveredRouter> {
    use std::sync::Mutex;
    static CACHE: Mutex<Option<(std::time::Instant, Vec<DiscoveredRouter>)>> = Mutex::new(None);
    let ttl = std::time::Duration::from_secs(60);

    // Check cache under lock — return immediately if fresh.
    {
        let guard = CACHE.lock().unwrap();
        if let Some((ts, ref data)) = *guard
            && ts.elapsed() < ttl { return data.clone(); }
    } // lock dropped before the expensive probe

    // Cache miss — probe outside the lock.
    let fresh = discover_routers();

    // Write back under lock.
    let mut guard = CACHE.lock().unwrap();
    *guard = Some((std::time::Instant::now(), fresh.clone()));
    fresh
}

fn walk_interfaces(
    bps: &HashMap<String, (u64, u64)>,
    config: &RouterConfig,
    node_id: &str,
) -> Vec<PortState> {
    // Use `ip -j link` and `ip -j addr` for machine-readable output.
    let link_text = run_json(&["ip", "-j", "link"]);
    let addr_text = run_json(&["ip", "-j", "addr"]);
    let links: Vec<serde_json::Value> = serde_json::from_str(&link_text).unwrap_or_default();
    let addrs: Vec<serde_json::Value> = serde_json::from_str(&addr_text).unwrap_or_default();

    // Build ifname → addrs map.
    let mut addr_map: HashMap<String, Vec<String>> = HashMap::new();
    for a in &addrs {
        let name = a.get("ifname").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let ips: Vec<String> = a.get("addr_info")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().filter_map(|e| {
                    let ip = e.get("local")?.as_str()?;
                    let prefix = e.get("prefixlen")?.as_u64()?;
                    Some(format!("{}/{}", ip, prefix))
                }).collect()
            })
            .unwrap_or_default();
        addr_map.insert(name, ips);
    }

    let mut out = Vec::new();
    for (slot, link) in links.iter().enumerate() {
        let name = link.get("ifname").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if name.is_empty() { continue; }
        // Skip purely-internal interfaces that aren't useful in the rack
        // view: loopback, per-VM TAPs (their owning VM is rendered
        // separately as a device), per-container veth pairs, the
        // Linux-bridge slave names. WolfNet (wn*/wolfnet*) and WireGuard
        // bridges (wg-*) ARE included as first-class ports — WolfRouter
        // needs to show what WolfStack already runs, not hide it.
        if name == "lo"
            || name.starts_with("tap-")
            || name.starts_with("veth")
        {
            continue;
        }
        // docker0/lxcbr0/br-* render in walk_bridges, but we still want
        // them visible somewhere — emit them as ports too so the user
        // sees the whole cluster layout from one place.
        let _is_overlay_or_bridge =
            name.starts_with("wn") || name.starts_with("wolfnet")
            || name.starts_with("wg-")
            || name == "docker0" || name == "lxcbr0"
            || name.starts_with("br-");
        let mac = link.get("address").and_then(|v| v.as_str()).unwrap_or("").to_string();
        // Port up/down detection — `operstate` from `ip link` is unreliable
        // for many interfaces (returns UNKNOWN on virtual/wireless NICs
        // that are functionally up). The kernel exposes the authoritative
        // physical link state at `/sys/class/net/<iface>/carrier` (1=up,
        // 0=down). Read carrier first and fall back to operstate=="UP"
        // only when carrier isn't readable.
        let operstate = link.get("operstate").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
        let link_up = read_carrier(&name).unwrap_or(operstate == "UP" || operstate == "UNKNOWN");
        let master = link.get("master").and_then(|v| v.as_str()).map(|s| s.to_string());
        let speed_mbps = read_speed_mbps(&name);
        let (rx, tx) = bps.get(&name).cloned().unwrap_or((0, 0));
        let addresses = addr_map.get(&name).cloned().unwrap_or_default();
        let zone = config.zones.get(node_id, &name).cloned();
        let role = infer_role(&name, &zone, link_up, master.is_some(), config, node_id);

        out.push(PortState {
            name,
            slot: slot as u32,
            mac,
            link_up,
            speed_mbps,
            addresses,
            zone,
            role,
            rx_bps: rx,
            tx_bps: tx,
            master,
        });
    }
    out
}

fn walk_bridges(config: &RouterConfig, node_id: &str) -> Vec<BridgeState> {
    // `ip -j link show type bridge` lists bridges. Membership comes from
    // the `master` field of slave links.
    let text = run_json(&["ip", "-j", "link", "show", "type", "bridge"]);
    let bridges: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap_or_default();
    let all_links_text = run_json(&["ip", "-j", "link"]);
    let all_links: Vec<serde_json::Value> = serde_json::from_str(&all_links_text).unwrap_or_default();
    let addr_text = run_json(&["ip", "-j", "addr"]);
    let addrs: Vec<serde_json::Value> = serde_json::from_str(&addr_text).unwrap_or_default();

    let mut out = Vec::new();
    for b in bridges {
        let name = b.get("ifname").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if name.is_empty() { continue; }
        let members: Vec<String> = all_links.iter().filter_map(|l| {
            let master = l.get("master").and_then(|v| v.as_str())?;
            if master == name {
                l.get("ifname").and_then(|v| v.as_str()).map(|s| s.to_string())
            } else { None }
        }).collect();
        let addresses: Vec<String> = addrs.iter().find(|a| {
            a.get("ifname").and_then(|v| v.as_str()) == Some(name.as_str())
        }).and_then(|a| a.get("addr_info"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|e| {
                let ip = e.get("local")?.as_str()?;
                let prefix = e.get("prefixlen")?.as_u64()?;
                Some(format!("{}/{}", ip, prefix))
            }).collect()).unwrap_or_default();
        let zone = config.zones.get(node_id, &name).cloned();
        out.push(BridgeState { name, members, addresses, zone });
    }
    out
}

fn walk_vlans() -> Vec<VlanState> {
    let text = run_json(&["ip", "-j", "-d", "link"]);
    let links: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap_or_default();
    let addr_text = run_json(&["ip", "-j", "addr"]);
    let addrs: Vec<serde_json::Value> = serde_json::from_str(&addr_text).unwrap_or_default();

    let mut out = Vec::new();
    for l in links {
        let linkinfo = match l.get("linkinfo") { Some(v) => v, None => continue };
        let kind = linkinfo.get("info_kind").and_then(|v| v.as_str()).unwrap_or("");
        if kind != "vlan" { continue; }
        let name = l.get("ifname").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let parent = l.get("link").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let vlan_id = linkinfo.get("info_data")
            .and_then(|d| d.get("id"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let addresses: Vec<String> = addrs.iter().find(|a| {
            a.get("ifname").and_then(|v| v.as_str()) == Some(name.as_str())
        }).and_then(|a| a.get("addr_info"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|e| {
                let ip = e.get("local")?.as_str()?;
                let prefix = e.get("prefixlen")?.as_u64()?;
                Some(format!("{}/{}", ip, prefix))
            }).collect()).unwrap_or_default();
        out.push(VlanState { name, parent, vlan_id, addresses });
    }
    out
}

fn walk_vms(node_id: &str, passive: bool) -> Vec<DeviceAttachment> {
    // VmConfig has a `host_id` field that records which node owns the
    // VM. Filter to only this node's VMs so the cluster view doesn't
    // duplicate every VM under every node.
    let vmm = crate::vms::manager::VmManager::new();
    // `passive` (observed Network Map) uses the read-only listing so it
    // never self-heals a stale pause marker on disk.
    let configs = if passive { vmm.list_vms_readonly() } else { vmm.list_vms() };
    configs.into_iter()
        .filter(|c| c.host_id.as_deref().map(|h| h == node_id).unwrap_or(true))
        .map(|c| {
            let attached = if c.wolfnet_ip.is_some() { "wolfnet".to_string() }
                else if let Some(n) = c.extra_nics.first() {
                    n.passthrough_interface.clone()
                        .or_else(|| n.bridge.clone())
                        .unwrap_or_else(|| "user-mode".into())
                } else { "user-mode".into() };
            DeviceAttachment {
                name: c.name,
                kind: "vm".into(),
                attached_to: attached,
                ip: c.wolfnet_ip,
            }
        })
        .collect()
}

fn walk_containers(_node_id: &str) -> Vec<DeviceAttachment> {
    // Best-effort: list docker + lxc containers WITH their IPs so the
    // rack-view device badges show something useful.
    let mut out = Vec::new();
    // Docker — M4 fix: collapse the per-container `docker inspect`
    // fan-out into a SINGLE multi-id inspect call. `docker inspect`
    // accepts any number of container IDs as positional args, so one
    // subprocess produces output for every running container instead
    // of (1 + N). On a node with 20 containers that's 2 subprocess
    // calls per topology poll instead of 21.
    //
    // Pass 1: collect (name, networks) from `docker ps --format` (no
    // IP available here — `.Networks` is the network-name CSV).
    // Pass 2: feed every name into a single `docker inspect ...` and
    // parse one line of "<name>\t<first-ip>" per container.
    if let Ok(o) = Command::new("docker")
        .args(["ps", "--format", "{{.Names}}\t{{.Networks}}"])
        .output()
        && o.status.success() {
            let mut entries: Vec<(String, String)> = Vec::new();
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                let parts: Vec<&str> = line.splitn(2, '\t').collect();
                if parts.is_empty() { continue; }
                let name = parts[0].to_string();
                let nets = parts.get(1).map(|s| s.to_string()).unwrap_or_default();
                entries.push((name, nets));
            }
            // Single multi-id inspect.
            let mut ip_by_name: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            if !entries.is_empty() {
                let mut args: Vec<&str> = vec![
                    "inspect", "--format",
                    "{{.Name}}\t{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                ];
                let name_refs: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
                args.extend(name_refs.iter().copied());
                if let Ok(o2) = Command::new("docker").args(&args).output() {
                    // M4-FAIL-ALL fix: parse stdout regardless of exit
                    // status. `docker inspect` exits non-zero if ANY
                    // container ID is missing (the brief race between
                    // `docker ps` above and this call — short-lived
                    // containers can disappear), but it still emits
                    // output for every container it DID find before
                    // hitting the missing one. Gating on success was
                    // turning that race into "all IPs vanish" on busy
                    // hosts; without the gate we get IPs for whatever
                    // is still alive, which is what we want.
                    for line in String::from_utf8_lossy(&o2.stdout).lines() {
                        let parts: Vec<&str> = line.splitn(2, '\t').collect();
                        if parts.len() != 2 { continue; }
                        // docker prepends `/` to .Name; strip it.
                        let name = parts[0].trim_start_matches('/').to_string();
                        let ip = parts[1].split_whitespace().next()
                            .filter(|t| !t.is_empty())
                            .map(|t| t.to_string());
                        if let Some(ip) = ip { ip_by_name.insert(name, ip); }
                    }
                }
            }
            for (name, nets) in entries {
                let ip = ip_by_name.get(&name).cloned();
                out.push(DeviceAttachment {
                    name,
                    kind: "docker".into(),
                    attached_to: nets,
                    ip,
                });
            }
        }
    // LXC — `lxc-info -iH` returns IPs only.
    if let Ok(o) = Command::new("lxc-ls").args(["--running"]).output()
        && o.status.success() {
            for name in String::from_utf8_lossy(&o.stdout).split_whitespace() {
                let ip = Command::new("lxc-info")
                    .args(["-n", name, "-iH"])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    // lxc-info can return multiple lines (one per iface);
                    // first non-link-local IPv4 wins.
                    .and_then(|s| s.lines().find(|l| !l.starts_with("fe80") && l.contains('.'))
                        .map(|l| l.trim().to_string()));
                out.push(DeviceAttachment {
                    name: name.to_string(),
                    kind: "lxc".into(),
                    attached_to: "lxcbr0".into(),
                    ip,
                });
            }
        }
    out
}

fn infer_role(
    name: &str,
    zone: &Option<Zone>,
    _link_up: bool,
    slaved: bool,
    config: &RouterConfig,
    node_id: &str,
) -> PortRole {
    // Reality beats label. If a WanConnection or LanSegment actually
    // points at this interface, that's what it IS, regardless of what
    // the user has clicked in the Zones tab. This stops the rack view
    // from lying after a zone-drift (zones say WAN but the LAN segment
    // is still serving DHCP here — showing a cable to Internet would
    // be wrong and is exactly the "weird rack" bug users hit).
    if config.wan_connections.iter().any(|w| w.enabled && w.node_id == node_id && w.interface == name) {
        return PortRole::Wan;
    }
    if config.lans.iter().any(|l| l.node_id == node_id && l.interface == name) {
        return PortRole::Lan;
    }

    // No actual config binds this iface. Fall back to the zone label
    // as the admin's intent, then name heuristics.
    if let Some(z) = zone {
        return match z {
            Zone::Wan => PortRole::Wan,
            Zone::Lan(_) => PortRole::Lan,
            Zone::Wolfnet => PortRole::Wolfnet,
            _ => PortRole::Lan,
        };
    }
    // Auto-detect WolfStack-managed infrastructure. WolfRouter doesn't
    // own these interfaces but it should recognise and label them so
    // the user sees their full stack in one view rather than wondering
    // why wn0 isn't showing up.
    if name.starts_with("wn") || name.starts_with("wolfnet") {
        return PortRole::Wolfnet;
    }
    if name.starts_with("wg-") {
        // WireGuard bridge — VPN access into the cluster. Treated as
        // its own role; the firewall view colours it management.
        return PortRole::Management;
    }
    if name == "docker0" || name == "lxcbr0" || name.starts_with("br-") {
        // Container/Linux bridges = LAN by default (containers get an
        // IP on these and need outbound).
        return PortRole::Lan;
    }
    if slaved { return PortRole::Lan; }
    // Heuristic: default-route interface = WAN. Cache avoided per-call
    // to keep this cheap.
    if name == crate::networking::detect_primary_interface() {
        return PortRole::Wan;
    }
    PortRole::Unused
}

/// Read the kernel's authoritative link state from sysfs. Returns
/// `Some(true)` if the carrier is up (cable plugged in / wireless
/// associated), `Some(false)` if down, `None` if the file isn't
/// readable (e.g. interface is administratively down so the kernel
/// refuses to evaluate carrier) — caller should fall back.
fn read_carrier(iface: &str) -> Option<bool> {
    std::fs::read_to_string(format!("/sys/class/net/{}/carrier", iface))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map(|n| n == 1)
}

fn read_speed_mbps(iface: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{}/speed", iface))
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&n| n > 0)
        .map(|n| n as u32)
}

fn run_json(args: &[&str]) -> String {
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|| "[]".into())
}

/// Derive logical links (wires) from a list of per-node topologies.
/// Rendered as curved SVG paths in the rack view.
pub fn derive_links(nodes: &[NodeTopology]) -> Vec<TopologyLink> {
    let mut links = Vec::new();

    for node in nodes {
        // Every up port with a WAN role connects to the Upstream "cloud".
        for port in &node.interfaces {
            if port.role == PortRole::Wan && port.link_up {
                links.push(TopologyLink {
                    from: EndpointRef::Port { node: node.node_id.clone(), iface: port.name.clone() },
                    to: EndpointRef::Upstream,
                    kind: LinkKind::Physical,
                    bps_live: Some(port.rx_bps + port.tx_bps),
                });
            }
            // Ports slaved to a bridge connect to that bridge.
            if let Some(master) = &port.master {
                links.push(TopologyLink {
                    from: EndpointRef::Port { node: node.node_id.clone(), iface: port.name.clone() },
                    to: EndpointRef::Bridge { node: node.node_id.clone(), name: master.clone() },
                    kind: LinkKind::Physical,
                    bps_live: Some(port.rx_bps + port.tx_bps),
                });
            }
        }

        // VMs attached to WolfNet → Wolfnet endpoint.
        for vm in &node.vms {
            let to = if vm.attached_to == "wolfnet" {
                EndpointRef::Wolfnet
            } else {
                // Attached to a named interface/bridge.
                EndpointRef::Bridge { node: node.node_id.clone(), name: vm.attached_to.clone() }
            };
            links.push(TopologyLink {
                from: EndpointRef::Vm { node: node.node_id.clone(), name: vm.name.clone() },
                to,
                kind: if vm.attached_to == "wolfnet" { LinkKind::Wolfnet } else { LinkKind::Tap },
                bps_live: None,
            });
        }

        for ct in &node.containers {
            links.push(TopologyLink {
                from: EndpointRef::Container { node: node.node_id.clone(), name: ct.name.clone() },
                to: EndpointRef::Bridge { node: node.node_id.clone(), name: ct.attached_to.clone() },
                kind: LinkKind::Veth,
                bps_live: None,
            });
        }
    }

    // Cross-node WolfNet mesh edge — L2 fix: emit ONE logical edge
    // representing the WolfNet cloud (the rack view renders it as a
    // shaded cloud, not per-pair wires). Pre-fix the nested loop
    // emitted N*(N-1)/2 IDENTICAL `Wolfnet→Wolfnet` links (both
    // endpoints had no node identifier) — the inner `let _ = (i, j)`
    // discarded the loop indices and the misleading "Break early"
    // comment suggested it stopped after one iteration; it didn't.
    // The frontend deduplicated visually but the payload was N²-bloated.
    if nodes.len() > 1 {
        links.push(TopologyLink {
            from: EndpointRef::Wolfnet,
            to: EndpointRef::Wolfnet,
            kind: LinkKind::Wolfnet,
            bps_live: None,
        });
    }

    links
}
