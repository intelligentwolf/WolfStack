// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Wake-on-LAN — machines an operator can power on from the dashboard.
//!
//! A magic packet is a layer-2 broadcast, so it only reaches a machine
//! on the same LAN segment as the sender. Targets are therefore stored
//! on the node that sends them (`/etc/wolfstack/wol-targets.json` on
//! each node, never replicated): the node that holds the target IS the
//! node on that machine's LAN. The cluster Wake-on-LAN page lists every
//! node's targets through the node proxy, and the Wake button is sent
//! by the node that owns the target. That is what makes waking a
//! machine at home work from anywhere the dashboard is reachable.
//!
//! No replication means no replication bugs: a delete cannot come back
//! from a peer (see the WolfRun tombstone saga), and a target cannot be
//! sent from a node on the wrong network.

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

/// One machine that can be woken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolTarget {
    pub id: String,
    pub name: String,
    /// Canonical `aa:bb:cc:dd:ee:ff` form. Stored canonical so the UI
    /// and duplicate check never compare `AA-BB-…` against `aa:bb:…`.
    pub mac: String,
    /// Optional directed-broadcast address (e.g. `192.168.1.255`).
    /// Empty = send on every network this node is on; see
    /// `destinations`.
    #[serde(default)]
    pub broadcast: String,
    /// UDP port. The magic packet is recognised anywhere in the frame,
    /// so the port only matters to routers/firewalls in between; 9
    /// (discard) is the conventional choice, 7 (echo) the other one.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Optional IP or hostname pinged to show whether the machine is
    /// up. Empty = no status shown.
    #[serde(default)]
    pub host: String,
}

fn default_port() -> u16 { 9 }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WolConfig {
    #[serde(default)]
    pub targets: Vec<WolTarget>,
}

/// Fields the operator supplies when creating or editing a target.
#[derive(Debug, Clone, Deserialize)]
pub struct WolTargetInput {
    pub name: String,
    pub mac: String,
    #[serde(default)]
    pub broadcast: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub host: String,
}

fn config_path() -> String { crate::paths::get().wol_targets_config }

/// Serialises load-modify-save so two operators editing the same node
/// at once (two tabs, or a proxied call racing a local one) cannot
/// silently drop each other's change. Only ever taken inside
/// spawn_blocking and never held across an await.
static WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Per-node ceiling. Bounds the file and the parallel pings behind
/// GET /api/wol/status, which any logged-in viewer can poll.
const MAX_TARGETS: usize = 256;

fn write_lock() -> std::sync::MutexGuard<'static, ()> {
    // A panic mid-save leaves nothing half-applied worth refusing over:
    // the file is replaced atomically, so recover the guard.
    WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn load() -> WolConfig {
    match std::fs::read_to_string(config_path()) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
            tracing::warn!("wol: {} parse failed ({}) — starting empty", config_path(), e);
            WolConfig::default()
        }),
        Err(_) => WolConfig::default(),
    }
}

fn save(cfg: &WolConfig) -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(cfg)
        .map_err(|e| format!("serialize wake-on-lan targets: {}", e))?;
    // Atomic write — a crash mid-write must not lose every target.
    let tmp = format!("{}.tmp", path);
    std::fs::write(&tmp, &json).map_err(|e| format!("write {}: {}", tmp, e))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename {}: {}", tmp, e))?;
    Ok(())
}

/// Parse a MAC address in any of the common spellings:
/// `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff` (Cisco)
/// or bare `aabbccddeeff`. Returns the six bytes.
pub fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let hex: String = s.trim().chars().filter(|c| !matches!(c, ':' | '-' | '.')).collect();
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "'{}' is not a MAC address — expected six hex pairs, e.g. 3c:7c:3f:12:ab:cd",
            s.trim()
        ));
    }
    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("'{}' is not a MAC address", s.trim()))?;
    }
    if mac == [0u8; 6] || mac == [0xffu8; 6] {
        return Err("that is not a network card's address (all zeros / all ones)".into());
    }
    // Bit 0 of the first octet is the IEEE 802 group bit: set = a
    // multicast address, which no network card is burned in with.
    if mac[0] & 0x01 != 0 {
        return Err(format!(
            "{} is a multicast address — use the machine's own network card MAC",
            format_mac(&mac)
        ));
    }
    Ok(mac)
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}

/// Build the magic packet: 6 bytes of 0xFF followed by the target MAC
/// repeated 16 times — 102 bytes. Source: AMD "Magic Packet Technology"
/// white paper (publication 20213, 1995), the definition every WoL NIC
/// implements.
pub fn magic_packet(mac: &[u8; 6]) -> [u8; 102] {
    let mut pkt = [0xffu8; 102];
    for rep in 0..16 {
        pkt[6 + rep * 6..12 + rep * 6].copy_from_slice(mac);
    }
    pkt
}

/// Validate operator input and turn it into a stored target. `id` is
/// the existing id on edit, or None to mint one.
pub fn build_target(input: &WolTargetInput, id: Option<String>) -> Result<WolTarget, String> {
    let name = input.name.trim();
    if name.is_empty() {
        return Err("name is required".into());
    }
    if name.chars().count() > 80 {
        return Err("name must be 80 characters or fewer".into());
    }
    let mac = format_mac(&parse_mac(&input.mac)?);
    let broadcast = input.broadcast.trim().to_string();
    if !broadcast.is_empty() {
        let ip: Ipv4Addr = broadcast.parse().map_err(|_| format!(
            "broadcast address '{}' is not an IPv4 address — e.g. 192.168.1.255, or leave it blank",
            broadcast
        ))?;
        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
            return Err(format!("{} cannot be used as a broadcast address", ip));
        }
    }
    let port = input.port.unwrap_or(9);
    if port == 0 {
        return Err("port must be between 1 and 65535".into());
    }
    let host = input.host.trim().to_string();
    if !host.is_empty() && !valid_host(&host) {
        return Err(format!(
            "'{}' is not an IP address or hostname — used only to show whether the machine is up",
            host
        ));
    }
    Ok(WolTarget {
        id: id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        name: name.to_string(),
        mac,
        broadcast,
        port,
        host,
    })
}

/// An IP literal or a hostname. `ping` is exec'd without a shell, but a
/// value starting with `-` would still be read as an option, so the
/// hostname branch only admits letters, digits, dots, hyphens and
/// underscores (valid in /etc/hosts and container names) and never a
/// leading hyphen.
fn valid_host(h: &str) -> bool {
    if h.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    h.len() <= 253
        && !h.starts_with('-')
        && !h.starts_with('.')
        && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

pub fn add(input: &WolTargetInput) -> Result<WolTarget, String> {
    let target = build_target(input, None)?;
    let _guard = write_lock();
    let mut cfg = load();
    if cfg.targets.len() >= MAX_TARGETS {
        return Err(format!("this node already has the maximum of {} machines", MAX_TARGETS));
    }
    if let Some(dup) = cfg.targets.iter().find(|t| t.mac == target.mac) {
        return Err(format!("{} is already listed on this node as '{}'", target.mac, dup.name));
    }
    cfg.targets.push(target.clone());
    save(&cfg)?;
    Ok(target)
}

pub fn update(id: &str, input: &WolTargetInput) -> Result<WolTarget, String> {
    let target = build_target(input, Some(id.to_string()))?;
    let _guard = write_lock();
    let mut cfg = load();
    if let Some(dup) = cfg.targets.iter().find(|t| t.mac == target.mac && t.id != id) {
        return Err(format!("{} is already listed on this node as '{}'", target.mac, dup.name));
    }
    let slot = cfg.targets.iter_mut().find(|t| t.id == id)
        .ok_or_else(|| "target not found".to_string())?;
    *slot = target.clone();
    save(&cfg)?;
    Ok(target)
}

/// Returns the removed target so the caller can log what went.
pub fn remove(id: &str) -> Result<WolTarget, String> {
    let _guard = write_lock();
    let mut cfg = load();
    let pos = cfg.targets.iter().position(|t| t.id == id)
        .ok_or_else(|| "target not found".to_string())?;
    let removed = cfg.targets.remove(pos);
    save(&cfg)?;
    Ok(removed)
}

/// Where the magic packet goes. With an explicit broadcast address,
/// only there. Otherwise the kernel-reported broadcast address of every
/// up IPv4 interface on this node (from `ip -j -4 addr show up`; point-
/// to-point links such as WolfNet and Tailscale report none and are
/// skipped), plus the limited broadcast 255.255.255.255. The limited
/// broadcast alone leaves only through the default-route interface, so
/// on a host whose LAN is not the default route — a second NIC, a
/// Proxmox bridge — the directed broadcasts are what actually reach it.
fn destinations(target: &WolTarget) -> Vec<Ipv4Addr> {
    if let Ok(ip) = target.broadcast.parse::<Ipv4Addr>() {
        return vec![ip];
    }
    let mut out = interface_broadcasts();
    if !out.contains(&Ipv4Addr::BROADCAST) {
        out.push(Ipv4Addr::BROADCAST);
    }
    out
}

fn interface_broadcasts() -> Vec<Ipv4Addr> {
    let output = match std::process::Command::new("ip")
        .args(["-j", "-4", "addr", "show", "up"])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    let entries: Vec<serde_json::Value> = serde_json::from_slice(&output).unwrap_or_default();
    let mut out = Vec::new();
    for entry in &entries {
        if entry["ifname"].as_str() == Some("lo") { continue; }
        let Some(addrs) = entry["addr_info"].as_array() else { continue };
        for a in addrs {
            if let Some(ip) = a["broadcast"].as_str().and_then(|s| s.parse::<Ipv4Addr>().ok())
                && !out.contains(&ip)
            {
                out.push(ip);
            }
        }
    }
    out
}

/// Outcome of one wake, returned to the UI.
#[derive(Debug, Serialize)]
pub struct WakeResult {
    pub mac: String,
    pub port: u16,
    /// Broadcast addresses the packet was handed to the kernel for.
    pub sent_to: Vec<String>,
    /// Destinations the kernel refused, with the reason.
    pub failed: Vec<String>,
}

/// Send the magic packet for `target`. Blocking (socket + `ip`) — call
/// from a blocking context. Succeeds if at least one destination took
/// the packet. A magic packet is fire-and-forget: success means the
/// packet left this node, not that the machine woke — the status ping
/// is what confirms that.
pub fn wake(target: &WolTarget) -> Result<WakeResult, String> {
    let mac = parse_mac(&target.mac)?;
    let packet = magic_packet(&mac);
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|e| format!("could not open a UDP socket: {}", e))?;
    socket.set_broadcast(true)
        .map_err(|e| format!("could not enable broadcast on the UDP socket: {}", e))?;
    let mut sent_to = Vec::new();
    let mut failed = Vec::new();
    for dest in destinations(target) {
        // Three copies: UDP has no retransmit and a switch that is
        // still learning, or a NIC in a deep sleep state, can miss one.
        // Extra copies are harmless — the machine is either waking or awake.
        let mut last_err = None;
        let mut ok = false;
        for _ in 0..3 {
            match socket.send_to(&packet, SocketAddrV4::new(dest, target.port)) {
                Ok(_) => ok = true,
                Err(e) => last_err = Some(e.to_string()),
            }
        }
        if ok {
            sent_to.push(dest.to_string());
        } else {
            failed.push(format!("{}: {}", dest, last_err.unwrap_or_default()));
        }
    }
    if sent_to.is_empty() {
        return Err(format!(
            "the magic packet could not be sent from this node ({})",
            if failed.is_empty() { "no network to send on".to_string() } else { failed.join("; ") }
        ));
    }
    Ok(WakeResult { mac: target.mac.clone(), port: target.port, sent_to, failed })
}

/// Whether the target answers a ping from this node. None = no host
/// configured. One echo, one-second wait: the page polls, so a slow
/// answer is simply caught on the next round.
pub async fn is_up(target: &WolTarget) -> Option<bool> {
    if target.host.is_empty() || !valid_host(&target.host) {
        return None;
    }
    let out = tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", &target.host])
        .output()
        .await;
    Some(matches!(out, Ok(o) if o.status.success()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_common_mac_spelling() {
        let want = [0x3c, 0x7c, 0x3f, 0x12, 0xab, 0xcd];
        for s in ["3c:7c:3f:12:ab:cd", "3C-7C-3F-12-AB-CD", "3c7c.3f12.abcd", "3c7c3f12abcd", " 3c:7c:3f:12:ab:cd "] {
            assert_eq!(parse_mac(s).unwrap(), want, "{}", s);
        }
    }

    #[test]
    fn rejects_non_nic_macs() {
        for s in ["", "3c:7c:3f:12:ab", "3c:7c:3f:12:ab:cd:ef", "zz:7c:3f:12:ab:cd",
                  "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01"] {
            assert!(parse_mac(s).is_err(), "{} should be rejected", s);
        }
    }

    #[test]
    fn magic_packet_layout() {
        let mac = [1u8 << 1, 2, 3, 4, 5, 6];
        let p = magic_packet(&mac);
        assert_eq!(p.len(), 102);
        assert_eq!(&p[..6], &[0xff; 6]);
        for rep in 0..16 {
            assert_eq!(&p[6 + rep * 6..12 + rep * 6], &mac);
        }
    }

    #[test]
    fn build_target_normalises_and_validates() {
        let input = WolTargetInput {
            name: "  GPU box ".into(),
            mac: "3C-7C-3F-12-AB-CD".into(),
            broadcast: "".into(),
            port: None,
            host: "192.168.1.50".into(),
        };
        let t = build_target(&input, None).unwrap();
        assert_eq!(t.name, "GPU box");
        assert_eq!(t.mac, "3c:7c:3f:12:ab:cd");
        assert_eq!(t.port, 9);

        let bad_host = WolTargetInput { host: "-f".into(), ..input.clone() };
        assert!(build_target(&bad_host, None).is_err());
        let bad_bcast = WolTargetInput { broadcast: "192.168.1".into(), ..input.clone() };
        assert!(build_target(&bad_bcast, None).is_err());
        let zero_port = WolTargetInput { port: Some(0), ..input.clone() };
        assert!(build_target(&zero_port, None).is_err());
        let no_name = WolTargetInput { name: "  ".into(), ..input };
        assert!(build_target(&no_name, None).is_err());
    }

    #[test]
    fn explicit_broadcast_is_the_only_destination() {
        let t = WolTarget {
            id: "x".into(), name: "x".into(), mac: "3c:7c:3f:12:ab:cd".into(),
            broadcast: "192.168.1.255".into(), port: 9, host: String::new(),
        };
        assert_eq!(destinations(&t), vec![Ipv4Addr::new(192, 168, 1, 255)]);
    }
}
