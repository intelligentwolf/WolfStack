// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Networking — System network interface and VLAN management
//!
//! Provides read/write access to:
//! - Network interfaces (ip link/addr)
//! - VLANs (802.1Q)
//! - DNS configuration
//! - WolfNet overlay status
//! - WireGuard bridge (VPN access to WolfNet from external clients)

use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{info, warn};

pub mod lan_bridge;
pub mod nic_addr;
pub mod link_persist;
pub mod router;
pub mod vlan;
pub mod vlan_attach;

/// Network interface info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub mac: String,
    pub state: String,         // up, down, unknown
    pub mtu: u32,
    pub addresses: Vec<InterfaceAddress>,
    pub is_vlan: bool,
    pub vlan_id: Option<u32>,
    pub parent: Option<String>, // parent interface for VLANs
    pub speed: Option<String>,  // link speed (1000Mb/s etc)
    pub driver: Option<String>,
}

/// IP address on an interface
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceAddress {
    pub address: String,   // e.g. 192.168.1.10
    pub prefix: u32,       // e.g. 24
    pub family: String,    // inet or inet6
    pub scope: String,     // global, link, host
}

/// DNS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub nameservers: Vec<String>,
    pub search_domains: Vec<String>,
    pub method: String,       // how DNS is managed: "systemd-resolved", "networkmanager", "netplan", "resolv.conf"
    pub editable: bool,       // whether we can edit DNS
}

/// Which DNS management method is active
#[derive(Debug, Clone, PartialEq)]
enum DnsMethod {
    SystemdResolved, // Ubuntu 18+, some Debian, Fedora 33+
    NetworkManager,  // Fedora, RHEL, CentOS, IBM Power (RHEL)
    Netplan,         // Ubuntu 18+ server (configures systemd-resolved or NM)
    ResolvConf,      // Direct /etc/resolv.conf (Debian, older systems, IBM Power SLES)
}

impl DnsMethod {
    fn as_str(&self) -> &'static str {
        match self {
            DnsMethod::SystemdResolved => "systemd-resolved",
            DnsMethod::NetworkManager => "networkmanager",
            DnsMethod::Netplan => "netplan",
            DnsMethod::ResolvConf => "resolv.conf",
        }
    }
}

/// Detect how this system manages DNS
fn detect_dns_method() -> DnsMethod {
    // 1. Check for netplan (Ubuntu server)
    if std::path::Path::new("/etc/netplan").exists() {
        let has_files = std::fs::read_dir("/etc/netplan")
            .map(|entries| entries.filter_map(|e| e.ok())
                .any(|e| e.path().extension().is_some_and(|ext| ext == "yaml" || ext == "yml")))
            .unwrap_or(false);
        if has_files {
            return DnsMethod::Netplan;
        }
    }

    // 2. Check for NetworkManager FIRST — on Fedora/RHEL, both NM and
    //    systemd-resolved are active, but NM is the actual DNS manager.
    //    systemd-resolved is just a stub resolver forwarding to NM's DNS.
    if Command::new("systemctl")
        .args(["is-active", "NetworkManager"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false)
    {
        return DnsMethod::NetworkManager;
    }

    // 3. Check for systemd-resolved (standalone, without NM)
    if Command::new("systemctl")
        .args(["is-active", "systemd-resolved"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false)
    {
        return DnsMethod::SystemdResolved;
    }

    // 4. Fallback: direct resolv.conf
    DnsMethod::ResolvConf
}

/// Get DNS configuration — reads from the correct source for the detected method
pub fn get_dns() -> DnsConfig {
    let method = detect_dns_method();
    let mut nameservers = Vec::new();
    let mut search_domains = Vec::new();

    // Read effective DNS — resolvectl for systemd-resolved/netplan, resolv.conf for others
    match method {
        DnsMethod::SystemdResolved | DnsMethod::Netplan => {
            // Netplan on Ubuntu typically uses systemd-resolved as its backend,
            // so /etc/resolv.conf shows 127.0.0.53 (the stub listener) — not useful.
            // Use resolvectl to get the actual configured nameservers.
            if let Ok(out) = Command::new("resolvectl").arg("status").output() {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    let line = line.trim();
                    if line.starts_with("DNS Servers:") || line.starts_with("DNS Server:") {
                        let servers = line.split_once(':').map(|x| x.1).unwrap_or("").trim();
                        for s in servers.split_whitespace() {
                            if !s.is_empty() && !nameservers.contains(&s.to_string()) {
                                nameservers.push(s.to_string());
                            }
                        }
                    }
                    if line.starts_with("DNS Domain:") {
                        let domains = line.split_once(':').map(|x| x.1).unwrap_or("").trim();
                        for d in domains.split_whitespace() {
                            if !d.is_empty() && !search_domains.contains(&d.to_string()) {
                                search_domains.push(d.to_string());
                            }
                        }
                    }
                }
            }

            // If resolvectl gave nothing, try reading the WolfStack override file
            if nameservers.is_empty() && method == DnsMethod::Netplan {
                let override_path = "/etc/netplan/99-wolfstack-dns.yaml";
                if let Ok(content) = std::fs::read_to_string(override_path) {
                    // Simple YAML parsing: extract addresses: [...] and search: [...]
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("addresses:") {
                            let bracket_part = trimmed.trim_start_matches("addresses:").trim();
                            let inner = bracket_part.trim_start_matches('[').trim_end_matches(']');
                            for addr in inner.split(',') {
                                let addr = addr.trim().trim_matches('"').trim();
                                if !addr.is_empty() && !nameservers.contains(&addr.to_string()) {
                                    nameservers.push(addr.to_string());
                                }
                            }
                        }
                        if trimmed.starts_with("search:") {
                            let bracket_part = trimmed.trim_start_matches("search:").trim();
                            let inner = bracket_part.trim_start_matches('[').trim_end_matches(']');
                            for domain in inner.split(',') {
                                let domain = domain.trim().trim_matches('"').trim();
                                if !domain.is_empty() && !search_domains.contains(&domain.to_string()) {
                                    search_domains.push(domain.to_string());
                                }
                            }
                        }
                    }
                }
            }

            // Final fallback: resolv.conf (filter out 127.0.0.53 stub)
            if nameservers.is_empty() {
                read_resolv_conf(&mut nameservers, &mut search_domains);
                nameservers.retain(|ns| ns != "127.0.0.53");
            }
        }
        DnsMethod::NetworkManager => {
            // On RHEL/Fedora/IBM Power, read DNS from the primary NM connection
            // (ethernet or wifi), not from ALL devices which includes Tailscale etc.
            if let Some(conn_name) = find_primary_nm_connection()
                && let Ok(out) = Command::new("nmcli")
                    .args(["-t", "-f", "IP4.DNS,IP4.DOMAIN", "connection", "show", &conn_name])
                    .output()
                {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines() {
                        let line = line.trim();
                        if line.starts_with("IP4.DNS")
                            && let Some(dns) = line.split_once(':').map(|x| x.1) {
                                let dns = dns.trim();
                                if !dns.is_empty() && !nameservers.contains(&dns.to_string()) {
                                    nameservers.push(dns.to_string());
                                }
                            }
                        if line.starts_with("IP4.DOMAIN")
                            && let Some(domain) = line.split_once(':').map(|x| x.1) {
                                let domain = domain.trim();
                                if !domain.is_empty() && !search_domains.contains(&domain.to_string()) {
                                    search_domains.push(domain.to_string());
                                }
                            }
                    }
                }
            // Fallback to resolv.conf if nmcli gave nothing
            if nameservers.is_empty() {
                read_resolv_conf(&mut nameservers, &mut search_domains);
                nameservers.retain(|ns| ns != "127.0.0.53");
            }
        }
        DnsMethod::ResolvConf => {
            read_resolv_conf(&mut nameservers, &mut search_domains);
        }
    }

    DnsConfig {
        nameservers,
        search_domains,
        method: method.as_str().to_string(),
        editable: true,
    }
}

/// Parse /etc/resolv.conf
/// Strip a resolv.conf comment and return the remaining text.
///
/// resolv.conf(5) starts a comment at `#` or `;`. Unraid writes them on the
/// nameserver line — `nameserver 10.10.1.250  # eth0:v4`.
fn strip_resolv_comment(value: &str) -> &str {
    value.split(['#', ';']).next().unwrap_or("")
}

/// The directive's value, if `line` is that directive.
///
/// Requires whitespace after the keyword so `nameserver` doesn't also match a
/// hypothetical `nameservers`, and avoids the byte-slicing the old code did
/// (which would panic on a multi-byte character in the line).
fn resolv_directive<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(keyword)?;
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    Some(rest.trim())
}

/// Parse one `nameserver` value.
///
/// Returns None for anything that is not an address. The old code took the
/// whole rest of the line, so on Unraid the nameserver became the literal
/// string `10.10.1.250  # eth0:v4`, which was handed to `docker --dns` (JJ's
/// failed install, 2026-07-27) and written into /etc/docker/daemon.json.
/// Validating here keeps junk out of every consumer at once.
fn parse_nameserver(value: &str) -> Option<String> {
    let token = strip_resolv_comment(value).split_whitespace().next()?;
    // A link-local address may carry a zone (fe80::1%eth0). Validate the
    // address part; keep the zone, which the resolver needs.
    token.split('%').next()?.parse::<std::net::IpAddr>().ok()?;
    Some(token.to_string())
}

fn read_resolv_conf(nameservers: &mut Vec<String>, search_domains: &mut Vec<String>) {
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if let Some(ns) = resolv_directive(line, "nameserver").and_then(parse_nameserver) {
                if !nameservers.contains(&ns) {
                    nameservers.push(ns);
                }
            } else if let Some(value) = resolv_directive(line, "search") {
                *search_domains = strip_resolv_comment(value)
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
            }
        }
    }
}

/// Set DNS nameservers and search domains — writes to the correct config
pub fn set_dns(nameservers: Vec<String>, search_domains: Vec<String>) -> Result<String, String> {
    let method = detect_dns_method();


    match method {
        DnsMethod::Netplan => set_dns_netplan(&nameservers, &search_domains),
        DnsMethod::SystemdResolved => set_dns_systemd_resolved(&nameservers, &search_domains),
        DnsMethod::NetworkManager => set_dns_networkmanager(&nameservers, &search_domains),
        DnsMethod::ResolvConf => set_dns_resolv_conf(&nameservers, &search_domains),
    }
}

/// Set DNS via netplan (Ubuntu server)
fn set_dns_netplan(nameservers: &[String], search_domains: &[String]) -> Result<String, String> {
    // Find existing netplan config
    let netplan_dir = "/etc/netplan";
    let files: Vec<_> = std::fs::read_dir(netplan_dir)
        .map_err(|e| format!("Cannot read {}: {}", netplan_dir, e))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.ends_with(".yaml") || name.ends_with(".yml")
        })
        .collect();

    if files.is_empty() {
        return Err("No netplan config files found".to_string());
    }

    // Read the first config file
    let config_path = files[0].path();
    let _content = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Cannot read {}: {}", config_path.display(), e))?;

    // Simple YAML manipulation: find the nameservers block and update it
    // For safety, use a WolfStack-specific override file instead
    let override_path = format!("{}/99-wolfstack-dns.yaml", netplan_dir);

    // Detect the primary ethernet interface
    let primary_iface = detect_primary_interface();

    let mut yaml = String::from("# Managed by WolfStack — DNS configuration\nnetwork:\n  version: 2\n  ethernets:\n");
    yaml.push_str(&format!("    {}:\n", primary_iface));
    yaml.push_str("      nameservers:\n");
    yaml.push_str(&format!("        addresses: [{}]\n",
        nameservers.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(", ")));
    if !search_domains.is_empty() {
        yaml.push_str(&format!("        search: [{}]\n",
            search_domains.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(", ")));
    }

    std::fs::write(&override_path, &yaml)
        .map_err(|e| format!("Cannot write {}: {}", override_path, e))?;

    // Apply netplan
    let output = Command::new("netplan")
        .arg("apply")
        .output()
        .map_err(|e| format!("Failed to run netplan apply: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        // Clean up on failure
        let _ = std::fs::remove_file(&override_path);
        return Err(format!("netplan apply failed: {}", stderr));
    }


    Ok("DNS updated via netplan".to_string())
}

/// Set DNS via systemd-resolved
fn set_dns_systemd_resolved(nameservers: &[String], search_domains: &[String]) -> Result<String, String> {
    // Write a resolved.conf drop-in
    let dropin_dir = "/etc/systemd/resolved.conf.d";
    std::fs::create_dir_all(dropin_dir)
        .map_err(|e| format!("Cannot create {}: {}", dropin_dir, e))?;

    let dropin_path = format!("{}/wolfstack-dns.conf", dropin_dir);
    let mut conf = String::from("# Managed by WolfStack\n[Resolve]\n");
    if !nameservers.is_empty() {
        conf.push_str(&format!("DNS={}\n", nameservers.join(" ")));
    }
    if !search_domains.is_empty() {
        conf.push_str(&format!("Domains={}\n", search_domains.join(" ")));
    }
    conf.push_str("DNSStubListener=yes\n");

    std::fs::write(&dropin_path, &conf)
        .map_err(|e| format!("Cannot write {}: {}", dropin_path, e))?;

    // Restart systemd-resolved
    let output = Command::new("systemctl")
        .args(["restart", "systemd-resolved"])
        .output()
        .map_err(|e| format!("Failed to restart resolved: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }


    Ok("DNS updated via systemd-resolved".to_string())
}

/// Ensure NetworkManager has a persistent config to ignore WolfStack/WolfNet interfaces.
/// Writes /etc/NetworkManager/conf.d/wolfstack.conf and reloads NM if the file is new.
fn ensure_nm_unmanaged() {
    // Only act if NetworkManager conf.d directory exists (NM is installed)
    if !std::path::Path::new("/etc/NetworkManager/conf.d").is_dir() {
        return;
    }
    let conf_path = "/etc/NetworkManager/conf.d/wolfstack.conf";
    // The WG interface name includes the cluster name which may be mixed-case
    // (e.g. "wg-WolfStack"), so use the broad "wg-*" pattern. Re-write if an
    // older version with the narrow pattern exists.
    let content = "\
# WolfStack: prevent NetworkManager from managing overlay/tunnel interfaces.
# These are managed by WolfStack/WolfNet and NM interference causes routing
# problems on desktop systems (especially Fedora with WiFi).
[keyfile]
unmanaged-devices=interface-name:wg-*;interface-name:wolfnet*
";
    let needs_write = match std::fs::read_to_string(conf_path) {
        Ok(existing) => existing != content,
        Err(_) => true,
    };
    if needs_write
        && std::fs::write(conf_path, content).is_ok() {
            let _ = Command::new("nmcli").args(["general", "reload"]).output();
        }
}

/// Find the primary NetworkManager connection (ethernet or wifi)
fn find_primary_nm_connection() -> Option<String> {
    let output = Command::new("nmcli")
        .args(["-t", "-f", "NAME,DEVICE,TYPE", "connection", "show", "--active"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Prefer ethernet, then wifi — skip tun/bridge/loopback
    let primary_types = ["802-3-ethernet", "ethernet", "802-11-wireless", "wifi"];
    for ptype in &primary_types {
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && parts[2] == *ptype {
                return Some(parts[0].to_string());
            }
        }
    }
    None
}

/// Set DNS via NetworkManager (Fedora, RHEL, IBM Power RHEL)
fn set_dns_networkmanager(nameservers: &[String], search_domains: &[String]) -> Result<String, String> {
    // Find the primary active connection (ethernet or wifi)
    let conn_name = find_primary_nm_connection()
        .ok_or_else(|| "No active NetworkManager ethernet/wifi connection found".to_string())?;

    // Set DNS via nmcli
    let dns_str = nameservers.join(" ");
    let dns_search_str = search_domains.join(" ");

    let output = Command::new("nmcli")
        .args(["connection", "modify", &conn_name,
              "ipv4.dns", &dns_str,
              "ipv4.dns-search", &dns_search_str])
        .output()
        .map_err(|e| format!("nmcli modify failed: {}", e))?;

    if !output.status.success() {
        return Err(format!("nmcli modify failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Reload connection
    let _ = Command::new("nmcli")
        .args(["connection", "up", &conn_name])
        .output();


    Ok(format!("DNS updated via NetworkManager (connection: {})", conn_name))
}

/// Set DNS via direct /etc/resolv.conf (Debian, IBM Power SLES, older systems)
fn set_dns_resolv_conf(nameservers: &[String], search_domains: &[String]) -> Result<String, String> {
    // Check if resolv.conf is a symlink (managed by another tool)
    let resolv_path = std::path::Path::new("/etc/resolv.conf");
    if resolv_path.is_symlink() {
        // Read what it points to
        if let Ok(target) = std::fs::read_link(resolv_path) {
            let target_str = target.to_string_lossy();
            if target_str.contains("systemd") {
                return Err("Cannot edit /etc/resolv.conf: it's managed by systemd-resolved. Use resolvectl instead.".to_string());
            }
        }
    }

    // Preserve comments and non-nameserver/non-search lines
    let existing = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let mut output = String::new();

    // Keep comments and options
    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with("options ") {
            output.push_str(line);
            output.push('\n');
        }
    }

    // Add search domains
    if !search_domains.is_empty() {
        output.push_str(&format!("search {}\n", search_domains.join(" ")));
    }

    // Add nameservers
    for ns in nameservers {
        output.push_str(&format!("nameserver {}\n", ns));
    }

    std::fs::write("/etc/resolv.conf", &output)
        .map_err(|e| format!("Cannot write /etc/resolv.conf: {}", e))?;


    Ok("DNS updated via /etc/resolv.conf".to_string())
}

/// Detect primary network interface
pub fn detect_primary_interface() -> String {
    // Use `ip route` to find the default route interface
    if let Ok(out) = Command::new("ip").args(["route", "show", "default"]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(idx) = parts.iter().position(|&p| p == "dev")
                && let Some(iface) = parts.get(idx + 1) {
                    return iface.to_string();
                }
        }
    }
    "eth0".to_string()
}

/// WolfNet interface status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfNetStatus {
    pub installed: bool,
    pub running: bool,
    pub interface: Option<String>,  // tun interface name (e.g. wn0)
    pub ip: Option<String>,
    pub peers: Vec<WolfNetPeer>,
}

/// A WolfNet peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfNetPeer {
    pub name: String,
    pub endpoint: String,
    pub ip: String,
    pub connected: bool,
}

/// List all network interfaces with their addresses
pub fn list_interfaces() -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();

    // Use `ip -j addr show` for JSON output
    let output = Command::new("ip")
        .args(["-j", "addr", "show"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let json_str = String::from_utf8_lossy(&out.stdout);
            if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
                for entry in entries {
                    let name = entry["ifname"].as_str().unwrap_or("").to_string();
                    if name == "lo" { continue; } // skip loopback

                    let mac = entry["address"].as_str().unwrap_or("").to_string();
                    let state = entry["operstate"].as_str().unwrap_or("unknown").to_lowercase();
                    let mtu = entry["mtu"].as_u64().unwrap_or(1500) as u32;

                    // Parse addresses
                    let mut addresses = Vec::new();
                    if let Some(addr_info) = entry["addr_info"].as_array() {
                        for addr in addr_info {
                            let family = addr["family"].as_str().unwrap_or("").to_string();
                            let local = addr["local"].as_str().unwrap_or("").to_string();
                            let prefix = addr["prefixlen"].as_u64().unwrap_or(0) as u32;
                            let scope = addr["scope"].as_str().unwrap_or("").to_string();
                            if !local.is_empty() {
                                addresses.push(InterfaceAddress {
                                    address: local,
                                    prefix,
                                    family,
                                    scope,
                                });
                            }
                        }
                    }

                    // Check if it's a VLAN
                    let (is_vlan, vlan_id, parent) = detect_vlan(&name, &entry);

                    // Get speed
                    let speed = get_link_speed(&name);
                    let driver = get_driver(&name);

                    interfaces.push(NetworkInterface {
                        name,
                        mac,
                        state,
                        mtu,
                        addresses,
                        is_vlan,
                        vlan_id,
                        parent,
                        speed,
                        driver,
                    });
                }
            }
        }
        _ => {
            warn!("Failed to run `ip -j addr show`");
        }
    }

    interfaces
}

/// Detect if an interface is a VLAN
fn detect_vlan(name: &str, entry: &serde_json::Value) -> (bool, Option<u32>, Option<String>) {
    // Check link_info for VLAN
    if let Some(linkinfo) = entry.get("linkinfo")
        && let Some(info_kind) = linkinfo.get("info_kind").and_then(|v| v.as_str())
            && info_kind == "vlan" {
                let vlan_id = linkinfo.get("info_data")
                    .and_then(|d| d.get("id"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                let parent = entry.get("link").and_then(|v| v.as_str()).map(|s| s.to_string());
                return (true, vlan_id, parent);
            }

    // Fallback: check if name contains a dot (e.g. eth0.100)
    if let Some(dot_pos) = name.rfind('.')
        && let Ok(vid) = name[dot_pos + 1..].parse::<u32>() {
            let parent = name[..dot_pos].to_string();
            return (true, Some(vid), Some(parent));
        }

    (false, None, None)
}

/// Get link speed for an interface
fn get_link_speed(name: &str) -> Option<String> {
    let path = format!("/sys/class/net/{}/speed", name);
    std::fs::read_to_string(&path).ok()
        .and_then(|s| format_link_speed(s.trim().parse::<i64>().ok()?))
}

/// sysfs speed (Mb/s) → display string. Integer division would show a
/// 2.5GbE NIC (sysfs 2500) as "2Gb/s" — RutgerDiehard, 2026-08-18 — so
/// non-whole gigabit rates keep their fraction.
fn format_link_speed(speed: i64) -> Option<String> {
    if speed <= 0 { return None; }
    if speed < 1000 {
        Some(format!("{}Mb/s", speed))
    } else if speed % 1000 == 0 {
        Some(format!("{}Gb/s", speed / 1000))
    } else {
        Some(format!("{}Gb/s", speed as f64 / 1000.0))
    }
}

/// Get driver for an interface
fn get_driver(name: &str) -> Option<String> {
    let path = format!("/sys/class/net/{}/device/driver", name);
    std::fs::read_link(&path).ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()))
}

/// Resolve the absolute path to `systemctl`. A WolfStack process started
/// with a stripped PATH (some systemd unit setups, minimal containers) hits
/// ENOENT — "No such file or directory" — on `Command::new("systemctl")`
/// even though systemd is perfectly present; that's exactly what surfaced as
/// "Failed to stop wolfnet: No such file or directory" for a sponsor. Search
/// PATH first (honours a custom install), then the standard absolute
/// locations. `None` means this genuinely isn't a systemd host.
fn systemctl_bin() -> Option<String> {
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':').filter(|d| !d.is_empty()) {
            let cand = format!("{}/systemctl", dir);
            if std::path::Path::new(&cand).exists() {
                return Some(cand);
            }
        }
    }
    for cand in ["/usr/bin/systemctl", "/bin/systemctl", "/usr/sbin/systemctl", "/sbin/systemctl"] {
        if std::path::Path::new(cand).exists() {
            return Some(cand.to_string());
        }
    }
    None
}

/// Get WolfNet status
pub fn get_wolfnet_status() -> WolfNetStatus {
    let not_installed = || WolfNetStatus {
        installed: false,
        running: false,
        interface: None,
        ip: None,
        peers: Vec::new(),
    };
    let (installed, running) = if crate::installer::unraid_tools::is_unraid() {
        // Unraid has no systemd: the agent bundles and supervises the
        // daemon itself (installer::unraid_tools), so ask the supervisor.
        // Before this the page said "Not Installed" on every Unraid node
        // while the daemon was running (klas, 2026-09-10).
        crate::installer::unraid_tools::wolfnet_state()
    } else {
        // No systemd on this host → WolfNet service can't exist here.
        let Some(systemctl) = systemctl_bin() else { return not_installed(); };

        // Check if wolfnet service exists
        let installed = Command::new(&systemctl)
            .args(["cat", "wolfnet"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let running = installed
            && Command::new(&systemctl)
                .args(["is-active", "wolfnet"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
                .unwrap_or(false);
        (installed, running)
    };

    if !installed {
        return not_installed();
    }

    // Try to get WolfNet IP from the tun interface
    let mut wn_interface = None;
    let mut wn_ip = None;
    let interfaces = list_interfaces();
    for iface in &interfaces {
        if iface.name.starts_with("wn") || iface.name.starts_with("wolfnet") {
            wn_interface = Some(iface.name.clone());
            if let Some(addr) = iface.addresses.iter().find(|a| a.family == "inet") {
                wn_ip = Some(format!("{}/{}", addr.address, addr.prefix));
            }
            break;
        }
    }

    // Try to parse peers from wolfnet config
    let peers = get_wolfnet_peers();

    WolfNetStatus {
        installed,
        running,
        interface: wn_interface,
        ip: wn_ip,
        peers,
    }
}

/// Read WolfNet peers from config.toml
pub fn get_wolfnet_peers_list() -> Vec<WolfNetPeer> {
    get_wolfnet_peers()
}

fn get_wolfnet_peers() -> Vec<WolfNetPeer> {
    let config_path = "/etc/wolfnet/config.toml";
    let mut peers = Vec::new();

    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(_) => return peers,
    };

    // Simple TOML parsing for [[peers]] sections
    let mut current_name = String::new();
    let mut current_endpoint = String::new();
    let mut current_ip = String::new();
    let mut in_peer = false;

    for line in content.lines() {
        let line = line.trim();
        if line == "[[peers]]" {
            if in_peer && !current_name.is_empty() {
                peers.push(WolfNetPeer {
                    name: current_name.clone(),
                    endpoint: current_endpoint.clone(),
                    ip: current_ip.clone(),
                    connected: false,
                });
            }
            in_peer = true;
            current_name.clear();
            current_endpoint.clear();
            current_ip.clear();
        } else if in_peer {
            if let Some(val) = line.strip_prefix("name") {
                let val = val.trim().trim_start_matches('=').trim().trim_matches('"');
                current_name = val.to_string();
            } else if let Some(val) = line.strip_prefix("endpoint") {
                let val = val.trim().trim_start_matches('=').trim().trim_matches('"');
                current_endpoint = val.to_string();
            } else if let Some(val) = line.strip_prefix("allowed_ip").or_else(|| line.strip_prefix("ip")) {
                let val = val.trim().trim_start_matches('=').trim().trim_matches('"');
                current_ip = val.to_string();
            }
        }
    }
    // Push last peer
    if in_peer && !current_name.is_empty() {
        peers.push(WolfNetPeer {
            name: current_name,
            endpoint: current_endpoint,
            ip: current_ip,
            connected: false,
        });
    }

    // Check connectivity via ping (non-blocking, fast)
    for peer in &mut peers {
        if !peer.ip.is_empty() {
            let ip = peer.ip.split('/').next().unwrap_or(&peer.ip);
            peer.connected = Command::new("ping")
                .args(["-c", "1", "-W", "1", ip])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
        }
    }

    peers
}

/// Read the raw WolfNet config file
pub fn get_wolfnet_config() -> Result<String, String> {
    std::fs::read_to_string("/etc/wolfnet/config.toml")
        .map_err(|e| format!("Failed to read WolfNet config: {}", e))
}

/// Get local WolfNet node info (public key, address, port) from runtime status
pub fn get_wolfnet_local_info() -> Option<serde_json::Value> {
    let status_path = "/var/run/wolfnet/status.json";
    let content = std::fs::read_to_string(status_path).ok()?;
    let status: serde_json::Value = serde_json::from_str(&content).ok()?;
    // Current configured peers (name + allowed_ip). Lets the cluster sync
    // prune entries that don't belong to this node's cluster, and lets
    // diagnostics report a node's real peer count instead of guessing from
    // the bastion's own peer list.
    let peers: Vec<serde_json::Value> = get_wolfnet_peers_list().into_iter()
        .map(|p| {
            let ip = p.ip.split('/').next().unwrap_or(&p.ip).to_string();
            serde_json::json!({ "name": p.name, "ip": ip })
        })
        .collect();
    Some(serde_json::json!({
        "hostname": status["hostname"],
        "address": status["address"],
        "public_key": status["public_key"],
        "listen_port": status["listen_port"],
        "interface": status["interface"],
        "peers": peers,
    }))
}

/// Atomic + backup write of `/etc/wolfnet/config.toml`. Every code
/// path that updates the WolfNet config goes through here.
///
/// Three guarantees on top of a plain `fs::write`:
///   1. **No empty replaces.** If the caller hands us a blank or
///      whitespace-only payload we refuse the write outright. A
///      truncated payload that survives serialisation but is missing
///      the [network]/[security] sections also fails the load-check
///      below, so the original file stays intact. klasSponsor
///      2026-05-28 reported `config.toml` being wiped after a port
///      edit on one node — wolfnet then exited on next start because
///      it had no config to load. This check makes that class of
///      regression impossible regardless of which call site is at
///      fault.
///   2. **`config.toml.bak` snapshot before every replace.** Always
///      written when the on-disk file is non-empty. Manual recovery
///      becomes `cp config.toml.bak config.toml`, and the wolfnet
///      daemon also picks it up automatically (see wolfnet's
///      `Config::load_from_file`).
///   3. **Atomic rename**, not in-place truncate. A crash partway
///      through the write can no longer leave the live config
///      truncated/empty — the previous file remains visible until
///      the rename completes.
fn write_wolfnet_config_atomic(content: &str) -> Result<(), String> {
    const PATH: &str = "/etc/wolfnet/config.toml";
    const TMP: &str = "/etc/wolfnet/config.toml.tmp";
    const BAK: &str = "/etc/wolfnet/config.toml.bak";

    if content.trim().is_empty() {
        return Err(
            "Refusing to write empty WolfNet config (would brick the daemon). \
             Existing config left untouched.".to_string(),
        );
    }

    // Sanity-check: a real wolfnet config always carries at least
    // [network] and [security] sections. Anything missing both is a
    // tell-tale of a serialisation bug upstream — fail fast rather
    // than overwrite a working file with garbage.
    if !content.contains("[network]") || !content.contains("[security]") {
        return Err(
            "Refusing to write WolfNet config missing [network]/[security] sections. \
             Existing config left untouched.".to_string(),
        );
    }

    // Make sure /etc/wolfnet exists — write to .tmp first.
    if let Some(parent) = std::path::Path::new(PATH).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(TMP, content)
        .map_err(|e| format!("Failed to stage WolfNet config at {}: {}", TMP, e))?;

    // Snapshot the previous good config to .bak — best-effort: an
    // absent .bak isn't fatal, but we want a recovery copy after
    // every successful replace.
    if std::path::Path::new(PATH).exists() {
        let _ = std::fs::copy(PATH, BAK);
    }

    // Atomic rename — POSIX guarantees this is either fully visible
    // or fully not.
    std::fs::rename(TMP, PATH).map_err(|e| {
        format!(
            "Failed to install new {} (staged copy left at {}): {}",
            PATH, TMP, e
        )
    })?;

    Ok(())
}

/// Save the raw WolfNet config file
pub fn save_wolfnet_config(content: &str) -> Result<String, String> {
    write_wolfnet_config_atomic(content)?;
    Ok("Configuration saved".to_string())
}

/// What `add_wolfnet_peer` should do with the endpoint field on an
/// existing peer. Three states, because empty-string-means-X is too
/// ambiguous: the manual "Add Peer" form wants to preserve whatever
/// endpoint is already there if the user leaves the field blank, while
/// the cluster-sync code wants to ACTIVELY WIPE a stale endpoint when
/// the target can't reach the peer's static address (roaming-only).
#[derive(Debug, Clone)]
pub enum PeerEndpoint {
    /// Set or update the endpoint to this string.
    Set(String),
    /// Remove the endpoint field entirely — roaming-only.
    Clear,
    /// Leave whatever endpoint the existing peer has (or none, for new).
    Preserve,
}

/// Serialises every `add_wolfnet_peer` invocation so concurrent
/// reconciler / gossip-arrival / manual-API paths can't race on the
/// `/etc/wolfnet/config.toml` read-modify-write cycle. 22.14.7 shipped
/// without this and on klasSponsor's 14-node cluster Hook B fired
/// per-peer in parallel — concurrent writes could lose updates and
/// leave the TOML half-written, which would make wolfnet refuse to
/// start. The mutex is process-local; cross-process safety isn't
/// needed because only one WolfStack instance touches the file.
static WOLFNET_CONFIG_WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Compute a node's effective site tag for cluster-sync endpoint
/// selection. Used by `pick_wolfnet_endpoint` to decide whether two
/// nodes can dial each other at their LAN address (same site) or
/// must go via the public IP (different sites).
///
/// Rules:
/// * If the operator declared an explicit `site` string, that wins.
/// * Otherwise, auto-derive from the first three octets of `address`
///   when `address` is an RFC1918 IPv4 literal. Two nodes that share
///   a /24 get the same auto-tag (`auto:192.168.10`) and are treated
///   as same-LAN — this preserves pre-Site behaviour for single-LAN
///   clusters without any operator action.
/// * For public IPv4 / IPv6 / unparseable / empty addresses, return
///   `None` — there's no LAN context to infer, so the node will
///   match no one on auto-tag and the cluster-sync will route via
///   the public path.
///
/// The auto-tag is namespaced with the `auto:` prefix so operators
/// can't accidentally type a value that collides with an
/// auto-derived one (e.g. `192.168.10`); explicit tags never carry
/// that prefix.
pub fn effective_site(site: &Option<String>, address: &str) -> Option<String> {
    if let Some(s) = site.as_ref()
        && !s.is_empty() {
            return Some(s.clone());
        }
    let ip: std::net::Ipv4Addr = match address.parse() {
        Ok(ip) => ip,
        Err(_) => return None,
    };
    // Narrow to true RFC1918 — loopback (127/8) and link-local
    // (169.254/16) are not meaningful site anchors even though
    // `is_private_ip` calls them private. JS `autoSiteHint` applies
    // the same narrow check so the UI hint matches the Rust value
    // exactly.
    let oct = ip.octets();
    let rfc1918 = oct[0] == 10
        || (oct[0] == 172 && (16..=31).contains(&oct[1]))
        || (oct[0] == 192 && oct[1] == 168);
    if !rfc1918 {
        return None;
    }
    Some(format!("auto:{}.{}.{}", oct[0], oct[1], oct[2]))
}

/// Read the local wolfnet `(address, prefix_length)` from
/// `/etc/wolfnet/config.toml`. Used by `decide_peer_endpoint` to
/// detect the routing-loop case where a peer's `public_ip` lands
/// inside our own wolfnet subnet — see `decide_peer_endpoint` guard #2
/// for the failure mode. Returns `None` when the config is missing or
/// the `address`/`subnet` fields are malformed (callers treat that as
/// "don't apply the subnet guard"; the other guards still fire).
pub fn get_local_wolfnet_subnet() -> Option<(std::net::Ipv4Addr, u8)> {
    let content = std::fs::read_to_string("/etc/wolfnet/config.toml").ok()?;
    let doc: toml::Value = toml::from_str(&content).ok()?;
    let net = doc.get("network")?;
    let addr: std::net::Ipv4Addr = net.get("address")?.as_str()?.parse().ok()?;
    // Default to /24 if the field is missing or out of range — wolfnet's
    // own default is /24, so the assumption is safe in practice.
    let prefix: u8 = net.get("subnet")
        .and_then(|v| v.as_integer())
        .and_then(|i| u8::try_from(i).ok())
        .filter(|p| *p <= 32)
        .unwrap_or(24);
    Some((addr, prefix))
}

/// Does `ip` fall inside the subnet `(net_addr, prefix)`?
fn is_in_subnet(ip: std::net::Ipv4Addr, net_addr: std::net::Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 { return true; }
    if prefix > 32 { return false; }
    let ip_u32 = u32::from(ip);
    let net_u32 = u32::from(net_addr);
    let mask: u32 = (!0u32).checked_shl(32 - prefix as u32).unwrap_or(0);
    (ip_u32 & mask) == (net_u32 & mask)
}

/// Decide the endpoint to write for a peer, given everything we know.
/// Pure function — pulled out of `reconcile_local_wolfnet_endpoint_if_needed`
/// and `pick_wolfnet_endpoint` so the safety guards are unit-testable
/// without touching the filesystem, and so both the auto-reconciler
/// path AND the manual-sync path apply the same logic.
///
/// Guards (in order, all default to `Clear` for safety):
///   1. No public_ip → roaming-only. Peer's keepalive will let wolfnet
///      learn the source address on first arrival.
///   2. public_ip inside our wolfnet subnet → kernel routing loop.
///      The catastrophic klasSponsor 2026-05-11 case: unifios's
///      wolfstack agent reported `10.100.10.1` (its own WolfNet IP)
///      as its public_ip; 22.14.7 wrote `10.100.10.1:9634` as the
///      endpoint, kernel routed wolfnet's outgoing UDP back through
///      wolfnet0, wolfnet re-encapsulated, repeat → 17 MB/s outbound
///      black-hole.
///   3. public_ip equals our own address → self-loop.
///   4. public_ip is loopback or link-local → never a valid endpoint.
///   5. peer.lan_address differs from peer.public_ip → peer is behind
///      NAT. Set is fragile (requires either NAT source-port
///      preservation or a manually configured port-forward on the
///      same port wolfnet listens on, neither guaranteed); Clear is
///      robust (roaming-only via the source address+port the peer
///      actually initiated from, kept alive by NAT's flow mapping).
///   Otherwise → Set to `public_ip:peer_port`.
pub fn decide_peer_endpoint(
    self_lan_address: &str,
    self_wolfnet_subnet: Option<(std::net::Ipv4Addr, u8)>,
    peer_lan_address: Option<&str>,
    peer_public_ip: Option<&str>,
    peer_port: u16,
) -> PeerEndpoint {
    // 1. No public IP → roaming-only.
    let pip_str = match peer_public_ip.filter(|s| !s.is_empty()) {
        Some(p) => p,
        None => return PeerEndpoint::Clear,
    };

    // The remaining guards only apply to IPv4 literals — wolfnet config
    // also accepts hostnames as endpoints (resolve_endpoint handles
    // both), and we don't second-guess those.
    let pip = match pip_str.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => ip,
        Err(_) => return PeerEndpoint::Set(format!("{}:{}", pip_str, peer_port)),
    };

    // 2. WolfNet subnet loop — most important guard (the klasSponsor
    //    flood). Must check before self-loop because for a peer with
    //    `public_ip == self_lan_address` the self-loop branch would
    //    also trigger, but the loop guard logs the more specific
    //    cause.
    if let Some((net_addr, prefix)) = self_wolfnet_subnet
        && is_in_subnet(pip, net_addr, prefix) {
            return PeerEndpoint::Clear;
        }

    // 3. Self-loop.
    if let Ok(self_ip) = self_lan_address.parse::<std::net::Ipv4Addr>()
        && pip == self_ip { return PeerEndpoint::Clear; }

    // 4. Loopback / link-local.
    if pip.is_loopback() {
        return PeerEndpoint::Clear;
    }
    let oct = pip.octets();
    if oct[0] == 169 && oct[1] == 254 {
        return PeerEndpoint::Clear;
    }

    // 5. Behind-NAT.
    if let Some(plan) = peer_lan_address
        && let Ok(plan_ip) = plan.parse::<std::net::Ipv4Addr>()
            && plan_ip != pip {
                return PeerEndpoint::Clear;
            }

    PeerEndpoint::Set(format!("{}:{}", pip, peer_port))
}

/// Subnets this node is directly attached to via a NON-WolfNet interface.
/// An endpoint inside one of these is reachable on-link, even when the cluster
/// classifies this node's own address as public. The WolfNet overlay is
/// excluded — a match there would be the routing loop that `decide_peer_endpoint`
/// guard #2 exists to prevent. One `list_interfaces()` call; the caller computes
/// this once per reconcile pass and reuses it.
fn local_lan_subnets(self_wolfnet_subnet: Option<(std::net::Ipv4Addr, u8)>) -> Vec<(std::net::Ipv4Addr, u8)> {
    let mut out = Vec::new();
    for iface in list_interfaces() {
        for addr in &iface.addresses {
            if addr.family != "inet" || addr.scope != "global" { continue; }
            let ip = match addr.address.parse::<std::net::Ipv4Addr>() {
                Ok(i) => i,
                Err(_) => continue,
            };
            if let Some((wn_net, wn_prefix)) = self_wolfnet_subnet
                && is_in_subnet(ip, wn_net, wn_prefix)
            {
                continue;
            }
            out.push((ip, addr.prefix as u8));
        }
    }
    out
}

/// True if `target` sits on one of `subnets` — i.e. reachable on-link from
/// this node without routing through the overlay.
fn is_on_link(target: std::net::Ipv4Addr, subnets: &[(std::net::Ipv4Addr, u8)]) -> bool {
    subnets.iter().any(|&(net, prefix)| is_in_subnet(target, net, prefix))
}

/// Friendly error for a failed read of `/etc/wolfnet/config.toml`. A missing
/// file (`NotFound`) means WolfNet simply isn't set up on this node. The
/// cluster-sync sweep surfaces this verbatim as e.g. `nginx → docker: ...`,
/// where `nginx` is the NODE NAME, not the web server — so the old bare
/// "Failed to read config: ... (os error 2)" was misread as a missing *nginx*
/// config file (wabil 2026-06-17). Say plainly what's actually missing.
fn missing_wolfnet_config_msg(e: std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::NotFound {
        "WolfNet is not configured on this node (/etc/wolfnet/config.toml is missing) — \
         run setup or 'Update WolfNet Connections' on this node to create it".to_string()
    } else {
        format!("Failed to read WolfNet config (/etc/wolfnet/config.toml): {}", e)
    }
}

/// Add or update a peer in WolfNet config (upsert).
/// If a peer with the same name, public key, or allowed IP already exists,
/// its name is updated and the endpoint is handled per `endpoint` (see
/// `PeerEndpoint` for the three modes). Otherwise a new peer is appended,
/// with the endpoint included only for `PeerEndpoint::Set`.
///
/// `PeerEndpoint::Clear` is what cluster-sync uses when an internet-only
/// node would otherwise be pinned to an unreachable RFC1918 endpoint —
/// without an active wipe, every SIGHUP re-pins the wrong address and
/// any roaming-learned update gets clobbered on the next tick.
pub fn add_wolfnet_peer(name: &str, endpoint: PeerEndpoint, ip: &str, public_key: Option<&str>) -> Result<String, String> {
    // Serialise concurrent callers (reconciler / sync / manual API). The
    // mutex is held for the whole read-modify-write-reload cycle so a
    // racing call can't observe a half-written TOML or clobber our edit.
    // Poisoning shouldn't happen here (no panics inside), but recover if
    // it does so we don't deadlock the cluster on a stray panic.
    let _guard = WOLFNET_CONFIG_WRITE_LOCK.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Normalise to a BARE address — WolfNet's config parser does a plain
    // `Ipv4Addr::parse` on allowed_ip (wolfnet/src/main.rs:489,945) and a
    // CIDR suffix like "/32" makes it log "Invalid peer IP" and skip the
    // peer. Strip any prefix here so no caller can write a form WolfNet
    // can't read, regardless of what it passes in.
    let ip = ip.split('/').next().unwrap_or(ip);
    let config_path = "/etc/wolfnet/config.toml";
    let content = std::fs::read_to_string(config_path)
        .map_err(missing_wolfnet_config_msg)?;

    // Fix any `ip = ` entries to `allowed_ip = ` before parsing
    let fixed: String = content.lines().map(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with("ip = ") && !trimmed.starts_with("ip_") {
            line.replace("ip = ", "allowed_ip = ")
        } else {
            line.to_string()
        }
    }).collect::<Vec<_>>().join("\n");

    let mut doc: toml::Value = toml::from_str(&fixed)
        .map_err(|e| format!("Failed to parse config: {}", e))?;

    // Self-peer guard: a node must never list its own WolfNet address as a
    // peer. Such an entry is logged by WolfNet as "Invalid peer IP" forever
    // and can wedge the route/peer reconcile into a per-tick rewrite loop.
    // JJ 2026-06-04: amd9 was being added as its own peer. `[network].address`
    // is this node's own WolfNet IP. The `is_some()` check stops a missing
    // address + unparseable `ip` (None == None) from matching.
    let self_wn_ip = doc.get("network")
        .and_then(|n| n.get("address"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok());
    if self_wn_ip.is_some() && ip.parse::<std::net::Ipv4Addr>().ok() == self_wn_ip {
        return Err(format!(
            "Refusing to add '{}' as a WolfNet peer: {} is this node's own \
             WolfNet address (self-peer)", name, ip));
    }

    let peers = doc.get_mut("peers")
        .and_then(|v| v.as_array_mut());

    // Find existing peer by name, public key, or IP
    let existing_idx = peers.as_ref().and_then(|arr| {
        arr.iter().position(|p| {
            // Match by name
            if let Some(pname) = p.get("name").and_then(|v| v.as_str())
                && pname == name { return true; }
            // Match by public key
            if let Some(pk) = public_key
                && !pk.is_empty()
                    && let Some(ppk) = p.get("public_key").and_then(|v| v.as_str())
                        && ppk == pk { return true; }
            // Match by IP — compare bare. `ip` is already normalised above;
            // an existing entry may still carry a legacy "/32" suffix, so
            // strip it here too or a bare add would miss the match and
            // append a duplicate peer.
            if !ip.is_empty()
                && let Some(pip) = p.get("allowed_ip").and_then(|v| v.as_str())
                    && pip.split('/').next().unwrap_or(pip) == ip { return true; }
            false
        })
    });

    let result_msg;

    if let Some(idx) = existing_idx {
        let peers_arr = doc.get_mut("peers").unwrap().as_array_mut().unwrap();
        let peer = &mut peers_arr[idx];
        let _old_name = peer.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let _old_endpoint = peer.get("endpoint").and_then(|v| v.as_str()).unwrap_or("").to_string();

        let mut changed = false;
        if peer.get("name").and_then(|v| v.as_str()) != Some(name) {
            peer.as_table_mut().unwrap().insert("name".to_string(), toml::Value::String(name.to_string()));
            changed = true;
        }
        // Track whether we wiped an endpoint that was actually present —
        // if so, fall back to a full wolfnet restart instead of SIGHUP.
        // Pre-0.5.22 wolfnet's SIGHUP handler only honours the "Some(ep)"
        // branch and silently leaves a stale in-memory endpoint when the
        // config line vanishes (klasSponsor's symptom — the bad
        // `10.10.10.30` endpoint kept being dialed even after WolfStack
        // rewrote the config without it). A cold restart re-reads the
        // config from scratch and the cleared peer comes up roaming-only
        // as intended. New wolfnet handles SIGHUP correctly so this is
        // belt-and-braces for mixed-version clusters.
        let mut cleared_endpoint = false;
        match &endpoint {
            PeerEndpoint::Set(s) if !s.is_empty() => {
                if peer.get("endpoint").and_then(|v| v.as_str()) != Some(s.as_str()) {
                    peer.as_table_mut().unwrap().insert("endpoint".to_string(), toml::Value::String(s.clone()));
                    changed = true;
                }
            }
            PeerEndpoint::Set(_) | PeerEndpoint::Preserve => {
                // Set("") is treated as Preserve — historically callers used
                // empty string to mean "no change", and we honour that here
                // so a stray empty payload from a script doesn't wipe a good
                // endpoint by accident.
            }
            PeerEndpoint::Clear => {
                if peer.as_table_mut().unwrap().remove("endpoint").is_some() {
                    changed = true;
                    cleared_endpoint = true;
                }
            }
        }

        if !changed {
            return Err(format!("Peer '{}' already exists (no changes needed)", name));
        }

        // Write back, then either SIGHUP or full restart depending on
        // whether we cleared an endpoint (see above).
        let output = toml::to_string_pretty(&doc)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        write_wolfnet_config_atomic(&output)?;
        if cleared_endpoint {
            restart_wolfnet();
        } else {
            reload_or_restart_wolfnet();
        }

        return Ok(format!("Peer '{}' updated and WolfNet {}", name,
            if cleared_endpoint { "restarted" } else { "reloaded" }));
    } else {
        // Add new peer
        let mut new_peer = toml::map::Map::new();
        new_peer.insert("name".to_string(), toml::Value::String(name.to_string()));
        if let Some(pk) = public_key
            && !pk.is_empty() {
                new_peer.insert("public_key".to_string(), toml::Value::String(pk.to_string()));
            }
        if let PeerEndpoint::Set(s) = &endpoint
            && !s.is_empty() {
                new_peer.insert("endpoint".to_string(), toml::Value::String(s.clone()));
            }
        if !ip.is_empty() {
            new_peer.insert("allowed_ip".to_string(), toml::Value::String(ip.to_string()));
        }

        if let Some(arr) = doc.get_mut("peers").and_then(|v| v.as_array_mut()) {
            arr.push(toml::Value::Table(new_peer));
        } else {
            doc.as_table_mut().unwrap().insert(
                "peers".to_string(),
                toml::Value::Array(vec![toml::Value::Table(new_peer)]),
            );
        }


        result_msg = format!("Peer '{}' added and WolfNet restarted", name);

        // An explicit add overrides a stale tombstone — e.g. a node moved
        // out of another cluster and into this one. Without this the peer
        // stays tombstoned and the endpoint reconciler would skip it.
        let _ = wolfnet_tombstone_remove(name);
    }

    // Write back
    let output = toml::to_string_pretty(&doc)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    write_wolfnet_config_atomic(&output)?;

    // Apply config: try SIGHUP hot-reload, fall back to restart for older wolfnet
    reload_or_restart_wolfnet();

    Ok(result_msg)
}

/// Edit an existing WolfNet peer, located by its current name.
///
/// Unlike `add_wolfnet_peer` (an upsert whose "empty endpoint = preserve"
/// rule protects scripted callers), edit is WYSIWYG — the operator submits the
/// full desired state from the Edit modal, so `PeerEndpoint::Clear` means "the
/// endpoint field was emptied, make this peer roaming/auto-discovery" and
/// `PeerEndpoint::Set` pins it. `public_key` is changed only when a non-empty
/// value is supplied (blank = keep current) so a name/IP/endpoint correction
/// doesn't force the operator to re-paste the key.
///
/// Returns Err if no peer matches `old_name`: edit operates on *configured*
/// peers. Pinning a PEX-discovered/relay peer is done via Add (it needs the
/// peer's key, which a relay entry doesn't carry locally).
pub fn edit_wolfnet_peer(
    old_name: &str,
    new_name: &str,
    ip: &str,
    endpoint: PeerEndpoint,
    public_key: Option<&str>,
) -> Result<String, String> {
    // Same lock as add/remove/reconcile — the whole read-modify-write-reload
    // cycle is serialised so a racing reconcile can't clobber the edit.
    let _guard = WOLFNET_CONFIG_WRITE_LOCK.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Normalise to a BARE address — WolfNet rejects a CIDR suffix on allowed_ip
    // (same reason as add_wolfnet_peer).
    let ip = ip.split('/').next().unwrap_or(ip);
    let config_path = "/etc/wolfnet/config.toml";
    let content = std::fs::read_to_string(config_path)
        .map_err(missing_wolfnet_config_msg)?;

    // Fix any legacy `ip = ` entries to `allowed_ip = ` before parsing.
    let fixed: String = content.lines().map(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with("ip = ") && !trimmed.starts_with("ip_") {
            line.replace("ip = ", "allowed_ip = ")
        } else {
            line.to_string()
        }
    }).collect::<Vec<_>>().join("\n");

    let mut doc: toml::Value = toml::from_str(&fixed)
        .map_err(|e| format!("Failed to parse config: {}", e))?;

    // Self-peer guard: never let an edit point a peer at this node's own
    // WolfNet address — WolfNet logs such an entry as "Invalid peer IP" forever
    // (mirrors add_wolfnet_peer). Computed before the mutable borrow below.
    let self_wn_ip = doc.get("network")
        .and_then(|n| n.get("address"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok());
    if !ip.is_empty()
        && self_wn_ip.is_some()
        && ip.parse::<std::net::Ipv4Addr>().ok() == self_wn_ip
    {
        return Err(format!(
            "Refusing to set peer '{}' to {}: that is this node's own WolfNet \
             address (self-peer)", new_name, ip));
    }

    // Locate the peer by its CURRENT name.
    let idx = doc.get("peers")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.iter().position(|p| {
            p.get("name").and_then(|v| v.as_str()) == Some(old_name)
        }));
    let idx = match idx {
        Some(i) => i,
        None => return Err(format!(
            "Peer '{}' not found in WolfNet config (a discovered/relay peer is \
             pinned via Add, not Edit)", old_name)),
    };

    let peers_arr = doc.get_mut("peers").unwrap().as_array_mut().unwrap();
    let peer = peers_arr[idx].as_table_mut()
        .ok_or_else(|| "Malformed peer entry in config".to_string())?;

    let mut cleared_endpoint = false;

    peer.insert("name".to_string(), toml::Value::String(new_name.to_string()));

    // allowed_ip — only when provided; an empty ip means "leave as-is".
    if !ip.is_empty() {
        peer.insert("allowed_ip".to_string(), toml::Value::String(ip.to_string()));
        peer.remove("ip"); // drop any legacy key that could shadow it
    }

    // public_key — only overwrite when a non-empty value is supplied.
    if let Some(pk) = public_key.filter(|s| !s.is_empty()) {
        peer.insert("public_key".to_string(), toml::Value::String(pk.to_string()));
    }

    // endpoint — WYSIWYG.
    match &endpoint {
        PeerEndpoint::Set(s) if !s.is_empty() => {
            peer.insert("endpoint".to_string(), toml::Value::String(s.clone()));
        }
        PeerEndpoint::Clear => {
            if peer.remove("endpoint").is_some() {
                cleared_endpoint = true;
            }
        }
        // Set("") / Preserve: leave the endpoint untouched.
        PeerEndpoint::Set(_) | PeerEndpoint::Preserve => {}
    }

    // A rename can strand a tombstone under either name and make the endpoint
    // reconciler skip the peer — clear both so an explicit edit always wins.
    if new_name != old_name {
        let _ = wolfnet_tombstone_remove(old_name);
    }
    let _ = wolfnet_tombstone_remove(new_name);

    let output = toml::to_string_pretty(&doc)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    write_wolfnet_config_atomic(&output)?;

    // Clearing an endpoint needs a cold restart on pre-0.5.22 daemons whose
    // SIGHUP handler leaves a stale in-memory endpoint when the config line
    // vanishes (same rationale as add_wolfnet_peer's cleared branch).
    if cleared_endpoint {
        restart_wolfnet();
    } else {
        reload_or_restart_wolfnet();
    }

    Ok(format!("Peer '{}' updated and WolfNet {}", new_name,
        if cleared_endpoint { "restarted" } else { "reloaded" }))
}

/// Auto-fix a single peer's endpoint in the local wolfnet config if it
/// matches a known-bad pattern that can't be reached from this node.
/// Returns `Some(msg)` when a fix was applied, `None` when nothing
/// needed doing — the common case for healthy configs, so this is cheap
/// to call from gossip arrival.
///
/// Trigger condition: this node sits on the public internet AND the
/// current configured endpoint resolves to an RFC1918 address that
/// can't be reached from a public-internet host. That's klasSponsor's
/// 2026-05-11 symptom — VPS's wolfnet config pinned `ninni` to
/// `10.10.10.30:9630`.
///
/// Desired-endpoint computation is delegated to `decide_peer_endpoint`
/// which applies five safety guards (wolfnet-subnet loop, self-loop,
/// loopback/link-local, behind-NAT, no-public-ip) — see that function
/// for the rationale. The key takeaway is that this reconciler is
/// CONSERVATIVE: it never "improves" a plausible entry, only repairs
/// a demonstrably-bad one, so a partially-converged cluster during a
/// rolling upgrade can't make things worse with stale gossip.
///
/// `self_lan_address` is the local node's externally-known address
/// (typically `Node.address`), used to classify self as public vs LAN
/// and to populate the self-loop guard. `peer_hostname` matches the
/// `name = "..."` field in the wolfnet config peer entry.
/// `peer_lan_address` and `peer_public_ip` come from cluster gossip
/// and drive the behind-NAT guard.
pub fn reconcile_local_wolfnet_endpoint_if_needed(
    self_lan_address: &str,
    peer_hostname: &str,
    peer_lan_address: Option<&str>,
    peer_public_ip: Option<&str>,
) -> Option<String> {
    // 0. Tombstone gate — if the operator explicitly removed this peer,
    //    don't touch its entry. Without this gate, the next Hook B
    //    gossip arrival would re-inject the peer's endpoint into the
    //    wolfnet config and override the operator's deliberate removal.
    if wolfnet_tombstone_contains(peer_hostname) {
        return None;
    }
    // 1. Bail if self is private — the bug pattern requires self-public.
    //    (And keeps LAN-only clusters out of this code entirely.)
    let self_addr: std::net::Ipv4Addr = self_lan_address.parse().ok()?;
    if is_private_ip(self_addr) { return None; }

    // 2. Read the wolfnet config. Missing/unparseable file → nothing to do.
    let config_path = "/etc/wolfnet/config.toml";
    let content = std::fs::read_to_string(config_path).ok()?;
    let doc: toml::Value = toml::from_str(&content).ok()?;
    let peers = doc.get("peers").and_then(|v| v.as_array())?;

    // 3. Locate the peer entry by hostname. Hostname is the stable key
    //    here — wolfnet IP can be reused after a rejoin and public_key
    //    isn't carried in gossip. Also capture the allowed_ip and
    //    public_key so we can hand them back to add_wolfnet_peer below;
    //    that way if the peer was concurrently removed between this
    //    read and the upsert (rare, but possible — operator hit Delete
    //    in the UI mid-tick), the upsert still constructs a valid
    //    `[[peers]]` entry instead of a name-only stub.
    let peer_entry = peers.iter().find(|p| {
        p.get("name").and_then(|v| v.as_str()) == Some(peer_hostname)
    })?;
    let current_endpoint = peer_entry.get("endpoint").and_then(|v| v.as_str())?;
    let existing_ip = peer_entry.get("allowed_ip").and_then(|v| v.as_str()).unwrap_or("");
    let existing_pk = peer_entry.get("public_key").and_then(|v| v.as_str());

    // 4. Extract the host portion. If it's not an RFC1918 IPv4 we have
    //    no evidence the entry is wrong — leave it alone.
    let host = endpoint_host(current_endpoint)?;
    let host_ip: std::net::Ipv4Addr = host.parse().ok()?;
    if !is_private_ip(host_ip) { return None; }

    // 4a. On-link guard. A dual-homed node — public in the cluster's eyes yet
    //     also sitting on the peer's LAN — can reach an RFC1918 endpoint
    //     directly. Never "repair" an endpoint that lives on a subnet this node
    //     has a real (non-WolfNet) interface on. klasSponsor 2026-06-08: hemulen
    //     (public cluster address) wiped ninni's 10.10.10.20:9620 endpoint even
    //     though both nodes are on the same home LAN, leaving ninni unreachable.
    if is_on_link(host_ip, &local_lan_subnets(get_local_wolfnet_subnet())) {
        return None;
    }

    // 5. Reuse the existing port (wolfnet listen ports vary per peer,
    //    e.g. 9600/9605/9630 in klas's cluster). If somehow malformed,
    //    fall back to the wolfnet default 9600.
    let port = current_endpoint.rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(9600);

    // 6. Compute the desired endpoint via the shared decision function
    //    so all the safety guards (wolfnet-subnet loop, behind-NAT,
    //    self-loop, loopback, no-public-ip) apply in one place.
    let new_endpoint = decide_peer_endpoint(
        self_lan_address,
        get_local_wolfnet_subnet(),
        peer_lan_address,
        peer_public_ip,
        port,
    );

    // 7. Apply. `add_wolfnet_peer` returns Err for "no changes needed"
    //    — we treat that as success (nothing to do this tick).
    match add_wolfnet_peer(peer_hostname, new_endpoint, existing_ip, existing_pk) {
        Ok(msg) => {
            tracing::info!(
                "WolfNet endpoint auto-fixed: peer '{}' had unreachable RFC1918 endpoint '{}', repaired",
                peer_hostname, current_endpoint
            );
            Some(msg)
        }
        Err(e) if e.contains("no changes needed") => None,
        Err(e) => {
            tracing::warn!(
                "WolfNet endpoint auto-fix for peer '{}' failed: {}",
                peer_hostname, e
            );
            None
        }
    }
}

/// A peer's identity from cluster gossip, fed to the batched reconciler
/// to drive endpoint decisions.
#[derive(Debug, Clone)]
pub struct ReconcileTarget {
    pub hostname: String,
    /// `Node.address` — the peer's externally-known address (usually
    /// LAN IP, but a public IP for internet-only peers).
    pub lan_address: Option<String>,
    /// `Node.public_ip` from gossip — what the peer detected as its own
    /// public IP via outbound probe.
    pub public_ip: Option<String>,
    /// The peer's authoritative WolfNet IP — its own live `wolfnet0`
    /// address as self-reported via cluster gossip
    /// (`crate::api::lookup_node_wolfnet_ip`). `None` until the peer has
    /// been polled at least once. Used to self-heal a stale/wrong
    /// `allowed_ip` in the local `/etc/wolfnet/config.toml`.
    pub wolfnet_ip: Option<String>,
}

/// Reconcile ALL peers in one pass — read config once, apply every
/// change in-memory, write once, reload/restart wolfnet ONCE.
///
/// Why this exists (klasSponsor 2026-05-11 incident analysis): in
/// 22.14.8 each per-peer reconciler call independently invoked
/// `add_wolfnet_peer`, which writes the config and either SIGHUPs or
/// runs `systemctl restart wolfnet`. On a cluster with N peers needing
/// a `Clear` (the behind-NAT case), Hook A's startup pass triggered N
/// rapid systemctl restarts. systemd's default
/// `StartLimitBurst=5/StartLimitIntervalSec=10` ate that cascade,
/// refused further starts, and wolfnet stayed dead — wolfstack's
/// auto-restart watchdog then logged "auto-restart failed" because the
/// service was rate-limited. Batching collapses N restarts to 1.
///
/// In addition to the cluster-known peers passed in, this function
/// scans the existing wolfnet config for ORPHAN peers — entries that
/// AREN'T wolfstack cluster members but whose configured endpoint is
/// inside our own wolfnet subnet (the klasSponsor unifios case: a
/// UniFi router that runs wolfnet but not wolfstack, with a stale
/// endpoint of `10.100.10.1:9634` pointed at its own WolfNet IP, which
/// creates the kernel routing loop). Those are wiped to roaming-only
/// so wolfnet stops sending self-encapsulated UDP into the void.
///
/// Returns the number of peer entries actually changed. `0` means no
/// reload was triggered. Errors are returned only for unrecoverable
/// I/O / parse failures — individual peer mismatches are skipped
/// silently (no peer entry → nothing to update for that peer).
pub fn reconcile_wolfnet_peers_batch(
    self_lan_address: &str,
    targets: &[ReconcileTarget],
) -> Result<usize, String> {
    let _guard = WOLFNET_CONFIG_WRITE_LOCK.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let config_path = "/etc/wolfnet/config.toml";
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        // No WolfNet config = nothing to reconcile. Return Ok(0) so the periodic
        // caller doesn't log an error every tick on nodes that don't run WolfNet.
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(missing_wolfnet_config_msg(e)),
    };
    let mut doc: toml::Value = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse config: {}", e))?;

    let wn_subnet = get_local_wolfnet_subnet();
    // Local LAN subnets, computed once for the on-link guard below (a peer
    // endpoint we can reach directly must not be cleared as "unreachable").
    let local_subnets = local_lan_subnets(wn_subnet);
    let tombstoned = load_wolfnet_tombstones();
    // Index targets by hostname for O(1) lookup as we walk the peers array.
    // Filter out tombstoned targets up-front so they're never considered for
    // (re-)application — operator removed = stay removed.
    let target_by_name: std::collections::HashMap<&str, &ReconcileTarget> =
        targets.iter()
            .filter(|t| !tombstoned.contains(&t.hostname))
            .map(|t| (t.hostname.as_str(), t))
            .collect();

    let mut changes = 0usize;
    let mut any_cleared = false;

    {
        let peers_arr = match doc.get_mut("peers").and_then(|v| v.as_array_mut()) {
            Some(p) => p,
            None => return Ok(0), // no peers section, nothing to do
        };

        // Self-peer removal. A node must NEVER list its own WolfNet address
        // in its own [[peers]] — WolfNet logs it as "Invalid peer IP" on
        // every reload and the entry perturbs the route/peer reconcile.
        // JJ 2026-06-04: amd9 had itself as a peer. Guarded on a parseable
        // local [network].address (the first element of `wn_subnet`) so a
        // missing/malformed address can never wipe legitimate peers.
        if let Some((self_wn_ip, _)) = wn_subnet {
            let before = peers_arr.len();
            peers_arr.retain(|p| {
                let allowed = p.get("allowed_ip").and_then(|v| v.as_str())
                    .or_else(|| p.get("ip").and_then(|v| v.as_str()))
                    .map(|s| s.split('/').next().unwrap_or(s));
                match allowed.and_then(|s| s.parse::<std::net::Ipv4Addr>().ok()) {
                    Some(a) => a != self_wn_ip,   // drop only an exact self-match
                    None => true,                 // no/unparseable IP — leave alone
                }
            });
            let removed = before - peers_arr.len();
            if removed > 0 {
                changes += removed;
                tracing::warn!(
                    "WolfNet self-heal: removed {} self-peer entr{} \
                     (own WolfNet address {} must never appear in [[peers]])",
                    removed, if removed == 1 { "y" } else { "ies" }, self_wn_ip
                );
            }
        }

        // Legacy "/32" normalisation. The v24.20.0 IP self-heal wrote
        // allowed_ip as "<ip>/32"; WolfNet rejects any CIDR suffix
        // (wolfnet/src/main.rs:489,945) and skips the peer. The drift-based
        // correction below only rewrites on an IP *change*, so a "/32" entry
        // whose stripped value is already correct would never be healed — it
        // would stay rejected on every reload forever. Strip the suffix here
        // so existing configs converge to bare addresses on the next tick.
        for peer in peers_arr.iter_mut() {
            let bare = match peer.get("allowed_ip").and_then(|v| v.as_str()) {
                Some(s) if s.contains('/') => Some(s.split('/').next().unwrap_or(s).to_string()),
                _ => None,
            };
            if let Some(bare) = bare
                && let Some(tbl) = peer.as_table_mut() {
                    tbl.insert("allowed_ip".to_string(), toml::Value::String(bare));
                    changes += 1;
                }
        }

        for peer in peers_arr.iter_mut() {
            let name = match peer.get("name").and_then(|v| v.as_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            // ── WolfNet IP self-heal ──
            // A peer is authoritative about its own WolfNet IP (it reports its
            // live wolfnet0 address). If our local config.toml has drifted —
            // e.g. stale addresses left by a past cross-cluster sync; the
            // klasSponsor 2026-06-04 case where a VPS showed peers as
            // 10.10.20.x instead of 10.100.10.x — converge the peer's
            // allowed_ip to that authoritative value. Two guards keep this
            // safe: only cluster-known, non-tombstoned peers are in
            // `target_by_name`, and we ONLY write an address that is inside
            // our own WolfNet subnet, so a stale out-of-mesh IP can never be
            // propagated back into the config.
            if let Some(target) = target_by_name.get(name.as_str())
                && let (Some(correct_ip), Some((net_addr, prefix))) =
                    (target.wolfnet_ip.as_deref(), wn_subnet)
                    && let Ok(correct_v4) = correct_ip.parse::<std::net::Ipv4Addr>() {
                        let current_ip = peer.get("allowed_ip").and_then(|v| v.as_str())
                            .or_else(|| peer.get("ip").and_then(|v| v.as_str()))
                            .map(|s| s.split('/').next().unwrap_or(s).to_string());
                        if is_in_subnet(correct_v4, net_addr, prefix)
                            && let Some(cur) = current_ip
                                && !cur.is_empty() && cur != correct_ip {
                                    if let Some(tbl) = peer.as_table_mut() {
                                        // Write a BARE address, no CIDR suffix.
                                        // WolfNet parses allowed_ip with a plain
                                        // `Ipv4Addr::parse` (wolfnet/src/main.rs:489,945)
                                        // which rejects "/32" — it then logs
                                        // "Invalid peer IP '<ip>/32'" and skips the
                                        // peer on every reload. JJ 2026-06-04: this
                                        // was dropping amd9's peers from the mesh.
                                        tbl.insert(
                                            "allowed_ip".to_string(),
                                            toml::Value::String(correct_ip.to_string()),
                                        );
                                        // Drop any legacy `ip` key so it can't
                                        // shadow the corrected allowed_ip.
                                        tbl.remove("ip");
                                    }
                                    changes += 1;
                                    tracing::warn!(
                                        "WolfNet IP self-heal: peer '{}' allowed_ip {} → {} \
                                         (was stale; converged to the peer's live WolfNet address)",
                                        name, cur, correct_ip
                                    );
                                }
                    }

            let current_endpoint = peer.get("endpoint")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            // Reuse the existing port if any; otherwise default to wolfnet's 9600.
            let port = current_endpoint.as_deref()
                .and_then(|e| e.rsplit_once(':'))
                .and_then(|(_, p)| p.parse::<u16>().ok())
                .unwrap_or(9600);

            // Decide what the endpoint SHOULD be. For cluster-known
            // peers, drive the decision via `decide_peer_endpoint` (full
            // 5-guard logic). For orphan peers (in wolfnet config but
            // not in cluster gossip), only act if the current endpoint
            // is loop-inducing — never "improve" an orphan beyond that.
            let decision: Option<PeerEndpoint> = if let Some(target) = target_by_name.get(name.as_str()) {
                let trigger_present = current_endpoint.as_deref()
                    .and_then(endpoint_host)
                    .and_then(|h| h.parse::<std::net::Ipv4Addr>().ok())
                    .map(is_private_ip)
                    .unwrap_or(false);
                let self_priv = self_lan_address.parse::<std::net::Ipv4Addr>()
                    .map(is_private_ip).unwrap_or(true);
                // The 22.14.8 reconciler only fires for public-self + RFC1918-endpoint.
                // Preserve that conservative gate here so LAN-only clusters aren't
                // disturbed by the batched pass.
                if !self_priv && trigger_present {
                    let d = decide_peer_endpoint(
                        self_lan_address, wn_subnet,
                        target.lan_address.as_deref(),
                        target.public_ip.as_deref(),
                        port,
                    );
                    // On-link guard (see reconcile_local_wolfnet_endpoint_if_needed):
                    // don't clear an RFC1918 endpoint this node can reach on a
                    // directly-attached interface. klasSponsor 2026-06-08.
                    let reachable_on_link = current_endpoint.as_deref()
                        .and_then(endpoint_host)
                        .and_then(|h| h.parse::<std::net::Ipv4Addr>().ok())
                        .map(|ip| is_on_link(ip, &local_subnets))
                        .unwrap_or(false);
                    if matches!(d, PeerEndpoint::Clear) && reachable_on_link {
                        None
                    } else {
                        Some(d)
                    }
                } else {
                    None
                }
            } else if let Some(eps) = current_endpoint.as_deref() {
                // Orphan peer — only act if its endpoint is inside our
                // own wolfnet subnet (klasSponsor unifios case).
                let loop_inducing = (|| {
                    let host = endpoint_host(eps)?;
                    let host_ip = host.parse::<std::net::Ipv4Addr>().ok()?;
                    let (net_addr, prefix) = wn_subnet?;
                    if is_in_subnet(host_ip, net_addr, prefix) { Some(()) } else { None }
                })().is_some();
                if loop_inducing {
                    Some(PeerEndpoint::Clear)
                } else {
                    None
                }
            } else {
                None
            };

            let decision = match decision {
                Some(d) => d,
                None => continue,
            };

            match decision {
                PeerEndpoint::Set(s) if !s.is_empty() => {
                    if current_endpoint.as_deref() != Some(s.as_str()) {
                        peer.as_table_mut().unwrap().insert(
                            "endpoint".to_string(),
                            toml::Value::String(s.clone()),
                        );
                        changes += 1;
                        tracing::info!(
                            "WolfNet endpoint batched reconcile: peer '{}' → {}",
                            name, s
                        );
                    }
                }
                PeerEndpoint::Set(_) | PeerEndpoint::Preserve => {}
                PeerEndpoint::Clear => {
                    if peer.as_table_mut().unwrap().remove("endpoint").is_some() {
                        changes += 1;
                        any_cleared = true;
                        tracing::warn!(
                            "WolfNet endpoint batched reconcile: peer '{}' cleared \
                             (was unreachable from this node; roaming-only)",
                            name
                        );
                    }
                }
            }
        }
    }

    if changes == 0 {
        return Ok(0);
    }

    // Write the whole updated config once.
    let output = toml::to_string_pretty(&doc)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    write_wolfnet_config_atomic(&output)?;

    // ONE reload/restart at the end. If any peer was cleared and we're
    // running against a pre-0.5.22 wolfnet whose SIGHUP handler doesn't
    // honour a vanished endpoint line, the restart belt is needed to
    // re-read the file from scratch. Otherwise SIGHUP is enough and
    // cheaper.
    if any_cleared {
        // Clear any cumulative systemd start-limit ban from prior
        // versions' restart-storms (klasSponsor 2026-05-11 — by the
        // time the operator upgrades, systemd may have refused
        // further starts after the cascade). Best-effort; the
        // restart below proceeds either way.
        let _ = Command::new("systemctl").args(["reset-failed", "wolfnet"]).output();
        restart_wolfnet();
    } else {
        reload_or_restart_wolfnet();
    }

    Ok(changes)
}

/// Remove a peer from WolfNet config by name
pub fn remove_wolfnet_peer(name: &str) -> Result<String, String> {
    let config_path = "/etc/wolfnet/config.toml";
    let content = std::fs::read_to_string(config_path)
        .map_err(missing_wolfnet_config_msg)?;

    let mut result_lines: Vec<String> = Vec::new();
    let mut in_target_peer = false;
    let mut found = false;
    let mut i = 0;
    let lines: Vec<&str> = content.lines().collect();

    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed == "[[peers]]" {
            // Check if the next few lines contain our target peer name
            let mut is_target = false;
            for j in (i + 1)..std::cmp::min(i + 10, lines.len()) {
                let check = lines[j].trim();
                if check.starts_with('[') && check != "[[peers]]" { break; }
                if check == "[[peers]]" { break; }
                if check.starts_with("name") {
                    let val = check.split('=').nth(1).unwrap_or("").trim().trim_matches('"');
                    if val == name {
                        is_target = true;
                        found = true;
                    }
                    break;
                }
            }
            if is_target {
                in_target_peer = true;
                // Skip blank lines before this [[peers]] block
                while result_lines.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
                    result_lines.pop();
                }
                i += 1;
                continue;
            }
        }

        if in_target_peer {
            if trimmed.starts_with('[') || (trimmed.is_empty() && i + 1 < lines.len() && lines[i + 1].trim().starts_with('[')) {
                in_target_peer = false;
                if !trimmed.is_empty() {
                    result_lines.push(lines[i].to_string());
                }
            }
            i += 1;
            continue;
        }

        result_lines.push(lines[i].to_string());
        i += 1;
    }

    if !found {
        return Err(format!("Peer '{}' not found in config", name));
    }

    let new_content = result_lines.join("\n");
    write_wolfnet_config_atomic(&new_content)?;



    // Mark this hostname as tombstoned so the gossip / auto-apply /
    // reconciler paths don't immediately re-inject it. Without this,
    // every 60s `auto_apply_missing_workload_routes` would re-create
    // subnet_routes through this peer from cluster gossip, and the
    // operator's "remove this peer" intent would be silently
    // overridden — klasSponsor 2026-05-12 hit this exactly.
    wolfnet_tombstone_add(name);

    // Apply config: try SIGHUP hot-reload, fall back to restart for older wolfnet
    reload_or_restart_wolfnet();

    Ok(format!("Peer '{}' removed and tombstoned; WolfNet reloaded", name))
}

// ─── WolfNet peer tombstones ────────────────────────────────────────
//
// Persistent record of peer hostnames the operator has explicitly
// removed. Any code path that auto-(re)injects peers — cluster-gossip
// reconciler (Hook A/B), `auto_apply_missing_workload_routes`,
// gossip-driven subnet-route auto-creation — consults this set and
// skips tombstoned peers.
//
// Why this exists: klasSponsor 2026-05-12 — he manually removed peers
// from `/etc/wolfnet/config.toml`, but every 60s `auto_apply_missing_
// workload_routes` re-created subnet_routes through them from cluster
// gossip, and packets continued to flow into a black hole at ~17 MB/s.
// The operator's intent was being silently overridden. The tombstone
// list is the operator's authoritative "no, really, stay removed"
// signal, persisted across daemon restarts so it survives upgrades.
//
// The list is hostname-keyed because that's what's stable across the
// wolfnet config (`name = "..."`), the cluster Node struct
// (`hostname`), and the subnet_route metadata. Wolfnet IPs can change
// after a rejoin; public keys aren't propagated to all paths.
//
// To un-tombstone (re-add a previously-removed peer) the operator
// calls the DELETE endpoint or removes the entry from the file by
// hand. The next gossip / auto-apply / sync will then re-add it
// normally.

const WOLFNET_TOMBSTONE_FILE: &str = "/etc/wolfstack/wolfnet-tombstones.json";

#[derive(serde::Serialize, serde::Deserialize, Default, Clone)]
struct WolfnetTombstones {
    /// Hostnames the operator has removed. Sorted for stable diffs.
    /// `#[serde(default)]` so an empty-ish file (e.g. `{}` from a
    /// truncated write) deserializes to an empty list rather than an
    /// error — we'd rather "no tombstones" than "couldn't read".
    #[serde(default)]
    hostnames: Vec<String>,
}

fn load_wolfnet_tombstones() -> std::collections::HashSet<String> {
    match std::fs::read_to_string(WOLFNET_TOMBSTONE_FILE) {
        Ok(s) => serde_json::from_str::<WolfnetTombstones>(&s)
            .map(|t| t.hostnames.into_iter().collect())
            .unwrap_or_default(),
        Err(_) => std::collections::HashSet::new(),
    }
}

fn save_wolfnet_tombstones(set: &std::collections::HashSet<String>) -> Result<(), String> {
    let mut hostnames: Vec<String> = set.iter().cloned().collect();
    hostnames.sort();
    let t = WolfnetTombstones { hostnames };
    let content = serde_json::to_string_pretty(&t)
        .map_err(|e| format!("serialize tombstones: {}", e))?;
    if let Some(parent) = std::path::Path::new(WOLFNET_TOMBSTONE_FILE).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(WOLFNET_TOMBSTONE_FILE, content)
        .map_err(|e| format!("write tombstones: {}", e))
}

/// Mark `hostname` as removed. All future auto-(re)injection paths will
/// skip this hostname until it's removed via `wolfnet_tombstone_remove`.
pub fn wolfnet_tombstone_add(hostname: &str) {
    if hostname.is_empty() { return; }
    let mut set = load_wolfnet_tombstones();
    if set.insert(hostname.to_string()) {
        if let Err(e) = save_wolfnet_tombstones(&set) {
            tracing::warn!("Failed to persist wolfnet tombstone for '{}': {}", hostname, e);
        } else {
            tracing::info!(
                "WolfNet tombstone added: '{}' will be ignored by gossip / auto-apply / reconcilers",
                hostname
            );
        }
    }
}

/// Un-tombstone a hostname. Returns true if it was actually tombstoned
/// (i.e. caller has effected a change).
pub fn wolfnet_tombstone_remove(hostname: &str) -> bool {
    let mut set = load_wolfnet_tombstones();
    if set.remove(hostname) {
        if let Err(e) = save_wolfnet_tombstones(&set) {
            tracing::warn!("Failed to persist wolfnet tombstone removal for '{}': {}", hostname, e);
        }
        true
    } else {
        false
    }
}

/// Check whether `hostname` is tombstoned. Cheap — load+lookup is one
/// small file read. Auto-(re)injection paths call this per peer.
pub fn wolfnet_tombstone_contains(hostname: &str) -> bool {
    load_wolfnet_tombstones().contains(hostname)
}

/// List all tombstoned hostnames. Used by the inspect endpoint.
pub fn wolfnet_tombstone_list() -> Vec<String> {
    let mut v: Vec<String> = load_wolfnet_tombstones().into_iter().collect();
    v.sort();
    v
}

/// Try SIGHUP hot-reload first; if wolfnet dies (old version without handler),
/// fall back to systemctl restart.
/// Force a full systemctl restart of wolfnet (skip SIGHUP). Used when
/// the config change is one that pre-0.5.22 wolfnet can't apply via
/// SIGHUP — currently just "endpoint removed from peer entry". A cold
/// restart re-reads the file and the peer comes up with no static
/// endpoint, ready for roaming.
fn restart_wolfnet() {
    // Via wolfnet_service_action so the systemctl path is resolved robustly
    // (a stripped PATH would otherwise ENOENT — see systemctl_bin).
    let _ = wolfnet_service_action("restart");
}

fn reload_or_restart_wolfnet() {
    // Check if wolfnet is currently running
    let was_running = Command::new("pgrep").arg("wolfnet")
        .output().map(|o| o.status.success()).unwrap_or(false);

    if !was_running {
        // Not running at all — just start it (resolved systemctl path).
        let _ = wolfnet_service_action("start");
        return;
    }

    // Send SIGHUP for hot-reload
    let _ = Command::new("pkill").args(["-HUP", "wolfnet"]).output();

    // Brief pause to let signal be processed
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Check if it survived (old versions without SIGHUP handler will die)
    let still_running = Command::new("pgrep").arg("wolfnet")
        .output().map(|o| o.status.success()).unwrap_or(false);

    if !still_running {
        warn!("WolfNet died after SIGHUP (old version?) — restarting via systemctl");
        let _ = wolfnet_service_action("restart");
    }
}

/// Restart or start WolfNet service
pub fn wolfnet_service_action(action: &str) -> Result<String, String> {
    // Unraid: no systemd, the agent is the supervisor — every verb has a
    // supervisor equivalent there (klas, 2026-09-10: the WolfNet page's
    // Start button answered "systemctl isn't available").
    if crate::installer::unraid_tools::is_unraid() {
        return crate::installer::unraid_tools::wolfnet_service_action(action);
    }
    let systemctl = systemctl_bin().ok_or_else(|| {
        "systemd (systemctl) isn't available on this host, so the WolfNet \
         service can't be managed here.".to_string()
    })?;

    let output = Command::new(&systemctl)
        .args([action, "wolfnet"])
        .output()
        .map_err(|e| format!("Failed to {} WolfNet: {}", action, e))?;

    if output.status.success() {
        return Ok(format!("WolfNet {}", action));
    }

    // Stopping/disabling a service that isn't loaded means the goal is
    // already met — report success rather than a scary error (the operator
    // wanted it off, and it's off).
    let stderr = String::from_utf8_lossy(&output.stderr);
    if (action == "stop" || action == "disable")
        && (stderr.contains("not loaded")
            || stderr.contains("not-found")
            || stderr.contains("not found")
            || stderr.contains("No such file"))
    {
        return Ok(format!(
            "WolfNet already {}",
            if action == "stop" { "stopped" } else { "disabled" }
        ));
    }

    Err(format!("Failed to {} WolfNet: {}", action, stderr.trim()))
}

/// Generate an invite token for a new peer to join this WolfNet network.
/// Replicates `wolfnet invite` CLI command logic.
pub fn generate_wolfnet_invite() -> Result<serde_json::Value, String> {
    let config_path = "/etc/wolfnet/config.toml";
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read WolfNet config: {}", e))?;
    
    // Parse config to get network settings
    let get_val = |key: &str| -> String {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with(key)
                && let Some(eq_pos) = trimmed.find('=') {
                    return trimmed[eq_pos+1..].trim().trim_matches('"').trim_matches('\'').to_string();
                }
        }
        String::new()
    };
    
    let address = get_val("address");
    let subnet: u8 = get_val("subnet").parse().unwrap_or(24);
    let listen_port: u16 = get_val("listen_port").parse().unwrap_or(9600);
    
    if address.is_empty() {
        return Err("WolfNet address not configured".to_string());
    }
    
    
    // Read the public key via wolfnet CLI
    let pubkey_output = Command::new("wolfnet")
        .args(["--config", config_path, "pubkey"])
        .output()
        .map_err(|e| format!("Failed to get WolfNet public key: {}", e))?;
    
    if !pubkey_output.status.success() {
        return Err("Failed to read WolfNet public key — is wolfnet installed?".to_string());
    }
    let public_key = String::from_utf8_lossy(&pubkey_output.stdout).trim().to_string();
    
    // Auto-detect public IP 
    let public_ip = detect_public_ip();
    let endpoint = match &public_ip {
        Some(ip) => format!("{}:{}", ip, listen_port),
        None => format!("{}:{}", address, listen_port),
    };
    
    // Build invite token as JSON → base64
    let invite = serde_json::json!({
        "pk": public_key,
        "ep": endpoint,
        "ip": address,
        "sn": subnet,
        "pt": listen_port,
    });
    
    use base64::Engine;
    let token = base64::engine::general_purpose::STANDARD.encode(invite.to_string().as_bytes());
    
    Ok(serde_json::json!({
        "token": token,
        "public_key": public_key,
        "endpoint": endpoint,
        "address": address,
        "subnet": subnet,
        "listen_port": listen_port,
        "public_ip": public_ip,
        "join_command": format!("sudo wolfnet --config /etc/wolfnet/config.toml join {}", token),
    }))
}

/// Detect public IP address (used for invite tokens)
fn detect_public_ip() -> Option<String> {
    let services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
        "https://checkip.amazonaws.com",
    ];
    for url in &services {
        if let Ok(output) = Command::new("curl")
            .args(["-sf", "--connect-timeout", "3", url])
            .output()
            && output.status.success() {
                let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                    return Some(ip);
                }
            }
    }
    None
}

/// Get full WolfNet status including live peer data from status.json
pub fn get_wolfnet_status_full() -> serde_json::Value {
    let status = get_wolfnet_status();
    
    // Also read live peer data from status.json (richer info than config)
    let live_peers = match std::fs::read_to_string("/var/run/wolfnet/status.json") {
        Ok(content) => {
            match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(v) => v.get("peers").cloned().unwrap_or(serde_json::json!([])),
                Err(_) => serde_json::json!([]),
            }
        }
        Err(_) => serde_json::json!([]),
    };
    
    serde_json::json!({
        "installed": status.installed,
        "running": status.running,
        "interface": status.interface,
        "ip": status.ip,
        "peers": status.peers,
        "live_peers": live_peers,
    })
}

/// Add an IP address to an interface — runtime AND persisted. The old
/// bare `ip addr add` stored nothing: the address evaporated on reboot,
/// yet squatted on the NIC so a hand-written ifupdown stanza failed
/// `ifup` with "already assigned" (RutgerDiehard, 2026-08-11). The full
/// behaviour — cross-interface conflict naming, idempotent re-add,
/// tri-manager persistence with honest fallbacks — lives in
/// [`nic_addr`].
pub fn add_ip(interface: &str, address: &str, prefix: u32) -> Result<String, String> {
    nic_addr::add_ip(interface, address, prefix)
}

/// Remove an IP address from an interface — runtime AND persisted; also
/// clears WolfStack's persisted record when the runtime address is
/// already gone, and names the actual holder when the address lives on
/// a different NIC. See [`nic_addr`].
pub fn remove_ip(interface: &str, address: &str, prefix: u32) -> Result<String, String> {
    nic_addr::remove_ip(interface, address, prefix)
}

/// Runtime-only removal, kept for internal callers that manage their
/// own persistence.
#[allow(dead_code)]
pub fn remove_ip_runtime_only(interface: &str, address: &str, prefix: u32) -> Result<String, String> {
    let cidr = format!("{}/{}", address, prefix);
    let output = Command::new("ip")
        .args(["addr", "del", &cidr, "dev", interface])
        .output()
        .map_err(|e| format!("Failed to run ip addr del: {}", e))?;

    if output.status.success() {

        Ok(format!("Removed {} from {}", cidr, interface))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Set interface up or down
pub fn set_interface_state(interface: &str, up: bool) -> Result<String, String> {
    let state = if up { "up" } else { "down" };
    let output = Command::new("ip")
        .args(["link", "set", interface, state])
        .output()
        .map_err(|e| format!("Failed to set interface state: {}", e))?;

    if output.status.success() {

        Ok(format!("Interface {} set {}", interface, state))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Delete a VLAN interface
pub fn delete_vlan(name: &str) -> Result<String, String> {
    let output = Command::new("ip")
        .args(["link", "delete", name])
        .output()
        .map_err(|e| format!("Failed to delete VLAN: {}", e))?;

    if output.status.success() {

        Ok(format!("Deleted VLAN {}", name))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Set interface MTU
pub fn set_mtu(interface: &str, mtu: u32) -> Result<String, String> {
    let output = Command::new("ip")
        .args(["link", "set", interface, "mtu", &mtu.to_string()])
        .output()
        .map_err(|e| format!("Failed to set MTU: {}", e))?;

    if output.status.success() {

        Ok(format!("MTU set to {} on {}", mtu, interface))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

// ─── Public IP → WolfNet IP Mapping ───

fn ip_mappings_path() -> String { crate::paths::get().ip_mappings }

/// A mapping from a public IP to a WolfNet IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpMapping {
    pub id: String,
    pub public_ip: String,
    pub wolfnet_ip: String,
    pub ports: Option<String>,      // None = all ports, Some("80,443") = specific source ports
    pub dest_ports: Option<String>, // None = same as source, Some("80") = different dest port
    pub protocol: String,           // "all", "tcp", "udp"
    pub label: String,
    pub enabled: bool,
}

/// Persistent config for IP mappings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct IpMappingConfig {
    mappings: Vec<IpMapping>,
}

fn load_ip_mapping_config() -> IpMappingConfig {
    match std::fs::read_to_string(ip_mappings_path()) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => IpMappingConfig::default(),
    }
}

fn save_ip_mapping_config(config: &IpMappingConfig) -> Result<(), String> {
    let path = ip_mappings_path();
    let dir = std::path::Path::new(&path).parent().unwrap();
    std::fs::create_dir_all(dir).map_err(|e| format!("Cannot create config dir: {}", e))?;
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    std::fs::write(&path, json)
        .map_err(|e| format!("Failed to write {}: {}", path, e))
}

/// List all IP mappings
pub fn list_ip_mappings() -> Vec<IpMapping> {
    load_ip_mapping_config().mappings
}

/// Ports whose SOURCE mapping could lock the operator out of critical
/// services on this host. The block is context-sensitive: each entry
/// is only refused when that port is actually listening on this host
/// (verified live via `get_listening_ports`). On a plain Linux box
/// with no PVE installed, 8006/8007/8443 are free and mappable — you
/// can land PBS on those. On a PVE host, they're refused because the
/// DNAT would collide with pveproxy/spiceproxy.
///
/// WolfStack's own ports (8552/8553) and the SSH guard (22) are
/// always blocked — those are bedrock, never let anyone override.
const BLOCKED_PORTS: &[(u16, &str, bool)] = &[
    // (port, label, ALWAYS_BLOCK)
    (22,   "SSH", true),
    (111,  "NFS portmapper", false),
    (2049, "NFS", false),
    (3128, "Proxmox CONNECT proxy", false),
    (5900, "Proxmox VNC console", false),
    (5901, "Proxmox VNC console", false),
    (5902, "Proxmox VNC console", false),
    (5903, "Proxmox VNC console", false),
    (5999, "Proxmox SPICE console", false),
    (8006, "Proxmox Web UI", false),
    (8007, "Proxmox Spiceproxy / PBS Web UI", false),
    (8443, "Proxmox API", false),
    (8552, "WolfStack API",    true),
    (8553, "WolfStack cluster", true),
    (9600, "WolfNet", true),
];

/// Parse a port specification string into individual port numbers.
/// Accepts: "80", "80,443", "8000:8100", "80,443,8000:8100"
fn parse_port_list(ports_str: &str) -> Result<Vec<u16>, String> {
    let mut result = Vec::new();
    for part in ports_str.split(',') {
        let part = part.trim();
        if part.is_empty() { continue; }
        if part.contains(':') {
            // Range like 8000:8100
            let bounds: Vec<&str> = part.split(':').collect();
            if bounds.len() != 2 {
                return Err(format!("Invalid port range: '{}'", part));
            }
            let lo: u16 = bounds[0].trim().parse()
                .map_err(|_| format!("Invalid port number: '{}'", bounds[0].trim()))?;
            let hi: u16 = bounds[1].trim().parse()
                .map_err(|_| format!("Invalid port number: '{}'", bounds[1].trim()))?;
            if lo > hi {
                return Err(format!("Invalid port range: {} > {}", lo, hi));
            }
            if hi - lo > 1000 {
                return Err(format!("Port range {}:{} is too large (max 1000 ports)", lo, hi));
            }
            for p in lo..=hi { result.push(p); }
        } else {
            let p: u16 = part.parse()
                .map_err(|_| format!("Invalid port number: '{}'", part))?;
            result.push(p);
        }
    }
    Ok(result)
}

/// Add a new IP mapping and apply iptables rules
pub fn add_ip_mapping(
    public_ip: &str,
    wolfnet_ip: &str,
    ports: Option<&str>,
    dest_ports: Option<&str>,
    protocol: &str,
    label: &str,
) -> Result<IpMapping, String> {
    // Validate IPs
    if public_ip.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(format!("Invalid public IP: {}", public_ip));
    }
    if wolfnet_ip.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(format!("Invalid WolfNet IP: {}", wolfnet_ip));
    }

    // Self-mapping guard: don't route traffic to yourself
    if let Some(gw) = detect_wolfnet_gateway_ip()
        && wolfnet_ip == gw {
            return Err("Cannot map to this server's own WolfNet IP — this would create a routing loop".to_string());
        }

    // Protocol validation
    if !["all", "tcp", "udp"].contains(&protocol) {
        return Err(format!("Invalid protocol '{}' — must be 'all', 'tcp', or 'udp'", protocol));
    }

    // Port validation & blocked port check
    if let Some(port_str) = ports {
        let trimmed = port_str.trim();
        if !trimmed.is_empty() {
            // Protocol must be tcp or udp when specific ports are used (iptables requirement)
            if protocol == "all" {
                return Err("When specifying ports, you must select TCP or UDP (not 'All'). \
                    iptables --dport requires a specific protocol.".to_string());
            }

            let port_list = parse_port_list(trimmed)?;
            // Live listening-ports scan once, reuse for both checks.
            let listening = get_listening_ports();
            let is_listening = |p: u16| -> Option<String> {
                listening.iter()
                    .find(|e| e["port"].as_u64() == Some(p as u64))
                    .and_then(|e| e["process"].as_str().map(str::to_string))
            };

            // Check against blocked ports. Entries flagged ALWAYS_BLOCK
            // (WolfStack's own ports, SSH) are refused unconditionally;
            // everything else is only refused when that port is ACTUALLY
            // listening on this host — so e.g. PBS-as-VM can land its
            // 8007 mapping on a plain Linux host where 8007 is free,
            // but still gets blocked on a PVE host where pveproxy/
            // spiceproxy is listening.
            for &port in &port_list {
                for &(blocked, service, always) in BLOCKED_PORTS {
                    if port != blocked { continue; }
                    let live = is_listening(port);
                    if always || live.is_some() {
                        let extra = if let Some(proc) = live {
                            format!(" (currently in use by '{}')", proc)
                        } else { String::new() };
                        return Err(format!(
                            "Port {} is reserved for {}{}. Map a different source port \
                             (e.g. {}→{}) if you need this service exposed externally.",
                            port, service, extra, port.saturating_add(1000), port
                        ));
                    }
                }
            }

            // Live scan: warn (not block) for any OTHER port in use
            // on this host. DNAT rules are IP-specific so they won't
            // necessarily conflict; operator may know what they're doing.
            for &port in &port_list {
                if BLOCKED_PORTS.iter().any(|&(bp, _, _)| bp == port) { continue; }
                if let Some(proc_name) = is_listening(port) {
                    warn!("Source port {} is in use by '{}' — mapping will use DNAT on public IP only", port, proc_name);
                }
            }
        }
    }

    // Validate dest_ports if provided
    let dest_ports_clean: Option<&str> = match dest_ports {
        Some(s) if !s.trim().is_empty() => Some(s),
        _ => None,
    };
    if let Some(dp_str) = dest_ports_clean {
        if ports.map(|s| s.trim().is_empty()).unwrap_or(true) {
            return Err("Destination ports require source ports to be specified too.".to_string());
        }
        if protocol == "all" {
            return Err("When specifying ports, you must select TCP or UDP (not 'All').".to_string());
        }
        let dp_list = parse_port_list(dp_str)?;
        let sp_list = parse_port_list(ports.unwrap())?;
        if dp_list.len() != sp_list.len() {
            return Err(format!(
                "Source ports ({}) and destination ports ({}) must have the same count.",
                sp_list.len(), dp_list.len()
            ));
        }
    }

    let mut config = load_ip_mapping_config();

    // Check for duplicate
    if config.mappings.iter().any(|m| m.public_ip == public_ip && m.wolfnet_ip == wolfnet_ip
        && m.ports == ports.map(|s| s.to_string()) && m.protocol == protocol)
    {
        return Err(format!("{} → {} already mapped with these ports/protocol", public_ip, wolfnet_ip));
    }

    let mapping = IpMapping {
        id: format!("{:x}", rand_id()),
        public_ip: public_ip.to_string(),
        wolfnet_ip: wolfnet_ip.to_string(),
        ports: ports.map(|s| s.to_string()),
        dest_ports: dest_ports_clean.map(|s| s.to_string()),
        protocol: protocol.to_string(),
        label: label.to_string(),
        enabled: true,
    };

    // Apply iptables rules
    apply_mapping_rules(&mapping)?;

    config.mappings.push(mapping.clone());
    save_ip_mapping_config(&config)?;


    Ok(mapping)
}

/// Get list of TCP/UDP ports currently listening on this server (for conflict detection)
pub fn get_listening_ports() -> Vec<serde_json::Value> {
    let output = Command::new("ss")
        .args(["-tlnp"])  // TCP listening, numeric, show processes
        .output();

    let mut ports = Vec::new();

    if let Ok(o) = output
        && o.status.success() {
            for line in String::from_utf8_lossy(&o.stdout).lines().skip(1) {
                // Format: State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 5 {
                    let local = cols[3];
                    // Extract port from the last colon-separated part
                    if let Some(port_str) = local.rsplit(':').next()
                        && let Ok(port) = port_str.parse::<u16>() {
                            let process = if cols.len() >= 6 { cols[5..].join(" ") } else { String::new() };
                            // Extract process name from users:(("name",pid=N,fd=N))
                            let proc_name = process.split('"').nth(1).unwrap_or("").to_string();
                            ports.push(serde_json::json!({
                                "port": port,
                                "protocol": "tcp",
                                "process": proc_name,
                            }));
                        }
                }
            }
        }

    // Also get UDP
    let output = Command::new("ss")
        .args(["-ulnp"])
        .output();

    if let Ok(o) = output
        && o.status.success() {
            for line in String::from_utf8_lossy(&o.stdout).lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 5 {
                    let local = cols[4];
                    if let Some(port_str) = local.rsplit(':').next()
                        && let Ok(port) = port_str.parse::<u16>() {
                            let process = if cols.len() >= 6 { cols[5..].join(" ") } else { String::new() };
                            let proc_name = process.split('"').nth(1).unwrap_or("").to_string();
                            ports.push(serde_json::json!({
                                "port": port,
                                "protocol": "udp",
                                "process": proc_name,
                            }));
                        }
                }
            }
        }

    // De-duplicate by port+protocol
    ports.sort_by_key(|p| (p["port"].as_u64().unwrap_or(0), p["protocol"].as_str().unwrap_or("").to_string()));
    ports.dedup_by(|a, b| a["port"] == b["port"] && a["protocol"] == b["protocol"]);
    ports
}

/// Get the list of blocked ports (for frontend display). `always` is
/// included so the UI can distinguish the bedrock blocks (WolfStack's
/// own ports, SSH — refused regardless of what's running) from the
/// context-sensitive ones (refused only when that port is listening
/// on this host).
pub fn get_blocked_ports() -> Vec<serde_json::Value> {
    BLOCKED_PORTS.iter().map(|&(port, service, always)| {
        serde_json::json!({ "port": port, "service": service, "always": always })
    }).collect()
}

/// Remove an IP mapping by ID and clean up iptables rules
pub fn remove_ip_mapping(id: &str) -> Result<String, String> {
    let mut config = load_ip_mapping_config();
    let idx = config.mappings.iter().position(|m| m.id == id)
        .ok_or_else(|| format!("Mapping '{}' not found", id))?;

    let mapping = config.mappings.remove(idx);
    remove_mapping_rules(&mapping);
    save_ip_mapping_config(&config)?;


    Ok(format!("Removed mapping {} → {}", mapping.public_ip, mapping.wolfnet_ip))
}

/// Update an existing IP mapping by ID
pub fn update_ip_mapping(
    id: &str,
    public_ip: &str,
    wolfnet_ip: &str,
    ports: Option<&str>,
    dest_ports: Option<&str>,
    protocol: &str,
    label: &str,
) -> Result<IpMapping, String> {
    let mut config = load_ip_mapping_config();
    let idx = config.mappings.iter().position(|m| m.id == id)
        .ok_or_else(|| format!("Mapping '{}' not found", id))?;

    // Remove old iptables rules
    remove_mapping_rules(&config.mappings[idx]);

    // Validate protocol
    let protocol = if protocol.is_empty() { "all" } else { protocol };
    if !["all", "tcp", "udp"].contains(&protocol) {
        return Err(format!("Invalid protocol '{}'. Must be 'all', 'tcp', or 'udp'.", protocol));
    }

    // Validate ports
    if let Some(port_str) = ports
        && !port_str.trim().is_empty() {
            if protocol == "all" {
                return Err("When specifying ports, you must select TCP or UDP (not 'All').".to_string());
            }
            parse_port_list(port_str)?;
        }

    // Validate dest_ports
    let dest_ports_clean: Option<&str> = match dest_ports {
        Some(s) if !s.trim().is_empty() => Some(s),
        _ => None,
    };
    if let Some(dp_str) = dest_ports_clean {
        if ports.map(|s| s.trim().is_empty()).unwrap_or(true) {
            return Err("Destination ports require source ports to be specified too.".to_string());
        }
        let dp_list = parse_port_list(dp_str)?;
        let sp_list = parse_port_list(ports.unwrap())?;
        if dp_list.len() != sp_list.len() {
            return Err(format!(
                "Source ports ({}) and destination ports ({}) must have the same count.",
                sp_list.len(), dp_list.len()
            ));
        }
    }

    // Update the mapping in-place
    let mapping = &mut config.mappings[idx];
    mapping.public_ip = public_ip.to_string();
    mapping.wolfnet_ip = wolfnet_ip.to_string();
    mapping.ports = ports.map(|s| s.to_string());
    mapping.dest_ports = dest_ports_clean.map(|s| s.to_string());
    mapping.protocol = protocol.to_string();
    mapping.label = label.to_string();

    // Apply new rules
    apply_mapping_rules(mapping)?;

    let result = mapping.clone();
    save_ip_mapping_config(&config)?;


    Ok(result)
}

/// Build iptables port-match arguments.
/// For a single port or range: `--dport <port>`
/// For multiple comma-separated ports: `-m multiport --dports <ports>`
fn build_port_args(ports: &str) -> Vec<String> {
    if ports.contains(',') {
        // Multiple ports — must use the multiport extension
        vec!["-m".into(), "multiport".into(), "--dports".into(), ports.to_string()]
    } else {
        // Single port or range — plain --dport works
        vec!["--dport".into(), ports.to_string()]
    }
}

/// Delete every iptables rule in `table`/`chain` whose listing line contains
/// ALL of the given substring markers. Loops until no match remains. Returns
/// the number of rules removed (capped at 1024 as a safety stop).
///
/// Used to flush duplicate/stale mapping rules before re-applying. Matches
/// on text rather than exact rule spec so it catches rules whose DNAT target
/// or SNAT source differs from the current mapping (i.e. stale rules left
/// from a previous WolfNet IP or a different translated destination port).
/// True when an `iptables -S` rule line belongs to `chain` (via its
/// `-A <chain> ` prefix) and contains every marker substring. Pulled out
/// so the matching logic is unit-testable without shelling out to iptables.
fn rule_spec_matches(line: &str, add_prefix: &str, markers: &[&str]) -> bool {
    line.starts_with(add_prefix) && markers.iter().all(|m| line.contains(m))
}

fn purge_matching_lines(table: &str, chain: &str, markers: &[&str]) -> usize {
    // Read rules in canonical spec form (`iptables -S`), which is identical
    // across the legacy and nft backends — unlike `iptables -L -n`, whose
    // nft-side rendering of `-m conntrack --ctstate DNAT` and ports does NOT
    // contain the substrings the old `-L` scrape searched for. On an
    // nft-backend host that silently defeated the FORWARD purge, so the 30s
    // reconcile re-appended the conntrack-ACCEPT rule every cycle and it
    // piled up into the thousands (PapaSchlumpf: 9988 FORWARD rules, vs the
    // PREROUTING DNAT rule which `-L` happened to render matchably — hence
    // only the FORWARD chain ran away). `-S` matches deterministically.
    let add_prefix = format!("-A {} ", chain);
    let text = match Command::new("iptables").args(["-t", table, "-S", chain]).output() {
        Ok(ref o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => return 0,
    };
    // Distinct matching specs (the text after "-A <chain> ").
    let mut specs: Vec<String> = text
        .lines()
        .filter(|l| rule_spec_matches(l, &add_prefix, markers))
        .map(|l| l[add_prefix.len()..].to_string())
        .collect();
    specs.sort();
    specs.dedup();

    // Drain every copy of each matching rule by issuing its exact inverse
    // (`-D <chain> <spec>`) until iptables reports no match left. Deleting
    // by spec rather than by line number is immune to concurrent FORWARD
    // edits (Docker) shifting positions mid-purge, and `-S`'s canonical
    // form is always a valid `-D` argument regardless of whether the rule
    // was originally added with `-A` or `-I`. No per-call cap — a healthy
    // chain has one rule per spec; a runaway one must drain fully.
    let mut removed = 0usize;
    for spec in &specs {
        let spec_tokens: Vec<&str> = spec.split_whitespace().collect();
        loop {
            let mut argv: Vec<&str> = vec!["-t", table, "-D", chain];
            argv.extend_from_slice(&spec_tokens);
            match Command::new("iptables").args(&argv).output() {
                Ok(ref o) if o.status.success() => {
                    removed += 1;
                    // Runaway guard — far above any legitimate count, but
                    // bounded so a pathological state can't spin forever.
                    if removed >= 200_000 { return removed; }
                }
                Ok(o) => {
                    // Non-zero is usually "Bad rule (Does a matching rule
                    // exist…)" — the expected end-of-drain. Any OTHER stderr
                    // (permission denied, no such chain/module) means the purge
                    // silently left rules in place, so surface it rather than
                    // swallowing it.
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    let s = stderr.trim();
                    if !s.is_empty() && !s.contains("Does a matching rule exist") {
                        warn!("purge_matching_lines: iptables -D {} {} failed: {}", table, chain, s);
                    }
                    break;
                }
                Err(e) => {
                    warn!("purge_matching_lines: could not run iptables -D {} {}: {}", table, chain, e);
                    break;
                }
            }
        }
    }
    removed
}

/// Sweep iptables for any existing rule belonging to this mapping —
/// duplicates accumulated across WolfStack restarts, plus stale rules
/// whose DNAT target or SNAT source no longer matches the current
/// mapping (left over when the WolfNet IP was edited).
///
/// This is called at the top of apply_mapping_rules so a subsequent
/// append always produces exactly one rule per chain, regardless of
/// how many stale copies were there before.
fn purge_mapping_rules(m: &IpMapping) {
    // Build the port-match token exactly as build_port_args() emits it into
    // the rule spec, so the purge marker lines up with what apply wrote.
    // None when the rule carries no port match (no ports, or protocol "all",
    // which suppresses the -p/port match in apply too). Keying off the same
    // source as apply is what guarantees the purge actually matches —
    // previously the FORWARD marker searched for a `dpt:N` token that the
    // nft backend never rendered.
    let src_marker = port_purge_marker(m.ports.as_deref(), &m.protocol);
    let dest_marker = port_purge_marker(
        m.dest_ports.as_deref().or(m.ports.as_deref()), &m.protocol);

    // Source side (PREROUTING + OUTPUT): match any DNAT rule for this
    // public_ip (+ src port). Catches duplicates AND stale rules whose
    // --to-destination points at an old WolfNet IP.
    let mut src = vec![m.public_ip.as_str(), "DNAT"];
    if let Some(ref pm) = src_marker { src.push(pm.as_str()); }
    purge_matching_lines("nat", "PREROUTING", &src);
    purge_matching_lines("nat", "OUTPUT", &src);

    // Dest side (POSTROUTING SNAT + FORWARD conntrack-DNAT ACCEPT): match
    // on the current wolfnet_ip (+ dest port). Won't catch rules from a
    // previous WolfNet IP, but those are benign (wrong-target SNAT/ACCEPT
    // just dead-routes traffic to a defunct IP, it doesn't mis-route).
    let mut snat = vec![m.wolfnet_ip.as_str(), "SNAT"];
    if let Some(ref pm) = dest_marker { snat.push(pm.as_str()); }
    purge_matching_lines("nat", "POSTROUTING", &snat);

    let mut fwd = vec![m.wolfnet_ip.as_str(), "ctstate DNAT"];
    if let Some(ref pm) = dest_marker { fwd.push(pm.as_str()); }
    purge_matching_lines("filter", "FORWARD", &fwd);

    // VIP mappings (apply_vip_mapping_rules) write their POSTROUTING SNAT and
    // FORWARD ACCEPT rules keyed on the *backend* IP (`-d <backend>`), not on
    // m.wolfnet_ip — so the IP-based markers above never match them, and one
    // full set was appended on every reconcile. That accumulated into thousands
    // of identical SNAT/ACCEPT rules in the packet hot path and collapsed
    // forwarding throughput (PapaSchlumpf: 3589 duplicates each). Every VIP rule
    // carries the unique `wolfstack-vip-map-<id>` comment, so a comment-based
    // purge removes them all regardless of which IP they key on — making the VIP
    // path idempotent and self-healing any existing backlog on the next apply.
    remove_rules_by_comment(&format!("wolfstack-vip-map-{}", m.id));
}

/// The port-match substring that `build_port_args()` produces in a rule
/// spec (`iptables -S` form), or None when apply emits no port match.
/// Mirrors build_port_args()/the apply gating so purge markers line up with
/// the rules apply actually wrote:
///   - protocol "all" or empty ports → None (apply emits no -p/port match)
///   - "8000"      → "--dport 8000"
///   - "8000,8001" → "--dports 8000,8001"
fn port_purge_marker(ports: Option<&str>, protocol: &str) -> Option<String> {
    let ports = ports?;
    if ports.is_empty() || protocol == "all" {
        return None;
    }
    if ports.contains(',') {
        Some(format!("--dports {}", ports))
    } else {
        Some(format!("--dport {}", ports))
    }
}

/// Apply iptables rules for a single mapping
fn apply_mapping_rules(m: &IpMapping) -> Result<(), String> {
    if !m.enabled { return Ok(()); }

    // Flush any existing rules for this mapping first — makes the whole
    // function idempotent. Without this, every WolfStack startup calls
    // apply_ip_mappings → apply_mapping_rules → -A, piling duplicate DNAT
    // rules into PREROUTING. Since iptables DNAT is terminating and the
    // first match wins, once a stale rule with a wrong target accumulates
    // (e.g. from before an edit changed the WolfNet IP), all traffic gets
    // black-holed to the dead target. Purging first guarantees exactly one
    // rule per chain after this function returns.
    purge_mapping_rules(m);

    // Detect gateway WolfNet IP for SNAT
    let gateway_ip = detect_wolfnet_gateway_ip()
        .ok_or_else(|| "Cannot detect WolfNet gateway IP — is WolfNet running?".to_string())?;

    // Build port/protocol args
    let proto_args: Vec<String> = if m.protocol != "all" {
        vec!["-p".into(), m.protocol.clone()]
    } else {
        vec![]
    };

    // Source port args (for matching incoming traffic in PREROUTING)
    let src_port_args: Vec<String> = if let Some(ref ports) = m.ports {
        if !ports.is_empty() && m.protocol != "all" {
            build_port_args(ports)
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    // Check if target is a WolfRun VIP with backends
    if let Some((backends, lb_policy)) = resolve_wolfrun_vip(&m.wolfnet_ip)
        && !backends.is_empty() {
            return apply_vip_mapping_rules(m, &backends, &lb_policy, &gateway_ip, &proto_args, &src_port_args);
        }

    // Standard mapping (non-VIP target)

    // Determine if port translation is needed (dest_ports differs from source ports)
    let has_port_translation = m.dest_ports.as_ref()
        .map(|dp| !dp.is_empty() && m.ports.as_ref().map(|sp| sp != dp).unwrap_or(true))
        .unwrap_or(false);

    // When port translation involves multiple ports, we must emit separate rules
    // per port pair because --to-destination only accepts a single port.
    // When ports aren't being translated, omit port from DNAT target (iptables preserves it).
    if has_port_translation && m.dest_ports.as_ref().map(|dp| dp.contains(',')).unwrap_or(false) {
        // Multi-port translation: one rule per source→dest port pair
        let sp_list = parse_port_list(m.ports.as_deref().unwrap_or(""))?;
        let dp_list = parse_port_list(m.dest_ports.as_deref().unwrap_or(""))?;

        for (sp, dp) in sp_list.iter().zip(dp_list.iter()) {
            let sp_str = sp.to_string();
            let dp_str = dp.to_string();
            let per_src = vec!["--dport".into(), sp_str];
            let per_dest = vec!["--dport".into(), dp_str.clone()];
            let dnat_target = format!("{}:{}", m.wolfnet_ip, dp);

            // DNAT PREROUTING
            run_iptables(&[
                "-t", "nat", "-A", "PREROUTING", "-d", &m.public_ip,
            ], &proto_args, &per_src, &["-j", "DNAT", "--to-destination", &dnat_target])?;

            // DNAT OUTPUT
            run_iptables(&[
                "-t", "nat", "-A", "OUTPUT", "-d", &m.public_ip,
            ], &proto_args, &per_src, &["-j", "DNAT", "--to-destination", &dnat_target])?;

            // SNAT
            run_iptables(&[
                "-t", "nat", "-A", "POSTROUTING", "-d", &m.wolfnet_ip,
            ], &proto_args, &per_dest, &["-j", "SNAT", "--to-source", &gateway_ip])?;

            // FORWARD
            run_iptables(&[
                "-I", "FORWARD", "1", "-d", &m.wolfnet_ip,
            ], &proto_args, &per_dest, &["-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"])?;
        }
    } else {
        // Single rule path: either no port translation, single port, or no ports at all
        let dnat_dest = if has_port_translation {
            // Single dest port translation
            format!("{}:{}", m.wolfnet_ip, m.dest_ports.as_ref().unwrap())
        } else {
            // No translation — iptables preserves original port
            m.wolfnet_ip.clone()
        };

        // Dest port args (for matching translated traffic in POSTROUTING/FORWARD)
        let dest_port_args: Vec<String> = {
            let effective_ports = m.dest_ports.as_ref().or(m.ports.as_ref());
            if let Some(ports) = effective_ports {
                if !ports.is_empty() && m.protocol != "all" {
                    build_port_args(ports)
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        };

        // DNAT: redirect incoming traffic to WolfNet IP (with optional port translation)
        run_iptables(&[
            "-t", "nat", "-A", "PREROUTING", "-d", &m.public_ip,
        ], &proto_args, &src_port_args, &["-j", "DNAT", "--to-destination", &dnat_dest])?;

        // OUTPUT DNAT: also redirect traffic originating FROM this server (e.g. wget from localhost)
        run_iptables(&[
            "-t", "nat", "-A", "OUTPUT", "-d", &m.public_ip,
        ], &proto_args, &src_port_args, &["-j", "DNAT", "--to-destination", &dnat_dest])?;

        // SNAT: ensure return traffic goes back through this gateway
        run_iptables(&[
            "-t", "nat", "-A", "POSTROUTING", "-d", &m.wolfnet_ip,
        ], &proto_args, &dest_port_args, &["-j", "SNAT", "--to-source", &gateway_ip])?;

        // FORWARD: allow DNAT'd traffic (must be at top before Docker chains DROP it)
        run_iptables(&[
            "-I", "FORWARD", "1", "-d", &m.wolfnet_ip,
        ], &proto_args, &dest_port_args, &["-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"])?;
    }

    Ok(())
}

/// Resolve a WolfRun VIP to its backend IPs and LB policy.
/// Returns None if the IP is not a WolfRun service VIP.
fn resolve_wolfrun_vip(ip: &str) -> Option<(Vec<String>, String)> {
    let data = std::fs::read_to_string(&crate::paths::get().wolfrun_services).ok()?;
    let services: Vec<serde_json::Value> = serde_json::from_str(&data).ok()?;
    for svc in &services {
        if svc.get("service_ip").and_then(|v| v.as_str()) == Some(ip) {
            let lb_policy = svc.get("lb_policy").and_then(|v| v.as_str())
                .unwrap_or("round_robin").to_string();
            let backends: Vec<String> = svc.get("instances")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter(|i| i.get("status").and_then(|s| s.as_str()) == Some("running"))
                        .filter_map(|i| i.get("wolfnet_ip").and_then(|v| v.as_str()).map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            return Some((backends, lb_policy));
        }
    }
    None
}

/// Apply mapping rules for a WolfRun VIP — DNAT directly to backends
/// with round-robin or ip_hash distribution (same as WolfRun's own LB logic).
/// This avoids DNAT'ing to the VIP which is a local route (kernel → INPUT → RST).
fn apply_vip_mapping_rules(
    m: &IpMapping,
    backends: &[String],
    lb_policy: &str,
    gateway_ip: &str,
    proto_args: &[String],
    src_port_args: &[String],
) -> Result<(), String> {
    let n = backends.len();
    let dest_port = m.dest_ports.as_ref().or(m.ports.as_ref())
        .map(|s| s.as_str()).unwrap_or("");

    let comment = format!("wolfstack-vip-map-{}", m.id);

    for chain in &["PREROUTING", "OUTPUT"] {
        for (i, backend) in backends.iter().enumerate() {
            let remaining = n - i;

            let mut args: Vec<String> = vec![
                "-t".into(), "nat".into(), "-A".into(), chain.to_string(),
                "-d".into(), m.public_ip.clone(),
            ];

            // Add protocol + port matching
            for a in proto_args { args.push(a.clone()); }
            for a in src_port_args { args.push(a.clone()); }

            // Distribution mode
            if remaining > 1 {
                if lb_policy == "ip_hash" {
                    let prob = 1.0 / remaining as f64;
                    args.extend_from_slice(&[
                        "-m".into(), "statistic".into(),
                        "--mode".into(), "random".into(),
                        "--probability".into(), format!("{:.6}", prob),
                    ]);
                } else {
                    // round_robin
                    args.extend_from_slice(&[
                        "-m".into(), "statistic".into(),
                        "--mode".into(), "nth".into(),
                        "--every".into(), remaining.to_string(),
                        "--packet".into(), "0".into(),
                    ]);
                }
            }

            // DNAT target — include dest port if specified
            let dnat_dest = if !dest_port.is_empty() {
                format!("{}:{}", backend, dest_port)
            } else {
                backend.clone()
            };

            args.extend_from_slice(&[
                "-j".into(), "DNAT".into(),
                "--to-destination".into(), dnat_dest,
                "-m".into(), "comment".into(),
                "--comment".into(), comment.clone(),
            ]);

            run_iptables_vec(&args)?;
        }
    }

    // SNAT + FORWARD for each backend
    for backend in backends {
        // SNAT
        let mut snat_args = vec![
            "-t".into(), "nat".into(), "-A".into(), "POSTROUTING".into(),
            "-d".into(), backend.clone(),
        ];
        for a in proto_args { snat_args.push(a.clone()); }
        snat_args.extend_from_slice(&[
            "-m".into(), "comment".into(), "--comment".into(), comment.clone(),
            "-j".into(), "SNAT".into(), "--to-source".into(), gateway_ip.to_string(),
        ]);
        run_iptables_vec(&snat_args)?;

        // FORWARD (insert at top)
        let mut fwd_args = vec![
            "-I".into(), "FORWARD".into(), "1".into(),
            "-d".into(), backend.clone(),
        ];
        for a in proto_args { fwd_args.push(a.clone()); }
        fwd_args.extend_from_slice(&[
            "-m".into(), "conntrack".into(), "--ctstate".into(), "DNAT".into(),
            "-m".into(), "comment".into(), "--comment".into(), comment.clone(),
            "-j".into(), "ACCEPT".into(),
        ]);
        run_iptables_vec(&fwd_args)?;
    }


    Ok(())
}

/// Run iptables with a Vec<String> of args
fn run_iptables_vec(args: &[String]) -> Result<(), String> {
    let str_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = Command::new("iptables")
        .args(&str_args)
        .output()
        .map_err(|e| format!("Failed to run iptables: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(format!("iptables {} failed: {}", str_args.join(" "), stderr));
    }
    Ok(())
}

/// Remove iptables rules for a mapping (best-effort, uses -D instead of -A)
fn remove_mapping_rules(m: &IpMapping) {
    let gateway_ip = detect_wolfnet_gateway_ip().unwrap_or_default();

    // Try VIP comment-based cleanup first (handles round-robin/ip_hash rules)
    let vip_comment = format!("wolfstack-vip-map-{}", m.id);
    let _removed_vip = remove_rules_by_comment(&vip_comment);

    // Also remove standard (non-VIP) rules
    let proto_args: Vec<String> = if m.protocol != "all" {
        vec!["-p".into(), m.protocol.clone()]
    } else {
        vec![]
    };

    let src_port_args: Vec<String> = if let Some(ref ports) = m.ports {
        if !ports.is_empty() && m.protocol != "all" {
            build_port_args(ports)
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    // Determine if port translation was used
    let has_port_translation = m.dest_ports.as_ref()
        .map(|dp| !dp.is_empty() && m.ports.as_ref().map(|sp| sp != dp).unwrap_or(true))
        .unwrap_or(false);

    // Best-effort removal — ignore errors
    if has_port_translation && m.dest_ports.as_ref().map(|dp| dp.contains(',')).unwrap_or(false) {
        // Multi-port translation: remove per-port rules
        let sp_list = parse_port_list(m.ports.as_deref().unwrap_or("")).unwrap_or_default();
        let dp_list = parse_port_list(m.dest_ports.as_deref().unwrap_or("")).unwrap_or_default();

        for (sp, dp) in sp_list.iter().zip(dp_list.iter()) {
            let sp_str = sp.to_string();
            let dp_str = dp.to_string();
            let per_src = vec!["--dport".into(), sp_str];
            let per_dest = vec!["--dport".into(), dp_str.clone()];
            let dnat_target = format!("{}:{}", m.wolfnet_ip, dp);

            let _ = run_iptables(&[
                "-t", "nat", "-D", "PREROUTING", "-d", &m.public_ip,
            ], &proto_args, &per_src, &["-j", "DNAT", "--to-destination", &dnat_target]);
            let _ = run_iptables(&[
                "-t", "nat", "-D", "OUTPUT", "-d", &m.public_ip,
            ], &proto_args, &per_src, &["-j", "DNAT", "--to-destination", &dnat_target]);
            let _ = run_iptables(&[
                "-t", "nat", "-D", "POSTROUTING", "-d", &m.wolfnet_ip,
            ], &proto_args, &per_dest, &["-j", "SNAT", "--to-source", &gateway_ip]);
            let _ = run_iptables(&[
                "-D", "FORWARD", "-d", &m.wolfnet_ip,
            ], &proto_args, &per_dest, &["-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"]);
        }
    } else {
        // Standard removal path
        let dnat_dest = if has_port_translation {
            format!("{}:{}", m.wolfnet_ip, m.dest_ports.as_ref().unwrap())
        } else {
            m.wolfnet_ip.clone()
        };

        let dest_port_args: Vec<String> = {
            let effective_ports = m.dest_ports.as_ref().or(m.ports.as_ref());
            if let Some(ports) = effective_ports {
                if !ports.is_empty() && m.protocol != "all" {
                    build_port_args(ports)
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        };

        let _ = run_iptables(&[
            "-t", "nat", "-D", "PREROUTING", "-d", &m.public_ip,
        ], &proto_args, &src_port_args, &["-j", "DNAT", "--to-destination", &dnat_dest]);

        let _ = run_iptables(&[
            "-t", "nat", "-D", "OUTPUT", "-d", &m.public_ip,
        ], &proto_args, &src_port_args, &["-j", "DNAT", "--to-destination", &dnat_dest]);

        let _ = run_iptables(&[
            "-t", "nat", "-D", "POSTROUTING", "-d", &m.wolfnet_ip,
        ], &proto_args, &dest_port_args, &["-j", "SNAT", "--to-source", &gateway_ip]);

        let _ = run_iptables(&[
            "-D", "FORWARD", "-d", &m.wolfnet_ip,
        ], &proto_args, &dest_port_args, &["-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"]);
    }

}

/// Remove all iptables rules matching a comment string (used for VIP cleanup)
fn remove_rules_by_comment(comment: &str) -> usize {
    // Delegate to the `-S` + delete-by-spec path (`purge_matching_lines`) using
    // the comment as the match marker. That gets us, for free, the hardening the
    // IP-based purge already has: deterministic on the nft backend (the old
    // `-L --line-numbers` scrape mis-rendered some matches there), immune to the
    // concurrent-edit (Docker) line-number TOCTOU that delete-by-number suffers,
    // O(N) instead of O(N²) when draining a large backlog, and runaway-capped.
    let mut removed = 0;
    let targets: &[(&str, &[&str])] = &[
        ("nat", &["PREROUTING", "OUTPUT", "POSTROUTING"]),
        ("filter", &["FORWARD"]),
    ];
    for &(table, chains) in targets {
        for &chain in chains {
            removed += purge_matching_lines(table, chain, &[comment]);
        }
    }
    removed
}

/// Run an iptables command with base args + protocol + port + tail args
/// Transform a rule's add-form `base` (which begins with `-A <chain>` or
/// `-I <chain> [pos]`, optionally prefixed by `-t <table>`) into its `-C`
/// check-existence form: `-A`/`-I` becomes `-C` and the numeric `-I` position is
/// dropped. The proto/port/tail match args are identical for check vs add, so the
/// caller appends them unchanged. Used to make rule application idempotent.
fn iptables_check_base(base: &[&str]) -> Vec<String> {
    let mut check: Vec<String> = Vec::with_capacity(base.len());
    let mut i = 0;
    while i < base.len() {
        match base[i] {
            "-A" | "-I" => {
                let is_insert = base[i] == "-I";
                check.push("-C".into());
                if i + 1 < base.len() { check.push(base[i + 1].into()); } // chain
                i += 2;
                // `-I <chain> <pos>` carries a numeric position the `-C` form omits.
                if is_insert && i < base.len() && base[i].parse::<u32>().is_ok() {
                    i += 1;
                }
            }
            other => { check.push(other.into()); i += 1; }
        }
    }
    check
}

fn run_iptables(base: &[&str], proto: &[String], port: &[String], tail: &[&str]) -> Result<(), String> {
    // IDEMPOTENT add: the reconciliation loop re-applies these mapping rules on
    // every tick. With a bare `-A`/`-I` that appended another identical rule each
    // pass, so PapaSchlumpf's FORWARD chain grew to ~4000 duplicate ACCEPT rules
    // and throttled the router (the kernel walks the whole chain per packet — a
    // reboot cleared it, then it grew back). Modify-in-place: build the `-C`
    // (check) form of the exact rule and only add what's actually missing, so a
    // steady reconcile is a no-op and rules never duplicate. (No purge churn.)
    let mut check: Vec<String> = iptables_check_base(base);
    for p in proto { check.push(p.clone()); }
    for p in port { check.push(p.clone()); }
    for t in tail { check.push((*t).to_string()); }

    // Rule already present → nothing to do.
    if Command::new("iptables").args(&check).output()
        .map(|o| o.status.success()).unwrap_or(false)
    {
        return Ok(());
    }

    let mut args: Vec<&str> = base.to_vec();
    for p in proto { args.push(p.as_str()); }
    for p in port { args.push(p.as_str()); }
    args.extend_from_slice(tail);

    let output = Command::new("iptables")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run iptables: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(format!("iptables {} failed: {}", args.join(" "), stderr));
    }
    Ok(())
}

/// Restore all IP mappings on startup, *and* re-run periodically from
/// the reconciliation loop in main.rs.
///
/// Returns the count of *enabled* mappings whose iptables rules failed
/// to apply on this pass. Non-zero means the reconciliation loop
/// should keep retrying — the most common cause is
/// `detect_wolfnet_gateway_ip()` returning None because wolfnet0
/// hasn't come up yet (typical right after a reboot, before WireGuard
/// finishes establishing the mesh and assigns the wolfnet0 address).
/// Before the reconciliation loop existed, that case silently dropped
/// every mapping on the floor and the operator only saw a `warn!` line
/// in journalctl — PapaSchlumpf's Frigate / Home Assistant
/// "mapped-but-unreachable" symptom.
///
/// Idempotent: `apply_mapping_rules` calls `purge_mapping_rules` first,
/// so re-running this function is safe even when all rules are already
/// in place. Steady-state cost is ~2 iptables ops per enabled mapping
/// per reconcile tick.
pub fn apply_ip_mappings() -> usize {
    // Enable IP forwarding
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");

    // Apply conntrack ESTABLISHED,RELATED rule (idempotent — check first)
    let existing = Command::new("iptables")
        .args(["-C", "FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        .output();
    if existing.map(|o| !o.status.success()).unwrap_or(true) {
        let _ = Command::new("iptables")
            .args(["-A", "FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
            .output();
    }

    let config = load_ip_mapping_config();
    let mut failed = 0usize;
    for mapping in &config.mappings {
        if !mapping.enabled { continue; }
        if let Err(e) = apply_mapping_rules(mapping) {
            warn!("Failed to apply IP mapping {} → {}: {}", mapping.public_ip, mapping.wolfnet_ip, e);
            failed += 1;
        }
    }
    failed
}

/// Periodic reconciliation: ensure NICs enslaved to `br-pt-*`
/// passthrough bridges don't carry a duplicate of any IP that's already
/// on the bridge.
///
/// `vms::manager::create_linux_passthrough_bridge` flushes the slave's
/// IP at bridge-creation time and then re-adds it on the bridge — but
/// external IP managers (NetworkManager, systemd-networkd, dhclient
/// running on the slave) often re-assign the IP to the slave shortly
/// after we flush it. Result: the same IP lives on the slave AND the
/// bridge, plus duplicate kernel routes for the same subnet via two
/// devices. The kernel resolves the route by some arbitrary tiebreak
/// and ARP gets confused.
///
/// PapaSchlumpf's box hit this on `ens1` (enslaved to `br-pt-ens1`):
/// both interfaces had `10.10.10.1/24`, with two routes for
/// `10.10.10.0/24`. The slave should be IP-less. This function cleans
/// up after the external manager every tick.
///
/// Safety: only removes IPs from the slave that ALSO exist on the
/// bridge (true duplicates). Never strips an IP that only exists on
/// the slave — that would leave the host without an address if the
/// migration to the bridge had failed.
pub fn cleanup_passthrough_slave_ips() {
    let entries = match std::fs::read_dir("/sys/class/net") {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let bridge = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if !bridge.starts_with("br-pt-") { continue; }

        let bridge_ips = iface_ipv4_cidrs(&bridge);
        if bridge_ips.is_empty() { continue; } // bridge has no IP — don't risk stripping the slave's

        let brif_path = format!("/sys/class/net/{}/brif", bridge);
        let slaves = match std::fs::read_dir(&brif_path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for slave_entry in slaves.flatten() {
            let slave = match slave_entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            for cidr in iface_ipv4_cidrs(&slave) {
                if !bridge_ips.contains(&cidr) { continue; } // not a duplicate
                let res = Command::new("ip")
                    .args(["addr", "del", &cidr, "dev", &slave])
                    .output();
                if res.map(|o| o.status.success()).unwrap_or(false) {
                    info!(
                        "Passthrough cleanup: removed duplicate {} from {} (already on bridge {})",
                        cidr, slave, bridge
                    );
                }
            }
        }
    }
}

/// Return all IPv4 addresses (in `addr/prefix` form) currently bound to
/// the given interface. Helper for `cleanup_passthrough_slave_ips`.
fn iface_ipv4_cidrs(iface: &str) -> Vec<String> {
    let out = match Command::new("ip").args(["-4", "addr", "show", "dev", iface]).output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .filter_map(|l| {
            let l = l.trim_start();
            if !l.starts_with("inet ") { return None; }
            l.split_whitespace().nth(1).map(|s| s.to_string())
        })
        .collect()
}

/// Detect this node's WolfNet IP address (for SNAT source)
pub fn detect_wolfnet_gateway_ip() -> Option<String> {
    let interfaces = list_interfaces();
    for iface in &interfaces {
        if (iface.name.starts_with("wn") || iface.name.starts_with("wolfnet"))
            && let Some(addr) = iface.addresses.iter().find(|a| a.family == "inet") {
                return Some(addr.address.clone());
            }
    }
    None
}

/// Check whether a WolfNet IP is reachable from this host — used by the
/// IP-mapping create/update flow to catch the case where someone maps to
/// a VM on a remote cluster node that isn't actually reachable over
/// WolfNet (stale route cache, WireGuard peer down, VM not yet booted,
/// etc.). Without this probe, `add_ip_mapping` silently writes DNAT
/// rules that black-hole traffic and the operator has no idea why the
/// mapping doesn't work.
///
/// Returns one of:
///   - "local"       — target IS this host's own WolfNet IP
///   - "reachable"   — ping over WolfNet succeeded
///   - "unreachable" — ping failed (WolfNet routing broken, or target down)
///   - "no_wolfnet"  — this host has no WolfNet interface at all
pub fn check_wolfnet_reachability(ip: &str) -> &'static str {
    let gw = detect_wolfnet_gateway_ip();
    if gw.is_none() { return "no_wolfnet"; }
    if gw.as_deref() == Some(ip) { return "local"; }

    match Command::new("ping")
        .args(["-c", "1", "-W", "1", ip])
        .output()
    {
        Ok(o) if o.status.success() => "reachable",
        _ => "unreachable",
    }
}

/// Detect the best reachable LAN IP for this node.
/// Returns the first private (RFC1918) IPv4 address found on a real interface,
/// skipping loopback, docker, wolfnet, veth, and bridge interfaces.
/// Used when the node is bound to 0.0.0.0 or 127.0.0.1 and we need a real
/// endpoint for WolfNet peers to connect to.
pub fn detect_lan_ip() -> Option<String> {
    let interfaces = list_interfaces();
    for iface in &interfaces {
        if iface.name == "lo" || iface.name.starts_with("docker")
            || iface.name.starts_with("br-") || iface.name.starts_with("veth")
            || iface.name.starts_with("wn") || iface.name.starts_with("wolfnet")
            || iface.name.starts_with("virbr")
        {
            continue;
        }
        for addr in &iface.addresses {
            if addr.family == "inet"
                && let Ok(ip) = addr.address.parse::<std::net::Ipv4Addr>()
                    && is_private_ip(ip) && !ip.is_loopback() {
                        return Some(addr.address.clone());
                    }
        }
    }
    None
}

/// ALL non-loopback private IPv4 addresses on real interfaces (same interface
/// exclusions as `detect_lan_ip`), sorted for a stable order. `detect_lan_ip`
/// returns only the FIRST private IP, which on a Proxmox host with many bridges
/// (vmbr*, fwbr*, tap*, …) is not reliably the cluster-LAN one and can vary
/// between calls — that flapped the cluster-sync's chosen WolfNet endpoint
/// between the LAN IP and the public IP. Callers that know which subnet they
/// want should enumerate these and pick the match deterministically
/// (wabil 2026-06-27).
pub fn local_lan_ips() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for iface in &list_interfaces() {
        if iface.name == "lo" || iface.name.starts_with("docker")
            || iface.name.starts_with("br-") || iface.name.starts_with("veth")
            || iface.name.starts_with("wn") || iface.name.starts_with("wolfnet")
            || iface.name.starts_with("virbr")
        {
            continue;
        }
        for addr in &iface.addresses {
            if addr.family == "inet"
                && let Ok(ip) = addr.address.parse::<std::net::Ipv4Addr>()
                && is_private_ip(ip) && !ip.is_loopback()
                && !out.contains(&addr.address)
            {
                out.push(addr.address.clone());
            }
        }
    }
    out.sort();
    out
}

/// Detect public (non-RFC1918) IPs on all interfaces
pub fn detect_public_ips() -> Vec<String> {
    let mut public_ips = Vec::new();
    let interfaces = list_interfaces();
    for iface in &interfaces {
        // Skip loopback, docker, wolfnet, veth
        if iface.name == "lo" || iface.name.starts_with("docker")
            || iface.name.starts_with("br-") || iface.name.starts_with("veth")
            || iface.name.starts_with("wn") || iface.name.starts_with("wolfnet")
            || iface.name.starts_with("virbr")
        {
            continue;
        }
        for addr in &iface.addresses {
            if addr.family == "inet"
                && let Ok(ip) = addr.address.parse::<std::net::Ipv4Addr>()
                    && !is_private_ip(ip) {
                        public_ips.push(addr.address.clone());
                    }
        }
    }
    public_ips
}

/// Collect every CIDR on this node that represents a *workload* network —
/// Docker bridges (`docker0`, `br-*`), LXC bridges (`lxcbr*`), KVM/libvirt
/// bridges (`virbr*`), and the passthrough bridges that VMs sit on
/// (`br-pt-*`). The set returned is what remote WolfNet peers need
/// subnet_routes for so traffic to "the VMs behind klnet-12gb" actually
/// reaches them rather than dropping at the wolfnet edge.
///
/// Klas 2026-05-11: his cluster peers can ping each other's WolfNet IPs
/// but can't ping VMs / containers / LXC instances behind those peers
/// because nobody has manually configured subnet_routes for those
/// workload subnets. This function is the data source the cluster gossip
/// then ships round, and the missing-route analyzer consumes.
///
/// Skips:
///   • `lo`, `enp*`/`eth*`/`eno*`/`wlp*` (host uplinks, not workloads)
///   • `wolfnet*` / `wn*` (the overlay itself)
///   • IPv6 addresses (subnet_routes are IPv4 today)
///   • Interfaces with no addresses
///   • Duplicate CIDRs
pub fn collect_workload_subnets() -> Vec<String> {
    // Cache for 30s — workload subnets change only when a Docker / LXC /
    // libvirt bridge is created or destroyed, not on the per-second
    // cluster-poll cadence. Without this cache, a 14-node cluster polls
    // each peer every ~10s, each `/api/agent/status` invokes
    // `collect_workload_subnets`, each call shells out to `ip -j addr
    // show` and parses JSON — ~15-30 ms per call × 18 calls/sec across
    // the cluster = visibly degraded dashboard responsiveness on real
    // clusters (klasSponsor / paulc 2026-05-11).
    use std::sync::Mutex;
    use std::time::Instant;
    static CACHE: Mutex<Option<(Instant, Vec<String>)>> = Mutex::new(None);
    if let Ok(guard) = CACHE.lock()
        && let Some((ts, ref cached)) = *guard
            && ts.elapsed().as_secs() < 30 {
                return cached.clone();
            }
    let fresh = collect_workload_subnets_uncached();
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some((Instant::now(), fresh.clone()));
    }
    fresh
}

fn collect_workload_subnets_uncached() -> Vec<String> {
    use std::collections::BTreeSet;
    let mut out: BTreeSet<String> = BTreeSet::new();
    for iface in list_interfaces() {
        let name = iface.name.as_str();
        let is_workload =
            name.starts_with("docker")
            || name.starts_with("lxcbr")
            || name.starts_with("br-")     // Docker user-defined bridges (br-<id>) + br-pt-*
            || name.starts_with("virbr");  // libvirt
        if !is_workload { continue; }
        for addr in &iface.addresses {
            match addr.family.as_str() {
                "inet" => {
                    // Derive the network address from address + prefix so two
                    // containers on the same /24 don't each contribute their
                    // own /32.
                    let ip = match addr.address.parse::<std::net::Ipv4Addr>() {
                        Ok(ip) => ip,
                        Err(_) => continue,
                    };
                    let prefix = addr.prefix.min(32);
                    let mask: u32 = if prefix == 0 { 0 }
                        else { 0xFFFF_FFFFu32.checked_shl(32 - prefix).unwrap_or(0) };
                    let net = u32::from(ip) & mask;
                    let net_ip = std::net::Ipv4Addr::from(net);
                    out.insert(format!("{}/{}", net_ip, prefix));
                }
                "inet6" => {
                    // v6 container bridges (Docker fixed-cidr-v6 ULA, LXC RA
                    // prefixes) need the same never-block exemption as v4.
                    let ip = match addr.address.parse::<std::net::Ipv6Addr>() {
                        Ok(ip) => ip,
                        Err(_) => continue, // zone-scoped forms don't parse — skip
                    };
                    // SKIP link-local (fe80::/10): every interface carries the
                    // same fe80::/64, so protecting it would make ANY
                    // link-local source — including a LAN attacker on the same
                    // L2 — permanently unblockable. Loopback never appears on
                    // a bridge; skip it defensively anyway.
                    if ip.is_loopback() || (ip.segments()[0] & 0xffc0) == 0xfe80 {
                        continue;
                    }
                    let prefix = addr.prefix.min(128);
                    if prefix == 0 { continue; } // never emit ::/0
                    let mask: u128 = if prefix == 128 { u128::MAX }
                        else { u128::MAX.checked_shl(128 - prefix).unwrap_or(0) };
                    let net_ip = std::net::Ipv6Addr::from(u128::from(ip) & mask);
                    out.insert(format!("{}/{}", net_ip, prefix));
                }
                _ => {}
            }
        }
    }
    out.into_iter().collect()
}

/// Check if an IPv4 address is RFC1918 private (plus loopback and link-local).
/// Pub so predictive analyzers can flag the case where a peer's endpoint
/// is a private address but the local node has only public addresses —
/// klasSponsor 2026-05-11 hit exactly that: peer endpoint `10.10.10.30:9630`
/// advertised from a LAN node, then klas's public VPS faithfully sent
/// handshake UDP to 10.10.10.30 which doesn't exist on the internet.
pub fn is_private_ip(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    if octets[0] == 10 { return true; }
    if octets[0] == 172 && (16..=31).contains(&octets[1]) { return true; }
    if octets[0] == 192 && octets[1] == 168 { return true; }
    if octets[0] == 127 || (octets[0] == 169 && octets[1] == 254) { return true; }
    false
}

/// Extract the host portion (IPv4 or hostname) from an endpoint string
/// of the form `host:port` or `[v6]:port`. Returns None for empty input.
/// Used by the reachability analyzer to classify peer endpoints by RFC1918
/// scope without taking on a full URL/socket parsing dependency.
pub fn endpoint_host(endpoint: &str) -> Option<&str> {
    let s = endpoint.trim();
    if s.is_empty() { return None; }
    // IPv6 bracketed form
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') { return Some(&rest[..end]); }
        return None;
    }
    // host:port (split on the LAST colon; IPv4 host has no other colons)
    match s.rfind(':') {
        Some(idx) => Some(&s[..idx]),
        None => Some(s),
    }
}

/// Collect WolfNet IPs in use (peers + this node)
pub fn detect_wolfnet_ips() -> Vec<serde_json::Value> {
    let mut ips = Vec::new();

    // This node's WolfNet IP
    if let Some(gw) = detect_wolfnet_gateway_ip() {
        ips.push(serde_json::json!({ "ip": gw, "source": "this-node (gateway)" }));
    }

    // Peers from config
    let peers = get_wolfnet_peers();
    for peer in &peers {
        let ip = peer.ip.split('/').next().unwrap_or(&peer.ip).to_string();
        if !ip.is_empty() {
            ips.push(serde_json::json!({ "ip": ip, "source": format!("peer: {}", peer.name) }));
        }
    }

    // Docker containers with WolfNet IPs (label wolfnet.ip)
    if let Ok(output) = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}|{{.Label \"wolfnet.ip\"}}"])
        .output()
        && output.status.success() {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let parts: Vec<&str> = line.splitn(2, '|').collect();
                if parts.len() == 2 {
                    let name = parts[0].trim();
                    let wip = parts[1].trim();
                    if !wip.is_empty() && wip != "<no value>"
                        && wip.parse::<std::net::Ipv4Addr>().is_ok() {
                            ips.push(serde_json::json!({
                                "ip": wip,
                                "source": format!("docker: {}", name)
                            }));
                        }
                }
            }
        }

    // LXC containers with WolfNet IPs — scan all registered storage paths
    for lxc_path in crate::containers::lxc_storage_paths() {
        if let Ok(entries) = std::fs::read_dir(&lxc_path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let ip_file = entry.path().join(".wolfnet/ip");
                if let Ok(ip) = std::fs::read_to_string(&ip_file) {
                    let ip = ip.trim().to_string();
                    if !ip.is_empty() && ip.parse::<std::net::Ipv4Addr>().is_ok() {
                        ips.push(serde_json::json!({
                            "ip": ip,
                            "source": format!("lxc: {}", name)
                        }));
                    }
                }
            }
        }
    }

    // Proxmox LXC containers — check pct configs for wn0 IPs
    if std::path::Path::new("/etc/pve").exists()
        && let Ok(entries) = std::fs::read_dir("/etc/pve/lxc") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "conf").unwrap_or(false) {
                    let vmid = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
                    if let Ok(conf) = std::fs::read_to_string(&path) {
                        for line in conf.lines() {
                            // net lines look like: net1: name=wn0,bridge=lxcbr0,ip=x.x.x.x/24,...
                            if line.contains("name=wn0")
                                && let Some(ip_part) = line.split(',').find(|p| p.starts_with("ip=")) {
                                    let ip = ip_part.trim_start_matches("ip=")
                                        .split('/')
                                        .next()
                                        .unwrap_or("")
                                        .to_string();
                                    if !ip.is_empty() && ip.parse::<std::net::Ipv4Addr>().is_ok() {
                                        ips.push(serde_json::json!({
                                            "ip": ip,
                                            "source": format!("pve-lxc: CT{}", vmid)
                                        }));
                                    }
                                }
                        }
                    }
                }
            }
        }

    // Remote container/VIP IPs from the WolfNet routes cache
    let routes = crate::containers::WOLFNET_ROUTES.lock().unwrap().clone();
    for (container_ip, gateway_ip) in &routes {
        if container_ip.parse::<std::net::Ipv4Addr>().is_ok() {
            ips.push(serde_json::json!({
                "ip": container_ip,
                "source": format!("remote via {}", gateway_ip)
            }));
        }
    }

    // De-duplicate by IP
    let mut seen = std::collections::HashSet::new();
    ips.retain(|v| {
        let ip = v["ip"].as_str().unwrap_or("").to_string();
        seen.insert(ip)
    });

    ips
}

/// Simple random ID generator
fn rand_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (nanos as u64) ^ (std::process::id() as u64) ^ 0xdeadbeef
}

// ─── WireGuard Bridge ──────────────────────────────────────────────────────
//
// Provides VPN access to WolfNet overlay networks from external clients.
// Each cluster gets a unique WireGuard bridge subnet (10.20.X.0/24) with
// NAT bridging into the actual WolfNet subnet — allowing simultaneous
// connections to multiple clusters without IP conflicts.

const WG_BRIDGE_CONFIG: &str = "/etc/wolfstack/wireguard-bridge.json";

/// WireGuard bridge configuration for a single cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardBridge {
    pub cluster: String,
    pub enabled: bool,
    pub listen_port: u16,
    pub private_key: String,
    pub public_key: String,
    /// Third octet for bridge subnet, e.g. 1 → 10.20.1.0/24
    pub bridge_octet: u8,
    pub server_ip: String,
    /// WolfNet subnet prefix, e.g. "10.0.10"
    #[serde(default)]
    pub wolfnet_subnet: String,
    #[serde(default)]
    pub clients: Vec<WireGuardClient>,
}

/// A WireGuard client (external user) connected via the bridge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardClient {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub private_key: String,
    pub assigned_ip: String,
    pub created_at: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool { true }

impl WireGuardBridge {
    /// Interface name for this bridge (e.g. "wg-prod")
    pub fn interface_name(&self) -> String {
        // ASCII-only: is_alphanumeric() accepts Unicode letters, but the kernel's
        // dev_valid_name rejects them — a cluster named e.g. "kläs" would pass the
        // filter yet fail `ip link add`. Restrict to chars valid in an iface name.
        let safe: String = self.cluster.chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(12)
            .collect();
        format!("wg-{}", if safe.is_empty() { "bridge".to_string() } else { safe })
    }

    /// Full bridge subnet CIDR (e.g. "10.20.1.0/24")
    pub fn bridge_subnet(&self) -> String {
        format!("10.20.{}.0/24", self.bridge_octet)
    }
}

/// Check if WireGuard tools are installed
pub fn wireguard_installed() -> bool {
    Command::new("which").arg("wg")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Attempt to install wireguard-tools for the current distro
pub fn install_wireguard_tools() -> Result<String, String> {
    // Detect distro
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let id = os_release.lines()
        .find(|l| l.starts_with("ID="))
        .map(|l| l.trim_start_matches("ID=").trim_matches('"').to_lowercase())
        .unwrap_or_default();
    let id_like = os_release.lines()
        .find(|l| l.starts_with("ID_LIKE="))
        .map(|l| l.trim_start_matches("ID_LIKE=").trim_matches('"').to_lowercase())
        .unwrap_or_default();

    let (cmd, args): (&str, Vec<&str>) = if id == "ubuntu" || id == "debian" || id_like.contains("debian") {
        ("apt", vec!["install", "-y", "wireguard-tools"])
    } else if id == "fedora" || id_like.contains("fedora") || id_like.contains("rhel") {
        ("dnf", vec!["install", "-y", "wireguard-tools"])
    } else if id == "centos" || id == "rhel" || id_like.contains("centos") {
        ("yum", vec!["install", "-y", "wireguard-tools"])
    } else if id == "opensuse" || id == "sles" || id_like.contains("suse") {
        ("zypper", vec!["install", "-y", "wireguard-tools"])
    } else {
        return Err(format!("Unsupported distro '{}' — install wireguard-tools manually", id));
    };

    let output = Command::new(cmd).args(&args).output()
        .map_err(|e| format!("Failed to run {}: {}", cmd, e))?;

    if output.status.success() {
        Ok("wireguard-tools installed".to_string())
    } else {
        Err(format!("Package install failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

/// Load all WireGuard bridge configs from disk
pub fn load_wireguard_bridges() -> std::collections::HashMap<String, WireGuardBridge> {
    match std::fs::read_to_string(WG_BRIDGE_CONFIG) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => std::collections::HashMap::new(),
    }
}

/// Save all WireGuard bridge configs to disk
pub fn save_wireguard_bridges(bridges: &std::collections::HashMap<String, WireGuardBridge>) -> Result<(), String> {
    let json = serde_json::to_string_pretty(bridges)
        .map_err(|e| format!("Failed to serialize WireGuard config: {}", e))?;
    std::fs::write(WG_BRIDGE_CONFIG, json)
        .map_err(|e| format!("Failed to write {}: {}", WG_BRIDGE_CONFIG, e))
}

/// The live in-memory bridge map (the one AppState serves requests from).
/// Registered once at startup so disk-side mutations made outside an HTTP
/// handler — the cluster-rename re-key below, which can fire from the gossip
/// poll loop with no AppState in reach — can refresh it. Without the refresh
/// the renamed bridge 404s under its new cluster name until restart.
static WG_BRIDGES_SHARED: std::sync::OnceLock<
    std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, WireGuardBridge>>>,
> = std::sync::OnceLock::new();

pub fn register_shared_wireguard_bridges(
    map: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, WireGuardBridge>>>,
) {
    let _ = WG_BRIDGES_SHARED.set(map);
}

/// Re-key a cluster's WireGuard bridge when the WolfStack cluster is renamed
/// (case-insensitive). No-op if a bridge already exists under the new name —
/// renaming must never clobber an existing bridge. Returns 1 if moved.
pub fn rename_wireguard_bridge_cluster(old_name: &str, new_name: &str) -> usize {
    let mut bridges = load_wireguard_bridges();
    let old_key = match bridges.keys().find(|k| k.eq_ignore_ascii_case(old_name)).cloned() {
        Some(k) => k,
        None => return 0,
    };
    if bridges.keys().any(|k| k.eq_ignore_ascii_case(new_name)) {
        tracing::warn!(
            "cluster rename: WireGuard bridge for '{}' NOT re-keyed — a bridge already exists for '{}'",
            old_key, new_name
        );
        return 0;
    }
    if let Some(mut b) = bridges.remove(&old_key) {
        b.cluster = new_name.to_string();
        bridges.insert(new_name.to_string(), b.clone());
        let _ = save_wireguard_bridges(&bridges);
        // Keep the live request-serving map in step with the disk write.
        if let Some(shared) = WG_BRIDGES_SHARED.get() {
            let mut live = shared.write().unwrap_or_else(|e| e.into_inner());
            live.remove(&old_key);
            live.insert(new_name.to_string(), b);
        }
        return 1;
    }
    0
}

/// Initialize a WireGuard bridge for a cluster
pub fn init_wireguard_bridge(cluster: &str, listen_port: u16) -> Result<WireGuardBridge, String> {
    // Install wireguard-tools if needed
    if !wireguard_installed() {
        install_wireguard_tools()?;
        if !wireguard_installed() {
            return Err("wireguard-tools installation failed — 'wg' not found".to_string());
        }
    }

    let mut bridges = load_wireguard_bridges();

    // Idempotent: a config record already exists for this cluster. Rather than
    // hard-erroring (which left klasSponsor 2026-06-18 stuck — "bridge already
    // exists" with NOTHING in the WireGuard UI to view or remove, because a
    // prior create saved to disk then failed mid-apply, so the live/UI map never
    // received it while the wg-<cluster> iface lingered in Networking), re-apply
    // the existing config (apply is idempotent) and return it. The API handler
    // then refreshes the live map from disk, so the bridge reappears in the UI
    // and becomes manageable/removable again.
    if let Some(existing) = bridges.get(cluster).cloned() {
        apply_wireguard_bridge(&existing)?;
        return Ok(existing);
    }

    // Check port not already in use by another bridge
    for (name, b) in &bridges {
        if b.listen_port == listen_port {
            return Err(format!("Port {} already in use by cluster '{}'", listen_port, name));
        }
    }

    // Generate server keypair
    let priv_key = wg_genkey()?;
    let pub_key = wg_pubkey(&priv_key)?;

    // Auto-assign bridge octet (1, 2, 3, ...)
    let used_octets: Vec<u8> = bridges.values().map(|b| b.bridge_octet).collect();
    let octet = (1u8..=254).find(|o| !used_octets.contains(o))
        .ok_or("No available bridge subnets (all 254 in use)")?;

    // Detect WolfNet subnet
    let wolfnet_subnet = detect_wolfnet_subnet().unwrap_or_else(|| "10.0.10".to_string());

    let bridge = WireGuardBridge {
        cluster: cluster.to_string(),
        enabled: true,
        listen_port,
        private_key: priv_key,
        public_key: pub_key,
        bridge_octet: octet,
        server_ip: format!("10.20.{}.1/24", octet),
        wolfnet_subnet,
        clients: Vec::new(),
    };

    // Apply the interface FIRST. If apply fails we must NOT leave a phantom
    // config record on disk — that's the half-state that blocks every future
    // create ("already exists") while the bridge is unusable and invisible in
    // the UI (klasSponsor 2026-06-18). Only persist once the kernel/wg side is
    // actually up.
    apply_wireguard_bridge(&bridge)?;

    bridges.insert(cluster.to_string(), bridge.clone());
    save_wireguard_bridges(&bridges)?;

    Ok(bridge)
}

/// Add a client to a cluster's WireGuard bridge
pub fn add_wireguard_client(cluster: &str, name: &str) -> Result<(WireGuardClient, String), String> {
    let mut bridges = load_wireguard_bridges();
    let bridge = bridges.get_mut(cluster)
        .ok_or(format!("No WireGuard bridge for cluster '{}'", cluster))?;

    // Check name uniqueness
    if bridge.clients.iter().any(|c| c.name == name) {
        return Err(format!("Client '{}' already exists", name));
    }

    // Generate client keypair
    let priv_key = wg_genkey()?;
    let pub_key = wg_pubkey(&priv_key)?;

    // Assign next available IP (.2, .3, .4, ...)
    let used_hosts: Vec<u8> = bridge.clients.iter()
        .filter_map(|c| {
            c.assigned_ip.split('.').nth(3)
                .and_then(|s| s.split('/').next())
                .and_then(|s| s.parse::<u8>().ok())
        })
        .collect();
    let host = (2u8..=254).find(|h| !used_hosts.contains(h))
        .ok_or("No available client IPs in bridge subnet")?;

    let client = WireGuardClient {
        id: format!("{:016x}", rand_id()),
        name: name.to_string(),
        public_key: pub_key,
        private_key: priv_key,
        assigned_ip: format!("10.20.{}.{}/32", bridge.bridge_octet, host),
        created_at: chrono_now(),
        enabled: true,
    };

    // Generate the .conf content before adding to bridge (need bridge data)
    let conf = generate_client_config(bridge, &client)?;

    bridge.clients.push(client.clone());
    save_wireguard_bridges(&bridges)?;

    // Apply the peer to the live interface
    let bridge_ref = bridges.get(cluster).unwrap();
    let _ = wg_set_peer(bridge_ref, &client);

    Ok((client, conf))
}

/// Remove a client from a cluster's WireGuard bridge
pub fn remove_wireguard_client(cluster: &str, client_id: &str) -> Result<String, String> {
    let mut bridges = load_wireguard_bridges();
    let bridge = bridges.get_mut(cluster)
        .ok_or(format!("No WireGuard bridge for cluster '{}'", cluster))?;

    let idx = bridge.clients.iter().position(|c| c.id == client_id)
        .ok_or(format!("Client '{}' not found", client_id))?;

    let client = bridge.clients.remove(idx);

    // Remove from live interface
    let _ = Command::new("wg")
        .args(["set", &bridge.interface_name(), "peer", &client.public_key, "remove"])
        .output();

    save_wireguard_bridges(&bridges)?;
    Ok(format!("Client '{}' removed", client.name))
}

/// Get a client's .conf content (for re-download)
pub fn get_client_config(cluster: &str, client_id: &str) -> Result<String, String> {
    let bridges = load_wireguard_bridges();
    let bridge = bridges.get(cluster)
        .ok_or(format!("No WireGuard bridge for cluster '{}'", cluster))?;
    let client = bridge.clients.iter().find(|c| c.id == client_id)
        .ok_or(format!("Client '{}' not found", client_id))?;
    generate_client_config(bridge, client)
}

/// Generate the WireGuard client .conf file content
fn generate_client_config(bridge: &WireGuardBridge, client: &WireGuardClient) -> Result<String, String> {
    // Detect the server's public/reachable IP for the Endpoint field
    let server_endpoint = detect_server_endpoint(bridge.listen_port);

    // AllowedIPs covers BOTH the bridge subnet (used by NETMAP-style
    // 1:1 translation — `ping 10.20.X.5` reaches wolfnet `.5`) AND
    // the raw WolfNet subnet so the operator can also address
    // wolfnet IPs directly (`ping 10.0.10.5`). Without the wolfnet
    // entry the phone OS doesn't route those addresses through the
    // tunnel at all, leaving the operator wondering why it doesn't
    // work — which is exactly the bug Klas hit (2026-05-08).
    //
    // Trade-off: if an operator runs MULTIPLE WolfStack clusters
    // whose wolfnet subnets overlap (default 10.0.10.0/24 is the
    // same on every fresh install) and adds peers on the SAME phone
    // for each one, the second tunnel's AllowedIPs would conflict
    // with the first. Multi-cluster road-warrior is rare; document
    // it in the .conf comments so anyone hitting it can switch to
    // bridge-only by hand.
    let bridge_sub = bridge.bridge_subnet();
    let wn_sub = format!("{}.0/24", bridge.wolfnet_subnet);
    let allowed_ips = if !bridge.wolfnet_subnet.is_empty() {
        format!("{}, {}", bridge_sub, wn_sub)
    } else {
        bridge_sub.clone()
    };

    Ok(format!(
        "# WolfStack WireGuard Bridge — Cluster: {cluster}\n\
         # Client: {name}\n\
         # Generated: {date}\n\
         #\n\
         # Bridge subnet {bridge_sub} maps to WolfNet {wn_sub}.\n\
         # Either form reaches the same host:\n\
         #   ping {bridge_prefix}.5      (NETMAP-translated to wolfnet)\n\
         #   ping {wn_prefix}.5      (direct wolfnet routing)\n\
         #\n\
         # If you peer THIS phone to multiple WolfStack clusters and\n\
         # they share the wolfnet subnet, remove the wolfnet entry\n\
         # from AllowedIPs below to avoid routing conflicts.\n\
         \n\
         [Interface]\n\
         PrivateKey = {priv_key}\n\
         Address = {addr}\n\
         \n\
         [Peer]\n\
         PublicKey = {pub_key}\n\
         Endpoint = {endpoint}\n\
         AllowedIPs = {allowed}\n\
         PersistentKeepalive = 25\n",
        cluster = bridge.cluster,
        name = client.name,
        date = &chrono_now()[..10],
        bridge_sub = bridge_sub,
        bridge_prefix = format!("10.20.{}", bridge.bridge_octet),
        wn_sub = wn_sub,
        wn_prefix = bridge.wolfnet_subnet,
        priv_key = client.private_key,
        addr = client.assigned_ip,
        pub_key = bridge.public_key,
        endpoint = server_endpoint,
        allowed = allowed_ips,
    ))
}

/// Enable or disable a WireGuard bridge
pub fn toggle_wireguard_bridge(cluster: &str, enabled: bool) -> Result<String, String> {
    let mut bridges = load_wireguard_bridges();
    let bridge = bridges.get_mut(cluster)
        .ok_or(format!("No WireGuard bridge for cluster '{}'", cluster))?;

    bridge.enabled = enabled;
    let bridge_clone = bridge.clone();
    save_wireguard_bridges(&bridges)?;

    if enabled {
        apply_wireguard_bridge(&bridge_clone)?;
        Ok("Bridge enabled".to_string())
    } else {
        teardown_wireguard_bridge(cluster)?;
        Ok("Bridge disabled".to_string())
    }
}

/// Delete a WireGuard bridge entirely
pub fn delete_wireguard_bridge(cluster: &str) -> Result<String, String> {
    let mut bridges = load_wireguard_bridges();
    if bridges.remove(cluster).is_none() {
        return Err(format!("No WireGuard bridge for cluster '{}'", cluster));
    }
    let _ = teardown_wireguard_bridge(cluster);
    save_wireguard_bridges(&bridges)?;
    Ok(format!("Bridge for cluster '{}' deleted", cluster))
}

/// Create/configure the WireGuard interface, add all peers, set up NAT
pub fn apply_wireguard_bridge(bridge: &WireGuardBridge) -> Result<(), String> {
    let iface = bridge.interface_name();

    // Does the interface already exist? If so this is a re-apply (idempotent
    // startup/refresh path) and we must NOT delete it on a transient failure —
    // it may be a perfectly good live bridge. If it does NOT exist we are
    // creating it fresh, so we own cleanup-on-failure.
    let exists = Command::new("ip").args(["link", "show", &iface]).output()
        .map(|o| o.status.success()).unwrap_or(false);

    if !exists {
        // Guard against the cryptic "ip link set up: Address already in use".
        // WolfNet is itself WireGuard, and a prior half-applied bridge can
        // linger holding the UDP port, so surface a clear, actionable error
        // before we even create the interface.
        if udp_port_in_use(bridge.listen_port) {
            return Err(format!(
                "UDP port {} is already in use on this host (WolfNet or another \
                 WireGuard bridge may be using it) — choose a different WireGuard listen port",
                bridge.listen_port
            ));
        }
        run_cmd("ip", &["link", "add", &iface, "type", "wireguard"])?;
    }

    // Run the configuration steps; on failure of a freshly-created iface, tear
    // it down so the lingering device doesn't hold the listen-port and block
    // the next retry with "Address already in use".
    let result = apply_wireguard_bridge_inner(bridge, &iface);
    if result.is_err() && !exists {
        let _ = Command::new("ip").args(["link", "set", &iface, "down"]).output();
        let _ = Command::new("ip").args(["link", "delete", &iface]).output();
    }
    result
}

/// Configure an already-created WireGuard interface (key, port, IP, peers, NAT).
fn apply_wireguard_bridge_inner(bridge: &WireGuardBridge, iface: &str) -> Result<(), String> {
    // Tell NetworkManager to ignore WireGuard and WolfNet interfaces — on
    // Fedora/RHEL desktops NM tries to manage them, messes with routing
    // metrics, and causes slow/broken connectivity on WiFi.
    ensure_nm_unmanaged();
    let _ = Command::new("nmcli")
        .args(["device", "set", iface, "managed", "no"])
        .output();

    // Set private key + listen port. The key is fed on a pipe via /dev/stdin
    // so it never touches disk: the old /tmp/wg-<iface>-key staging file failed
    // with "fopen: Permission denied" on hardened hosts (SELinux/AppArmor or a
    // restrictively-mounted /tmp denied wg reading even a root-owned 0600 file).
    // The stdin pattern is already proven by wg_pubkey() above.
    wg_set_private_key(iface, &bridge.private_key, bridge.listen_port)?;

    // Set IP address (flush first to avoid duplicates)
    let _ = Command::new("ip").args(["addr", "flush", "dev", iface]).output();
    run_cmd("ip", &["addr", "add", &bridge.server_ip, "dev", iface])?;

    // Bring up
    run_cmd("ip", &["link", "set", iface, "up"])?;

    // Clamp MTU to 1280. The kernel default (1420) blackholes large response
    // packets behind PMTUD-broken paths (notably iPhone-over-cellular): pings
    // work but bulk HTTP/SSH silently stalls. 1280 is the IPv6 minimum and
    // safely under any WireGuard overhead, so it's a robust floor.
    let _ = Command::new("ip").args(["link", "set", iface, "mtu", "1280"]).output();

    // Add all enabled client peers
    for client in &bridge.clients {
        if client.enabled {
            let _ = wg_set_peer(bridge, client);
        }
    }

    // Set up NAT/forwarding rules
    setup_bridge_nat(bridge)?;

    Ok(())
}

/// Remove WireGuard interface and NAT rules for a cluster
pub fn teardown_wireguard_bridge(cluster: &str) -> Result<(), String> {
    let bridges = load_wireguard_bridges();
    if let Some(bridge) = bridges.get(cluster) {
        let iface = bridge.interface_name();
        let _ = Command::new("ip").args(["link", "set", &iface, "down"]).output();
        let _ = Command::new("ip").args(["link", "delete", &iface]).output();
        cleanup_bridge_nat(bridge);
    }
    Ok(())
}

/// Re-apply all enabled bridges (called on startup)
pub fn apply_all_wireguard_bridges() {
    let bridges = load_wireguard_bridges();
    for (cluster, bridge) in &bridges {
        if bridge.enabled
            && let Err(e) = apply_wireguard_bridge(bridge) {
                warn!("Failed to apply WireGuard bridge for cluster '{}': {}", cluster, e);
            }
    }
}

// ─── WireGuard helpers ──────────────────────────────────────────────────────

/// Generate a WireGuard private key
fn wg_genkey() -> Result<String, String> {
    let output = Command::new("wg").arg("genkey").output()
        .map_err(|e| format!("wg genkey failed: {}", e))?;
    if !output.status.success() {
        return Err("wg genkey failed".to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Derive public key from a private key
fn wg_pubkey(private_key: &str) -> Result<String, String> {
    use std::io::Write;
    let mut child = Command::new("wg").arg("pubkey")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("wg pubkey failed: {}", e))?;
    child.stdin.take().unwrap().write_all(private_key.as_bytes())
        .map_err(|e| format!("wg pubkey stdin: {}", e))?;
    let output = child.wait_with_output()
        .map_err(|e| format!("wg pubkey wait: {}", e))?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Set a WireGuard interface's private key + listen port without staging the
/// key on disk. The key is piped to `wg set <iface> private-key /dev/stdin`,
/// so it never lands in /tmp (which broke on hardened hosts — SELinux/AppArmor
/// or a restrictive /tmp mount denied wg's fopen of even a root-owned 0600
/// file). Mirrors the proven stdin pattern in wg_pubkey().
fn wg_set_private_key(iface: &str, private_key: &str, listen_port: u16) -> Result<(), String> {
    use std::io::Write;
    let port = listen_port.to_string();
    let mut child = Command::new("wg")
        .args(["set", iface, "private-key", "/dev/stdin", "listen-port", &port])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("wg set failed: {}", e))?;
    child.stdin.take().unwrap().write_all(private_key.as_bytes())
        .map_err(|e| format!("wg set stdin: {}", e))?;
    let output = child.wait_with_output()
        .map_err(|e| format!("wg set wait: {}", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("wg set {} private-key /dev/stdin listen-port {}: {}",
            iface, listen_port,
            String::from_utf8_lossy(&output.stderr).trim()))
    }
}

/// Best-effort check whether a UDP port is already bound on this host.
/// Used to convert the cryptic "ip link set up: Address already in use" into a
/// clear, actionable error when a WireGuard listen-port collides (with WolfNet,
/// which is itself WireGuard, or a lingering half-applied bridge). If `ss` is
/// unavailable we return false and let the real bind attempt surface the error.
fn udp_port_in_use(port: u16) -> bool {
    let output = match Command::new("ss").args(["-lunH"]).output() {
        Ok(o) if o.status.success() => o,
        _ => return false,
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let want = port.to_string();
    for line in text.lines() {
        // ss columns vary slightly by version; only the address columns
        // (Local Address:Port / Peer Address:Port) contain a ':'. Match the
        // trailing ":<port>" there. We must NOT scan the bare-number Recv-Q /
        // Send-Q columns — a receive-queue depth that happens to equal the
        // port would false-positive. The Peer column for a listening UDP
        // socket is "0.0.0.0:*" / "*:*", whose trailing segment is "*", so it
        // never matches a numeric port.
        for col in line.split_whitespace() {
            if !col.contains(':') {
                continue;
            }
            if col.rsplit(':').next() == Some(want.as_str()) {
                return true;
            }
        }
    }
    false
}

/// Add a peer to a live WireGuard interface
fn wg_set_peer(bridge: &WireGuardBridge, client: &WireGuardClient) -> Result<(), String> {
    let iface = bridge.interface_name();
    run_cmd("wg", &[
        "set", &iface,
        "peer", &client.public_key,
        "allowed-ips", &client.assigned_ip,
    ])
}

/// Set up iptables NAT rules for a bridge.
///
/// Creates a bidirectional NAT mapping between the bridge subnet (10.20.X.0/24)
/// and the WolfNet subnet (e.g. 10.0.10.0/24) using NETMAP for 1:1 translation:
///   - Client sends to 10.20.X.5 → DNAT rewrites dst to 10.0.10.5
///   - Response from 10.0.10.5 → SNAT rewrites src to 10.20.X.5
/// Also MASQUERADEs the client source so WolfNet peers route replies back here.
fn setup_bridge_nat(bridge: &WireGuardBridge) -> Result<(), String> {
    let iface = bridge.interface_name();
    let subnet = bridge.bridge_subnet();
    let wn_subnet = format!("{}.0/24", bridge.wolfnet_subnet);

    // Detect WolfNet interface name
    let wn_iface = detect_wolfnet_iface().unwrap_or_else(|| "wolfnet0".to_string());

    // Enable forwarding only on the WireGuard and WolfNet interfaces — avoid
    // enabling the global ip_forward flag which turns the machine into a full
    // router and can cause network-wide slowdowns (especially on low-powered
    // devices like Raspberry Pis that send ICMP redirects or forward LAN traffic).
    let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.forwarding=1", iface)]).output();
    let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.forwarding=1", wn_iface)]).output();
    // Disable ICMP redirects on these interfaces — we handle routing ourselves
    let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.send_redirects=0", iface)]).output();
    let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.send_redirects=0", wn_iface)]).output();

    // On firewalld systems, add WG + WolfNet to trusted zone
    crate::containers::ensure_firewalld_trusted(&[&iface, &wn_iface]);

    // Clean up any existing rules for this bridge first
    cleanup_bridge_nat(bridge);

    // Run an iptables rule and surface failures. Previously each rule was
    // `let _ = …output()`, so on a pure-nftables host with no iptables(-nft)
    // every rule silently failed and the bridge had NO NAT/forwarding — the
    // operator saw "tunnel up, can't reach anything" with nothing in the log.
    let mut failures = 0u32;
    let mut run_nat = |args: &[&str]| {
        match Command::new("iptables").args(args).output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                failures += 1;
                warn!("WG bridge NAT rule failed (iptables {}): {}",
                    args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
            }
            Err(e) => {
                failures += 1;
                warn!("WG bridge NAT rule could not run (iptables {}): {}", args.join(" "), e);
            }
        }
    };

    // NETMAP: translate bridge subnet ↔ WolfNet subnet (1:1 mapping)
    // Inbound on WG: 10.20.X.5 → 10.0.10.5
    run_nat(&["-t", "nat", "-A", "PREROUTING",
        "-i", &iface, "-d", &subnet, "-j", "NETMAP", "--to", &wn_subnet]);
    // Return traffic: 10.0.10.5 → 10.20.X.5 (for packets going back out WG)
    run_nat(&["-t", "nat", "-A", "POSTROUTING",
        "-o", &iface, "-s", &wn_subnet, "-j", "NETMAP", "--to", &subnet]);
    // MASQUERADE the client source IP so WolfNet peers route replies back here
    run_nat(&["-t", "nat", "-A", "POSTROUTING",
        "-s", &subnet, "-o", &wn_iface, "-j", "MASQUERADE"]);
    // Allow forwarding in both directions between WG and WolfNet
    run_nat(&["-A", "FORWARD", "-i", &iface, "-o", &wn_iface, "-j", "ACCEPT"]);
    run_nat(&["-A", "FORWARD", "-i", &wn_iface, "-o", &iface, "-j", "ACCEPT"]);

    if failures > 0 {
        warn!("WG bridge '{}' NAT setup had {} failed iptables rule(s) — the \
            tunnel may come up but not pass traffic. Ensure iptables (or \
            iptables-nft on an nftables host) is installed.", bridge.cluster, failures);
    }
    Ok(())
}

/// Remove iptables NAT rules for a bridge
fn cleanup_bridge_nat(bridge: &WireGuardBridge) {
    let iface = bridge.interface_name();
    let subnet = bridge.bridge_subnet();
    let wn_subnet = format!("{}.0/24", bridge.wolfnet_subnet);
    let wn_iface = detect_wolfnet_iface().unwrap_or_else(|| "wolfnet0".to_string());

    // NETMAP rules
    let _ = Command::new("iptables").args([
        "-t", "nat", "-D", "PREROUTING",
        "-i", &iface, "-d", &subnet, "-j", "NETMAP", "--to", &wn_subnet,
    ]).output();
    let _ = Command::new("iptables").args([
        "-t", "nat", "-D", "POSTROUTING",
        "-o", &iface, "-s", &wn_subnet, "-j", "NETMAP", "--to", &subnet,
    ]).output();

    // MASQUERADE
    let _ = Command::new("iptables").args([
        "-t", "nat", "-D", "POSTROUTING",
        "-s", &subnet, "-o", &wn_iface, "-j", "MASQUERADE",
    ]).output();

    // FORWARD rules
    let _ = Command::new("iptables").args([
        "-D", "FORWARD", "-i", &iface, "-o", &wn_iface, "-j", "ACCEPT",
    ]).output();
    let _ = Command::new("iptables").args([
        "-D", "FORWARD", "-i", &wn_iface, "-o", &iface, "-j", "ACCEPT",
    ]).output();
}

/// Detect WolfNet interface name (wn0 or wolfnet0)
pub fn detect_wolfnet_iface() -> Option<String> {
    let interfaces = list_interfaces();
    interfaces.iter()
        .find(|i| i.name.starts_with("wn") || i.name.starts_with("wolfnet"))
        .map(|i| i.name.clone())
}

/// Detect the WolfNet subnet prefix (e.g. "10.0.10")
/// Detect the WolfNet subnet prefix by reading /etc/wolfnet/config.toml directly.
/// Falls back to runtime status.json, then to default.
fn detect_wolfnet_subnet() -> Option<String> {
    // Primary: read from config.toml (source of truth — user may have changed it)
    if let Ok(content) = std::fs::read_to_string("/etc/wolfnet/config.toml") {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("address") && trimmed.contains('=') {
                // address = "x.x.x.1" or address = x.x.x.1
                if let Some(val) = trimmed.split('=').nth(1) {
                    let addr = val.trim().trim_matches('"').trim();
                    let parts: Vec<&str> = addr.split('.').collect();
                    if parts.len() >= 3 {
                        return Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]));
                    }
                }
            }
        }
    }

    // Fallback: runtime status (may be stale if WolfNet was reconfigured but not restarted)
    if let Some(info) = get_wolfnet_local_info()
        && let Some(addr) = info["address"].as_str() {
            let parts: Vec<&str> = addr.split('.').collect();
            if parts.len() >= 3 {
                return Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]));
            }
        }
    None
}

/// Detect the best endpoint address for clients to connect to
fn detect_server_endpoint(port: u16) -> String {
    // Try multiple public IP services with -f (fail on HTTP errors like 403)
    let services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
        "https://checkip.amazonaws.com",
    ];
    for url in &services {
        if let Ok(output) = Command::new("curl")
            .args(["-sf", "--connect-timeout", "3", url])
            .output()
        {
            let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
            // Validate it looks like an IP address (not HTML or garbage)
            if output.status.success() && !ip.is_empty() && !ip.contains('<')
                && ip.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ':')
            {
                return format!("{}:{}", ip, port);
            }
        }
    }

    // Fall back to LAN IP
    if let Some(lan_ip) = detect_lan_ip() {
        return format!("{}:{}", lan_ip, port);
    }

    format!("YOUR_SERVER_IP:{}", port)
}

/// Run a command, return Ok(()) on success or Err with stderr
fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(cmd).args(args).output()
        .map_err(|e| format!("{} failed: {}", cmd, e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("{} {}: {}", cmd, args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()))
    }
}

/// Get current ISO 8601 timestamp
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    // Simple UTC timestamp without chrono dependency
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Days since 1970-01-01
    let mut y = 1970i64;
    let mut remaining = days as i64;
    loop {
        let year_days = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
        if remaining < year_days { break; }
        remaining -= year_days;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut m = 0usize;
    while m < 12 && remaining >= month_days[m] {
        remaining -= month_days[m];
        m += 1;
    }

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m + 1, remaining + 1, hours, minutes, seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> Ipv4Addr { s.parse().unwrap() }

    // ── Link-speed display (RutgerDiehard 2.5GbE regression) ──
    // sysfs reports Mb/s; 2500 must render as 2.5Gb/s, not 2Gb/s.
    #[test]
    fn link_speed_keeps_fractional_gigabit() {
        assert_eq!(format_link_speed(2500).as_deref(), Some("2.5Gb/s"));
        assert_eq!(format_link_speed(1000).as_deref(), Some("1Gb/s"));
        assert_eq!(format_link_speed(2000).as_deref(), Some("2Gb/s"));
        assert_eq!(format_link_speed(10000).as_deref(), Some("10Gb/s"));
        assert_eq!(format_link_speed(100).as_deref(), Some("100Mb/s"));
        // Unplugged/virtual NICs report -1 or 0 → no speed shown.
        assert_eq!(format_link_speed(-1), None);
        assert_eq!(format_link_speed(0), None);
    }

    // ── IP-mapping purge marker regression (PapaSchlumpf throughput) ──
    // The FORWARD conntrack-ACCEPT rule accumulated to ~10k because the
    // purge searched `iptables -L -n` output for a `dpt:N` token the nft
    // backend never rendered. The fix matches `iptables -S` (canonical)
    // spec form instead. These tests pin the spec form the purge relies on.

    #[test]
    fn port_purge_marker_mirrors_build_port_args() {
        // Single port → `--dport N`, and that token IS in build_port_args.
        let single = build_port_args("8000").join(" ");
        assert_eq!(port_purge_marker(Some("8000"), "tcp").as_deref(), Some("--dport 8000"));
        assert!(single.contains(port_purge_marker(Some("8000"), "tcp").unwrap().as_str()));

        // Multiport → `--dports a,b`, also a substring of build_port_args.
        let multi = build_port_args("8000,8001").join(" ");
        assert_eq!(port_purge_marker(Some("8000,8001"), "tcp").as_deref(), Some("--dports 8000,8001"));
        assert!(multi.contains(port_purge_marker(Some("8000,8001"), "tcp").unwrap().as_str()));

        // protocol "all" and empty/None suppress the marker (apply emits no
        // port match in those cases, so the purge must not require one).
        assert_eq!(port_purge_marker(Some("8000"), "all"), None);
        assert_eq!(port_purge_marker(Some(""), "tcp"), None);
        assert_eq!(port_purge_marker(None, "tcp"), None);
    }

    #[test]
    fn forward_conntrack_rule_matches_in_spec_form() {
        // Exactly the FORWARD rule WolfStack writes, as `iptables -S`
        // renders it (identical on legacy and nft backends).
        let line = "-A FORWARD -d 10.10.10.8/32 -p tcp -m tcp --dport 8000 -m conntrack --ctstate DNAT -j ACCEPT";
        let port = port_purge_marker(Some("8000"), "tcp").unwrap();
        let markers = ["10.10.10.8", "ctstate DNAT", port.as_str()];
        assert!(rule_spec_matches(line, "-A FORWARD ", &markers));

        // Root cause: the OLD purge searched for `dpt:8000`, which the
        // canonical spec form does NOT contain — so it never matched.
        assert!(!line.contains("dpt:8000"));

        // Wrong chain prefix must not match.
        assert!(!rule_spec_matches(line, "-A PREROUTING ", &markers));
    }

    #[test]
    fn prerouting_dnat_rule_matches_in_spec_form() {
        let line = "-A PREROUTING -d 192.168.17.4/32 -p tcp -m tcp --dport 8000 -j DNAT --to-destination 10.10.10.8:8000";
        let port = port_purge_marker(Some("8000"), "tcp").unwrap();
        let markers = ["192.168.17.4", "DNAT", port.as_str()];
        assert!(rule_spec_matches(line, "-A PREROUTING ", &markers));
    }

    #[test]
    fn iptables_check_base_builds_the_check_form() {
        // -I <chain> <pos>  ->  -C <chain>  (position dropped)
        assert_eq!(
            iptables_check_base(&["-I", "FORWARD", "1", "-d", "10.0.0.5"]),
            vec!["-C", "FORWARD", "-d", "10.0.0.5"]);
        // -t nat -A <chain>  ->  -t nat -C <chain>
        assert_eq!(
            iptables_check_base(&["-t", "nat", "-A", "PREROUTING", "-d", "1.2.3.4"]),
            vec!["-t", "nat", "-C", "PREROUTING", "-d", "1.2.3.4"]);
        // -I without a position still maps cleanly.
        assert_eq!(
            iptables_check_base(&["-I", "FORWARD", "-i", "eth0"]),
            vec!["-C", "FORWARD", "-i", "eth0"]);
    }

    // ─── is_in_subnet ───
    #[test]
    fn is_in_subnet_24() {
        let net = ip("10.100.10.0");
        assert!(is_in_subnet(ip("10.100.10.1"), net, 24));
        assert!(is_in_subnet(ip("10.100.10.40"), net, 24));
        assert!(is_in_subnet(ip("10.100.10.255"), net, 24));
        assert!(!is_in_subnet(ip("10.100.11.1"), net, 24));
        assert!(!is_in_subnet(ip("185.57.4.152"), net, 24));
    }

    #[test]
    fn is_in_subnet_16() {
        let net = ip("172.16.0.0");
        assert!(is_in_subnet(ip("172.16.0.1"), net, 16));
        assert!(is_in_subnet(ip("172.16.255.255"), net, 16));
        assert!(!is_in_subnet(ip("172.17.0.1"), net, 16));
    }

    #[test]
    fn is_in_subnet_zero_prefix_matches_all() {
        assert!(is_in_subnet(ip("8.8.8.8"), ip("0.0.0.0"), 0));
    }

    // ─── effective_site ───

    #[test]
    fn effective_site_explicit_wins() {
        let s = effective_site(&Some("office-vlan10".to_string()), "10.10.5.42");
        assert_eq!(s.as_deref(), Some("office-vlan10"));
    }

    #[test]
    fn effective_site_empty_explicit_falls_back_to_auto() {
        // Operator clearing the tag (empty string) drops back to auto-derive.
        let s = effective_site(&Some(String::new()), "192.168.10.42");
        assert_eq!(s.as_deref(), Some("auto:192.168.10"));
    }

    #[test]
    fn effective_site_auto_from_rfc1918_24() {
        assert_eq!(
            effective_site(&None, "192.168.10.42").as_deref(),
            Some("auto:192.168.10")
        );
        assert_eq!(
            effective_site(&None, "10.10.5.7").as_deref(),
            Some("auto:10.10.5")
        );
        assert_eq!(
            effective_site(&None, "172.20.0.1").as_deref(),
            Some("auto:172.20.0")
        );
    }

    #[test]
    fn effective_site_none_for_public_address() {
        // Public-IP-only nodes (a VPS) have no LAN context to auto-tag,
        // so they get None — the cluster-sync routes to/from them via
        // the public path regardless of any other peer's site.
        assert_eq!(effective_site(&None, "203.0.113.5"), None);
        assert_eq!(effective_site(&None, "8.8.8.8"), None);
    }

    #[test]
    fn effective_site_none_for_unparseable_or_empty() {
        assert_eq!(effective_site(&None, ""), None);
        assert_eq!(effective_site(&None, "not-an-ip"), None);
    }

    #[test]
    fn effective_site_none_for_loopback_and_link_local() {
        // is_private_ip considers 127/8 and 169.254/16 private, but
        // they aren't meaningful site anchors — no node is reachable
        // to a peer via either range. The JS autoSiteHint helper
        // intentionally rejects them too; this test pins the parity.
        assert_eq!(effective_site(&None, "127.0.0.1"), None);
        assert_eq!(effective_site(&None, "127.0.0.42"), None);
        assert_eq!(effective_site(&None, "169.254.1.1"), None);
    }

    #[test]
    fn effective_site_same_24_matches_different_24_doesnt() {
        // The core property the cluster-sync relies on: same /24 → same
        // auto-tag → LAN-dial; different /24 → different tag → public-dial.
        // This is what kills klasSponsor's multi-VLAN flap when no
        // explicit site is set.
        let a = effective_site(&None, "192.168.10.5");
        let b = effective_site(&None, "192.168.10.99");
        let c = effective_site(&None, "192.168.20.5");
        assert_eq!(a, b, "same /24 must produce the same auto-tag");
        assert_ne!(a, c, "different /24s must produce different auto-tags");
    }

    // ─── decide_peer_endpoint guards ───
    // Each guard exercised independently. The base "ok" case sits at the
    // bottom to show what the function looks like when nothing trips.

    fn klas_wn() -> Option<(Ipv4Addr, u8)> { Some((ip("10.100.10.0"), 24)) }

    #[test]
    fn decide_clears_when_no_public_ip() {
        let r = decide_peer_endpoint(
            "194.104.94.40", klas_wn(),
            Some("10.10.10.30"), None, 9630,
        );
        assert!(matches!(r, PeerEndpoint::Clear));
    }

    #[test]
    fn decide_clears_when_public_ip_empty() {
        let r = decide_peer_endpoint(
            "194.104.94.40", klas_wn(),
            Some("10.10.10.30"), Some(""), 9630,
        );
        assert!(matches!(r, PeerEndpoint::Clear));
    }

    #[test]
    fn decide_clears_when_public_ip_in_wolfnet_subnet() {
        // klasSponsor 2026-05-11 regression: unifios's wolfstack agent
        // reported its WolfNet IP (10.100.10.1) as public_ip; without
        // this guard we wrote that as the endpoint and triggered the
        // kernel routing loop.
        let r = decide_peer_endpoint(
            "194.104.94.40", klas_wn(),
            Some("10.10.5.2"), Some("10.100.10.1"), 9634,
        );
        assert!(matches!(r, PeerEndpoint::Clear), "must Clear loop-inducing endpoint, got {:?}", r);
    }

    #[test]
    fn decide_clears_self_loop() {
        let r = decide_peer_endpoint(
            "194.104.94.40", klas_wn(),
            Some("194.104.94.40"), Some("194.104.94.40"), 9600,
        );
        assert!(matches!(r, PeerEndpoint::Clear));
    }

    #[test]
    fn decide_clears_loopback_endpoint() {
        let r = decide_peer_endpoint(
            "194.104.94.40", klas_wn(),
            Some("127.0.0.1"), Some("127.0.0.1"), 9600,
        );
        assert!(matches!(r, PeerEndpoint::Clear));
    }

    #[test]
    fn decide_clears_link_local_endpoint() {
        let r = decide_peer_endpoint(
            "194.104.94.40", klas_wn(),
            Some("169.254.1.1"), Some("169.254.1.1"), 9600,
        );
        assert!(matches!(r, PeerEndpoint::Clear));
    }

    #[test]
    fn decide_clears_when_peer_behind_nat() {
        // peer.lan_address (10.10.10.30) != peer.public_ip (185.57.4.152)
        // → behind NAT → roaming-only is the robust answer.
        let r = decide_peer_endpoint(
            "194.104.94.40", klas_wn(),
            Some("10.10.10.30"), Some("185.57.4.152"), 9630,
        );
        assert!(matches!(r, PeerEndpoint::Clear));
    }

    #[test]
    fn decide_sets_when_peer_is_direct_internet() {
        // peer.lan_address == peer.public_ip — peer is sitting directly
        // on the public internet, Set is safe.
        let r = decide_peer_endpoint(
            "194.104.94.40", klas_wn(),
            Some("185.57.4.100"), Some("185.57.4.100"), 9600,
        );
        match r {
            PeerEndpoint::Set(s) => assert_eq!(s, "185.57.4.100:9600"),
            other => panic!("expected Set, got {:?}", other),
        }
    }

    #[test]
    fn decide_sets_when_peer_public_ip_is_hostname() {
        // Hostname endpoints are common in DynDNS setups — we trust
        // them and Set without applying the IP-literal guards.
        let r = decide_peer_endpoint(
            "194.104.94.40", klas_wn(),
            Some("10.10.10.30"), Some("ninni.example.com"), 9630,
        );
        match r {
            PeerEndpoint::Set(s) => assert_eq!(s, "ninni.example.com:9630"),
            other => panic!("expected Set, got {:?}", other),
        }
    }

    #[test]
    fn decide_loop_guard_fires_even_without_peer_lan_address() {
        // The wolfnet-subnet loop check must work without peer_lan_address
        // — that's the worst case (gossip half-converged, peer.address
        // unknown but peer.public_ip happens to be a wolfnet-subnet IP).
        let r = decide_peer_endpoint(
            "194.104.94.40", klas_wn(),
            None, Some("10.100.10.5"), 9600,
        );
        assert!(matches!(r, PeerEndpoint::Clear));
    }

    // ─── tombstone semantics ───
    // The tombstone helpers touch the real `/etc/wolfstack/...` path,
    // which isn't writable in CI; we test the JSON-format round-trip
    // directly to verify the on-disk shape is stable, plus the in-set
    // semantics via `WolfnetTombstones`.
    #[test]
    fn tombstone_serializes_sorted_hostnames() {
        let mut set = std::collections::HashSet::new();
        set.insert("ninni".to_string());
        set.insert("alpha".to_string());
        set.insert("lillamy".to_string());
        let mut hostnames: Vec<String> = set.iter().cloned().collect();
        hostnames.sort();
        let t = WolfnetTombstones { hostnames };
        let json = serde_json::to_string(&t).unwrap();
        // Order matters for stable diffs — alpha < lillamy < ninni.
        assert_eq!(
            json,
            r#"{"hostnames":["alpha","lillamy","ninni"]}"#
        );
    }

    #[test]
    fn tombstone_deserializes_empty_when_missing_field() {
        let t: WolfnetTombstones = serde_json::from_str("{}").unwrap();
        assert!(t.hostnames.is_empty());
    }

    #[test]
    fn tombstone_round_trip() {
        let original = WolfnetTombstones {
            hostnames: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: WolfnetTombstones = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.hostnames, original.hostnames);
    }

    #[test]
    fn decide_loop_guard_off_when_no_subnet_known() {
        // If we couldn't read the local wolfnet subnet (e.g. config
        // missing on a fresh install), the subnet guard skips and the
        // other guards still fire normally.
        let r = decide_peer_endpoint(
            "194.104.94.40", None,
            Some("185.57.4.100"), Some("185.57.4.100"), 9600,
        );
        match r {
            PeerEndpoint::Set(s) => assert_eq!(s, "185.57.4.100:9600"),
            other => panic!("expected Set, got {:?}", other),
        }
    }

    #[test]
    fn on_link_matches_directly_attached_subnet() {
        // hemulen's real LAN interfaces (address form — is_in_subnet masks).
        let subnets = [
            ("10.10.10.30".parse().unwrap(), 24u8),
            ("192.168.1.10".parse().unwrap(), 24u8),
        ];
        // ninni's LAN endpoint host sits on 10.10.10.0/24 → reachable on-link,
        // so the reconciler must NOT clear it (klasSponsor 2026-06-08).
        assert!(is_on_link("10.10.10.20".parse().unwrap(), &subnets));
        assert!(is_on_link("192.168.1.50".parse().unwrap(), &subnets));
        // Addresses on no local subnet are not on-link.
        assert!(!is_on_link("10.10.20.5".parse().unwrap(), &subnets));
        assert!(!is_on_link("8.8.8.8".parse().unwrap(), &subnets));
        // No local subnets → never on-link, so the guard can't wrongly fire.
        assert!(!is_on_link("10.10.10.20".parse().unwrap(), &[]));
    }
}

#[cfg(test)]
mod resolv_conf_tests {
    use super::*;

    #[test]
    fn unraid_trailing_comment_is_stripped() {
        // The exact shape that broke JJ's Unraid install (2026-07-27): the
        // whole string "10.10.1.250  # eth0:v4" reached `docker --dns`.
        assert_eq!(parse_nameserver("10.10.1.250  # eth0:v4").as_deref(), Some("10.10.1.250"));
        assert_eq!(parse_nameserver("192.168.1.1 ; comment").as_deref(), Some("192.168.1.1"));
        assert_eq!(parse_nameserver("  8.8.8.8  ").as_deref(), Some("8.8.8.8"));
    }

    #[test]
    fn non_addresses_are_rejected() {
        // Anything that isn't an address must never reach --dns or daemon.json.
        assert_eq!(parse_nameserver("# only a comment"), None);
        assert_eq!(parse_nameserver(""), None);
        assert_eq!(parse_nameserver("not-an-ip"), None);
        assert_eq!(parse_nameserver("eth0:v4"), None);
    }

    #[test]
    fn ipv6_and_zones_survive() {
        assert_eq!(parse_nameserver("2001:4860:4860::8888").as_deref(), Some("2001:4860:4860::8888"));
        // The zone is meaningful to the resolver — validate the address, keep the zone.
        assert_eq!(parse_nameserver("fe80::1%eth0 # link-local").as_deref(), Some("fe80::1%eth0"));
    }

    #[test]
    fn directive_matching_requires_whitespace() {
        assert_eq!(resolv_directive("nameserver 1.1.1.1", "nameserver"), Some("1.1.1.1"));
        assert_eq!(resolv_directive("nameserver\t1.1.1.1", "nameserver"), Some("1.1.1.1"));
        // Must not match a longer keyword that merely starts the same way.
        assert_eq!(resolv_directive("nameservers 1.1.1.1", "nameserver"), None);
        assert_eq!(resolv_directive("# nameserver 1.1.1.1", "nameserver"), None);
    }

    #[test]
    fn search_line_drops_its_comment() {
        assert_eq!(
            strip_resolv_comment("lan local # set by dhcp").split_whitespace().collect::<Vec<_>>(),
            vec!["lan", "local"]
        );
    }

    #[test]
    fn multibyte_line_does_not_panic() {
        // The old code byte-sliced line[11..], which could split a UTF-8 char.
        assert_eq!(resolv_directive("nameserver ✓", "nameserver"), Some("✓"));
        assert_eq!(parse_nameserver("✓"), None);
    }
}
