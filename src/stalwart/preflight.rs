// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com
//
//! Node-local pre-install checks for a Stalwart mail cluster member.
//!
//! The wizard runs this on every chosen node and shows the result before it
//! installs anything, so an operator learns about an old kernel, a blocked
//! port 25 or an occupied mail port up front — with the reason and the fix —
//! instead of from a half-finished install.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::Command;
use std::time::Duration;

/// Minimum kernel for a Stalwart Keep server or client node.
/// Source: keep docs/DEPLOYMENT.md §1 — "Linux kernel 6.12 or later | minimum
/// supported kernel; no feature probe beyond it".
pub const KEEP_MIN_KERNEL: (u32, u32) = (6, 12);
/// Below this, `net.ipv4.tcp_rto_min_us=5000` must be set on Keep servers and
/// client nodes. Source: keep docs/DEPLOYMENT.md §3 — "on kernels before 6.15
/// set `net.ipv4.tcp_rto_min_us=5000` (6.11 and later) … on Keep servers and
/// on client nodes; on 6.15 and later each end sets `TCP_RTO_MIN_US` per
/// socket itself".
pub const KEEP_RTO_SOCKOPT_KERNEL: (u32, u32) = (6, 15);

/// Host ports Stalwart's default listeners bind on every interface.
/// Source: stalwart crates/common/src/manager/defaults.rs:478-485 (the
/// listener set created when none exists): smtp 25, submissions 465, imaps
/// 993, pop3s 995, sieve 4190, https 443 (and http 8080, which WolfStack
/// publishes on the WolfNet address only).
pub const STALWART_PUBLIC_PORTS: [u16; 6] = [25, 465, 993, 995, 4190, 443];
/// Stalwart's plain HTTP management listener (same source, `http` 8080).
pub const STALWART_MGMT_PORT: u16 = 8080;
/// Keep client and peer ports. Source: keep README "Binaries and Docker" —
/// "exposes the client port 7000 and the peer port 7100 (TCP and UDP)".
pub const KEEP_CLIENT_PORT: u16 = 7000;
pub const KEEP_PEER_PORT: u16 = 7100;
/// Valkey and Sentinel default ports. Source: valkey 9.1.3 valkey.conf:139
/// `port 6379`; sentinel.conf:10 `port 26379`.
pub const VALKEY_PORT: u16 = 6379;
pub const SENTINEL_PORT: u16 = 26379;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Preflight {
    pub hostname: String,
    /// `uname -r`.
    pub kernel: String,
    /// True when the kernel is at least [`KEEP_MIN_KERNEL`].
    pub kernel_ok_for_keep: bool,
    /// True when Keep needs the `tcp_rto_min_us` sysctl on this kernel.
    pub needs_rto_sysctl: bool,
    /// `PRETTY_NAME` from /etc/os-release, for the upgrade guidance.
    pub os_pretty_name: String,
    /// `ID` and `VERSION_ID` from /etc/os-release.
    pub os_id: String,
    pub os_version_id: String,
    pub docker: bool,
    pub docker_detail: String,
    /// This node's WolfNet address (from wolfnet's status file).
    pub wolfnet_ip: Option<String>,
    /// NTP synchronised per `timedatectl`. `None` when it can't be read.
    /// Stalwart node-id leases and Keep both depend on synchronised clocks
    /// (docs cluster/configuration/node-id.md: "Node clocks must be
    /// synchronised").
    pub ntp_synchronized: Option<bool>,
    /// Mail ports already bound by something else, with the owner.
    pub port_conflicts: Vec<String>,
    /// Coordinator ports already bound on this node.
    pub coordinator_port_conflicts: Vec<String>,
    /// Outbound TCP/25 reachability (most clouds block it on new accounts).
    pub outbound_smtp: Option<bool>,
    pub outbound_smtp_detail: String,
    /// How to get this OS to a Keep-capable kernel, when it isn't on one.
    pub kernel_guidance: KernelGuidance,
    /// CPUs and memory available, for coordinator sizing.
    pub cpus: usize,
    pub memory_mb: u64,
}

/// Parse "6.12.3-amd64" / "7.2.15-1-omarchy" → (major, minor).
pub fn parse_kernel(s: &str) -> Option<(u32, u32)> {
    let mut it = s.trim().split(|c: char| !c.is_ascii_digit());
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    Some((major, minor))
}

fn at_least(k: Option<(u32, u32)>, min: (u32, u32)) -> bool {
    k.map(|k| k >= min).unwrap_or(false)
}

fn os_release() -> (String, String, String) {
    let text = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let get = |key: &str| -> String {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{}=", key)))
            .map(|v| v.trim().trim_matches('"').to_string())
            .unwrap_or_default()
    };
    (get("PRETTY_NAME"), get("ID"), get("VERSION_ID"))
}

/// Outbound port 25 check: connect to Gmail's primary MX and read the SMTP
/// greeting. `gmail-smtp-in.l.google.com` is the priority-5 MX of gmail.com
/// (`dig mx gmail.com`, checked 2026-11-13). This only opens a TCP connection
/// to Google and closes it after the banner — it never sends mail, and never
/// touches our own servers.
fn outbound_smtp() -> (Option<bool>, String) {
    const HOST: &str = "gmail-smtp-in.l.google.com:25";
    let addrs: Vec<_> = match HOST.to_socket_addrs() {
        Ok(a) => a.filter(|a| a.is_ipv4()).collect(),
        Err(e) => return (None, format!("could not resolve {}: {}", HOST, e)),
    };
    let Some(addr) = addrs.first() else {
        return (None, format!("{} has no IPv4 address", HOST));
    };
    match TcpStream::connect_timeout(addr, Duration::from_secs(6)) {
        Ok(mut s) => {
            let _ = s.set_read_timeout(Some(Duration::from_secs(6)));
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).unwrap_or(0);
            let _ = s.write_all(b"QUIT\r\n");
            if buf[..n].starts_with(b"220") {
                (Some(true), "outbound port 25 is open".into())
            } else {
                (Some(false), "connected on port 25 but got no SMTP greeting — something on the path is intercepting mail traffic".into())
            }
        }
        Err(e) => (Some(false), format!(
            "outbound port 25 is blocked ({}). Most cloud providers block it on new accounts; \
             ask your provider to unblock it, or this server cannot deliver mail to other domains", e)),
    }
}

fn conflicts(ports: &[String]) -> Vec<String> {
    match crate::containers::validate_host_ports_free(ports, "") {
        Ok(()) => vec![],
        Err(e) => e.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
    }
}

/// Run every check on THIS node. `cluster_id` is the mail cluster being
/// installed: ports held by that cluster's own containers are not conflicts
/// (a re-run after a partial install).
pub fn run_local(cluster_id: &str) -> Preflight {
    let kernel = Command::new("uname").arg("-r").output()
        .ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let k = parse_kernel(&kernel);
    let (pretty, id, ver) = os_release();

    let (docker, docker_detail) = match Command::new("docker").args(["version", "--format", "{{.Server.Version}}"]).output() {
        Ok(o) if o.status.success() => (true, format!("Docker {}", String::from_utf8_lossy(&o.stdout).trim())),
        Ok(o) => (false, format!("Docker is installed but not running: {}", String::from_utf8_lossy(&o.stderr).trim())),
        Err(_) => (false, "Docker is not installed on this server".into()),
    };

    let wolfnet_ip = crate::networking::get_wolfnet_local_info()
        .and_then(|v| v.get("address").and_then(|a| a.as_str()).map(|s| s.split('/').next().unwrap_or(s).to_string()))
        .filter(|s| !s.is_empty());

    let ntp_synchronized = Command::new("timedatectl").args(["show", "-p", "NTPSynchronized", "--value"]).output()
        .ok().filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "yes");

    // Our own containers from an earlier, partial run are not conflicts.
    let ours: Vec<String> = [
        super::stalwart_container(cluster_id), super::keep_container(cluster_id),
        super::valkey_container(cluster_id), super::sentinel_container(cluster_id),
    ].to_vec();
    let strip_ours = |v: Vec<String>| -> Vec<String> {
        v.into_iter().filter(|l| !ours.iter().any(|c| l.contains(&format!("`{}`", c)))).collect()
    };
    let mut mail_ports: Vec<String> = STALWART_PUBLIC_PORTS.iter().map(|p| format!("{}:{}", p, p)).collect();
    if let Some(ip) = &wolfnet_ip {
        mail_ports.push(format!("{}:{}:{}", ip, STALWART_MGMT_PORT, STALWART_MGMT_PORT));
    }
    let port_conflicts = strip_ours(conflicts(&mail_ports));
    let coord_ports: Vec<String> = match &wolfnet_ip {
        Some(ip) => [KEEP_CLIENT_PORT, KEEP_PEER_PORT, VALKEY_PORT, SENTINEL_PORT].iter()
            .map(|p| format!("{}:{}:{}", ip, p, p)).collect(),
        None => vec![],
    };
    let coordinator_port_conflicts = strip_ours(conflicts(&coord_ports));

    let (outbound_smtp, outbound_smtp_detail) = outbound_smtp();

    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    let memory_mb = sys.total_memory() / (1024 * 1024);
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

    Preflight {
        hostname: sysinfo::System::host_name().unwrap_or_default(),
        kernel_guidance: kernel_guidance(&id, &ver),
        kernel_ok_for_keep: at_least(k, KEEP_MIN_KERNEL),
        needs_rto_sysctl: !at_least(k, KEEP_RTO_SOCKOPT_KERNEL),
        kernel,
        os_pretty_name: pretty,
        os_id: id,
        os_version_id: ver,
        docker,
        docker_detail,
        wolfnet_ip,
        ntp_synchronized,
        port_conflicts,
        coordinator_port_conflicts,
        outbound_smtp,
        outbound_smtp_detail,
        cpus,
        memory_mb,
    }
}

/// Distro-specific route to a kernel >= 6.12. Every package name, repo line
/// and command below was checked against the distro's own primary pages on
/// 2026-11-13 (packages.debian.org, backports.debian.org/Instructions,
/// packages.ubuntu.com, ubuntu.com/kernel/lifecycle, pve.proxmox.com/wiki/
/// Roadmap + the Proxmox staff opt-in-kernel announcement, access.redhat.com/
/// articles/3078, elrepo.org/wiki). Recorded in plans/stalwart-mail-manager.md.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KernelGuidance {
    /// True when the distro has an official, supported route to >= 6.12
    /// without changing release.
    pub supported_in_place: bool,
    /// Plain-English summary.
    pub summary: String,
    /// Shell commands, one per line (run as root). Empty when none apply.
    pub commands: Vec<String>,
    /// Caveats the operator must know (DKMS, Secure Boot, recommendations).
    pub notes: Vec<String>,
    /// Primary source the steps came from.
    pub source: String,
}

pub fn kernel_guidance(os_id: &str, version_id: &str) -> KernelGuidance {
    // Proxmox VE reports os-release ID=debian, but its kernel comes from
    // Proxmox's own packages — never point a PVE host at Debian backports.
    if is_proxmox() {
        return proxmox_guidance();
    }
    let major = version_id.split('.').next().unwrap_or("");
    let g = |supported: bool, summary: &str, commands: &[&str], notes: &[&str], source: &str| KernelGuidance {
        supported_in_place: supported,
        summary: summary.into(),
        commands: commands.iter().map(|s| s.to_string()).collect(),
        notes: notes.iter().map(|s| s.to_string()).collect(),
        source: source.into(),
    };
    const DKMS: &str = "Kernel modules built with DKMS (ZFS, NVIDIA, DRBD) need the matching headers and a rebuild before the reboot.";
    match (os_id, major) {
        ("debian", "12") => g(true,
            "Debian 12 ships kernel 6.1. Debian's official bookworm-backports repository has kernel 6.12.",
            &["echo 'deb http://deb.debian.org/debian bookworm-backports main' > /etc/apt/sources.list.d/bookworm-backports.list",
              "apt update",
              "apt install -t bookworm-backports linux-image-amd64   # on ARM: linux-image-arm64",
              "reboot"],
            &[DKMS, "For DKMS also install linux-headers-amd64 (or -arm64) from bookworm-backports.",
              "The backports kernel is signed, so Secure Boot keeps working."],
            "https://packages.debian.org/bookworm-backports/linux-image-amd64"),
        ("ubuntu", "22") => g(false,
            "Ubuntu 22.04's newest supported kernel is 6.8 (HWE). There is no supported 6.12 kernel for 22.04 — upgrade the release to Ubuntu 24.04 or later.",
            &["do-release-upgrade", "reboot"],
            &["After moving to 24.04, install its HWE kernel (linux-generic-hwe-24.04) to get past 6.12.",
              "Ubuntu offers the LTS-to-LTS upgrade only after the next release's first point release."],
            "https://ubuntu.com/kernel/lifecycle"),
        ("ubuntu", "24") => g(true,
            "Ubuntu 24.04 ships kernel 6.8. Its official HWE kernel (linux-generic-hwe-24.04) is newer than 6.12.",
            &["apt update", "apt install linux-generic-hwe-24.04", "reboot"],
            &[DKMS],
            "https://packages.ubuntu.com/noble-updates/linux-generic-hwe-24.04"),
        ("rhel" | "rocky" | "almalinux" | "centos", "9") => g(false,
            "Enterprise Linux 9 stays on kernel 5.14 for its whole life; there is no official 6.12 kernel. Enterprise Linux 10 ships 6.12 — migrating to it is the supported route.",
            &[],
            &["ELRepo's kernel-ml package can install a newer kernel, but it is third-party, unsupported and not signed for Secure Boot. Use it only if you accept that.",
              "Alternatively, choose \"Use Redis instead\" in the wizard — it works on this kernel."],
            "https://access.redhat.com/articles/3078"),
        _ => g(false,
            "This distribution has no upgrade route recorded in WolfStack. Install a distribution kernel of 6.12 or newer (Debian 13, Ubuntu 24.04 HWE or 26.04, Proxmox VE 9, Enterprise Linux 10, Fedora and Arch all ship one), or use Redis instead.",
            &[], &[], ""),
    }
}

fn is_proxmox() -> bool {
    std::path::Path::new("/usr/bin/pveversion").exists()
}

fn proxmox_guidance() -> KernelGuidance {
    let ver = Command::new("pveversion").output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    // "pve-manager/8.4.1/…" → major 8.
    let major = ver.split('/').nth(1).and_then(|v| v.split('.').next()).unwrap_or("");
    if major == "8" {
        KernelGuidance {
            supported_in_place: true,
            summary: "Proxmox VE 8 defaults to kernel 6.8. Proxmox publishes an opt-in 6.14 kernel for PVE 8, or you can upgrade to Proxmox VE 9 (6.14 and newer by default).".into(),
            commands: vec!["apt update".into(), "apt install proxmox-kernel-6.14".into(), "reboot".into()],
            notes: vec![
                "The opt-in kernel comes from the pve-no-subscription or pvetest repository.".into(),
                "Proxmox staff recommend keeping the 6.8 kernel on production PVE 8 hosts; upgrading to PVE 9 (pve8to9, needs 8.4.1+) is the long-term route.".into(),
                "NIC names can change between kernels — pin interface names first.".into(),
            ],
            source: "https://forum.proxmox.com/threads/opt-in-linux-6-14-kernel-for-proxmox-ve-8-available-on-test-no-subscription.164497/".into(),
        }
    } else {
        KernelGuidance {
            supported_in_place: false,
            summary: "Upgrade to Proxmox VE 9 or later, which ships kernel 6.14 or newer.".into(),
            commands: vec![],
            notes: vec!["NIC names can change between kernels — pin interface names first.".into()],
            source: "https://pve.proxmox.com/wiki/Roadmap".into(),
        }
    }
}

/// Can THIS node open a TCP connection to each `ip:port`? Used across the
/// chosen servers' WolfNet addresses before an install: WolfNet "running" on
/// every node does not mean they can reach each other (found 2026-11-13: two
/// nodes in one WolfStack cluster with no WolfNet peering between them, so
/// Stalwart could not reach Keep). Targets are the other nodes' own WolfStack
/// ports — one known port per cluster member, never a sweep.
pub fn reach(targets: &[String]) -> Vec<(String, Result<(), String>)> {
    targets.iter().map(|t| {
        let r = t.parse::<std::net::SocketAddr>()
            .map_err(|e| format!("bad address {}: {}", t, e))
            .and_then(|a| TcpStream::connect_timeout(&a, Duration::from_secs(4)).map(|_| ()).map_err(|e| e.to_string()));
        (t.clone(), r)
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_parsing() {
        assert_eq!(parse_kernel("6.12.3-amd64"), Some((6, 12)));
        assert_eq!(parse_kernel("7.2.15-1-omarchy"), Some((7, 2)));
        assert_eq!(parse_kernel("5.15.0-125-generic"), Some((5, 15)));
        assert_eq!(parse_kernel("6.8.12-4-pve"), Some((6, 8)));
        assert_eq!(parse_kernel(""), None);
    }

    #[test]
    fn guidance_routes() {
        if is_proxmox() { return; } // host-dependent branch
        assert!(kernel_guidance("debian", "12").supported_in_place);
        assert!(!kernel_guidance("ubuntu", "22.04").supported_in_place);
        assert!(kernel_guidance("ubuntu", "24.04").commands.iter().any(|c| c.contains("linux-generic-hwe-24.04")));
        assert!(!kernel_guidance("rocky", "9.4").supported_in_place);
        assert!(!kernel_guidance("plan9", "4").supported_in_place);
    }

    #[test]
    fn keep_kernel_gate() {
        assert!(at_least(parse_kernel("6.12.0"), KEEP_MIN_KERNEL));
        assert!(at_least(parse_kernel("7.0.1"), KEEP_MIN_KERNEL));
        assert!(!at_least(parse_kernel("6.11.9"), KEEP_MIN_KERNEL));
        assert!(!at_least(parse_kernel("5.15.0"), KEEP_MIN_KERNEL));
        assert!(!at_least(None, KEEP_MIN_KERNEL));
    }
}
