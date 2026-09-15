// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! Per-LAN dnsmasq lifecycle. One dnsmasq instance per LanSegment,
//! bound to the segment's interface with its own config file, pid file,
//! and lease file.
//!
//! We use dnsmasq (not ISC DHCPD) because:
//!   • It's everywhere — already the VM TAP DHCP provider in WolfStack.
//!   • It does DHCP + DNS in one process, which is exactly the LAN model.
//!   • Config is a single flat file, easy to template safely.
//!   • Reload is a SIGHUP, no restart needed.
//!
//! Config files live in `/etc/wolfstack/router/dnsmasq.d/` — one per LAN.
//! We do NOT write into `/etc/dnsmasq.d/` because that's owned by any
//! system-global dnsmasq the distro ships; we run our own instances
//! explicitly.

use super::*;
use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

const DNSMASQ_DIR: &str = "/etc/wolfstack/router/dnsmasq.d";
const PID_DIR: &str = "/run/wolfstack-router";
const LEASE_DIR: &str = "/var/lib/wolfstack-router";
const ADBLOCK_HOSTS: &str = "/etc/wolfstack/router/adblock-hosts";

/// Ensure runtime directories exist. Idempotent.
fn ensure_dirs() -> Result<(), String> {
    for d in [DNSMASQ_DIR, PID_DIR, LEASE_DIR] {
        fs::create_dir_all(d).map_err(|e| format!("mkdir {}: {}", d, e))?;
    }
    Ok(())
}

/// Render the dnsmasq `address=/<domain>/<ip>` lines for a LAN's wildcard
/// local domains. Each entry resolves the domain AND every subdomain to one
/// IP — e.g. `address=/ai.home/192.168.10.2` answers ai.home, app.ai.home,
/// a.b.ai.home … all with that IP (the home-lab "*.ai.home → reverse proxy"
/// pattern). A leading `*.` or `.` the operator may have typed is stripped;
/// dnsmasq wants the bare domain. An entry that normalises to an empty domain
/// is skipped so we never emit a malformed `address=//ip` line (which would
/// make dnsmasq reject the whole config and take the LAN's DNS+DHCP down).
/// Pure (no I/O) so it can be unit-tested; empty input renders an empty
/// string, leaving existing LANs' configs byte-identical.
fn render_wildcard_lines(domains: &[WildcardDomain]) -> String {
    let mut out = String::new();
    for wc in domains {
        let domain = wc.domain.trim().trim_start_matches("*.").trim_start_matches('.');
        let ip = wc.ip.trim();
        // Self-protecting: skip anything that can't form a valid
        // `address=/<domain>/<ip>` line, so even an un-validated config (the
        // API validator is the normal gate, but a config can be hand-edited
        // on disk or imported) can never emit a directive that makes dnsmasq
        // reject the whole file and take the LAN's DNS+DHCP down. A `/`, `#`
        // or whitespace would break the directive's structure; a non-IP value
        // would be rejected by dnsmasq for that line.
        if domain.is_empty()
            || domain.contains('/') || domain.contains('#')
            || domain.chars().any(|c| c.is_whitespace())
            || ip.parse::<std::net::IpAddr>().is_err()
        {
            continue;
        }
        out.push_str(&format!("address=/{}/{}\n", domain, ip));
    }
    out
}

/// Write the dnsmasq config for one LAN using an explicit bind interface.
/// `bind_iface` may differ from `lan.interface` when apply-time self-heal
/// resolves a mismatch (router_ip is on a different iface than configured).
/// Returns the path written.
pub fn render_config_for_iface(lan: &LanSegment, bind_iface: &str) -> Result<String, String> {
    ensure_dirs()?;
    let path = format!("{}/lan-{}.conf", DNSMASQ_DIR, lan.id);

    let mut cfg = String::new();
    // Header so humans debugging can tell what this is.
    cfg.push_str(&format!(
        "# WolfRouter LAN: {} ({})\n# Managed by WolfStack — do not edit by hand.\n",
        lan.name, lan.id
    ));
    if bind_iface != lan.interface {
        cfg.push_str(&format!(
            "# Self-heal active: configured interface is '{}', \
             but router_ip {} is on '{}', so dnsmasq is bound to '{}'.\n",
            lan.interface, lan.router_ip, bind_iface, bind_iface
        ));
    }

    // Strict interface binding: only listen on the LAN's interface.
    cfg.push_str(&format!("interface={}\n", bind_iface));
    cfg.push_str("bind-interfaces\n");
    cfg.push_str("except-interface=lo\n");

    // Run as a dedicated instance with per-LAN pid/lease files.
    cfg.push_str(&format!("pid-file={}/lan-{}.pid\n", PID_DIR, lan.id));
    cfg.push_str(&format!("dhcp-leasefile={}/lan-{}.leases\n", LEASE_DIR, lan.id));

    // Don't touch /etc/resolv.conf / /etc/hosts. We're a LAN server,
    // not the host's resolver.
    cfg.push_str("no-resolv\n");
    cfg.push_str("no-hosts\n");
    cfg.push_str("no-poll\n");
    // Quiet DHCP: no broadcast of defaults we didn't ask for.
    cfg.push_str("dhcp-authoritative\n");

    // DHCP
    if lan.dhcp.enabled {
        let (_, prefix) = parse_cidr(&lan.subnet_cidr)
            .ok_or_else(|| format!("Bad subnet_cidr: {}", lan.subnet_cidr))?;
        let netmask = prefix_to_netmask(prefix);
        cfg.push_str(&format!(
            "dhcp-range={},{},{},{}\n",
            lan.dhcp.pool_start, lan.dhcp.pool_end, netmask, lan.dhcp.lease_time
        ));
        // Default gateway (option 3) = router_ip.
        cfg.push_str(&format!("dhcp-option=3,{}\n", lan.router_ip));
        // DNS (option 6) — where clients should ask for DNS. When
        // external_server is set (either because mode=External or the
        // operator moved WolfRouter to a non-standard port), advertise
        // that; otherwise fall back to router_ip. Save-time validation
        // in the API stops the footgun where mode=External has no
        // external_server at all.
        let dns_opt6 = lan.dns.external_server.clone()
            .unwrap_or_else(|| lan.router_ip.clone());
        cfg.push_str(&format!("dhcp-option=6,{}\n", dns_opt6));

        // Static reservations.
        for r in &lan.dhcp.reservations {
            let host = r.hostname.as_deref().unwrap_or("");
            if host.is_empty() {
                cfg.push_str(&format!("dhcp-host={},{}\n", r.mac, r.ip));
            } else {
                cfg.push_str(&format!("dhcp-host={},{},{}\n", r.mac, r.ip, host));
            }
        }

        // Any extra options the admin wants to push (e.g. option 42 NTP).
        for opt in &lan.dhcp.extra_options {
            cfg.push_str(&format!("dhcp-option={}\n", opt));
        }
    }

    // DNS — behaviour depends on the LAN's DNS mode.
    //
    //   External → dnsmasq runs DHCP only. `port=0` tells dnsmasq not
    //   to bind any DNS listener at all, freeing port 53 on the LAN
    //   interface so the operator's own DNS server (AdGuard Home in a
    //   container, Pi-hole on a separate box, etc.) can claim it. We
    //   still render DHCP options above — option 6 already points at
    //   external_server so clients resolve there.
    //
    //   WolfRouter → dnsmasq answers DNS itself. `port=N` sets the
    //   listening port (default 53; 5353 is the common "move out of
    //   the way for AdGuard" value). Forwarders, cache, local
    //   records, EDNS client subnet, ad-block hosts and query logging
    //   all apply in this mode only.
    match lan.dns.mode {
        DnsMode::External => {
            cfg.push_str("# DNS disabled: WolfRouter DHCP-only, client DNS via external_server.\n");
            cfg.push_str("port=0\n");
        }
        DnsMode::WolfRouter => {
            // Explicit port directive so 5353 (or whatever the operator
            // picked) actually takes effect. Emit the line even at 53 so
            // the config is self-documenting.
            cfg.push_str(&format!("port={}\n", lan.dns.listen_port));
            // Cache size: 0 = disabled, otherwise a reasonable 1500.
            let cache_size = if lan.dns.cache_enabled { 1500 } else { 0 };
            cfg.push_str(&format!("cache-size={}\n", cache_size));
            for fwd in &lan.dns.forwarders {
                cfg.push_str(&format!("server={}\n", fwd));
            }
            // EDNS Client Subnet (RFC 7871). When enabled, dnsmasq tags every
            // outbound forwarded query with the client's /32 (IPv4) or /128
            // (IPv6). Upstreams that honour ECS — AdGuard Home, NextDNS,
            // Pi-hole with EDNS enabled — then attribute queries to the real
            // LAN client instead of to the router. Matters most for AdGuard
            // running in Docker bridge mode where every query otherwise
            // appears to come from 172.17.0.1.
            if lan.dns.forward_client_subnet {
                cfg.push_str("add-subnet=32,128\n");
            }
            for rec in &lan.dns.local_records {
                // address= gives an A record; host-record= gives A + PTR.
                cfg.push_str(&format!("host-record={},{}\n", rec.hostname, rec.ip));
            }
            // Wildcard local domains — see render_wildcard_lines.
            cfg.push_str(&render_wildcard_lines(&lan.dns.wildcard_domains));
            // Ad-blocking: use a shared hosts file if available. The file is
            // maintained separately (phase 4 feature) — for now it's optional.
            if lan.dns.block_ads && Path::new(ADBLOCK_HOSTS).exists() {
                cfg.push_str(&format!("addn-hosts={}\n", ADBLOCK_HOSTS));
            }
            // Query logging — drives the "LAN-side DNS health" diagnostic in
            // the DNS Tools tab. When on, dnsmasq writes one line per query to
            // a dedicated per-LAN file (NOT syslog — we don't want to pollute
            // journald, and reading back is much simpler from a known path).
            if lan.dns.query_log {
                let log_path = format!("{}/lan-{}.log", LEASE_DIR, lan.id);
                cfg.push_str("log-queries\n");
                cfg.push_str(&format!("log-facility={}\n", log_path));
            }
        }
    }

    fs::write(&path, cfg)
        .map_err(|e| format!("Write dnsmasq config {}: {}", path, e))?;
    Ok(path)
}

/// Outcome of the apply-time interface resolution. The watchdog and health
/// panel use this to surface "we silently fixed something for you" so the
/// operator can persist the fix in their saved config.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApplyResolution {
    /// LAN's configured interface carries router_ip — nothing to fix.
    Healthy { iface: String },
    /// router_ip is on a different interface than configured. dnsmasq is
    /// bound to the actual carrier; saved config still says `configured`.
    /// Operator should either move the IP, or update the saved config —
    /// the UI exposes both as one-click actions.
    BoundToActualInterface { configured: String, actual: String },
    /// Configured interface exists but didn't carry router_ip (and no
    /// other interface did either). We assigned router_ip live with
    /// `ip addr add`. Not persisted to /etc/network/interfaces or
    /// netplan — operator should persist if they want it across reboots
    /// without the watchdog re-applying every tick.
    AssignedRouterIp { iface: String },
    /// Configured interface is enslaved to a Linux bridge (typical
    /// scenario: a VM bridge-mode passthrough auto-created `br-pt-<iface>`
    /// and put the physical NIC into it). DHCP and other broadcast
    /// frames arrive at the master, not the slave — `SO_BINDTODEVICE`
    /// to the slave silently sees nothing. dnsmasq is bound to the
    /// master bridge instead. Operator should either update the LAN's
    /// saved interface to `master`, or detach the slave from the bridge.
    BoundToBridgeMaster { slave: String, master: String },
}

impl ApplyResolution {
    pub fn iface(&self) -> &str {
        match self {
            ApplyResolution::Healthy { iface } => iface,
            ApplyResolution::BoundToActualInterface { actual, .. } => actual,
            ApplyResolution::AssignedRouterIp { iface } => iface,
            ApplyResolution::BoundToBridgeMaster { master, .. } => master,
        }
    }
}

/// Decide which interface dnsmasq should bind for this LAN, performing
/// safe live fixes when host state and saved config disagree:
///   • configured iface ✓ + router_ip on it ✓                  → Healthy
///   • configured iface ✓ + router_ip on a *different* iface  → BoundToActualInterface
///   • configured iface ✓ + router_ip on no iface              → ip addr add → AssignedRouterIp
///   • configured iface ✗ + router_ip on a different iface    → BoundToActualInterface
///   • configured iface ✗ + router_ip on no iface              → Err
///
/// Used by both the live `start()` path and the UI's read-only health
/// probe. Every "self-heal" branch only runs when the current state is
/// already broken — working LANs always fall into Healthy.
pub fn resolve_apply_interface(lan: &LanSegment) -> Result<ApplyResolution, String> {
    let configured = lan.interface.clone();
    let configured_exists = std::path::Path::new(
        &format!("/sys/class/net/{}", configured)
    ).exists();

    // Bridge-slave check: when the configured interface is enslaved to
    // a Linux bridge — typical when a VM with bridge-mode passthrough
    // auto-created `br-pt-<iface>` and put the physical NIC into it —
    // DHCP/broadcast frames arrive at the MASTER, not the slave. dnsmasq
    // bound to the slave via `SO_BINDTODEVICE` (what `bind-interfaces`
    // uses) silently sees no client traffic. Redirect resolution to the
    // master bridge before any other branch runs. PapaSchlumpf hit this
    // when his HA VM's bridge-mode passthrough enslaved ens1.
    if configured_exists
        && let Some(master) = bridge_master_of(&configured) {
            return resolve_against_bridge_master(lan, &configured, &master);
        }

    // Find ANY interface (not just the configured one) currently carrying
    // router_ip. The PapaSchlumpf case: router_ip was a secondary on ens1
    // while the saved LAN config said `br-lan`.
    let actual_carrier = find_interface_with_ip(&lan.router_ip);

    if configured_exists {
        // Bring the configured iface up if it's down — the watchdog hits
        // this on every tick after a reboot if the bridge starts down.
        if !is_interface_up(&configured) {
            let _ = Command::new("ip").args(["link", "set", &configured, "up"]).output();
            std::thread::sleep(std::time::Duration::from_millis(400));
            if !is_interface_up(&configured) {
                return Err(format!(
                    "LAN '{}' interface '{}' is DOWN. Tried `ip link set {} up` but it didn't come up. \
                     If '{}' is a bridge, it likely has no slave interfaces — add at least one with \
                     `ip link set <slave> master {}` and `ip link set <slave> up`. \
                     If it's a physical NIC, check the cable/driver.",
                    lan.name, configured, configured, configured, configured
                ));
            }
            info!("WolfRouter: brought interface '{}' up for LAN '{}'", configured, lan.name);
        }

        let configured_addrs = interface_addresses(&configured);
        if configured_addrs.iter().any(|ip| ip == &lan.router_ip) {
            return Ok(ApplyResolution::Healthy { iface: configured });
        }

        // Configured iface up but router_ip not on it.
        if let Some(other) = actual_carrier {
            // router_ip lives on a different interface — bind there.
            // Don't rewrite the saved config: the operator may have
            // INTENDED `configured` and just hasn't moved the IP yet.
            // The health panel surfaces this with a one-click "use
            // <other> as the saved interface" action.
            // Operator-facing warning is logged by the caller's
            // `ApplyResolution::BoundToActualInterface` arm — keep this
            // as a developer breadcrumb only.
            tracing::debug!(
                "resolve_apply_interface: LAN '{}' router_ip {} is on '{}', not configured '{}' — binding to '{}'",
                lan.name, lan.router_ip, other, configured, other
            );
            return Ok(ApplyResolution::BoundToActualInterface {
                configured, actual: other,
            });
        }

        // No interface carries router_ip. Add it to the configured iface.
        let prefix = lan.subnet_cidr.split('/').nth(1).unwrap_or("24");
        let cidr = format!("{}/{}", lan.router_ip, prefix);
        let out = Command::new("ip")
            .args(["addr", "add", &cidr, "dev", &configured])
            .output()
            .map_err(|e| format!("ip addr add: {}", e))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // "File exists" is a benign race — kernel got there first.
            if !stderr.contains("File exists") {
                return Err(format!(
                    "Tried to assign LAN '{}' router_ip {} to '{}' (so dnsmasq can bind), \
                     but `ip addr add {} dev {}` failed: {}. \
                     If you intended router_ip on a different interface, edit the LAN.",
                    lan.name, lan.router_ip, configured, cidr, configured, stderr.trim()
                ));
            }
        }
        // The user-facing warning is logged by the caller's
        // `ApplyResolution::AssignedRouterIp` arm in `start_all_for_node` /
        // `start()` — keeps the operator from seeing the same self-heal
        // narrated twice. Keep this debug-level breadcrumb so a developer
        // tailing logs can still tell where the live `ip addr add` ran.
        tracing::debug!(
            "resolve_apply_interface: ran `ip addr add {} dev {}` for LAN '{}'",
            cidr, configured, lan.name
        );
        return Ok(ApplyResolution::AssignedRouterIp { iface: configured });
    }

    // Configured iface doesn't exist on this host at all.
    if let Some(other) = actual_carrier {
        // router_ip is on SOME iface — bind there, surface the mismatch.
        // Operator-facing warning is logged by the caller's
        // `ApplyResolution::BoundToActualInterface` arm.
        tracing::debug!(
            "resolve_apply_interface: LAN '{}' configured iface '{}' missing; router_ip {} on '{}' — binding to '{}'",
            lan.name, configured, lan.router_ip, other, other
        );
        return Ok(ApplyResolution::BoundToActualInterface {
            configured, actual: other,
        });
    }
    let available = list_host_interfaces();
    Err(format!(
        "LAN '{}' interface '{}' doesn't exist on this host, and router_ip {} \
         isn't assigned to any interface either. Available interfaces: {}. \
         Either create the bridge first, change the LAN's interface, or \
         assign {} to an existing interface.",
        lan.name, configured, lan.router_ip,
        if available.is_empty() { "(none)".to_string() } else { available.join(", ") },
        lan.router_ip
    ))
}

/// Find the (first) interface carrying the given IPv4 address, or None
/// when no interface has it. Walks `/sys/class/net` and asks `ip addr`
/// per interface — same shape the rest of dhcp.rs uses.
fn find_interface_with_ip(target_ip: &str) -> Option<String> {
    list_host_interfaces().into_iter()
        .find(|iface| interface_addresses(iface).iter().any(|ip| ip == target_ip))
}

/// If `iface` is enslaved to a Linux bridge, return the bridge name.
/// `None` when the interface is standalone, when its master isn't a
/// bridge (e.g. a bond), or when /sys lookup fails.
///
/// Bridge slaves can't deliver broadcast/multicast frames up the host's
/// L3 stack — the kernel rewrites `skb->dev` to the master before
/// dispatch, so a `SO_BINDTODEVICE`-bound socket on the slave never
/// matches incoming packets. Callers that need to bind a listening
/// socket (dnsmasq, in our case) must use the master.
pub(super) fn bridge_master_of(iface: &str) -> Option<String> {
    let master_link = format!("/sys/class/net/{}/master", iface);
    let target = std::fs::read_link(&master_link).ok()?;
    let bridge_name = target.file_name()?.to_str()?.to_string();
    // Verify the master is actually a bridge (not a bond, team, etc.).
    let bridge_check = format!("/sys/class/net/{}/bridge", bridge_name);
    if std::path::Path::new(&bridge_check).exists() {
        Some(bridge_name)
    } else {
        None
    }
}

/// Resolve binding for the case where the LAN's configured iface is a
/// bridge slave. Mirrors the standalone-iface logic but operates on the
/// master bridge:
///   • master carries router_ip                       → BoundToBridgeMaster
///   • master doesn't, but another iface does          → BoundToActualInterface
///   • no iface carries router_ip                      → ip addr add to master
///
/// Also defensively removes router_ip from the slave if a previous
/// (broken) self-heal added it there — leaving it would create two
/// interfaces with the same IP, which causes ARP responses from
/// whichever wins the race. The IP belongs on the master only.
fn resolve_against_bridge_master(
    lan: &LanSegment,
    slave: &str,
    master: &str,
) -> Result<ApplyResolution, String> {
    // Master must be up for dnsmasq to bind to it. Bridges typically
    // report `up` once they have at least one slave (we have one — the
    // physical NIC), but bring it up explicitly if needed.
    if !is_interface_up(master) {
        let _ = Command::new("ip").args(["link", "set", master, "up"]).output();
        std::thread::sleep(std::time::Duration::from_millis(400));
        if !is_interface_up(master) {
            return Err(format!(
                "LAN '{}' configured iface '{}' is enslaved to bridge '{}', but the bridge \
                 is DOWN. Bring '{}' up (`ip link set {} up`) or detach '{}' from the bridge \
                 and update the LAN's configured interface.",
                lan.name, slave, master, master, master, slave
            ));
        }
    }

    // Defensive cleanup: if a previous (broken) self-heal added
    // router_ip to the slave, remove it. The IP belongs on the master.
    if interface_addresses(slave).iter().any(|ip| ip == &lan.router_ip) {
        let prefix = lan.subnet_cidr.split('/').nth(1).unwrap_or("24");
        let cidr = format!("{}/{}", lan.router_ip, prefix);
        let out = Command::new("ip").args(["addr", "del", &cidr, "dev", slave]).output();
        if let Ok(o) = out
            && o.status.success() {
                tracing::info!(
                    "WolfRouter LAN '{}': removed stale router_ip {} from bridge slave '{}'; \
                     IP belongs on master '{}'.",
                    lan.name, cidr, slave, master
                );
            }
    }

    let master_addrs = interface_addresses(master);
    if master_addrs.iter().any(|ip| ip == &lan.router_ip) {
        return Ok(ApplyResolution::BoundToBridgeMaster {
            slave: slave.to_string(),
            master: master.to_string(),
        });
    }

    // Master doesn't carry router_ip. If router_ip is on some OTHER
    // interface entirely, bind dnsmasq there — the operator may have
    // moved the LAN to a different NIC and the slave/bridge situation
    // is incidental.
    if let Some(other) = find_interface_with_ip(&lan.router_ip)
        && other != master && other != slave {
            return Ok(ApplyResolution::BoundToActualInterface {
                configured: slave.to_string(),
                actual: other,
            });
        }

    // No other interface carries router_ip. Assign it to the master
    // bridge (NOT the slave — that bind would be invisible to clients).
    let prefix = lan.subnet_cidr.split('/').nth(1).unwrap_or("24");
    let cidr = format!("{}/{}", lan.router_ip, prefix);
    let out = Command::new("ip")
        .args(["addr", "add", &cidr, "dev", master])
        .output()
        .map_err(|e| format!("ip addr add: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // "File exists" = kernel got there first; benign.
        if !stderr.contains("File exists") {
            return Err(format!(
                "Tried to assign LAN '{}' router_ip {} to master bridge '{}' (configured \
                 iface '{}' is a bridge slave, so binding dnsmasq to the slave wouldn't see \
                 client traffic), but `ip addr add {} dev {}` failed: {}.",
                lan.name, lan.router_ip, master, slave, cidr, master, stderr.trim()
            ));
        }
    }
    tracing::debug!(
        "resolve_apply_interface: ran `ip addr add {} dev {}` (master bridge of slave '{}') for LAN '{}'",
        cidr, master, slave, lan.name
    );
    Ok(ApplyResolution::BoundToBridgeMaster {
        slave: slave.to_string(),
        master: master.to_string(),
    })
}

/// Start (or restart) the dnsmasq instance for a LAN. Returns the
/// apply-time resolution outcome so the caller (watchdog, save-and-apply
/// path) can surface "we silently fixed X" to the operator.
pub fn start(lan: &LanSegment) -> Result<ApplyResolution, String> {
    // Resolve which interface to bind. Self-healing: when router_ip is
    // on a different iface than configured, we bind to the actual one;
    // when no iface carries router_ip but the configured iface exists,
    // we add router_ip to it live. Hard-fails only when no iface exists
    // at all — there's no safe auto-fix for that.
    let resolution = resolve_apply_interface(lan)?;
    let bind_iface = resolution.iface().to_string();

    // Render config using the resolved interface (not lan.interface
    // directly — the two differ when self-heal kicked in).
    let cfg_path = render_config_for_iface(lan, &bind_iface)?;

    // If there's an existing instance, kill it gracefully first. Our pid
    // files are per-LAN so we don't affect anyone else's dnsmasq.
    stop(lan)?;

    // Verify dnsmasq exists.
    if !Command::new("which").arg("dnsmasq").status()
        .map(|s| s.success()).unwrap_or(false)
    {
        return Err(
            "dnsmasq is not installed. Install the 'dnsmasq' package and retry.".into()
        );
    }

    // Spawn as daemon (dnsmasq's default is to daemonize). `--conf-file=`
    // (with the equals sign) is the only form dnsmasq accepts — separate
    // arg causes "junk found in command line" because dnsmasq treats
    // the path as a non-option positional. Same for --local-service.
    let out = Command::new("dnsmasq")
        .arg(format!("--conf-file={}", cfg_path))
        .arg("--local-service")
        .output()
        .map_err(|e| format!("spawn dnsmasq: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "dnsmasq failed to start for LAN '{}': {}",
            lan.name, stderr.trim()
        ));
    }
    info!("WolfRouter: dnsmasq started for LAN {} on {}", lan.name, bind_iface);

    // Proactively announce the gateway's MAC to every LAN client so none is
    // left on a stale ARP entry after WolfRouter (re)binds the gateway IP —
    // across an upgrade restart, a self-heal that moved router_ip to another
    // interface, or a WAN bounce. macOS especially clings to stale neighbour
    // entries: PapaSchlumpf's MacBook lost the whole LAN (couldn't even ping
    // the gateway) until he reset Wi-Fi, while every other device rode it out.
    announce_gateway(&bind_iface, &lan.router_ip);

    Ok(resolution)
}

/// Push the LAN gateway's current MAC to every client via gratuitous ARP, and
/// arm the kernel to keep doing so on future link-ups / MAC changes.
///
/// A client holding the gateway's *old* MAC — because a restart re-placed the
/// IP, a bridge MAC drifted, or the gateway briefly went unreachable on a WAN
/// bounce — black-holes all traffic to the gateway until its ARP entry ages
/// out: minutes on Linux, stickier still on macOS. RFC 5227 gratuitous ARP is
/// the standard cure: announce unsolicited so every neighbour overwrites its
/// cache at once. Best-effort throughout — an apply must never fail over it.
fn announce_gateway(iface: &str, router_ip: &str) {
    // arp_notify=1: the kernel emits a gratuitous ARP whenever the iface is
    // brought up or its hardware address changes. Set-and-forget, needs no
    // tool, harmless if the knob is absent — covers the link-up / MAC-drift
    // cases for free on every future event.
    let _ = Command::new("sysctl")
        .args(["-w", "net.ipv4.conf.all.arp_notify=1"]).output();
    let _ = Command::new("sysctl")
        .args(["-w", &format!("net.ipv4.conf.{}.arp_notify=1", iface)]).output();

    // The kernel does NOT arp_notify on a mere secondary-IP add (how WolfRouter
    // assigns a gateway when the IP wasn't already present) and never fires on
    // a plain service restart where the IP didn't move — so fire an explicit
    // unsolicited ARP now. iputils-arping form (the build shipped on WolfStack's
    // Debian/Ubuntu/Proxmox targets); best-effort, with arp_notify as the
    // tool-free backstop when arping isn't installed.
    //
    // Run it on a detached thread: arping sends a packet/sec, so `-c 2` blocks
    // ~2s, and start() is called inline on latency-sensitive paths (inter-node
    // config-receive, save-and-apply). The thread still waits on the child so
    // it's reaped (no zombies), but the caller returns immediately. The GARP
    // goes out a few ms later — the gateway is already live by then.
    let (iface, router_ip) = (iface.to_string(), router_ip.to_string());
    std::thread::spawn(move || {
        match Command::new("arping")
            .args(["-U", "-c", "2", "-w", "3", "-I", &iface, &router_ip])
            .output()
        {
            Ok(o) if o.status.success() => info!(
                "WolfRouter: announced gateway {} on {} (gratuitous ARP)", router_ip, iface
            ),
            Ok(_) => tracing::debug!(
                "WolfRouter: arping returned non-zero announcing {} on {} — arp_notify still armed",
                router_ip, iface
            ),
            Err(_) => tracing::debug!(
                "WolfRouter: arping unavailable to announce {} on {} — relying on arp_notify",
                router_ip, iface
            ),
        }
    });
}

/// List all non-loopback interfaces visible to the kernel. Used to give
/// the admin a useful "did you mean…" hint when their LAN config points
/// at a bridge that doesn't exist.
pub(super) fn list_host_interfaces() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name == "lo" { continue; }
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    out
}

/// True when the kernel reports the interface as carrying or capable of
/// carrying traffic. We accept both `up` and `unknown`:
/// - "up": physical NIC with carrier, or bridge with active slaves
/// - "unknown": bridges without slaves report this even when configured
///   up; tap/tun devices likewise. dnsmasq can still bind to them.
/// - "down" / "lowerlayerdown": dnsmasq's bind-interfaces will silently
///   produce no socket. Refuse and surface the diagnostic.
pub(super) fn is_interface_up(iface: &str) -> bool {
    let path = format!("/sys/class/net/{}/operstate", iface);
    std::fs::read_to_string(&path)
        .map(|s| {
            let s = s.trim().to_lowercase();
            s == "up" || s == "unknown"
        })
        .unwrap_or(false)
}

/// Return all IPv4 addresses currently assigned to the interface (just the
/// host part, not CIDR). Empty Vec if `ip` isn't on PATH or the interface
/// has nothing — the caller distinguishes those cases via the existence
/// check that ran upstream.
pub(super) fn interface_addresses(iface: &str) -> Vec<String> {
    let out = match Command::new("ip").args(["-o", "-4", "addr", "show", "dev", iface]).output() {
        Ok(o) if o.status.success() => o,
        _ => return vec![],
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut result = Vec::new();
    for line in stdout.lines() {
        if let Some(idx) = line.find("inet ") {
            let after = &line[idx + 5..];
            let cidr = after.split_whitespace().next().unwrap_or("");
            if let Some((ip, _)) = cidr.split_once('/') {
                result.push(ip.to_string());
            }
        }
    }
    result
}

/// Stop the dnsmasq instance for a LAN (if any). Safe to call even when
/// nothing is running.
///
/// Waits for the process to actually exit (up to ~2 seconds) before
/// returning. Pre-v18.7.30 we sent SIGTERM and immediately deleted
/// the PID file — the next `start()` would then race with the still-
/// dying dnsmasq and the new instance would fail to bind :53 / :67
/// on the same interface. That manifested as "dnsmasq failed to start"
/// errors on rapid save cycles (the LAN editor save-and-apply path).
pub fn stop(lan: &LanSegment) -> Result<(), String> {
    let pid_file = format!("{}/lan-{}.pid", PID_DIR, lan.id);
    let pid_str = match fs::read_to_string(&pid_file) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return Ok(()),
    };
    if pid_str.is_empty() { return Ok(()); }
    // Validate the PID is numeric before shelling out to kill. A
    // corrupted or manually-edited pid file can otherwise contain
    // arbitrary text; `kill "garbage"` silently fails and we proceed
    // to remove the pid file, at which point the next start() spawns
    // a new dnsmasq while the old one still holds the port. The
    // numeric check also rejects negative numbers (which `kill -N`
    // interprets as a process group — not what we want here).
    let pid: u32 = match pid_str.parse() {
        Ok(p) => p,
        Err(_) => {
            // Unreadable pid file — remove it and move on. A subsequent
            // start() will spawn cleanly; if the old dnsmasq is still
            // running on the bridge, the new one will fail to bind and
            // surface a clear error to the operator.
            let _ = fs::remove_file(&pid_file);
            return Ok(());
        }
    };
    let pid_s = pid.to_string();

    // SIGTERM (dnsmasq handles it cleanly and releases sockets fast).
    let _ = Command::new("kill").arg(&pid_s).status();

    // Poll /proc/<pid> for up to 2 seconds. dnsmasq typically exits
    // in < 50ms on SIGTERM; we cap at 2s to avoid blocking a router
    // reconfigure indefinitely on a stuck process.
    let proc_path = format!("/proc/{}", pid_s);
    for _ in 0..40 {
        if !std::path::Path::new(&proc_path).exists() { break; }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // If still alive after 2s, escalate to SIGKILL. Better to force-
    // kill a stuck dnsmasq than leave it holding the port forever.
    if std::path::Path::new(&proc_path).exists() {
        let _ = Command::new("kill").args(["-KILL", &pid_s]).status();
        // Give SIGKILL a beat to propagate — the kernel is synchronous
        // here, so this is mostly paranoia.
        for _ in 0..20 {
            if !std::path::Path::new(&proc_path).exists() { break; }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    // Remove the pid file now that the process is confirmed gone.
    let _ = fs::remove_file(&pid_file);
    Ok(())
}

/// Remove all traces of a LAN's dnsmasq: stop it, delete config and lease.
pub fn purge(lan: &LanSegment) -> Result<(), String> {
    stop(lan)?;
    let cfg = format!("{}/lan-{}.conf", DNSMASQ_DIR, lan.id);
    let leases = format!("{}/lan-{}.leases", LEASE_DIR, lan.id);
    let _ = fs::remove_file(&cfg);
    let _ = fs::remove_file(&leases);
    Ok(())
}

/// One active DHCP lease as read from a dnsmasq lease file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Lease {
    pub expires: u64,
    pub mac: String,
    pub ip: String,
    pub hostname: String,
    pub client_id: String,
}

/// Parse the dnsmasq lease file for a LAN. Format per-line:
/// `<expires> <mac> <ip> <hostname> <client-id>`
pub fn read_leases(lan_id: &str) -> Vec<Lease> {
    let path = format!("{}/lan-{}.leases", LEASE_DIR, lan_id);
    let text = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 { continue; }
        let expires: u64 = parts[0].parse().unwrap_or(0);
        let mac = parts[1].to_string();
        let ip = parts[2].to_string();
        let hostname = parts.get(3).map(|s| s.to_string()).unwrap_or_default();
        let client_id = parts.get(4).map(|s| s.to_string()).unwrap_or_default();
        // dnsmasq sometimes writes "*" as placeholder for missing hostname.
        let hostname = if hostname == "*" { "".into() } else { hostname };
        out.push(Lease { expires, mac, ip, hostname, client_id });
    }
    out
}

/// Convert a prefix length (e.g. 24) to a dotted-quad netmask.
fn prefix_to_netmask(prefix: u32) -> String {
    if prefix >= 32 { return "255.255.255.255".into(); }
    let mask: u32 = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xff,
        (mask >> 16) & 0xff,
        (mask >> 8) & 0xff,
        mask & 0xff
    )
}

/// Bring up every LAN segment owned by this node. Idempotent: if an
/// instance is already running with the same config, SIGHUP it instead
/// of restart. MVP does a stop/start cycle because it's simpler and the
/// disruption is ~100ms.
pub fn start_all_for_node(config: &RouterConfig, self_node_id: &str) {
    for lan in &config.lans {
        if lan.node_id != self_node_id { continue; }
        match start(lan) {
            Ok(ApplyResolution::Healthy { .. }) => {}
            Ok(ApplyResolution::BoundToActualInterface { configured, actual }) => {
                warn!(
                    "WolfRouter LAN '{}': self-healed at apply — configured iface '{}' \
                     doesn't carry router_ip {}, bound dnsmasq to '{}'. \
                     Update the LAN's saved interface to '{}' from the UI to make this stick.",
                    lan.name, configured, lan.router_ip, actual, actual
                );
            }
            Ok(ApplyResolution::AssignedRouterIp { iface }) => {
                warn!(
                    "WolfRouter LAN '{}': self-healed at apply — added router_ip {} to '{}' live \
                     (no interface carried it). Persist via your distro's network config to \
                     survive reboots without watchdog re-applying.",
                    lan.name, lan.router_ip, iface
                );
            }
            Ok(ApplyResolution::BoundToBridgeMaster { slave, master }) => {
                warn!(
                    "WolfRouter LAN '{}': self-healed at apply — configured iface '{}' is enslaved \
                     to bridge '{}' (likely from a VM bridge-mode passthrough). Bound dnsmasq to \
                     '{}' instead — bridge slaves can't deliver DHCP/broadcast traffic up the host \
                     stack, so binding to '{}' would leave clients unable to get an IP. Update the \
                     LAN's saved interface to '{}' from the UI, or detach '{}' from the bridge if \
                     the passthrough was unintended.",
                    lan.name, slave, master, master, slave, master, slave
                );
            }
            Err(e) => {
                warn!("Failed to start LAN '{}': {}", lan.name, e);
            }
        }
    }
}

/// Stop every LAN instance on this node (used on shutdown).
#[allow(dead_code)]
pub fn stop_all_for_node(config: &RouterConfig, self_node_id: &str) {
    for lan in &config.lans {
        if lan.node_id != self_node_id { continue; }
        let _ = stop(lan);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wc(domain: &str, ip: &str) -> WildcardDomain {
        WildcardDomain { domain: domain.into(), ip: ip.into() }
    }

    #[test]
    fn wildcard_domains_render_as_address_directive() {
        let out = render_wildcard_lines(&[
            wc("ai.home", "192.168.10.2"),
            wc("*.lab.lan", "192.168.10.3"),   // leading *. stripped
            wc(".svc.home", "192.168.10.4"),   // leading . stripped
            wc("  pad.home  ", " 192.168.10.5 "), // trimmed
        ]);
        assert!(out.contains("address=/ai.home/192.168.10.2\n"),
            "wildcard domain must render as dnsmasq address=/domain/ip; got:\n{out}");
        assert!(out.contains("address=/lab.lan/192.168.10.3\n"),
            "a leading *. must be stripped to the bare domain");
        assert!(out.contains("address=/svc.home/192.168.10.4\n"),
            "a leading . must be stripped to the bare domain");
        assert!(out.contains("address=/pad.home/192.168.10.5\n"),
            "domain and ip must be trimmed");
    }

    #[test]
    fn empty_wildcard_domains_render_nothing() {
        // GOLDEN RULE: a LAN with no wildcard_domains renders an empty string,
        // so its dnsmasq config is byte-for-byte the pre-feature behaviour —
        // an upgrade changes no existing LAN's config.
        assert_eq!(render_wildcard_lines(&[]), "");
        assert!(!render_wildcard_lines(&[]).contains("address=/"));
    }

    #[test]
    fn blank_wildcard_domain_is_skipped_not_malformed() {
        // A domain that normalises to empty must be skipped, never rendered as
        // `address=//ip` — that would make dnsmasq reject the whole config and
        // take the LAN's DNS+DHCP down. Validation also rejects these; the
        // renderer guards defensively.
        let out = render_wildcard_lines(&[wc("*.", "10.0.0.1"), wc("", "10.0.0.2"), wc(".", "10.0.0.3")]);
        assert_eq!(out, "", "blank domains must produce no lines at all; got:\n{out}");
        assert!(!out.contains("address=//"));
    }

    #[test]
    fn structurally_unsafe_wildcard_entries_are_skipped() {
        // Defense-in-depth: even if a bad entry reaches the renderer (config
        // hand-edited on disk, bypassing the API validator), it must be
        // dropped rather than emit a directive dnsmasq would choke on.
        let out = render_wildcard_lines(&[
            wc("ok.home", "10.0.0.1"),          // valid — kept
            wc("bad/slash.home", "10.0.0.2"),   // slash breaks address=/.../
            wc("has#hash.home", "10.0.0.3"),    // # breaks the directive
            wc("has space.home", "10.0.0.4"),   // whitespace
            wc("noip.home", "not-an-ip"),       // invalid IP
        ]);
        assert_eq!(out, "address=/ok.home/10.0.0.1\n",
            "only the valid entry may survive; got:\n{out}");
    }

    #[test]
    fn netmask_conversion() {
        assert_eq!(prefix_to_netmask(24), "255.255.255.0");
        assert_eq!(prefix_to_netmask(16), "255.255.0.0");
        assert_eq!(prefix_to_netmask(8), "255.0.0.0");
        assert_eq!(prefix_to_netmask(30), "255.255.255.252");
        assert_eq!(prefix_to_netmask(0), "0.0.0.0");
        assert_eq!(prefix_to_netmask(32), "255.255.255.255");
    }

    #[test]
    fn apply_resolution_iface_includes_bridge_master() {
        // Regression guard: every variant of ApplyResolution must report
        // the interface dnsmasq is actually bound to via `iface()`. The
        // watchdog and health probe rely on this to decide whether the
        // bind looks alive — missing a variant here would silently make
        // the watchdog think bridge-master self-heals are unhealthy and
        // restart loop.
        let h = ApplyResolution::Healthy { iface: "br0".into() };
        assert_eq!(h.iface(), "br0");

        let b = ApplyResolution::BoundToActualInterface {
            configured: "br-lan".into(), actual: "ens0".into(),
        };
        assert_eq!(b.iface(), "ens0");

        let a = ApplyResolution::AssignedRouterIp { iface: "ens1".into() };
        assert_eq!(a.iface(), "ens1");

        let m = ApplyResolution::BoundToBridgeMaster {
            slave: "ens1".into(), master: "br-pt-ens1".into(),
        };
        assert_eq!(m.iface(), "br-pt-ens1",
            "BoundToBridgeMaster::iface() must return the master — dnsmasq binds there \
             because the slave can't deliver broadcast traffic up the host stack");
    }

    #[test]
    fn bridge_master_of_returns_none_for_loopback() {
        // Loopback is never a bridge slave on any sane host. This is the
        // cheapest sanity check that bridge_master_of doesn't panic on
        // real /sys paths and correctly distinguishes "no master link"
        // from "master is a bridge".
        assert!(bridge_master_of("lo").is_none());
    }

    #[test]
    fn bridge_master_of_returns_none_for_nonexistent_iface() {
        // Defensive: callers may pass an interface name that doesn't
        // exist on this host. `read_link` returns Err in that case and
        // we want None, not a panic.
        assert!(bridge_master_of("does-not-exist-xyz123").is_none());
    }

    #[test]
    fn bridge_master_of_resolves_real_bridge_slave_when_present() {
        // Opt-in integration test: when the env vars are set, verify
        // bridge_master_of resolves a known-real bridge-slave/master pair
        // on the host. Used to validate the /sys read against a live
        // kernel — the unit test suite normally skips this because it
        // requires root to set up.
        //
        // Usage:
        //   sudo ip link add SLAVE type veth peer name SLAVE-peer
        //   sudo ip link add MASTER type bridge
        //   sudo ip link set SLAVE master MASTER
        //   WOLFSTACK_TEST_BRIDGE_SLAVE=SLAVE WOLFSTACK_TEST_BRIDGE_MASTER=MASTER \
        //     cargo test bridge_master_of_resolves_real_bridge_slave
        let slave = match std::env::var("WOLFSTACK_TEST_BRIDGE_SLAVE") {
            Ok(s) => s, Err(_) => return,
        };
        let expected_master = std::env::var("WOLFSTACK_TEST_BRIDGE_MASTER")
            .expect("set WOLFSTACK_TEST_BRIDGE_MASTER alongside WOLFSTACK_TEST_BRIDGE_SLAVE");

        let resolved = bridge_master_of(&slave);
        assert_eq!(
            resolved.as_deref(), Some(expected_master.as_str()),
            "bridge_master_of('{}') should return '{}' (the bridge it's enslaved to)",
            slave, expected_master
        );

        // Bridge itself should have no master.
        assert!(
            bridge_master_of(&expected_master).is_none(),
            "bridge_master_of('{}') should return None — the bridge is the master, not a slave",
            expected_master
        );
    }
}
