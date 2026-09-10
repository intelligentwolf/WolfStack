// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Container management — Docker and LXC support for WolfStack
//!
//! Docker: communicates via /var/run/docker.sock REST API
//! LXC: communicates via lxc-* CLI commands
//! WolfNet: Optional overlay network integration for container networking

pub mod docker_dns;
pub mod image_watcher;
pub mod lxc_storage;

use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::Mutex;
use std::time::Instant;
use tracing::{error, info, warn};
use crate::node_identity::PeerAuth;

/// Shared HTTP client for sync_wolfnet_peer_routes. Per-call was a
/// latent leak source even though the function is currently
/// `#[allow(dead_code)]` — keeping it leak-clean so whenever it's
/// wired back up it doesn't regress.
static CONTAINER_WOLFNET_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .timeout(std::time::Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

/// One-time WolfNet networking initialization — called at WolfStack startup.
/// Sets kernel parameters and iptables rules needed for container traffic to flow through wolfnet0.
/// Called once at startup. The reconciliation loop (cleanup_stale_wolfnet_routes) re-applies
/// iptables rules every 30s to survive Docker restarts that rebuild the FORWARD chain.
pub fn wolfnet_init() {
    // Check if wolfnet0 exists
    let exists = Command::new("ip").args(["link", "show", "wolfnet0"]).output()
        .map(|o| o.status.success()).unwrap_or(false);
    if !exists {
        return;
    }

    setup_wolfnet_forwarding();
}

/// Put (and keep) WolfStack's wolfnet0 ACCEPT rules at the head of a filter
/// chain. `with_conntrack` adds the ESTABLISHED,RELATED accept that the Docker
/// chains need; the FORWARD chain already carries one of its own.
///
/// Re-applies only when a rule has actually gone missing. The caller runs from
/// the 60s reconciliation loop, and the delete-then-insert-at-1 dance this
/// replaces rewrote a perfectly healthy ruleset on every single pass — a
/// permanent drip of NETFILTER_CFG audit records on every WolfStack host, plus
/// a window each minute where the rules were briefly absent. `iptables -C`
/// compares the parsed rule rather than its text, so `--ctstate
/// ESTABLISHED,RELATED` still matches a rule iptables prints back as
/// `RELATED,ESTABLISHED`.
///
/// Presence is checked, not position: position 1 was never actually held in
/// steady state anyway. Docker re-inserts its own `-j DOCKER-USER` jump above
/// ours whenever it rebuilds, and that jump enters a chain we accept wolfnet0
/// traffic at the head of — so precedence survives where it matters, exactly
/// as it did before.
fn apply_wolfnet_accepts(chain: &str, with_conntrack: bool) {
    // Desired head-of-chain rules, in top-down order.
    let mut rules: Vec<Vec<&str>> = vec![
        vec!["-i", "wolfnet0", "-j", "ACCEPT"],
        vec!["-o", "wolfnet0", "-j", "ACCEPT"],
    ];
    if with_conntrack {
        rules.push(vec!["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]);
    }

    let all_present = rules.iter().all(|rule| {
        let mut args = vec!["-C", chain];
        args.extend_from_slice(rule);
        Command::new("iptables").args(&args).output()
            .map(|o| o.status.success()).unwrap_or(false)
    });
    if all_present { return; }

    // At least one is gone (Docker restarted, firewalld reloaded, someone
    // flushed the chain). Clear any survivors first — twice, in case an
    // earlier pass stacked a duplicate — then re-insert the whole set at the
    // head so the final order matches `rules`.
    for rule in &rules {
        for _ in 0..2 {
            let mut args = vec!["-D", chain];
            args.extend_from_slice(rule);
            let _ = Command::new("iptables").args(&args).output();
        }
    }
    for rule in rules.iter().rev() {
        let mut args = vec!["-I", chain, "1"];
        args.extend_from_slice(rule);
        let _ = Command::new("iptables").args(&args).output();
    }
}

/// Core forwarding setup — called from wolfnet_init() and cleanup_stale_wolfnet_routes().
/// Idempotent — safe to call repeatedly.
pub fn setup_wolfnet_forwarding() {
    // ── Kernel parameters ──
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.wolfnet0.forwarding=1"]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.wolfnet0.rp_filter=0"]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.wolfnet0.send_redirects=0"]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.wolfnet0.proxy_arp=1"]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.all.rp_filter=0"]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.all.send_redirects=0"]).output();

    // Enable forwarding on known bridge interfaces
    for iface in &["docker0", "lxcbr0"] {
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.forwarding=1", iface)]).output();
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.send_redirects=0", iface)]).output();
    }

    // ── firewalld trusted zone ──
    ensure_firewalld_trusted(&["wolfnet0", "lxcbr0", "docker0"]);

    // ── Blanket FORWARD rules for wolfnet0 ──
    // Any traffic in/out of wolfnet0 must be allowed — inserted at position 1
    // so they run before Docker's FORWARD jump to DOCKER-USER → DOCKER-ISOLATION
    apply_wolfnet_accepts("FORWARD", false);

    // ── Docker chains: DOCKER-USER, DOCKER-ISOLATION-STAGE-1/2 ──
    for chain in &["DOCKER-USER", "DOCKER-ISOLATION-STAGE-1", "DOCKER-ISOLATION-STAGE-2"] {
        let exists = Command::new("iptables").args(["-L", chain]).output()
            .map(|o| o.status.success()).unwrap_or(false);
        if !exists { continue; }

        apply_wolfnet_accepts(chain, true);
    }

    // ── raw PREROUTING exceptions for locally-owned workload subnets ──
    // jdelrue 2026-08-15: dockerd protects every container address with an
    // anti-direct-routing rule in the raw table
    // (`-t raw -A PREROUTING -d <ip> ! -i docker0 -j DROP`), which runs
    // BEFORE the FORWARD / DOCKER-USER accepts installed above — so a
    // packet another cluster node sent us over WolfNet for one of our own
    // containers was dropped at the earliest netfilter hook and none of
    // the accepts ever saw it. Keep a per-subnet exception at the head of
    // raw PREROUTING, scoped to traffic that arrived through wolfnet0 and
    // only for the workload CIDRs this node intentionally advertises over
    // gossip (default bridges excluded, exactly like auto-apply and the
    // predictive rule). Stale exceptions are removed when a bridge
    // disappears — this runs on the same 60s reconcile as the rest of
    // this function.
    reconcile_wolfnet_raw_workload_accepts();

    // ── MASQUERADE for non-WolfNet source IPs going out wolfnet0 ──
    // Containers without a WolfNet IP (using Docker IPs like 172.x) need source NAT
    // so remote peers can route replies back. Containers WITH WolfNet IPs are not
    // masqueraded — they keep their WolfNet IP as source.
    if let Some(net) = wolfnet_network() {
        let wn_subnet = net.cidr();
        // Versions before v25.26.1 wrote this rule with the node's /24.
        // On a wider WolfNet that rule MASQUERADEs every workload outside
        // the node's own third octet (klas: 10.100.20.x containers left
        // the node as 10.100.10.20), and because it precedes the corrected
        // rule it keeps doing so until removed.
        if let Some(legacy) = net.legacy_slash24() {
            let _ = Command::new("iptables").args([
                "-t", "nat", "-D", "POSTROUTING",
                "!", "-s", &legacy, "-o", "wolfnet0",
                "-j", "MASQUERADE"
            ]).output();
        }
        let check = Command::new("iptables").args([
            "-t", "nat", "-C", "POSTROUTING",
            "!", "-s", &wn_subnet, "-o", "wolfnet0",
            "-j", "MASQUERADE"
        ]).output();
        if check.map(|o| !o.status.success()).unwrap_or(true) {
            let _ = Command::new("iptables").args([
                "-t", "nat", "-A", "POSTROUTING",
                "!", "-s", &wn_subnet, "-o", "wolfnet0",
                "-j", "MASQUERADE"
            ]).output();
        }
    }
}

/// Keep raw-table PREROUTING exceptions in sync with this node's workload
/// subnets: one `-i wolfnet0 -d <cidr> -j ACCEPT` per locally-owned,
/// non-default-bridge CIDR (marker RAW_MARKER_LOCAL), stale ones removed.
/// See the call site in setup_wolfnet_forwarding for why raw is the only
/// table that can host this exception. v6 CIDRs participate only when the
/// operator has enabled IPv6 subnet routing; with the gate off, the empty
/// wanted-set still sweeps any v6 exceptions left from when it was on.
fn reconcile_wolfnet_raw_workload_accepts() {
    use crate::networking::router::{
        is_default_bridge_cidr, is_ipv6_cidr, v6_subnet_routing_enabled, RAW_MARKER_LOCAL,
    };
    let locals = crate::networking::collect_workload_subnets();

    let v4_wanted: Vec<String> = locals.iter()
        .filter(|s| !is_ipv6_cidr(s))
        .filter(|s| !is_default_bridge_cidr(s))
        .cloned()
        .collect();
    // Config is read only when a v6 candidate actually exists (same lazy
    // pattern as sync_subnet_routes_to_wolfnet).
    let v6_candidates: Vec<String> = locals.iter()
        .filter(|s| is_ipv6_cidr(s))
        .cloned()
        .collect();
    let v6_wanted: Vec<String> = if !v6_candidates.is_empty() && v6_subnet_routing_enabled() {
        v6_candidates
    } else {
        Vec::new()
    };

    reconcile_raw_accepts_family("iptables", &v4_wanted, RAW_MARKER_LOCAL);
    reconcile_raw_accepts_family("ip6tables", &v6_wanted, RAW_MARKER_LOCAL);
}

/// One address family of the reconcile above: read the current PREROUTING
/// rules, add missing exceptions, delete ours that no longer correspond to
/// a live workload subnet. Rules carrying the router-plumbing marker
/// (RAW_MARKER_ROUTE) are invisible here — different comment, so the
/// substring filter in the parser never selects them.
fn reconcile_raw_accepts_family(bin: &str, wanted: &[String], marker: &str) {
    let out = Command::new(bin)
        .args(["-t", "raw", "-S", "PREROUTING"])
        .output();
    let listing = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        // Can't read the table (no binary / raw unsupported) — adding
        // would fail the same way, and deleting blind is worse. Skip.
        _ => return,
    };
    let existing = parse_marked_raw_accept_cidrs(&listing, marker);
    let existing_set: std::collections::HashSet<&str> =
        existing.iter().map(String::as_str).collect();
    let wanted_set: std::collections::HashSet<&str> =
        wanted.iter().map(String::as_str).collect();

    for cidr in wanted {
        if !existing_set.contains(cidr.as_str())
            && let Err(e) = crate::networking::router::ensure_raw_wolfnet_accept(bin, "wolfnet0", cidr, marker) {
                tracing::warn!("wolfnet raw exception for {} not installed: {}", cidr, e);
            }
    }
    for cidr in &existing {
        if !wanted_set.contains(cidr.as_str()) {
            crate::networking::router::remove_raw_wolfnet_accept(bin, "wolfnet0", cidr, marker);
        }
    }
}

/// Pull the `-d <cidr>` operand out of every PREROUTING rule that carries
/// our marker comment. Tolerates both comment print forms — iptables-nft
/// quotes the comment (`--comment "wolfstack-wolfnet-local"`), legacy
/// prints it bare — by substring-matching the marker and trimming quotes
/// off the extracted operand defensively. Pure; unit-tested below.
fn parse_marked_raw_accept_cidrs(listing: &str, marker: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in listing.lines() {
        if !line.starts_with("-A PREROUTING") || !line.contains(marker) {
            continue;
        }
        let mut toks = line.split_whitespace();
        while let Some(t) = toks.next() {
            if t == "-d" {
                if let Some(c) = toks.next() {
                    out.push(c.trim_matches('"').to_string());
                }
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod wolfnet_raw_exception_tests {
    use super::parse_marked_raw_accept_cidrs;

    // Real-world shapes: iptables-nft quotes the comment, legacy doesn't.
    const NFT_LISTING: &str = "\
-P PREROUTING ACCEPT
-A PREROUTING -d 172.21.0.0/24 -i wolfnet0 -m comment --comment \"wolfstack-wolfnet-local\" -j ACCEPT
-A PREROUTING -d 192.168.50.0/24 -i wolfnet0 -m comment --comment \"wolfstack-wolfnet-route\" -j ACCEPT
-A PREROUTING -d 172.21.0.2/32 ! -i docker0 -j DROP";

    #[test]
    fn extracts_only_rules_with_our_marker() {
        let got = parse_marked_raw_accept_cidrs(NFT_LISTING, "wolfstack-wolfnet-local");
        assert_eq!(got, vec!["172.21.0.0/24".to_string()]);
        // The router-plumbing marker selects ITS rule and not ours — the two
        // cleanup paths must never see each other's exceptions.
        let got = parse_marked_raw_accept_cidrs(NFT_LISTING, "wolfstack-wolfnet-route");
        assert_eq!(got, vec!["192.168.50.0/24".to_string()]);
    }

    #[test]
    fn dockers_own_drop_rules_are_never_selected() {
        // Docker's anti-direct-routing DROP has no marker; an empty result
        // here is what guarantees the stale-sweep can never delete it.
        let got = parse_marked_raw_accept_cidrs(
            "-A PREROUTING -d 172.21.0.2/32 ! -i docker0 -j DROP",
            "wolfstack-wolfnet-local",
        );
        assert!(got.is_empty());
    }

    #[test]
    fn legacy_unquoted_comment_form_parses_too() {
        let listing = "-A PREROUTING -d fd42:1::/64 -i wolfnet0 -m comment --comment wolfstack-wolfnet-local -j ACCEPT";
        let got = parse_marked_raw_accept_cidrs(listing, "wolfstack-wolfnet-local");
        assert_eq!(got, vec!["fd42:1::/64".to_string()]);
    }

    #[test]
    fn only_prerouting_appends_are_considered() {
        // -P policy lines, other chains, and unrelated tables must not
        // contribute entries even if a marker string appears in them.
        let listing = "\
-P PREROUTING ACCEPT
-A OUTPUT -d 10.9.9.0/24 -m comment --comment wolfstack-wolfnet-local -j ACCEPT";
        let got = parse_marked_raw_accept_cidrs(listing, "wolfstack-wolfnet-local");
        assert!(got.is_empty());
    }
}

/// Add interfaces to the firewalld trusted zone (if firewalld is running).
/// This prevents firewalld's nftables REJECT rule from blocking forwarded
/// traffic between WolfNet, container bridges, and WireGuard interfaces.
pub fn ensure_firewalld_trusted(ifaces: &[&str]) {
    // Quick check: is firewalld running?
    let running = Command::new("firewall-cmd").args(["--state"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !running { return; }

    // Did we actually write anything to firewalld's *permanent* config this
    // pass?  Only then is a reload warranted — see the reload comment below
    // for why an unconditional one is destructive.
    let mut changed = false;

    for iface in ifaces {
        // Docker manages its own bridges' firewalld zone (the `docker` zone,
        // target ACCEPT). If we bind docker0 / br-<id> to `trusted` instead,
        // the next dockerd start aborts with
        //   ZONE_CONFLICT: 'docker0' already bound to 'trusted'
        // and the daemon refuses to come up — which is how a WolfStack restart
        // "killed Docker" on firewalld hosts (wabil, Oracle Linux), and why a
        // Docker reinstall didn't help: the bad binding lives in firewalld's
        // *permanent* config, not in Docker's packages. So: never claim a
        // Docker-managed bridge, and actively undo it if a prior WolfStack
        // version already did, so broken hosts heal on upgrade. WolfNet↔
        // container forwarding does not need the trusted zone — it's handled by
        // the explicit iptables FORWARD/DOCKER-USER ACCEPT rules above.
        //
        // Match docker0 and br-<id> by name (ordering-safe: docker0 must be
        // healed even while the daemon is down, since its binding is what's
        // keeping it down), plus anything Docker already owns in its own
        // `docker` zone — that catches a custom bridge renamed via
        // com.docker.network.bridge.name=… .
        let docker_managed = *iface == "docker0"
            || iface.starts_with("br-")
            || Command::new("firewall-cmd")
                .args(["--permanent", "--zone=docker", "--query-interface", iface])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
        if docker_managed {
            let in_trusted = Command::new("firewall-cmd")
                .args(["--permanent", "--zone=trusted", "--query-interface", iface])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if in_trusted {
                let removed = Command::new("firewall-cmd")
                    .args(["--permanent", "--zone=trusted", "--remove-interface", iface])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                changed |= removed;
            }
            continue;
        }

        // Check if already in trusted zone (avoid unnecessary reloads).
        // Permanent AND runtime, because they can disagree: a permanent add
        // whose reload never landed leaves the interface trusted on disk but
        // still filtered in the live ruleset, and WolfNet traffic stays
        // blocked. The old unconditional reload papered over that; now we
        // have to notice it and reload deliberately.
        let already_permanent = Command::new("firewall-cmd")
            .args(["--permanent", "--zone=trusted", "--query-interface", iface])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        let already_runtime = Command::new("firewall-cmd")
            .args(["--zone=trusted", "--query-interface", iface])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if already_permanent {
            // On disk but not live — the reload below is exactly the fix.
            changed |= !already_runtime;
            continue;
        }

        let added = Command::new("firewall-cmd")
            .args(["--permanent", "--zone=trusted", "--add-interface", iface])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        changed |= added;
    }

    // Enable masquerading in trusted zone so container NAT works. Ask before
    // setting: `--add-masquerade` on an already-masqueraded zone is a no-op
    // that logs `WARNING: ALREADY_ENABLED: masquerade` and, worse, used to
    // drag the unconditional reload below along with it. Same permanent-vs-
    // runtime split as the interfaces above.
    let masq_permanent = Command::new("firewall-cmd")
        .args(["--permanent", "--zone=trusted", "--query-masquerade"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if masq_permanent {
        let masq_runtime = Command::new("firewall-cmd")
            .args(["--zone=trusted", "--query-masquerade"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        changed |= !masq_runtime;
    } else {
        let enabled = Command::new("firewall-cmd")
            .args(["--permanent", "--zone=trusted", "--add-masquerade"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        changed |= enabled;
    }

    // Reload to apply permanent changes — ONLY if we made some.
    //
    // This function is called from the 60s WolfNet reconciliation loop, so an
    // unconditional reload here meant a full firewalld rebuild every minute on
    // every firewalld host, forever. Docker's `iptables+firewalld` backend
    // reacts to each reload by tearing down and re-installing its own v4 and
    // v6 chains (DOCKER-FORWARD, DOCKER-BRIDGE, DOCKER-CT …), so container
    // forwarding had a hole in it once a minute, any runtime-only rule anyone
    // else added was wiped just as often, and the audit log filled with tens
    // of thousands of NETFILTER_CFG records a day. In steady state there is
    // nothing to apply, so there is nothing to reload.
    if changed {
        let _ = Command::new("firewall-cmd").args(["--reload"]).output();
    }
}

// ─── WolfNet Route Cache ───
// Keep container→host route map in memory; only flush to disk when it changes.
//
// Signalled whenever `flush_routes_to_disk` writes the map to disk —
// i.e. only on real change. The push task in main.rs awaits this so
// peers learn about our local routes the moment they change, with no
// polling cost during steady-state. Coalesced: multiple notify_one
// calls before the consumer wakes collapse to a single notification.
pub static WOLFNET_ROUTES_CHANGED: std::sync::LazyLock<tokio::sync::Notify> =
    std::sync::LazyLock::new(tokio::sync::Notify::new);

pub static WOLFNET_ROUTES: std::sync::LazyLock<Mutex<std::collections::HashMap<String, String>>> =
    std::sync::LazyLock::new(|| {
        // Seed from existing routes file on startup
        let mut map = std::collections::HashMap::new();
        if let Ok(content) = std::fs::read_to_string("/var/run/wolfnet/routes.json")
            && let Ok(existing) = serde_json::from_str::<std::collections::HashMap<String, String>>(&content) {
                map = existing;
            }
        Mutex::new(map)
    });

/// Merge new routes into the in-memory cache and flush to disk only if anything changed.
/// Returns true if routes were updated.
pub fn update_wolfnet_routes(new_routes: &std::collections::HashMap<String, String>) -> bool {
    let mut cache = WOLFNET_ROUTES.lock().unwrap();
    let file_exists = std::path::Path::new("/var/run/wolfnet/routes.json").exists();
    let mut changed = false;
    for (k, v) in new_routes {
        if cache.get(k) != Some(v) {
            cache.insert(k.clone(), v.clone());
            changed = true;
        }
    }
    if changed || !file_exists {
        flush_routes_to_disk(&cache);
    }
    changed
}

/// Remove a single WolfNet IP from the route cache and flush to disk. Called
/// when a VM/container is deleted so the IP becomes immediately available
/// for a new allocation instead of lingering in the cache until the next
/// reconcile cycle.
///
/// Also invalidates the WOLFNET_IPS_CACHE so the very next reconcile cycle
/// re-reads fresh data from disk. Without this, the reconcile reads stale
/// cache that still contains the freed IP and re-inserts it into the route
/// table, which makes the IP unavailable for reuse for the cache TTL window.
pub fn release_wolfnet_ip(ip: &str) {
    if ip.is_empty() {
        return;
    }
    let removed = {
        let mut cache = WOLFNET_ROUTES.lock().unwrap();
        let removed = cache.remove(ip).is_some();
        if removed {
            flush_routes_to_disk(&cache);
        }
        removed
    };
    // Always invalidate the IPs cache — even if the IP wasn't in
    // WOLFNET_ROUTES (not every VM/container IP ends up in the route
    // table immediately), the caller is telling us the underlying
    // source of truth (VM config, container labels, etc.) has changed.
    invalidate_wolfnet_ips_cache();
    if removed {
        info!("WolfNet: released route for {}", ip);
    }
}

/// Replace the entire route table with the given complete set of routes.
/// Unlike update_wolfnet_routes (which merges), this is authoritative —
/// it ensures stale routes are removed and the file reflects current reality.
pub fn replace_wolfnet_routes(complete_routes: std::collections::HashMap<String, String>) {
    let mut cache = WOLFNET_ROUTES.lock().unwrap();
    let file_exists = std::path::Path::new("/var/run/wolfnet/routes.json").exists();
    if *cache == complete_routes && file_exists {
        return; // No change and file exists — skip disk write + SIGHUP
    }
    *cache = complete_routes;
    flush_routes_to_disk(&cache);
}

/// Write the route map to /var/run/wolfnet/routes.json and signal WolfNet to reload.
pub fn flush_routes_to_disk(routes: &std::collections::HashMap<String, String>) {
    let routes_path = "/var/run/wolfnet/routes.json";
    if let Err(e) = std::fs::create_dir_all("/var/run/wolfnet") {
        warn!("Failed to create /var/run/wolfnet: {}", e);
        return;
    }
    match serde_json::to_string_pretty(routes) {
        Ok(json) => {
            match std::fs::write(routes_path, &json) {
                Ok(_) => {
                    // Wake the push task — peers should learn about
                    // this route change immediately, not on a poll.
                    WOLFNET_ROUTES_CHANGED.notify_one();
                    // Deliberately do NOT SIGHUP WolfNet here. WolfNet's only
                    // signal is SIGHUP, and its handler does a FULL config reload:
                    // it reloads routes (wolfnet/src/main.rs:1031-1032) AND purges
                    // every PEX-/roaming-learned peer not pinned in config.toml
                    // (wolfnet/src/main.rs:1010-1027). We don't need the SIGHUP for
                    // the routes — WolfNet already reloads routes.json on its own 15s
                    // timer (wolfnet/src/main.rs:928-930) — so signalling here buys
                    // nothing but the peer-purge, which wiped the mesh's learned
                    // endpoints before it could stabilise (JJ 2026-06-04: "SIGHUP
                    // every 60s purging dynamically learned peer endpoints"). The 15s
                    // tick applies the route locally; the push notify above propagates
                    // it to peers immediately.
                }
                Err(e) => warn!("Failed to write {}: {}", routes_path, e),
            }
        }
        Err(e) => warn!("Failed to serialize routes: {}", e),
    }
}

// ─── Lightweight container counting (for monitoring loops) ───
// These avoid the expensive per-container docker inspect calls that docker_list_all() performs.

/// Count all Docker containers with a single subprocess call (no per-container inspect).
fn docker_count_inner() -> u32 {
    Command::new("docker")
        .args(["ps", "-aq"])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .count() as u32
        })
        .unwrap_or(0)
}

/// Count all LXC containers with a single subprocess call.
/// Does a `pct list` line describe a ghost husk? Mirrors the `possible_ghost`
/// rule in `pct_list_all` exactly (stopped CT whose hostname is a bare VMID
/// that isn't its own VMID) so the menu count and the list — which HIDES
/// ghosts — agree. The `pct list` Name column is the hostname PVE reports.
fn pct_list_line_is_ghost(line: &str) -> bool {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let vmid = match parts.first() { Some(v) => *v, None => return false };
    let status = parts.get(1).map(|s| s.to_lowercase()).unwrap_or_default();
    // The Name column sits after an optional Lock column (same handling as
    // pct_list_all's parser).
    let lock = parts.get(2).copied().unwrap_or("");
    let name = if matches!(lock, "backup" | "snapshot" | "migrate" | "rollback" | "create" | "mounted") {
        parts.get(3..).map(|p| p.join(" ")).unwrap_or_default()
    } else {
        parts.get(2..).map(|p| p.join(" ")).unwrap_or_default()
    };
    status != "running" && is_pve_vmid_name(&name) && name != vmid
}

fn lxc_count_inner() -> u32 {
    // Check for pct (Proxmox) first
    let is_proxmox = Command::new("which").arg("pct").output()
        .map(|o| o.status.success()).unwrap_or(false);
    if is_proxmox {
        return Command::new("pct")
            .args(["list"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .skip(1) // header
                    .filter(|l| !l.trim().is_empty())
                    // Exclude ghost husks so the menu count matches the list,
                    // which hides them (Paul 2026-06-24).
                    .filter(|l| !pct_list_line_is_ghost(l))
                    .count() as u32
            })
            .unwrap_or(0);
    }
    // Native LXC — count container directories across all storage paths. Use a
    // directory scan (a sub-dir with a `config` file IS a container) rather than
    // `lxc-ls`: lxc-ls is a python script that needs the python3-lxc bindings,
    // which are absent by default on Fedora — there it returns nothing, so the
    // menu showed 0 even though the containers exist and the list (which already
    // dir-scans, since v24.46.0) shows them. Counting the same way keeps the
    // menu count and the list in sync on every distro.
    let mut seen = std::collections::HashSet::new();
    for base_path in lxc_storage_paths() {
        if let Ok(entries) = std::fs::read_dir(&base_path) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.is_empty() { continue; }
                if !e.path().join("config").is_file() { continue; }
                seen.insert(name);
            }
        }
    }
    seen.len() as u32
}

// ─── Cached container counts ───
// Avoid spawning docker/pct/lxc-ls subprocesses on every 2-second monitoring tick.

static DOCKER_COUNT_CACHE: Mutex<Option<(u32, Instant)>> = Mutex::new(None);
static LXC_COUNT_CACHE: Mutex<Option<(u32, Instant)>> = Mutex::new(None);

const COUNT_CACHE_TTL_SECS: u64 = 5;

// ─── Cached container list/stats/images ───
// Avoid spawning dozens of subprocesses per API request.

const LIST_CACHE_TTL_SECS: u64 = 5;
const IMAGES_CACHE_TTL_SECS: u64 = 60;

/// A probe whose refresh has been in flight longer than this is reported as
/// a hung runtime. Chosen well above any healthy enumeration (the slowest
/// observed real host takes low single-digit seconds) and well below the
/// point at which an operator has already given up on the page.
const PROBE_HUNG_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

/// Refresh-coalescing cache for an expensive container probe.
///
/// The previous shape of these caches was:
///
/// ```ignore
/// { let c = CACHE.lock().unwrap(); if fresh { return c.clone() } }   // lock dropped
/// let v = expensive_probe();                                        // <-- unguarded
/// *CACHE.lock().unwrap() = Some((v.clone(), Instant::now()));
/// ```
///
/// The lock is released before the probe runs, so every caller arriving
/// while it runs starts its OWN probe. With a 5s TTL, ~24 call sites (four
/// `predictive` items, the WolfRun reconciler, the alerting loop and several
/// API handlers) and a daemon that has slowed down, that is unbounded
/// growth: each `docker_list_all` spawns a batched `docker inspect` over
/// every container, the extra load slows the daemon further, and more
/// callers therefore miss the cache. klas 2026-08-13 — hundreds of
/// concurrent `docker inspect` processes against one container id, node
/// unreachable.
///
/// A timeout is the wrong instrument for that: it bounds each call's
/// lifetime but not how many get started, and it cannot tell a slow daemon
/// from a wedged one — it just converts a slow success into a certain
/// failure. This type removes the multiplication instead:
///
/// * **Single-flight.** At most one refresh runs at a time. Callers do not
///   queue behind it either; they take the previous value.
/// * **Serve-stale.** A caller arriving during a refresh gets the last good
///   value immediately. Slightly stale beats both blocking and (worse)
///   an empty list, which reads as "you have no containers".
/// * **Observable.** [`Self::refresh_age`] reports how long the in-flight
///   refresh has been running, so a wedged runtime is a reportable state
///   rather than a mystery blank page.
pub(crate) struct CoalescedProbe<T: Clone> {
    inner: Mutex<ProbeState<T>>,
    /// Signalled when a refresh finishes, so a cold caller can wake as soon
    /// as the first value exists instead of polling.
    ready: std::sync::Condvar,
    label: &'static str,
}

struct ProbeState<T> {
    value: Option<(T, Instant)>,
    /// `Some(started)` while a refresh is in flight. Cleared by
    /// `RefreshGuard::drop`, so a panicking probe cannot wedge the cache.
    refresh_started: Option<Instant>,
}

/// Clears the in-flight marker even if the probe panics, and wakes anyone
/// waiting on a cold cache.
struct RefreshGuard<'a, T: Clone> {
    cache: &'a CoalescedProbe<T>,
}

impl<T: Clone> Drop for RefreshGuard<'_, T> {
    fn drop(&mut self) {
        if let Ok(mut g) = self.cache.inner.lock() {
            g.refresh_started = None;
        }
        // Wake cold waiters unconditionally: on the panic path there is no
        // new value, and leaving them parked until their timeout would turn
        // one failed probe into a stall for every concurrent caller.
        self.cache.ready.notify_all();
    }
}

impl<T: Clone + Default> CoalescedProbe<T> {
    pub(crate) const fn new(label: &'static str) -> Self {
        Self {
            inner: Mutex::new(ProbeState { value: None, refresh_started: None }),
            ready: std::sync::Condvar::new(),
            label,
        }
    }

    /// How long the in-flight refresh has been running, or `None` if idle.
    pub(crate) fn refresh_age(&self) -> Option<std::time::Duration> {
        self.inner.lock().ok()?.refresh_started.map(|t| t.elapsed())
    }

    /// Fetch, refreshing at most one-at-a-time. `probe` runs outside the
    /// lock so a slow runtime never blocks readers of the cached value.
    pub(crate) fn get(&self, ttl: std::time::Duration, probe: impl FnOnce() -> T) -> T {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            // A poisoned lock means a previous probe panicked mid-update.
            // Recover rather than propagating: container enumeration is not
            // worth taking a handler thread down for.
            Err(e) => e.into_inner(),
        };

        if let Some((v, ts)) = &g.value
            && ts.elapsed() < ttl {
                return v.clone();
            }

        if let Some(started) = g.refresh_started {
            // Another caller owns the refresh.
            if let Some((v, _)) = &g.value {
                return v.clone(); // serve stale — the common case
            }
            // Cold: no value has ever been produced, so stale isn't an
            // option. Wait for the in-flight probe rather than starting a
            // duplicate. Bounded so a wedged runtime can't park us forever.
            let waited = started.elapsed();
            let budget = PROBE_HUNG_AFTER.saturating_sub(waited);
            if !budget.is_zero() {
                let (g2, _) = self.ready
                    .wait_timeout(g, budget)
                    .unwrap_or_else(|e| e.into_inner());
                g = g2;
                if let Some((v, _)) = &g.value {
                    return v.clone();
                }
            }
            warn!(
                "{}: runtime probe has been running {}s with no result yet — \
                 treating the runtime as unresponsive and returning no data. \
                 The daemon is likely wedged; existing data is unaffected.",
                self.label,
                g.refresh_started.map(|s| s.elapsed().as_secs()).unwrap_or(0),
            );
            return T::default();
        }

        // Claim the refresh.
        g.refresh_started = Some(Instant::now());
        drop(g);
        let _guard = RefreshGuard { cache: self };
        let started = Instant::now();
        let val = probe();
        let took = started.elapsed();
        if took >= PROBE_HUNG_AFTER {
            warn!(
                "{}: runtime probe took {}s — the container runtime is \
                 responding very slowly. Concurrent callers were served \
                 cached data rather than starting their own probes.",
                self.label, took.as_secs(),
            );
        }
        {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            g.value = Some((val.clone(), Instant::now()));
        }
        // `_guard` clears refresh_started and notifies cold waiters here.
        val
    }

    /// Drop the cached value so the next `get` re-probes.
    pub(crate) fn invalidate(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.value = None;
        } else if let Err(e) = self.inner.lock() {
            e.into_inner().value = None;
        }
    }
}

static DOCKER_LIST_CACHE: CoalescedProbe<Vec<ContainerInfo>> = CoalescedProbe::new("docker list");
static DOCKER_STATS_CACHE: CoalescedProbe<Vec<ContainerStats>> = CoalescedProbe::new("docker stats");
static DOCKER_IMAGES_CACHE: CoalescedProbe<Vec<ContainerImage>> = CoalescedProbe::new("docker images");
static LXC_LIST_CACHE: CoalescedProbe<Vec<ContainerInfo>> = CoalescedProbe::new("lxc list");
static LXC_STATS_CACHE: CoalescedProbe<Vec<ContainerStats>> = CoalescedProbe::new("lxc stats");

/// Outcome of a direct health check against the Docker daemon socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum DockerHealth {
    /// Daemon answered `/_ping`. A healthy daemon replies in single-digit
    /// milliseconds; tens or hundreds of ms means it is alive but stressed,
    /// which is a very different situation from wedged and should not be
    /// treated as a failure.
    Alive { latency_ms: u64 },
    /// The socket accepted our connection but the daemon never answered
    /// inside the budget. The process is up and not servicing requests —
    /// this is the genuine hang, and the state in which spawning more
    /// `docker` CLI calls does nothing but consume descriptors.
    Unresponsive { waited_ms: u64 },
    /// Could not talk to the socket at all: Docker not installed, not
    /// running, or we lack permission on the socket.
    Down { reason: String },
}

/// Path to the Docker daemon socket, honouring a `unix://` `DOCKER_HOST`.
fn docker_socket_path() -> String {
    match std::env::var("DOCKER_HOST") {
        Ok(h) if h.starts_with("unix://") => h.trim_start_matches("unix://").to_string(),
        _ => "/var/run/docker.sock".to_string(),
    }
}

/// Ask the Docker daemon whether it is servicing requests, via `GET /_ping`
/// straight down the unix socket.
///
/// This is deliberately NOT `docker version` or any other CLI call: the
/// point is to answer "is the daemon wedged?" without forking a process,
/// because forking more `docker` processes is precisely what a wedged
/// daemon turns into an outage. One socket write and a short read, bounded
/// by socket timeouts.
///
/// Distinguishes the three states that matter operationally — alive (with a
/// latency figure, so "slow" is visible as a number rather than inferred),
/// unresponsive, and down. A short timeout is safe here in a way it is not
/// for real work: `_ping` does no I/O and touches no container state, so a
/// daemon that cannot answer it inside a second or two is genuinely unwell
/// rather than merely busy.
///
/// Caveat: `std::os::unix::net::UnixStream` has no connect timeout, so if
/// the daemon's listen backlog is full the connect itself can block. That is
/// rare compared to the accept-then-never-answer case this catches, and
/// bounding it would mean a nonblocking connect plus a poll loop.
pub fn docker_health(budget: std::time::Duration) -> DockerHealth {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let path = docker_socket_path();
    let started = Instant::now();
    let mut stream = match UnixStream::connect(&path) {
        Ok(s) => s,
        Err(e) => return DockerHealth::Down { reason: format!("{}: {}", path, e) },
    };
    if let Err(e) = stream.set_write_timeout(Some(budget)) {
        return DockerHealth::Down { reason: format!("set_write_timeout: {}", e) };
    }
    if let Err(e) = stream.set_read_timeout(Some(budget)) {
        return DockerHealth::Down { reason: format!("set_read_timeout: {}", e) };
    }
    // HTTP/1.0 so the daemon closes the body itself and we never wait on a
    // keep-alive connection for an end we can't detect.
    if let Err(e) = stream.write_all(b"GET /_ping HTTP/1.0\r\nHost: localhost\r\n\r\n") {
        return DockerHealth::Unresponsive { waited_ms: started.elapsed().as_millis() as u64 }
            .or_down(e);
    }
    let mut buf = [0u8; 128];
    match stream.read(&mut buf) {
        Ok(0) => DockerHealth::Unresponsive { waited_ms: started.elapsed().as_millis() as u64 },
        Ok(n) => {
            let head = String::from_utf8_lossy(&buf[..n]);
            if head.contains(" 200 ") || head.contains("OK") {
                DockerHealth::Alive { latency_ms: started.elapsed().as_millis() as u64 }
            } else {
                // Answered, but not with a healthy ping — still "alive" in
                // the sense that matters here (it is servicing the socket).
                DockerHealth::Alive { latency_ms: started.elapsed().as_millis() as u64 }
            }
        }
        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
            DockerHealth::Unresponsive { waited_ms: started.elapsed().as_millis() as u64 }
        }
        Err(e) => DockerHealth::Down { reason: format!("read: {}", e) },
    }
}

impl DockerHealth {
    /// Reclassify a write failure: a socket we connected to but cannot write
    /// to is down, not merely unresponsive.
    fn or_down(self, e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => self,
            _ => DockerHealth::Down { reason: format!("write: {}", e) },
        }
    }
}

/// Longest-running in-flight container probe, if any is past
/// [`PROBE_HUNG_AFTER`]. Lets the API surface "the container runtime is not
/// responding" instead of an unexplained empty list.
pub fn hung_runtime_probe() -> Option<(&'static str, std::time::Duration)> {
    [
        ("docker list", DOCKER_LIST_CACHE.refresh_age()),
        ("docker stats", DOCKER_STATS_CACHE.refresh_age()),
        ("docker images", DOCKER_IMAGES_CACHE.refresh_age()),
        ("lxc list", LXC_LIST_CACHE.refresh_age()),
        ("lxc stats", LXC_STATS_CACHE.refresh_age()),
    ]
    .into_iter()
    .filter_map(|(n, age)| age.map(|a| (n, a)))
    .filter(|(_, a)| *a >= PROBE_HUNG_AFTER)
    .max_by_key(|(_, a)| *a)
}

// ─── Per-container probe caches ───
// docker_list/lxc list spawn TWO subprocesses per container on every
// UNCACHED enumeration: detect_container_services shells INTO the
// container (docker exec / lxc-attach + a /proc walk) and
// get_path_disk_usage runs `df` on its rootfs. The list itself was
// batched down to 2 subprocesses (v20.x), but these two stayed N+1 —
// on a node with ~100 containers each enumeration spawned ~200
// processes, and the WolfRun reconcile + UI poll + notify/predictive
// pollers each trigger enumerations. This was a big slice of the
// sustained ~70% CPU (mostly system time) klas reported (2026-08-12).
// Both facts change slowly; 30s staleness is invisible in the UI.
/// (used_bytes, total_bytes, fs_type) as returned by get_path_disk_usage.
type PathDiskUsage = (Option<u64>, Option<u64>, Option<String>);

type ProbeCache<V> = std::sync::LazyLock<Mutex<std::collections::HashMap<String, (V, Instant)>>>;

static SERVICES_PROBE_CACHE: ProbeCache<Vec<ContainerService>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
static DISK_USAGE_CACHE: ProbeCache<PathDiskUsage> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

const PROBE_CACHE_TTL_SECS: u64 = 300;

// Service detection execs INTO a container and walks its /proc. That is
// two processes per container per probe (coreutils `timeout` + `docker
// exec`) plus a container-namespace entry — by far the most expensive
// thing an enumeration does, and the resulting `services` field is never
// read by any Rust code: it exists purely to be rendered in the UI's
// container list.
//
// So it must not run for the enumerations nobody is looking at. Every
// background caller — WolfRun reconcile, the notify poller, the four
// predictive scanners, statuspage, exposure, the router, galera — walks
// the same `*_list_all_cached()` helpers as the UI does, so the caller
// cannot be told apart by function. This flag distinguishes them: the two
// API handlers that serve the list to a browser set it for the duration of
// their call, and nothing else does.
//
// Measured on klas's node (2026-08-12): ~100 running containers probed on
// a 30s cycle held ~10 process spawns/sec, which at ~1,000 syscalls per
// spawn accounted for the 8,214 syscalls/sec and 61% system time behind a
// sustained 354% CPU.
thread_local! {
    static PROBE_ALLOWED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run `f` with in-container service probing enabled for this thread.
/// Only the UI list handlers should use this.
pub fn with_service_probing<T>(f: impl FnOnce() -> T) -> T {
    PROBE_ALLOWED.with(|p| p.set(true));
    let out = f();
    PROBE_ALLOWED.with(|p| p.set(false));
    out
}

fn probing_allowed() -> bool {
    PROBE_ALLOWED.with(|p| p.get())
}
/// Entry cap for the per-container probe caches — far above any real
/// container count; keeps a name-churning fleet from growing the maps
/// without bound. On overflow, expired entries are dropped.
const PROBE_CACHE_MAX: usize = 1024;

fn probe_cache_prune<V>(map: &mut std::collections::HashMap<String, (V, Instant)>) {
    if map.len() > PROBE_CACHE_MAX {
        map.retain(|_, (_, ts)| ts.elapsed().as_secs() < PROBE_CACHE_TTL_SECS);
    }
}

/// Cached docker_list_all — reuses result for 5 seconds.
pub fn docker_list_all_cached() -> Vec<ContainerInfo> {
    DOCKER_LIST_CACHE.get(std::time::Duration::from_secs(LIST_CACHE_TTL_SECS), docker_list_all)
}

/// Cached docker_stats — reuses result for 5 seconds.
pub fn docker_stats_cached() -> Vec<ContainerStats> {
    DOCKER_STATS_CACHE.get(std::time::Duration::from_secs(LIST_CACHE_TTL_SECS), docker_stats)
}

/// Cached docker_images — reuses result for 60 seconds.
pub fn docker_images_cached() -> Vec<ContainerImage> {
    DOCKER_IMAGES_CACHE.get(std::time::Duration::from_secs(IMAGES_CACHE_TTL_SECS), docker_images)
}

/// Cached lxc_list_all — reuses result for 5 seconds.
pub fn lxc_list_all_cached() -> Vec<ContainerInfo> {
    LXC_LIST_CACHE.get(std::time::Duration::from_secs(LIST_CACHE_TTL_SECS), lxc_list_all)
}

/// Cached lxc_stats — reuses result for 5 seconds.
pub fn lxc_stats_cached() -> Vec<ContainerStats> {
    LXC_STATS_CACHE.get(std::time::Duration::from_secs(LIST_CACHE_TTL_SECS), lxc_stats)
}

/// Invalidate container count caches (call after create/delete operations).
pub fn invalidate_count_caches() {
    *DOCKER_COUNT_CACHE.lock().unwrap() = None;
    *LXC_COUNT_CACHE.lock().unwrap() = None;
}

/// Invalidate all container list/stats caches (call after create/delete/start/stop).
#[allow(dead_code)]
pub fn invalidate_list_caches() {
    DOCKER_LIST_CACHE.invalidate();
    DOCKER_STATS_CACHE.invalidate();
    DOCKER_IMAGES_CACHE.invalidate();
    LXC_LIST_CACHE.invalidate();
    LXC_STATS_CACHE.invalidate();
}

/// Invalidate just the Docker list cache. Used by write paths that change
/// docker-side metadata (autostart, memory, cpus, wolfnet IP, env) so the
/// UI doesn't read back the pre-change snapshot for the next 5 seconds.
pub fn invalidate_docker_list_cache() {
    DOCKER_LIST_CACHE.invalidate();
}

/// Count Docker containers (cached for 5s).
pub fn docker_count() -> u32 {
    {
        let cache = DOCKER_COUNT_CACHE.lock().unwrap();
        if let Some((val, ts)) = &*cache
            && ts.elapsed().as_secs() < COUNT_CACHE_TTL_SECS {
                return *val;
            }
    } // release lock before subprocess
    let val = docker_count_inner();
    *DOCKER_COUNT_CACHE.lock().unwrap() = Some((val, Instant::now()));
    val
}

/// Count LXC containers (cached for 5s).
pub fn lxc_count() -> u32 {
    {
        let cache = LXC_COUNT_CACHE.lock().unwrap();
        if let Some((val, ts)) = &*cache
            && ts.elapsed().as_secs() < COUNT_CACHE_TTL_SECS {
                return *val;
            }
    } // release lock before subprocess
    let val = lxc_count_inner();
    *LXC_COUNT_CACHE.lock().unwrap() = Some((val, Instant::now()));
    val
}

// ─── Cached runtime detection ───
// has_docker/has_lxc/has_kvm rarely change during runtime. Caching avoids
// spawning 'which' and 'docker info' every 2 seconds in the monitoring loop.

static HAS_DOCKER_CACHE: Mutex<Option<(bool, Instant)>> = Mutex::new(None);
static HAS_LXC_CACHE: Mutex<Option<(bool, Instant)>> = Mutex::new(None);
static HAS_KVM_CACHE: Mutex<Option<(bool, Instant)>> = Mutex::new(None);

const RUNTIME_CACHE_TTL_SECS: u64 = 120;

/// Check if Docker is installed (cached for 120s).
pub fn has_docker_cached() -> bool {
    let mut cache = HAS_DOCKER_CACHE.lock().unwrap();
    if let Some((val, ts)) = &*cache
        && ts.elapsed().as_secs() < RUNTIME_CACHE_TTL_SECS {
            return *val;
        }
    let val = Command::new("which").arg("docker").output()
        .map(|o| o.status.success()).unwrap_or(false);
    *cache = Some((val, Instant::now()));
    val
}

/// Check if LXC is installed (cached for 120s).
pub fn has_lxc_cached() -> bool {
    let mut cache = HAS_LXC_CACHE.lock().unwrap();
    if let Some((val, ts)) = &*cache
        && ts.elapsed().as_secs() < RUNTIME_CACHE_TTL_SECS {
            return *val;
        }
    let val = Command::new("which").arg("lxc-ls").output()
        .map(|o| o.status.success()).unwrap_or(false);
    *cache = Some((val, Instant::now()));
    val
}

/// Check if KVM/QEMU is installed (cached for 120s).
pub fn has_kvm_cached() -> bool {
    let mut cache = HAS_KVM_CACHE.lock().unwrap();
    if let Some((val, ts)) = &*cache
        && ts.elapsed().as_secs() < RUNTIME_CACHE_TTL_SECS {
            return *val;
        }
    let val = kvm_installed();
    *cache = Some((val, Instant::now()));
    val
}

// ─── Cached WolfNet IP lookup ───
// wolfnet_used_ips() spawns multiple subprocesses. Cache for 5 seconds
// since it's called every 2s in monitoring and 10s in route cleanup.

static WOLFNET_IPS_CACHE: Mutex<Option<(Vec<String>, Instant)>> = Mutex::new(None);

const WOLFNET_IPS_CACHE_TTL_SECS: u64 = 5;

/// Get WolfNet IPs with caching (TTL 5s).
pub fn wolfnet_used_ips_cached() -> Vec<String> {
    let mut cache = WOLFNET_IPS_CACHE.lock().unwrap();
    if let Some((ref val, ts)) = *cache
        && ts.elapsed().as_secs() < WOLFNET_IPS_CACHE_TTL_SECS {
            return val.clone();
        }
    let val = wolfnet_used_ips();
    *cache = Some((val.clone(), Instant::now()));
    val
}

/// Invalidate the WolfNet used-IPs cache so the next call recomputes.
/// Called after a VM/container is deleted so the reconcile cycle doesn't
/// treat the freed IP as still-in-use for up to 5s (long enough for a user
/// to recreate a VM with the same IP and get rejected).
pub fn invalidate_wolfnet_ips_cache() {
    *WOLFNET_IPS_CACHE.lock().unwrap() = None;
    *WOLFNET_ACTIVE_IPS_CACHE.lock().unwrap() = None;
}

static WOLFNET_ACTIVE_IPS_CACHE: Mutex<Option<(Vec<String>, Instant)>> = Mutex::new(None);

/// Cached `wolfnet_active_ips()` — the RUNNING set. This is what the
/// status report, the route announce, the route seed and the local half
/// of the route map advertise. The used set (stopped included) is for
/// allocation only: a stopped container's IP must stay reserved, but it
/// must never attract cluster traffic. Before this split every route
/// source used the used set, so an IP held stopped on one node and
/// running on another had two owners and flipped between them on every
/// poll (klas, 2026-09-07).
pub fn wolfnet_active_ips_cached() -> Vec<String> {
    let mut cache = WOLFNET_ACTIVE_IPS_CACHE.lock().unwrap();
    if let Some((ref val, ts)) = *cache
        && ts.elapsed().as_secs() < WOLFNET_IPS_CACHE_TTL_SECS {
            return val.clone();
        }
    let val = wolfnet_active_ips();
    *cache = Some((val.clone(), Instant::now()));
    val
}

/// What a cluster peer last reported about its WolfNet IPs, kept by the
/// status poll (`record_remote_wolfnet_ips`). `active` = running
/// workloads (conflict detection); `reserved` = every workload, stopped
/// included (allocation). Entries older than REMOTE_WOLFNET_IPS_MAX_AGE
/// are ignored so a deleted node cannot reserve addresses forever.
#[derive(Debug, Clone)]
pub struct RemoteWolfnetIps {
    pub label: String,
    pub host_ip: String,
    pub active: Vec<String>,
    pub reserved: Vec<String>,
    pub seen: Instant,
}

static REMOTE_WOLFNET_IPS: std::sync::LazyLock<Mutex<std::collections::HashMap<String, RemoteWolfnetIps>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

const REMOTE_WOLFNET_IPS_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(600);

pub fn record_remote_wolfnet_ips(node_id: &str, label: &str, host_ip: &str, active: &[String], reserved: &[String]) {
    if let Ok(mut m) = REMOTE_WOLFNET_IPS.lock() {
        m.insert(node_id.to_string(), RemoteWolfnetIps {
            label: label.to_string(),
            host_ip: host_ip.to_string(),
            active: active.to_vec(),
            reserved: reserved.to_vec(),
            seen: Instant::now(),
        });
    }
}

/// Fresh peer reports only.
pub fn remote_wolfnet_ips() -> Vec<RemoteWolfnetIps> {
    REMOTE_WOLFNET_IPS
        .lock()
        .map(|m| m.values().filter(|r| r.seen.elapsed() < REMOTE_WOLFNET_IPS_MAX_AGE).cloned().collect())
        .unwrap_or_default()
}

/// One entry of a wolfnetd status.json `peers` array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WolfnetPeer {
    pub hostname: String,
    pub address: String,
    /// wolfnetd's own `connected` — `Peer::is_connected()`, a signed
    /// packet inside the last 120 s. It decides whether this peer
    /// actually takes delivery of its address: wolfnet main.rs
    /// `encrypt_and_send` returns false without an endpoint or when
    /// `is_connected()` is false, and the packet then falls through to
    /// the container route map.
    pub connected: bool,
}

/// Pure: every peer in a wolfnetd status.json.
pub fn parse_wolfnet_status_peers(json: &str) -> Vec<WolfnetPeer> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else { return Vec::new() };
    let Some(peers) = v.get("peers").and_then(|p| p.as_array()) else { return Vec::new() };
    peers
        .iter()
        .filter_map(|p| {
            let address = p.get("address")?.as_str()?.split('/').next()?.trim().to_string();
            if address.parse::<std::net::Ipv4Addr>().is_err() { return None; }
            let hostname = p.get("hostname").and_then(|h| h.as_str()).unwrap_or("").to_string();
            // Absent only if the status file is not a wolfnetd one —
            // every released PeerStatus carries it. Absent reads as
            // "not delivering", which reserves the address without
            // raising a shadowing finding for it.
            let connected = p.get("connected").and_then(|c| c.as_bool()).unwrap_or(false);
            Some(WolfnetPeer { hostname, address, connected })
        })
        .collect()
}

/// Every peer wolfnetd currently knows — config-listed, PEX-learned or
/// roaming (VPN clients included) — from the status file it rewrites
/// every 5 s. The config-file peer list misses everything learned at
/// runtime, which is exactly the set that collides with allocation.
pub fn wolfnet_live_peers() -> Vec<WolfnetPeer> {
    std::fs::read_to_string("/var/run/wolfnet/status.json")
        .map(|s| parse_wolfnet_status_peers(&s))
        .unwrap_or_default()
}

/// Addresses legitimately present on EVERY node's active set — WolfRun
/// service VIPs (a local route on lo on each node) and Kubernetes route
/// IPs from the cluster-synced config. Conflict detection must skip them.
pub fn wolfnet_anycast_ips() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(data) = std::fs::read_to_string(&crate::paths::get().wolfrun_services)
        && let Ok(services) = serde_json::from_str::<Vec<serde_json::Value>>(&data) {
            for svc in &services {
                if let Some(vip) = svc.get("service_ip").and_then(|v| v.as_str())
                    && !vip.is_empty() {
                        out.push(vip.to_string());
                    }
            }
        }
    if let Ok(data) = std::fs::read_to_string(&crate::paths::get().kubernetes_config)
        && let Ok(config) = serde_json::from_str::<serde_json::Value>(&data)
            && let Some(clusters) = config.get("clusters").and_then(|c| c.as_array()) {
                for cluster in clusters {
                    if let Some(routes) = cluster.get("wolfnet_routes").and_then(|r| r.as_array()) {
                        for route in routes {
                            if let Some(ip) = route.get("wolfnet_ip").and_then(|v| v.as_str())
                                && !ip.is_empty() {
                                    out.push(ip.to_string());
                                }
                        }
                    }
                }
            }
    out
}

#[cfg(test)]
mod wolfnet_status_peers_tests {
    use super::{parse_wolfnet_status_peers, WolfnetPeer};

    #[test]
    fn peers_come_back_with_a_bare_address_and_their_tunnel_state() {
        let json = r#"{"hostname":"hemulen","address":"10.10.10.2","peers":[
            {"hostname":"ninni","address":"10.10.10.3","connected":true},
            {"hostname":"","address":"10.10.10.160/32","connected":false},
            {"hostname":"nostate","address":"10.10.10.161"},
            {"hostname":"bad","address":"not-an-ip"}
        ]}"#;
        let peers = parse_wolfnet_status_peers(json);
        assert_eq!(peers, vec![
            WolfnetPeer { hostname: "ninni".into(), address: "10.10.10.3".into(), connected: true },
            WolfnetPeer { hostname: "".into(), address: "10.10.10.160".into(), connected: false },
            WolfnetPeer { hostname: "nostate".into(), address: "10.10.10.161".into(), connected: false },
        ]);
    }

    #[test]
    fn garbage_or_missing_peers_yield_nothing() {
        assert!(parse_wolfnet_status_peers("").is_empty());
        assert!(parse_wolfnet_status_peers(r#"{"hostname":"x"}"#).is_empty());
    }
}

// ─── LXC Storage Paths Registry ───
// Tracks all known directories that may contain LXC containers.
// Always includes /var/lib/lxc as the default.
// Persisted at /etc/wolfstack/lxc-paths.json.

pub const LXC_DEFAULT_PATH: &str = "/var/lib/lxc";
fn lxc_paths_file() -> String { crate::paths::get().lxc_paths }

pub static LXC_STORAGE_PATHS: std::sync::LazyLock<Mutex<Vec<String>>> =
    std::sync::LazyLock::new(|| {
        let mut paths = vec![LXC_DEFAULT_PATH.to_string()];
        if let Ok(content) = std::fs::read_to_string(lxc_paths_file())
            && let Ok(saved) = serde_json::from_str::<Vec<String>>(&content) {
                for p in saved {
                    if p != LXC_DEFAULT_PATH && !paths.contains(&p) && std::path::Path::new(&p).is_dir() {
                        paths.push(p);
                    }
                }
            }
        Mutex::new(paths)
    });

/// Get all known LXC storage paths (always includes /var/lib/lxc).
pub fn lxc_storage_paths() -> Vec<String> {
    LXC_STORAGE_PATHS.lock().unwrap().clone()
}

/// Register an additional LXC storage path. Returns true if the path was new.
pub fn lxc_register_path(path: &str) -> bool {
    if path.is_empty() || path == LXC_DEFAULT_PATH {
        return false;
    }
    let mut paths = LXC_STORAGE_PATHS.lock().unwrap();
    if paths.contains(&path.to_string()) {
        return false;
    }
    paths.push(path.to_string());
    let _ = std::fs::write(lxc_paths_file(), serde_json::to_string_pretty(&*paths).unwrap_or_default());
    true
}

/// Find the base directory containing a named LXC container.
/// Checks all registered paths; falls back to /var/lib/lxc if not found.
pub fn lxc_base_dir(container: &str) -> String {
    let paths = LXC_STORAGE_PATHS.lock().unwrap();
    for base in paths.iter() {
        let dir = format!("{}/{}", base, container);
        if std::path::Path::new(&dir).is_dir() {
            return base.clone();
        }
    }
    LXC_DEFAULT_PATH.to_string()
}

/// Clean up stale /32 kernel routes for WolfNet IPs that don't belong to local containers.
/// Stale routes (from deleted/moved containers) override the wolfnet0 /24 route and
/// prevent cross-node container routing through the WolfNet tunnel.
/// Comment tag on container→WolfNet DNAT rules so they're identifiable in
/// `iptables-save` and cleanable by comment. (KO4BSR/Gary saw untagged rules
/// he couldn't attribute.) WolfRun VIP-map rules use `wolfstack-vip-map-*`.
const WOLFNET_CT_COMMENT: &str = "wolfstack-wolfnet-container";

/// For an `iptables -S` line, return the DNAT destination-match IP (the `-d`
/// address) IFF the line is a container→WolfNet exposure DNAT rule we own.
/// Ownership signature: it is a DNAT whose `-d` is a WolfNet IP (inside
/// `net`, the real network — not a three-octet prefix, see `WolfNetNetwork`)
/// and whose `--to-destination` is a
/// container bridge IP OUTSIDE the WolfNet subnet. That last condition is what
/// separates our rules from an `IpMapping` DNAT (`public_ip → wolfnet_ip`,
/// where `--to` IS inside WolfNet), so we can never sweep a legitimate IP
/// mapping even if its public_ip were set inside the WolfNet range. WolfRun
/// vip-map and standard ip-map comment tags are also excluded defensively.
/// Returns the bare `-d` IP without the `/32`. Pure — unit-tested — so the
/// accumulation/orphan matching can't regress.
fn container_dnat_dst_ip(line: &str, net: &WolfNetNetwork) -> Option<String> {
    container_dnat_rule_parts(line, net).map(|(dip, _)| dip)
}

/// Both halves of a container→WolfNet DNAT rule: `(wolfnet_ip, bridge_ip)`.
/// Same shape test as `container_dnat_dst_ip` — which is now a thin wrapper,
/// so the "which rules are ours" rule lives in exactly one place.
fn container_dnat_rule_parts(line: &str, net: &WolfNetNetwork) -> Option<(String, String)> {
    if !line.contains("DNAT")
        || line.contains("wolfstack-vip-map")
        || line.contains("wolfstack-ip-map")
    {
        return None;
    }
    // -d must be a WolfNet IP (and not a negated `! -d`).
    let dpos = line.find(" -d ")?;
    if line[..dpos].ends_with('!') { return None; }
    let dcidr = line[dpos + 4..].split_whitespace().next()?;
    let dip = dcidr.split('/').next()?;
    if !net.contains(dip) { return None; }
    // --to-destination must be a bridge IP OUTSIDE the WolfNet subnet.
    let tpos = line.find("--to-destination ")?;
    let tdest = line[tpos + 17..].split_whitespace().next()?;
    let tip = tdest.split(':').next()?; // strip :port if present
    if net.contains(tip) { return None; }
    Some((dip.to_string(), tip.to_string()))
}

/// Pure: `container name → its bridge addresses` from one
/// `docker inspect --format '{{.Name}}|{{range …}}{{.IPAddress}} {{end}}'`
/// over every RUNNING container. Docker prints the name with a leading
/// slash; addresses are space-separated and may be empty.
fn parse_running_container_addrs(text: &str) -> Vec<(String, Vec<String>)> {
    text.lines()
        .filter_map(|l| {
            let (name, addrs) = l.split_once('|')?;
            let name = name.trim().trim_start_matches('/').to_string();
            if name.is_empty() { return None; }
            Some((
                name,
                addrs.split_whitespace().filter(|a| !a.is_empty()).map(|a| a.to_string()).collect(),
            ))
        })
        .collect()
}

/// `bridge address → the RUNNING container that holds it now`. One
/// `docker ps -q` plus one batched inspect; empty when either fails,
/// which makes every caller fall back to "nobody else owns it" — the
/// conservative answer (leave the rule alone).
fn running_container_addr_owners() -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let ids = match Command::new("timeout").args(["10", "docker", "ps", "-q"]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect::<Vec<_>>(),
        _ => return out,
    };
    if ids.is_empty() { return out; }
    let mut args: Vec<String> = vec![
        "10".into(), "docker".into(), "inspect".into(), "--format".into(),
        "{{.Name}}|{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}".into(),
    ];
    args.extend(ids);
    let text = match Command::new("timeout").args(&args).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return out,
    };
    for (name, addrs) in parse_running_container_addrs(&text) {
        for a in addrs {
            out.insert(a, name.clone());
        }
    }
    out
}

/// Pure: may a stopped-but-labelled container keep its DNAT rules?
///
/// A stopped container's rule is HARMLESS while nothing else holds the
/// bridge address it points at — and it must be kept, because Docker
/// restarts (restart policies, health-check bounces, `docker compose up`)
/// read as stopped for a moment and an eagerly deleted rule would leave
/// the container answering ping but not TCP until the next reconcile:
/// exactly the fault this whole area exists to remove.
///
/// It becomes DANGEROUS the moment Docker hands that address to a
/// different running container, because the rule then delivers this
/// WolfNet IP's traffic to a stranger. That, and only that, is a purge.
fn stopped_dnat_is_misdirected(
    container: &str,
    targets: &[String],
    addr_owner: &std::collections::HashMap<String, String>,
) -> bool {
    targets.iter().any(|t| addr_owner.get(t).is_some_and(|owner| owner != container))
}

/// Every `(wolfnet_ip, bridge_ip)` pair our container DNAT rules carry,
/// from one listing per chain.
fn container_dnat_pairs(net: &WolfNetNetwork) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for chain in ["PREROUTING", "OUTPUT"] {
        if let Ok(o) = Command::new("iptables").args(["-t", "nat", "-S", chain]).output()
            && o.status.success()
        {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                if let Some(p) = container_dnat_rule_parts(line, net) {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// Delete any container DNAT that points at `addr` but belongs to a
/// different WolfNet IP than `keep_ip`. Called when a container starts
/// and takes a bridge address: that is the exact moment a stopped
/// container's leftover rule stops being harmless.
fn purge_foreign_dnat_pointing_at(addr: &str, keep_ip: &str, net: &WolfNetNetwork) {
    if addr.is_empty() { return; }
    let stale: std::collections::BTreeSet<String> = container_dnat_pairs(net)
        .into_iter()
        .filter(|(wn, target)| target == addr && wn != keep_ip)
        .map(|(wn, _)| wn)
        .collect();
    for wn in stale {
        warn!("WolfNet: {} now holds bridge address {}; dropping the stale DNAT that still sent {} there", keep_ip, addr, wn);
        for chain in ["PREROUTING", "OUTPUT"] {
            purge_container_dnat_for_ip(chain, &wn, net);
        }
    }
}

#[cfg(test)]
mod container_dnat_ownership_tests {
    use super::*;

    #[test]
    fn rule_parts_returns_both_halves_and_ignores_foreign_rules() {
        let p = &WolfNetNetwork::parse("10.10.10.1/24").unwrap();
        assert_eq!(
            container_dnat_rule_parts(
                "-A PREROUTING -d 10.10.10.150/32 -j DNAT --to-destination 172.18.0.5 -m comment --comment wolfstack-wolfnet-container", p),
            Some(("10.10.10.150".into(), "172.18.0.5".into()))
        );
        // WolfRun VIP and IP-mapping rules are never ours to touch.
        assert_eq!(container_dnat_rule_parts(
            "-A PREROUTING -d 10.10.10.50/32 -j DNAT --to-destination 10.10.10.101:80 -m comment --comment wolfrun-lb-10.10.10.50", p), None);
        assert_eq!(container_dnat_rule_parts(
            "-A PREROUTING -d 10.10.10.60/32 -j DNAT --to-destination 172.18.0.9 -m comment --comment wolfstack-ip-map", p), None);
        // A target inside WolfNet is not a container bridge rule.
        assert_eq!(container_dnat_rule_parts(
            "-A PREROUTING -d 10.10.10.61/32 -j DNAT --to-destination 10.10.10.9", p), None);
    }

    #[test]
    fn running_container_addresses_parse_with_the_leading_slash_stripped() {
        let text = "/app_web|172.18.0.5 172.19.0.3 \n/db|172.18.0.6 \n|172.18.0.7 \n";
        assert_eq!(
            parse_running_container_addrs(text),
            vec![
                ("app_web".to_string(), vec!["172.18.0.5".to_string(), "172.19.0.3".to_string()]),
                ("db".to_string(), vec!["172.18.0.6".to_string()]),
            ]
        );
    }

    #[test]
    fn a_stopped_containers_rule_is_kept_unless_someone_else_took_the_address() {
        let mut owners = std::collections::HashMap::new();
        // Nobody holds it — a restart bounce must not lose its DNAT.
        assert!(!stopped_dnat_is_misdirected("app_web", &["172.18.0.5".into()], &owners));
        // The container itself is back up (raced the check) — still fine.
        owners.insert("172.18.0.5".to_string(), "app_web".to_string());
        assert!(!stopped_dnat_is_misdirected("app_web", &["172.18.0.5".into()], &owners));
        // Docker recycled the address to a stranger — now it misdirects.
        owners.insert("172.18.0.5".to_string(), "someone_else".to_string());
        assert!(stopped_dnat_is_misdirected("app_web", &["172.18.0.5".into()], &owners));
    }
}

/// Pure: is `chain`'s listing (`iptables -t nat -S <chain>` lines) already
/// exactly right for `label` — ONE rule of ours for that WolfNet IP, tagged,
/// pointing at `docker_ip` — so the reconcile has nothing to do?
///
/// "The correct rule exists" used to be tested with `iptables -C` and was
/// taken as steady state. It is not: a stale rule for the same WolfNet IP
/// that sits AHEAD of the correct one is the rule iptables applies, and
/// the -C check could not see it. klas's paperless container had three
/// (→ .5, → .6, → .4; only .6 was current) and the first one won — the
/// WolfNet IP answered ping from the wrong container and refused port
/// 8000. Steady state is exactly one rule, and it is the right one.
fn chain_dnat_is_exactly<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    label: &str,
    docker_ip: &str,
    net: &WolfNetNetwork,
) -> bool {
    let mut ours = 0usize;
    let mut correct = false;
    for line in lines {
        let Some((wn, target)) = container_dnat_rule_parts(line, net) else { continue };
        if wn != label { continue; }
        ours += 1;
        if target == docker_ip && line.contains(WOLFNET_CT_COMMENT) {
            correct = true;
        }
    }
    ours == 1 && correct
}

/// DNAT WolfNet IP → the container's CURRENT Docker IP, on both PREROUTING
/// (host-forwarded) and OUTPUT (host-local). Idempotent: when the chain
/// already holds exactly one rule for this WolfNet IP and it is the
/// correct tagged one (`chain_dnat_is_exactly`), NO change is made, so
/// there is no reachability gap on the reconcile tick. Otherwise — fresh
/// container, redeployed onto a new Docker IP, or stale rules for this IP
/// still present from earlier deployments (the accumulation Gary hit:
/// 10.10.10.3 → .2/.3/.4, and klas's 10.100.20.1 → .5/.6/.4 that the
/// three-octet prefix could not see) — purge EVERY DNAT for this WolfNet
/// IP, legacy comment-less ones included, then add the fresh, tagged one.
/// Called from the 60 s reconcile and, so a started container does not
/// wait a tick for it, from docker_connect_wolfnet.
fn ensure_container_dnat(label: &str, docker_ip: &str, net: &WolfNetNetwork) {
    for chain in ["PREROUTING", "OUTPUT"] {
        let listing = Command::new("iptables").args(["-t", "nat", "-S", chain]).output();
        if let Ok(o) = &listing && o.status.success() {
            let text = String::from_utf8_lossy(&o.stdout);
            if chain_dnat_is_exactly(text.lines(), label, docker_ip, net) { continue; }
            let stale: Vec<String> = text.lines()
                .filter_map(|l| container_dnat_rule_parts(l, net))
                .filter(|(wn, target)| wn == label && target != docker_ip)
                .map(|(_, target)| target)
                .collect();
            if !stale.is_empty() {
                warn!("WolfNet: {} DNAT for {} pointed at {} — replacing every rule for it with → {}",
                    chain, label, stale.join(", "), docker_ip);
            }
        }
        purge_container_dnat_for_ip(chain, label, net);
        let _ = Command::new("iptables").args([
            "-t", "nat", "-A", chain, "-d", label,
            "-j", "DNAT", "--to-destination", docker_ip,
            "-m", "comment", "--comment", WOLFNET_CT_COMMENT,
        ]).output();
    }
}

#[cfg(test)]
mod chain_dnat_steady_state_tests {
    use super::*;

    /// ninni's PREROUTING, verbatim from klas's 2026-09-10 diagnostic
    /// (WolfNet 10.100.10.20/16). Three rules for 10.100.20.1; iptables
    /// applied the first, → 192.168.12.5, a container with no :8000.
    const KLAS: &str = "\
-P PREROUTING ACCEPT
-A PREROUTING -d 10.100.30.2/32 -m comment --comment wolfstack-wolfnet-container -j DNAT --to-destination 172.18.0.4
-A PREROUTING -d 10.100.20.1/32 -m comment --comment wolfstack-wolfnet-container -j DNAT --to-destination 192.168.12.5
-A PREROUTING -d 10.100.10.26/32 -m comment --comment wolfstack-wolfnet-container -j DNAT --to-destination 172.19.0.2
-A PREROUTING -d 10.100.20.1/32 -m comment --comment wolfstack-wolfnet-container -j DNAT --to-destination 192.168.12.6
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A PREROUTING -d 10.100.20.1/32 -m comment --comment wolfstack-wolfnet-container -j DNAT --to-destination 192.168.12.4
-A PREROUTING -d 10.100.10.24/32 -m comment --comment wolfstack-wolfnet-container -j DNAT --to-destination 192.168.5.4";

    #[test]
    fn klas_three_rules_are_not_steady_state_even_though_the_correct_one_exists() {
        let net = WolfNetNetwork::parse("10.100.10.20/16").unwrap();
        assert!(!chain_dnat_is_exactly(KLAS.lines(), "10.100.20.1", "192.168.12.6", &net));
        // The single-rule neighbours ARE steady state.
        assert!(chain_dnat_is_exactly(KLAS.lines(), "10.100.10.24", "192.168.5.4", &net));
        assert!(chain_dnat_is_exactly(KLAS.lines(), "10.100.30.2", "172.18.0.4", &net));
    }

    /// The defect itself: with the old three-octet prefix of the NODE
    /// (10.100.10.) none of the 10.100.20.1 rules were even recognised as
    /// ours, so nothing could ever purge them.
    #[test]
    fn a_slash16_rule_is_ours_under_the_network_but_was_invisible_to_the_node_prefix() {
        let net = WolfNetNetwork::parse("10.100.10.20/16").unwrap();
        let line = "-A PREROUTING -d 10.100.20.1/32 -m comment --comment wolfstack-wolfnet-container -j DNAT --to-destination 192.168.12.5";
        assert_eq!(container_dnat_rule_parts(line, &net),
            Some(("10.100.20.1".into(), "192.168.12.5".into())));
        assert!(!"10.100.20.1".starts_with("10.100.10."), "the old prefix test misses it");
        let only_the_node_slash24 = WolfNetNetwork::parse("10.100.10.20/24").unwrap();
        assert_eq!(container_dnat_rule_parts(line, &only_the_node_slash24), None,
            "a genuine /24 network must still not claim addresses outside it");
    }

    #[test]
    fn steady_state_needs_the_tag_and_the_current_target() {
        let net = WolfNetNetwork::parse("10.10.10.1/24").unwrap();
        let ok = ["-A OUTPUT -d 10.10.10.3/32 -m comment --comment wolfstack-wolfnet-container -j DNAT --to-destination 172.18.0.2"];
        assert!(chain_dnat_is_exactly(ok, "10.10.10.3", "172.18.0.2", &net));
        assert!(!chain_dnat_is_exactly(ok, "10.10.10.3", "172.18.0.9", &net), "redeployed onto a new address");
        let untagged = ["-A OUTPUT -d 10.10.10.3/32 -j DNAT --to-destination 172.18.0.2"];
        assert!(!chain_dnat_is_exactly(untagged, "10.10.10.3", "172.18.0.2", &net), "legacy rule gets re-tagged");
        assert!(!chain_dnat_is_exactly(std::iter::empty(), "10.10.10.3", "172.18.0.2", &net));
        // Another IP's rules never count towards this one.
        let other = ["-A OUTPUT -d 10.10.10.4/32 -m comment --comment wolfstack-wolfnet-container -j DNAT --to-destination 172.18.0.2"];
        assert!(!chain_dnat_is_exactly(other, "10.10.10.3", "172.18.0.2", &net));
    }
}

/// Remove this WolfNet IP's container DNAT from both chains (container
/// stopped or its IP changed).
pub fn purge_container_dnat_for_wolfnet_ip(ip: &str) {
    let Some(net) = wolfnet_network_or_slash24(ip) else { return };
    for chain in ["PREROUTING", "OUTPUT"] {
        purge_container_dnat_for_ip(chain, ip, &net);
    }
}

/// Delete EVERY container→WolfNet DNAT rule in `chain` whose destination is
/// exactly `ip`, while leaving WolfRun vip-map / IpMapping rules alone (see
/// `container_dnat_dst_ip`). Deleting by exact spec (from `iptables -S`) is
/// nft-safe and position-independent. Used to clear stale/accumulated rules:
/// a container's Docker IP changes on redeploy, so the old delete (keyed on
/// the *current* Docker IP) left the previous rule behind and they piled up.
fn purge_container_dnat_for_ip(chain: &str, ip: &str, net: &WolfNetNetwork) {
    let out = match Command::new("iptables").args(["-t", "nat", "-S", chain]).output() {
        Ok(o) if o.status.success() => o,
        _ => return,
    };
    let add_prefix = format!("-A {} ", chain);
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if container_dnat_dst_ip(line, net).as_deref() != Some(ip) { continue; }
        let spec = match line.strip_prefix(&add_prefix) { Some(s) => s, None => continue };
        let mut argv: Vec<&str> = vec!["-t", "nat", "-D", chain];
        argv.extend(spec.split_whitespace());
        let _ = Command::new("iptables").args(&argv).output();
    }
}

#[cfg(test)]
mod coalesced_probe_tests {
    use super::CoalescedProbe;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    static CALLS: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn a_fresh_value_is_reused_without_probing() {
        static C: CoalescedProbe<Vec<u32>> = CoalescedProbe::new("test-fresh");
        let hits = AtomicUsize::new(0);
        let v = C.get(Duration::from_secs(60), || { hits.fetch_add(1, Ordering::SeqCst); vec![1] });
        assert_eq!(v, vec![1]);
        let v = C.get(Duration::from_secs(60), || { hits.fetch_add(1, Ordering::SeqCst); vec![2] });
        assert_eq!(v, vec![1], "second call must serve the cached value");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "probe must run exactly once");
    }

    #[test]
    fn an_expired_value_is_refreshed() {
        static C: CoalescedProbe<Vec<u32>> = CoalescedProbe::new("test-expired");
        assert_eq!(C.get(Duration::from_millis(1), || vec![1]), vec![1]);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(C.get(Duration::from_millis(1), || vec![2]), vec![2]);
    }

    #[test]
    fn invalidate_forces_a_reprobe() {
        static C: CoalescedProbe<Vec<u32>> = CoalescedProbe::new("test-invalidate");
        assert_eq!(C.get(Duration::from_secs(60), || vec![1]), vec![1]);
        C.invalidate();
        assert_eq!(C.get(Duration::from_secs(60), || vec![2]), vec![2]);
    }

    /// The bug this type exists to remove: a slow probe plus concurrent
    /// callers used to mean one subprocess PER CALLER. klas 2026-08-13 —
    /// hundreds of concurrent `docker inspect` against one container id.
    #[test]
    fn concurrent_callers_do_not_each_probe() {
        static C: CoalescedProbe<Vec<u32>> = CoalescedProbe::new("test-single-flight");
        CALLS.store(0, Ordering::SeqCst);
        // Seed a value so the 15 late callers can be served stale rather
        // than having to wait — that is the behaviour we want under load.
        C.get(Duration::from_millis(1), || vec![0]);
        std::thread::sleep(Duration::from_millis(5));

        let threads: Vec<_> = (0..16).map(|_| std::thread::spawn(|| {
            C.get(Duration::from_millis(1), || {
                CALLS.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(120));
                vec![9]
            })
        })).collect();
        for t in threads { t.join().unwrap(); }

        let n = CALLS.load(Ordering::SeqCst);
        assert!(n >= 1, "at least one refresh must have run");
        assert!(n < 16, "16 concurrent callers must NOT each start a probe (ran {n})");
    }

    #[test]
    fn a_panicking_probe_does_not_wedge_the_cache() {
        static C: CoalescedProbe<Vec<u32>> = CoalescedProbe::new("test-panic");
        let panicked = std::panic::catch_unwind(|| {
            C.get(Duration::from_secs(60), || -> Vec<u32> { panic!("probe blew up") })
        });
        assert!(panicked.is_err());
        // The in-flight marker must have been cleared by RefreshGuard::drop,
        // otherwise every later caller is locked out permanently.
        assert!(C.refresh_age().is_none(), "refresh marker must be cleared after a panic");
        assert_eq!(C.get(Duration::from_secs(60), || vec![7]), vec![7]);
    }

    #[test]
    fn refresh_age_is_none_when_idle() {
        static C: CoalescedProbe<Vec<u32>> = CoalescedProbe::new("test-idle");
        C.get(Duration::from_secs(60), || vec![1]);
        assert!(C.refresh_age().is_none());
    }
}

#[cfg(test)]
mod container_dnat_tests {
    use super::{container_dnat_dst_ip, WolfNetNetwork};
    fn p() -> WolfNetNetwork { WolfNetNetwork::parse("10.10.10.1/24").unwrap() }

    #[test]
    fn matches_container_dnat_and_extracts_dst() {
        assert_eq!(
            container_dnat_dst_ip("-A PREROUTING -d 10.10.10.3/32 -j DNAT --to-destination 172.18.0.4", &p()),
            Some("10.10.10.3".to_string()));
        assert_eq!(
            container_dnat_dst_ip("-A OUTPUT -d 10.10.10.3/32 -j DNAT --to-destination 172.18.0.2 -m comment --comment wolfstack-wolfnet-container", &p()),
            Some("10.10.10.3".to_string()));
    }

    #[test]
    fn does_not_confuse_similar_prefix_ips() {
        assert_eq!(
            container_dnat_dst_ip("-A PREROUTING -d 10.10.10.30/32 -j DNAT --to-destination 172.18.0.9", &p()),
            Some("10.10.10.30".to_string()));
    }

    #[test]
    fn skips_vip_map_ip_map_and_non_dnat() {
        // WolfRun VIP-map LB rules are protected.
        assert_eq!(
            container_dnat_dst_ip("-A PREROUTING -d 10.10.10.3/32 -m statistic --mode nth --every 2 --packet 0 -j DNAT --to-destination 10.0.0.5 -m comment --comment wolfstack-vip-map-abc", &p()),
            None);
        assert_eq!(container_dnat_dst_ip("-A POSTROUTING ! -s 10.10.10.0/24 -o wolfnet0 -j MASQUERADE", &p()), None);
        assert_eq!(container_dnat_dst_ip("-A FORWARD -d 10.10.10.3/32 -j ACCEPT", &p()), None);
    }

    #[test]
    fn protects_ip_mapping_dnat_pointing_into_wolfnet() {
        // An IpMapping DNAT whose -d is (unusually) a WolfNet IP but whose
        // --to-destination is a WolfNet IP must NOT be treated as ours.
        assert_eq!(
            container_dnat_dst_ip("-A PREROUTING -d 10.10.10.3/32 -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.10.10.50:80", &p()),
            None);
        // A negated -d is not a destination match.
        assert_eq!(
            container_dnat_dst_ip("-A PREROUTING ! -d 10.10.10.3/32 -j DNAT --to-destination 172.18.0.4", &p()),
            None);
    }
}

pub fn cleanup_stale_wolfnet_routes() {
    let local_ips: std::collections::HashSet<String> = wolfnet_used_ips_cached().into_iter().collect();

    // The REAL network (address + prefix length), not the node's first
    // three octets: every membership test and every "WolfNet subnet" CIDR
    // below is wrong on anything wider than a /24 otherwise (klas, /16).
    let wn_net = match wolfnet_network() {
        Some(n) => n,
        None => return, // WolfNet not configured
    };

    // Get all kernel routes in the WolfNet range
    let output = match Command::new("ip").args(["route", "show"]).output() {
        Ok(o) => o,
        Err(_) => return,
    };
    let text = String::from_utf8_lossy(&output.stdout);

    for line in text.lines() {
        let ip = match line.split_whitespace().next() {
            Some(ip) if !ip.contains('/') && wn_net.contains(ip) => ip,
            _ => continue,
        };

        // Skip the subnet route (10.10.10.0/24 dev wolfnet0)
        if ip.contains('/') { continue; }

        // Remove if: IP not in local used IPs, OR route has linkdown (container stopped)
        let is_linkdown = line.contains("linkdown");
        if !local_ips.contains(ip) || is_linkdown {
            // Best-effort: whichever form the route was added with succeeds,
            // the other fails harmlessly.
            let _ = Command::new("ip")
                .args(["route", "del", &format!("{}/32", ip)])
                .output();
            // Also try without /32 in case the route was added without it
            let _ = Command::new("ip")
                .args(["route", "del", ip])
                .output();
        }
    }

    // Ensure Docker containers with WolfNet IPs have correct host routes
    // Uses each container's actual bridge device (docker0 or br-<id> for custom networks)
    let mut bridge_devs: std::collections::HashSet<String> = std::collections::HashSet::new();
    // WolfNet IPs CLAIMED by a container that still carries a WolfNet label —
    // running OR stopped. The orphan sweep below only removes DNAT rules for
    // IPs NOT in this set, so a temporarily-stopped-but-labeled container
    // (planned restart / compose bounce) is never swept; only a genuinely
    // label-removed / deleted container's rules are.
    let mut claimed_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    // CRITICAL: gate on the process EXIT status, not just Ok(spawned). A failed
    // `docker ps` (dockerd restarting/upgrading) returns Ok with empty stdout;
    // treating that as "no containers" would make the sweep delete EVERY
    // container DNAT rule on the host. On failure we skip the whole block and
    // retry next tick — leftover rules are harmless, a wrongful mass-delete is not.
    // One listing per chain for the whole pass: the stopped-container
    // check below is then a lookup rather than two iptables invocations
    // per stopped container per tick.
    let dnat_pairs = container_dnat_pairs(&wn_net);
    // Built at most once per tick, and only if a stopped labelled
    // container actually has rules to judge.
    let mut addr_owners: Option<std::collections::HashMap<String, String>> = None;

    let ps = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}"])
        .output();
    if let Some(output) = ps.as_ref().ok().filter(|o| o.status.success()) {
        let text = String::from_utf8_lossy(&output.stdout);
        for name in text.lines().filter(|l| !l.is_empty()) {
            // Check override file first, then Docker label
            let label = match docker_effective_wolfnet_ip(name) {
                Some(ip) => ip,
                None => continue,
            };
            // A labeled container claims its WolfNet IP even while stopped.
            claimed_ips.insert(label.clone());

            // Check if the container is running (needs a PID for nsenter)
            let pid_out = Command::new("docker")
                .args(["inspect", "--format", "{{.State.Pid}}", name])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            if pid_out.is_empty() || pid_out == "0" {
                // Stopped but still labelled. Its IP stays reserved
                // (claimed_ips above) and its DNAT STAYS unless the bridge
                // address that rule points at now belongs to a different
                // running container — see stopped_dnat_is_misdirected. A
                // Docker-driven restart reads as stopped for a moment, and
                // deleting the rule there would leave the container
                // answering ping but not TCP until the next tick.
                let targets: Vec<String> = dnat_pairs.iter()
                    .filter(|(wn, _)| *wn == label)
                    .map(|(_, target)| target.clone())
                    .collect();
                if !targets.is_empty() {
                    let owners = addr_owners
                        .get_or_insert_with(running_container_addr_owners);
                    if stopped_dnat_is_misdirected(name, &targets, owners) {
                        warn!("WolfNet: {} is stopped and its DNAT for {} now points at an address another container holds; removing it", name, label);
                        for chain in ["PREROUTING", "OUTPUT"] {
                            purge_container_dnat_for_ip(chain, &label, &wn_net);
                        }
                    }
                }
                continue;
            }

            // Detect this container's actual bridge device and gateway
            let net = docker_bridge_info(name);
            let (bridge_dev, gw) = (net.bridge_dev.clone(), net.gateway.clone());
            bridge_devs.insert(bridge_dev.clone());

            // Ensure host route via the container's actual bridge (idempotent — replace if exists)
            let _ = Command::new("ip")
                .args(["route", "replace", &format!("{}/32", label), "dev", &bridge_dev])
                .output();

            // Ensure static ARP entry. The MAC comes from the SAME network
            // the bridge and gateway were resolved from: the previous
            // per-field template ranged over every network with no
            // separator, so a container on two compose networks produced
            // "02:42:…02:42:…" and this replace failed silently every tick.
            if !net.mac.is_empty() {
                let _ = Command::new("ip")
                    .args(["neigh", "replace", &label, "lladdr", &net.mac, "dev", &bridge_dev, "nud", "permanent"])
                    .output();
            }

            // Ensure container has the WolfNet IP alias on eth0 (via nsenter)
            let _ = Command::new("nsenter")
                .args(["--target", &pid_out, "--net", "ip", "addr", "add", &format!("{}/32", label), "dev", "eth0"])
                .output(); // Silently ignores EEXIST

            // Ensure container can route WolfNet subnet via its network's gateway
            // with src hint so the container uses its WolfNet IP as source
            let wn_subnet = wn_net.cidr();
            let _ = Command::new("nsenter")
                .args(["--target", &pid_out, "--net", "ip", "route", "replace", &wn_subnet, "via", &gw, "src", &label])
                .output();

            // For containers on custom Docker networks (not docker0), also set up DNAT
            // so that traffic arriving at the host for this WolfNet IP gets redirected
            // to the container's Docker IP on the custom bridge. This ensures Docker's
            // own connection tracking handles the return path correctly, which is
            // required for reverse proxies and sustained connections (not just ping/curl).
            if bridge_dev != "docker0" {
                // The container's Docker IP on the network the bridge was
                // resolved from — never a concatenation of every network's
                // address (see docker_bridge_info). With the old template a
                // two-network container got "172.18.0.5172.19.0.3": the -C
                // check failed, the purge removed any good rule, and the -A
                // was rejected, so the container had NO DNAT at all.
                let docker_ip = net.ip.clone();
                if !docker_ip.is_empty() && docker_ip != label {
                    ensure_container_dnat(&label, &docker_ip, &wn_net);
                }
            }
        }

        // ── Orphan sweep ──────────────────────────────────────────────
        // Remove container→WolfNet DNAT rules for any WolfNet IP no longer
        // CLAIMED by a labeled container. This is what was missing entirely:
        // when a WolfNet label is removed the container drops out of the loop
        // above, so nothing ever cleaned its DNAT rules and the IP stayed
        // pingable (KO4BSR/Gary). container_dnat_dst_ip identifies our rules by
        // shape (WolfNet -d, bridge --to) so it also clears legacy untagged
        // rules and accumulated duplicates while never touching vip-map or
        // IpMapping rules. Runs only when `docker ps` genuinely SUCCEEDED
        // (checked above), so a dockerd hiccup can't be mistaken for
        // "everything orphaned".
        let mut present: std::collections::HashSet<String> = std::collections::HashSet::new();
        for chain in ["PREROUTING", "OUTPUT"] {
            if let Ok(out) = Command::new("iptables").args(["-t", "nat", "-S", chain]).output() {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    if let Some(ip) = container_dnat_dst_ip(line, &wn_net) {
                        present.insert(ip);
                    }
                }
            }
        }
        for ip in present {
            if !claimed_ips.contains(&ip) {
                purge_container_dnat_for_ip("PREROUTING", &ip, &wn_net);
                purge_container_dnat_for_ip("OUTPUT", &ip, &wn_net);
            }
        }
    }

    // ─── Subnet-collision /32 host routes ──────────────────────────────
    //
    // PapaSchlumpf's case: a Docker macvlan whose subnet happens to be
    // the same as WolfNet's (`10.0.10.0/24` here). The kernel's /24 route
    // for the WolfNet subnet sends every packet for that range into
    // wolfnet0 (the WireGuard tunnel) — where the container doesn't
    // exist. DNAT rules to such containers black-hole because routing
    // happens AFTER DNAT. The container is reachable on the LAN at L2
    // via the macvlan's parent NIC, so a /32 host route via that parent
    // wins by longest-prefix-match and packets get delivered.
    //
    // We do this for any running Docker container whose IP falls in the
    // WolfNet subnet AND isn't already accounted for by the
    // `wolfnet_ip`-labelled path above. Idempotent: `ip route replace`
    // creates or overrides as needed.
    if let Ok(output) = Command::new("docker")
        .args(["ps", "--format", "{{.Names}}"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for name in text.lines().filter(|l| !l.is_empty()) {
            // Skip if this container is the WolfStack-managed flavour —
            // the labelled-WolfNet-IP loop above already added its /32
            // route via the WolfStack-managed bridge.
            if docker_effective_wolfnet_ip(name).is_some() { continue; }

            let (cip, egress) = match docker_container_egress(name) {
                Some(t) => t,
                None => continue,
            };

            // Only act when the container's IP falls in WolfNet's range.
            // Other subnets aren't this loop's concern.
            if !wn_net.contains(&cip) { continue; }
            // Belt-and-braces: don't fight the labelled path if we
            // somehow disagree about what's a wolfnet IP.
            if local_ips.contains(&cip) { continue; }

            let res = Command::new("ip")
                .args(["route", "replace", &format!("{}/32", cip), "dev", &egress])
                .output();
            if res.map(|o| o.status.success()).unwrap_or(false) {
                bridge_devs.insert(egress.clone());
                info!(
                    "subnet-collision route: {}/32 dev {} (container '{}' uses Docker network in WolfNet subnet)",
                    cip, egress, name
                );
            }
        }
    }

    // Same subnet-collision /32 route for LXC. An LXC on a USER bridge with a
    // static IP inside the WolfNet /24 black-holes into wolfnet0 exactly like
    // the Docker case above — and the WolfNet route-maintenance pass only repairs
    // lxcbr0 / WolfNet-IP-labelled containers, not a plain user-bridge collision.
    // Covers native LXC (lxc.net.0.link) and Proxmox (net0 bridge=).
    for c in lxc_list_all() {
        if c.state != "running" { continue; }
        // `ip_address` here may be multi-homed ("10.0.10.5, 192.168.1.5"),
        // CIDR-suffixed ("10.0.10.5/24" from the pct config fallback), or carry
        // a " (wolfnet)" annotation — none of which `ip route` accepts. The
        // Docker loop above gets a clean single IP from docker_container_egress;
        // LXC has to sanitise its own.
        let Some(cip) = first_reportable_ip(&c.ip_address) else { continue };
        let cip = cip.as_str();
        if !wn_net.contains(cip) { continue; }
        if local_ips.contains(cip) { continue; }
        // The WolfNet-IP-labelled / lxcbr0 path is repaired elsewhere.
        if lxc_get_wolfnet_ip(&c.name).is_some() { continue; }
        let Some(egress) = lxc_primary_bridge_any(&c.name) else { continue; };
        if egress == "lxcbr0" { continue; }
        let res = Command::new("ip")
            .args(["route", "replace", &format!("{}/32", cip), "dev", &egress])
            .output();
        if res.map(|o| o.status.success()).unwrap_or(false) {
            bridge_devs.insert(egress.clone());
            info!(
                "subnet-collision route: {}/32 dev {} (LXC '{}' on a user bridge in WolfNet subnet)",
                cip, egress, c.name
            );
        }
    }

    // Inject WolfNet subnet route into ALL running Docker containers (not just ones with WolfNet IPs)
    // so any container can reach remote WolfNet hosts via the Docker gateway
    if let Ok(output) = Command::new("docker")
        .args(["ps", "--format", "{{.Names}}"])
        .output()
    {
        let wn_subnet = wn_net.cidr();
        let text = String::from_utf8_lossy(&output.stdout);
        for name in text.lines().filter(|l| !l.is_empty()) {
            let pid_out = Command::new("docker")
                .args(["inspect", "--format", "{{.State.Pid}}", name])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            if pid_out.is_empty() || pid_out == "0" { continue; }

            let net = docker_bridge_info(name);
            let (bridge_dev, gw) = (net.bridge_dev.clone(), net.gateway.clone());
            bridge_devs.insert(bridge_dev);

            // Add route for WolfNet subnet via the Docker gateway (idempotent).
            // If the container has a WolfNet IP, include `src <wolfnet_ip>` so the
            // kernel uses it as the source address — otherwise this `replace` would
            // clobber the src hint set by the per-WolfNet-IP loop above, leaving
            // traffic sourced from the container's Docker IP (breaks TCP/MTU paths).
            let wolfnet_ip = docker_effective_wolfnet_ip(name);
            let mut args: Vec<String> = vec![
                "--target".into(), pid_out.clone(), "--net".into(),
                "ip".into(), "route".into(), "replace".into(),
                wn_subnet.clone(), "via".into(), gw.clone(),
            ];
            if let Some(ref ip) = wolfnet_ip {
                args.push("src".into());
                args.push(ip.clone());
            }
            let _ = Command::new("nsenter").args(&args).output();
        }
    }

    // Re-apply all wolfnet0 forwarding rules (survives Docker iptables rebuilds)
    setup_wolfnet_forwarding();

    // Enable forwarding and firewalld trust for any custom Docker bridges we found
    for bd in &bridge_devs {
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.forwarding=1", bd)]).output();
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.send_redirects=0", bd)]).output();
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.rp_filter=0", bd)]).output();
        let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.proxy_arp=1", bd)]).output();
        ensure_firewalld_trusted(&[bd, "wolfnet0"]);
    }
}

// ─── WolfNet Integration ───

/// The WolfNet network this node is on: its own address plus the prefix
/// length wolfnet configured on wolfnet0 (`ip addr add <address>/<subnet>`
/// in wolfnet's `tun.rs`). This — not the first three octets — is what
/// decides whether an address is a WolfNet address.
///
/// WolfNet's default is a /24, and until v25.26.1 every membership test
/// and every "the WolfNet subnet" CIDR in WolfStack was built from the
/// node's first three octets. On a /16 (klas: nodes on 10.100.10.x,
/// containers on 10.100.20.x/30.x) that made every 10.100.20.x DNAT rule
/// invisible to the code that purges stale ones: each container
/// recreation appended a fresh rule BEHIND the old one, iptables took the
/// first match, and the WolfNet IP was delivered to whatever container now
/// held the old bridge address — which answered ping and refused the port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WolfNetNetwork {
    /// This node's own WolfNet address (host bits kept).
    pub addr: std::net::Ipv4Addr,
    /// Prefix length, 0..=32.
    pub prefix: u8,
}

impl WolfNetNetwork {
    /// Parse `"10.100.10.20/16"`. A bare address has no prefix and is
    /// rejected — callers must never invent one.
    pub fn parse(cidr: &str) -> Option<Self> {
        let (a, p) = cidr.trim().split_once('/')?;
        let addr: std::net::Ipv4Addr = a.parse().ok()?;
        let prefix: u8 = p.parse().ok()?;
        if prefix > 32 { return None; }
        Some(Self { addr, prefix })
    }

    fn mask(&self) -> u32 {
        if self.prefix == 0 { 0 } else { (!0u32).checked_shl(32 - self.prefix as u32).unwrap_or(0) }
    }

    /// Is `ip` (a bare dotted quad; anything else is "no") inside this network?
    pub fn contains(&self, ip: &str) -> bool {
        match ip.trim().parse::<std::net::Ipv4Addr>() {
            Ok(a) => (u32::from(a) & self.mask()) == (u32::from(self.addr) & self.mask()),
            Err(_) => false,
        }
    }

    /// The network in CIDR form with host bits cleared: `"10.100.0.0/16"`.
    pub fn cidr(&self) -> String {
        let net = std::net::Ipv4Addr::from(u32::from(self.addr) & self.mask());
        format!("{}/{}", net, self.prefix)
    }

    /// The `/24` CIDR older WolfStack versions wrote for this node
    /// (`<first three octets>.0/24`), when it differs from the real
    /// network. Used to remove the rules those versions left behind; None
    /// on a /24, where the old and new forms are the same rule.
    pub fn legacy_slash24(&self) -> Option<String> {
        if self.prefix == 24 { return None; }
        let o = self.addr.octets();
        Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
    }
}

/// This node's WolfNet network, from the live wolfnet0 address (which
/// wolfnet writes as `<address>/<subnet>`), else from
/// /etc/wolfnet/config.toml (`address` + `subnet`, default 24 exactly as
/// wolfnet's own `default_subnet()`). None when WolfNet is not configured.
pub fn wolfnet_network() -> Option<WolfNetNetwork> {
    if let Ok(out) = Command::new("ip").args(["-4", "addr", "show", "wolfnet0"]).output()
        && out.status.success()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some(cidr) = text.lines()
            .find(|l| l.trim_start().starts_with("inet "))
            .and_then(|l| l.split_whitespace().nth(1))
            && let Some(net) = WolfNetNetwork::parse(cidr)
        {
            return Some(net);
        }
    }
    crate::networking::get_local_wolfnet_subnet()
        .map(|(addr, prefix)| WolfNetNetwork { addr, prefix })
}

/// The WolfNet network for routing/NAT rules that name a workload's WolfNet
/// address: the real network when this node knows it, otherwise the
/// address's own /24 — the only thing older versions ever used, kept solely
/// so a node whose wolfnet0 is down AND whose config.toml is unreadable
/// still installs/removes the same rule it always did.
pub fn wolfnet_network_or_slash24(ip: &str) -> Option<WolfNetNetwork> {
    wolfnet_network().or_else(|| WolfNetNetwork::parse(&format!("{}/24", ip.trim())))
}

/// `wolfnet_network_or_slash24(ip).cidr()`, or "" when `ip` is not even an
/// address — for the `ip route` / iptables argument lists.
pub fn wolfnet_cidr_for(ip: &str) -> String {
    wolfnet_network_or_slash24(ip).map(|n| n.cidr()).unwrap_or_default()
}

#[cfg(test)]
mod wolfnet_network_tests {
    use super::WolfNetNetwork;

    #[test]
    fn parses_and_masks() {
        let n = WolfNetNetwork::parse("10.100.10.20/16").unwrap();
        assert_eq!(n.cidr(), "10.100.0.0/16");
        assert_eq!(n.legacy_slash24().as_deref(), Some("10.100.10.0/24"));
        let n24 = WolfNetNetwork::parse("10.10.10.1/24").unwrap();
        assert_eq!(n24.cidr(), "10.10.10.0/24");
        assert_eq!(n24.legacy_slash24(), None, "on a /24 the old and new rule are identical");
        assert_eq!(WolfNetNetwork::parse("10.10.10.1"), None, "a prefix is never invented");
        assert_eq!(WolfNetNetwork::parse("10.10.10.1/33"), None);
        assert_eq!(WolfNetNetwork::parse("0.0.0.0/0").unwrap().cidr(), "0.0.0.0/0");
    }

    /// klas's network: nodes on 10.100.10.x, containers on 10.100.20.x.
    #[test]
    fn membership_follows_the_prefix_not_the_third_octet() {
        let n = WolfNetNetwork::parse("10.100.10.20/16").unwrap();
        assert!(n.contains("10.100.10.30"));
        assert!(n.contains("10.100.20.1"), "a /16 spans every third octet");
        assert!(n.contains("10.100.255.254"));
        assert!(!n.contains("10.101.0.1"));
        assert!(!n.contains("192.168.12.5"), "a Docker bridge address is never WolfNet");
        assert!(!n.contains("10.100.20.1/32"), "only bare addresses");
        assert!(!n.contains(""));
        let n24 = WolfNetNetwork::parse("10.10.10.1/24").unwrap();
        assert!(n24.contains("10.10.10.200"));
        assert!(!n24.contains("10.10.11.1"));
    }
}

/// The node's own /24 slice as `"10.100.10"`, from wolfnet0 or
/// /etc/wolfnet/config.toml. Never hardcode "10.10.10" — users choose their
/// own subnet when they set up WolfNet.
///
/// This is the range the IP ALLOCATORS hand addresses out of (the node's
/// own third octet, hosts 2..=254), and only that. It is NOT a membership
/// test and NOT "the WolfNet subnet": on a WolfNet wider than /24 both of
/// those are wrong here — use `wolfnet_network()`.
pub fn wolfnet_subnet_prefix() -> Option<String> {
    // Primary: read wolfnet0 interface IP
    if let Ok(out) = Command::new("ip").args(["addr", "show", "wolfnet0"]).output()
        && out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(ip) = text.lines()
                .find(|l| l.contains("inet "))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.split('/').next())
            {
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() == 4 {
                    return Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]));
                }
            }
        }
    // Fallback: config file
    if let Ok(content) = std::fs::read_to_string("/etc/wolfnet/config.toml") {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("address") && trimmed.contains('=')
                && let Some(val) = trimmed.split('=').nth(1) {
                    let addr = val.trim().trim_matches('"').trim();
                    let parts: Vec<&str> = addr.split('.').collect();
                    if parts.len() >= 3 {
                        return Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]));
                    }
                }
        }
    }
    None
}

/// WolfNet status for container networking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfNetStatus {
    pub available: bool,
    pub interface: String,
    pub ip: String,
    pub subnet: String,
    pub next_available_ip: String,
}

/// Check if WolfNet is running and get network info
pub fn wolfnet_status(extra_used: &[u8]) -> WolfNetStatus {
    // Check if wolfnet0 interface exists
    let output = Command::new("ip")
        .args(["addr", "show", "wolfnet0"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            // Parse IP from wolfnet0 interface
            let ip = text.lines()
                .find(|l| l.contains("inet "))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.split('/').next())
                .unwrap_or("")
                .to_string();

            // The real network wolfnet configured (the same `ip addr show`
            // carries the prefix length), not the address's /24.
            let subnet = if !ip.is_empty() {
                text.lines()
                    .find(|l| l.trim_start().starts_with("inet "))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(WolfNetNetwork::parse)
                    .map(|n| n.cidr())
                    .unwrap_or_default()
            } else {
                String::new()
            };

            let next_ip = wolfnet_allocate_ip(&ip, extra_used);

            WolfNetStatus {
                available: !ip.is_empty(),
                interface: "wolfnet0".to_string(),
                ip,
                subnet,
                next_available_ip: next_ip,
            }
        }
        _ => WolfNetStatus {
            available: false,
            interface: String::new(),
            ip: String::new(),
            subnet: String::new(),
            next_available_ip: String::new(),
        },
    }
}

/// Allocate the next available WolfNet IP for a container
/// Scans existing containers and picks the next free IP in the WolfNet /24 range
pub fn wolfnet_allocate_ip(host_ip: &str, extra_used: &[u8]) -> String {
    let parts: Vec<&str> = host_ip.split('.').collect();
    if parts.len() != 4 {
        // Fall back to dynamic detection instead of hardcoded prefix
        if let Some(pfx) = wolfnet_subnet_prefix() {
            return format!("{}.100", pfx);
        }
        return String::new();
    }
    let prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);

    // Get all IPs currently in use on the wolfnet0 subnet
    let mut used_ips = std::collections::HashSet::new();

    // Host IP
    if let Ok(last) = parts[3].parse::<u8>() {
        used_ips.insert(last);
    }

    // Add extra IPs from remote cluster nodes
    for &ip in extra_used {
        used_ips.insert(ip);
    }

    // Live WolfNet peers and stopped workloads on other nodes — see
    // wolfnet_used_ip_set for why both must be excluded.
    for peer in wolfnet_live_peers() {
        if let Some(last) = peer.address.rsplit('.').next().and_then(|s| s.parse::<u8>().ok()) {
            used_ips.insert(last);
        }
    }
    for r in remote_wolfnet_ips() {
        for ip in r.reserved {
            if let Some(last) = ip.rsplit('.').next().and_then(|s| s.parse::<u8>().ok()) {
                used_ips.insert(last);
            }
        }
    }

    // Check cluster-wide route cache (populated by poll_remote_nodes)
    // This catches container IPs from ALL nodes in the cluster
    {
        let cache = WOLFNET_ROUTES.lock().unwrap();
        for ip_str in cache.keys() {
            let ip_parts: Vec<&str> = ip_str.split('.').collect();
            if ip_parts.len() == 4
                && let Ok(last) = ip_parts[3].parse::<u8>() {
                    used_ips.insert(last);
                }
        }
    }

    // Also check routes.json as fallback
    if let Ok(content) = std::fs::read_to_string("/var/run/wolfnet/routes.json")
        && let Ok(routes) = serde_json::from_str::<std::collections::HashMap<String, String>>(&content) {
            for ip_str in routes.keys() {
                let ip_parts: Vec<&str> = ip_str.split('.').collect();
                if ip_parts.len() == 4
                    && let Ok(last) = ip_parts[3].parse::<u8>() {
                        used_ips.insert(last);
                    }
            }
        }

    // Check Docker containers with WolfNet IPs (override file or label)
    if let Ok(output) = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for name in text.lines().filter(|l| !l.is_empty()) {
            if let Some(ip) = docker_effective_wolfnet_ip(name) {
                let ip_parts: Vec<&str> = ip.split('.').collect();
                if ip_parts.len() == 4
                    && let Ok(last) = ip_parts[3].parse::<u8>() {
                        used_ips.insert(last);
                    }
            }
        }
    }

    // Check LXC containers with .wolfnet/ip marker files
    for lxc_path in lxc_storage_paths() {
        if let Ok(entries) = std::fs::read_dir(&lxc_path) {
            for entry in entries.flatten() {
                let ip_file = entry.path().join(".wolfnet/ip");
                if let Ok(ip_str) = std::fs::read_to_string(&ip_file) {
                    let ip_str = ip_str.trim();
                    let ip_parts: Vec<&str> = ip_str.split('.').collect();
                    if ip_parts.len() == 4
                        && let Ok(last) = ip_parts[3].parse::<u8>() {
                            used_ips.insert(last);
                        }
                }
            }
        }
    }

    // Check VM configs for wolfnet_ip
    let vm_dir = std::path::Path::new("/var/lib/wolfstack/vms");
    if let Ok(entries) = std::fs::read_dir(vm_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json")
                && let Ok(content) = std::fs::read_to_string(&path)
                    && let Ok(vm) = serde_json::from_str::<serde_json::Value>(&content)
                        && let Some(ip_str) = vm.get("wolfnet_ip").and_then(|v| v.as_str()) {
                            let ip_parts: Vec<&str> = ip_str.split('.').collect();
                            if ip_parts.len() == 4
                                && let Ok(last) = ip_parts[3].parse::<u8>() {
                                    used_ips.insert(last);
                                }
                        }
        }
    }

    // Check ARP table on wolfnet0 for any other IPs in use
    if let Ok(output) = Command::new("ip")
        .args(["neigh", "show", "dev", "wolfnet0"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if let Some(ip) = line.split_whitespace().next() {
                let ip_parts: Vec<&str> = ip.split('.').collect();
                if ip_parts.len() == 4
                    && let Ok(last) = ip_parts[3].parse::<u8>() {
                        used_ips.insert(last);
                    }
            }
        }
    }

    // WolfRun service VIPs — reserve these so containers don't collide
    if let Ok(data) = std::fs::read_to_string(&crate::paths::get().wolfrun_services)
        && let Ok(services) = serde_json::from_str::<Vec<serde_json::Value>>(&data) {
            for svc in &services {
                if let Some(vip) = svc.get("service_ip").and_then(|v| v.as_str()) {
                    let ip_parts: Vec<&str> = vip.split('.').collect();
                    if ip_parts.len() == 4
                        && let Ok(last) = ip_parts[3].parse::<u8>() {
                            used_ips.insert(last);
                        }
                }
            }
        }

    // Allocate from 100-254 range (reserving 1-99 for hosts)
    for i in 100..=254u8 {
        if !used_ips.contains(&i) {
            return format!("{}.{}", prefix, i);
        }
    }

    format!("{}.100", prefix) // Fallback
}

/// The set of LXC containers currently RUNNING on this host (names on
/// standalone, VMIDs on Proxmox), computed in one shot so the WolfNet
/// advertisement scan doesn't spawn a status probe per container.
///
/// Returns `None` when the running state can't be determined at all (the
/// `pct`/`lxc-ls` probe failed to run) — callers then fall back to the
/// old "advertise every marker" behaviour rather than risk dropping a
/// reachable container's route on a transient tooling hiccup.
fn lxc_running_names() -> Option<std::collections::HashSet<String>> {
    let mut set = std::collections::HashSet::new();
    if is_proxmox() {
        let o = Command::new("pct").arg("list").output().ok()?;
        if !o.status.success() { return None; }
        // Header line then rows: "VMID  Status   Lock  Name".
        for line in String::from_utf8_lossy(&o.stdout).lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 2 && cols[1].eq_ignore_ascii_case("running") {
                set.insert(cols[0].to_string()); // VMID — matches the marker dir name
            }
        }
        return Some(set);
    }
    // Require every storage path's probe to succeed for a definitive
    // answer; on ANY failure (missing/erroring lxc-ls, stale path) return
    // None so callers advertise all markers — never blackhole a running
    // container's route because one path couldn't be listed.
    let mut all_ok = true;
    for base in lxc_storage_paths() {
        let mut args: Vec<String> = Vec::new();
        if base != LXC_DEFAULT_PATH {
            args.push("-P".to_string());
            args.push(base);
        }
        args.push("-1".to_string());
        args.push("--running".to_string());
        match Command::new("lxc-ls").args(&args).output() {
            Ok(o) if o.status.success() => {
                for name in String::from_utf8_lossy(&o.stdout).split_whitespace() {
                    if !name.is_empty() { set.insert(name.to_string()); }
                }
            }
            _ => { all_ok = false; }
        }
    }
    if all_ok { Some(set) } else { None }
}

/// Get list of WolfNet IPs currently in use on this node (for cluster-wide
/// dedup / allocation). Counts every workload that holds an IP, running or
/// stopped, so a stopped container's IP stays reserved and can't be handed
/// out to something else.
pub fn wolfnet_used_ips() -> Vec<String> {
    wolfnet_ips_internal(false)
}

/// Get the WolfNet IPs of workloads ACTIVE (running) on this node. This is
/// what gets advertised for routing and used for start-time conflict
/// detection — a stopped container is unreachable, so its IP must neither
/// attract cluster traffic nor block a start elsewhere. Allocation keeps
/// using wolfnet_used_ips()/wolfnet_used_ip_set(), which still count it.
pub fn wolfnet_active_ips() -> Vec<String> {
    wolfnet_ips_internal(true)
}

fn wolfnet_ips_internal(running_only: bool) -> Vec<String> {
    let mut ips = Vec::new();

    // Host IP from wolfnet0
    if let Ok(output) = Command::new("ip")
        .args(["addr", "show", "wolfnet0"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        if output.status.success() && !text.is_empty() {
            if let Some(ip) = text.lines()
                .find(|l| l.contains("inet "))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.split('/').next())
            {
                ips.push(ip.to_string());
            } else {
                warn!("wolfnet0 interface exists but has NO IP address — WolfNet may have lost its IP. Routes and connectivity will be broken.");
            }
        }
    }

    // Docker containers on a "wolfnet" Docker network (if it exists).
    // 10s cap — this runs in the WolfNet push/seed paths and a wedged
    // dockerd hung the task forever (masterpier's athena, 2026-07-03).
    // `docker network inspect` lists attached containers whatever their
    // run state, so in active-only mode each address is kept only when a
    // RUNNING container holds it — otherwise a stopped container here
    // would re-enter the routing set and re-create the double-claim this
    // split exists to end.
    if let Ok(output) = Command::new("timeout")
        .args(["10", "docker", "network", "inspect", "wolfnet", "--format",
               "{{range .Containers}}{{.IPv4Address}} {{end}}"])
        .output()
    {
        let running_addrs: Option<std::collections::HashMap<String, String>> =
            if running_only { Some(running_container_addr_owners()) } else { None };
        let text = String::from_utf8_lossy(&output.stdout);
        for addr in text.split_whitespace() {
            if let Some(ip) = addr.split('/').next()
                && !ip.is_empty() && !ips.contains(&ip.to_string()) {
                    if let Some(ref owners) = running_addrs
                        && !owners.contains_key(ip) {
                            continue;
                        }
                    ips.push(ip.to_string());
                }
        }
    }

    // Docker containers with WolfNet IPs (override file or label). In
    // active-only mode list just running containers (`docker ps`); in used
    // mode list all (`docker ps -a`) so stopped containers stay reserved.
    let docker_ps_args: &[&str] = if running_only {
        &["ps", "--format", "{{.Names}}"]
    } else {
        &["ps", "-a", "--format", "{{.Names}}"]
    };
    // 10s cap — wedged dockerd protection, same as the inspect above.
    let mut capped_ps: Vec<&str> = vec!["10", "docker"];
    capped_ps.extend_from_slice(docker_ps_args);
    if let Ok(output) = Command::new("timeout")
        .args(&capped_ps)
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for name in text.lines().filter(|l| !l.is_empty()) {
            if let Some(ip) = docker_effective_wolfnet_ip(name)
                && !ips.contains(&ip) {
                    ips.push(ip);
                }
        }
    }

    // LXC containers (from .wolfnet/ip marker files — authoritative source).
    // In active-only mode skip stopped containers: a stopped one (e.g. the
    // source side of a completed migrate, kept as a rollback) is unreachable,
    // and advertising its IP makes the cluster route there instead of the
    // node now hosting the container. In used (allocation) mode count them
    // all so their IPs stay reserved.
    let running = if running_only { lxc_running_names() } else { None };
    for lxc_path in lxc_storage_paths() {
        if let Ok(entries) = std::fs::read_dir(&lxc_path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                // `running` is Some only in active mode; if the probe failed
                // (None there) we fall back to advertising the marker.
                if running.as_ref().is_some_and(|r| !r.contains(&name)) { continue; }
                let ip_file = entry.path().join(".wolfnet/ip");
                if let Ok(contents) = std::fs::read_to_string(&ip_file) {
                    let ip = contents.trim().to_string();
                    if !ip.is_empty() && !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
        }
    }

    // VM WolfNet IPs. In active-only mode gate by per-platform run state
    // (PVE pidfiles / virsh / qemu pgrep) — the same reasoning as the LXC
    // gate above. Counting every VM config as active had two real failures:
    // a stopped VM's IP kept attracting cluster routes, and the start-time
    // conflict check matched the VM's OWN config file, so any wolfnet_ip a
    // VM was given reported "already in use: active on this node" and the
    // VM could never start (klasSponsor 2026-06-10). Probe failure → None
    // → count every config, mirroring the LXC fallback. In used
    // (allocation) mode count them all so stopped VMs' IPs stay reserved.
    let vm_running = if running_only { crate::vms::manager::running_vm_names() } else { None };
    let vm_dir = std::path::Path::new("/var/lib/wolfstack/vms");
    if let Ok(entries) = std::fs::read_dir(vm_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json")
                && let Ok(content) = std::fs::read_to_string(&path)
                    && let Ok(vm) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(running) = vm_running.as_ref() {
                            // Gate only when the config names the VM (it
                            // always does — VmConfig serializes `name`);
                            // an unnamed config stays advertised, fail-open.
                            let name = vm.get("name").and_then(|v| v.as_str()).unwrap_or("");
                            if !name.is_empty() && !running.contains(name) {
                                continue;
                            }
                        }
                        if let Some(ip_str) = vm.get("wolfnet_ip").and_then(|v| v.as_str()) {
                            ips.push(ip_str.to_string());
                        }
                    }
        }
    }
    // WolfRun service VIPs (load-balanced virtual IPs)
    if let Ok(data) = std::fs::read_to_string(&crate::paths::get().wolfrun_services)
        && let Ok(services) = serde_json::from_str::<Vec<serde_json::Value>>(&data) {
            for svc in &services {
                if let Some(vip) = svc.get("service_ip").and_then(|v| v.as_str())
                    && !vip.is_empty() && !ips.contains(&vip.to_string()) {
                        ips.push(vip.to_string());
                    }
            }
        }

    // Kubernetes WolfNet route IPs (k8s deployments with allocated WolfNet addresses)
    if let Ok(data) = std::fs::read_to_string(&crate::paths::get().kubernetes_config)
        && let Ok(config) = serde_json::from_str::<serde_json::Value>(&data)
            && let Some(clusters) = config.get("clusters").and_then(|c| c.as_array()) {
                for cluster in clusters {
                    if let Some(routes) = cluster.get("wolfnet_routes").and_then(|r| r.as_array()) {
                        for route in routes {
                            if let Some(ip) = route.get("wolfnet_ip").and_then(|v| v.as_str())
                                && !ip.is_empty() && !ips.contains(&ip.to_string()) {
                                    ips.push(ip.to_string());
                                }
                        }
                    }
                }
            }

    ips
}

/// Sync container routes from all WolfNet peers.
/// Reads /etc/wolfnet/config.toml to discover peers, calls each peer's
/// WolfStack API for their container IPs, builds routes.json, and
/// signals WolfNet to reload. This is the ground-truth mechanism —
/// config.toml defines exactly which nodes share this WolfNet mesh,
/// bypassing the cluster_name matching that can get out of sync.
pub async fn sync_wolfnet_peer_routes() {
    // Load cluster secret for authenticating API requests
    let cluster_secret = crate::auth::load_cluster_secret();

    // Read WolfNet config to find peers
    let config_path = "/etc/wolfnet/config.toml";
    let config_str = match std::fs::read_to_string(config_path) {
        Ok(s) => s,
        Err(_) => return, // No WolfNet config
    };

    // Parse the TOML to extract peer info
    let config: toml::Value = match config_str.parse() {
        Ok(v) => v,
        Err(_) => return,
    };

    let peers = match config.get("peers").and_then(|p| p.as_array()) {
        Some(p) => p,
        None => return,
    };

    // Shared pool — see CONTAINER_WOLFNET_CLIENT.
    let client = &*CONTAINER_WOLFNET_CLIENT;

    let mut subnet_routes: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for peer in peers {
        let allowed_ip = match peer.get("allowed_ip").and_then(|v| v.as_str()) {
            Some(ip) => ip.to_string(),
            None => continue,
        };
        let endpoint = match peer.get("endpoint").and_then(|v| v.as_str()) {
            Some(e) => e.to_string(),
            None => continue,
        };

        // Extract hostname from endpoint (e.g., "cynthia.wolfterritories.org:9600" → "cynthia.wolfterritories.org");
        // port-aware so a bare/bracketed IPv6 endpoint isn't truncated at its first group.
        let hostname = crate::netaddr::strip_port(&endpoint);

        // Pull the peer's ACTIVE WolfNet IPs (running workloads only) for
        // routing — a stopped container must not attract traffic to a node
        // that no longer hosts it. Fall back to /used-ips for peers not yet
        // upgraded to /active-ips. Try common WolfStack ports: 8553, 8552.
        let mut used_ips: Vec<String> = Vec::new();
        'byname: for path in &["/api/wolfnet/active-ips", "/api/wolfnet/used-ips"] {
            for port in &[8553, 8552] {
                for scheme in &["https", "http"] {
                    let url = format!("{}://{}:{}{}", scheme, crate::netaddr::bracket_host(hostname), port, path);
                    if let Ok(resp) = client.get(&url)
                        .peer_auth(&cluster_secret)
                        .send().await
                        && resp.status().is_success()
                            && let Ok(ips) = resp.json::<Vec<String>>().await
                                && !ips.is_empty() {
                                    used_ips = ips;
                                    break 'byname;
                                }
                }
            }
        }

        // Also try via WolfNet IP directly (in case DNS doesn't resolve but WolfNet tunnel works)
        if used_ips.is_empty() {
            'byip: for path in &["/api/wolfnet/active-ips", "/api/wolfnet/used-ips"] {
                for port in &[8553, 8552] {
                    let url = format!("http://{}:{}{}", allowed_ip, port, path);
                    if let Ok(resp) = client.get(&url)
                        .peer_auth(&cluster_secret)
                        .send().await
                        && resp.status().is_success()
                            && let Ok(ips) = resp.json::<Vec<String>>().await
                                && !ips.is_empty() {
                                    used_ips = ips;
                                    break 'byip;
                                }
                }
            }
        }

        if used_ips.is_empty() { continue; }

        // First IP is the host WolfNet address, rest are container/VM IPs
        // Map each container IP → host WolfNet IP (for routing)
        let host_wn_ip = &used_ips[0];
        for container_ip in &used_ips[1..] {
            if !container_ip.is_empty() && container_ip != host_wn_ip {
                subnet_routes.insert(container_ip.clone(), host_wn_ip.clone());
            }
        }
    }

    // Update in-memory route cache; only flushes to disk + SIGHUP if anything changed
    if !subnet_routes.is_empty() {
        update_wolfnet_routes(&subnet_routes);
    }
    // Note: do NOT delete routes.json when no routes found — poll_remote_nodes may have written valid routes
}

/// Ensure the Docker 'wolfnet' network exists (macvlan on wolfnet0)
/// Ensure networking requirements (just forwarding)
pub fn ensure_docker_wolfnet_network() -> Result<(), String> {
    // Enable per-interface forwarding so containers can route to WolfNet
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.wolfnet0.forwarding=1"]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.docker0.forwarding=1"]).output();

    // Ensure Docker DNS is configured (fixes 127.0.0.53 stub problem)
    // and outbound NAT/FORWARD rules are intact for Docker bridges.
    if docker_dns::ensure_docker_dns() {
        docker_dns::reload_docker_if_needed();
    }
    docker_dns::ensure_docker_outbound();

    Ok(())
}

/// Detect the host bridge interface and gateway for a Docker container.
/// Custom Docker networks use `br-<id>` instead of `docker0`, so we inspect
/// the container's actual network settings rather than assuming the default bridge.
/// The one Docker network WolfStack plumbs a container's WolfNet IP
/// through: host `/32` route, permanent ARP entry, DNAT target and the
/// container-side gateway all refer to THIS network, so its IP and MAC
/// must be read from the same place — never from a template that ranges
/// over every network.
#[derive(Debug, Clone)]
struct DockerPrimaryNet {
    pub bridge_dev: String,
    pub gateway: String,
    pub ip: String,
    pub mac: String,
}

const DOCKER_NET_INSPECT_FMT: &str =
    "{{range $net, $cfg := .NetworkSettings.Networks}}{{$net}}|{{$cfg.Gateway}}|{{$cfg.IPAddress}}|{{$cfg.MacAddress}}\n{{end}}";

/// Pure: choose the primary network from the `name|gateway|ip|mac` lines
/// DOCKER_NET_INSPECT_FMT emits (Go templates range a map in sorted key
/// order, so the choice is stable across ticks). The first network that
/// actually holds an IPv4 address wins; a container attached to a network
/// it has no address on yet (compose connects secondary networks after
/// create) must not be plumbed through that network. Falls back to the
/// first line, then to Docker's default bridge.
/// Returns (net_name, gateway, ip, mac).
fn parse_docker_primary_network(lines: &str) -> (String, String, String, String) {
    let parsed: Vec<[&str; 4]> = lines
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|l| {
            let mut it = l.split('|').map(|p| p.trim());
            let mut f = [""; 4];
            for slot in f.iter_mut() {
                *slot = it.next().unwrap_or("");
            }
            f
        })
        .collect();
    let chosen = parsed
        .iter()
        .find(|f| !f[2].is_empty())
        .or_else(|| parsed.first());
    let f = match chosen {
        Some(f) => *f,
        None => [""; 4],
    };
    let net_name = if f[0].is_empty() { "bridge" } else { f[0] };
    let gateway = if f[1].is_empty() { "172.17.0.1" } else { f[1] };
    (net_name.to_string(), gateway.to_string(), f[2].to_string(), f[3].to_string())
}

#[cfg(test)]
mod docker_primary_network_tests {
    use super::parse_docker_primary_network;

    #[test]
    fn single_network_is_taken_verbatim() {
        let (n, gw, ip, mac) = parse_docker_primary_network(
            "bridge|172.17.0.1|172.17.0.2|02:42:ac:11:00:02\n");
        assert_eq!((n.as_str(), gw.as_str(), ip.as_str(), mac.as_str()),
                   ("bridge", "172.17.0.1", "172.17.0.2", "02:42:ac:11:00:02"));
    }

    #[test]
    fn two_networks_never_concatenate_and_pick_the_first_with_an_ip() {
        // The pre-fix templates produced "172.18.0.5172.19.0.3" and
        // "02:42:ac:12:00:0502:42:ac:13:00:03" here — an unusable DNAT
        // target and an ARP entry the kernel rejected, every tick.
        let listing = "app_backend|172.18.0.1|172.18.0.5|02:42:ac:12:00:05\n\
                       proxy_net|172.19.0.1|172.19.0.3|02:42:ac:13:00:03\n";
        let (n, gw, ip, mac) = parse_docker_primary_network(listing);
        assert_eq!(n, "app_backend");
        assert_eq!(gw, "172.18.0.1");
        assert_eq!(ip, "172.18.0.5");
        assert_eq!(mac, "02:42:ac:12:00:05");
    }

    #[test]
    fn a_network_without_an_address_is_skipped() {
        let listing = "aaa_pending||||\nzzz_live|172.20.0.1|172.20.0.9|02:42:ac:14:00:09\n";
        let (n, gw, ip, mac) = parse_docker_primary_network(listing);
        assert_eq!(n, "zzz_live");
        assert_eq!(gw, "172.20.0.1");
        assert_eq!(ip, "172.20.0.9");
        assert_eq!(mac, "02:42:ac:14:00:09");
    }

    #[test]
    fn no_networks_falls_back_to_the_default_bridge() {
        let (n, gw, ip, mac) = parse_docker_primary_network("");
        assert_eq!((n.as_str(), gw.as_str(), ip.as_str(), mac.as_str()),
                   ("bridge", "172.17.0.1", "", ""));
    }
}

/// Detect the host bridge interface, gateway, container IP and MAC for a
/// Docker container — all from its primary network (see
/// `parse_docker_primary_network`). Custom Docker networks use `br-<id>`
/// instead of `docker0`, so the network is inspected rather than assumed.
fn docker_bridge_info(container: &str) -> DockerPrimaryNet {
    let network_info = Command::new("docker")
        .args(["inspect", "--format", DOCKER_NET_INSPECT_FMT, container])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    let (net_name, gateway, ip, mac) = parse_docker_primary_network(&network_info);
    let net_name = net_name.as_str();

    // Determine the host bridge interface for this Docker network
    let bridge_dev = if net_name == "bridge" || net_name == "host" || net_name.is_empty() {
        "docker0".to_string()
    } else {
        // Custom network — check for explicit bridge name, then fall back to br-<id>
        let explicit = Command::new("docker")
            .args(["network", "inspect", net_name, "--format",
                   "{{index .Options \"com.docker.network.bridge.name\"}}"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        if !explicit.is_empty() && explicit != "<no value>" {
            explicit
        } else {
            // Default: br-<first 12 chars of network ID>
            let net_id = Command::new("docker")
                .args(["network", "inspect", net_name, "--format", "{{.Id}}"])
                .output()
                .map(|o| {
                    let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if id.len() >= 12 { id[..12].to_string() } else { id }
                })
                .unwrap_or_default();
            if !net_id.is_empty() {
                format!("br-{}", net_id)
            } else {
                "docker0".to_string()
            }
        }
    };

    DockerPrimaryNet { bridge_dev, gateway, ip, mac }
}

/// For a running Docker container, return `(ip, egress_iface)` —
/// the container's primary IP and the host-side interface that
/// reaches the container at L2.
///
///   * macvlan / ipvlan networks → egress is the network's `parent`
///     option (the host NIC the macvlan attaches to). The container
///     is reachable at L2 via that NIC, even though no Linux interface
///     for the macvlan child exists on the host side.
///   * everything else (bridge networks) → egress is the network's
///     explicit `com.docker.network.bridge.name` option, or
///     `br-<first-12-chars-of-network-id>` (Docker's default naming).
///
/// Returns `None` when Docker can't be reached, the container has no
/// network, or the network's required option is missing. Used by the
/// subnet-collision /32 router in `cleanup_stale_wolfnet_routes`.
fn docker_container_egress(container: &str) -> Option<(String, String)> {
    let inspect_fmt = "{{range $net, $cfg := .NetworkSettings.Networks}}{{$net}}|{{$cfg.IPAddress}}\n{{end}}";
    let info = Command::new("docker")
        .args(["inspect", "--format", inspect_fmt, container])
        .output()
        .ok()?;
    if !info.status.success() { return None; }
    let text = String::from_utf8_lossy(&info.stdout);
    let first_line = text.lines().next()?;
    let parts: Vec<&str> = first_line.split('|').collect();
    if parts.len() < 2 { return None; }
    let net_name = parts[0].trim();
    let ip = parts[1].trim().to_string();
    if ip.is_empty() || net_name.is_empty() { return None; }

    // Inspect the network for driver + parent (macvlan/ipvlan) +
    // bridge name (custom bridges) + ID (default-named bridges).
    let net_info = Command::new("docker")
        .args(["network", "inspect", net_name, "--format",
               "{{.Driver}}|{{index .Options \"parent\"}}|{{index .Options \"com.docker.network.bridge.name\"}}|{{.Id}}"])
        .output()
        .ok()?;
    if !net_info.status.success() { return None; }
    let net_text = String::from_utf8_lossy(&net_info.stdout);
    let np: Vec<&str> = net_text.trim().split('|').collect();
    if np.len() < 4 { return None; }
    let driver = np[0].trim();
    let parent = np[1].trim();
    let bridge_name_opt = np[2].trim();
    let net_id = np[3].trim();

    let egress = match driver {
        "macvlan" | "ipvlan" => {
            if parent.is_empty() || parent == "<no value>" { return None; }
            parent.to_string()
        }
        _ => {
            if !bridge_name_opt.is_empty() && bridge_name_opt != "<no value>" {
                bridge_name_opt.to_string()
            } else if net_id.len() >= 12 {
                format!("br-{}", &net_id[..12])
            } else {
                return None;
            }
        }
    };

    Some((ip, egress))
}

/// Connect a Docker container to WolfNet via host routing (IP alias)
pub fn docker_connect_wolfnet(container: &str, ip: &str) -> Result<String, String> {
    ensure_docker_wolfnet_network()?;

    // 1. Detect the container's actual bridge device and gateway
    //    Custom Docker networks use br-<id>, not docker0
    let net = docker_bridge_info(container);
    let bridge_dev = net.bridge_dev.clone();
    let gateway = net.gateway.clone();

    // 2./3. The container's IP and MAC on THAT network. These used to come
    //    from two templates ranging over every network with no separator,
    //    which on a multi-network container (any compose stack with a
    //    proxy network) yielded a concatenated IP and MAC — the ARP entry
    //    and the ping fallback below then both worked on garbage.
    let container_bridge_ip = net.ip.clone();
    if container_bridge_ip.is_empty() {
        return Err(format!("Container '{}' has no bridge IP — is it running?", container));
    }
    let container_mac = net.mac.clone();

    // 4. Configure Container Side — use nsenter to avoid requiring 'ip' inside the container.
    //    Many images (e.g. official nginx) don't ship iproute2, so `docker exec ip ...` silently fails.
    //    nsenter enters the container's network namespace using the host's /sbin/ip binary.
    let container_pid = Command::new("docker")
        .args(["inspect", "--format", "{{.State.Pid}}", container])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    if container_pid.is_empty() || container_pid == "0" {

    } else {

        // Add IP alias /32 (idempotent — ignore EEXIST)
        let alias_result = Command::new("nsenter")
            .args(["--target", &container_pid, "--net", "ip", "addr", "add", &format!("{}/32", ip), "dev", "eth0"])
            .output();
        match &alias_result {
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if o.status.success() {

                } else if stderr.contains("EEXIST") || stderr.contains("File exists") {

                } 
            }
            Err(_e) => {},
        }

        // Add route to WolfNet subnet via gateway so container can reach other WolfNet hosts.
        // The `src` hint ensures the kernel uses the WolfNet IP as source, not the
        // Docker bridge IP — critical for cross-node connectivity.
        let subnet = wolfnet_cidr_for(ip);
        if !subnet.is_empty() {
            let _ = Command::new("nsenter")
                .args(["--target", &container_pid, "--net", "ip", "route", "replace", &subnet, "via", &gateway, "src", ip])
                .output();
        }
    }

    // 5. Configure Host Side
    // Enable per-interface forwarding on both wolfnet0 and the container's bridge
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.wolfnet0.forwarding=1"]).output();
    let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.forwarding=1", bridge_dev)]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.wolfnet0.send_redirects=0"]).output();
    let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.send_redirects=0", bridge_dev)]).output();
    let _ = Command::new("sysctl").args(["-w", &format!("net.ipv4.conf.{}.proxy_arp=1", bridge_dev)]).output();

    // iptables FORWARD rules (idempotent — check before adding)
    let check = Command::new("iptables")
        .args(["-C", "FORWARD", "-i", "wolfnet0", "-o", &bridge_dev, "-j", "ACCEPT"]).output();
    if check.map(|o| !o.status.success()).unwrap_or(true) {
        let _ = Command::new("iptables").args(["-I", "FORWARD", "-i", "wolfnet0", "-o", &bridge_dev, "-j", "ACCEPT"]).output();
        let _ = Command::new("iptables").args(["-I", "FORWARD", "-i", &bridge_dev, "-o", "wolfnet0", "-j", "ACCEPT"]).output();
    }

    // 6. Add static ARP entry so the host can reach the WolfNet IP without ARP resolution.
    if !container_mac.is_empty() {
        let neigh_result = Command::new("ip")
            .args(["neigh", "replace", ip, "lladdr", &container_mac, "dev", &bridge_dev, "nud", "permanent"])
            .output();
        match &neigh_result {
            Ok(_o) if _o.status.success() => {}
            Ok(_o) => {}
            Err(_e) => {}
        }
    } else {
        // Fallback: if we can't get the MAC, look up the container's bridge IP in the ARP table
        // and use that MAC for the WolfNet IP

        // Ping the bridge IP to populate ARP table
        let _ = Command::new("ping").args(["-c", "1", "-W", "1", &container_bridge_ip]).output();
        if let Ok(output) = Command::new("ip").args(["neigh", "show", &container_bridge_ip, "dev", &bridge_dev]).output() {
            let line = String::from_utf8_lossy(&output.stdout);
            // Parse: "172.17.0.2 lladdr 02:42:ac:11:00:02 REACHABLE"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[1] == "lladdr" {
                let mac = parts[2];

                let _ = Command::new("ip")
                    .args(["neigh", "replace", ip, "lladdr", mac, "dev", &bridge_dev, "nud", "permanent"])
                    .output();

            } 
        }
    }

    // 6b. Custom bridge: the DNAT the reconcile would otherwise add up to
    //     60 s from now — a freshly started container is reachable at once.
    if bridge_dev != "docker0" && container_bridge_ip != ip
        && let Some(net) = wolfnet_network_or_slash24(ip)
    {
        ensure_container_dnat(ip, &container_bridge_ip, &net);
    }

    // 7. Route traffic for this WolfNet IP to the container's bridge
    let _ = Command::new("ip").args(["route", "del", &format!("{}/32", ip)]).output();
    let route_result = Command::new("ip")
        .args(["route", "add", &format!("{}/32", ip), "dev", &bridge_dev])
        .output();

    match route_result {
        Ok(o) if o.status.success() => {

        }
        Ok(o) => {
            let _err = String::from_utf8_lossy(&o.stderr);

        }
        Err(e) => {
            return Err(format!("Failed to add host route: {}", e));
        }
    }

    Ok(format!("Container '{}' routed to WolfNet at {} via {}", container, ip, bridge_dev))
}

/// Ensure lxcbr0 bridge exists for default LXC container networking
/// (with DHCP/NAT). Idempotent — safe to call every minute. Logs every
/// error rather than swallowing them: silent failures here are how a
/// host ends up with running containers and no working bridge, with
/// the operator hunting through unrelated layers.
pub fn ensure_lxc_bridge() {
    if let Err(e) = ensure_lxc_bridge_checked() {
        error!("ensure_lxc_bridge: {}", e);
    }
}

/// Like `ensure_lxc_bridge` but surfaces the first hard failure. Used
/// internally so the public function can keep its `()` return — most
/// callers can't do anything useful with the error, they just need it
/// logged. The periodic self-heal tick uses the same wrapper.
fn ensure_lxc_bridge_checked() -> Result<(), String> {
    // FAST PATH: if lxcbr0 already has its IP, the bridge is up and lxc-net
    // (or a prior run) already did its job — do NOTHING. This is the steady
    // state on every healthy host, and the 60s self-heal tick lands here.
    // The previous code ran `systemctl enable --now lxc-net` on EVERY tick
    // regardless of state; because lxc-net is a sysv-init unit, each `enable`
    // triggers update-rc.d -> `systemctl daemon-reload`, producing a relentless
    // per-minute reload storm AND re-bouncing lxcbr0/dnsmasq. (regions9 /
    // PapaSchlumpf investigation, 2026-06-17.)
    //
    // The /32 host-route verification at the bottom of this function is
    // the ONE repair that must still run on this path: it is a handful of
    // `ip route show` calls, touches nothing systemd, and is the only
    // thing that puts back a route the linkdown sweep removed. The fast
    // path was added after it and silently made the "ALWAYS, even on
    // steady-state ticks" promise below false — a dropped route then
    // stayed gone until the container was restarted.
    if bridge_has_ip("lxcbr0", "10.0.3.1") {
        ensure_host_wolfnet_routes();
        return Ok(());
    }

    // Load the kernel bridge module first. `ip link add … type bridge`
    // fails with "Operation not supported" on kernels where the module
    // isn't built in and hasn't been auto-loaded yet (minimal cloud
    // images, custom kernels). Idempotent if already loaded; we don't
    // treat modprobe failure as fatal because some hosts ship bridge
    // built-in (no /lib/modules entry) and modprobe returns non-zero.
    let _ = Command::new("modprobe").arg("bridge").output();

    // Bridge isn't up — bring it up via lxc-net. Avoid `enable` (which rewrites
    // the sysv init links and forces a `daemon-reload`) when the unit is already
    // enabled; only `enable --now` if it isn't, otherwise just `start`. Keeps
    // the reload churn out of the recovery path too.
    let mut used_lxc_net = false;
    let already_enabled = Command::new("systemctl")
        .args(["is-enabled", "lxc-net"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let svc_args: &[&str] = if already_enabled {
        &["start", "lxc-net"]
    } else {
        &["enable", "--now", "lxc-net"]
    };
    if let Ok(o) = Command::new("systemctl").args(svc_args).output()
        && o.status.success() {
            used_lxc_net = true;
            for _ in 0..10 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if bridge_has_ip("lxcbr0", "10.0.3.1") { break; }
            }
        }

    let needs_create = !bridge_exists("lxcbr0");
    let needs_ip = !bridge_has_ip("lxcbr0", "10.0.3.1");

    if needs_create {
        let o = Command::new("ip")
            .args(["link", "add", "lxcbr0", "type", "bridge"])
            .output()
            .map_err(|e| format!("spawn `ip link add lxcbr0`: {}", e))?;
        if !o.status.success() {
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            // "File exists" = a parallel ensure_lxc_bridge already
            // created it — race is harmless. Anything else is real.
            if !err.contains("File exists") {
                return Err(format!(
                    "`ip link add lxcbr0 type bridge` failed: {}", err
                ));
            }
        } else {
            info!("ensure_lxc_bridge: created lxcbr0");
        }
    }

    if needs_ip {
        let o = Command::new("ip")
            .args(["addr", "add", "10.0.3.1/24", "dev", "lxcbr0"])
            .output()
            .map_err(|e| format!("spawn `ip addr add`: {}", e))?;
        if !o.status.success() {
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            if !err.contains("File exists") {
                return Err(format!(
                    "`ip addr add 10.0.3.1/24 dev lxcbr0` failed: {}", err
                ));
            }
        }
    }

    let o = Command::new("ip")
        .args(["link", "set", "lxcbr0", "up"])
        .output()
        .map_err(|e| format!("spawn `ip link set lxcbr0 up`: {}", e))?;
    if !o.status.success() {
        return Err(format!(
            "`ip link set lxcbr0 up` failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }

    // Final verification. If we got here without an error but the
    // bridge still isn't present + addressed, something *outside*
    // wolfstack is actively tearing it down (lxc-net stop hooks,
    // NetworkManager, an admin script, a malicious cleanup). Surface
    // that loudly — operators have lost hours chasing this when our
    // code silently returned success.
    if !bridge_has_ip("lxcbr0", "10.0.3.1") {
        return Err(
            "lxcbr0 still missing or unaddressed after create — \
             something external is tearing it down. Check \
             `journalctl -u lxc-net`, `journalctl --since '1 hour ago' \
             | grep -iE 'bridge|lxcbr'`, and any custom firewall / \
             network scripts on this host."
                .to_string(),
        );
    }

    // We just (re)brought lxcbr0 up. Two pieces of state the kernel
    // tore down when lxcbr0 vanished and that we have to put back:
    //
    //   1. Container veth peers — survived the deletion but are now
    //      unmastered orphans, no traffic until re-attached. Walk
    //      every running LXC container and re-master its veth.
    //
    //   2. Per-container host /32 routes (inside the container too).
    //      `reapply_wolfnet_routes` walks every running container's
    //      .wolfnet/ip marker and shells out to lxc-attach + `ip` to
    //      re-add the address inside the container AND the host /32
    //      route. Heavy (a 2s readiness sleep per container) but
    //      thorough; only worth running when we just created the
    //      bridge.
    //
    // Steady-state ticks (bridge already up) skip both.
    if needs_create {
        lxc_remaster_orphan_veths();
        reapply_wolfnet_routes();
    }

    // ALWAYS, even on steady-state ticks: verify the host /32 routes
    // that deliver inbound WolfNet traffic to each running container
    // are present, and reinstall any that are missing. This is the
    // light path — no lxc-attach, no readiness sleep, just one `ip
    // route show` per container plus an `ip route replace` for any
    // that drifted. mouse 2026-05-26: regions80 on dreamer could ping
    // 10.10.10.2 on mouse but not 10.10.10.200 / .3 / .4 — bridge was
    // up but those three `/32` routes were silently gone, so wolfnet
    // packets arrived at mouse's wolfnet0 and the kernel had nowhere
    // to deliver them. Without this verification step the only path
    // to recovery was restarting each affected container.
    ensure_host_wolfnet_routes();

    ensure_lxcbr0_services(used_lxc_net);
    Ok(())
}

/// For every running LXC container that owns a WolfNet IP, verify the
/// host has a `/32` route delivering that IP via `lxcbr0`. Reinstall
/// any that are missing using the bridge-IP/WolfNet-IP last-octet
/// convention (`10.10.10.X → 10.0.3.X`). Cheap: skips containers whose
/// routes are already correct.
fn ensure_host_wolfnet_routes() {
    for base_path in lxc_storage_paths() {
        let entries = match std::fs::read_dir(&base_path) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let container = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue,
            };
            // Skip dotted dirs (staging, tombstones, etc.).
            if container.starts_with('.') {
                continue;
            }

            let ip_file = entry.path().join(".wolfnet/ip");
            let wolfnet_ip = match std::fs::read_to_string(&ip_file) {
                Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
                _ => continue,
            };
            if wolfnet_ip.parse::<std::net::Ipv4Addr>().is_err() {
                continue;
            }

            // Only act on RUNNING containers — a stopped one has no
            // veth, so a host route would just black-hole.
            let mut info_args: Vec<String> =
                vec!["lxc-info".to_string()];
            if base_path != LXC_DEFAULT_PATH {
                info_args.push("-P".to_string());
                info_args.push(base_path.clone());
            }
            info_args.push("-n".to_string());
            info_args.push(container.clone());
            info_args.push("-sH".to_string());
            let running = Command::new(&info_args[0])
                .args(&info_args[1..])
                .output()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .trim()
                        .to_uppercase()
                        .contains("RUNNING")
                })
                .unwrap_or(false);
            if !running {
                continue;
            }

            // Already routed via lxcbr0? Skip.
            let route_present = Command::new("ip")
                .args(["route", "show", &format!("{}/32", wolfnet_ip)])
                .output()
                .map(|o| {
                    let s = String::from_utf8_lossy(&o.stdout);
                    s.contains("dev lxcbr0")
                })
                .unwrap_or(false);
            if route_present {
                continue;
            }

            // Derive bridge IP via the WolfNet-IP last-octet convention
            // (`assign_container_bridge_ip` enforces this on every
            // attach; legacy containers without that convention will
            // still fail until manually fixed — but the alternative is
            // shelling into the container, which makes this tick slow).
            let last_octet = match wolfnet_ip.rsplit('.').next() {
                Some(o) => o,
                None => continue,
            };
            let bridge_ip = format!("10.0.3.{}", last_octet);

            let out = Command::new("ip")
                .args([
                    "route",
                    "replace",
                    &format!("{}/32", wolfnet_ip),
                    "via",
                    &bridge_ip,
                    "dev",
                    "lxcbr0",
                ])
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    info!(
                        "ensure_host_wolfnet_routes: re-added /32 route for {} via {} dev lxcbr0 (container '{}')",
                        wolfnet_ip, bridge_ip, container
                    );
                }
                Ok(o) => {
                    warn!(
                        "ensure_host_wolfnet_routes: `ip route replace {}/32 via {} dev lxcbr0` failed: {}",
                        wolfnet_ip,
                        bridge_ip,
                        String::from_utf8_lossy(&o.stderr).trim()
                    );
                }
                Err(e) => {
                    warn!("ensure_host_wolfnet_routes: spawn `ip route`: {}", e);
                }
            }
        }
    }
}

/// True if `name` exists as a link of any kind on the host.
fn bridge_exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// True if `name` exists AND has the given IPv4 address.
fn bridge_has_ip(name: &str, ip: &str) -> bool {
    Command::new("ip")
        .args(["addr", "show", name])
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains(ip))
        .unwrap_or(false)
}

/// dnsmasq + NAT MASQUERADE + FORWARD rules. Each rule is checked
/// with `-C` first; we only insert what's missing. Stderr is logged on
/// failure so a wedged iptables doesn't disappear silently.
fn ensure_lxcbr0_services(_used_lxc_net: bool) {
    // dnsmasq — only start if nothing is already listening.
    let dns_in_use = Command::new("ss")
        .args(["-lnup", "sport", "=", "53"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("10.0.3.1"))
        .unwrap_or(false);
    let dnsmasq_running = Command::new("pgrep")
        .args(["-f", "dnsmasq.*lxcbr0"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        || Command::new("pgrep")
            .args(["-f", "dnsmasq.*10.0.3.1"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

    if !dns_in_use && !dnsmasq_running {
        let _ = std::fs::create_dir_all("/run/lxc");
        // `.status()`, not `.spawn()`: dnsmasq daemonizes by double-fork,
        // and its initial process exits the moment it has forked the
        // daemon. If we `.spawn()` and drop the Child handle we never
        // reap that initial process — it stays as a `<defunct>` zombie
        // parented to wolfstack. KO4BSR 2026-05-28: 1300+ defunct
        // dnsmasq under wolfstack on a node where this reconcile fires
        // every minute. `.status()` blocks just long enough for the
        // daemonize fork to complete (typically <100ms) and reaps it.
        let _ = Command::new("dnsmasq")
            .args([
                "--strict-order",
                "--bind-interfaces",
                "--pid-file=/run/lxc/dnsmasq.pid",
                "--listen-address",
                "10.0.3.1",
                "--dhcp-range",
                "10.0.3.2,10.0.3.254",
                "--dhcp-lease-max=253",
                "--dhcp-no-override",
                "--except-interface=lo",
                "--interface=lxcbr0",
                "--conf-file=", // avoid reading /etc/dnsmasq.conf
            ])
            .status();
    }

    // Forwarding sysctl on the bridge — separate from global ip_forward
    // because some hardened hosts disable per-interface forwarding.
    let _ = Command::new("sysctl")
        .args(["-w", "net.ipv4.conf.lxcbr0.forwarding=1"])
        .output();

    // NAT MASQUERADE — required for containers to reach the outside.
    let nat_present = Command::new("iptables")
        .args([
            "-t", "nat", "-C", "POSTROUTING",
            "-s", "10.0.3.0/24", "!", "-d", "10.0.3.0/24",
            "-j", "MASQUERADE",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !nat_present {
        let o = Command::new("iptables")
            .args([
                "-t", "nat", "-A", "POSTROUTING",
                "-s", "10.0.3.0/24", "!", "-d", "10.0.3.0/24",
                "-j", "MASQUERADE",
            ])
            .output();
        match o {
            Ok(o) if o.status.success() => info!(
                "ensure_lxc_bridge: re-added MASQUERADE for 10.0.3.0/24"
            ),
            Ok(o) => warn!(
                "ensure_lxc_bridge: iptables MASQUERADE insert failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => warn!("ensure_lxc_bridge: spawn iptables: {}", e),
        }
    }

    // FORWARD ACCEPT — both directions. Without these, containers
    // can't reach beyond lxcbr0 even with NAT and ip_forward on.
    let fwd_in_present = Command::new("iptables")
        .args(["-C", "FORWARD", "-i", "lxcbr0", "-j", "ACCEPT"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !fwd_in_present {
        let o = Command::new("iptables")
            .args(["-I", "FORWARD", "-i", "lxcbr0", "-j", "ACCEPT"])
            .output();
        match o {
            Ok(o) if o.status.success() => info!(
                "ensure_lxc_bridge: re-added FORWARD -i lxcbr0 ACCEPT"
            ),
            Ok(o) => warn!(
                "ensure_lxc_bridge: FORWARD -i insert failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => warn!("ensure_lxc_bridge: spawn iptables: {}", e),
        }
        let _ = Command::new("iptables")
            .args([
                "-I", "FORWARD", "-o", "lxcbr0",
                "-m", "state", "--state", "RELATED,ESTABLISHED",
                "-j", "ACCEPT",
            ])
            .output();
    }
}

/// Find the host-side veth name for a running LXC container, by
/// reading the container's `eth0`'s `iflink` from inside its netns and
/// mapping that ifindex back to a host interface. Returns None if the
/// container isn't running, has no eth0, or nsenter isn't available.
fn lxc_container_host_veth(container: &str) -> Option<String> {
    let base = lxc_base_dir(container);
    let mut args: Vec<String> = vec!["lxc-info".to_string()];
    if base != LXC_DEFAULT_PATH {
        args.push("-P".to_string());
        args.push(base.clone());
    }
    args.extend([
        "-n".to_string(),
        container.to_string(),
        "-p".to_string(),
        "-H".to_string(),
    ]);
    let pid: u32 = Command::new(&args[0])
        .args(&args[1..])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())?;
    if pid == 0 {
        return None;
    }

    let iflink: u32 = Command::new("nsenter")
        .args([
            "-t",
            &pid.to_string(),
            "-n",
            "cat",
            "/sys/class/net/eth0/iflink",
        ])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())?;
    if iflink == 0 {
        return None;
    }

    let link_out = Command::new("ip").args(["-o", "link", "show"]).output().ok()?;
    let s = String::from_utf8_lossy(&link_out.stdout);
    for line in s.lines() {
        // "56: vethABCDEF@if2: <BROADCAST,...> ..."
        let mut parts = line.splitn(2, ':');
        let idx_str = parts.next()?.trim();
        let name_part = parts.next()?.trim();
        if idx_str.parse::<u32>().ok() == Some(iflink) {
            let name = name_part.split('@').next()?.trim();
            return Some(name.to_string());
        }
    }
    None
}

/// For every running LXC container that's configured to live on
/// lxcbr0, find its host-side veth and re-master it if it's currently
/// orphaned (i.e. has no master). Called after we re-create lxcbr0 so
/// containers that survived the bridge being deleted come back online
/// without an operator restart.
fn lxc_remaster_orphan_veths() {
    for container in lxc_list_all() {
        if !container.state.eq_ignore_ascii_case("RUNNING") {
            continue;
        }
        // Only re-master containers whose config actually says lxcbr0.
        // A container with a vSwitch / public-NIC config doesn't belong
        // on lxcbr0 and we'd cause an outage by attaching its veth.
        let cfg_path = format!(
            "{}/{}/config",
            lxc_base_dir(&container.name),
            container.name
        );
        let uses_lxcbr0 = std::fs::read_to_string(&cfg_path)
            .map(|c| {
                c.lines().any(|l| {
                    let t = l.trim();
                    t.starts_with("lxc.net.")
                        && t.contains(".link")
                        && t.contains("lxcbr0")
                })
            })
            .unwrap_or(false);
        if !uses_lxcbr0 {
            continue;
        }

        let veth = match lxc_container_host_veth(&container.name) {
            Some(v) => v,
            None => {
                warn!(
                    "ensure_lxc_bridge: could not locate host-side veth \
                     for running container '{}' — operator may need to \
                     restart it manually",
                    container.name
                );
                continue;
            }
        };

        // If the veth already has a master, leave it alone — that
        // master might be a non-default bridge the operator chose.
        let master_path = format!("/sys/class/net/{}/master", veth);
        if std::fs::read_link(&master_path).is_ok() {
            continue;
        }

        match Command::new("ip")
            .args(["link", "set", &veth, "master", "lxcbr0"])
            .output()
        {
            Ok(o) if o.status.success() => {
                let _ = Command::new("ip")
                    .args(["link", "set", &veth, "up"])
                    .output();
                info!(
                    "ensure_lxc_bridge: re-attached orphan veth '{}' \
                     for container '{}' to lxcbr0",
                    veth, container.name
                );
            }
            Ok(o) => warn!(
                "ensure_lxc_bridge: ip link set {} master lxcbr0 \
                 failed: {}",
                veth,
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => warn!(
                "ensure_lxc_bridge: spawn `ip link set {} master \
                 lxcbr0`: {}",
                veth, e
            ),
        }
    }
}

/// Configure an LXC container's network to use WolfNet
pub fn lxc_attach_wolfnet(container: &str, ip: &str) -> Result<String, String> {


    // wolfnet0 is a TUN device — can't be bridged.
    // Instead, save the WolfNet IP as a marker; it will be applied inside the
    // container at start time via lxc-attach + host routing.
    let base = lxc_base_dir(container);
    let marker_dir = format!("{}/{}/.wolfnet", base, container);
    let _ = std::fs::create_dir_all(&marker_dir);
    if let Err(e) = std::fs::write(format!("{}/ip", marker_dir), ip) {
        return Err(format!("Failed to save WolfNet IP: {}", e));
    }

    // Ensure lxcbr0 bridge exists (needed for WolfNet routing)
    ensure_lxc_bridge();

    // Write bridge IP network config into the rootfs.
    // Standalone only — Proxmox manages eth0 on vmbr0 and we must NOT overwrite
    // its config. Proxmox wn0 config is written at runtime by lxc_apply_wolfnet.
    if !is_proxmox() {
        assign_container_bridge_ip(container);
    }

    // Ensure the LXC config has a NIC on lxcbr0.
    // Proxmox: add a separate wn0 NIC (eth0 stays on vmbr0 for external access).
    // Standalone LXC: eth0 is already on lxcbr0 (set by lxc_ensure_network_config),
    //   so we just make sure lxcbr0 is present — no separate wn0 needed.
    if !is_proxmox() {
        let config_path = format!("{}/{}/config", base, container);
        if let Ok(cfg) = std::fs::read_to_string(&config_path)
            && !cfg.contains("lxcbr0") {
                // Point the existing eth0 (net.0) to lxcbr0
                lxc_ensure_network_config(container);
            }
    }

    // If the container is already running, apply immediately (no restart needed)
    let mut info_args = vec!["-n", container, "-sH"];
    if base != LXC_DEFAULT_PATH {
        info_args = vec!["-P", &base, "-n", container, "-sH"];
    }
    let running = Command::new("lxc-info")
        .args(&info_args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_uppercase().contains("RUNNING"))
        .unwrap_or(false);

    if running {

        lxc_apply_wolfnet(container);
        Ok(format!("LXC container '{}' now using WolfNet IP {} (applied live)", container, ip))
    } else {
        Ok(format!("LXC container '{}' will use WolfNet IP {} on start", container, ip))
    }
}

/// Get the bridge IP assigned to a container's interface (e.g. wn0)
fn get_container_bridge_ip(container: &str, iface: &str) -> String {
    let base = lxc_base_dir(container);
    let mut args: Vec<&str> = Vec::new();
    if base != LXC_DEFAULT_PATH { args.extend_from_slice(&["-P", &base]); }
    args.extend_from_slice(&["-n", container, "--", "ip", "-4", "addr", "show", iface]);
    if let Ok(output) = Command::new("lxc-attach")
        .args(&args)
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse "inet 10.0.3.x/24" from ip addr output
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("inet ")
                && let Some(addr) = rest.split('/').next()
                    && addr.starts_with("10.0.3.") {
                        return addr.to_string();
                    }
        }
    }
    // Derive from WolfNet IP so the last octet matches (10.10.10.X → 10.0.3.X)
    let wolfnet_ip_file = format!("{}/{}/.wolfnet/ip", base, container);
    if let Ok(wolfnet_ip) = std::fs::read_to_string(&wolfnet_ip_file) {
        let wolfnet_ip = wolfnet_ip.trim();
        if let Some(last_octet) = wolfnet_ip.rsplit('.').next() {
            return format!("10.0.3.{}", last_octet);
        }
    }
    // Last resort: assign a fresh bridge IP
    warn!("Could not detect bridge IP for {}:{}, assigning new one", container, iface);
    let last = find_free_bridge_ip();
    format!("10.0.3.{}", last)
}

/// Re-apply host routes for all running LXC containers with WolfNet IPs.
/// Called on WolfStack startup to restore routes that were lost since
/// `lxc_apply_wolfnet` only runs at container start time.
pub fn reapply_wolfnet_routes() {
    for base_path in lxc_storage_paths() {
        let lxc_base = std::path::Path::new(&base_path);
        let entries = match std::fs::read_dir(lxc_base) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let container = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Check if this container has a WolfNet IP
            let ip_file = entry.path().join(".wolfnet/ip");
            let _ip = match std::fs::read_to_string(&ip_file) {
                Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
                _ => continue,
            };

            // Check if the container is actually running
            let mut info_args = vec!["5".to_string(), "lxc-info".to_string(), "-n".to_string(), container.clone(), "-sH".to_string()];
            if base_path != LXC_DEFAULT_PATH {
                info_args = vec!["5".to_string(), "lxc-info".to_string(), "-P".to_string(), base_path.clone(), "-n".to_string(), container.clone(), "-sH".to_string()];
            }
            let running = Command::new("timeout")
                .args(&info_args)
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_uppercase().contains("RUNNING"))
                .unwrap_or(false);
            if !running { continue; }

            // Re-apply the WolfNet IP and routes INSIDE the container.
            lxc_apply_wolfnet(&container);
        }
    }

    // Ensure per-interface forwarding is on
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.wolfnet0.forwarding=1"]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.lxcbr0.forwarding=1"]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.wolfnet0.send_redirects=0"]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.lxcbr0.send_redirects=0"]).output();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.lxcbr0.proxy_arp=1"]).output();
}

/// True when the container has a NIC — other than the lxcbr0/WolfNet
/// `eth0` — that carries its own IPv4 gateway (a vSwitch or routed-
/// public NIC). Such a container must keep THAT NIC's gateway as its
/// default route: WolfNet's lxcbr0 path is a NAT fallback and must not
/// hijack a container that already has its own way out.
fn lxc_has_external_gateway(container: &str) -> bool {
    let path = format!("{}/{}/config", lxc_base_dir(container), container);
    let cfg = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    // Pair each NIC index with its bridge link and whether it carries a
    // non-empty ipv4.gateway, then flag any gateway NIC not on lxcbr0.
    let mut links: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    let mut gw_idxs: Vec<&str> = Vec::new();
    for line in cfg.lines() {
        let rest = match line.trim().strip_prefix("lxc.net.") {
            Some(r) => r,
            None => continue,
        };
        // rest is e.g. "1.link = vmbr4000" or "1.ipv4.gateway = 1.2.3.4"
        let (idx, key_val) = match rest.split_once('.') {
            Some(p) => p,
            None => continue,
        };
        let (key, value) = match key_val.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };
        if key == "link" {
            links.insert(idx, value);
        } else if key == "ipv4.gateway" && !value.is_empty() {
            gw_idxs.push(idx);
        }
    }
    gw_idxs.iter().any(|idx| links.get(idx).copied() != Some("lxcbr0"))
}

/// The container's primary NIC bridge — the value of `lxc.net.0.link` in its
/// LXC config — or None if not set / unreadable.
fn lxc_primary_bridge(container: &str) -> Option<String> {
    let cfg = format!("{}/{}/config", lxc_base_dir(container), container);
    let content = std::fs::read_to_string(&cfg).ok()?;
    content
        .lines()
        .find(|l| l.trim().starts_with("lxc.net.0.link"))
        .and_then(|l| l.split('=').nth(1))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Extract the host bridge an LXC's primary NIC is attached to, cross-platform:
/// native LXC keys it as `lxc.net.0.link = brX`; Proxmox as `net0: …,bridge=vmbrX`
/// in `/etc/pve/lxc/<vmid>.conf`. `name` is the native container name OR the PVE
/// vmid (lxc_list_all sets name==vmid for Proxmox). Trying both is safe — the
/// config for the wrong platform simply doesn't exist → None.
fn lxc_primary_bridge_any(name: &str) -> Option<String> {
    if let Some(b) = lxc_primary_bridge(name) {
        return Some(b);
    }
    let cfg = std::fs::read_to_string(format!("/etc/pve/lxc/{}.conf", name)).ok()?;
    bridge_from_pve_net0(&cfg)
}

/// Extract the first usable bare IP from an LXC `ip_address` field, which can
/// hold forms `ip route` rejects: multi-homed (`"a, b"`), a CIDR suffix
/// (`"10.0.0.5/24"`), or a `" (wolfnet)"` annotation. Returns the canonical bare
/// address, or None when the first token isn't a valid IP.
fn first_reportable_ip(raw: &str) -> Option<String> {
    let first = raw.split(',').next()?.trim();
    let token = first.split_whitespace().next()?; // drop trailing " (wolfnet)"
    let addr = token.split('/').next()?; // drop any CIDR suffix
    addr.parse::<std::net::IpAddr>().ok().map(|a| a.to_string())
}

/// Pick ONE address other hosts can reach from a multi-homed `ip_address`
/// field — the string a container reports when it has several NICs (the
/// lxcbr0 bridge + a LAN/vSwitch NIC + a WolfNet overlay NIC), e.g.
/// `"10.0.10.111, 10.0.3.3, 10.10.10.3"`. Tokens may carry a CIDR suffix
/// and/or a `" (wolfnet)"` annotation, both produced by the LXC listers in
/// this module.
///
/// Preference order:
/// 1. `prefer` (the container's WolfNet marker IP, when the caller has it)
///    if it is actually among the live addresses — the overlay is the
///    cross-host fabric WolfStack itself manages;
/// 2. a token annotated `(wolfnet)` by the lister;
/// 3. the first address that is not host-local — loopback, link-local, or
///    the lxcbr0 bridge 10.0.3.0/24, which only this host can route;
/// 4. the first address at all (better a candidate the operator can see
///    stored than rejecting the whole list).
///
/// None only when the string contains no parseable IP (e.g. a bare
/// hostname) — callers fall back to the raw value then.
pub fn pick_cross_host_ip(raw: &str, prefer: Option<&str>) -> Option<String> {
    struct Cand {
        ip: std::net::IpAddr,
        wolfnet_tagged: bool,
    }
    let mut cands: Vec<Cand> = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let tagged = part.contains("(wolfnet)");
        // First whitespace token drops the annotation; strip any CIDR.
        let Some(token) = part.split_whitespace().next() else { continue };
        let addr = token.split('/').next().unwrap_or("");
        if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
            cands.push(Cand { ip, wolfnet_tagged: tagged });
        }
    }
    if let Some(w) = prefer
        && let Ok(want) = w.trim().parse::<std::net::IpAddr>()
        && cands.iter().any(|c| c.ip == want)
    {
        return Some(want.to_string());
    }
    if let Some(c) = cands.iter().find(|c| c.wolfnet_tagged) {
        return Some(c.ip.to_string());
    }
    let host_local = |ip: &std::net::IpAddr| -> bool {
        match ip {
            std::net::IpAddr::V4(v) => {
                let o = v.octets();
                v.is_loopback()
                    || v.is_link_local()
                    // lxcbr0 bridge — routable only from the container's own
                    // host (same range wolfscale::pick_usable_address excludes).
                    || (o[0] == 10 && o[1] == 0 && o[2] == 3)
            }
            std::net::IpAddr::V6(v) => {
                // fe80::/10 link-local (is_unicast_link_local is unstable).
                v.is_loopback() || (v.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    };
    cands
        .iter()
        .find(|c| !host_local(&c.ip))
        .or_else(|| cands.first())
        .map(|c| c.ip.to_string())
}

/// Parse the `bridge=` value out of a Proxmox container's `net0:` line.
fn bridge_from_pve_net0(config: &str) -> Option<String> {
    for line in config.lines() {
        if let Some(rest) = line.trim().strip_prefix("net0:") {
            for part in rest.split(',') {
                if let Some(b) = part.trim().strip_prefix("bridge=") {
                    let b = b.trim();
                    if !b.is_empty() { return Some(b.to_string()); }
                }
            }
        }
    }
    None
}

/// A running container whose traffic bypasses the host's netfilter FORWARD
/// chain — a Docker macvlan/ipvlan network or a native-LXC macvlan/ipvlan NIC.
/// Carries the init PID needed to enter the container's network namespace via
/// `nsenter --net`. The host-side `kernel_block_ip` DROP in FORWARD never sees
/// these containers' packets (kernel bypass by design), so a security block has
/// to be mirrored INSIDE their namespace — see `auth::reconcile_macvlan_blocks`.
pub struct NetnsTarget {
    /// Human label for logs, e.g. `docker:web01` / `lxc:db1`.
    pub label: String,
    /// Host-side PID of the container's init, for `nsenter --target`.
    pub pid: i32,
}

/// Enumerate running macvlan/ipvlan containers (Docker + native LXC) whose
/// traffic bypasses the host FORWARD chain. Returns an empty Vec — cheaply —
/// when the container tools are absent or none are configured that way, so a
/// host with everything on standard bridges pays only one `docker network ls`.
pub fn macvlan_netns_targets() -> Vec<NetnsTarget> {
    let mut out = docker_macvlan_netns_targets();
    out.extend(native_lxc_macvlan_netns_targets());
    out
}

/// Docker containers attached to a macvlan/ipvlan network, with their PIDs.
fn docker_macvlan_netns_targets() -> Vec<NetnsTarget> {
    let mut targets = Vec::new();
    // Same-key filters are OR'd, so this returns every macvlan OR ipvlan net.
    // 10s cap — a wedged dockerd hung this loop's task forever (masterpier's
    // athena, 2026-07-03).
    let nets = match Command::new("timeout")
        .args([
            "10", "docker", "network", "ls", "--filter", "driver=macvlan",
            "--filter", "driver=ipvlan", "--format", "{{.Name}}",
        ])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return targets, // docker absent/errored — nothing to mirror into
    };
    let mut seen_pids = std::collections::HashSet::new();
    for net in String::from_utf8_lossy(&nets.stdout)
        .lines()
        .map(str::trim)
        .filter(|n| !n.is_empty())
    {
        // `.Containers` is a map keyed by container ID.
        let insp = match Command::new("docker")
            .args([
                "network", "inspect", net, "--format",
                "{{range $id, $c := .Containers}}{{$id}}\n{{end}}",
            ])
            .output()
        {
            Ok(o) if o.status.success() => o,
            _ => continue,
        };
        for cid in String::from_utf8_lossy(&insp.stdout)
            .lines()
            .map(str::trim)
            .filter(|c| !c.is_empty())
        {
            let det = match Command::new("docker")
                .args(["inspect", "--format", "{{.State.Running}}|{{.State.Pid}}|{{.Name}}", cid])
                .output()
            {
                Ok(o) if o.status.success() => o,
                _ => continue,
            };
            let txt = String::from_utf8_lossy(&det.stdout);
            let parts: Vec<&str> = txt.trim().split('|').collect();
            if parts.len() < 2 || parts[0].trim() != "true" {
                continue; // not running
            }
            let pid: i32 = match parts[1].trim().parse() {
                Ok(p) if p > 0 => p,
                _ => continue,
            };
            if !seen_pids.insert(pid) {
                continue; // same container on >1 macvlan network
            }
            let name = parts
                .get(2)
                .map(|s| s.trim().trim_start_matches('/'))
                .filter(|s| !s.is_empty())
                .unwrap_or(cid);
            targets.push(NetnsTarget { label: format!("docker:{}", name), pid });
        }
    }
    targets
}

/// Native-LXC containers whose primary NIC is macvlan/ipvlan, with their PIDs.
/// Proxmox CTs always use veth (the host FORWARD chain covers them), so this is
/// a no-op on a Proxmox host.
fn native_lxc_macvlan_netns_targets() -> Vec<NetnsTarget> {
    let mut targets = Vec::new();
    if Command::new("which").arg("pct").output().map(|o| o.status.success()).unwrap_or(false) {
        return targets;
    }
    let mut seen = std::collections::HashSet::new();
    for base in lxc_storage_paths() {
        let dir = match std::fs::read_dir(&base) {
            Ok(d) => d,
            Err(_) => continue,
        };
        for de in dir.flatten() {
            let name = de.file_name().to_string_lossy().to_string();
            if name.is_empty() || !seen.insert(name.clone()) {
                continue;
            }
            let cfg = match std::fs::read_to_string(format!("{}/{}/config", base, name)) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if !lxc_config_is_macvlan_or_ipvlan(&cfg) {
                continue;
            }
            // -pH = bare PID, no field label. A stopped container has no PID
            // (lxc-info prints "-1" or nothing) → parse fails → skip.
            let pid = Command::new("lxc-info")
                .args(["-P", &base, "-n", &name, "-pH"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<i32>().ok())
                .unwrap_or(-1);
            if pid <= 0 {
                continue;
            }
            targets.push(NetnsTarget { label: format!("lxc:{}", name), pid });
        }
    }
    targets
}

/// True if any `lxc.net.<n>.type` in a native-LXC config is macvlan or ipvlan
/// (the default is `veth`, which rides the host bridge and IS firewalled).
fn lxc_config_is_macvlan_or_ipvlan(cfg: &str) -> bool {
    for line in cfg.lines() {
        let Some(rest) = line.trim().strip_prefix("lxc.net.") else { continue };
        // rest e.g. "0.type = macvlan"
        let Some((_idx, kv)) = rest.split_once('.') else { continue };
        let Some((key, val)) = kv.split_once('=') else { continue };
        if key.trim() == "type" {
            let v = val.trim();
            if v == "macvlan" || v == "ipvlan" {
                return true;
            }
        }
    }
    false
}

/// Whether to SKIP the standalone (lxcbr0-based, eth0-flushing) WolfNet reapply
/// for a container, based on its primary NIC bridge. We skip ONLY when the
/// primary is a KNOWN, non-lxcbr0 bridge (a manual / migrated layout) — flushing
/// eth0 there would destroy the operator's addressing. `lxcbr0` (the WolfStack
/// default, used by every standard cluster) and `None` (unknown) both proceed
/// unchanged, so existing installs see byte-identical behaviour.
fn skip_standalone_wolfnet(primary_bridge: Option<&str>) -> bool {
    matches!(primary_bridge, Some(b) if b != "lxcbr0")
}

/// Apply WolfNet IP inside a running container (called after lxc-start)
fn lxc_apply_wolfnet(container: &str) {
    let base = lxc_base_dir(container);
    let ip_file = format!("{}/{}/.wolfnet/ip", base, container);
    if let Ok(ip) = std::fs::read_to_string(&ip_file) {
        let ip = ip.trim();
        if ip.is_empty() { return; }

        // Build lxc-attach prefix with -P if on non-default storage
        let attach_prefix: Vec<String> = if base != LXC_DEFAULT_PATH {
            vec!["-P".to_string(), base.clone(), "-n".to_string(), container.to_string(), "--".to_string()]
        } else {
            vec!["-n".to_string(), container.to_string(), "--".to_string()]
        };

        // Wait for container to be ready
        std::thread::sleep(std::time::Duration::from_secs(2));

        // On Proxmox, WolfNet uses wn0 on lxcbr0 (eth0 stays on vmbr0).
        // On standalone LXC, WolfNet uses a secondary IP on eth0 via lxcbr0.
        let is_pve = is_proxmox();
        let _wolfnet_iface = if is_pve { "wn0" } else { "eth0" };

        // The WolfNet network (real prefix length; see wolfnet_network)
        let wn_subnet = wolfnet_cidr_for(ip);

        if is_pve {
            // Proxmox: wn0 is on lxcbr0 with NO IP/gateway in pct config.
            // We assign a 10.0.3.x bridge IP for host routing and the WolfNet IP
            // as a secondary /32. No gateway is set on wn0, so eth0's default
            // route via vmbr0 stays intact.
            let bridge_ip = get_container_bridge_ip(container, "wn0");

            let bridge_cidr = format!("{}/24", bridge_ip);
            let wolfnet_cidr = format!("{}/32", ip);

            // Write persistent wn0 config for NetworkManager-based distros (Fedora, AlmaLinux, Rocky).
            // Without this, NM auto-manages wn0 with DHCP and overrides our manual IP assignments.
            // No gateway/DNS on wn0 — those stay on eth0 (vmbr0).
            let nm_cmd = format!(
                "if [ -d /etc/NetworkManager ]; then \
                     mkdir -p /etc/NetworkManager/system-connections && \
                     printf '[connection]\\nid=wn0\\ntype=ethernet\\ninterface-name=wn0\\nautoconnect=true\\n\\n\
[ipv4]\\nmethod=manual\\naddress1={}/24\\naddress2={}/32\\nroute1={},10.0.3.1\\nroute1_options=src={}\\n\\n\
[ipv6]\\nmethod=disabled\\n' \
                     > /etc/NetworkManager/system-connections/wn0.nmconnection && \
                     chmod 600 /etc/NetworkManager/system-connections/wn0.nmconnection && \
                     nmcli con reload 2>/dev/null && \
                     nmcli con up wn0 2>/dev/null; \
                 fi; true",
                bridge_ip, ip, wn_subnet, ip
            );
            let mut nm_args: Vec<String> = attach_prefix.clone();
            nm_args.extend(["sh", "-c", &nm_cmd].iter().map(|s| s.to_string()));
            let _ = Command::new("lxc-attach").args(&nm_args).output();

            // Bring wn0 up (fallback for non-NM distros; idempotent if NM already brought it up)
            let mut args: Vec<String> = attach_prefix.clone();
            args.extend(["ip", "link", "set", "wn0", "up"].iter().map(|s| s.to_string()));
            let _ = Command::new("lxc-attach").args(&args).output();

            // Assign bridge IP on wn0 for host-side routing (idempotent — addr add ignores dups)
            let mut args: Vec<String> = attach_prefix.clone();
            args.extend(["ip", "addr", "add", &bridge_cidr, "dev", "wn0"].iter().map(|s| s.to_string()));
            let _ = Command::new("lxc-attach").args(&args).output();

            // Add WolfNet IP as secondary /32 on wn0
            let mut args: Vec<String> = attach_prefix.clone();
            args.extend(["ip", "addr", "add", &wolfnet_cidr, "dev", "wn0"].iter().map(|s| s.to_string()));
            let _ = Command::new("lxc-attach").args(&args).output();

            // Route WolfNet subnet through wn0 via lxcbr0 gateway — without this,
            // WolfNet traffic goes out via eth0/vmbr0 where WolfNet is unreachable.
            // The `src` hint ensures the kernel uses the WolfNet IP as source, not the
            // bridge IP — critical for cross-node connectivity (remote hosts reply to the
            // WolfNet IP, which gets routed back through the overlay).
            let mut args: Vec<String> = attach_prefix.clone();
            args.extend(["ip", "route", "replace", &wn_subnet, "via", "10.0.3.1", "dev", "wn0", "src", ip].iter().map(|s| s.to_string()));
            let _ = Command::new("lxc-attach").args(&args).output();

            // Try to bring up eth0 via NetworkManager (write DHCP config if missing)
            let eth0_nm_cmd = "if [ -d /etc/NetworkManager ]; then \
                if [ ! -f /etc/NetworkManager/system-connections/eth0.nmconnection ]; then \
                    printf '[connection]\\nid=eth0\\ntype=ethernet\\ninterface-name=eth0\\nautoconnect=true\\n\\n\
[ipv4]\\nmethod=auto\\ndns=8.8.8.8;1.1.1.1;\\n\\n[ipv6]\\nmethod=auto\\n' \
                    > /etc/NetworkManager/system-connections/eth0.nmconnection && \
                    chmod 600 /etc/NetworkManager/system-connections/eth0.nmconnection; \
                fi; \
                nmcli con reload 2>/dev/null; \
                nmcli con up eth0 2>/dev/null; \
            fi; true";
            let mut eth0_args: Vec<String> = attach_prefix.clone();
            eth0_args.extend(["sh", "-c", eth0_nm_cmd].iter().map(|s| s.to_string()));
            let _ = Command::new("lxc-attach").args(&eth0_args).output();

            // Give DHCP a moment to acquire a lease on eth0
            std::thread::sleep(std::time::Duration::from_secs(3));

            // Check if eth0 got a default route. If not (no DHCP server on vmbr0),
            // fall back to routing internet through wn0/lxcbr0 which has NAT — just
            // like standalone LXC containers work.
            let mut chk_args: Vec<String> = attach_prefix.clone();
            chk_args.extend(["ip", "route", "show", "default"].iter().map(|s| s.to_string()));
            let has_default = Command::new("lxc-attach").args(&chk_args).output()
                .map(|o| {
                    let out = String::from_utf8_lossy(&o.stdout);
                    !out.trim().is_empty()
                })
                .unwrap_or(false);

            if !has_default {
                // No default route from eth0 DHCP — route internet through lxcbr0
                let mut args: Vec<String> = attach_prefix.clone();
                args.extend(["ip", "route", "replace", "default", "via", "10.0.3.1", "dev", "wn0"].iter().map(|s| s.to_string()));
                let _ = Command::new("lxc-attach").args(&args).output();

                // Write DNS so name resolution works
                let dns_cmd = "rm -f /etc/resolv.conf; \
                    printf 'nameserver 8.8.8.8\\nnameserver 1.1.1.1\\n' > /etc/resolv.conf";
                let mut dns_args: Vec<String> = attach_prefix.clone();
                dns_args.extend(["sh", "-c", dns_cmd].iter().map(|s| s.to_string()));
                let _ = Command::new("lxc-attach").args(&dns_args).output();
            }

            // Host route — via bridge IP so traffic for WolfNet IP reaches container
            let _ = Command::new("ip").args(["route", "del", &format!("{}/32", ip)]).output();
            let out = Command::new("ip")
                .args(["route", "add", &format!("{}/32", ip), "via", &bridge_ip, "dev", "lxcbr0"])
                .output();
            if let Ok(ref o) = out {
                if o.status.success() {

                } else {
                    error!("Host route failed: {}", String::from_utf8_lossy(&o.stderr));
                }
            }
        } else {
            // GOLDEN-RULE GATE: the standalone WolfNet path assumes eth0 is on
            // lxcbr0 (the WolfStack default) and FLUSHES eth0 to reassign it.
            // If the operator has put the container's primary NIC on a DIFFERENT
            // bridge (a manual / migrated layout — e.g. a Hetzner vSwitch
            // vmbrXXXX on 10.0.10.x), flushing eth0 would destroy their
            // addressing on every restart. Skip in that case — WolfNet-over-
            // lxcbr0 doesn't apply to a non-lxcbr0 primary anyway. lxcbr0 (the
            // default, used by every standard cluster) and "unknown" both
            // proceed UNCHANGED, so existing installs are unaffected.
            if skip_standalone_wolfnet(lxc_primary_bridge(container).as_deref()) {
                warn!(
                    "LXC '{}': skipping WolfNet reapply — primary NIC is on '{}', not lxcbr0; \
                     leaving its networking untouched (manage WolfNet manually for \
                     custom-bridge containers)",
                    container,
                    lxc_primary_bridge(container).unwrap_or_default()
                );
                return;
            }
            // Standalone LXC: original approach — bridge IP on eth0, WolfNet IP as secondary
            let bridge_ip = assign_container_bridge_ip(container);

            let bridge_cidr = format!("{}/24", bridge_ip);
            let wolfnet_cidr = format!("{}/32", ip);

            // 1. Write network config files FIRST (assign_container_bridge_ip already did this)
            //    so the restart below picks up the correct IP.

            // 2. Restart networking (try all methods for distro compat)
            let mut args: Vec<String> = attach_prefix.clone();
            args.extend(["sh", "-c",
                "nmcli con reload 2>/dev/null && nmcli con up eth0 2>/dev/null; \
                 systemctl restart systemd-networkd 2>/dev/null; \
                 netplan apply 2>/dev/null; \
                 /etc/init.d/networking restart 2>/dev/null; \
                 true"].iter().map(|s| s.to_string()));
            let _ = Command::new("lxc-attach").args(&args).output();

            // 3. Flush ALL addresses on eth0 to clear stale IPs from DHCP, NetworkManager,
            //    or old configs. Then re-add exactly the ones we want.
            //    Also tell NetworkManager to not manage eth0 temporarily so it
            //    doesn't override our manual IP assignments.
            let mut args: Vec<String> = attach_prefix.clone();
            args.extend(["sh", "-c",
                "nmcli dev set eth0 managed no 2>/dev/null; \
                 ip addr flush dev eth0"].iter().map(|s| s.to_string()));
            let _ = Command::new("lxc-attach").args(&args).output();

            // 4. Add bridge IP + wolfnet IP + default route
            let mut args: Vec<String> = attach_prefix.clone();
            args.extend(["ip", "addr", "add", &bridge_cidr, "dev", "eth0"].iter().map(|s| s.to_string()));
            let _ = Command::new("lxc-attach").args(&args).output();

            let mut args: Vec<String> = attach_prefix.clone();
            args.extend(["ip", "addr", "add", &wolfnet_cidr, "dev", "eth0"].iter().map(|s| s.to_string()));
            let _ = Command::new("lxc-attach").args(&args).output();

            // Default route via lxcbr0 — but ONLY when the container has
            // no other way out. A container with a vSwitch / routed-public
            // NIC has its own gateway (set by LXC from lxc.net.N.ipv4.
            // gateway); replacing the default here would hijack it and
            // black-hole the public IP. WolfNet still gets its subnet
            // route below — it just stops owning the default.
            if !lxc_has_external_gateway(container) {
                let mut args: Vec<String> = attach_prefix.clone();
                args.extend(["ip", "route", "replace", "default", "via", "10.0.3.1"].iter().map(|s| s.to_string()));
                let _ = Command::new("lxc-attach").args(&args).output();
            }

            // Route WolfNet subnet with correct source IP — ensures the container
            // uses its WolfNet IP (not the bridge IP) as source when talking to
            // remote WolfNet hosts, so replies get routed back correctly.
            let mut args: Vec<String> = attach_prefix.clone();
            args.extend(["ip", "route", "replace", &wn_subnet, "via", "10.0.3.1", "src", ip].iter().map(|s| s.to_string()));
            let _ = Command::new("lxc-attach").args(&args).output();

            // Host route — via bridge IP so ARP resolves on lxcbr0
            let _ = Command::new("ip").args(["route", "del", &format!("{}/32", ip)]).output();
            let out = Command::new("ip")
                .args(["route", "add", &format!("{}/32", ip), "via", &bridge_ip, "dev", "lxcbr0"])
                .output();
            if let Ok(ref o) = out {
                if o.status.success() {

                } else {
                    error!("Host route failed: {}", String::from_utf8_lossy(&o.stderr));
                }
            }
        }

        // Forwarding + iptables (common to both paths)
        let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.wolfnet0.forwarding=1"]).output();
        let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.lxcbr0.forwarding=1"]).output();
        let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.wolfnet0.send_redirects=0"]).output();
        let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.lxcbr0.send_redirects=0"]).output();
        let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.lxcbr0.proxy_arp=1"]).output();
        let check = Command::new("iptables")
            .args(["-C", "FORWARD", "-i", "wolfnet0", "-o", "lxcbr0", "-j", "ACCEPT"]).output();
        if check.map(|o| !o.status.success()).unwrap_or(true) {
            let _ = Command::new("iptables").args(["-I", "FORWARD", "-i", "wolfnet0", "-o", "lxcbr0", "-j", "ACCEPT"]).output();
            let _ = Command::new("iptables").args(["-I", "FORWARD", "-i", "lxcbr0", "-o", "wolfnet0", "-j", "ACCEPT"]).output();
        }

        // On Fedora/RHEL/AlmaLinux containers, firewalld blocks inbound WolfNet
        // traffic by default. Add the WolfNet interface to the trusted zone inside
        // the container so other nodes can reach services running here.
        let wn_iface = if is_pve { "wn0" } else { "eth0" };
        let fw_cmd = format!(
            "if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then \
                 firewall-cmd --permanent --zone=trusted --add-interface={} 2>/dev/null; \
                 firewall-cmd --reload 2>/dev/null; \
             fi; true", wn_iface
        );
        let mut fw_args: Vec<String> = attach_prefix.clone();
        fw_args.extend(["sh", "-c", &fw_cmd].iter().map(|s| s.to_string()));
        let _ = Command::new("lxc-attach").args(&fw_args).output();
    }
}

/// Tear down a WolfNet IP binding inside an LXC container — the inverse of
/// [`lxc_apply_wolfnet`]. Called when the WolfNet IP is cleared (e.g. switching
/// a container to bridge/nat mode). Removing the stored `.wolfnet/ip` marker and
/// the `wn0` NIC from the pct config is NOT enough: the address lives on inside
/// the container (a live `ip addr` plus a persistent NetworkManager keyfile /
/// rootfs network config), so without this the WolfNet IP is re-bound on the
/// next start — exactly the symptom Gary (KO4BSR) reported on v24.51.2.
///
/// Mirrors the bind path's platform split: Proxmox uses `wn0` (its own NM
/// keyfile), standalone LXC uses a secondary /32 on `eth0` persisted in the
/// rootfs network config. Both the live binding and the persistent config are
/// cleared, and the now-dead host route to the container's WolfNet IP is
/// removed. Every step is best-effort and idempotent so a stopped or
/// partly-configured container is safe.
fn lxc_remove_wolfnet(container: &str, old_ip: &str) {
    let old_ip = old_ip.trim();
    if old_ip.is_empty() { return; }

    let base = lxc_base_dir(container);
    let attach_prefix: Vec<String> = if base != LXC_DEFAULT_PATH {
        vec!["-P".to_string(), base.clone(), "-n".to_string(), container.to_string(), "--".to_string()]
    } else {
        vec!["-n".to_string(), container.to_string(), "--".to_string()]
    };
    let running = lxc_is_running(container);
    let wolfnet_cidr = format!("{}/32", old_ip);

    if is_proxmox() {
        // Proxmox: the WolfNet IP lives on wn0, persisted in a NetworkManager
        // keyfile (id=wn0). The caller removes the wn0 NIC from the pct config,
        // so once stopped there is no wn0 for the IP to re-bind to. While the
        // container is running we must also bring the NM connection down, delete
        // its keyfile, and remove the live address so the IP is gone immediately
        // rather than lingering until the next restart.
        if running {
            let cmd = format!(
                "nmcli con down wn0 2>/dev/null; nmcli con delete wn0 2>/dev/null; \
                 rm -f /etc/NetworkManager/system-connections/wn0.nmconnection; \
                 nmcli con reload 2>/dev/null; \
                 ip addr del {} dev wn0 2>/dev/null; true",
                wolfnet_cidr
            );
            let mut args: Vec<String> = attach_prefix.clone();
            args.extend(["sh", "-c", &cmd].iter().map(|s| s.to_string()));
            let _ = Command::new("lxc-attach").args(&args).output();
        }
    } else {
        // Standalone LXC: the WolfNet IP is a secondary /32 on eth0, persisted in
        // the rootfs network config. Rewrite that config WITHOUT the WolfNet IP
        // (keeping the 10.0.3.x bridge IP so host routing / connectivity
        // survives), then — if running — drop the live address and the
        // source-pinned WolfNet subnet route and re-apply the rewritten config so
        // NetworkManager / networkd don't immediately put the address back.
        // Derive the SAME bridge IP assign_container_bridge_ip wrote (last octet
        // of the WolfNet IP). Only rewrite when we can derive a valid octet — a
        // malformed marker must not make us guess a wrong bridge IP and break
        // connectivity; in that case we skip the rewrite and rely on the live
        // unbind below.
        if let Some(bridge_ip) = old_ip.rsplit('.').next()
            .filter(|o| o.parse::<u8>().is_ok())
            .map(|o| format!("10.0.3.{}", o)) {
            write_container_network_config(container, &bridge_ip, None);
        }

        if running {
            let mut cmd = format!("ip addr del {} dev eth0 2>/dev/null; ", wolfnet_cidr);
            if let Some(subnet) = wolfnet_subnet_from_ip(old_ip) {
                cmd.push_str(&format!("ip route del {} 2>/dev/null; ", subnet));
            }
            // Re-apply the rewritten config across renderers: NM (reload+up) and
            // systemd-networkd (reload re-reads the .network file, reconfigure
            // re-applies it to eth0 so the secondary address is dropped live).
            cmd.push_str("nmcli con reload 2>/dev/null && nmcli con up eth0 2>/dev/null; \
                          networkctl reload 2>/dev/null; networkctl reconfigure eth0 2>/dev/null; true");
            let mut args: Vec<String> = attach_prefix.clone();
            args.extend(["sh", "-c", &cmd].iter().map(|s| s.to_string()));
            let _ = Command::new("lxc-attach").args(&args).output();
        }
    }

    // The host route to the container's WolfNet IP is no longer valid.
    let _ = Command::new("ip").args(["route", "del", &wolfnet_cidr]).output();
}

/// Find a free IP in 10.0.3.100-254 by checking ALL containers, LXCs, VMs, Docker
fn find_free_bridge_ip() -> u8 {
    let mut used: Vec<u8> = Vec::new();

    // 1. Scan LXC config files (covers stopped containers too)
    for lxc_scan_path in lxc_storage_paths() {
    if let Ok(entries) = std::fs::read_dir(&lxc_scan_path) {
        for entry in entries.flatten() {
            // systemd-networkd
            let net_file = entry.path().join("rootfs/etc/systemd/network/eth0.network");
            if let Ok(content) = std::fs::read_to_string(&net_file) {
                for line in content.lines() {
                    if let Some(addr) = line.strip_prefix("Address=10.0.3.")
                        && let Some(last) = addr.split('/').next().and_then(|s| s.parse::<u8>().ok()) {
                            used.push(last);
                        }
                }
            }
            // Netplan
            let netplan_file = entry.path().join("rootfs/etc/netplan/50-wolfstack.yaml");
            if let Ok(content) = std::fs::read_to_string(&netplan_file) {
                for line in content.lines() {
                    let trimmed = line.trim().trim_start_matches("- ");
                    if let Some(addr) = trimmed.strip_prefix("10.0.3.")
                        && let Some(last) = addr.split('/').next().and_then(|s| s.parse::<u8>().ok()) {
                            used.push(last);
                        }
                }
            }
            // /etc/network/interfaces
            let ifaces_file = entry.path().join("rootfs/etc/network/interfaces");
            if let Ok(content) = std::fs::read_to_string(&ifaces_file) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("address 10.0.3.")
                        && let Some(addr) = trimmed.strip_prefix("address 10.0.3.")
                            && let Ok(last) = addr.trim().parse::<u8>() {
                                used.push(last);
                            }
                }
            }
        }
    }
    } // end for lxc_scan_path

    // 2. Scan running LXC containers' actual IPs
    for c in lxc_list_all() {
        for ip_str in c.ip_address.split(',') {
            let ip = ip_str.trim().replace(" (lxcbr0)", "").replace(" (eth0)", "");
            if let Some(last) = ip.strip_prefix("10.0.3.")
                && let Ok(n) = last.trim().parse::<u8>() {
                    used.push(n);
                }
        }
    }

    // 3. Scan Docker containers' IPs
    for c in docker_list_all() {
        for ip_str in c.ip_address.split(',') {
            let ip = ip_str.trim();
            if let Some(last) = ip.strip_prefix("10.0.3.")
                && let Ok(n) = last.trim().parse::<u8>() {
                    used.push(n);
                }
        }
    }

    // 4. GLOBAL: Scan cluster container cache (all remote nodes' containers)
    //    The heartbeat sync writes container data to /etc/wolfstack/cluster-containers/
    if let Ok(entries) = std::fs::read_dir(&crate::paths::get().cluster_containers_dir) {
        for entry in entries.flatten() {
            if let Ok(content) = std::fs::read_to_string(entry.path())
                && let Ok(containers) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
                    for c in &containers {
                        if let Some(ips) = c.get("ip_address").and_then(|v| v.as_str()) {
                            for ip_str in ips.split(',') {
                                let ip = ip_str.trim()
                                    .replace(" (lxcbr0)", "").replace(" (eth0)", "");
                                if let Some(last) = ip.strip_prefix("10.0.3.")
                                    && let Ok(n) = last.trim().parse::<u8>() {
                                        used.push(n);
                                    }
                            }
                        }
                    }
                }
        }
    }

    // 5. GLOBAL: Scan WolfRun services for all instance IPs across the cluster
    if let Ok(content) = std::fs::read_to_string(&crate::paths::get().wolfrun_services)
        && let Ok(services) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
            for svc in &services {
                if let Some(instances) = svc.get("instances").and_then(|v| v.as_array()) {
                    for inst in instances {
                        // Check bridge_ip field if tracked
                        if let Some(ip) = inst.get("bridge_ip").and_then(|v| v.as_str())
                            && let Some(last) = ip.strip_prefix("10.0.3.")
                                && let Ok(n) = last.trim().parse::<u8>() {
                                    used.push(n);
                                }
                    }
                }
            }
        }

    // 6. GLOBAL: Scan IP mappings (port forward destinations may use bridge IPs)
    if let Ok(content) = std::fs::read_to_string(&crate::paths::get().ip_mappings)
        && let Ok(wrapper) = serde_json::from_str::<serde_json::Value>(&content)
            && let Some(mappings) = wrapper.get("mappings").and_then(|v| v.as_array()) {
                for m in mappings {
                    // Check all IP fields for bridge IPs
                    for key in &["container_ip", "bridge_ip", "ip"] {
                        if let Some(ip) = m.get(*key).and_then(|v| v.as_str())
                            && let Some(last) = ip.strip_prefix("10.0.3.")
                                && let Ok(n) = last.trim().parse::<u8>() {
                                    used.push(n);
                                }
                    }
                }
            }

    // 7. Randomize and check for collision, retry if needed
    used.sort();
    used.dedup();
    for _ in 0..200 {
        let candidate = 100 + (rand_byte() % 155); // 100-254
        if !used.contains(&candidate) {
            return candidate;
        }
    }
    // Fallback: sequential scan
    (100u8..=254).find(|i| !used.contains(i)).unwrap_or(100)
}

/// Assign a bridge IP to a container. If a WolfNet IP is provided, derives the
/// bridge IP from its last octet (e.g. x.x.x.101 → 10.0.3.101). Otherwise allocates
/// the next free bridge IP. Writes network config in either case.
fn assign_container_bridge_ip(container: &str) -> String {
    // Try to derive from wolfnet IP (deterministic — no allocation needed)
    let base = lxc_base_dir(container);
    let wolfnet_ip_file = format!("{}/{}/.wolfnet/ip", base, container);
    let wolfnet_ip = std::fs::read_to_string(&wolfnet_ip_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let bridge_ip = match wolfnet_ip.as_deref().and_then(|w| w.rsplit('.').next()) {
        Some(last_octet) => format!("10.0.3.{}", last_octet),
        None => {
            let last = find_free_bridge_ip();
            format!("10.0.3.{}", last)
        }
    };

    write_container_network_config(container, &bridge_ip, wolfnet_ip.as_deref());
    bridge_ip
}

/// Build the WolfNet /24 subnet from a /32 WolfNet IP — `10.10.20.5` → `10.10.20.0/24`.
fn wolfnet_subnet_from_ip(ip: &str) -> Option<String> {
    Some(wolfnet_cidr_for(ip)).filter(|s| !s.is_empty())
}

// ─── Per-container DNS ───────────────────────────────────────────────────
//
// WolfStack rewrites a container's in-container network config every time it
// starts it (see `reconcile_bridge_static_on_start`). Through v25.17.0 that
// write hardcoded 1.1.1.1/8.8.8.8, so an operator who had set their own
// resolver inside the container watched it revert to Cloudflare/Google on
// every UI Restart — while an in-container `reboot`, which never runs our
// writer, kept it (RutgerDiehard, 2026-08-21). Two things fix that:
//
//   1. An explicit per-container DNS setting the writers honour. Proxmox CTs
//      already have a native place for it (the CT config's `nameserver:` /
//      `searchdomain:` fields, which PVE itself applies on start); native LXC
//      has none, so it goes in a WolfStack sidecar next to `.wolfstack/notes`.
//   2. When nothing is set, PRESERVE whatever the container already resolves
//      with instead of overwriting it. The public fallback is used only when
//      the container names no resolver at all.

/// Public resolvers written only when neither the operator nor the container
/// itself names one — a container with no nameserver would otherwise boot with
/// no DNS at all.
const FALLBACK_DNS: [&str; 2] = ["1.1.1.1", "8.8.8.8"];

/// Upper bound on stored/rendered DNS entries. glibc only reads the first 3
/// nameservers, but netplan/NM configs legitimately carry more; this exists to
/// bound the size of what we interpolate into config files.
const MAX_DNS_ENTRIES: usize = 6;

/// A container's DNS configuration: resolvers plus search domains.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerDns {
    #[serde(default)]
    pub servers: Vec<String>,
    #[serde(default)]
    pub search: Vec<String>,
}

impl ContainerDns {
    fn is_empty(&self) -> bool {
        self.servers.is_empty() && self.search.is_empty()
    }
}

/// Parse an operator-typed resolver list ("1.1.1.1, 9.9.9.9") into validated
/// addresses.
///
/// Anything that isn't a bare IP is dropped. This is the validation boundary
/// for the whole feature: these strings are interpolated into resolv.conf,
/// `/etc/network/interfaces`, netplan YAML and NetworkManager keyfiles, where a
/// stray newline or `;` would corrupt the file — or inject a directive into it.
/// Parsing to `IpAddr` makes that structurally impossible.
pub fn parse_dns_servers(input: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tok in input.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
        if tok.is_empty() || out.len() >= MAX_DNS_ENTRIES {
            continue;
        }
        if let Ok(ip) = tok.parse::<std::net::IpAddr>() {
            let s = ip.to_string();
            if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out
}

/// Parse an operator-typed search-domain list. Hostname charset only, for the
/// same injection reasons as [`parse_dns_servers`].
pub fn parse_dns_search(input: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tok in input.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
        if tok.is_empty() || out.len() >= MAX_DNS_ENTRIES {
            continue;
        }
        let ok = tok.len() <= 253
            && tok.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            && tok.chars().any(|c| c.is_ascii_alphanumeric());
        if ok && !out.iter().any(|e| e == tok) {
            out.push(tok.to_string());
        }
    }
    out
}

/// Re-validate a stored/parsed pair through the same boundary the UI input
/// goes through, so a hand-edited sidecar or CT config can't smuggle junk into
/// a rendered config file.
fn sanitize_dns(dns: ContainerDns) -> ContainerDns {
    ContainerDns {
        servers: parse_dns_servers(&dns.servers.join(" ")),
        search: parse_dns_search(&dns.search.join(" ")),
    }
}

/// Path to the WolfStack DNS sidecar for a NATIVE LXC container. Mirrors
/// [`lxc_notes_path`] — native LXC has no `nameserver` directive of its own.
fn lxc_dns_path(container: &str) -> String {
    format!("{}/{}/.wolfstack/dns", lxc_base_dir(container), container)
}

/// Pull `nameserver:` / `searchdomain:` out of a Proxmox CT config. PVE's own
/// fields, so a DNS set with `pct set --nameserver` (or in the PVE web UI) is
/// honoured by WolfStack too instead of being overwritten by our writers.
fn parse_pve_dns(conf: &str) -> ContainerDns {
    let mut dns = ContainerDns::default();
    for line in conf.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        match k.trim() {
            "nameserver" => dns.servers = parse_dns_servers(v),
            "searchdomain" => dns.search = parse_dns_search(v),
            _ => {}
        }
    }
    dns
}

/// The operator's explicit DNS choice for `container`, or an empty
/// [`ContainerDns`] when they haven't made one.
pub fn lxc_get_dns(container: &str) -> ContainerDns {
    if is_proxmox() {
        let conf = std::fs::read_to_string(format!("/etc/pve/lxc/{}.conf", container))
            .unwrap_or_default();
        return parse_pve_dns(&conf);
    }
    let dns = std::fs::read_to_string(lxc_dns_path(container))
        .ok()
        .and_then(|t| serde_json::from_str::<ContainerDns>(&t).ok())
        .unwrap_or_default();
    sanitize_dns(dns)
}

/// Write (or clear) the native-LXC DNS sidecar. Clearing removes the file so
/// the container falls back to "preserve whatever is inside it".
fn lxc_write_dns(container: &str, dns: &ContainerDns) -> Result<(), String> {
    let path = lxc_dns_path(container);
    if dns.is_empty() {
        if std::path::Path::new(&path).exists() {
            std::fs::remove_file(&path)
                .map_err(|e| format!("Failed to clear DNS {}: {}", path, e))?;
        }
        return Ok(());
    }
    if let Some(dir) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Failed to create DNS dir {}: {}", dir.display(), e))?;
    }
    let body = serde_json::to_string(dns).map_err(|e| format!("Failed to encode DNS: {}", e))?;
    std::fs::write(&path, body).map_err(|e| format!("Failed to write DNS {}: {}", path, e))
}

/// `nameserver` / `search` / `domain` out of a resolv.conf body. The
/// systemd-resolved stub (127.0.0.53) is dropped: it is a pointer to the
/// guest's own resolver, not an upstream, and copying it into a netplan or NM
/// config would leave the container resolving against nothing. Same exclusion
/// the host-side detection makes (see `crate::networking`).
fn parse_resolv_conf_dns(text: &str) -> ContainerDns {
    let mut dns = ContainerDns::default();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((k, v)) = line.split_once(char::is_whitespace) else { continue };
        match k {
            "nameserver" => dns.servers.extend(parse_dns_servers(v)),
            // `search` supersedes `domain`; taking both and de-duplicating in
            // parse_dns_search keeps whichever the file actually carries.
            "search" | "domain" => dns.search.extend(parse_dns_search(v)),
            _ => {}
        }
    }
    dns.servers.retain(|s| s != "127.0.0.53");
    sanitize_dns(dns)
}

/// `dns-nameservers` / `dns-search` out of an ifupdown interfaces body.
fn parse_interfaces_dns(text: &str) -> ContainerDns {
    let mut dns = ContainerDns::default();
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("dns-nameservers") {
            dns.servers.extend(parse_dns_servers(v));
        } else if let Some(v) = line.strip_prefix("dns-search") {
            dns.search.extend(parse_dns_search(v));
        }
    }
    sanitize_dns(dns)
}

/// `DNS=` / `Domains=` out of a systemd-networkd unit body.
fn parse_networkd_dns(text: &str) -> ContainerDns {
    let mut dns = ContainerDns::default();
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("DNS=") {
            dns.servers.extend(parse_dns_servers(v));
        } else if let Some(v) = line.strip_prefix("Domains=") {
            dns.search.extend(parse_dns_search(v));
        }
    }
    sanitize_dns(dns)
}

/// `nameservers:` out of a netplan document. Scoped to the block: a bare
/// `addresses:` at any other level is the interface's OWN addresses, and
/// hoovering those up would hand the container its own IP as a resolver.
fn parse_netplan_dns(text: &str) -> ContainerDns {
    let mut dns = ContainerDns::default();
    let mut in_ns = false;
    let mut ns_indent = 0usize;
    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if in_ns && indent <= ns_indent {
            in_ns = false;
        }
        if trimmed == "nameservers:" {
            in_ns = true;
            ns_indent = indent;
            continue;
        }
        if !in_ns {
            continue;
        }
        if let Some(v) = trimmed.strip_prefix("addresses:") {
            dns.servers.extend(parse_dns_servers(v.trim_matches(|c| c == '[' || c == ']' || c == ' ')));
        } else if let Some(v) = trimmed.strip_prefix("search:") {
            dns.search.extend(parse_dns_search(v.trim_matches(|c| c == '[' || c == ']' || c == ' ')));
        }
    }
    sanitize_dns(dns)
}

/// `dns=` / `dns-search=` out of a NetworkManager keyfile body.
fn parse_nm_dns(text: &str) -> ContainerDns {
    let mut dns = ContainerDns::default();
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("dns=") {
            dns.servers.extend(parse_dns_servers(v));
        } else if let Some(v) = line.strip_prefix("dns-search=") {
            dns.search.extend(parse_dns_search(v));
        }
    }
    sanitize_dns(dns)
}

/// What the container is ALREADY configured to resolve with, so a reconcile
/// write can preserve it. resolv.conf first — it is the file every resolver
/// actually reads — then each backend in the order the writers emit them.
fn read_rootfs_dns(rootfs: &str) -> ContainerDns {
    let read = |p: String| std::fs::read_to_string(p).unwrap_or_default();

    let mut found = parse_resolv_conf_dns(&read(format!("{}/etc/resolv.conf", rootfs)));
    if !found.servers.is_empty() {
        return found;
    }
    found = parse_interfaces_dns(&read(format!("{}/etc/network/interfaces", rootfs)));
    if !found.servers.is_empty() {
        return found;
    }
    found = parse_networkd_dns(&read(format!("{}/etc/systemd/network/eth0.network", rootfs)));
    if !found.servers.is_empty() {
        return found;
    }
    if let Ok(entries) = std::fs::read_dir(format!("{}/etc/netplan", rootfs)) {
        let mut files: Vec<std::path::PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "yaml" || x == "yml").unwrap_or(false))
            .collect();
        files.sort();
        for f in files {
            found = parse_netplan_dns(&std::fs::read_to_string(&f).unwrap_or_default());
            if !found.servers.is_empty() {
                return found;
            }
        }
    }
    found = parse_nm_dns(&read(format!(
        "{}/etc/NetworkManager/system-connections/eth0.nmconnection", rootfs
    )));
    if !found.servers.is_empty() {
        return found;
    }
    ContainerDns::default()
}

/// The DNS a writer should emit for one container, and whether the operator
/// asked for it explicitly (which decides whether we may replace a
/// resolver-managed /etc/resolv.conf symlink).
#[derive(Debug, Clone, PartialEq)]
struct ResolvedDns {
    servers: Vec<String>,
    search: Vec<String>,
    explicit: bool,
}

/// Pure resolution order behind [`resolve_container_dns`], split out so the
/// precedence is unit-testable without a rootfs. `defaults` is the writer's own
/// fallback (public resolvers for a LAN bridge, the lxcbr0 gateway for
/// WolfNet), used only when nothing else names a resolver.
fn decide_dns(set: ContainerDns, found: ContainerDns, defaults: &[&str]) -> ResolvedDns {
    let explicit = !set.servers.is_empty();
    let servers = if explicit {
        set.servers
    } else if !found.servers.is_empty() {
        found.servers
    } else {
        defaults.iter().map(|s| s.to_string()).collect()
    };
    let search = if set.search.is_empty() { found.search } else { set.search };
    ResolvedDns { servers, search, explicit }
}

/// Resolve the DNS to write into `container`'s rootfs: the operator's explicit
/// choice, else what the container already resolves with, else `defaults`.
fn resolve_container_dns(container: &str, rootfs: &str, defaults: &[&str]) -> ResolvedDns {
    decide_dns(lxc_get_dns(container), read_rootfs_dns(rootfs), defaults)
}

/// `DNS=`/`Domains=` lines for a systemd-networkd `[Network]` section.
fn dns_networkd_lines(dns: &ResolvedDns) -> String {
    let mut out = String::new();
    for s in &dns.servers {
        out.push_str(&format!("DNS={}\n", s));
    }
    if !dns.search.is_empty() {
        out.push_str(&format!("Domains={}\n", dns.search.join(" ")));
    }
    out
}

/// The `nameservers:` block for a netplan ethernet, at netplan's 6-space
/// key indent.
fn dns_netplan_block(dns: &ResolvedDns) -> String {
    let mut out = format!(
        "      nameservers:\n        addresses: [{}]\n",
        dns.servers.join(", ")
    );
    if !dns.search.is_empty() {
        out.push_str(&format!("        search: [{}]\n", dns.search.join(", ")));
    }
    out
}

/// `dns-nameservers`/`dns-search` lines for an ifupdown iface stanza.
fn dns_interfaces_lines(dns: &ResolvedDns) -> String {
    let mut out = format!("    dns-nameservers {}\n", dns.servers.join(" "));
    if !dns.search.is_empty() {
        out.push_str(&format!("    dns-search {}\n", dns.search.join(" ")));
    }
    out
}

/// `dns=`/`dns-search=` lines for a NetworkManager `[ipv4]` section.
fn dns_nm_lines(dns: &ResolvedDns) -> String {
    let mut out = format!("dns={};\n", dns.servers.join(";"));
    if !dns.search.is_empty() {
        out.push_str(&format!("dns-search={};\n", dns.search.join(";")));
    }
    out
}

/// A complete resolv.conf body.
fn dns_resolv_conf(dns: &ResolvedDns) -> String {
    let mut out = String::new();
    for s in &dns.servers {
        out.push_str(&format!("nameserver {}\n", s));
    }
    if !dns.search.is_empty() {
        out.push_str(&format!("search {}\n", dns.search.join(" ")));
    }
    out
}

/// True when `/etc/resolv.conf` in the rootfs is a symlink into a resolver's
/// generated state (systemd-resolved's stub, resolvconf's run dir). Replacing
/// one of those with a static file breaks the guest's own resolver
/// integration, so we leave it alone unless the operator explicitly asked for
/// specific servers.
fn resolv_conf_manager_owned(path: &str) -> bool {
    let Ok(target) = std::fs::read_link(path) else { return false };
    let t = target.to_string_lossy();
    t.contains("systemd/resolve") || t.contains("resolvconf") || t.contains("stub-resolv.conf")
}

/// Write the container's `/etc/resolv.conf`, unless the guest's own resolver
/// generates it (see [`resolv_conf_manager_owned`]). Returns whether the file
/// was written, so a caller can tell the operator whether their DNS change is
/// already live or only takes effect on the next start.
fn write_rootfs_resolv_conf(rootfs: &str, dns: &ResolvedDns) -> bool {
    let path = format!("{}/etc/resolv.conf", rootfs);
    if !dns.explicit && resolv_conf_manager_owned(&path) {
        return false;
    }
    let _ = std::fs::remove_file(&path); // might be a symlink
    std::fs::write(&path, dns_resolv_conf(dns)).is_ok()
}

#[cfg(test)]
mod container_dns_tests {
    use super::*;

    #[test]
    fn dns_servers_reject_anything_that_is_not_an_ip() {
        // The parse IS the validation boundary — these values are interpolated
        // into resolv.conf / netplan / NM keyfiles.
        assert_eq!(parse_dns_servers("1.1.1.1, 9.9.9.9"), vec!["1.1.1.1", "9.9.9.9"]);
        assert_eq!(parse_dns_servers("192.168.1.1\nnameserver 6.6.6.6"), vec!["192.168.1.1", "6.6.6.6"]);
        assert!(parse_dns_servers("$(curl evil)").is_empty());
        assert!(parse_dns_servers("not-an-ip").is_empty());
        assert_eq!(parse_dns_servers("2001:4860:4860::8888"), vec!["2001:4860:4860::8888"]);
        // Duplicates collapse, and the list is bounded.
        assert_eq!(parse_dns_servers("1.1.1.1 1.1.1.1"), vec!["1.1.1.1"]);
        assert_eq!(parse_dns_servers("1.1.1.1 1.1.1.2 1.1.1.3 1.1.1.4 1.1.1.5 1.1.1.6 1.1.1.7").len(), MAX_DNS_ENTRIES);
    }

    #[test]
    fn dns_search_keeps_hostname_charset_only() {
        assert_eq!(parse_dns_search("lan, home.arpa"), vec!["lan", "home.arpa"]);
        // A newline can't survive: the split makes each token its own entry and
        // the charset check drops the injected directive, leaving one label.
        assert_eq!(parse_dns_search("evil\nGateway=6.6.6.6"), vec!["evil"]);
        // `;` is a separator (NM keyfiles use it), not a smuggled character.
        assert_eq!(parse_dns_search("a;b"), vec!["a", "b"]);
        assert!(parse_dns_search("...").is_empty());
    }

    #[test]
    fn pve_dns_fields_are_read_back() {
        let conf = "arch: amd64\nnameserver: 192.168.1.1 1.1.1.1\nsearchdomain: lan\nnet0: name=eth0,bridge=vmbr0\n";
        assert_eq!(
            parse_pve_dns(conf),
            ContainerDns { servers: vec!["192.168.1.1".into(), "1.1.1.1".into()], search: vec!["lan".into()] }
        );
        assert_eq!(parse_pve_dns("arch: amd64\n"), ContainerDns::default());
    }

    #[test]
    fn resolv_conf_parses_and_drops_the_resolved_stub() {
        let text = "# Generated\nnameserver 192.168.1.1\nsearch lan\n";
        assert_eq!(
            parse_resolv_conf_dns(text),
            ContainerDns { servers: vec!["192.168.1.1".into()], search: vec!["lan".into()] }
        );
        // 127.0.0.53 is a pointer to the guest's own resolver, not an upstream:
        // copying it into a netplan/NM config would leave DNS resolving nowhere.
        assert!(parse_resolv_conf_dns("nameserver 127.0.0.53\noptions edns0\n").servers.is_empty());
        assert_eq!(parse_resolv_conf_dns("domain lan\n").search, vec!["lan"]);
    }

    #[test]
    fn each_backend_config_is_parsed_back() {
        assert_eq!(
            parse_interfaces_dns("iface eth0 inet static\n    dns-nameservers 10.0.0.1 10.0.0.2\n    dns-search lan\n"),
            ContainerDns { servers: vec!["10.0.0.1".into(), "10.0.0.2".into()], search: vec!["lan".into()] }
        );
        assert_eq!(
            parse_networkd_dns("[Network]\nAddress=10.0.0.5/24\nDNS=10.0.0.1\nDomains=lan\n"),
            ContainerDns { servers: vec!["10.0.0.1".into()], search: vec!["lan".into()] }
        );
        assert_eq!(
            parse_nm_dns("[ipv4]\nmethod=manual\naddress1=10.0.0.5/24,10.0.0.1\ndns=10.0.0.1;9.9.9.9;\ndns-search=lan;\n"),
            ContainerDns { servers: vec!["10.0.0.1".into(), "9.9.9.9".into()], search: vec!["lan".into()] }
        );
    }

    #[test]
    fn netplan_nameservers_do_not_swallow_the_interface_addresses() {
        // The `addresses:` under `eth0:` is the container's OWN IP — reading it
        // as a resolver would hand the container itself as its nameserver.
        let yaml = "network:\n  version: 2\n  ethernets:\n    eth0:\n      addresses:\n        - 10.0.0.5/24\n      routes:\n        - to: default\n          via: 10.0.0.1\n      nameservers:\n        addresses: [10.0.0.1, 9.9.9.9]\n        search: [lan]\n";
        assert_eq!(
            parse_netplan_dns(yaml),
            ContainerDns { servers: vec!["10.0.0.1".into(), "9.9.9.9".into()], search: vec!["lan".into()] }
        );
        let no_dns = "network:\n  version: 2\n  ethernets:\n    eth0:\n      addresses:\n        - 10.0.0.5/24\n";
        assert!(parse_netplan_dns(no_dns).servers.is_empty());
    }

    #[test]
    fn explicit_dns_wins_then_the_container_s_own_then_the_fallback() {
        let set = ContainerDns { servers: vec!["192.168.1.1".into()], search: vec![] };
        let found = ContainerDns { servers: vec!["10.0.0.1".into()], search: vec!["lan".into()] };

        let r = decide_dns(set.clone(), found.clone(), &FALLBACK_DNS);
        assert_eq!(r.servers, vec!["192.168.1.1"]);
        assert!(r.explicit);
        // An override with no search domains still inherits the container's.
        assert_eq!(r.search, vec!["lan"]);

        // This is the RutgerDiehard case: nothing pinned in WolfStack, so the
        // container's own resolver must survive the restart rewrite.
        let r = decide_dns(ContainerDns::default(), found, &FALLBACK_DNS);
        assert_eq!(r.servers, vec!["10.0.0.1"]);
        assert!(!r.explicit);

        // Only when the container names no resolver at all do we invent one.
        let r = decide_dns(ContainerDns::default(), ContainerDns::default(), &FALLBACK_DNS);
        assert_eq!(r.servers, vec!["1.1.1.1", "8.8.8.8"]);
        assert!(!r.explicit);
    }

    #[test]
    fn renderers_match_the_formats_the_writers_used_before() {
        let dns = ResolvedDns {
            servers: vec!["10.0.3.1".into(), "8.8.8.8".into()],
            search: vec![],
            explicit: false,
        };
        assert_eq!(dns_networkd_lines(&dns), "DNS=10.0.3.1\nDNS=8.8.8.8\n");
        assert_eq!(dns_netplan_block(&dns), "      nameservers:\n        addresses: [10.0.3.1, 8.8.8.8]\n");
        assert_eq!(dns_interfaces_lines(&dns), "    dns-nameservers 10.0.3.1 8.8.8.8\n");
        assert_eq!(dns_nm_lines(&dns), "dns=10.0.3.1;8.8.8.8;\n");
        assert_eq!(dns_resolv_conf(&dns), "nameserver 10.0.3.1\nnameserver 8.8.8.8\n");

        let with_search = ResolvedDns { search: vec!["lan".into()], ..dns };
        assert_eq!(dns_networkd_lines(&with_search), "DNS=10.0.3.1\nDNS=8.8.8.8\nDomains=lan\n");
        assert_eq!(dns_interfaces_lines(&with_search), "    dns-nameservers 10.0.3.1 8.8.8.8\n    dns-search lan\n");
        assert_eq!(dns_nm_lines(&with_search), "dns=10.0.3.1;8.8.8.8;\ndns-search=lan;\n");
        assert_eq!(dns_resolv_conf(&with_search), "nameserver 10.0.3.1\nnameserver 8.8.8.8\nsearch lan\n");
    }

    #[test]
    fn a_hand_edited_store_cannot_smuggle_junk_into_a_config_file() {
        let dirty = ContainerDns {
            servers: vec!["1.1.1.1\nDNS=6.6.6.6".into(), "nope".into()],
            search: vec!["lan\nGateway=6.6.6.6".into()],
        };
        // "DNS=6.6.6.6" is not a parseable address and "Gateway=6.6.6.6" is not
        // a hostname, so both injected directives are dropped outright.
        assert_eq!(
            sanitize_dns(dirty),
            ContainerDns { servers: vec!["1.1.1.1".into()], search: vec!["lan".into()] }
        );
    }

    /// End-to-end over a real rootfs: run the writer that fires on EVERY start
    /// and prove it no longer reverts the container's DNS. This is the exact
    /// path that made `pulse` snap back to 1.1.1.1/8.8.8.8 on every UI restart.
    #[test]
    fn the_start_rewrite_keeps_the_container_s_own_resolver() {
        // On a PVE host lxc_get_dns reads the CT config instead of the sidecar,
        // and this fixture is a native-layout container — skip rather than
        // assert against a layout that isn't in play.
        if is_proxmox() {
            return;
        }
        let name = "wolfstack-dnstest-ct";
        let base = std::env::temp_dir().join(format!("wolfstack-dnstest-{}", std::process::id()));
        let base_str = base.to_string_lossy().to_string();
        let _ = std::fs::remove_dir_all(&base);
        let etc = base.join(name).join("rootfs/etc");
        std::fs::create_dir_all(etc.join("network")).unwrap();
        LXC_STORAGE_PATHS.lock().unwrap().push(base_str.clone());

        // The operator's own resolver, as it looks inside a Debian container.
        std::fs::write(etc.join("resolv.conf"), "nameserver 192.168.1.1\nsearch lan\n").unwrap();
        std::fs::write(
            etc.join("network/interfaces"),
            "auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet static\n    address 192.168.1.50\n    netmask 255.255.255.0\n    gateway 192.168.1.1\n    dns-nameservers 192.168.1.1\n",
        ).unwrap();

        // 1. A restart rewrite must preserve it.
        write_lxc_bridge_static_config(name, "192.168.1.50/24", Some("192.168.1.1")).unwrap();
        let resolv = std::fs::read_to_string(etc.join("resolv.conf")).unwrap();
        let ifaces = std::fs::read_to_string(etc.join("network/interfaces")).unwrap();
        assert_eq!(resolv, "nameserver 192.168.1.1\nsearch lan\n");
        assert!(ifaces.contains("dns-nameservers 192.168.1.1"), "{}", ifaces);
        assert!(ifaces.contains("dns-search lan"), "{}", ifaces);
        assert!(!ifaces.contains("8.8.8.8"), "the start rewrite reintroduced public DNS:\n{}", ifaces);
        // The addressing it exists to write is still written.
        assert!(ifaces.contains("address 192.168.1.50"), "{}", ifaces);
        assert!(ifaces.contains("gateway 192.168.1.1"), "{}", ifaces);

        // 2. A pinned override beats what's in the container.
        lxc_write_dns(name, &ContainerDns { servers: vec!["10.0.0.53".into()], search: vec![] }).unwrap();
        write_lxc_bridge_static_config(name, "192.168.1.50/24", Some("192.168.1.1")).unwrap();
        let resolv = std::fs::read_to_string(etc.join("resolv.conf")).unwrap();
        assert!(resolv.contains("nameserver 10.0.0.53"), "{}", resolv);
        assert!(!resolv.contains("nameserver 192.168.1.1"), "{}", resolv);
        // Search domains the operator didn't override are still inherited.
        assert!(resolv.contains("search lan"), "{}", resolv);
        assert_eq!(lxc_get_dns(name).servers, vec!["10.0.0.53"]);

        // 3. Clearing the override hands DNS back to the container.
        lxc_write_dns(name, &ContainerDns::default()).unwrap();
        assert_eq!(lxc_get_dns(name), ContainerDns::default());

        // 4. A container naming no resolver at all still gets working DNS.
        std::fs::remove_file(etc.join("resolv.conf")).unwrap();
        std::fs::write(etc.join("network/interfaces"), "auto lo\niface lo inet loopback\n").unwrap();
        write_lxc_bridge_static_config(name, "192.168.1.50/24", Some("192.168.1.1")).unwrap();
        let resolv = std::fs::read_to_string(etc.join("resolv.conf")).unwrap();
        assert_eq!(resolv, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n");

        LXC_STORAGE_PATHS.lock().unwrap().retain(|p| p != &base_str);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The guest's own resolver keeps ownership of /etc/resolv.conf: a symlink
    /// into systemd-resolved's run dir must survive a start rewrite, or the
    /// guest boots with a static file its resolver no longer maintains.
    #[test]
    fn a_resolved_managed_resolv_conf_symlink_is_left_alone() {
        if is_proxmox() {
            return;
        }
        let name = "wolfstack-dnstest-stub";
        let base = std::env::temp_dir().join(format!("wolfstack-dnsstub-{}", std::process::id()));
        let base_str = base.to_string_lossy().to_string();
        let _ = std::fs::remove_dir_all(&base);
        let etc = base.join(name).join("rootfs/etc");
        std::fs::create_dir_all(etc.join("network")).unwrap();
        LXC_STORAGE_PATHS.lock().unwrap().push(base_str.clone());

        std::os::unix::fs::symlink("../run/systemd/resolve/stub-resolv.conf", etc.join("resolv.conf")).unwrap();
        std::fs::write(etc.join("network/interfaces"), "auto lo\niface lo inet loopback\n").unwrap();

        write_lxc_bridge_static_config(name, "192.168.1.50/24", Some("192.168.1.1")).unwrap();
        assert!(
            std::fs::symlink_metadata(etc.join("resolv.conf")).unwrap().file_type().is_symlink(),
            "the start rewrite replaced a resolver-managed resolv.conf symlink with a static file"
        );

        // An explicit pin is the operator overruling that, so it does replace it.
        lxc_write_dns(name, &ContainerDns { servers: vec!["10.0.0.53".into()], search: vec![] }).unwrap();
        write_lxc_bridge_static_config(name, "192.168.1.50/24", Some("192.168.1.1")).unwrap();
        let md = std::fs::symlink_metadata(etc.join("resolv.conf")).unwrap();
        assert!(!md.file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(etc.join("resolv.conf")).unwrap(), "nameserver 10.0.0.53\n");

        LXC_STORAGE_PATHS.lock().unwrap().retain(|p| p != &base_str);
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// Write persistent network config into the container's rootfs, covering
/// every renderer we support (NM, systemd-networkd, netplan, ifupdown).
///
/// `bridge_ip` is the lxcbr0 IP used for host↔container routing.
/// `wolfnet_ip`, when present, is added as a secondary /32 on the same
/// interface and routed via the bridge gateway with `src=wolfnet_ip` so
/// the container uses its WolfNet IP as the source for WolfNet traffic.
///
/// Critical for distros that ship NetworkManager (Linux Mint, Ubuntu
/// Desktop, Fedora): if the WolfNet IP is only added at runtime via
/// `lxc-attach ip addr add`, NM rewrites the interface and drops it.
/// Persisting both addresses in the keyfile makes NM apply them on every
/// boot.
fn write_container_network_config(container: &str, bridge_ip: &str, wolfnet_ip: Option<&str>) {
    let rootfs = format!("{}/{}/rootfs", lxc_base_dir(container), container);
    let wn_subnet = wolfnet_ip.and_then(wolfnet_subnet_from_ip);
    // When the container has its own vSwitch / public NIC, eth0 is the
    // WolfNet-only NIC here: it must NOT carry a default route, or it
    // would compete with (and on a route flush, replace) the public
    // NIC's gateway. See lxc_has_external_gateway.
    let wolfnet_only = lxc_has_external_gateway(container);

    // DNS: the operator's explicit choice when they made one, otherwise the
    // defaults this path has always written. Preserving the container's own
    // resolvers is deliberately NOT the default here — on a WolfNet NAT
    // container the lxcbr0 resolver (10.0.3.1, lxc-net's dnsmasq) is the one
    // that answers sibling-container names, and whatever the image left behind
    // usually is not reachable from the NAT subnet.
    let dns_set = lxc_get_dns(container);
    let dns_defaults: &[&str] = if wolfnet_only {
        &["8.8.8.8", "1.1.1.1"]
    } else {
        &["10.0.3.1", "8.8.8.8"]
    };
    let dns = decide_dns(dns_set.clone(), ContainerDns::default(), dns_defaults);

    // Method 1: systemd-networkd (Debian Trixie, Arch, etc.)
    let networkd_dir = format!("{}/etc/systemd/network", rootfs);
    if std::path::Path::new(&networkd_dir).exists() {
        let mut conf = format!(
            "[Match]\nName=eth0\n\n[Network]\nAddress={}/24\n",
            bridge_ip
        );
        if let Some(wip) = wolfnet_ip {
            conf.push_str(&format!("Address={}/32\n", wip));
        }
        if wolfnet_only {
            // eth0 is WolfNet-only — no default gateway; the container's
            // vSwitch / public NIC owns the default route.
            conf.push_str(&dns_networkd_lines(&dns));
        } else {
            conf.push_str("Gateway=10.0.3.1\n");
            conf.push_str(&dns_networkd_lines(&dns));
        }
        if let (Some(wip), Some(subnet)) = (wolfnet_ip, &wn_subnet) {
            // Source-pinned route so reply traffic uses the WolfNet IP, not the bridge IP.
            conf.push_str(&format!(
                "\n[Route]\nDestination={}\nGateway=10.0.3.1\nPreferredSource={}\n",
                subnet, wip
            ));
        }
        let _ = std::fs::write(format!("{}/eth0.network", networkd_dir), &conf);
    }

    // Method 2: Netplan (Ubuntu 18.04+, Linux Mint based on Ubuntu)
    let netplan_dir = format!("{}/etc/netplan", rootfs);
    if std::path::Path::new(&netplan_dir).exists() {
        let mut addresses = format!("        - {}/24\n", bridge_ip);
        if let Some(wip) = wolfnet_ip {
            addresses.push_str(&format!("        - {}/32\n", wip));
        }
        // eth0 carries a default route only when the container has no
        // vSwitch / public NIC of its own; the WolfNet subnet route is
        // always present.
        let mut route_lines = String::new();
        if !wolfnet_only {
            route_lines.push_str("        - to: default\n          via: 10.0.3.1\n");
        }
        if let (Some(wip), Some(subnet)) = (wolfnet_ip, &wn_subnet) {
            route_lines.push_str(&format!(
                "        - to: {}\n          via: 10.0.3.1\n          from: {}\n",
                subnet, wip
            ));
        }
        let routes = if route_lines.is_empty() {
            String::new()
        } else {
            format!("      routes:\n{}", route_lines)
        };
        let conf = format!(
            "network:\n  version: 2\n  ethernets:\n    eth0:\n      addresses:\n{}{}{}",
            addresses, routes, dns_netplan_block(&dns)
        );
        // Remove conflicting configs
        if let Ok(entries) = std::fs::read_dir(&netplan_dir) {
            for e in entries.flatten() {
                let _ = std::fs::remove_file(e.path());
            }
        }
        let _ = std::fs::write(format!("{}/50-wolfstack.yaml", netplan_dir), &conf);
    }

    // Method 3: /etc/network/interfaces (Debian Bullseye/Bookworm, Alpine)
    let ifaces_path = format!("{}/etc/network/interfaces", rootfs);
    if std::path::Path::new(&ifaces_path).exists() {
        let mut conf = format!(
            "auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet static\n    address {}\n    netmask 255.255.255.0\n",
            bridge_ip
        );
        if !wolfnet_only {
            conf.push_str("    gateway 10.0.3.1\n");
        }
        conf.push_str(&dns_interfaces_lines(&dns));
        if let (Some(wip), Some(subnet)) = (wolfnet_ip, &wn_subnet) {
            // post-up adds the WolfNet IP as a secondary + the source-pinned subnet route
            conf.push_str(&format!(
                "    post-up ip addr add {}/32 dev eth0 || true\n    post-up ip route replace {} via 10.0.3.1 dev eth0 src {} || true\n",
                wip, subnet, wip
            ));
        }
        let _ = std::fs::write(&ifaces_path, &conf);
    }

    // Method 4: NetworkManager keyfile (RHEL, AlmaLinux, Rocky, Fedora,
    // CentOS, Linux Mint, Ubuntu Desktop, anything with NM enabled).
    // NM uses `address1`/`address2` for primary/secondary addresses and
    // `route1` for explicit routes with `route1_options=src=…`.
    let nm_dir = format!("{}/etc/NetworkManager/system-connections", rootfs);
    if std::path::Path::new(&nm_dir).exists() || std::path::Path::new(&format!("{}/etc/NetworkManager", rootfs)).exists() {
        let _ = std::fs::create_dir_all(&nm_dir);
        let mut ipv4 = String::from("[ipv4]\nmethod=manual\n");
        if wolfnet_only {
            // No gateway on eth0, and never-default so NetworkManager
            // won't route the world through lxcbr0 — the public NIC
            // owns the default route.
            ipv4.push_str(&format!("address1={}/24\n", bridge_ip));
            ipv4.push_str("never-default=true\n");
        } else {
            ipv4.push_str(&format!("address1={}/24,10.0.3.1\n", bridge_ip));
        }
        if let Some(wip) = wolfnet_ip {
            ipv4.push_str(&format!("address2={}/32\n", wip));
        }
        if let (Some(wip), Some(subnet)) = (wolfnet_ip, &wn_subnet) {
            ipv4.push_str(&format!("route1={},10.0.3.1\n", subnet));
            ipv4.push_str(&format!("route1_options=src={}\n", wip));
        }
        ipv4.push_str(&dns_nm_lines(&dns));

        let conf = format!(
            "[connection]\nid=eth0\ntype=ethernet\ninterface-name=eth0\nautoconnect=true\n\n\
             {}\n\
             [ipv6]\nmethod=disabled\n",
            ipv4
        );
        let nm_path = format!("{}/eth0.nmconnection", nm_dir);
        let _ = std::fs::write(&nm_path, &conf);
        // NM refuses to load keyfiles that aren't 0600.
        let _ = std::fs::set_permissions(&nm_path, std::fs::Permissions::from_mode(0o600));
        // Remove legacy ifcfg files that might conflict
        let ifcfg_path = format!("{}/etc/sysconfig/network-scripts/ifcfg-eth0", rootfs);
        let _ = std::fs::remove_file(&ifcfg_path);
    }

    // resolv.conf keeps the lxcbr0 resolver first in BOTH branches: lxc-net's
    // dnsmasq answers sibling-container names there, and that is what this file
    // has always said — including in the no-default-route case, whose backend
    // configs list public resolvers instead. Left untouched when the guest's own
    // resolver generates it and the operator set nothing (see
    // write_rootfs_resolv_conf).
    let dns_resolv = decide_dns(dns_set, ContainerDns::default(), &["10.0.3.1", "8.8.8.8"]);
    write_rootfs_resolv_conf(&rootfs, &dns_resolv);
}

/// Convert a CIDR prefix length to a dotted-quad netmask (24 -> 255.255.255.0).
fn prefix_to_netmask(prefix: u8) -> String {
    let p = prefix.min(32);
    let mask: u32 = if p == 0 { 0 } else { u32::MAX << (32 - p) };
    format!("{}.{}.{}.{}", (mask >> 24) & 0xff, (mask >> 16) & 0xff, (mask >> 8) & 0xff, mask & 0xff)
}

/// True when `s` is a well-formed IPv4 CIDR ("A.B.C.D/NN", prefix 0-32). Used to
/// reject non-address values (e.g. the literal "dhcp", which normalize_bridge_cidr
/// passes through unchanged) and any string with embedded newlines/junk before it
/// is written into a container's network config.
pub fn is_ipv4_cidr(s: &str) -> bool {
    match s.split_once('/') {
        Some((ip, prefix)) => {
            ip.parse::<std::net::Ipv4Addr>().is_ok()
                && prefix.parse::<u8>().map(|p| p <= 32).unwrap_or(false)
        }
        None => false,
    }
}

/// Write the in-container static network config for a NATIVE LXC attached to a
/// user bridge with a static IP. Returns the list of in-container backends that
/// were configured, or an error string the caller can surface.
///
/// liblxc's `lxc.net.0.ipv4.address` assigns the address to eth0 at start, but
/// the container's own init then runs whatever its image ships — and most
/// download templates default to DHCP, which promptly overrides the static
/// address (wabil 2026-06-26: "set static, gets dhcp"). We mirror the user's
/// CIDR + gateway into every in-container network backend that's present
/// (systemd-networkd, netplan, /etc/network/interfaces, NetworkManager) and turn
/// DHCP off, so the container comes up on the address the operator chose.
///
/// `cidr` must be a validated IPv4 CIDR (see [`is_ipv4_cidr`]); `gateway` an
/// optional validated IPv4 default-route gateway. Unlike
/// [`write_container_network_config`] this carries NO WolfNet assumptions (no
/// hardcoded 10.0.3.1 gateway, no forced /24, no wn0 source-routes) — eth0 is
/// the container's primary LAN NIC here. Errors are returned (not swallowed) so
/// a failed write never reports a phantom "static" success.
pub fn write_lxc_bridge_static_config(container: &str, cidr: &str, gateway: Option<&str>) -> Result<(), String> {
    let rootfs = format!("{}/{}/rootfs", lxc_base_dir(container), container);
    if !std::path::Path::new(&rootfs).exists() {
        return Err(format!("container rootfs not found at {}", rootfs));
    }
    let cidr = cidr.trim();
    let (ip, prefix) = match cidr.split_once('/') {
        Some((a, p)) => (a.to_string(), p.parse::<u8>().unwrap_or(24)),
        None => (cidr.to_string(), 24),
    };
    let netmask = prefix_to_netmask(prefix);
    let gw = gateway.map(str::trim).filter(|g| !g.is_empty());
    // DNS: the operator's explicit choice → whatever the container already
    // resolves with → public fallback. The middle step is what stops a UI
    // restart reverting an operator's own resolver: this writer runs on EVERY
    // start (reconcile_bridge_static_on_start), and hardcoding public DNS here
    // is what made a container's /etc/resolv.conf snap back to 1.1.1.1/8.8.8.8
    // after every restart from the UI (RutgerDiehard 2026-08-21).
    let dns = resolve_container_dns(container, &rootfs, &FALLBACK_DNS);
    let mut errors: Vec<String> = Vec::new();
    let mut wrote_any = false;

    // Method 1: systemd-networkd (Debian Trixie, Arch, etc.). A Name=eth0 match
    // is more specific than the image's wildcard DHCP .network, so it wins.
    let networkd_dir = format!("{}/etc/systemd/network", rootfs);
    if std::path::Path::new(&networkd_dir).exists() {
        let mut conf = format!("[Match]\nName=eth0\n\n[Network]\nDHCP=no\nAddress={}\n", cidr);
        if let Some(g) = gw { conf.push_str(&format!("Gateway={}\n", g)); }
        conf.push_str(&dns_networkd_lines(&dns));
        match std::fs::write(format!("{}/eth0.network", networkd_dir), &conf) {
            Ok(()) => wrote_any = true,
            Err(e) => errors.push(format!("systemd-networkd: {}", e)),
        }
    }

    // Method 2: Netplan (Ubuntu 18.04+). Write a highest-priority (99-) file so
    // our eth0 stanza wins netplan's per-key merge over the image's cloud-init
    // default WITHOUT deleting other NICs' configs (multi-NIC safe). The DHCP
    // revert reuses the SAME filename, so it cleanly overrides this one.
    let netplan_dir = format!("{}/etc/netplan", rootfs);
    if std::path::Path::new(&netplan_dir).exists() {
        let routes = gw
            .map(|g| format!("      routes:\n        - to: default\n          via: {}\n", g))
            .unwrap_or_default();
        let conf = format!(
            "network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: false\n      addresses:\n        - {}\n{}{}",
            cidr, routes, dns_netplan_block(&dns)
        );
        match std::fs::write(format!("{}/99-wolfstack-eth0.yaml", netplan_dir), &conf) {
            Ok(()) => wrote_any = true,
            Err(e) => errors.push(format!("netplan: {}", e)),
        }
    }

    // Method 3: /etc/network/interfaces (Debian Bookworm, Alpine)
    let ifaces_path = format!("{}/etc/network/interfaces", rootfs);
    if std::path::Path::new(&ifaces_path).exists() {
        let mut conf = format!(
            "auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet static\n    address {}\n    netmask {}\n",
            ip, netmask
        );
        if let Some(g) = gw { conf.push_str(&format!("    gateway {}\n", g)); }
        conf.push_str(&dns_interfaces_lines(&dns));
        match std::fs::write(&ifaces_path, &conf) {
            Ok(()) => wrote_any = true,
            Err(e) => errors.push(format!("interfaces: {}", e)),
        }
    }

    // Method 4: NetworkManager keyfile (RHEL family, Ubuntu Desktop, etc.)
    let nm_base = format!("{}/etc/NetworkManager", rootfs);
    if std::path::Path::new(&nm_base).exists() {
        let nm_dir = format!("{}/system-connections", nm_base);
        let _ = std::fs::create_dir_all(&nm_dir);
        let addr_line = match gw {
            Some(g) => format!("address1={},{}\n", cidr, g),
            None => format!("address1={}\n", cidr),
        };
        let conf = format!(
            "[connection]\nid=eth0\ntype=ethernet\ninterface-name=eth0\nautoconnect=true\n\n\
             [ipv4]\nmethod=manual\n{}{}\n[ipv6]\nmethod=auto\n",
            addr_line, dns_nm_lines(&dns)
        );
        let nm_file = format!("{}/eth0.nmconnection", nm_dir);
        match std::fs::write(&nm_file, &conf) {
            Ok(()) => {
                let _ = std::fs::set_permissions(&nm_file, std::fs::Permissions::from_mode(0o600));
                let _ = std::fs::remove_file(format!("{}/etc/sysconfig/network-scripts/ifcfg-eth0", rootfs));
                wrote_any = true;
            }
            Err(e) => errors.push(format!("NetworkManager: {}", e)),
        }
    }

    // resolv.conf so DNS works regardless of which manager runs — skipped when
    // the guest's own resolver generates the file and the operator set nothing.
    write_rootfs_resolv_conf(&rootfs, &dns);

    if !errors.is_empty() {
        Err(errors.join("; "))
    } else if !wrote_any {
        Err("no supported in-container network backend found \
             (systemd-networkd / netplan / /etc/network/interfaces / NetworkManager) — \
             the container may still come up via DHCP".to_string())
    } else {
        Ok(())
    }
}

/// Reset a NATIVE LXC's primary NIC (eth0) back to DHCP inside the container.
/// Counterpart to [`write_lxc_bridge_static_config`]: when an operator edits a
/// previously-static bridge NIC back to DHCP, the static config we wrote earlier
/// would otherwise pin the old address forever. Mirrors the same backend
/// coverage and returns an error rather than swallowing a failed write.
fn write_lxc_bridge_dhcp_config(container: &str) -> Result<(), String> {
    let rootfs = format!("{}/{}/rootfs", lxc_base_dir(container), container);
    if !std::path::Path::new(&rootfs).exists() {
        return Err(format!("container rootfs not found at {}", rootfs));
    }
    let mut errors: Vec<String> = Vec::new();
    let mut wrote_any = false;

    // A DHCP NIC still honours an explicit DNS override: each backend is told
    // to ignore the lease's resolvers so the operator's choice survives every
    // renewal. With no override the lease supplies DNS exactly as before.
    let dns_set = lxc_get_dns(container);
    let dns: Option<ResolvedDns> = if dns_set.servers.is_empty() {
        None
    } else {
        Some(decide_dns(dns_set, ContainerDns::default(), &FALLBACK_DNS))
    };

    let networkd_dir = format!("{}/etc/systemd/network", rootfs);
    if std::path::Path::new(&networkd_dir).exists() {
        let mut conf = String::from("[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n");
        if let Some(ref d) = dns {
            conf.push_str(&dns_networkd_lines(d));
            conf.push_str("\n[DHCP]\nUseDNS=no\n");
        }
        match std::fs::write(format!("{}/eth0.network", networkd_dir), &conf) {
            Ok(()) => wrote_any = true,
            Err(e) => errors.push(format!("systemd-networkd: {}", e)),
        }
    }

    // Highest-priority (99-) eth0 stanza wins netplan's merge over the image's
    // default without deleting other NICs' configs; same filename the static
    // writer uses, so this overrides our own earlier static stanza.
    let netplan_dir = format!("{}/etc/netplan", rootfs);
    if std::path::Path::new(&netplan_dir).exists() {
        let mut conf = String::from("network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: true\n");
        if let Some(ref d) = dns {
            conf.push_str("      dhcp4-overrides:\n        use-dns: false\n");
            conf.push_str(&dns_netplan_block(d));
        }
        match std::fs::write(format!("{}/99-wolfstack-eth0.yaml", netplan_dir), &conf) {
            Ok(()) => wrote_any = true,
            Err(e) => errors.push(format!("netplan: {}", e)),
        }
    }

    let ifaces_path = format!("{}/etc/network/interfaces", rootfs);
    if std::path::Path::new(&ifaces_path).exists() {
        let mut conf = String::from("auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet dhcp\n");
        if let Some(ref d) = dns {
            // resolvconf/openresolv apply this over the lease's servers; on a
            // guest without either it is inert, which is why the explicit
            // resolv.conf write below is the one that actually guarantees it.
            conf.push_str(&dns_interfaces_lines(d));
        }
        match std::fs::write(&ifaces_path, &conf) {
            Ok(()) => wrote_any = true,
            Err(e) => errors.push(format!("interfaces: {}", e)),
        }
    }

    let nm_base = format!("{}/etc/NetworkManager", rootfs);
    if std::path::Path::new(&nm_base).exists() {
        let nm_dir = format!("{}/system-connections", nm_base);
        let _ = std::fs::create_dir_all(&nm_dir);
        let nm_file = format!("{}/eth0.nmconnection", nm_dir);
        let mut nm_conf = String::from(
            "[connection]\nid=eth0\ntype=ethernet\ninterface-name=eth0\nautoconnect=true\n\n[ipv4]\nmethod=auto\n");
        if let Some(ref d) = dns {
            nm_conf.push_str("ignore-auto-dns=true\n");
            nm_conf.push_str(&dns_nm_lines(d));
        }
        nm_conf.push_str("\n[ipv6]\nmethod=auto\n");
        match std::fs::write(&nm_file, &nm_conf) {
            Ok(()) => {
                let _ = std::fs::set_permissions(&nm_file, std::fs::Permissions::from_mode(0o600));
                wrote_any = true;
            }
            Err(e) => errors.push(format!("NetworkManager: {}", e)),
        }
    }

    // With an override in force, resolv.conf is written outright — dhclient
    // would otherwise replace it with the lease's servers on the next renewal
    // regardless of what the backend configs say.
    if let Some(ref d) = dns {
        write_rootfs_resolv_conf(&rootfs, d);
    }

    if !errors.is_empty() { Err(errors.join("; ")) }
    else if !wrote_any { Err("no supported in-container network backend found".to_string()) }
    else { Ok(()) }
}

/// What to do to the primary NIC's in-container config on a settings edit.
#[derive(Debug, PartialEq)]
enum PrimaryNicNetAction {
    Static { cidr: String, gateway: Option<String> },
    Dhcp,
    Skip,
}

/// Pure decision behind [`apply_primary_nic_in_container_config`] — extracted so
/// the static / DHCP-revert / skip branches are unit-testable without touching
/// the filesystem. Scoped to a real user bridge: an unset link, or the private
/// `lxcbr0` (WolfNet) bridge, is always `Skip`. `previously_static` gates the
/// DHCP revert so we only undo OUR own static pin, never clobbering a
/// DHCP container's custom config on an unrelated save.
fn decide_primary_nic_net_action(
    link: &str,
    ipv4: &str,
    ipv4_gw: &str,
    previously_static: bool,
) -> PrimaryNicNetAction {
    let link = link.trim();
    if link.is_empty() || link == "lxcbr0" {
        return PrimaryNicNetAction::Skip;
    }
    let norm = normalize_bridge_cidr(ipv4);
    if is_ipv4_cidr(&norm) {
        let g = ipv4_gw.trim();
        let gateway = if !g.is_empty() && g.parse::<std::net::Ipv4Addr>().is_ok() {
            Some(g.to_string())
        } else {
            None
        };
        PrimaryNicNetAction::Static { cidr: norm, gateway }
    } else if ipv4.trim().is_empty() && previously_static {
        PrimaryNicNetAction::Dhcp
    } else {
        PrimaryNicNetAction::Skip
    }
}

/// Resolve the in-container action for the primary NIC (eth0) on a settings
/// edit, or `None` when nothing should be written. Shared by the native and
/// Proxmox edit paths (which differ only in HOW they write — direct rootfs vs
/// `pct mount`). Returns `None` when WolfNet manages eth0, when there's no
/// index-0 NIC, or when the decision is `Skip`.
fn primary_nic_edit_action(
    new_nics: &[LxcNetInterface],
    current_nics: &[LxcNetInterface],
    wolfnet_active: bool,
) -> Option<PrimaryNicNetAction> {
    if wolfnet_active {
        return None;
    }
    let new0 = new_nics.iter().find(|n| n.index == 0)?;
    let cur0 = current_nics.iter().find(|n| n.index == 0);
    // Only act when the primary NIC's bridge/IP actually changed — otherwise an
    // unrelated save (memory, cores, notes…) would needlessly rewrite the
    // in-container config and could clobber a manual tweak the operator made.
    let changed = match cur0 {
        Some(b) => new0.link != b.link || new0.ipv4 != b.ipv4 || new0.ipv4_gw != b.ipv4_gw,
        None => true,
    };
    if !changed {
        return None;
    }
    let previously_static = cur0.map(|b| !b.ipv4.trim().is_empty()).unwrap_or(false);
    match decide_primary_nic_net_action(&new0.link, &new0.ipv4, &new0.ipv4_gw, previously_static) {
        PrimaryNicNetAction::Skip => None,
        action => Some(action),
    }
}

/// Self-heal a native LXC's in-container network config from its LXC config,
/// called just before `lxc-start`. A container created before WolfStack wrote
/// any in-container config (≤ v24.57.31) has the static IP in
/// `lxc.net.0.ipv4.address` but its image's default DHCP `eth0.network` /
/// interfaces inside — so it boots DHCP forever (wabil 2026-06-26, fresh trixie
/// LXC). Reconciling on every start fixes those existing containers without a
/// re-create, and keeps new ones correct too. Scoped to a static IPv4 on eth0's
/// real user bridge; DHCP, WolfNet (`lxcbr0` or a `.wolfnet/ip` marker), and
/// host mode are left alone. Idempotent.
fn reconcile_bridge_static_on_start(container: &str) {
    let path = format!("{}/{}/config", lxc_base_dir(container), container);
    let cfg = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let (mut link, mut ipv4, mut gw) = (String::new(), String::new(), String::new());
    for line in cfg.lines() {
        let Some((k, v)) = line.trim().split_once('=') else { continue };
        match k.trim() {
            "lxc.net.0.link" => link = v.trim().to_string(),
            "lxc.net.0.ipv4.address" => ipv4 = v.trim().to_string(),
            "lxc.net.0.ipv4.gateway" => gw = v.trim().to_string(),
            _ => {}
        }
    }
    // Only a static IPv4 on a real user bridge; never WolfNet / lxcbr0 / DHCP.
    if link.is_empty() || link == "lxcbr0" || !is_ipv4_cidr(&ipv4) {
        return;
    }
    if lxc_get_wolfnet_ip(container).is_some() {
        return;
    }
    let gw_opt = if gw.is_empty() { None } else { Some(gw.as_str()) };
    if let Err(e) = write_lxc_bridge_static_config(container, &ipv4, gw_opt) {
        warn!("{}: bridge static in-container config not reconciled on start: {}", container, e);
    }
}

/// Parse a Proxmox `net0:` value (e.g. `name=eth0,bridge=br0,ip=1.2.3.4/24,gw=1.2.3.1`)
/// into `(bridge, ip, gw)`; missing fields come back empty.
fn pct_net0_fields(net0: &str) -> (String, String, String) {
    let (mut bridge, mut ip, mut gw) = (String::new(), String::new(), String::new());
    for part in net0.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("bridge=") { bridge = v.to_string(); }
        else if let Some(v) = part.strip_prefix("ip=") { ip = v.to_string(); }
        else if let Some(v) = part.strip_prefix("gw=") { gw = v.to_string(); }
    }
    (bridge, ip, gw)
}

/// Proxmox counterpart of [`reconcile_bridge_static_on_start`]: parse the CT's
/// `net0:` line in `/etc/pve/lxc/<vmid>.conf` and, for a static IP on a real
/// user bridge, write the in-container config via `pct mount` before `pct start`
/// (the CT is stopped here, so the mount succeeds). Self-heals Proxmox CTs
/// created before WolfStack wrote in-container config.
fn reconcile_pct_bridge_static_on_start(vmid: &str) {
    let path = format!("/etc/pve/lxc/{}.conf", vmid);
    let cfg = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let Some(net0) = cfg.lines().find_map(|l| l.trim().strip_prefix("net0:")) else { return };
    let (bridge, ip, gw) = pct_net0_fields(net0);
    if bridge.is_empty() || bridge == "lxcbr0" || !is_ipv4_cidr(&ip) {
        return;
    }
    if lxc_get_wolfnet_ip(vmid).is_some() {
        return;
    }
    let gw_opt = if gw.is_empty() { None } else { Some(gw.as_str()) };
    if let Err(e) = pct_write_bridge_netconfig(vmid, Some(&ip), gw_opt) {
        warn!("{}: pct bridge static config not reconciled on start: {}", vmid, e);
    }
}

/// Native edit path: push the primary NIC's static IP (or a revert to DHCP)
/// into the container's own network config by writing its rootfs directly.
/// Returns true when it wrote a config (so the caller surfaces a restart hint).
fn apply_primary_nic_in_container_config(
    container: &str,
    new_nics: &[LxcNetInterface],
    current_nics: &[LxcNetInterface],
    wolfnet_active: bool,
) -> bool {
    match primary_nic_edit_action(new_nics, current_nics, wolfnet_active) {
        Some(PrimaryNicNetAction::Static { cidr, gateway }) => {
            if let Err(e) = write_lxc_bridge_static_config(container, &cidr, gateway.as_deref()) {
                warn!("{}: static IP in-container config not fully written: {}", container, e);
            }
            true
        }
        Some(PrimaryNicNetAction::Dhcp) => {
            if let Err(e) = write_lxc_bridge_dhcp_config(container) {
                warn!("{}: DHCP in-container config not fully written: {}", container, e);
            }
            true
        }
        _ => false,
    }
}

// ─── Common types ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerService {
    pub name: String,
    pub status: String, // "running" or "stopped"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub state: String,    // running, stopped, paused, etc.
    pub created: String,
    pub ports: Vec<String>,
    pub runtime: String,  // "docker" or "lxc"
    pub ip_address: String,
    pub autostart: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_usage: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<ContainerService>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gateway: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mac_address: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub network_name: String,
    /// Cumulative restart count reported by the runtime. Docker's
    /// `State.RestartCount` from inspect; populated for Docker
    /// containers. Always `None` for LXC (whose container-internal
    /// init handles its own restart accounting).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_count: Option<u64>,
    /// Per-mapping published status. One entry per requested host-port
    /// binding (`HostConfig.PortBindings`), cross-checked against what
    /// the Docker daemon actually published (`NetworkSettings.Ports`).
    /// When `published` is false, the operator's compose spec asked
    /// for a host port but the daemon never bound it — typically a
    /// host-port collision after a reboot, where the second container
    /// to start lost the race. The frontend renders unpublished
    /// mappings with a strikethrough + warning so the operator can
    /// see the silent failure that previously left the inbox blank.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_mappings: Vec<PortMapping>,
    /// Heuristic flag: this PVE container looks like a leftover "ghost" husk.
    /// When a CT is migrated/destroyed on a rebuilt cluster, its
    /// `/var/lib/lxc/<vmid>/` staging dir can linger and (on a pre-guard
    /// build) get auto-adopted into a fresh VMID with the OLD vmid stuck on as
    /// the hostname — leaving an empty container whose hostname is a bare
    /// number that isn't even its own VMID. We surface that as a UI badge so
    /// the operator can spot and remove these; never auto-deleted (a stopped
    /// empty CT could still be one the operator means to keep).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub possible_ghost: bool,
    /// This copy is a stopped WolfHA standby (`.wolfha-replica` marker).
    /// The UI badges it instead of showing a puzzling duplicate; it must
    /// never be started by hand while its primary is active elsewhere.
    #[serde(default)]
    pub ha_replica: bool,
}

/// One requested host→container port mapping, with the published flag
/// indicating whether Docker actually bound the host side. Modelled as
/// its own struct (rather than a tuple in `ports: Vec<String>`) so the
/// JSON wire format and the analyzer can both read structured fields
/// without re-parsing free-form strings like `"8080:80/tcp"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    /// Listen IP inside `HostConfig.PortBindings.*.HostIp`. Empty
    /// string and `0.0.0.0` both mean "all IPv4 addresses"; `::` means
    /// "all IPv6". We preserve the raw value so the frontend can
    /// distinguish `127.0.0.1:5432` from `0.0.0.0:5432`.
    pub host_ip: String,
    pub host_port: u16,
    pub container_port: u16,
    /// Lowercased: `"tcp"` or `"udp"` — taken from the
    /// `<port>/<proto>` key in PortBindings. Unknown protos pass
    /// through verbatim.
    pub proto: String,
    /// True iff `NetworkSettings.Ports."<container_port>/<proto>"`
    /// contains an entry whose `HostIp`/`HostPort` matches this
    /// requested mapping. False means the daemon never published the
    /// binding — the operator's URL pointing at this host port is
    /// effectively dead.
    pub published: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerStats {
    pub id: String,
    pub name: String,
    /// CPU usage on the "100% == one core" scale, matching `docker stats`:
    /// a container saturating four cores reports 400. Verified against
    /// docker 2026-07-27 — a two-core busy loop on a 24-core host reports
    /// 200.35%. Divide by `cpu_capacity_percent` for a share of what this
    /// container is actually allowed to use.
    pub cpu_percent: f64,
    /// What this container may use, on the same scale: its own CPU limit
    /// when one is set (`--cpus`, cpu-quota, cpuset), otherwise every host
    /// core. Without this the UI had no denominator and clamped usage at
    /// 100%, so one busy core on a 24-core host looked like a maxed-out
    /// container (klas 2026-07-27).
    #[serde(default = "default_cpu_capacity_percent")]
    pub cpu_capacity_percent: f64,
    /// Host core count, for cluster-wide totals.
    #[serde(default)]
    pub host_cpu_cores: u32,
    /// What the container is really holding: everything charged to its cgroup
    /// EXCEPT page cache the kernel can drop under pressure. See
    /// [`MemoryBreakdown`] for why that is not the same as what `docker stats`
    /// prints, and `memory_cache` below for the part that used to be folded in
    /// here.
    pub memory_usage: u64,
    pub memory_limit: u64,
    pub memory_percent: f64,
    /// Reclaimable file-backed page cache — real pages, but the kernel drops
    /// them under pressure rather than OOM-killing, so they are not "used" in
    /// any sense the operator cares about. Broken out so the UI can show it in
    /// its own colour instead of silently inflating the usage figure.
    #[serde(default)]
    pub memory_cache: u64,
    /// Anonymous memory — heap, stacks, anonymous mmap. The part a process
    /// genuinely cannot give back.
    #[serde(default)]
    pub memory_anon: u64,
    /// tmpfs / `/dev/shm` / shm segments. Swap-backed rather than file-backed,
    /// so it is NOT reclaimable cache and DOES count as used, even though the
    /// kernel files it under `file` in memory.stat.
    #[serde(default)]
    pub memory_shmem: u64,
    /// Kernel memory charged to this cgroup — slab, page tables, kernel
    /// stacks, socket buffers, percpu. Derived by subtraction so it stays
    /// correct as kernels add new charge types.
    #[serde(default)]
    pub memory_kernel: u64,
    pub net_input: u64,
    pub net_output: u64,
    pub block_read: u64,
    pub block_write: u64,
    pub pids: u32,
    pub runtime: String,
}

/// A container's memory split the way the kernel actually accounts it, rather
/// than the single number `docker stats` prints.
///
/// The bug this exists to kill: a container was reported at 8 GB when almost
/// all of it was page cache. Both runtimes derived "used" the way the Docker
/// CLI does — `memory.current - inactive_file` — and that leaves `active_file`
/// (page cache that has been touched more than once) counted as usage. On a
/// long-lived container with a hot file set that is unbounded, and it is what
/// put 8 GB on the dashboard. Measured on wolfdisplay against Docker 29.6.1,
/// cgroup v2: a fixture with 800 MiB of file cache and 400 MiB of tmpfs
/// reported `usage 1261211648 - inactive_file 828473344 = 412.7 MiB`, exactly
/// what `docker stats` printed.
///
/// Two traps, both verified on live cgroup data rather than assumed:
///
///  1. `shmem` (tmpfs, `/dev/shm`, shm segments) is counted INSIDE `file` in
///     cgroup v2 — kernel docs, admin-guide/cgroup-v2: file is "filesystem
///     data, including tmpfs and shared memory". Subtracting all of `file`
///     would therefore discount real tmpfs as cache and under-report, which is
///     the same bug pointing the other way. Reclaimable cache is `file - shmem`.
///  2. `shmem` is not on the file LRU lists at all — it ages on the anon lists
///     because it is swap-backed. Confirmed numerically on the fixture:
///     `inactive_file + active_file = 1153773568 = file - shmem`, to the byte.
///     The same identity holds at host scope (6701420544 vs 6701563904, a
///     140 KiB gap purely from reading the counters non-atomically) — which is
///     why `cache` below is computed from the single `file`/`shmem` pair
///     instead of by summing the two LRU lists.
///
/// So the over-report was exactly `active_file`, and the fix is to subtract the
/// whole reclaimable set. `shmem` keeps counting as used, as it should.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryBreakdown {
    /// `memory.current` — every byte charged to the cgroup.
    pub usage: u64,
    /// Anonymous memory (cgroup v2 `anon`, v1 `rss`).
    pub anon: u64,
    /// Reclaimable file-backed page cache: `file - shmem`.
    pub cache: u64,
    /// tmpfs / shm — real usage despite living under `file`.
    pub shmem: u64,
    /// Everything else charged here: slab, page tables, stacks, sockets.
    pub kernel: u64,
}

impl MemoryBreakdown {
    /// Build the split from the four raw cgroup numbers. `file` is the total
    /// including `shmem`, exactly as the kernel reports it — this does the
    /// subtraction so no caller has to remember to.
    ///
    /// Every arithmetic step saturates. The four values are read from separate
    /// counters that the kernel updates independently, so a sample can be
    /// mildly self-inconsistent (see the host-scope 140 KiB skew above);
    /// saturating means that shows up as a zero rather than a u64 wrapping to
    /// something absurd on a dashboard.
    pub fn from_cgroup(usage: u64, anon: u64, file: u64, shmem: u64) -> Self {
        // shmem is a subset of file; clamp so a skewed sample can't produce a
        // cache figure larger than the file total.
        let shmem = shmem.min(file);
        MemoryBreakdown {
            usage,
            anon,
            cache: file.saturating_sub(shmem),
            shmem,
            kernel: usage.saturating_sub(anon).saturating_sub(file),
        }
    }

    /// The figure to show and to alert on: everything charged to the cgroup
    /// except droppable page cache. Equivalently `anon + shmem + kernel`.
    pub fn used(&self) -> u64 {
        self.usage.saturating_sub(self.cache)
    }

    /// `used` as a percentage of `limit`; 0 when the container has no limit.
    pub fn used_percent(&self, limit: u64) -> f64 {
        if limit == 0 { return 0.0; }
        (self.used() as f64 / limit as f64) * 100.0
    }
}

/// Pull the four numbers [`MemoryBreakdown`] needs out of an already-parsed
/// `memory.stat` map, trying cgroup v2 key names first and falling back to
/// cgroup v1.
///
/// v1 names come from kernel docs, admin-guide/cgroup-v1/memory: `rss` is
/// "anonymous and swap cache" (the v2 `anon`), `cache` is "page cache" and
/// like v2's `file` it includes tmpfs/shmem. The `total_`-prefixed variants are
/// the hierarchy rollups and are the right ones when a container has child
/// cgroups. v1 does not document a `shmem` key; where the kernel does not emit
/// one we get 0, which means tmpfs stays inside `cache` and is counted as cache
/// rather than as used. That is the pre-existing v1 behaviour, it only affects
/// legacy cgroup v1 hosts, and it errs toward the smaller usage figure.
fn breakdown_from_stat_map(usage: u64, stat: &std::collections::HashMap<String, u64>) -> MemoryBreakdown {
    let pick = |v2: &str, v1: &str, v1_total: &str| -> u64 {
        stat.get(v2)
            .or_else(|| stat.get(v1_total))
            .or_else(|| stat.get(v1))
            .copied()
            .unwrap_or(0)
    };
    let anon = pick("anon", "rss", "total_rss");
    let file = pick("file", "cache", "total_cache");
    let shmem = pick("shmem", "shmem", "total_shmem");
    MemoryBreakdown::from_cgroup(usage, anon, file, shmem)
}

/// Parse a `memory.stat` body (`key value` per line) into a map. Splitting on
/// exact whitespace tokens keeps `inactive_file` from matching
/// `total_inactive_file`.
fn parse_cgroup_stat(text: &str) -> std::collections::HashMap<String, u64> {
    let mut map = std::collections::HashMap::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(k), Some(v)) = (parts.next(), parts.next())
            && let Ok(n) = v.parse::<u64>() {
                map.insert(k.to_string(), n);
            }
    }
    map
}

#[cfg(test)]
mod pick_cross_host_ip_tests {
    use super::pick_cross_host_ip;

    /// The live failure (Paul, 2026-08-14): iw-db-2's Galera adopt got the
    /// raw three-NIC list and rejected the whole string. The pick must skip
    /// the host-local lxcbr0 bridge (10.0.3.x) and return one address.
    #[test]
    fn multi_homed_list_yields_one_cross_host_address() {
        assert_eq!(
            pick_cross_host_ip("10.0.10.111, 10.0.3.3, 10.10.10.3", None).as_deref(),
            Some("10.0.10.111")
        );
        // Bridge listed first must still lose to a routable address.
        assert_eq!(
            pick_cross_host_ip("10.0.3.3, 10.10.10.3", None).as_deref(),
            Some("10.10.10.3")
        );
    }

    /// The WolfNet marker wins when its address is live — the overlay is
    /// the fabric WolfStack manages — but a stale marker naming an address
    /// the container doesn't hold must NOT be returned.
    #[test]
    fn wolfnet_marker_is_preferred_only_when_live() {
        assert_eq!(
            pick_cross_host_ip("10.0.10.111, 10.0.3.3, 10.10.10.3", Some("10.10.10.3")).as_deref(),
            Some("10.10.10.3")
        );
        assert_eq!(
            pick_cross_host_ip("10.0.10.111, 10.10.10.3", Some("192.168.9.9")).as_deref(),
            Some("10.0.10.111")
        );
    }

    /// The LXC listers annotate the overlay NIC and can leave CIDR
    /// suffixes — both forms the old wolfscale picker silently dropped.
    #[test]
    fn annotated_and_cidr_tokens_are_parsed() {
        assert_eq!(
            pick_cross_host_ip("10.0.3.3, 10.0.10.5/24 (wolfnet)", None).as_deref(),
            Some("10.0.10.5")
        );
        assert_eq!(
            pick_cross_host_ip("10.10.10.3/16", None).as_deref(),
            Some("10.10.10.3")
        );
    }

    /// All-host-local lists still return SOMETHING (the operator can see
    /// what was stored and fix it), and a bare hostname returns None so
    /// callers fall back to the raw string.
    #[test]
    fn degenerate_inputs_degrade_honestly() {
        assert_eq!(pick_cross_host_ip("10.0.3.3", None).as_deref(), Some("10.0.3.3"));
        assert_eq!(pick_cross_host_ip("db-node-2.internal", None), None);
        assert_eq!(pick_cross_host_ip("", None), None);
        assert_eq!(pick_cross_host_ip("-", None), None);
    }
}

#[cfg(test)]
mod memory_breakdown_tests {
    use super::*;

    /// Every number here was read off a live cgroup: a Docker 29.6.1 container
    /// on wolfdisplay (cgroup v2, systemd driver) holding 800 MiB of file cache
    /// and a 400 MiB tmpfs, while `docker stats` reported 412.9 MiB.
    const USAGE: u64 = 1261211648;
    const ANON: u64 = 118784;
    const FILE: u64 = 1258631168;
    const SHMEM: u64 = 419430400;
    const INACTIVE_FILE: u64 = 828473344;
    const ACTIVE_FILE: u64 = 10727424;

    #[test]
    fn tmpfs_is_counted_as_used_not_as_cache() {
        let b = MemoryBreakdown::from_cgroup(USAGE, ANON, FILE, SHMEM);
        // shmem lives inside `file`, but it is swap-backed and cannot simply be
        // dropped — so it must not land in `cache`.
        assert_eq!(b.cache, FILE - SHMEM);
        assert_eq!(b.shmem, SHMEM);
        assert!(b.used() > SHMEM, "400 MiB of tmpfs must still count as used");
    }

    #[test]
    fn used_is_anon_plus_shmem_plus_kernel() {
        let b = MemoryBreakdown::from_cgroup(USAGE, ANON, FILE, SHMEM);
        assert_eq!(b.used(), b.anon + b.shmem + b.kernel);
    }

    /// The regression this whole change exists for. The old figure —
    /// `usage - inactive_file`, what `docker stats` prints and what both
    /// runtimes used to report — over-counts by exactly `active_file`.
    #[test]
    fn the_over_report_was_exactly_active_file() {
        let b = MemoryBreakdown::from_cgroup(USAGE, ANON, FILE, SHMEM);
        let old_figure = USAGE - INACTIVE_FILE;
        assert_eq!(old_figure, 432738304, "matches the 412.9 MiB docker stats printed");
        assert_eq!(old_figure - b.used(), ACTIVE_FILE);
    }

    /// The file LRU lists account exactly the non-shmem page cache. Verified on
    /// the same fixture; `cache` is derived from `file - shmem` rather than this
    /// sum because the counters are read non-atomically and can skew.
    #[test]
    fn file_lru_lists_equal_file_minus_shmem() {
        assert_eq!(INACTIVE_FILE + ACTIVE_FILE, FILE - SHMEM);
    }

    #[test]
    fn cgroup_v1_key_names_are_understood() {
        let stat = parse_cgroup_stat("total_rss 1000\ntotal_cache 5000\ntotal_shmem 2000\n");
        let b = breakdown_from_stat_map(9000, &stat);
        assert_eq!(b.anon, 1000);
        assert_eq!(b.shmem, 2000);
        assert_eq!(b.cache, 3000); // cache - shmem
        assert_eq!(b.used(), 6000);
    }

    #[test]
    fn cgroup_v2_keys_win_over_v1_when_both_present() {
        // A v1 rollup key must never shadow the v2 key on a v2 host.
        let stat = parse_cgroup_stat("anon 10\nfile 20\nshmem 5\ntotal_rss 999\ntotal_cache 999\n");
        let b = breakdown_from_stat_map(40, &stat);
        assert_eq!(b.anon, 10);
        assert_eq!(b.cache, 15);
    }

    #[test]
    fn exact_key_match_only() {
        // `inactive_file` must not satisfy a lookup for `file`.
        let stat = parse_cgroup_stat("inactive_file 500\nactive_file 100\n");
        let b = breakdown_from_stat_map(500, &stat);
        assert_eq!(b.cache, 0, "neither LRU list is the `file` total");
    }

    /// A sample where the counters disagree must degrade to zeroes, never wrap.
    #[test]
    fn a_skewed_sample_cannot_underflow() {
        let b = MemoryBreakdown::from_cgroup(100, 50, 40, 900);
        assert_eq!(b.shmem, 40, "shmem is clamped to the file total");
        assert_eq!(b.cache, 0);
        assert_eq!(b.used(), 100);
        let b2 = MemoryBreakdown::from_cgroup(0, 500, 500, 0);
        assert_eq!(b2.kernel, 0);
        assert_eq!(b2.used(), 0);
    }

    #[test]
    fn no_limit_means_no_percentage() {
        let b = MemoryBreakdown::from_cgroup(USAGE, ANON, FILE, SHMEM);
        assert_eq!(b.used_percent(0), 0.0);
        // 402.5 MiB of a 4 GiB limit.
        let pct = b.used_percent(4 * 1024 * 1024 * 1024);
        assert!((pct - 9.83).abs() < 0.05, "got {}", pct);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerImage {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub size: String,
    pub created: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeStatus {
    pub name: String,
    pub installed: bool,
    pub running: bool,
    pub version: String,
    pub container_count: usize,
    pub running_count: usize,
}

// ─── Service detection inside containers ───

/// Detect Wolf ecosystem services (and web servers) running inside a container.
/// Returns a list of services found with their running status.
/// Cached front-end for probe_container_services — one exec per container
/// per PROBE_CACHE_TTL_SECS instead of one per enumeration (see the
/// per-container probe cache docs above).
fn detect_container_services(runtime: &str, name: &str) -> Vec<ContainerService> {
    let key = format!("{}:{}", runtime, name);
    {
        let cache = SERVICES_PROBE_CACHE.lock().unwrap();
        if let Some((val, ts)) = cache.get(&key)
            && ts.elapsed().as_secs() < PROBE_CACHE_TTL_SECS
        {
            return val.clone();
        }
    }
    // Cache miss. Only a UI-facing enumeration may pay for a fresh probe;
    // a background caller serves whatever is already known (a stale entry
    // if we have one, otherwise nothing) rather than spawning subprocesses
    // for a field it will never read. See the PROBE_ALLOWED docs above.
    if !probing_allowed() {
        return SERVICES_PROBE_CACHE
            .lock()
            .unwrap()
            .get(&key)
            .map(|(val, _)| val.clone())
            .unwrap_or_default();
    }
    let val = probe_container_services(runtime, name);
    let mut cache = SERVICES_PROBE_CACHE.lock().unwrap();
    cache.insert(key, (val.clone(), Instant::now()));
    probe_cache_prune(&mut cache);
    val
}

fn probe_container_services(runtime: &str, name: &str) -> Vec<ContainerService> {
    // Running-check must work on MINIMAL images too. Many app containers
    // (e.g. aonsoku: Alpine/BusyBox running nginx as PID 1 with `daemon off`)
    // have neither systemd nor pgrep, so a `systemctl is-active || pgrep`
    // check falsely reported the service as stopped even though `ps` clearly
    // showed it running (KO4BSR, Jul 2026). Fall back to scanning
    // /proc/<pid>/comm, which needs no extra tooling and matches the kernel's
    // process name — nginx keeps comm "nginx" even though its setproctitle
    // rewrites the cmdline to "nginx: master process ...".
    let script = r#"is_running() {
systemctl is-active --quiet "$1" 2>/dev/null && return 0
if command -v pgrep >/dev/null 2>&1; then pgrep -x "$1" >/dev/null 2>&1 && return 0; fi
for c in /proc/[0-9]*/comm; do
[ -r "$c" ] || continue
read cn < "$c" 2>/dev/null || continue
[ "$cn" = "$1" ] && return 0
done
return 1
}
for s in wolfproxy wolfserve wolfdisk wolfscale nginx apache2 httpd; do
if command -v "$s" >/dev/null 2>&1 || [ -f "/etc/systemd/system/${s}.service" ] || [ -f "/usr/lib/systemd/system/${s}.service" ]; then
if is_running "$s"; then
echo "${s}:running"
else
echo "${s}:stopped"
fi
fi
done"#;

    // BOUNDED. This probe execs INTO the container and walks /proc there,
    // so it inherits the container's health: one that is dying, wedged, or
    // mid-restart can hang the exec indefinitely, and `.output()` waits
    // forever. Every such hang permanently holds the child's pipe
    // descriptors and pins the calling worker thread — accumulate enough
    // and the process runs out of file descriptors, at which point
    // actix_server can no longer accept and the node drops off the
    // cluster (klas, klnet-12gb, 2026-08-12: repeated
    // "error accepting connection" at actix's 500ms EMFILE backoff).
    // A crash-looping service is exactly the supply of dying containers
    // that triggers it. Matches the coreutils-`timeout` pattern used by
    // every other probe in this file; 5s is far beyond a healthy walk.
    const PROBE_TIMEOUT_SECS: &str = "5";
    let output = match runtime {
        "docker" => Command::new("timeout")
            .args([PROBE_TIMEOUT_SECS, "docker", "exec", name, "sh", "-c", script])
            .output(),
        "lxc" => {
            let base = lxc_base_dir(name);
            let mut args: Vec<&str> = vec![PROBE_TIMEOUT_SECS, "lxc-attach"];
            if base != LXC_DEFAULT_PATH { args.extend_from_slice(&["-P", &base]); }
            args.extend_from_slice(&["-n", name, "--", "sh", "-c", script]);
            Command::new("timeout").args(&args).output()
        }
        _ => return vec![],
    };

    output.ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        // Normalize httpd → apache2 for display consistency
                        let svc_name = if parts[0] == "httpd" { "apache2" } else { parts[0] };
                        Some(ContainerService {
                            name: svc_name.to_string(),
                            status: parts[1].to_string(),
                        })
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

// ─── Detection ───

/// Check if KVM/QEMU is installed
pub fn kvm_installed() -> bool {
    // Check for qemu-system-x86_64, qemu-system-aarch64 (ARM/PiMox), qm (Proxmox), or virsh
    for bin in &["qemu-system-x86_64", "qemu-system-aarch64", "qm", "virsh"] {
        if Command::new("which").arg(bin).output()
            .map(|o| o.status.success()).unwrap_or(false) {
            return true;
        }
    }
    false
}

/// Check if Docker is installed and running
pub fn docker_status() -> RuntimeStatus {
    let installed = Command::new("which")
        .arg("docker")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let running = if installed {
        // Hard 10s cap: a wedged dockerd (socket accepts, daemon never
        // answers — classic right after a host reboot) made this hang
        // FOREVER, and with docker_status() on the startup path the
        // dashboard never bound at all (masterpier's athena, PVE 7,
        // 2026-07-03). timeout(1) is coreutils, same pattern as the
        // backup hooks / proxy_runtime.
        Command::new("timeout")
            .args(["10", "docker", "info", "--format", "{{.ServerVersion}}"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    } else {
        false
    };

    let version = if installed {
        Command::new("docker")
            .args(["--version"])
            .output()
            .ok()
            .map(|o| {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                // "Docker version 24.0.7, build ..." -> "24.0.7"
                s.split("version ").nth(1)
                    .and_then(|v| v.split(',').next())
                    .unwrap_or(&s)
                    .to_string()
            })
            .unwrap_or_default()
    } else {
        String::new()
    };

    let (container_count, running_count) = if running {
        let total = docker_list_all().len();
        let running_c = docker_list_running().len();
        (total, running_c)
    } else {
        (0, 0)
    };

    RuntimeStatus {
        name: "Docker".to_string(),
        installed,
        running,
        version,
        container_count,
        running_count,
    }
}

/// Check if LXC is installed and running
pub fn lxc_status() -> RuntimeStatus {
    let installed = Command::new("which")
        .arg("lxc-ls")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let running = installed; // LXC doesn't have a daemon — it's always "available" if installed

    let version = if installed {
        Command::new("lxc-ls")
            .arg("--version")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };

    let (container_count, running_count) = if installed {
        let all = lxc_list_all();
        let running_c = all.iter().filter(|c| c.state == "running").count();
        (all.len(), running_c)
    } else {
        (0, 0)
    };

    RuntimeStatus {
        name: "LXC".to_string(),
        installed,
        running,
        version,
        container_count,
        running_count,
    }
}

// ─── Docker operations ───

/// List all Docker containers
pub fn docker_list_all() -> Vec<ContainerInfo> {
    docker_list(true)
}

/// List running Docker containers
pub fn docker_list_running() -> Vec<ContainerInfo> {
    docker_list(false)
}

fn docker_list(all: bool) -> Vec<ContainerInfo> {
    let mut cmd = Command::new("docker");
    cmd.args(["ps", "--format", "{{.ID}}\\t{{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.State}}\\t{{.CreatedAt}}\\t{{.Ports}}\\t{{.Networks}}", "--no-trunc"]);
    if all {
        cmd.arg("-a");
    }

    let ps_out = match cmd.output() {
        Ok(o) => o,
        Err(_) => return vec![],
    };
    let ps_text = String::from_utf8_lossy(&ps_out.stdout);
    let lines: Vec<String> = ps_text.lines()
        .filter(|l| !l.is_empty())
        .map(|s| s.to_string())
        .collect();

    // Collect every container ID from the ps output, then run ONE
    // `docker inspect <id1> <id2> ...` call and index the result by ID.
    // This replaces the previous per-container-inspect loop (2 inspect
    // calls × N containers = 2N subprocesses) with exactly 2 docker
    // invocations total. Adam Cogswell's Proxmox box wasn't even
    // running a Docker fleet, but the same N+1 pattern affected any
    // user with more than a handful of containers — ~100ms per inspect
    // × 30 containers = 3s before this fix.
    let ids: Vec<String> = lines.iter()
        .filter_map(|line| line.split('\t').next().map(|s| s.to_string()))
        .filter(|id| !id.is_empty())
        .collect();
    let inspect_map: std::collections::HashMap<String, DockerInspectFields> =
        docker_batched_inspect(&ids);

    lines.iter()
        .map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            let cid = parts.first().copied().unwrap_or("").to_string();
            let name = parts.get(1).unwrap_or(&"").to_string();
            let state = parts.get(4).unwrap_or(&"").to_string();

            // Look up batched inspect data. Containers that race with
            // a `docker rm` between `docker ps` and the inspect call
            // simply have no entry — we fall through to defaults
            // identical to what the old per-container fallback would
            // have produced.
            let fields = inspect_map.get(&cid).cloned().unwrap_or_default();
            let raw_net_ips  = fields.network_ips.as_str();
            let raw_gateways = fields.network_gateways.as_str();
            let raw_macs     = fields.network_macs.as_str();
            let rootfs_raw   = fields.merged_dir.clone();
            let restart_policy = fields.restart_policy.clone();

                    // Parse WolfNet IP — override file takes priority, then Docker label
                    let wolfnet_ip = docker_effective_wolfnet_ip(&name);

                    // Parse bridge/network IP (only valid when running)
                    let bridge_ip = raw_net_ips.split_whitespace()
                        .find(|s| {
                            let iparts: Vec<&str> = s.split('.').collect();
                            iparts.len() == 4 && iparts.iter().all(|p| p.parse::<u8>().is_ok())
                        })
                        .unwrap_or("")
                        .to_string();

                    // Parse gateway and MAC
                    let container_gateway = raw_gateways.split_whitespace()
                        .find(|s| !s.is_empty() && *s != "<no value>")
                        .unwrap_or("")
                        .to_string();
                    let container_mac = raw_macs.split_whitespace()
                        .find(|s| !s.is_empty() && s.contains(':'))
                        .unwrap_or("")
                        .to_string();

                    // Display logic: WolfNet IP is primary if set
                    let ip = if let Some(ref wip) = wolfnet_ip {
                        if state == "running" && !bridge_ip.is_empty() && bridge_ip != *wip {
                            format!("{} (wolfnet)", wip)
                        } else {
                            wip.clone()
                        }
                    } else {
                        bridge_ip
                    };
                    // Parse autostart from combined inspect
                    let autostart = !restart_policy.is_empty() && restart_policy != "no";

                    // Parse rootfs from combined inspect
                    let docker_rootfs = if rootfs_raw.is_empty() || rootfs_raw.contains("no value") {
                        None
                    } else {
                        Some(rootfs_raw)
                    };
                    let (du, dt, ft) = docker_rootfs.as_ref()
                        .map(|p| get_path_disk_usage(p))
                        .unwrap_or((None, None, None));

                    // Detect Wolf services inside running containers
                    let services = if state == "running" {
                        detect_container_services("docker", &name)
                    } else {
                        vec![]
                    };

                    let net_name = parts.get(7).unwrap_or(&"").to_string();

                    ContainerInfo {
                        id: parts.first().unwrap_or(&"").to_string(),
                        name,
                        image: parts.get(2).unwrap_or(&"").to_string(),
                        status: parts.get(3).unwrap_or(&"").to_string(),
                        state: parts.get(4).unwrap_or(&"").to_string(),
                        created: parts.get(5).unwrap_or(&"").to_string(),
                        ports: parts.get(6).unwrap_or(&"")
                            .split(", ")
                            .filter(|p| !p.is_empty())
                            .map(|p| p.to_string())
                            .collect(),
                        runtime: "docker".to_string(),
                        ip_address: ip,
                        autostart,
                        hostname: String::new(),
                        storage_path: docker_rootfs,
                        disk_usage: du,
                        disk_total: dt,
                        fs_type: ft,
                        version: None,
                        services,
                gateway: container_gateway,
                mac_address: container_mac,
                network_name: net_name,
                restart_count: Some(fields.restart_count),
                port_mappings: fields.port_mappings.clone(),
                possible_ghost: false, // docker containers are never PVE husks
                ha_replica: false,
            }
        })
        .collect()
}

/// Fields we extract from `docker inspect` for the list view. Defaults
/// match what the old per-container template-format calls produced when
/// they failed (empty network info, no rootfs, no restart policy → maps
/// to "no autostart" in the UI).
#[derive(Default, Clone)]
struct DockerInspectFields {
    network_ips: String,       // space-separated, mirrors old template output
    network_gateways: String,
    network_macs: String,
    merged_dir: String,
    restart_policy: String,
    /// Cumulative number of times Docker has restarted this
    /// container since creation (`State.RestartCount` from inspect).
    /// The predictive restart-loop analyzer reads the delta of this
    /// across ticks to detect crash-loops.
    restart_count: u64,
    /// Per-binding requested-vs-published port map, derived from
    /// `HostConfig.PortBindings` cross-checked with
    /// `NetworkSettings.Ports`. Used to surface the silent
    /// host-port-conflict failure mode where Docker accepted the
    /// container's restart on boot but couldn't bind a published port
    /// because another container had already grabbed it.
    port_mappings: Vec<PortMapping>,
}

/// Run ONE `docker inspect <id1> <id2> ...` and parse the resulting JSON
/// array into a HashMap keyed by container ID. Replaces what used to be
/// 2 inspect subprocesses per container — for a 30-container fleet
/// that's 60 forks → 1 fork.
///
/// Falls back to an empty map when `docker inspect` fails outright (the
/// daemon's down). Per-container fallback isn't necessary because the
/// caller treats a missing entry as default-fields, which is the same
/// thing the old code did when an individual inspect failed.
fn docker_batched_inspect(ids: &[String])
    -> std::collections::HashMap<String, DockerInspectFields>
{
    let mut map = std::collections::HashMap::new();
    if ids.is_empty() { return map; }

    // One `docker network ls` up-front so parse_port_mappings can ask
    // "what driver is this network?" without an extra subprocess per
    // container. Empty map on failure → parse_port_mappings falls back
    // to its conservative empty-Ports heuristic. See the doc comment on
    // parse_port_mappings for why the driver matters (macvlan / ipvlan
    // never NAT, so the requested-vs-published port diff is a false
    // positive there even when the operator declared `ports:`).
    let net_drivers = docker_network_drivers();

    // Pass IDs as positional args. Avoid building a single space-joined
    // string — IDs never contain spaces but argv passing is the right
    // shape for the tool anyway.
    let mut cmd = Command::new("docker");
    cmd.arg("inspect");
    for id in ids { cmd.arg(id); }

    let out = match cmd.output() {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            warn!(
                "docker inspect (batched, {} ids) exited {}: {}",
                ids.len(), o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stderr).trim()
            );
            return map;
        }
        Err(e) => {
            warn!("docker inspect (batched, {} ids) spawn failed: {}", ids.len(), e);
            return map;
        }
    };

    let arr: Vec<serde_json::Value> = match serde_json::from_slice(&out.stdout) {
        Ok(a) => a,
        Err(e) => {
            warn!("docker inspect output JSON parse failed: {}", e);
            return map;
        }
    };

    for entry in arr {
        let id = entry.get("Id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if id.is_empty() { continue; }
        let mut fields = DockerInspectFields::default();

        // Network: walk every entry under .NetworkSettings.Networks
        // and concatenate IP/Gateway/MAC values space-separated, the
        // same shape the old `{{range .NetworkSettings.Networks}}…
        // {{end}}` Go template produced.
        if let Some(networks) = entry.pointer("/NetworkSettings/Networks").and_then(|v| v.as_object()) {
            let mut ips = Vec::new();
            let mut gws = Vec::new();
            let mut macs = Vec::new();
            for (_, n) in networks {
                if let Some(s) = n.get("IPAddress").and_then(|v| v.as_str()) && !s.is_empty() { ips.push(s.to_string()); }
                if let Some(s) = n.get("Gateway").and_then(|v| v.as_str()) && !s.is_empty() { gws.push(s.to_string()); }
                if let Some(s) = n.get("MacAddress").and_then(|v| v.as_str()) && !s.is_empty() { macs.push(s.to_string()); }
            }
            fields.network_ips = ips.join(" ");
            fields.network_gateways = gws.join(" ");
            fields.network_macs = macs.join(" ");
        }
        if let Some(s) = entry.pointer("/GraphDriver/Data/MergedDir").and_then(|v| v.as_str()) {
            fields.merged_dir = s.to_string();
        }
        if let Some(s) = entry.pointer("/HostConfig/RestartPolicy/Name").and_then(|v| v.as_str()) {
            fields.restart_policy = s.to_string();
        }
        if let Some(n) = entry.pointer("/State/RestartCount").and_then(|v| v.as_u64()) {
            fields.restart_count = n;
        }
        fields.port_mappings = parse_port_mappings(&entry, &net_drivers);
        map.insert(id, fields);
    }
    map
}

/// Run `docker network ls --format '{{.Name}}\t{{.Driver}}'` once and
/// return a `name → driver` map. Used by `parse_port_mappings` to skip
/// the requested-vs-published port diff for `macvlan` / `ipvlan`
/// networks, where Docker doesn't NAT and the diff is a false positive
/// even when compose declared `ports:`.
///
/// Empty map on failure (daemon down, permission denied, etc.) — the
/// caller treats a missing driver entry as "unknown" and falls back to
/// the conservative empty-Ports heuristic from v22.10.2. That heuristic
/// only catches the no-`ports:` macvlan case; the driver lookup is
/// what catches the with-`ports:` macvlan case (Frigate).
fn docker_network_drivers() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let out = match Command::new("docker")
        .args(["network", "ls", "--format", "{{.Name}}\t{{.Driver}}"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            warn!(
                "docker network ls exited {}: {}",
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stderr).trim()
            );
            return map;
        }
        Err(e) => {
            warn!("docker network ls spawn failed: {}", e);
            return map;
        }
    };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if line.is_empty() { continue; }
        let mut split = line.splitn(2, '\t');
        let name = split.next().unwrap_or("").trim().to_string();
        let driver = split.next().unwrap_or("").trim().to_string();
        if !name.is_empty() && !driver.is_empty() {
            map.insert(name, driver);
        }
    }
    map
}

/// Build the requested-vs-published port map for one inspected
/// container. Compares `HostConfig.PortBindings` (operator intent —
/// what compose / `docker run -p` asked for) against
/// `NetworkSettings.Ports` (daemon truth — what's actually bound).
///
/// Algorithm:
///   1. Walk PortBindings → list of (host_ip, host_port, cport, proto).
///   2. Walk NetworkSettings.Ports → set of bound (host_ip, host_port,
///      cport, proto) tuples (entries with `null` values mean Docker
///      knows about the container port but didn't bind a host port).
///   3. For each requested entry, mark `published=true` iff the
///      published set contains the same tuple.
///
/// IPv4/IPv6 dual-stack note: Docker on Linux publishes a `0.0.0.0`
/// host-port binding twice — once as `0.0.0.0` and once as `::` — and
/// reports both in `NetworkSettings.Ports`. PortBindings still only
/// has the single `0.0.0.0` request, so we treat any `::` published
/// entry whose port matches as a confirmation. Avoids false positives
/// where the requested IP is `0.0.0.0` and the published IP is `::`.
///
/// Host-mode / shared-namespace / direct-routing note: when Docker isn't
/// doing host-port NAT for the container, the requested-vs-published
/// diff is meaningless even when the operator declared `ports:` in
/// compose — the container is reachable on its own IP. We short-circuit
/// in these cases:
///
///   * `NetworkMode == "host"` — container shares the host's network
///     namespace, listens directly on its stack (e.g. AdGuard Home
///     binding :53 on the LAN).
///   * `NetworkMode == "container:<id>"` — container shares another
///     container's namespace, same property as host mode.
///   * `NetworkMode == "none"` — container has no network at all;
///     port-mapping declarations are vestigial.
///   * `NetworkMode` resolves (via `net_drivers`) to a network whose
///     driver is `macvlan` or `ipvlan` — Docker never NATs those, and
///     `NetworkSettings.Ports` may be either `{}` *or* a map of
///     `{"5000/tcp": null, ...}` depending on whether compose declared
///     `ports:`. The latter shape is byte-identical to a real
///     silent-publish failure on a bridge, so we *must* consult the
///     network driver to tell them apart. This is the v22.10.3 fix for
///     PapaSchlumpf's Frigate (macvlan + declared `ports:`).
///   * Fallback (driver unknown — `docker network ls` failed): if
///     `NetworkSettings.Ports` is *truly* empty `{}` on a user-defined
///     network, skip. Catches macvlan-without-`ports:` and is
///     conservative when the driver lookup misses. User-defined bridges
///     with port mapping populate `Ports` properly so the silent-publish
///     detector still works for those.
pub fn parse_port_mappings(
    inspect: &serde_json::Value,
    net_drivers: &std::collections::HashMap<String, String>,
) -> Vec<PortMapping> {
    use std::collections::HashSet;

    // ─── Network-mode short-circuits (see doc comment) ─────────────────
    let network_mode = inspect.pointer("/HostConfig/NetworkMode")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if network_mode == "host"
        || network_mode == "none"
        || network_mode.starts_with("container:")
    {
        return Vec::new();
    }

    let is_user_defined = !matches!(network_mode, "" | "default" | "bridge");
    if is_user_defined {
        // Authoritative check: ask Docker what driver this network uses.
        // macvlan / ipvlan don't NAT, so the requested-vs-published diff
        // is meaningless regardless of what `Ports` happens to look
        // like. This is what catches Frigate-on-macvlan with declared
        // `ports:`, where Docker emits `{"5000/tcp": null, ...}` —
        // identical in shape to a real silent-publish failure on a
        // bridge.
        if let Some(driver) = net_drivers.get(network_mode)
            && (driver == "macvlan" || driver == "ipvlan") {
                return Vec::new();
            }
        // Fallback for when the driver lookup missed (docker network ls
        // failed, or the network was removed between calls). Same
        // heuristic as v22.10.2: a truly empty `{}` Ports on a
        // user-defined network is almost certainly macvlan/ipvlan-
        // without-`ports:`. This branch does NOT catch the
        // declared-`ports:` macvlan case (those have null entries) —
        // that's the driver-map check above. We keep this fallback so
        // we degrade gracefully when the driver list is unavailable.
        let ports_truly_empty = match inspect.pointer("/NetworkSettings/Ports") {
            None | Some(serde_json::Value::Null) => true,
            Some(serde_json::Value::Object(o)) => o.is_empty(),
            _ => false,
        };
        if ports_truly_empty {
            return Vec::new();
        }
    }

    // Step 2: actual published bindings. Tuple is (host_ip, host_port,
    // container_port, proto). `host_ip == ""` means the published
    // record had no HostIp string (Docker shouldn't emit this in
    // practice, but be defensive).
    let mut published: HashSet<(String, u16, u16, String)> = HashSet::new();
    if let Some(net_ports) = inspect.pointer("/NetworkSettings/Ports").and_then(|v| v.as_object()) {
        for (cport_proto_key, host_list) in net_ports {
            let (cport, proto) = split_port_proto(cport_proto_key);
            let arr = match host_list.as_array() {
                Some(a) => a,
                None => continue, // null value = container port known but not bound
            };
            for binding in arr {
                let host_ip = binding.get("HostIp").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let host_port_str = binding.get("HostPort").and_then(|v| v.as_str()).unwrap_or("");
                let host_port: u16 = match host_port_str.parse() {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                published.insert((host_ip, host_port, cport, proto.clone()));
            }
        }
    }

    // Step 1 + 3: requested bindings, with published flag.
    let mut out: Vec<PortMapping> = Vec::new();
    if let Some(bindings) = inspect.pointer("/HostConfig/PortBindings").and_then(|v| v.as_object()) {
        for (cport_proto_key, host_list) in bindings {
            let (cport, proto) = split_port_proto(cport_proto_key);
            let arr = match host_list.as_array() {
                Some(a) => a,
                None => continue,
            };
            for binding in arr {
                let host_ip_raw = binding.get("HostIp").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let host_port_str = binding.get("HostPort").and_then(|v| v.as_str()).unwrap_or("");
                let host_port: u16 = match host_port_str.parse() {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                // Look for a matching published entry. Treat empty
                // and `0.0.0.0` requests as equivalent on the IPv4
                // side, and accept either `0.0.0.0` or `::` from the
                // published side as a match — Docker reports the
                // dual-stack pair and we don't want to flag that as
                // unpublished.
                let is_v4_wildcard = host_ip_raw.is_empty() || host_ip_raw == "0.0.0.0";
                let published_flag = published.iter().any(|(pip, pport, pcport, pproto)| {
                    pport == &host_port
                        && pcport == &cport
                        && pproto == &proto
                        && (
                            pip == &host_ip_raw
                            || (is_v4_wildcard && (pip == "0.0.0.0" || pip == "::" || pip.is_empty()))
                        )
                });
                out.push(PortMapping {
                    host_ip: host_ip_raw,
                    host_port,
                    container_port: cport,
                    proto: proto.clone(),
                    published: published_flag,
                });
            }
        }
    }
    out
}

/// Split a PortBindings map key like `"8080/tcp"` into
/// (container_port, proto). Defaults to `"tcp"` when the proto suffix
/// is absent (Docker always emits the suffix in modern versions, but
/// we accept the older `"8080"` form too). Bad keys produce
/// (0, "tcp") which is harmless — they'll never match a published
/// entry and the analyzer skips port 0.
fn split_port_proto(key: &str) -> (u16, String) {
    let mut split = key.splitn(2, '/');
    let port_str = split.next().unwrap_or("0");
    let proto = split.next().unwrap_or("tcp").to_ascii_lowercase();
    let port: u16 = port_str.parse().unwrap_or(0);
    (port, proto)
}

/// Number of CPUs visible to this host. Never returns 0 — a zero would turn
/// every capacity division into NaN/inf on the way to the UI.
pub fn host_cpu_cores() -> f64 {
    std::thread::available_parallelism()
        .map(|n| n.get() as f64)
        .unwrap_or(1.0)
        .max(1.0)
}

/// Serde default for configs written before `cpu_capacity_percent` existed:
/// one core, i.e. the old "100% is full" reading.
fn default_cpu_capacity_percent() -> f64 {
    100.0
}

/// Count the CPUs named by a cpuset string such as `"0-3,8"`.
/// Returns None for an empty set (= no cpuset restriction).
fn cpuset_core_count(cpuset: &str) -> Option<f64> {
    let mut count = 0u32;
    for part in cpuset.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((lo, hi)) => {
                let lo: u32 = lo.trim().parse().ok()?;
                let hi: u32 = hi.trim().parse().ok()?;
                if hi < lo {
                    return None;
                }
                count += hi - lo + 1;
            }
            None => {
                part.parse::<u32>().ok()?;
                count += 1;
            }
        }
    }
    if count == 0 { None } else { Some(count as f64) }
}

/// Effective CPU allowance, in cores, for every running Docker container.
///
/// One `docker inspect` for all of them rather than one per container. The
/// three limit mechanisms are checked in the order Docker applies them:
/// `--cpus` (NanoCpus), then an explicit quota/period pair, then `--cpuset-cpus`,
/// with the tightest winning. Absent all three the container may use the
/// whole host.
fn docker_cpu_limits() -> std::collections::HashMap<String, f64> {
    let mut limits = std::collections::HashMap::new();
    let host_cores = host_cpu_cores();

    let ids = match Command::new("docker").args(["ps", "-q"]).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).split_whitespace()
            .map(|s| s.to_string()).collect::<Vec<_>>(),
        Err(_) => return limits,
    };
    if ids.is_empty() {
        return limits;
    }

    let mut args = vec![
        "inspect".to_string(),
        "--format".to_string(),
        "{{.Name}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.CpuQuota}}|{{.HostConfig.CpuPeriod}}|{{.HostConfig.CpusetCpus}}".to_string(),
    ];
    args.extend(ids);
    let out = match Command::new("docker").args(&args).output() {
        Ok(o) => o,
        Err(_) => return limits,
    };

    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let f: Vec<&str> = line.split('|').collect();
        if f.len() < 5 {
            continue;
        }
        // docker reports names as "/name"
        let name = f[0].trim().trim_start_matches('/').to_string();
        if name.is_empty() {
            continue;
        }
        let mut cores = host_cores;

        // --cpus, expressed in billionths of a core
        if let Some(nano) = f[1].trim().parse::<i64>().ok().filter(|n| *n > 0) {
            cores = cores.min(nano as f64 / 1e9);
        }
        // --cpu-quota / --cpu-period (period 0 means Docker's 100ms default)
        if let Some(quota) = f[2].trim().parse::<i64>().ok().filter(|q| *q > 0) {
            let period = f[3].trim().parse::<i64>().unwrap_or(0);
            let period = if period > 0 { period as f64 } else { 100_000.0 };
            cores = cores.min(quota as f64 / period);
        }
        // --cpuset-cpus
        if let Some(set_cores) = cpuset_core_count(f[4]) {
            cores = cores.min(set_cores);
        }

        limits.insert(name, cores.max(0.01));
    }
    limits
}

/// Whether `<program> <args...> version` runs successfully.
fn compose_probe(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// How to invoke Docker Compose on this host: (program, leading args).
///
/// `docker compose` (the v2 CLI plugin) is preferred, falling back to the
/// standalone `docker-compose` binary. Every call site used to hardcode
/// `docker compose`, which on a Docker CLI without the plugin doesn't fail
/// cleanly — the CLI parses `-f` as a *global* flag and prints its own usage,
/// so JJ's Unraid install died with the baffling "unknown shorthand flag: 'f'
/// in -f" (2026-07-27). Unraid's Docker Compose Manager plugin installs the
/// standalone binary, which this now finds.
pub fn compose_command() -> Result<(String, Vec<String>), String> {
    if compose_probe("docker", &["compose"]) {
        return Ok(("docker".to_string(), vec!["compose".to_string()]));
    }
    if compose_probe("docker-compose", &[]) {
        return Ok(("docker-compose".to_string(), Vec::new()));
    }
    Err("Docker Compose is not available on this node — neither the \
         `docker compose` plugin nor a standalone `docker-compose` binary was \
         found. On Unraid, install the Docker Compose Manager plugin; on other \
         hosts install the docker-compose-plugin package. You can also install \
         this app with the Standard (Docker Run) option instead."
        .to_string())
}

/// A `Command` pre-loaded with the working compose invocation, ready for the
/// caller to append `-f <file> …` to.
pub fn compose_cmd() -> Result<Command, String> {
    let (program, base_args) = compose_command()?;
    let mut cmd = Command::new(program);
    cmd.args(base_args);
    Ok(cmd)
}

/// Read a running container's memory split straight from its cgroup.
///
/// The path comes from `/proc/<pid>/cgroup` rather than from a guessed layout:
/// Docker's systemd driver puts containers at
/// `/sys/fs/cgroup/system.slice/docker-<full-id>.scope` while the cgroupfs
/// driver uses `/sys/fs/cgroup/docker/<full-id>`, and reading the process's own
/// cgroup line is correct under both without having to detect which is in use.
/// Verified on wolfdisplay (systemd driver, cgroup v2): `/proc/<pid>/cgroup`
/// gave `0::/system.slice/docker-<id>.scope`, and that directory existed while
/// the cgroupfs path did not.
///
/// Returns `None` for a container with no usable cgroup (not running, or
/// cgroup v1 with a per-controller layout the single-line v2 form doesn't
/// cover) so the caller can fall back to whatever `docker stats` reported.
fn container_memory_from_pid(pid: u32) -> Option<MemoryBreakdown> {
    let cgroup_line = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;
    // cgroup v2 is a single `0::<path>` line. cgroup v1 emits one line per
    // controller (`<id>:memory:<path>`) — take the memory controller's path
    // there, and mount-relative paths resolve the same way underneath
    // /sys/fs/cgroup/memory.
    let (subdir, v1_memory) = cgroup_line
        .lines()
        .find_map(|l| {
            let mut f = l.splitn(3, ':');
            let _id = f.next()?;
            let controllers = f.next()?;
            let path = f.next()?;
            if controllers.is_empty() {
                Some((path.to_string(), false))
            } else if controllers.split(',').any(|c| c == "memory") {
                Some((path.to_string(), true))
            } else {
                None
            }
        })?;

    let base = if v1_memory {
        format!("/sys/fs/cgroup/memory{}", subdir)
    } else {
        format!("/sys/fs/cgroup{}", subdir)
    };

    let usage = std::fs::read_to_string(format!("{}/memory.current", base))
        .or_else(|_| std::fs::read_to_string(format!("{}/memory.usage_in_bytes", base)))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())?;
    let stat = parse_cgroup_stat(&std::fs::read_to_string(format!("{}/memory.stat", base)).ok()?);
    Some(breakdown_from_stat_map(usage, &stat))
}

/// Map container name → PID for every running container, in one `docker
/// inspect` call rather than one per container.
fn docker_container_pids() -> std::collections::HashMap<String, u32> {
    let mut map = std::collections::HashMap::new();
    let out = match Command::new("docker")
        .args(["ps", "-q", "--no-trunc"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return map,
    };
    let ids: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect();
    if ids.is_empty() { return map; }

    let mut args: Vec<String> = vec![
        "inspect".to_string(),
        "--format".to_string(),
        // Name carries a leading '/' from the daemon; strip it here so the key
        // matches the name `docker stats` prints.
        "{{.Name}} {{.State.Pid}}".to_string(),
    ];
    args.extend(ids);
    if let Ok(o) = Command::new("docker").args(&args).output() {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            let mut parts = line.split_whitespace();
            if let (Some(name), Some(pid)) = (parts.next(), parts.next())
                && let Ok(pid) = pid.parse::<u32>()
                    && pid > 0 {
                        map.insert(name.trim_start_matches('/').to_string(), pid);
                    }
        }
    }
    map
}

/// Get Docker container stats (one-shot)
pub fn docker_stats() -> Vec<ContainerStats> {
    let limits = docker_cpu_limits();
    let host_cores = host_cpu_cores();
    // `docker stats` reports memory as `memory.current - inactive_file`, which
    // still counts active page cache as usage — the 8 GB-that-was-all-cache
    // report. Read the real split from each container's cgroup and use that;
    // the CLI figures are still the source for CPU, net, block and PIDs.
    let pids = docker_container_pids();
    Command::new("docker")
        .args(["stats", "--no-stream", "--format", "{{.ID}}\\t{{.Name}}\\t{{.CPUPerc}}\\t{{.MemUsage}}\\t{{.MemPerc}}\\t{{.NetIO}}\\t{{.BlockIO}}\\t{{.PIDs}}"])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    let cpu_str = parts.get(2).unwrap_or(&"0%").trim_end_matches('%');
                    let mem_usage = parse_docker_mem(parts.get(3).unwrap_or(&"0B / 0B"));
                    let mem_perc = parts.get(4).unwrap_or(&"0%").trim_end_matches('%');
                    let net_io = parse_docker_io(parts.get(5).unwrap_or(&"0B / 0B"));
                    let block_io = parse_docker_io(parts.get(6).unwrap_or(&"0B / 0B"));
                    let name = parts.get(1).unwrap_or(&"").to_string();
                    let cores = limits.get(&name).copied().unwrap_or(host_cores);

                    // Prefer the cgroup breakdown. Fall back to the CLI's
                    // cache-inflated figure only when the cgroup is
                    // unreadable, so a container we can't introspect still
                    // reports something rather than zero.
                    let limit = mem_usage.1;
                    let breakdown = pids.get(&name).copied().and_then(container_memory_from_pid);
                    let (used, cache, anon, shmem, kernel, pct) = match breakdown {
                        Some(b) => (
                            b.used(), b.cache, b.anon, b.shmem, b.kernel,
                            b.used_percent(limit),
                        ),
                        None => (
                            mem_usage.0, 0, 0, 0, 0,
                            mem_perc.parse().unwrap_or(0.0),
                        ),
                    };

                    ContainerStats {
                        id: parts.first().unwrap_or(&"").to_string(),
                        name,
                        cpu_percent: cpu_str.parse().unwrap_or(0.0),
                        cpu_capacity_percent: cores * 100.0,
                        host_cpu_cores: host_cores as u32,
                        memory_usage: used,
                        memory_limit: limit,
                        memory_percent: pct,
                        memory_cache: cache,
                        memory_anon: anon,
                        memory_shmem: shmem,
                        memory_kernel: kernel,
                        net_input: net_io.0,
                        net_output: net_io.1,
                        block_read: block_io.0,
                        block_write: block_io.1,
                        pids: parts.get(7).unwrap_or(&"0").parse().unwrap_or(0),
                        runtime: "docker".to_string(),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Get Docker container logs
pub fn docker_logs(container: &str, lines: u32) -> Vec<String> {
    Command::new("docker")
        .args(["logs", "--tail", &lines.to_string(), "--timestamps", container])
        .output()
        .ok()
        .map(|o| {
            let mut logs: Vec<String> = Vec::new();
            // Docker logs go to both stdout and stderr
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            logs.extend(stdout.lines().map(|l| l.to_string()));
            logs.extend(stderr.lines().map(|l| l.to_string()));
            logs
        })
        .unwrap_or_default()
}

/// After `docker start` / `docker restart` the container has a brand-new
/// network namespace: its WolfNet /32 alias, src-hinted route, the host
/// /32 route and the permanent ARP entry all have to be laid down again.
/// `docker_start` always did this; `docker_restart` never did, so a
/// restarted container was unreachable on its WolfNet IP until the 60 s
/// reconcile tick got to it.
fn docker_reapply_wolfnet(container: &str) {
    // Override file first, then the wolfnet.ip label.
    if let Some(ip) = docker_effective_wolfnet_ip(container) {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let _ = docker_connect_wolfnet(container, &ip);
    }
}

/// Start a Docker container
pub fn docker_start(container: &str) -> Result<String, String> {
    let result = run_docker_cmd(&["start", container])?;

    docker_reapply_wolfnet(container);

    // This container has just taken a bridge address. If a stopped
    // container's DNAT still sends its own WolfNet IP there, that rule
    // now misdirects — drop it here rather than up to 60 s later.
    let net = docker_bridge_info(container);
    if !net.ip.is_empty() {
        let own = docker_effective_wolfnet_ip(container).unwrap_or_default();
        if let Some(wn) = wolfnet_network() {
            purge_foreign_dnat_pointing_at(&net.ip, &own, &wn);
        }
    }

    // WolfUSB: re-attach any USB devices assigned to this container
    let self_id = crate::agent::self_node_id();
    crate::wolfusb::on_container_started(container, "docker", &self_id);

    invalidate_docker_list_cache();
    Ok(result)
}

/// Stop a Docker container
pub fn docker_stop(container: &str) -> Result<String, String> {
    let result = run_docker_cmd(&["stop", container])?;
    // The DNAT deliberately STAYS: it is harmless until something else
    // takes this container's bridge address, and whatever does take it
    // clears the rule on its own start (purge_foreign_dnat_pointing_at),
    // as does the reconcile. Deleting it here would break the stop/start
    // half of a restart just as surely as doing it in the reconcile.
    // The IP inventory does change — this container stops being active.
    invalidate_wolfnet_ips_cache();
    invalidate_docker_list_cache();
    Ok(result)
}

/// Restart a Docker container
pub fn docker_restart(container: &str) -> Result<String, String> {
    let result = run_docker_cmd(&["restart", container])?;
    docker_reapply_wolfnet(container);
    let self_id = crate::agent::self_node_id();
    crate::wolfusb::on_container_started(container, "docker", &self_id);
    invalidate_docker_list_cache();
    Ok(result)
}

/// Remove a Docker container
pub fn docker_remove(container: &str) -> Result<String, String> {
    let result = run_docker_cmd(&["rm", "-f", container]);
    if result.is_ok() {
        invalidate_count_caches();
        invalidate_docker_list_cache();
    }
    result
}

/// Pause a Docker container
pub fn docker_pause(container: &str) -> Result<String, String> {
    let result = run_docker_cmd(&["pause", container])?;
    invalidate_docker_list_cache();
    Ok(result)
}

/// Unpause a Docker container
pub fn docker_unpause(container: &str) -> Result<String, String> {
    let result = run_docker_cmd(&["unpause", container])?;
    invalidate_docker_list_cache();
    Ok(result)
}

/// List Docker images
pub fn docker_images() -> Vec<ContainerImage> {
    Command::new("docker")
        .args(["images", "--format", "{{.ID}}\\t{{.Repository}}\\t{{.Tag}}\\t{{.Size}}\\t{{.CreatedAt}}"])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    ContainerImage {
                        id: parts.first().unwrap_or(&"").to_string(),
                        repository: parts.get(1).unwrap_or(&"").to_string(),
                        tag: parts.get(2).unwrap_or(&"").to_string(),
                        size: parts.get(3).unwrap_or(&"").to_string(),
                        created: parts.get(4).unwrap_or(&"").to_string(),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Update Docker container configuration
pub fn docker_update_config(container: &str, autostart: Option<bool>, memory_mb: Option<u64>, cpus: Option<f32>, wolfnet_ip: Option<String>) -> Result<String, String> {
    let mut messages = Vec::new();

    // Handle WolfNet IP change
    if let Some(ref wip) = wolfnet_ip {
        let ip = if wip.trim().is_empty() { None } else { Some(wip.trim()) };
        match docker_set_wolfnet_ip(container, ip) {
            Ok(msg) => messages.push(msg),
            Err(e) => return Err(format!("Failed to set WolfNet IP: {}", e)),
        }
    }

    let mut args = vec!["update"];

    // Autostart policy
    let policy_str;
    if let Some(autostart) = autostart {
        policy_str = if autostart { "unless-stopped" } else { "no" };
        args.push("--restart");
        args.push(policy_str);
    }

    // Memory limit
    let mem_str;
    if let Some(mem) = memory_mb {
        mem_str = format!("{}m", mem);
        args.push("--memory");
        args.push(&mem_str);
    }

    // CPU limit
    let cpus_str;
    if let Some(c) = cpus {
        cpus_str = format!("{}", c);
        args.push("--cpus");
        args.push(&cpus_str);
    }

    if args.len() > 1 {
        args.push(container);
        let result = run_docker_cmd(&args)?;
        messages.push(result);
    }

    if messages.is_empty() {
        return Ok("No changes requested".to_string());
    }

    // Drop the cached list so the next GET reflects the new config (otherwise
    // the UI re-renders the autostart checkbox / memory / cpus from the stale
    // 5-second cache and the user's change appears to revert on refresh).
    invalidate_docker_list_cache();

    // Post-verify the autostart change actually stuck. `docker update` can
    // exit 0 but leave the restart policy unchanged in surprising edge
    // cases — e.g. the container was just removed / renamed / handed off
    // to docker-compose which immediately rewrote the policy from its
    // compose file. If we claim success here and the inspect still shows
    // the old value, the UI re-fetch on the operator's next breath will
    // untick their checkbox and they'll rightly call the whole feature
    // broken (exactly what users reported against pre-v18.7.31). Verify
    // and surface a real error instead of silently lying.
    if let Some(requested) = autostart {
        let expected = if requested { "unless-stopped" } else { "no" };
        match Command::new("docker")
            .args(["inspect", "-f", "{{.HostConfig.RestartPolicy.Name}}", container])
            .output()
        {
            Ok(o) if o.status.success() => {
                let actual = String::from_utf8_lossy(&o.stdout).trim().to_string();
                // Equality check tolerates the other valid "on" policies
                // (always, on-failure) — if the operator previously set
                // one of those via CLI and we're enabling autostart, we
                // don't want to flap it to unless-stopped.
                let actual_means_on = !actual.is_empty() && actual != "no";
                let matches = if requested { actual_means_on } else { !actual_means_on };
                if !matches {
                    return Err(format!(
                        "docker update returned exit 0 but the restart policy \
                         for container '{}' is still '{}' (expected '{}'). \
                         This usually means the container is managed by \
                         docker-compose (whose policy takes priority on the \
                         next `up`), or the container was recreated between \
                         the update and the verify. Run \
                         `docker inspect -f '{{{{.HostConfig.RestartPolicy.Name}}}}' {}` \
                         to see the current state.",
                        container, actual, expected, container
                    ));
                }
            }
            Ok(o) => {
                // inspect failed — container probably gone. Don't claim success.
                return Err(format!(
                    "update applied but verification inspect failed: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                ));
            }
            Err(e) => {
                return Err(format!("update applied but verification inspect errored: {}", e));
            }
        }
    }

    Ok(messages.join("; "))
}

/// Recreate a Docker container with updated environment variables.
/// Uses rename-based safe approach: renames old container, creates new one,
/// and only removes the old one on success. On failure, renames back.
pub fn docker_recreate_with_env(container: &str, new_env: &[String]) -> Result<String, String> {
    // Validate env vars before doing anything destructive
    for e in new_env {
        if !e.contains('=') {
            return Err(format!("Invalid env var (missing '='): '{}'", e));
        }
        let key = &e[..e.find('=').unwrap()];
        if key.is_empty() {
            return Err(format!("Invalid env var (empty key): '{}'", e));
        }
        if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || key.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(true) {
            return Err(format!("Invalid env var key '{}' — must match [A-Za-z_][A-Za-z0-9_]*", key));
        }
    }
    // Fetch current inspect, override /Config/Env with the new env,
    // and delegate to the generalised recreate path — single
    // implementation for both "change env" and "edit raw inspect".
    let mut inspect = docker_inspect(container)?;
    if let Some(cfg) = inspect.pointer_mut("/Config")
        && let Some(obj) = cfg.as_object_mut() {
            let env_arr: Vec<serde_json::Value> = new_env.iter()
                .map(|e| serde_json::Value::String(e.clone()))
                .collect();
            obj.insert("Env".to_string(), serde_json::Value::Array(env_arr));
        }
    docker_recreate_from_inspect(container, &inspect)
}

/// Rebuild a Docker container from an edited inspect-JSON spec. Used
/// by the "Edit Raw Config" UI and by docker_recreate_with_env above.
/// Rename-based: old container is renamed to `<name>_wolfstack_old`,
/// a new container is created from the new spec, old is removed on
/// success OR renamed back on failure. Invalidates the list cache on
/// completion so the UI re-renders from the new state.
///
/// The set of inspect fields we actually honour — operator-editable:
///   /Config/Image               — target image (full name:tag)
///   /Config/Env                 — environment variables (the common
///                                 edit driver)
///   /Config/Cmd                 — command args after entrypoint
///   /Config/Entrypoint          — entrypoint override
///   /Config/User, WorkingDir    — user + workdir
///   /Config/Labels              — docker labels (dict)
///   /Config/Tty, OpenStdin      — tty / stdin flags
///   /HostConfig/Binds           — host-path bind mounts (this is what
///                                 users have been asking for — add a
///                                 new bind without recreating by hand)
///   /HostConfig/PortBindings    — published ports
///   /HostConfig/RestartPolicy   — restart policy
///   /HostConfig/Memory, NanoCpus— resource limits
///   /HostConfig/NetworkMode     — bridge / host / container: / custom
///   /HostConfig/CapAdd, CapDrop — capabilities
///   /HostConfig/Devices         — /dev pass-through
///   /HostConfig/ShmSize         — /dev/shm size
///   /Mounts                     — named volumes (type=volume)
///
/// Read-only inspect fields (State, NetworkSettings.IPAddress, Created
/// timestamps) are ignored — they aren't a container spec, they're a
/// container STATE, and editing them has no effect.
pub fn docker_recreate_from_inspect(container: &str, inspect: &serde_json::Value) -> Result<String, String> {

    let image = inspect.pointer("/Config/Image")
        .and_then(|v| v.as_str())
        .ok_or("Cannot determine container image")?
        .to_string();

    let name = inspect.pointer("/Name")
        .and_then(|v| v.as_str())
        .unwrap_or(container)
        .trim_start_matches('/')
        .to_string();

    // Extract restart policy (with retry count for on-failure)
    let restart_name = inspect.pointer("/HostConfig/RestartPolicy/Name")
        .and_then(|v| v.as_str())
        .unwrap_or("no")
        .to_string();
    let restart_retries = inspect.pointer("/HostConfig/RestartPolicy/MaximumRetryCount")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let restart_policy = if restart_name == "on-failure" && restart_retries > 0 {
        format!("on-failure:{}", restart_retries)
    } else {
        restart_name
    };

    // Extract TTY and stdin settings
    let tty = inspect.pointer("/Config/Tty").and_then(|v| v.as_bool()).unwrap_or(false);
    let open_stdin = inspect.pointer("/Config/OpenStdin").and_then(|v| v.as_bool()).unwrap_or(false);

    // Extract entrypoint, cmd, user, workdir
    let entrypoint: Vec<String> = inspect.pointer("/Config/Entrypoint")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    let cmd: Vec<String> = inspect.pointer("/Config/Cmd")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    let user = inspect.pointer("/Config/User")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let workdir = inspect.pointer("/Config/WorkingDir")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Extract port bindings
    let mut ports = Vec::new();
    if let Some(bindings) = inspect.pointer("/HostConfig/PortBindings").and_then(|v| v.as_object()) {
        for (container_port, host_list) in bindings {
            if let Some(arr) = host_list.as_array() {
                for binding in arr {
                    let host_ip = binding.get("HostIp").and_then(|v| v.as_str()).unwrap_or("");
                    let host_port = binding.get("HostPort").and_then(|v| v.as_str()).unwrap_or("");
                    if !host_port.is_empty() {
                        if host_ip.is_empty() || host_ip == "0.0.0.0" {
                            ports.push(format!("{}:{}", host_port, container_port));
                        } else {
                            ports.push(format!("{}:{}:{}", host_ip, host_port, container_port));
                        }
                    }
                }
            }
        }
    }

    // Extract volume mounts: HostConfig.Binds
    let volumes: Vec<String> = inspect.pointer("/HostConfig/Binds")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    // Extract named volumes from Mounts (type=volume)
    let mut named_volumes: Vec<String> = Vec::new();
    if let Some(mounts) = inspect.pointer("/Mounts").and_then(|v| v.as_array()) {
        for mount in mounts {
            if mount.get("Type").and_then(|v| v.as_str()) != Some("volume") { continue; }
            let vol_name = mount.get("Name").and_then(|v| v.as_str()).unwrap_or("");
            let destination = mount.get("Destination").and_then(|v| v.as_str()).unwrap_or("");
            let rw = mount.get("RW").and_then(|v| v.as_bool()).unwrap_or(true);
            if !vol_name.is_empty() && !destination.is_empty() {
                let mode = if rw { "" } else { ":ro" };
                let spec = format!("{}:{}{}", vol_name, destination, mode);
                if !volumes.iter().any(|v| v.starts_with(&format!("{}:", vol_name))) {
                    named_volumes.push(spec);
                }
            }
        }
    }

    // Extract labels
    let labels: Vec<(String, String)> = inspect.pointer("/Config/Labels")
        .and_then(|v| v.as_object())
        .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect())
        .unwrap_or_default();

    // Extract resource limits
    let memory = inspect.pointer("/HostConfig/Memory")
        .and_then(|v| v.as_i64())
        .filter(|&m| m > 0)
        .map(|m| format!("{}m", m / 1048576));

    let cpus = inspect.pointer("/HostConfig/NanoCpus")
        .and_then(|v| v.as_i64())
        .filter(|&c| c > 0)
        .map(|c| format!("{:.1}", c as f64 / 1e9));

    // Extract network mode
    let network_mode = inspect.pointer("/HostConfig/NetworkMode")
        .and_then(|v| v.as_str())
        .unwrap_or("default")
        .to_string();

    // Extract capabilities
    let cap_add: Vec<String> = inspect.pointer("/HostConfig/CapAdd")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    let cap_drop: Vec<String> = inspect.pointer("/HostConfig/CapDrop")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    // Extract devices
    let devices: Vec<String> = inspect.pointer("/HostConfig/Devices")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|dev| {
            let host = dev.get("PathOnHost").and_then(|v| v.as_str())?;
            let container = dev.get("PathInContainer").and_then(|v| v.as_str())?;
            Some(format!("{}:{}", host, container))
        }).collect())
        .unwrap_or_default();

    // Extract shm size
    let shm_size = inspect.pointer("/HostConfig/ShmSize")
        .and_then(|v| v.as_i64())
        .filter(|&s| s > 0 && s != 67108864); // 64MB is docker default

    // Check if container was running
    let was_running = inspect.pointer("/State/Running")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // 2. Stop the container and rename it (safe approach — don't delete yet)
    if was_running {
        let stop = Command::new("docker").args(["stop", container]).output()
            .map_err(|e| format!("Failed to stop container: {}", e))?;
        if !stop.status.success() {
            return Err(format!("Failed to stop container: {}", String::from_utf8_lossy(&stop.stderr).trim()));
        }
    }

    let backup_name = format!("{}_wolfstack_old", name);
    // Clean up any stale backup from a previous failed recreate
    let _ = Command::new("docker").args(["rm", "-f", &backup_name]).output();

    let rename = Command::new("docker").args(["rename", container, &backup_name]).output()
        .map_err(|e| format!("Failed to rename container: {}", e))?;
    if !rename.status.success() {
        // Try to restart if it was running
        if was_running { let _ = Command::new("docker").args(["start", container]).output(); }
        return Err(format!("Failed to rename container: {}", String::from_utf8_lossy(&rename.stderr).trim()));
    }

    // 3. Build create command with same config + new env
    let mut args = vec![
        "create".to_string(),
        "--name".to_string(), name.clone(),
    ];

    if tty { args.push("-t".to_string()); }
    if open_stdin { args.push("-i".to_string()); }

    args.push("--restart".to_string());
    args.push(restart_policy);

    if network_mode != "default" {
        args.push("--network".to_string());
        args.push(network_mode);
    }

    if let Some(ref mem) = memory {
        args.push("--memory".to_string());
        args.push(mem.clone());
    }
    if let Some(ref cpu) = cpus {
        args.push("--cpus".to_string());
        args.push(cpu.clone());
    }

    if !user.is_empty() {
        args.push("--user".to_string());
        args.push(user);
    }
    if !workdir.is_empty() {
        args.push("--workdir".to_string());
        args.push(workdir);
    }

    for cap in &cap_add {
        args.push("--cap-add".to_string());
        args.push(cap.clone());
    }
    for cap in &cap_drop {
        args.push("--cap-drop".to_string());
        args.push(cap.clone());
    }
    for dev in &devices {
        args.push("--device".to_string());
        args.push(dev.clone());
    }
    if let Some(shm) = shm_size {
        args.push("--shm-size".to_string());
        args.push(format!("{}", shm));
    }

    for vol in &volumes {
        args.push("-v".to_string());
        args.push(vol.clone());
    }
    for vol in &named_volumes {
        args.push("-v".to_string());
        args.push(vol.clone());
    }

    for (k, v) in &labels {
        args.push("--label".to_string());
        args.push(format!("{}={}", k, v));
    }

    for port in &ports {
        args.push("-p".to_string());
        args.push(port.clone());
    }

    // Env comes from /Config/Env on the provided inspect — either the
    // live container's (plain recreate) or the operator's edited spec
    // (Edit Raw Config path).
    let env_list: Vec<String> = inspect.pointer("/Config/Env")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    for e in &env_list {
        if !e.is_empty() {
            args.push("-e".to_string());
            args.push(e.clone());
        }
    }

    // Entrypoint (must come before image — only accepts the executable)
    if !entrypoint.is_empty() {
        args.push("--entrypoint".to_string());
        args.push(entrypoint[0].clone());
    }

    args.push(image);

    // Entrypoint args beyond [0] must be prepended to cmd
    // e.g. entrypoint=["/bin/sh","-c"] cmd=["echo hi"] → docker create --entrypoint /bin/sh IMAGE -c "echo hi"
    for ep_arg in entrypoint.iter().skip(1) {
        args.push(ep_arg.clone());
    }
    // Cmd args (come after image + entrypoint extra args)
    for c in &cmd {
        args.push(c.clone());
    }

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = Command::new("docker")
        .args(&args_ref)
        .output()
        .map_err(|e| format!("Failed to create container: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        // Rollback: rename the backup back to the original name
        warn!("Recreate failed, rolling back: {}", stderr);
        let _ = Command::new("docker").args(["rename", &backup_name, &name]).output();
        if was_running { let _ = Command::new("docker").args(["start", &name]).output(); }
        return Err(format!("Recreate failed (rolled back): {}", stderr));
    }

    // 4. Success — remove the old renamed container
    let _ = Command::new("docker").args(["rm", &backup_name]).output();

    // 5. Start the container if it was running before
    if was_running {
        docker_start(&name)?;
    }

    invalidate_docker_list_cache();
    Ok(format!("Container '{}' recreated from edited spec{}", name,
        if was_running { " and started" } else { "" }))
}

/// Inspect a Docker container and return raw JSON
pub fn docker_inspect(container: &str) -> Result<serde_json::Value, String> {
    let output = Command::new("docker")
        .args(["inspect", container])
        .output()
        .map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Failed to parse JSON: {}", e))?;

    // docker inspect returns an array, take the first element if possible
    let mut obj = if let Some(arr) = json.as_array() {
        arr.first().cloned().unwrap_or(json.clone())
    } else {
        json
    };

    // Inject WolfNet IP override from config file into the labels
    // so the frontend always sees the effective WolfNet IP
    if let Some(override_ip) = docker_get_wolfnet_ip(container)
        && let Some(labels) = obj.pointer_mut("/Config/Labels")
            && let Some(map) = labels.as_object_mut() {
                map.insert("wolfnet.ip".to_string(), serde_json::Value::String(override_ip));
            }

    Ok(obj)
}

/// Config file path for Docker WolfNet IP overrides
const DOCKER_WOLFNET_CONFIG: &str = "/etc/wolfstack/docker-wolfnet.json";

/// Get the WolfNet IP override for a Docker container from the config file
pub fn docker_get_wolfnet_ip(container: &str) -> Option<String> {
    let data = std::fs::read_to_string(DOCKER_WOLFNET_CONFIG).ok()?;
    let map: std::collections::HashMap<String, String> = serde_json::from_str(&data).ok()?;
    map.get(container).cloned().filter(|ip| !ip.is_empty())
}

/// Get the effective WolfNet IP for a Docker container (override file first, then label)
/// Validate that a Docker container is compatible with WolfNet assignment.
/// Returns error if the container has incompatible network configuration.
fn validate_docker_wolfnet_compatible(container: &str) -> Result<(), String> {
    // For Docker, WolfNet is applied via macvlan on wolfnet0, which is generally
    // compatible with most Docker network modes. However, we should check for
    // host network mode which is incompatible.
    if let Ok(output) = Command::new("docker")
        .args(["inspect", "--format", "{{.HostConfig.NetworkMode}}", container])
        .output()
    {
        let mode = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if mode == "host" {
            return Err(
                "Cannot assign WolfNet to container with host network mode. \
                 Host networking shares the host's network stack, so WolfNet (which needs \
                 its own network interface) cannot coexist with it. Use bridge or custom \
                 Docker network mode instead.".to_string()
            );
        }
    }
    Ok(())
}

pub fn docker_effective_wolfnet_ip(container: &str) -> Option<String> {
    // Check override file first
    if let Some(ip) = docker_get_wolfnet_ip(container) {
        return Some(ip);
    }
    // Fall back to Docker label. 10s cap — this runs per-container inside
    // the WolfNet IP sweep; unbounded, a wedged dockerd hung the sweep
    // (masterpier's athena, 2026-07-03).
    if let Ok(output) = Command::new("timeout")
        .args(["10", "docker", "inspect", "--format", "{{index .Config.Labels \"wolfnet.ip\"}}", container])
        .output()
    {
        let label = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !label.is_empty() && label != "<no value>" {
            return Some(label);
        }
    }
    None
}

/// Set or remove the WolfNet IP for a Docker container.
/// Persists to config file and applies live if the container is running.
pub fn docker_set_wolfnet_ip(container: &str, ip: Option<&str>) -> Result<String, String> {
    // Validate that we're not setting WolfNet IP on a container with incompatible network config
    if ip.is_some() && ip.map(|i| !i.trim().is_empty()).unwrap_or(false) {
        validate_docker_wolfnet_compatible(container)?;
    }

    // Read existing overrides
    let mut map: std::collections::HashMap<String, String> = std::fs::read_to_string(DOCKER_WOLFNET_CONFIG)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default();

    let old_ip = docker_effective_wolfnet_ip(container);

    match ip {
        Some(new_ip) if !new_ip.trim().is_empty() => {
            let new_ip = new_ip.trim();
            map.insert(container.to_string(), new_ip.to_string());

            // Save config
            let data = serde_json::to_string_pretty(&map).map_err(|e| e.to_string())?;
            std::fs::write(DOCKER_WOLFNET_CONFIG, data).map_err(|e| e.to_string())?;

            // Apply live if running: remove old routes, apply new
            if let Some(ref old) = old_ip
                && old != new_ip {
                    let _ = Command::new("ip").args(["route", "del", &format!("{}/32", old)]).output();
                    purge_container_dnat_for_wolfnet_ip(old);
                }
            // Connect to WolfNet (idempotent)
            let _ = docker_connect_wolfnet(container, new_ip);

            Ok(format!("WolfNet IP set to {}", new_ip))
        }
        _ => {
            // Remove override
            map.remove(container);

            let data = serde_json::to_string_pretty(&map).map_err(|e| e.to_string())?;
            std::fs::write(DOCKER_WOLFNET_CONFIG, data).map_err(|e| e.to_string())?;

            // Remove old route if any
            if let Some(ref old) = old_ip {
                let _ = Command::new("ip").args(["route", "del", &format!("{}/32", old)]).output();
            }

            Ok("WolfNet IP removed".to_string())
        }
    }
}

/// Remove a Docker image by ID or name
pub fn docker_remove_image(image: &str) -> Result<String, String> {

    run_docker_cmd(&["rmi", image])
}

fn run_docker_cmd(args: &[&str]) -> Result<String, String> {
    // BOUNDED, for the same reason as the service probe above: an
    // unbounded `.output()` on a wedged daemon or a container stuck in
    // teardown holds its pipe descriptors and its worker thread forever,
    // and enough of those exhaust the fd table until actix can no longer
    // accept connections. Every caller here is a short lifecycle verb
    // (start / stop / restart / pause / unpause / rm / rmi), so 120s is
    // well clear of even a long `--stop-timeout` grace period while still
    // turning a permanent hang into a reported error.
    const LIFECYCLE_TIMEOUT_SECS: &str = "120";
    let mut argv: Vec<&str> = vec![LIFECYCLE_TIMEOUT_SECS, "docker"];
    argv.extend_from_slice(args);
    let output = Command::new("timeout")
        .args(&argv)
        .output()
        .map_err(|e| format!("Failed to run docker: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else if output.status.code() == Some(124) {
        // coreutils `timeout` exit code for "killed on timeout".
        Err(format!(
            "docker {} timed out after {}s",
            args.first().copied().unwrap_or("command"), LIFECYCLE_TIMEOUT_SECS,
        ))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

// ─── LXC operations ───

/// List all LXC containers
pub fn lxc_list_all() -> Vec<ContainerInfo> {
    // Detect if Proxmox is available (pct command exists)
    let is_proxmox = Command::new("which").arg("pct").output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if is_proxmox {
        // Use pct list for Proxmox — only lists containers Proxmox knows about
        return pct_list_all();
    }

    // Fallback: native LXC — scan all registered storage paths
    let mut containers = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    for base_path in lxc_storage_paths() {
        // Names + state + pid + IP from `lxc-ls -f` where it works
        // (Debian/Ubuntu). Each tuple: (name, state, pid, ls_ip).
        let mut entries: Vec<(String, String, String, String)> = Vec::new();
        if let Ok(output) = Command::new("lxc-ls")
            .args(["-P", &base_path, "-f", "-F", "NAME,STATE,PID,RAM,IPV4"])
            .output()
        {
            for line in String::from_utf8_lossy(&output.stdout).lines().skip(1).filter(|l| !l.is_empty()) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let name = parts.first().unwrap_or(&"").to_string();
                if name.is_empty() { continue; }
                let state = parts.get(1).unwrap_or(&"STOPPED").to_lowercase();
                let pid = parts.get(2).unwrap_or(&"-").to_string();
                // Skip NAME(0), STATE(1), PID(2), RAM(3); the rest is IPV4.
                let ls_ip = parts.get(4..).map(|p| p.join(" ")).unwrap_or_default().replace('-', "");
                entries.push((name, state, pid, ls_ip));
            }
        }

        // Directory-scan fallback. `lxc-ls -f` (fancy mode) needs the python3
        // lxc bindings, which aren't installed by default on some distros
        // (notably Fedora) — there it prints nothing even though containers
        // exist on disk, so they never show in the UI. Any sub-directory that
        // holds a `config` file IS a container; pick up the ones lxc-ls missed
        // and read their state from lxc-info (a C binary — no python needed).
        if let Ok(dir) = std::fs::read_dir(&base_path) {
            let have: std::collections::HashSet<String> =
                entries.iter().map(|(n, _, _, _)| n.clone()).collect();
            for de in dir.flatten() {
                let nm = de.file_name().to_string_lossy().to_string();
                if nm.is_empty() || have.contains(&nm) { continue; }
                if !de.path().join("config").is_file() { continue; }
                let state = lxc_info_state(&base_path, &nm);
                entries.push((nm, state, String::new(), String::new()));
            }
        }

        for (name, state, pid, ls_ip) in entries {
            if !seen_names.insert(name.clone()) {
                continue; // already added from an earlier storage path
            }
            let pid_opt = if pid.is_empty() || pid == "-" { None } else { Some(pid.as_str()) };
            containers.push(build_lxc_container_info(&base_path, &name, &state, pid_opt, &ls_ip));
        }
    }
    containers
}

/// Query an LXC container's state with `lxc-info -sH` (a C binary — works where
/// `lxc-ls -f` can't, e.g. without python3-lxc). Returns a lowercase state such
/// as "running"/"stopped"; defaults to "stopped" if lxc-info can't answer.
fn lxc_info_state(base_path: &str, name: &str) -> String {
    Command::new("lxc-info")
        .args(["-P", base_path, "-n", name, "-sH"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "stopped".to_string())
}

/// Build the ContainerInfo for one native-LXC container. Shared by the `lxc-ls`
/// path and the directory-scan fallback so both produce identical records.
/// `pid`/`ls_ip` carry what lxc-ls reported (None/"" when the container was
/// found by directory scan instead).
fn build_lxc_container_info(
    base_path: &str,
    name: &str,
    state: &str,
    pid: Option<&str>,
    ls_ip: &str,
) -> ContainerInfo {
    let status = if state == "running" {
        match pid {
            Some(p) => format!("Running (PID {})", p),
            None => "Running".to_string(),
        }
    } else {
        "Stopped".to_string()
    };

    // IP address: try multiple methods
    let mut ip = String::new();

    if state == "running" {
        // Method 1: Use lxc-info which reliably reports IP
        if let Ok(info_out) = Command::new("lxc-info")
            .args(["-P", base_path, "-n", name, "-iH"])
            .output()
        {
            let info_ip = String::from_utf8_lossy(&info_out.stdout)
                .lines()
                .filter(|l| !l.contains(':')) // Filter out IPv6 addresses
                .collect::<Vec<_>>()
                .join(", ");
            if !info_ip.is_empty() && info_ip != "-" {
                ip = info_ip;
            }
        }
    }

    // Method 2: If still no IP, use what lxc-ls reported (after the RAM column).
    if ip.is_empty() && !ls_ip.trim().is_empty() {
        ip = ls_ip.trim().to_string();
    }

    // Read the LXC config once — used for the static-IP fallback here and
    // the autostart/hostname/gateway/MAC fields below.
    let config_path = format!("{}/{}/config", base_path, name);
    let config_content = std::fs::read_to_string(&config_path).unwrap_or_default();

    // Method 2.5: a stopped container still shows its configured static
    // address (CIDR suffix stripped) — parity with the PVE path, which
    // reads `ip=` from the config for stopped CTs. Without this a freshly
    // migrated/cloned container displays no IP at all until first start.
    if ip.is_empty()
        && let Some(addr) = config_content.lines()
            .find(|l| l.trim().starts_with("lxc.net.0.ipv4.address"))
            .and_then(|l| l.split('=').nth(1))
        {
            let addr = addr.trim().split('/').next().unwrap_or("").trim();
            if !addr.is_empty() {
                ip = addr.to_string();
            }
        }

    // Method 3: Check for WolfNet IP marker
    let wolfnet_ip_file = format!("{}/{}/.wolfnet/ip", base_path, name);
    let wolfnet_ip = std::fs::read_to_string(&wolfnet_ip_file)
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if !wolfnet_ip.is_empty() {
        if ip.is_empty() {
            ip = format!("{} (wolfnet)", wolfnet_ip);
        } else if !ip.contains(&wolfnet_ip) {
            ip = format!("{}, {} (wolfnet)", ip, wolfnet_ip);
        }
    }

    // Parse config for autostart, hostname, gateway, MAC
    let autostart = config_content.lines().any(|l| l.trim() == "lxc.start.auto = 1");
    let hostname = config_content.lines()
        .find(|l| l.trim().starts_with("lxc.uts.name"))
        .and_then(|l| l.split('=').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let lxc_gateway = config_content.lines()
        .find(|l| l.trim().starts_with("lxc.net.0.ipv4.gateway"))
        .and_then(|l| l.split('=').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let lxc_mac = config_content.lines()
        .find(|l| l.trim().starts_with("lxc.net.0.hwaddr"))
        .and_then(|l| l.split('=').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let lxc_link = config_content.lines()
        .find(|l| l.trim().starts_with("lxc.net.0.link"))
        .and_then(|l| l.split('=').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    // Get LXC rootfs path and disk usage
    let rootfs_path = format!("{}/{}/rootfs", base_path, name);
    let storage_path = if std::path::Path::new(&rootfs_path).exists() {
        Some(rootfs_path.clone())
    } else { None };
    let (du, dt, ft) = get_path_disk_usage(&rootfs_path);

    let version = lxc_read_os_version(&rootfs_path);

    // Detect Wolf services inside running containers
    let services = if state == "running" {
        detect_container_services("lxc", name)
    } else {
        vec![]
    };

    ContainerInfo {
        id: name.to_string(),
        name: name.to_string(),
        image: "lxc".to_string(),
        status,
        state: state.to_string(),
        created: String::new(),
        ports: vec![],
        runtime: "lxc".to_string(),
        ip_address: ip,
        autostart,
        hostname,
        storage_path,
        disk_usage: du,
        disk_total: dt,
        fs_type: ft,
        version,
        services,
        gateway: lxc_gateway,
        mac_address: lxc_mac,
        network_name: lxc_link,
        restart_count: None,  // LXC: see ContainerInfo::restart_count doc
        port_mappings: Vec::new(),
        // Native-LXC builder (non-PVE listing path) — ghost-husk detection is
        // a PVE-adoption artifact, so never flagged here.
        possible_ghost: false,
        ha_replica: std::path::Path::new(&format!("{}/{}/{}", base_path, name, crate::wolfha::REPLICA_MARKER)).exists(),
    }
}

/// List LXC containers using Proxmox's pct command (filters out stale containers)
/// Run ONE `df -PT --block-size=1` for every running LXC container's
/// host-side rootfs path and return a map keyed by vmid. Avoids the
/// per-CT `pct exec <vmid> df` namespace-entry tax — same numbers
/// because the container's rootfs is mounted on the *host* at
/// /var/lib/lxc/<vmid>/rootfs before any `pct exec` ever runs.
///
/// Falls back to an empty map when df fails (PATH missing, no running
/// CTs, etc). Unparseable lines are skipped — the caller treats
/// missing entries as "no disk usage data" rather than failing.
///
/// `-P` enforces POSIX (no line wrapping for long device names),
/// `-T` adds the FS-type column, `--block-size=1` returns raw bytes.
fn host_df_for_lxc(vmids: &[String])
    -> std::collections::HashMap<String, (Option<u64>, Option<u64>, Option<String>)>
{
    let mut map = std::collections::HashMap::new();
    if vmids.is_empty() { return map; }

    // Build path → vmid lookup so we can match df output rows back to
    // VMIDs. df prints the mount point in the last column; if a CT's
    // rootfs is mounted directly on /var/lib/lxc/<vmid>/rootfs that
    // string is what df shows. Some PVE versions mount via
    // /var/lib/lxc/<vmid>/rootfs/ + bind, so we also accept the parent.
    let paths: Vec<(String, String)> = vmids.iter()
        .map(|v| (v.clone(), format!("/var/lib/lxc/{}/rootfs", v)))
        .filter(|(_, p)| std::path::Path::new(p).exists())
        .collect();
    if paths.is_empty() { return map; }

    let mut cmd = Command::new("df");
    cmd.args(["-PT", "--block-size=1"]);
    for (_, path) in &paths { cmd.arg(path); }

    let out = match cmd.output() {
        Ok(o) if o.status.success() || !o.stdout.is_empty() => o,
        // df returns nonzero when ANY path fails (e.g. unmounted) but
        // still writes valid rows for the others to stdout. Honour that
        // partial-success behaviour.
        Ok(o) => {
            warn!(
                "host_df_for_lxc: df exited {} with no stdout; falling back to empty map. stderr: {}",
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stderr).trim()
            );
            return map;
        }
        Err(e) => {
            warn!("host_df_for_lxc: df spawn failed: {}", e);
            return map;
        }
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    // df -PT header: Filesystem Type 1B-blocks Used Available Capacity Mounted on
    for line in stdout.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 7 { continue; }
        let fs    = cols[1].to_string();
        let total = cols[2].parse::<u64>().ok();
        let used  = cols[3].parse::<u64>().ok();
        // Mount column is the LAST column; -P prevents wrapping so the
        // last token is reliably the mount point.
        let mount = cols[cols.len() - 1];
        // Match the path back to its vmid. We compare the FULL mount
        // string (df doesn't trail-slash, neither does our format!).
        if let Some((vmid, _)) = paths.iter().find(|(_, p)| p == mount) {
            map.insert(vmid.clone(), (used, total, Some(fs)));
        }
    }
    map
}

/// Every value PVE allows in an LXC config's `lock:` property.
///
/// Source: PVE::LXC::Config, /usr/share/perl5/PVE/LXC/Config.pm:514-518 —
///   `enum => [qw(backup create destroyed disk fstrim migrate mounted rollback
///                snapshot snapshot-delete)]`
///
/// `pct list` prints the lock in a column between Status and Name, and only
/// for a guest that holds one, so the parser has to recognise the value to
/// know whether the third field is a lock or the first word of the name. The
/// hand-written list this replaces was missing `destroyed`, `disk`, `fstrim`
/// and `snapshot-delete` — a guest holding one of those reported its lock
/// string as its name.
const PVE_LXC_LOCKS: &[&str] = &[
    "backup", "create", "destroyed", "disk", "fstrim", "migrate", "mounted",
    "rollback", "snapshot", "snapshot-delete",
];

/// Locks worth reclaiming automatically once nothing owns them any more.
///
/// Deliberately a subset: `create`/`destroyed`/`migrate` guard a half-finished
/// guest that must stay untouchable until a human looks at it, and clearing
/// `disk`/`fstrim` buys nothing. These two are the pair the old listing-path
/// sweep already cleared — the fix is the gate in front of them, not a wider
/// reach.
const RECLAIMABLE_LXC_LOCKS: &[&str] = &["backup", "snapshot"];

/// One decoded Proxmox task id.
#[derive(Debug, PartialEq)]
struct PveUpid {
    pid: u32,
    /// Start time of `pid` in clock ticks since boot, as recorded when the
    /// task began. Pairing it with the pid is what makes a recycled pid fail.
    pstart: u64,
    /// The guest the task is operating on — empty for node-wide tasks.
    vmid: String,
}

/// Decode a Proxmox UPID.
///
/// Source: PVE::UPID::decode, /usr/share/perl5/PVE/UPID.pm:32-58 —
///   `UPID:$node:$pid:$pstart:$starttime:$dtype:$id:$user:`
/// with pid, pstart and starttime in hex and a trailing colon, so splitting on
/// ':' yields 9 parts with an empty last one.
fn decode_upid(upid: &str) -> Option<PveUpid> {
    let f: Vec<&str> = upid.split(':').collect();
    if f.len() != 9 || f[0] != "UPID" {
        return None;
    }
    Some(PveUpid {
        pid: u32::from_str_radix(f[2], 16).ok()?,
        pstart: u64::from_str_radix(f[3], 16).ok()?,
        vmid: f[6].to_string(),
    })
}

/// Field 22 (`starttime`) of `/proc/<pid>/stat`, in clock ticks since boot.
///
/// Source: PVE::ProcFSTools::read_proc_pid_stat,
/// /usr/share/perl5/PVE/ProcFSTools.pm:335-353 — its regex consumes
/// `pid (comm) `, then captures state (field 3) and ppid (4), skips 9 unnamed
/// fields (5-13), captures utime (14), stime (15), cutime (16), cstime (17),
/// skips 3 more (18-20) and the literal `0` at 21, and captures the next
/// number as `starttime` — field 22, which is what proc(5) documents.
fn pid_started_at(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // `comm` sits in parentheses and may itself contain spaces or a ')', so
    // the fields only become splittable after the LAST ')'. The first token
    // after it is field 3, putting field 22 at index 19.
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Is a Proxmox worker task still running for guest `vmid`?
///
/// PVE's own active-task index is the source of truth. Grammar, from
/// PVE::INotify::read_active_workers (/usr/share/perl5/PVE/INotify.pm:685-711):
///   `^(\S+)\s(0|1)(\s([0-9A-Za-z]{8})(\s(\s*\S.*))?)?$`
/// — UPID, a saved flag, then an OPTIONAL endtime and status. A line carrying
/// no endtime is a task PVE still believes is running.
///
/// The index alone is NOT enough: a worker killed outright never gets an
/// endtime written, so its line stays open forever. PVE does not trust the
/// index on its own either — PVE::ProcFSTools::check_process_running
/// (ProcFSTools.pm:358) requires the pid to still exist AND its start time to
/// equal the recorded `pstart`, which is also what rules out a recycled pid.
/// We apply the same pair.
///
/// The liveness half is not theoretical padding: wolf1's index carries 9
/// entries with no endtime, and checking them against /proc showed all 9 are
/// genuinely still-running console sessions (8 `vncshell`, 1 `vncproxy`), the
/// oldest open since January. Without the pid check we could not tell those
/// apart from abandoned ones — and with only the index we would call every
/// one of them a live owner.
///
/// A CLI `vzdump` registers here just like an API-launched one — verified on
/// wolf1 against the UPIDs of a scheduled run (2026-09-03).
fn pve_task_running_for_lxc(vmid: &str) -> bool {
    let Ok(raw) = std::fs::read_to_string("/var/log/pve/tasks/active") else {
        return false;
    };
    open_tasks_for_guest(&raw, vmid)
        .iter()
        .any(|t| pid_started_at(t.pid) == Some(t.pstart))
}

/// The still-open entries of an active-index body that belong to `vmid`.
///
/// "Still open" only means PVE has not written an endtime for the line — the
/// caller must confirm the process is actually alive, because a worker that
/// was killed never gets one written and its line stays here forever.
fn open_tasks_for_guest(active: &str, vmid: &str) -> Vec<PveUpid> {
    active
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let upid = fields.next()?;
            fields.next()?; // the saved flag
            if fields.next().is_some() {
                return None; // carries an endtime — finished
            }
            let task = decode_upid(upid)?;
            (task.vmid == vmid).then_some(task)
        })
        .collect()
}

/// Release a `backup`/`snapshot` lock left on a Proxmox container by a task
/// that died without clearing it.
///
/// This is the gated replacement for the unlock that used to sit inside
/// `pct_list_all`. That one fired from a read-only listing on every UI poll
/// and applied no staleness test at all, so it stripped the lock off each
/// container in the middle of its own scheduled `vzdump` (wolf1 nightly). The
/// lock is what stops a second vzdump, a migrate or a destroy starting on top
/// of a live backup, so tearing it off mid-run removed the only guard the
/// backup had.
///
/// Runs at boot and hourly alongside the staging and freeze sweeps.
///
/// LXC only, deliberately: `pct unlock` is the container command, and a stuck
/// lock on a QEMU guest is a separate job (`/etc/pve/qemu-server`, `qm unlock`,
/// and its own lock enum) that nothing here ever handled. Named for what it
/// does rather than "guest", which in Proxmox terms would promise VMs too.
pub fn sweep_stale_lxc_locks() {
    if !is_proxmox() {
        return;
    }
    // `/etc/pve/lxc` is this node's own directory in pmxcfs, so a container
    // that lives on another cluster node is not listed here.
    let Ok(dir) = std::fs::read_dir("/etc/pve/lxc") else { return };
    for entry in dir.flatten() {
        let file_name = entry.file_name().to_string_lossy().to_string();
        let Some(vmid) = file_name.strip_suffix(".conf") else { continue };
        let Ok(conf) = std::fs::read_to_string(entry.path()) else { continue };
        // Live section only — a `[snapshot_*]` block carries its own recorded
        // `lock:` value, which says nothing about the container right now.
        let Some(lock) = conf
            .lines()
            .take_while(|l| !l.trim_start().starts_with('['))
            .find_map(|l| l.trim().strip_prefix("lock:"))
            .map(|v| v.trim().to_string())
        else {
            continue;
        };
        if !RECLAIMABLE_LXC_LOCKS.contains(&lock.as_str()) {
            continue;
        }
        if pve_task_running_for_lxc(vmid) {
            continue; // owner is alive — the lock is doing its job
        }
        // No race against a backup that starts between the check and the
        // unlock: a task registers its UPID in the active index BEFORE it
        // touches the guest, so a lock can never exist without its task
        // already being visible above. wolf1's journal shows the order
        // plainly — "starting task UPID:...:vzdump:100:" is logged first,
        // "Starting Backup of VM 100 (lxc)" (which is what sets the lock)
        // after it. A lock with no live task in the index is therefore
        // abandoned, not about to be claimed.
        warn!(
            "lock sweep: container {} holds a '{}' lock but no Proxmox task owns it — releasing",
            vmid, lock
        );
        match Command::new("pct").args(["unlock", vmid]).output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => warn!(
                "lock sweep: `pct unlock {}` failed: {}",
                vmid,
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => warn!("lock sweep: could not run `pct unlock {}`: {}", vmid, e),
        }
    }
}

fn pct_list_all() -> Vec<ContainerInfo> {
    let output = match Command::new("pct").arg("list").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return vec![],
    };

    // Parse listing into (vmid, state, pct_name) tuples first
    // Header: VMID       Status     Lock         Name
    let entries: Vec<(String, String, String)> = output.lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let vmid = parts.first()?.to_string();
            let state = parts.get(1).unwrap_or(&"stopped").to_lowercase();
            // Detect lock field — if present it sits between status and name
            // e.g. "138    running    backup     myhost"
            let lock = parts.get(2).unwrap_or(&"").to_string();
            // Listing is a READ. It used to `pct unlock` any container it saw
            // holding a backup/snapshot lock, calling it "stale" with no
            // staleness test whatsoever — and this runs on every Containers
            // page poll. A container being backed up right now legitimately
            // holds `lock: backup`, so the sweep tore the lock off each guest
            // in the middle of its OWN vzdump (wolf1, every night: "Container
            // 100 has stale 'backup' lock — auto-unlocking" logged 48s into a
            // 88s vzdump). That lock is what stops a second vzdump, a migrate
            // or a destroy starting on top of a live backup. Recovery of a
            // genuinely abandoned lock now lives in `sweep_stale_lxc_locks`,
            // which checks whether the owning task is still alive first.
            let pct_name = if PVE_LXC_LOCKS.contains(&lock.as_str()) {
                parts.get(3..).map(|p| p.join(" ")).unwrap_or_default()
            } else {
                parts.get(2..).map(|p| p.join(" ")).unwrap_or_default()
            };
            Some((vmid, state, pct_name))
        })
        .collect();

    // Fetch all pct configs by reading /etc/pve/lxc/<vmid>.conf directly.
    // Same content `pct config <vmid>` returns — pmxcfs FUSE mount makes
    // this the source of truth — but with zero subprocess overhead. The
    // previous parallel-`pct config` approach paid ~300ms per CT (Perl
    // wrapper around the Proxmox API); on a 30-CT box that's ~9s of
    // forks even when fanned out. The filesystem path is microseconds
    // per file. Falls back to `pct config` per CT when /etc/pve/lxc
    // isn't readable (rare — same FUSE mount root needs to be available
    // for `pct config` to work too).
    //
    // Adam Cogswell context (2026-04-29): symptom was "Virtual machines
    // page spins forever" on his PVE box; same N+1 pattern exists for
    // LXC and was the next thing to fix.
    let pve_lxc_dir = "/etc/pve/lxc";
    let lxc_dir_readable = std::fs::read_dir(pve_lxc_dir).is_ok();
    let configs: Vec<String> = if lxc_dir_readable {
        entries.iter().map(|(vmid, _, _)| {
            let path = format!("{}/{}.conf", pve_lxc_dir, vmid);
            // Strip [snapshot_*] sections so per-snapshot values don't
            // bleed into the live view, mirroring pct config's default
            // (which only shows the live state without --snapshot).
            std::fs::read_to_string(&path)
                .map(|t| t.lines()
                    .take_while(|l| !l.trim_start().starts_with('['))
                    .collect::<Vec<_>>().join("\n"))
                .unwrap_or_default()
        }).collect()
    } else {
        // Fallback to the old subprocess path. Kept parallel because
        // when we DO need it, /etc/pve unreadable usually means the
        // pmxcfs is in a degraded state and every Perl fork is going
        // to be slow — at least let them race.
        std::thread::scope(|s| {
            let handles: Vec<_> = entries.iter().map(|(vmid, _, _)| {
                let vmid = vmid.clone();
                s.spawn(move || {
                    Command::new("pct").args(["config", &vmid]).output().ok()
                        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                        .unwrap_or_default()
                })
            }).collect();
            handles.into_iter().map(|h| h.join().unwrap_or_default()).collect()
        })
    };

    // Batched host-side `df` for every running CT in ONE invocation.
    // Each running LXC container's rootfs is mounted on the *host* at
    // /var/lib/lxc/<vmid>/rootfs (PVE convention) BEFORE pct-exec
    // crosses the namespace boundary — so calling df from the host on
    // those paths returns identical numbers without entering any
    // container's namespace.
    //
    // This replaces what used to be `timeout 5 pct exec <vmid> df`
    // per running CT: ~500ms each (namespace entry + Perl-shell
    // wrapper). On a 30-CT box that was ~15s wall-clock under the
    // parallel scope below; now it's one ~50ms df call. Adam Cogswell
    // 2026-04-29 follow-up: "lxc containers are a bit slow".
    let running_vmids: Vec<String> = entries.iter()
        .filter(|(_, state, _)| state == "running")
        .map(|(vmid, _, _)| vmid.clone())
        .collect();
    let host_df_map: std::collections::HashMap<String, (Option<u64>, Option<u64>, Option<String>)> =
        host_df_for_lxc(&running_vmids);

    // Now process each container in parallel for remaining details
    std::thread::scope(|s| {
        let handles: Vec<_> = entries.iter().zip(configs.iter()).map(|((vmid, state, pct_name), cfg_text)| {
            let vmid = vmid.clone();
            let state = state.clone();
            let pct_name = pct_name.clone();
            let cfg_text = cfg_text.clone();
            let df_for_this = host_df_map.get(&vmid).cloned();
            s.spawn(move || {
                let status = if state == "running" {
                    let pid = Command::new("timeout").args(["5", "lxc-info", "-n", &vmid, "-pH"])
                        .output().ok()
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                        .unwrap_or("-".to_string());
                    format!("Running (PID {})", pid)
                } else {
                    "Stopped".to_string()
                };

                // Get IP addresses for running containers
                let mut ip = String::new();
                if state == "running"
                    && let Ok(info_out) = Command::new("timeout").args(["5", "lxc-info", "-n", &vmid, "-iH"])
                        .output()
                    {
                        let info_ip = String::from_utf8_lossy(&info_out.stdout)
                            .lines()
                            .filter(|l| !l.contains(':'))
                            .collect::<Vec<_>>()
                            .join(", ");
                        if !info_ip.is_empty() && info_ip != "-" {
                            ip = info_ip;
                        }
                    }

                // Parse config for hostname, autostart, rootfs, gateway, MAC
                let mut hostname = pct_name.clone();
                let mut autostart = false;
                let mut rootfs_storage = String::new();
                let mut pve_gateway = String::new();
                let mut pve_mac = String::new();
                let mut pve_bridge = String::new();
                for cline in cfg_text.lines() {
                    let cline = cline.trim();
                    if cline.starts_with("hostname:") {
                        hostname = cline.split(':').nth(1).unwrap_or("").trim().to_string();
                    } else if cline.starts_with("onboot:") {
                        autostart = cline.split(':').nth(1).unwrap_or("").trim() == "1";
                    } else if cline.starts_with("rootfs:") {
                        rootfs_storage = cline.split_once(':').map(|x| x.1).unwrap_or("").trim().to_string();
                    }
                    if cline.starts_with("net") && cline.contains('=') {
                        let net_value = cline.split_once(':').map(|x| x.1).unwrap_or("").trim();
                        for part in net_value.split(',') {
                            let part = part.trim();
                            if part.starts_with("ip=") && ip.is_empty() {
                                let configured_ip = part.trim_start_matches("ip=");
                                if !configured_ip.is_empty() && configured_ip != "dhcp" {
                                    ip = configured_ip.to_string();
                                }
                            } else if part.starts_with("gw=") && pve_gateway.is_empty() {
                                pve_gateway = part.trim_start_matches("gw=").to_string();
                            } else if part.starts_with("hwaddr=") && pve_mac.is_empty() {
                                pve_mac = part.trim_start_matches("hwaddr=").to_string();
                            } else if part.starts_with("bridge=") && pve_bridge.is_empty() {
                                pve_bridge = part.trim_start_matches("bridge=").to_string();
                            }
                        }
                    }
                }

                // WolfNet IP
                let wolfnet_ip_file = format!("/var/lib/lxc/{}/.wolfnet/ip", vmid);
                let wolfnet_ip = std::fs::read_to_string(&wolfnet_ip_file)
                    .ok()
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                if !wolfnet_ip.is_empty() {
                    if ip.is_empty() {
                        ip = format!("{} (wolfnet)", wolfnet_ip);
                    } else if !ip.contains(&wolfnet_ip) {
                        ip = format!("{}, {} (wolfnet)", ip, wolfnet_ip);
                    }
                }

                let rootfs_path = format!("/var/lib/lxc/{}/rootfs", vmid);
                let storage_path = if !rootfs_storage.is_empty() {
                    let storage_name = rootfs_storage.split(':').next().unwrap_or("").to_string();
                    if storage_name.is_empty() { None } else { Some(storage_name) }
                } else if std::path::Path::new(&rootfs_path).exists() {
                    Some(rootfs_path.clone())
                } else { None };

                let (du, dt, ft) = if state == "running" {
                    // Pre-fetched in a single host-side `df` call — no
                    // subprocess spawn here, no namespace entry. Falls
                    // back to (None, None, None) when the rootfs path
                    // wasn't readable (rare — rootfs missing on a
                    // running CT means PVE is in a broken state).
                    df_for_this.unwrap_or((None, None, None))
                } else {
                    let alloc_bytes = parse_pct_rootfs_size(&rootfs_storage);
                    (Some(0), alloc_bytes, None)
                };

                let pve_rootfs_path = format!("/var/lib/lxc/{}/rootfs", vmid);
                let version = lxc_read_os_version(&pve_rootfs_path);

                let services = if state == "running" {
                    detect_container_services("lxc", &vmid)
                } else {
                    vec![]
                };

                // Ghost-husk heuristic: a hostname that's a bare VMID number
                // which ISN'T this CT's own VMID is the fingerprint of a
                // mis-adopted husk (old vmid carried over as the hostname). A
                // genuinely unnamed CT whose hostname equals its own vmid is
                // NOT flagged.
                //
                // The frontend HIDES flagged CTs from the list, so this gate is
                // a hard safety rule: a RUNNING container is in use and is never
                // a husk — never flag (and therefore never hide) one, even if
                // its hostname happens to be numeric. Only stopped CTs qualify.
                let possible_ghost = state != "running"
                    && is_pve_vmid_name(&hostname)
                    && hostname != vmid;
                ContainerInfo {
                    id: vmid.clone(),
                    name: vmid,
                    image: "lxc".to_string(),
                    status,
                    state,
                    created: String::new(),
                    ports: vec![],
                    runtime: "lxc".to_string(),
                    ip_address: ip,
                    autostart,
                    hostname,
                    storage_path,
                    disk_usage: du,
                    disk_total: dt,
                    fs_type: ft,
                    version,
                    services,
                    gateway: pve_gateway,
                    mac_address: pve_mac,
                    network_name: pve_bridge,
                    restart_count: None,  // PVE-LXC: see ContainerInfo::restart_count doc
                    port_mappings: Vec::new(),
                    possible_ghost,
                    ha_replica: false, // WolfHA replicas are native-only

                }
            })
        }).collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    })
}

/// Read OS version from an LXC container's rootfs (e.g. "Ubuntu 22.04.3 LTS")
fn lxc_read_os_version(rootfs_path: &str) -> Option<String> {
    // Try /etc/os-release first (standard on modern distros)
    let os_release_path = format!("{}/etc/os-release", rootfs_path);
    if let Ok(content) = std::fs::read_to_string(&os_release_path) {
        // Look for PRETTY_NAME first, then NAME + VERSION
        let mut pretty_name = None;
        let mut name = None;
        let mut version = None;
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("PRETTY_NAME=") {
                pretty_name = Some(line.trim_start_matches("PRETTY_NAME=")
                    .trim_matches('"').to_string());
            } else if line.starts_with("NAME=") {
                name = Some(line.trim_start_matches("NAME=")
                    .trim_matches('"').to_string());
            } else if line.starts_with("VERSION=") {
                version = Some(line.trim_start_matches("VERSION=")
                    .trim_matches('"').to_string());
            }
        }
        if let Some(pn) = pretty_name
            && !pn.is_empty() { return Some(pn); }
        if let (Some(n), Some(v)) = (name, version) {
            return Some(format!("{} {}", n, v));
        }
    }
    // Fallback: try /etc/lsb-release
    let lsb_path = format!("{}/etc/lsb-release", rootfs_path);
    if let Ok(content) = std::fs::read_to_string(&lsb_path) {
        for line in content.lines() {
            if line.starts_with("DISTRIB_DESCRIPTION=") {
                return Some(line.trim_start_matches("DISTRIB_DESCRIPTION=")
                    .trim_matches('"').to_string());
            }
        }
    }
    None
}

/// Get disk usage for a path using df (returns used_bytes, total_bytes)
/// Cached front-end for probe_path_disk_usage — one `df` per path per
/// PROBE_CACHE_TTL_SECS instead of one per container per enumeration
/// (see the per-container probe cache docs near the other caches).
fn get_path_disk_usage(path: &str) -> PathDiskUsage {
    {
        let cache = DISK_USAGE_CACHE.lock().unwrap();
        if let Some((val, ts)) = cache.get(path)
            && ts.elapsed().as_secs() < PROBE_CACHE_TTL_SECS
        {
            return val.clone();
        }
    }
    let val = probe_path_disk_usage(path);
    let mut cache = DISK_USAGE_CACHE.lock().unwrap();
    cache.insert(path.to_string(), (val.clone(), Instant::now()));
    probe_cache_prune(&mut cache);
    val
}

fn probe_path_disk_usage(path: &str) -> PathDiskUsage {
    // df -T --block-size=1 outputs: Filesystem Type 1B-blocks Used Available Use% Mounted
    if let Ok(out) = Command::new("df").args(["-T", "--block-size=1", path]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some(line) = text.lines().nth(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let fs_type = parts.get(1).map(|s| s.to_string());
            let total = parts.get(2).and_then(|s| s.parse::<u64>().ok());
            let used  = parts.get(3).and_then(|s| s.parse::<u64>().ok());
            return (used, total, fs_type);
        }
    }
    (None, None, None)
}

/// Parse the allocated rootfs size from a Proxmox rootfs config string.
/// Example input: "local-lvm:vm-101-disk-0,size=32G" → Some(34359738368)
fn parse_pct_rootfs_size(rootfs_cfg: &str) -> Option<u64> {
    // Look for "size=NNN[GMTK]" in the rootfs config
    for part in rootfs_cfg.split(',') {
        let p = part.trim();
        if p.starts_with("size=") {
            let size_str = p.trim_start_matches("size=");
            // Parse number + optional suffix (G, M, T, K)
            let (num_part, multiplier) = if size_str.ends_with('T') {
                (&size_str[..size_str.len()-1], 1024u64 * 1024 * 1024 * 1024)
            } else if size_str.ends_with('G') {
                (&size_str[..size_str.len()-1], 1024u64 * 1024 * 1024)
            } else if size_str.ends_with('M') {
                (&size_str[..size_str.len()-1], 1024u64 * 1024)
            } else if size_str.ends_with('K') {
                (&size_str[..size_str.len()-1], 1024u64)
            } else {
                (size_str, 1024u64 * 1024 * 1024) // Default to GiB
            };
            if let Ok(n) = num_part.parse::<f64>() {
                return Some((n * multiplier as f64) as u64);
            }
        }
    }
    None
}

/// Seed WOLFNET_ROUTES from this host's live container/VM IPs when the cache is
/// empty. Returns how many routes were added.
///
/// An empty cache is indistinguishable on the wire from "this host has no
/// container routes", and a receiving peer treats an announce as authoritative:
/// `wolfnet_routes_announce` drops every route pointing back at us. The cache
/// starts empty on any boot (/run is tmpfs) and — until the wolfnet.service
/// RuntimeDirectoryPreserve fix — after every upgrade, because stopping WolfNet
/// deleted its runtime directory. Seeding before we announce closes that window
/// whatever emptied it, rather than only at WolfStack startup.
///
/// The IP sweep shells out per container and can hang on a wedged dockerd
/// (masterpier's athena, v25.2.3), so it runs on its own thread under one hard
/// timeout: a stalled runtime must never block the caller.
pub fn seed_local_routes_if_empty() -> usize {
    if !WOLFNET_ROUTES.lock().unwrap().is_empty() {
        return 0;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(wolfnet_active_ips_cached());
    });
    let local_ips = match rx.recv_timeout(std::time::Duration::from_secs(15)) {
        Ok(ips) => ips,
        Err(_) => {
            tracing::warn!("WolfNet: route seed timed out (15s) — will retry on the next announce");
            return 0;
        }
    };
    if local_ips.len() <= 1 {
        return 0; // no container IPs to seed
    }
    let host_ip = &local_ips[0];
    let mut local_routes = std::collections::HashMap::new();
    for ip in &local_ips[1..] {
        if !ip.is_empty() && ip != host_ip {
            local_routes.insert(ip.clone(), host_ip.clone());
        }
    }
    if local_routes.is_empty() {
        return 0;
    }
    // Merge, not replace, so anything legitimately loaded from routes.json survives.
    let added = local_routes.len();
    update_wolfnet_routes(&local_routes);
    tracing::info!("WolfNet: seeded {} local container route(s) into an empty cache", added);
    added
}

/// Get LXC container stats
pub fn lxc_stats() -> Vec<ContainerStats> {
    let containers = lxc_list_all();
    containers.iter()
        .filter(|c| c.state == "running")
        .map(|c| {
            let info = lxc_info(&c.name);
            ContainerStats {
                id: c.name.clone(),
                name: c.name.clone(),
                cpu_percent: info.cpu_percent,
                cpu_capacity_percent: lxc_cpu_limit_cores(&c.name) * 100.0,
                host_cpu_cores: host_cpu_cores() as u32,
                memory_usage: info.memory.used(),
                memory_limit: info.memory_limit,
                memory_percent: info.memory.used_percent(info.memory_limit),
                memory_cache: info.memory.cache,
                memory_anon: info.memory.anon,
                memory_shmem: info.memory.shmem,
                memory_kernel: info.memory.kernel,
                net_input: info.net_input,
                net_output: info.net_output,
                block_read: 0,
                block_write: 0,
                pids: info.pids,
                runtime: "lxc".to_string(),
            }
        })
        .collect()
}

struct LxcDetailInfo {
    cpu_percent: f64,
    memory: MemoryBreakdown,
    memory_limit: u64,
    net_input: u64,
    net_output: u64,
    pids: u32,
}

fn lxc_info(name: &str) -> LxcDetailInfo {
    // Memory via lxc-cgroup (works on cgroup v1 and v2).
    //
    // Raw `memory.current` / `memory.usage_in_bytes` INCLUDES reclaimable page
    // cache, so a container that has read or written a lot of files reports a
    // usage that dwarfs — and can exceed — the host's own "used" figure (which
    // is `MemTotal - MemAvailable`, i.e. cache-excluded). That's how a
    // container showed 137 GB "used" on a host reporting only 80 GB used in
    // total.
    //
    // Subtracting only `inactive_file` — the cAdvisor / Kubernetes "working
    // set", and what `docker stats` prints — was not enough: it still counts
    // `active_file`, the page cache that has been touched more than once, and
    // on a long-lived container with a hot file set that grows without bound.
    // That is what put 8 GB of pure cache on the dashboard. [`MemoryBreakdown`]
    // subtracts the whole reclaimable set (`file - shmem`) and keeps tmpfs
    // counted as used; see its docs for the measurements behind that.
    //
    // One `memory.stat` read, not one per key: lxc-cgroup is a process spawn
    // each time and this runs for every container on every stats poll.
    let raw_usage = lxc_cgroup_read(name, "memory.current")
        .or_else(|| lxc_cgroup_read(name, "memory.usage_in_bytes"))
        .unwrap_or(0);
    let stat = lxc_cgroup_stat_map(name, "memory.stat");
    let memory = breakdown_from_stat_map(raw_usage, &stat);

    let mut memory_limit = lxc_cgroup_read(name, "memory.max")
        .or_else(|| lxc_cgroup_read(name, "memory.limit_in_bytes"))
        .unwrap_or(0);

    // Fallback: if cgroup reports 0 (unlimited/"max"), try Proxmox pct config
    if memory_limit == 0
        && let Ok(out) = Command::new("pct").args(["config", name]).output()
            && out.status.success() {
                let cfg = String::from_utf8_lossy(&out.stdout);
                for line in cfg.lines() {
                    let line = line.trim();
                    if line.starts_with("memory:")
                        && let Some(mb_str) = line.split(':').nth(1)
                            && let Ok(mb) = mb_str.trim().parse::<u64>() {
                                memory_limit = mb * 1024 * 1024; // MB → bytes
                            }
                }
            }

    // Fallback: if still 0, try reading /proc/meminfo inside the container
    if memory_limit == 0 {
        let base = lxc_base_dir(name);
        let mut attach_args: Vec<String> = vec!["5".to_string(), "lxc-attach".to_string()];
        if base != LXC_DEFAULT_PATH { attach_args.extend_from_slice(&["-P".to_string(), base.clone()]); }
        attach_args.extend_from_slice(&["-n".to_string(), name.to_string(), "--".to_string(), "cat".to_string(), "/proc/meminfo".to_string()]);
        if let Ok(out) = Command::new("timeout")
            .args(&attach_args)
            .output()
            && out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    if line.starts_with("MemTotal:") {
                        let kb: u64 = line.split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                        if kb > 0 {
                            memory_limit = kb * 1024; // kB → bytes
                        }
                        break;
                    }
                }
            }
    }

    // CPU — use lxc-attach to read /proc/stat quickly
    let cpu_percent = lxc_cpu_percent(name);

    // PID count
    let base_for_pid = lxc_base_dir(name);
    let mut pid_args: Vec<&str> = Vec::new();
    if base_for_pid != LXC_DEFAULT_PATH { pid_args.extend_from_slice(&["-P", &base_for_pid]); }
    pid_args.extend_from_slice(&["-n", name, "-pH"]);
    let pids = Command::new("lxc-info")
        .args(&pid_args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);

    // Network
    let (net_in, net_out) = read_container_net(name);

    LxcDetailInfo {
        cpu_percent,
        memory,
        memory_limit,
        net_input: net_in,
        net_output: net_out,
        pids,
    }
}

/// Get LXC container logs from journal
pub fn lxc_logs(container: &str, lines: u32) -> Vec<String> {
    let base = lxc_base_dir(container);
    let mut prefix: Vec<&str> = Vec::new();
    if base != LXC_DEFAULT_PATH { prefix.extend_from_slice(&["-P", &base]); }
    let lines_str = lines.to_string();
    let mut args = prefix.clone();
    args.extend_from_slice(&["-n", container, "--", "journalctl", "--no-pager", "-n", &lines_str]);
    // Try getting logs from lxc-attach dmesg or journal
    Command::new("lxc-attach")
        .args(&args)
        .output()
        .ok()
        .map(|o| {
            let out = String::from_utf8_lossy(&o.stdout);
            if out.trim().is_empty() {
                // Fallback: read from syslog
                let mut args2 = prefix.clone();
                args2.extend_from_slice(&["-n", container, "--", "cat", "/var/log/syslog"]);
                Command::new("lxc-attach")
                    .args(&args2)
                    .output()
                    .ok()
                    .map(|o2| {
                        String::from_utf8_lossy(&o2.stdout)
                            .lines()
                            .rev()
                            .take(lines as usize)
                            .map(|l| l.to_string())
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                out.lines().map(|l| l.to_string()).collect()
            }
        })
        .unwrap_or_default()
}

/// Set the root password on an LXC container
/// Writes password hash directly to rootfs /etc/shadow (no need to start container)
pub fn lxc_set_root_password(container: &str, password: &str) -> Result<String, String> {


    // Generate password hash using openssl
    let hash_output = Command::new("openssl")
        .args(["passwd", "-6", password])
        .output()
        .map_err(|e| format!("Failed to generate password hash: {}", e))?;

    if !hash_output.status.success() {
        return Err("Failed to generate password hash".to_string());
    }

    let hash = String::from_utf8_lossy(&hash_output.stdout).trim().to_string();

    // Find the rootfs — could be in default path or custom storage
    let shadow_path = format!("{}/{}/rootfs/etc/shadow", lxc_base_dir(container), container);
    
    if let Ok(shadow) = std::fs::read_to_string(&shadow_path) {
        let new_shadow: String = shadow.lines().map(|line| {
            if line.starts_with("root:") {
                let parts: Vec<&str> = line.splitn(3, ':').collect();
                if parts.len() >= 3 {
                    format!("root:{}:{}", hash, parts[2])
                } else {
                    format!("root:{}:19000:0:99999:7:::", hash)
                }
            } else {
                line.to_string()
            }
        }).collect::<Vec<_>>().join("\n");

        // Preserve trailing newline
        let new_shadow = if shadow.ends_with('\n') && !new_shadow.ends_with('\n') {
            format!("{}\n", new_shadow)
        } else {
            new_shadow
        };

        std::fs::write(&shadow_path, new_shadow)
            .map_err(|e| format!("Failed to write shadow file: {}", e))?;

        Ok("Root password set".to_string())
    } else {
        Err(format!("Shadow file not found at {}", shadow_path))
    }
}

/// Start an LXC container.
///
/// `lxc-start` daemonises and exits 0 *as soon as the fork completes* — it
/// does not wait for the container to actually reach RUNNING. So a
/// container that fails during init (missing kernel modules, AppArmor
/// blocks systemd, broken init binary, cgroup mismatch — common on Linux
/// Mint / Ubuntu Desktop LXC images) would otherwise return success and
/// silently die. We poll `lxc-info -s` until the state reaches RUNNING
/// or a short timeout, then surface the LXC log tail as the error so the
/// user can act on it.
pub fn lxc_start(container: &str) -> Result<String, String> {
    ensure_lxc_bridge();
    // On AppArmor-less LXC (Fedora/SELinux) an old `lxc.apparmor.profile` line
    // makes lxc-start reject the whole config — strip it first so the container
    // can actually start.
    heal_lxc_apparmor_config(container);
    if is_proxmox() {
        // Self-heal the in-container static config before boot (CT still stopped,
        // so pct mount works) — same rationale as the native path below.
        reconcile_pct_bridge_static_on_start(container);
        // pct start waits internally — its own exit code is authoritative.
        let msg = run_lxc_cmd(&["pct", "start", container])?;
        lxc_apply_wolfnet(container);
        lxc_post_start_setup(container);
        let self_id = crate::agent::self_node_id();
        crate::wolfusb::on_container_started(container, "lxc", &self_id);
        return Ok(msg);
    }

    let base = lxc_base_dir(container);
    let p_flag_args: Vec<String> = if base != LXC_DEFAULT_PATH {
        vec!["-P".into(), base.clone()]
    } else {
        Vec::new()
    };

    // Self-heal the in-container static-IP config from the LXC config BEFORE the
    // container boots, so its init comes up on the configured address instead of
    // DHCP'ing over it. Fixes containers created before WolfStack wrote any
    // in-container config (wabil 2026-06-26). No-op for DHCP / WolfNet / host.
    reconcile_bridge_static_on_start(container);

    // Kick off the start. lxc-start exits 0 once the daemon has forked.
    {
        let mut argv: Vec<String> = vec!["lxc-start".into()];
        argv.extend(p_flag_args.iter().cloned());
        argv.extend(["-n".into(), container.into()]);
        let argv_ref: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        run_lxc_cmd(&argv_ref)?;
    }

    // Poll lxc-info until state == RUNNING, up to ~8 s. Most healthy
    // containers reach RUNNING within 1–2 s; a misbehaving one stays
    // STOPPED or oscillates STARTING -> STOPPED.
    let mut last_state = String::new();
    for _ in 0..16 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let mut argv: Vec<String> = vec!["lxc-info".into()];
        argv.extend(p_flag_args.iter().cloned());
        argv.extend(["-n".into(), container.into(), "-s".into()]);
        let argv_ref: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        if let Ok(o) = Command::new(argv_ref[0]).args(&argv_ref[1..]).output() {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // Output: "State:          RUNNING\n"
            if let Some(state) = stdout.split(':').nth(1) {
                last_state = state.trim().to_string();
                if last_state == "RUNNING" { break; }
            }
        }
    }

    if last_state != "RUNNING" {
        // Surface the lxc log tail so the operator can diagnose. lxc-start
        // writes to {base}/{container}/{container}.log on most installs;
        // some distros use /var/log/lxc/{container}.log.
        let log_paths = [
            format!("{}/{}/{}.log", base, container, container),
            format!("/var/log/lxc/{}.log", container),
        ];
        let mut tail = String::new();
        for p in &log_paths {
            if let Ok(text) = std::fs::read_to_string(p) {
                let lines: Vec<&str> = text.lines().rev().take(20).collect();
                if !lines.is_empty() {
                    let mut rev: Vec<&str> = lines;
                    rev.reverse();
                    tail = rev.join("\n");
                    break;
                }
            }
        }

        let observed = if last_state.is_empty() { "(no state reported)".to_string() } else { last_state };
        let mut msg = format!(
            "lxc-start returned 0 but container did not reach RUNNING (state: {}). \
             Common causes on systemd-based containers (Linux Mint, Ubuntu Desktop): \
             AppArmor blocking init, missing kernel modules (overlay, loop), or \
             cgroup v1/v2 mismatch. Try `security.nesting = 1` and \
             `lxc.apparmor.profile = unconfined` in the container config.",
            observed
        );
        if !tail.is_empty() {
            msg.push_str("\n\n--- last lxc log lines ---\n");
            msg.push_str(&tail);
        }
        return Err(msg);
    }

    // Apply WolfNet IP if configured
    lxc_apply_wolfnet(container);
    lxc_post_start_setup(container);
    // WolfUSB: re-attach any USB devices assigned to this container
    let self_id = crate::agent::self_node_id();
    crate::wolfusb::on_container_started(container, "lxc", &self_id);

    Ok("Container started".to_string())
}

/// First-boot setup for LXC containers (runs once)
fn lxc_post_start_setup(container: &str) {
    let base = lxc_base_dir(container);
    let marker = format!("{}/{}/.wolfstack_setup_done", base, container);
    if std::path::Path::new(&marker).exists() { return; }

    // Build lxc-attach prefix args (with -P if non-default storage)
    let attach_prefix: Vec<&str> = if base != LXC_DEFAULT_PATH {
        vec!["-P", &base, "-n", container, "--"]
    } else {
        vec!["-n", container, "--"]
    };

    // Assign a unique lxcbr0 (10.0.3.x) bridge IP if not already configured by
    // WolfNet. SKIP this entirely for a container on a KNOWN non-lxcbr0 primary
    // bridge (Bridged-LAN / vSwitch mode, e.g. lanbr0): it gets its address
    // from that bridge — DHCP or a static `lxc.net.0.ipv4.address` — and must
    // NOT be flushed onto the lxcbr0 NAT subnet. Doing so silently "reverted" a
    // freshly-created LAN-bridged container to 10.0.3.x right after start, with
    // no restart (Gary KO4BSR 2026-06-22). lxcbr0 and unknown(None) proceed
    // unchanged, so existing NAT containers are byte-identical (Golden Rule).
    // Mirrors the same gate `lxc_apply_wolfnet` uses (v24.55.1).
    let wolfnet_file = format!("{}/{}/.wolfnet/ip", base, container);
    let on_custom_bridge = skip_standalone_wolfnet(lxc_primary_bridge(container).as_deref());
    if !std::path::Path::new(&wolfnet_file).exists() && !on_custom_bridge {
        let bridge_ip = assign_container_bridge_ip(container);

        // Apply immediately
        let mut args = attach_prefix.clone();
        args.extend_from_slice(&["ip", "addr", "flush", "dev", "eth0"]);
        let _ = Command::new("lxc-attach").args(&args).output();

        let mut args = attach_prefix.clone();
        let cidr = format!("{}/24", bridge_ip);
        args.extend_from_slice(&["ip", "addr", "add", &cidr, "dev", "eth0"]);
        let _ = Command::new("lxc-attach").args(&args).output();

        // Default route via lxcbr0 only when the container has no
        // vSwitch / public NIC with its own gateway (see
        // lxc_has_external_gateway).
        if !lxc_has_external_gateway(container) {
            let mut args = attach_prefix.clone();
            args.extend_from_slice(&["ip", "route", "replace", "default", "via", "10.0.3.1"]);
            let _ = Command::new("lxc-attach").args(&args).output();
        }

        // Restart networking (multi-distro)
        let mut args = attach_prefix.clone();
        args.extend_from_slice(&["sh", "-c",
            "systemctl restart systemd-networkd 2>/dev/null; \
             netplan apply 2>/dev/null; \
             /etc/init.d/networking restart 2>/dev/null; \
             true"]);
        let _ = Command::new("lxc-attach").args(&args).output();
    }

    // Wait for container networking to settle
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Install openssh-server
    let mut args = attach_prefix.clone();
    args.extend_from_slice(&["sh", "-c",
        "apt-get update -qq && apt-get install -y -qq openssh-server 2>/dev/null || \
         yum install -y openssh-server 2>/dev/null || \
         apk add openssh 2>/dev/null"]);
    let ssh_install = Command::new("lxc-attach").args(&args).output();

    let ssh_ok = ssh_install.as_ref().map(|o| o.status.success()).unwrap_or(false);

    if ssh_ok {
        // Enable root SSH login and start sshd
        let mut args = attach_prefix.clone();
        args.extend_from_slice(&["sh", "-c",
            "sed -i 's/#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null; \
             sed -i 's/#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null; \
             mkdir -p /run/sshd; \
             systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || /usr/sbin/sshd 2>/dev/null || true; \
             systemctl enable sshd 2>/dev/null || update-rc.d ssh enable 2>/dev/null || true"]);
        let _ = Command::new("lxc-attach").args(&args).output();

    } 

    // Create WolfStack MOTD — write directly to rootfs (avoids shell escaping issues)
    let motd_path = format!("{}/{}/rootfs/etc/motd", base, container);
    let _ = std::fs::write(&motd_path, r#"
 __        __    _  __ ____  _             _
 \ \      / /__ | |/ _/ ___|| |_ __ _  ___| | __
  \ \ /\ / / _ \| | |_\___ \| __/ _` |/ __| |/ /
   \ V  V / (_) | |  _|___) | || (_| | (__|   <
    \_/\_/ \___/|_|_| |____/ \__\__,_|\___|_|\_\

  Managed by WolfStack — wolf.uk.com
  Container powered by IntelligentWolf Ltd

"#);

    // Only mark done if SSH was installed successfully
    if ssh_ok {
        let _ = std::fs::write(&marker, "done");

    }
}

/// Stop an LXC container
/// True if the container is currently RUNNING on this host. The migrate
/// orchestrator records this before stopping the source so a rollback
/// only restarts a container that had actually been running.
pub fn lxc_is_running(container: &str) -> bool {
    if is_proxmox() {
        return Command::new("pct").args(["status", container]).output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase().contains("running"))
            .unwrap_or(false);
    }
    let base = lxc_base_dir(container);
    let mut args: Vec<&str> = Vec::new();
    if base != LXC_DEFAULT_PATH { args.extend_from_slice(&["-P", &base]); }
    args.extend_from_slice(&["-n", container, "-sH"]);
    Command::new("lxc-info").args(&args).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_uppercase().contains("RUNNING"))
        .unwrap_or(false)
}

pub fn lxc_stop(container: &str) -> Result<String, String> {
    if is_proxmox() {
        run_lxc_cmd(&["pct", "stop", container])
    } else {
        let base = lxc_base_dir(container);
        if base != LXC_DEFAULT_PATH {
            run_lxc_cmd(&["lxc-stop", "-P", &base, "-n", container])
        } else {
            run_lxc_cmd(&["lxc-stop", "-n", container])
        }
    }
}

/// True if `container` (a Proxmox VMID) is a Proxmox HA-managed resource.
///
/// HA resources are listed by `ha-manager config`; a container resource's
/// section id is `ct:<vmid>` (PVE prints it as either `ct:105` or `ct: 105`
/// depending on version, so we tolerate both). Absent/erroring `ha-manager`
/// (single-node PVE, or HA not configured) → not HA-managed.
fn lxc_is_ha_managed(container: &str) -> bool {
    let out = match Command::new("ha-manager").arg("config").output() {
        Ok(o) if o.status.success() => o,
        _ => return false,
    };
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("ct:") {
            let id: String = rest.trim().chars().take_while(|c| c.is_ascii_digit()).collect();
            if !id.is_empty() && id == container {
                return true;
            }
        }
    }
    false
}

/// Restart an LXC container.
///
/// For an HA-managed Proxmox container a hard `pct stop` makes the HA manager
/// record the resource's *desired* state as stopped; our subsequent `pct start`
/// then races the HA manager (which re-asserts stopped) and the container
/// stays down (wabil 2026-06-28). `pct reboot` restarts it in place WITHOUT
/// changing the HA desired state, so HA never tears it back down. Non-HA and
/// native-LXC containers keep the exact stop+start path they always used.
pub fn lxc_restart(container: &str) -> Result<String, String> {
    if is_proxmox() && lxc_is_ha_managed(container) {
        // `pct reboot` only works on a running container (it errors on a
        // stopped one); if it isn't running, just start it — that's the
        // HA-safe equivalent of "restart" and never leaves the resource down.
        if lxc_is_running(container) {
            return run_lxc_cmd(&["pct", "reboot", container]);
        }
        return lxc_start(container);
    }
    lxc_stop(container)?;
    lxc_start(container)
}

/// Freeze (pause) an LXC container.
///
/// On Proxmox we deliberately use `lxc-freeze` instead of `pct suspend`:
/// `pct suspend` tries to serialise the container's state to disk (and
/// is flagged experimental in the PVE docs — it routinely fails on
/// ZFS/LVM-thin storage with a bare "suspend not supported" and leaves
/// the container untouched, which is what customers were hitting when
/// the Freeze button "did nothing"). `lxc-freeze` uses the cgroup
/// freezer directly and pauses execution without touching disk — the
/// operation the UI actually means by "Freeze". Proxmox ships the
/// liblxc tools and its container runtime lives at the default LXC
/// path (`/var/lib/lxc/<vmid>`), so no `-P` override is needed.
pub fn lxc_freeze(container: &str) -> Result<String, String> {
    if is_proxmox() {
        run_lxc_cmd(&["lxc-freeze", "-n", container])
    } else {
        let base = lxc_base_dir(container);
        if base != LXC_DEFAULT_PATH {
            run_lxc_cmd(&["lxc-freeze", "-P", &base, "-n", container])
        } else {
            run_lxc_cmd(&["lxc-freeze", "-n", container])
        }
    }
}

/// Unfreeze an LXC container. Mirror of `lxc_freeze` — `lxc-unfreeze`
/// on both Proxmox and plain LXC so a container frozen via our Freeze
/// button can always be thawed the same way.
pub fn lxc_unfreeze(container: &str) -> Result<String, String> {
    if is_proxmox() {
        run_lxc_cmd(&["lxc-unfreeze", "-n", container])
    } else {
        let base = lxc_base_dir(container);
        if base != LXC_DEFAULT_PATH {
            run_lxc_cmd(&["lxc-unfreeze", "-P", &base, "-n", container])
        } else {
            run_lxc_cmd(&["lxc-unfreeze", "-n", container])
        }
    }
}

/// Destroy an LXC container
pub fn lxc_destroy(container: &str) -> Result<String, String> {
    lxc_stop(container).ok(); // Stop first, ignore errors
    // Strip an unparseable apparmor line first, or lxc-destroy can't even LOAD
    // the config to destroy it (Fedora/SELinux — wabil 2026-06-14).
    heal_lxc_apparmor_config(container);
    let result = if is_proxmox() {
        run_lxc_cmd(&["pct", "destroy", container])
    } else {
        let base = lxc_base_dir(container);
        if base != LXC_DEFAULT_PATH {
            run_lxc_cmd(&["lxc-destroy", "-P", &base, "-n", container])
        } else {
            run_lxc_cmd(&["lxc-destroy", "-n", container])
        }
    };
    if result.is_ok() {
        invalidate_count_caches();
        release_lxc_vlan_allocations(container);
        return result;
    }
    // Fallback for native LXC: if lxc-destroy still couldn't load/destroy the
    // container (another host-incompatible config key, a corrupt config, etc.),
    // remove the container directory directly so a broken container is never
    // permanently undeletable. Guard the name against path traversal — it must
    // be a bare directory name with an actual container config inside.
    if !is_proxmox()
        && !container.is_empty()
        && !container.contains('/')
        && container != "."
        && container != ".."
    {
        let dir = format!("{}/{}", lxc_base_dir(container), container);
        if std::path::Path::new(&dir).join("config").is_file()
            && std::fs::remove_dir_all(&dir).is_ok()
        {
            invalidate_count_caches();
            release_lxc_vlan_allocations(container);
            return Ok(format!(
                "Removed '{}' by deleting its directory — lxc-destroy couldn't load its config.",
                container
            ));
        }
    }
    result
}

/// Release any vSwitch/VLAN IP allocation an LXC container held once it has been
/// permanently destroyed. The `container` identifier is the VMID on Proxmox and
/// the container name on native LXC — the same value used at attach time — so we
/// release both LXC target kinds; the one that doesn't match is a no-op. Called
/// only from `lxc_destroy` (all of whose callers are permanent teardowns — LXC
/// has no image-update recreate that would need the allocation preserved).
/// `TargetKind::Manual` reservations are deliberately not touched here — those
/// are operator-managed and not tied to a container's lifecycle.
fn release_lxc_vlan_allocations(container: &str) {
    use crate::networking::vlan::{release_target_allocations, TargetKind};
    release_target_allocations(TargetKind::LxcNative, container);
    release_target_allocations(TargetKind::LxcProxmox, container);
}

/// Permanently remove a Docker container AND release any vSwitch/VLAN IP
/// allocation it held. This is deliberately SEPARATE from `docker_remove`: the
/// image-update recreate path (`image_watcher`) uses `docker_remove` to drop and
/// re-create the same container under the same name and MUST keep its allocation.
/// Use this wrapper only at operator/orchestration delete boundaries where the
/// container is going away for good.
pub fn docker_remove_permanent(container: &str) -> Result<String, String> {
    let result = docker_remove(container);
    if result.is_ok() {
        crate::networking::vlan::release_target_allocations(
            crate::networking::vlan::TargetKind::Docker, container);
    }
    result
}

/// Read LXC container config
pub fn lxc_config(container: &str) -> Option<String> {
    let path = format!("{}/{}/config", lxc_base_dir(container), container);
    std::fs::read_to_string(&path).ok()
}

/// Save LXC container config (creates .bak backup first)
pub fn lxc_save_config(container: &str, content: &str) -> Result<String, String> {
    let path = format!("{}/{}/config", lxc_base_dir(container), container);
    if !std::path::Path::new(&path).exists() {
        return Err(format!("Container '{}' config not found", container));
    }

    // Validate that this config doesn't have conflicting WolfNet + VLAN settings
    validate_wolfnet_vlan_conflict(content)?;

    let backup = format!("{}.bak", path);
    let _ = std::fs::copy(&path, &backup);
    std::fs::write(&path, content)
        .map(|_| format!("Config saved for '{}'", container))
        .map_err(|e| format!("Failed to save config: {}", e))
}

/// Validate that a container config doesn't have conflicting WolfNet + VLAN settings.
/// WolfNet (wolfnet0 tunnel) and VLAN tags are incompatible network configurations
/// on Proxmox clusters — they cause routing conflicts that can break the container's
/// networking and potentially affect cluster-wide routing.
fn validate_wolfnet_vlan_conflict(config: &str) -> Result<(), String> {
    let has_wolfnet_ip = config.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with('#') { return false; }
        // Check for .wolfnet/ip marker file reference
        trimmed.contains(".wolfnet/ip") ||
        // Or check if this looks like a container being prepared for WolfNet
        (trimmed.contains("wolfnet") && !trimmed.contains("#"))
    });

    let has_vlan_tag = config.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with('#') { return false; }
        // Look for lines like: lxc.net.0.vlan.id = 10
        trimmed.starts_with("lxc.net.") && trimmed.contains("vlan.id")
    });

    if has_wolfnet_ip && has_vlan_tag {
        return Err(
            "Configuration conflict: Cannot assign WolfNet to a container with VLAN tagging. \
             WolfNet is a mesh overlay network (wolfnet0 tunnel) while VLAN uses tagged physical \
             interfaces — they have incompatible routing models that cause networking to fail on \
             Proxmox clusters. Choose one: either WolfNet mode (for mesh networking) or VLAN mode \
             (for bridged networking), but not both.".to_string()
        );
    }

    Ok(())
}

/// Structured representation of a single LXC network interface
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LxcNetInterface {
    pub index: u32,
    pub net_type: String,      // veth, etc.
    pub link: String,          // bridge name
    pub name: String,          // interface name inside container (eth0)
    pub hwaddr: String,        // MAC address
    pub ipv4: String,          // e.g. "192.168.1.100/24" or "" for DHCP
    pub ipv4_gw: String,       // gateway
    pub ipv6: String,
    pub ipv6_gw: String,
    pub firewall: bool,
    pub mtu: String,
    pub vlan: String,
    pub flags: String,         // e.g. "up"
    /// Physical uplink NIC this interface's VLAN bridge rides on. NOT a
    /// real LXC config key — it is recovered from the VLAN attachment
    /// store so the settings editor's "vSwitch uplink NIC" picker can
    /// round-trip. The frontend strips it before POSTing settings, and
    /// the config writer never emits it. `#[serde(default)]` is required:
    /// settings POSTs (and older configs) won't carry this field.
    #[serde(default)]
    pub vsw_uplink: String,
}

/// Structured representation of an LXC config
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LxcParsedConfig {
    // General
    pub hostname: String,
    pub arch: String,
    pub autostart: bool,
    pub start_delay: u32,
    pub start_order: u32,
    pub unprivileged: bool,

    // Network — flat fields kept for backward compat (populated from net.0)
    pub net_type: String,
    pub net_link: String,
    pub net_name: String,
    pub net_hwaddr: String,
    pub net_ipv4: String,
    pub net_ipv4_gw: String,
    pub net_ipv6: String,
    pub net_ipv6_gw: String,
    pub net_firewall: bool,
    pub net_mtu: String,
    pub net_vlan: String,

    // All network interfaces
    pub network_interfaces: Vec<LxcNetInterface>,

    // Resources
    pub memory_limit: String,  // e.g. "1G", "512M"
    pub swap_limit: String,
    pub cpus: String,          // cpuset e.g. "0-3"
    pub cpu_shares: String,

    // Features
    pub tun_enabled: bool,
    pub fuse_enabled: bool,
    pub nesting_enabled: bool,
    pub nfs_enabled: bool,
    pub keyctl_enabled: bool,

    // Raw config for advanced editing
    pub raw_config: String,

    // WolfNet
    pub wolfnet_ip: String,

    // DNS the operator pinned for this container, space-separated for the
    // settings form. Proxmox CTs use PVE's own `nameserver:`/`searchdomain:`
    // fields; native LXC uses the WolfStack sidecar. Empty means "no override"
    // — the writers then preserve whatever the container already resolves with.
    #[serde(default)]
    pub dns_servers: String,
    #[serde(default)]
    pub dns_search: String,

    // Free-text operator notes / description. Read back from the PVE
    // `description:` line (Proxmox CTs) or the WolfStack sidecar (native LXC).
    #[serde(default)]
    pub notes: String,

    // Storage
    #[serde(default)]
    pub storage_path: String,

    // True when the container's config lives in /etc/pve/lxc/… and
    // must be managed via `pct set`. The frontend uses this to decide
    // whether to show the PVE-specific mount options (shared, backup,
    // size, quota) in the Add Mount modal.
    #[serde(default)]
    pub proxmox: bool,
}
/// Parse a Proxmox-format config (/etc/pve/lxc/<vmid>.conf)
/// Format: `key: value` with network as `net0: name=eth0,bridge=vmbr0,hwaddr=...,ip=...,gw=...`
fn parse_proxmox_config(mut cfg: LxcParsedConfig, content: &str, container: &str) -> LxcParsedConfig {
    let mut net_map: std::collections::BTreeMap<u32, LxcNetInterface> = std::collections::BTreeMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() { continue; }

        // Proxmox format: "key: value"
        let (key, val) = match line.split_once(':') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };

        // Network interfaces: net0, net1, etc.
        if key.starts_with("net")
            && let Ok(idx) = key[3..].parse::<u32>() {
                let nic = net_map.entry(idx).or_insert_with(|| LxcNetInterface {
                    index: idx,
                    ..Default::default()
                });
                // Parse comma-separated key=value pairs
                for part in val.split(',') {
                    let part = part.trim();
                    if let Some((pk, pv)) = part.split_once('=') {
                        match pk.trim() {
                            "name" => nic.name = pv.to_string(),
                            "bridge" => nic.link = pv.to_string(),
                            "hwaddr" => nic.hwaddr = pv.to_string(),
                            "ip" => {
                                if pv != "dhcp" {
                                    nic.ipv4 = pv.to_string();
                                }
                            }
                            "gw" => nic.ipv4_gw = pv.to_string(),
                            "ip6" => {
                                if pv != "dhcp" && pv != "auto" {
                                    nic.ipv6 = pv.to_string();
                                }
                            }
                            "gw6" => nic.ipv6_gw = pv.to_string(),
                            "type" => nic.net_type = pv.to_string(),
                            "mtu" => nic.mtu = pv.to_string(),
                            "tag" => nic.vlan = pv.to_string(),
                            "firewall" => nic.firewall = pv == "1",
                            "rate" => {} // bandwidth limit, ignore
                            _ => {}
                        }
                    }
                }
                if nic.name.is_empty() {
                    nic.name = format!("eth{}", idx);
                }
                if nic.net_type.is_empty() {
                    nic.net_type = "veth".to_string();
                }
                nic.flags = "up".to_string();
                continue;
            }

        match key {
            "hostname" => cfg.hostname = val.to_string(),
            "description" => cfg.notes = pve_decode_description(val),
            "arch" => cfg.arch = val.to_string(),
            "onboot" => cfg.autostart = val == "1",
            "startup" => {
                // Parse startup order: "order=N" format
                if let Some(order_part) = val.split(',').find(|p| p.starts_with("order=")) {
                    cfg.start_order = order_part[6..].parse().unwrap_or(0);
                }
            }
            "cores" => cfg.cpus = val.to_string(),
            "memory" => {
                // Proxmox stores MB as plain number — pass through as-is
                cfg.memory_limit = val.to_string();
            }
            "swap" => {
                cfg.swap_limit = val.to_string();
            }
            "rootfs" => {
                // e.g. "local-lvm:vm-101-disk-0,size=32G" → storage name "local-lvm"
                if let Some(storage_name) = val.split(':').next() {
                    let storage_name = storage_name.trim();
                    if !storage_name.is_empty() {
                        cfg.storage_path = storage_name.to_string();
                    }
                }
            }
            "unprivileged" => cfg.unprivileged = val == "1",
            "features" => {
                // features: nesting=1,keyctl=1,fuse=1
                for feat in val.split(',') {
                    let feat = feat.trim();
                    match feat {
                        "nesting=1" => cfg.nesting_enabled = true,
                        "keyctl=1" => cfg.keyctl_enabled = true,
                        "fuse=1" => cfg.fuse_enabled = true,
                        _ => {}
                    }
                }
            }
            _ => {
                // Proxmox configs can contain raw LXC directives (lxc.mount.entry, lxc.cgroup2, etc.)
                // using the same "key: value" colon format, e.g.:
                //   lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file 0 0
                if key == "lxc.mount.entry" && val.contains("/dev/net/tun") {
                    cfg.tun_enabled = true;
                }
                if key == "lxc.mount.entry" && val.contains("/dev/fuse") {
                    cfg.fuse_enabled = true;
                }
                if key == "lxc.mount.entry" && val.contains("nfsd") {
                    cfg.nfs_enabled = true;
                }
                if key == "lxc.include" && val.contains("nesting.conf") {
                    cfg.nesting_enabled = true;
                }
                if key == "lxc.mount.auto" && val.contains("cgroup") {
                    cfg.nesting_enabled = true;
                }
                if key == "lxc.mount.auto" && val.contains("proc:rw") {
                    cfg.keyctl_enabled = true;
                }
            }
        }
    }

    cfg.network_interfaces = net_map.into_values().collect();
    recover_vswitch_uplinks(&mut cfg.network_interfaces);

    // Populate flat fields from NIC 0 for backward compat — read from the
    // enriched interface list so flat net_vlan matches network_interfaces[0].
    if let Some(nic0) = cfg.network_interfaces.iter().find(|n| n.index == 0) {
        cfg.net_type = nic0.net_type.clone();
        cfg.net_link = nic0.link.clone();
        cfg.net_name = nic0.name.clone();
        cfg.net_hwaddr = nic0.hwaddr.clone();
        cfg.net_ipv4 = nic0.ipv4.clone();
        cfg.net_ipv4_gw = nic0.ipv4_gw.clone();
        cfg.net_ipv6 = nic0.ipv6.clone();
        cfg.net_ipv6_gw = nic0.ipv6_gw.clone();
        cfg.net_firewall = nic0.firewall;
        cfg.net_mtu = nic0.mtu.clone();
        cfg.net_vlan = nic0.vlan.clone();
    }

    // Read WolfNet IP
    let wolfnet_ip_file = format!("{}/{}/.wolfnet/ip", lxc_base_dir(container), container);
    if let Ok(ip) = std::fs::read_to_string(&wolfnet_ip_file) {
        cfg.wolfnet_ip = ip.trim().to_string();
    }

    cfg
}

/// Recover the vSwitch uplink — and, for tagless vSwitch NICs, the VLAN
/// ID — for each parsed interface.
///
/// A container attached to a WolfStack VLAN bridge carries only the
/// bridge name (`vmbr<vlan>`) in its LXC config: the originating
/// physical uplink and the VLAN tag live in the VLAN attachment store
/// (`vlan-attachments.json`), not the container config. `saveLxcSettings`
/// even clears the NIC's own `vlan` because the tag rides on the
/// bridge's sub-interface. Without this recovery the settings editor's
/// "vSwitch uplink NIC" picker and VLAN Tag field both come back blank.
fn recover_vswitch_uplinks(nics: &mut [LxcNetInterface]) {
    if nics.iter().all(|n| n.link.is_empty()) {
        return;
    }
    let store = crate::networking::vlan::VlanStore::load();
    apply_vswitch_uplinks(nics, &store.vlans);
}

/// Pure form of [`recover_vswitch_uplinks`] — given the VLAN attachment
/// list, match each NIC's bridge against it. Split out from the store
/// load so it can be unit-tested without touching the filesystem.
fn apply_vswitch_uplinks(
    nics: &mut [LxcNetInterface],
    vlans: &[crate::networking::vlan::VlanAttachment],
) {
    for nic in nics.iter_mut() {
        if nic.link.is_empty() {
            continue;
        }
        if let Some(att) = vlans.iter().find(|v| v.bridge_name == nic.link) {
            nic.vsw_uplink = att.parent_iface.clone();
            // A vSwitch NIC keeps its tag on the bridge sub-interface, so
            // its own `vlan` is blank on disk — recover it. Never clobber
            // a tag the config genuinely carries.
            if nic.vlan.is_empty() {
                nic.vlan = att.vlan_id.to_string();
            }
        }
    }
}

#[cfg(test)]
mod wolfnet_gate_tests {
    use super::*;

    #[test]
    fn default_container_storage_picks_existing_not_hardcoded_lvm() {
        // ZFS-only host (wabil): no local-lvm → must NOT return local-lvm;
        // prefers local-zfs when present.
        let zfs_host = "Name             Type     Status        Total    Used   Avail   %\n\
                        local            dir      active        100      10     90      10\n\
                        local-zfs        zfspool  active        500      50     450     10\n";
        assert_eq!(pick_default_container_storage(zfs_host), "local-zfs");
        // Classic LVM host → local-lvm (unchanged behaviour).
        let lvm_host = "Name        Type   Status   Total Used Avail %\n\
                        local       dir    active   1 1 1 1\n\
                        local-lvm   lvmthin active  1 1 1 1\n";
        assert_eq!(pick_default_container_storage(lvm_host), "local-lvm");
        // Neither convention present → first active storage.
        let custom = "Name      Type     Status  T U A %\n\
                      tank-ct   zfspool  active  1 1 1 1\n";
        assert_eq!(pick_default_container_storage(custom), "tank-ct");
        // An INACTIVE local-lvm must be ignored (this is the exact bug —
        // referencing a storage that exists-but-isn't-usable / is gone).
        let inactive = "Name       Type     Status    T U A %\n\
                        local-lvm  lvmthin  inactive  1 1 1 1\n\
                        local-zfs  zfspool  active    1 1 1 1\n";
        assert_eq!(pick_default_container_storage(inactive), "local-zfs");
        // Empty / unparseable → historical default, nothing regresses.
        assert_eq!(pick_default_container_storage(""), "local-lvm");
    }

    #[test]
    fn standalone_wolfnet_gate_preserves_default_clusters() {
        // lxcbr0 (the WolfStack default — every standard cluster) must take the
        // SAME path as before: do NOT skip.
        assert!(!skip_standalone_wolfnet(Some("lxcbr0")));
        // Unknown / unreadable bridge → assume default behaviour, do NOT skip
        // (no regression for installs we can't read the config for).
        assert!(!skip_standalone_wolfnet(None));
        // A manual / migrated non-lxcbr0 primary (e.g. a Hetzner vSwitch) → SKIP
        // so we never flush its eth0.
        assert!(skip_standalone_wolfnet(Some("vmbr4001")));
        assert!(skip_standalone_wolfnet(Some("br0")));
        assert!(skip_standalone_wolfnet(Some("vmbr0")));
        // A WolfStack-created LAN bridge (Bridged-LAN mode) → SKIP, so
        // lxc_post_start_setup never flushes the container onto the lxcbr0
        // 10.0.3.x NAT subnet (Gary KO4BSR 2026-06-22).
        assert!(skip_standalone_wolfnet(Some("lanbr0")));
    }
}

#[cfg(test)]
mod vswitch_recovery_tests {
    use super::*;

    fn vlans(json: &str) -> Vec<crate::networking::vlan::VlanAttachment> {
        serde_json::from_str(json).expect("vlan fixture parses")
    }

    #[test]
    fn recovers_uplink_and_tag_for_a_vswitch_bridge_nic() {
        let store = vlans(
            r#"[{"id":"v1","name":"vsw","provider":"custom","parent_iface":"eno1",
                 "vlan_id":4000,"mtu":1400,"bridge_name":"vmbr4000",
                 "subnet":"","self_ip":""}]"#,
        );
        let mut nics = vec![
            // On the vSwitch bridge — tag was cleared on save, blank on disk.
            LxcNetInterface { index: 0, link: "vmbr4000".into(), ..Default::default() },
            // On a plain bridge with a real tag — must be left alone.
            LxcNetInterface {
                index: 1,
                link: "lxcbr0".into(),
                vlan: "7".into(),
                ..Default::default()
            },
        ];
        apply_vswitch_uplinks(&mut nics, &store);

        assert_eq!(nics[0].vsw_uplink, "eno1");
        assert_eq!(nics[0].vlan, "4000", "tag recovered from the attachment");
        assert_eq!(nics[1].vsw_uplink, "", "plain-bridge NIC gets no uplink");
        assert_eq!(nics[1].vlan, "7", "a real on-disk tag is preserved");
    }

    #[test]
    fn does_not_clobber_a_tag_the_config_already_carries() {
        let store = vlans(
            r#"[{"id":"v1","name":"vsw","provider":"custom","parent_iface":"bond0",
                 "vlan_id":4000,"mtu":1400,"bridge_name":"vmbr4000",
                 "subnet":"","self_ip":""}]"#,
        );
        let mut nics = vec![LxcNetInterface {
            index: 0,
            link: "vmbr4000".into(),
            vlan: "99".into(),
            ..Default::default()
        }];
        apply_vswitch_uplinks(&mut nics, &store);

        assert_eq!(nics[0].vsw_uplink, "bond0");
        assert_eq!(nics[0].vlan, "99", "on-disk tag wins over the attachment");
    }

    #[test]
    fn no_attachments_leaves_nics_untouched() {
        let mut nics = vec![LxcNetInterface {
            index: 0,
            link: "vmbr4000".into(),
            ..Default::default()
        }];
        apply_vswitch_uplinks(&mut nics, &[]);

        assert_eq!(nics[0].vsw_uplink, "");
        assert_eq!(nics[0].vlan, "");
    }
}

/// Parse an LXC container config into structured form
pub fn lxc_parse_config(container: &str) -> Option<LxcParsedConfig> {
    // Try Proxmox config first (/etc/pve/lxc/<vmid>.conf), then native LXC
    let pve_path = format!("/etc/pve/lxc/{}.conf", container);
    let lxc_path = format!("{}/{}/config", lxc_base_dir(container), container);

    let (content, is_proxmox_fmt) = if let Ok(c) = std::fs::read_to_string(&pve_path) {
        (c, true)
    } else if let Ok(c) = std::fs::read_to_string(&lxc_path) {
        (c, false)
    } else {
        return None;
    };

    let base = lxc_base_dir(container);
    let rootfs = format!("{}/{}/rootfs", base, container);
    let mut cfg = LxcParsedConfig {
        raw_config: content.clone(),
        storage_path: if std::path::Path::new(&rootfs).exists() { rootfs } else { base.clone() },
        proxmox: is_proxmox_fmt,
        ..Default::default()
    };

    if is_proxmox_fmt {
        return Some(parse_proxmox_config(cfg, &content, container));
    }

    // Collect network interfaces by index
    let mut net_map: std::collections::BTreeMap<u32, LxcNetInterface> = std::collections::BTreeMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() { continue; }

        let parts: Vec<&str> = line.splitn(2, '=').collect();
        if parts.len() != 2 { continue; }
        let key = parts[0].trim();
        let val = parts[1].trim();

        // Parse lxc.net.N.* keys for all network interfaces
        if let Some(remainder) = key.strip_prefix("lxc.net.") {
            if let Some(dot_pos) = remainder.find('.')
                && let Ok(idx) = remainder[..dot_pos].parse::<u32>() {
                    let field = &remainder[dot_pos + 1..];
                    let nic = net_map.entry(idx).or_insert_with(|| LxcNetInterface {
                        index: idx,
                        ..Default::default()
                    });
                    match field {
                        "type" => nic.net_type = val.to_string(),
                        "link" => nic.link = val.to_string(),
                        "name" => nic.name = val.to_string(),
                        "hwaddr" => nic.hwaddr = val.to_string(),
                        "ipv4.address" => nic.ipv4 = val.to_string(),
                        "ipv4.gateway" => nic.ipv4_gw = val.to_string(),
                        "ipv6.address" => nic.ipv6 = val.to_string(),
                        "ipv6.gateway" => nic.ipv6_gw = val.to_string(),
                        "flags" => nic.flags = val.to_string(),
                        "mtu" => nic.mtu = val.to_string(),
                        // type=vlan writes `vlan.id`; a veth on a bridge
                        // writes `veth.vlan.id` — accept both so the
                        // editor round-trips whichever form is on disk.
                        "vlan.id" | "veth.vlan.id" => nic.vlan = val.to_string(),
                        "firewall" => nic.firewall = val == "1",
                        _ => {}
                    }
                }
            continue;
        }

        match key {
            "lxc.uts.name" => cfg.hostname = val.to_string(),
            "lxc.arch" => cfg.arch = val.to_string(),
            "lxc.start.auto" => cfg.autostart = val == "1",
            "lxc.start.delay" => cfg.start_delay = val.parse().unwrap_or(0),
            "lxc.start.order" => cfg.start_order = val.parse().unwrap_or(0),
            "lxc.idmap" => cfg.unprivileged = true,
            _ => {
                // Feature detection
                if key == "lxc.mount.entry" && val.contains("/dev/net/tun") {
                    cfg.tun_enabled = true;
                }
                if key == "lxc.mount.entry" && val.contains("/dev/fuse") {
                    cfg.fuse_enabled = true;
                }
                if key == "lxc.include" && val.contains("nesting.conf") {
                    cfg.nesting_enabled = true;
                }
                if key == "lxc.mount.auto" && val.contains("cgroup") {
                    cfg.nesting_enabled = true;
                }
                if key == "lxc.mount.entry" && val.contains("nfsd") {
                    cfg.nfs_enabled = true;
                }

                // Resource limits (cgroup v1 and v2) — stored in bytes, convert to MB
                if key.contains("memory.limit") || key.contains("memory.max") {
                    if let Ok(bytes) = val.parse::<u64>() {
                        if bytes > 10000 {
                            cfg.memory_limit = (bytes / (1024 * 1024)).to_string();
                        } else {
                            cfg.memory_limit = val.to_string();
                        }
                    } else {
                        cfg.memory_limit = val.to_string();
                    }
                }
                if key.contains("memory.memsw") || key.contains("swap") {
                    if let Ok(bytes) = val.parse::<u64>() {
                        if bytes > 10000 {
                            cfg.swap_limit = (bytes / (1024 * 1024)).to_string();
                        } else {
                            cfg.swap_limit = val.to_string();
                        }
                    } else {
                        cfg.swap_limit = val.to_string();
                    }
                }
                // CPU limit can be either a CFS quota (cpu.max) or a
                // hard pin (cpuset.cpus). Prefer cpu.max if present —
                // round-trip it as the bare integer the operator typed
                // ("27" → "2700000 100000" → "27") so re-saving keeps
                // the quota semantics. A pin is shown verbatim ("0-3").
                if key.contains("cpu.max") {
                    if let Some(n) = lxc_quota_cores_from_cpu_max(val) {
                        cfg.cpus = n.to_string();
                    } else if cfg.cpus.is_empty() {
                        // Unrecognised quota shape — surface the raw
                        // value so the operator can see/edit it.
                        cfg.cpus = val.to_string();
                    }
                } else if key.contains("cpuset.cpus") && cfg.cpus.is_empty() {
                    cfg.cpus = val.to_string();
                }
                if key.contains("cpu.shares") || key.contains("cpu.weight") {
                    cfg.cpu_shares = val.to_string();
                }
            }
        }

        // keyctl detection
        if key == "lxc.mount.auto" && val.contains("proc:rw") {
            cfg.keyctl_enabled = true;
        }
    }

    // Set default interface name for NICs missing one
    for nic in net_map.values_mut() {
        if nic.name.is_empty() && !nic.net_type.is_empty() {
            nic.name = format!("eth{}", nic.index);
        }
    }

    // Store all NICs
    cfg.network_interfaces = net_map.into_values().collect();
    recover_vswitch_uplinks(&mut cfg.network_interfaces);

    // Populate flat fields from NIC 0 for backward compatibility — read
    // from the enriched list so flat net_vlan matches network_interfaces[0].
    if let Some(nic0) = cfg.network_interfaces.iter().find(|n| n.index == 0) {
        cfg.net_type = nic0.net_type.clone();
        cfg.net_link = nic0.link.clone();
        cfg.net_name = nic0.name.clone();
        cfg.net_hwaddr = nic0.hwaddr.clone();
        cfg.net_ipv4 = nic0.ipv4.clone();
        cfg.net_ipv4_gw = nic0.ipv4_gw.clone();
        cfg.net_ipv6 = nic0.ipv6.clone();
        cfg.net_ipv6_gw = nic0.ipv6_gw.clone();
        cfg.net_firewall = nic0.firewall;
        cfg.net_mtu = nic0.mtu.clone();
        cfg.net_vlan = nic0.vlan.clone();
    }

    // Read WolfNet IP from file
    let wolfnet_ip_file = format!("{}/{}/.wolfnet/ip", lxc_base_dir(container), container);
    if let Ok(ip) = std::fs::read_to_string(&wolfnet_ip_file) {
        cfg.wolfnet_ip = ip.trim().to_string();
    }

    // Native LXC has no description field — read the WolfStack sidecar.
    // (Proxmox CTs already had `notes` filled from the `description:` line in
    // parse_proxmox_config, so only do this for the native format.)
    if !cfg.proxmox
        && let Ok(n) = std::fs::read_to_string(lxc_notes_path(container)) {
        cfg.notes = n;
    }

    // Pinned DNS, from whichever store this backend keeps it in.
    let dns = lxc_get_dns(container);
    cfg.dns_servers = dns.servers.join(" ");
    cfg.dns_search = dns.search.join(" ");

    Some(cfg)
}

/// Path to the WolfStack notes sidecar for a NATIVE LXC container. Native LXC
/// has no `description` directive, so operator notes are kept alongside the
/// container's other WolfStack metadata under its base dir. Mirrors the
/// existing `.wolfnet/ip` sidecar convention.
fn lxc_notes_path(container: &str) -> String {
    format!("{}/{}/.wolfstack/notes", lxc_base_dir(container), container)
}

/// Set operator notes / description for a container, dispatched by backend.
/// Proxmox CTs use `pct set --description` (`--delete description` to clear);
/// native LXC uses the WolfStack sidecar. Used by the create path so notes
/// supplied at create time persist the same way an edit would.
pub fn lxc_set_notes(container: &str, notes: &str) -> Result<(), String> {
    let pve_path = format!("/etc/pve/lxc/{}.conf", container);
    if std::path::Path::new(&pve_path).exists() {
        let mut args: Vec<String> = vec!["set".to_string(), container.to_string()];
        if notes.is_empty() {
            args.push("--delete".to_string());
            args.push("description".to_string());
        } else {
            args.push("--description".to_string());
            args.push(notes.to_string());
        }
        let output = Command::new("pct").args(&args).output()
            .map_err(|e| format!("Failed to run pct set: {}", e))?;
        if !output.status.success() {
            return Err(format!("pct set --description failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()));
        }
        return Ok(());
    }
    lxc_write_notes(container, notes)
}

/// Write (or clear) the native-LXC notes sidecar. An empty string removes the
/// file so a cleared notes field reads back as empty.
fn lxc_write_notes(container: &str, notes: &str) -> Result<(), String> {
    let path = lxc_notes_path(container);
    if notes.is_empty() {
        // Best-effort removal; absent file is already the desired state.
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    if let Some(dir) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Failed to create notes dir {}: {}", dir.display(), e))?;
    }
    std::fs::write(&path, notes)
        .map_err(|e| format!("Failed to write notes {}: {}", path, e))
}

/// Decode a PVE `description:` value. Proxmox URL-encodes newlines as `%0A`
/// (CR as `%0D`, a literal `%` as `%25`) in the single-line config
/// representation. Decode those so the operator sees their notes with line
/// breaks intact; other `%xx` sequences are left untouched. Shared with the
/// VM manager (`qm`/PVE qemu-server configs use the identical encoding).
pub(crate) fn pve_decode_description(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Match the two bytes after '%' directly to avoid slicing the &str
        // across a char boundary on a stray non-escape '%'.
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            let (a, b) = (bytes[i + 1].to_ascii_uppercase(), bytes[i + 2].to_ascii_uppercase());
            match (a, b) {
                (b'0', b'A') => { out.push('\n'); i += 3; continue; }
                (b'0', b'D') => { i += 3; continue; } // strip CR; PVE pairs %0D%0A on Windows-edited configs
                (b'2', b'5') => { out.push('%'); i += 3; continue; }
                _ => {}
            }
        }
        let ch = raw[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Update settings for an LXC container with structured data
/// Preserves existing config lines that aren't being modified
#[derive(Debug, Default, Deserialize)]
pub struct LxcSettingsUpdate {
    // General
    pub hostname: Option<String>,
    pub autostart: Option<bool>,
    pub start_delay: Option<u32>,
    pub start_order: Option<u32>,
    pub unprivileged: Option<bool>,

    // Network (flat fields for backward compat — net.0 only)
    pub net_link: Option<String>,
    pub net_name: Option<String>,
    pub net_hwaddr: Option<String>,
    pub net_ipv4: Option<String>,
    pub net_ipv4_gw: Option<String>,
    pub net_ipv6: Option<String>,
    pub net_ipv6_gw: Option<String>,
    pub net_mtu: Option<String>,
    pub net_vlan: Option<String>,

    // All network interfaces (overrides flat fields if present)
    pub network_interfaces: Option<Vec<LxcNetInterface>>,

    // Resources
    pub memory_limit: Option<String>,
    pub swap_limit: Option<String>,
    pub cpus: Option<String>,

    // Features
    pub tun_enabled: Option<bool>,
    pub fuse_enabled: Option<bool>,
    pub nesting_enabled: Option<bool>,
    pub nfs_enabled: Option<bool>,
    pub keyctl_enabled: Option<bool>,

    // WolfNet
    pub wolfnet_ip: Option<String>,

    // DNS override. Space/comma separated; an empty string clears the override
    // and hands DNS back to whatever the container itself is configured with.
    pub dns_servers: Option<String>,
    pub dns_search: Option<String>,

    // Free-text operator notes / description. Empty string clears it.
    // Proxmox CTs store it in the PVE config (`pct set --description`);
    // native LXC has no description field, so WolfStack keeps it in a
    // per-container sidecar (see `lxc_notes_path`).
    pub notes: Option<String>,
}
/// Update LXC container settings via Proxmox pct set
fn pct_update_settings(container: &str, settings: &LxcSettingsUpdate) -> Result<String, String> {
    let current = lxc_parse_config(container).unwrap_or_default();
    let mut args: Vec<String> = vec!["set".to_string(), container.to_string()];
    // Keys the operator cleared. `pct set` takes `delete` as ONE comma-separated
    // configid list and Getopt keeps only the last occurrence of a repeated
    // option, so pushing `--delete` per key silently dropped all but the final
    // one (clearing CPU cores and notes in the same save lost the cores clear).
    // Collect them and emit a single `--delete a,b,c`.
    let mut deletes: Vec<&str> = Vec::new();

    // Hostname
    if let Some(ref h) = settings.hostname
        && !h.is_empty() {
            args.push("--hostname".to_string());
            args.push(h.clone());
        }

    // Memory (Proxmox uses MB as integer)
    let mem = settings.memory_limit.as_deref().unwrap_or(&current.memory_limit);
    if !mem.is_empty() {
        let mb = parse_mem_to_mb(mem);
        if mb > 0 {
            args.push("--memory".to_string());
            args.push(mb.to_string());
        }
    }

    // Swap
    let swap = settings.swap_limit.as_deref().unwrap_or(&current.swap_limit);
    if !swap.is_empty() {
        let mb = parse_mem_to_mb(swap);
        if mb > 0 {
            args.push("--swap".to_string());
            args.push(mb.to_string());
        }
    }

    // Cores / CPUs — Proxmox `cores` is a whole-number count. Reject a
    // cpuset spec ("0-3") with a clear message instead of letting
    // `pct set --cores 0-3` fail with a cryptic Proxmox error. When the
    // operator clears a previously-set value, issue `--delete cores`
    // so the limit actually drops — otherwise `pct set` with no
    // `--cores` leaves the old value in place and "clear = unlimited"
    // silently doesn't take.
    let new_cpus = settings.cpus.as_deref();
    let cpus = new_cpus.unwrap_or(&current.cpus);
    if !cpus.is_empty() {
        match cpus.trim().parse::<u32>() {
            Ok(n) if n >= 1 => {
                args.push("--cores".to_string());
                args.push(n.to_string());
            }
            _ => {
                return Err(format!(
                    "CPU Cores must be a whole number for a Proxmox container (got '{}'). \
                     A cpuset range like 0-3 applies only to native LXC.", cpus.trim()));
            }
        }
    } else if new_cpus.is_some() && !current.cpus.is_empty() {
        // Operator explicitly cleared a previously-set cores value —
        // tell pct to drop the limit entirely.
        deletes.push("cores");
    }

    // Autostart
    let autostart = settings.autostart.unwrap_or(current.autostart);
    args.push("--onboot".to_string());
    args.push(if autostart { "1" } else { "0" }.to_string());

    // DNS. PVE has native CT fields for this and regenerates the container's
    // /etc/resolv.conf from them on start, so `pct set` is the whole job — and
    // WolfStack's own writers read the same fields back as the operator's
    // explicit choice. `--delete` is only sent when the field is actually set:
    // deleting an unset key would fail the whole `pct set`, and the UI sends
    // these on every save.
    if let Some(ref v) = settings.dns_servers {
        let parsed = parse_dns_servers(v);
        if parsed.is_empty() {
            if !current.dns_servers.is_empty() {
                deletes.push("nameserver");
            }
        } else {
            args.push("--nameserver".to_string());
            args.push(parsed.join(" "));
        }
    }
    if let Some(ref v) = settings.dns_search {
        let parsed = parse_dns_search(v);
        if parsed.is_empty() {
            if !current.dns_search.is_empty() {
                deletes.push("searchdomain");
            }
        } else {
            args.push("--searchdomain".to_string());
            args.push(parsed.join(" "));
        }
    }

    // Notes / description. `pct set --description <text>` stores it in the PVE
    // config (read back from the `description:` line). An empty string clears
    // it via `--delete description`, so a cleared notes field actually drops
    // the stored value rather than leaving the old one in place.
    if let Some(ref n) = settings.notes {
        if n.is_empty() {
            deletes.push("description");
        } else {
            args.push("--description".to_string());
            args.push(n.clone());
        }
    }

    // Features
    let mut features: Vec<String> = Vec::new();
    if settings.nesting_enabled.unwrap_or(current.nesting_enabled) { features.push("nesting=1".to_string()); }
    if settings.keyctl_enabled.unwrap_or(current.keyctl_enabled) { features.push("keyctl=1".to_string()); }
    if settings.fuse_enabled.unwrap_or(current.fuse_enabled) { features.push("fuse=1".to_string()); }
    if !features.is_empty() {
        args.push("--features".to_string());
        args.push(features.join(","));
    }

    // Network interfaces
    let nics: Vec<LxcNetInterface> = if let Some(ref ifaces) = settings.network_interfaces {
        ifaces.clone()
    } else {
        current.network_interfaces.clone()
    };

    for nic in &nics {
        let mut parts: Vec<String> = Vec::new();
        let name = if nic.name.is_empty() { format!("eth{}", nic.index) } else { nic.name.clone() };
        parts.push(format!("name={}", name));
        if !nic.link.is_empty() { parts.push(format!("bridge={}", nic.link)); }
        if !nic.hwaddr.is_empty() { parts.push(format!("hwaddr={}", nic.hwaddr)); }
        if !nic.ipv4.is_empty() {
            parts.push(format!("ip={}", nic.ipv4));
        }
        if !nic.ipv4_gw.is_empty() { parts.push(format!("gw={}", nic.ipv4_gw)); }
        if !nic.ipv6.is_empty() {
            parts.push(format!("ip6={}", nic.ipv6));
        }
        if !nic.ipv6_gw.is_empty() { parts.push(format!("gw6={}", nic.ipv6_gw)); }
        let net_type = if nic.net_type.is_empty() { "veth".to_string() } else { nic.net_type.clone() };
        parts.push(format!("type={}", net_type));
        if !nic.mtu.is_empty() { parts.push(format!("mtu={}", nic.mtu)); }
        if !nic.vlan.is_empty() { parts.push(format!("tag={}", nic.vlan)); }
        if nic.firewall { parts.push("firewall=1".to_string()); }

        args.push(format!("--net{}", nic.index));
        args.push(parts.join(","));
    }

    if !deletes.is_empty() {
        args.push("--delete".to_string());
        args.push(deletes.join(","));
    }

    // Execute pct set
    let output = Command::new("pct")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run pct set: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("pct set failed: {}", stderr));
    }

    // Mirror the primary NIC's static IP (or a revert to DHCP) into the
    // container's OWN network config via pct mount — `pct set --net0 ip=` only
    // sets the veth address; many distros then DHCP over it (wabil 2026-06-26,
    // Proxmox edit). Same rules as the native edit path; skipped when WolfNet
    // manages eth0, and the helper further scopes to a real user bridge.
    let wolfnet_active = settings.wolfnet_ip.as_deref()
        .map(|s| !s.trim().is_empty()).unwrap_or(false)
        || lxc_get_wolfnet_ip(container).is_some();
    let mut net_applied = false;
    if let Some(action) = primary_nic_edit_action(&nics, &current.network_interfaces, wolfnet_active) {
        net_applied = true;
        // `action` is only ever Static/Dhcp here — primary_nic_edit_action maps
        // Skip to None — but the match stays exhaustive over the enum.
        let res = match action {
            PrimaryNicNetAction::Static { cidr, gateway } =>
                pct_write_bridge_netconfig(container, Some(&cidr), gateway.as_deref()),
            PrimaryNicNetAction::Dhcp =>
                pct_write_bridge_netconfig(container, None, None),
            PrimaryNicNetAction::Skip => Ok(()),
        };
        if let Err(e) = res {
            warn!("{}: in-container network config not written: {}", container, e);
        }
    }

    // Handle raw LXC directives (TUN, NFS) that pct set doesn't manage.
    // These are lxc.mount.entry / lxc.cgroup2.devices.allow lines in the PVE config.
    {
        let pve_conf = format!("/etc/pve/lxc/{}.conf", container);
        if let Ok(conf_content) = std::fs::read_to_string(&pve_conf) {
            let feature_markers = ["/dev/net/tun", "nfsd", "10:200"];
            // Strip existing managed lines
            let mut lines: Vec<&str> = conf_content.lines().filter(|line| {
                let trimmed = line.trim();
                !feature_markers.iter().any(|m| trimmed.contains(m))
            }).collect();

            // Re-add based on desired state
            let tun = settings.tun_enabled.unwrap_or(current.tun_enabled);
            if tun {
                lines.push("lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file 0 0");
                lines.push("lxc.cgroup2.devices.allow: c 10:200 rwm");
            }
            let nfs = settings.nfs_enabled.unwrap_or(current.nfs_enabled);
            if nfs {
                lines.push("lxc.mount.entry: nfsd nfsd nfsd defaults 0 0");
            }

            let new_content = lines.join("\n") + "\n";
            if let Err(e) = std::fs::write(&pve_conf, new_content) {
                error!("Failed to update raw LXC directives in {}: {}", pve_conf, e);
            }
        }
    }

    // Handle WolfNet IP separately
    if let Some(ref wip) = settings.wolfnet_ip {
        let wolfnet_dir = format!("{}/{}/.wolfnet", lxc_base_dir(container), container);
        let wolfnet_ip_file = format!("{}/ip", wolfnet_dir);
        let ip_trimmed = wip.trim();
        if ip_trimmed.is_empty() {
            // Read the old WolfNet IP before deleting the marker — it's the only
            // record of which address to unbind inside the container.
            let old_ip = std::fs::read_to_string(&wolfnet_ip_file).unwrap_or_default();
            let _ = std::fs::remove_file(&wolfnet_ip_file);
            // Unbind the WolfNet IP inside the container + drop the host route.
            // Without this the address is re-applied from the in-container NM
            // keyfile on next start (Gary KO4BSR, v24.51.2).
            lxc_remove_wolfnet(container, old_ip.trim());
            // Remove the wn0 NIC from pct config if it exists
            let current = lxc_parse_config(container).unwrap_or_default();
            if let Some(wn_nic) = current.network_interfaces.iter().find(|n| n.name == "wn0" || n.link == "lxcbr0") {
                let _ = Command::new("pct")
                    .args(["set", container, "--delete", &format!("net{}", wn_nic.index)])
                    .output();

            }
        } else {
            let _ = std::fs::create_dir_all(&wolfnet_dir);
            std::fs::write(&wolfnet_ip_file, ip_trimmed)
                .map_err(|e| format!("Failed to write WolfNet IP: {}", e))?;

            // Ensure lxcbr0 bridge exists
            ensure_lxc_bridge();

            // Find existing wn0 NIC index or use next free index
            let current = lxc_parse_config(container).unwrap_or_default();
            let wn_index = current.network_interfaces.iter()
                .find(|n| n.name == "wn0" || n.link == "lxcbr0")
                .map(|n| n.index)
                .unwrap_or_else(|| {
                    // Find next free net index
                    let max = current.network_interfaces.iter().map(|n| n.index).max().unwrap_or(0);
                    max + 1
                });

            // Add/update the wn0 NIC on lxcbr0 via pct set — NO ip/gw to avoid
            // creating a second default gateway that conflicts with eth0 on vmbr0.
            // lxc_apply_wolfnet will assign the bridge IP and WolfNet IP at runtime.
            let net_cfg = "name=wn0,bridge=lxcbr0";
            let set_out = Command::new("pct")
                .args(["set", container, &format!("--net{}", wn_index), net_cfg])
                .output();
            match set_out {
                Ok(ref o) if o.status.success() => {

                }
                Ok(ref o) => {
                    error!("Failed to set WolfNet NIC on VMID {}: {}", container, String::from_utf8_lossy(&o.stderr));
                }
                Err(e) => {
                    error!("Failed to run pct set for WolfNet NIC on VMID {}: {}", container, e);
                }
            }

            // Apply live if the container is running
            let running = Command::new("pct")
                .args(["status", container])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("running"))
                .unwrap_or(false);
            if running {
                lxc_apply_wolfnet(container);
            }
        }
    }

    // Drop the cached LXC list so the next GET shows the updated
    // settings immediately. Pre-v18.7.33 the cache stuck for 5s after
    // a pct set, so the UI would re-render the OLD memory/cores/etc
    // and the operator would think the save silently reverted.
    invalidate_list_caches();

    Ok(if net_applied {
        format!("Settings updated for '{}' via pct. Restart the container to apply the network changes (and ensure it was stopped for the IP to be written inside).", container)
    } else {
        format!("Settings updated for '{}' via pct", container)
    })
}

/// Parse memory string (e.g. "512M", "1G", "1024") to MB
fn parse_mem_to_mb(mem: &str) -> u64 {
    let mem = mem.trim();
    if mem.is_empty() { return 0; }
    // Normalise: strip trailing "B" so both "MB" and "M" work, "GB"
    // and "G" work, etc. Also accept lowercase.
    let low = mem.to_lowercase();
    let stripped = low.strip_suffix('b').unwrap_or(&low);
    if let Some(v) = stripped.strip_suffix('g') {
        return v.trim().parse::<u64>().unwrap_or(0) * 1024;
    }
    if let Some(v) = stripped.strip_suffix('m') {
        return v.trim().parse::<u64>().unwrap_or(0);
    }
    if let Some(v) = stripped.strip_suffix('k') {
        // kB → MB (rounded up — 1 kB still counts as 1 MB of allowance).
        let kb = v.trim().parse::<u64>().unwrap_or(0);
        return kb.div_ceil(1024);
    }
    // Plain number. This field is always MB in the WolfStack UI —
    // previous code had a "if val > 10000 treat as bytes" heuristic
    // that silently divided any value ≥ 10000 down to ~0, so any LXC
    // memory limit of 10 GB or more (10000+ MB) was being discarded
    // entirely. Every UI field that feeds this function is labelled
    // "MB" — trust the user.
    mem.parse::<u64>().unwrap_or(0)
}

#[cfg(test)]
mod mem_parse_tests {
    use super::*;

    #[test]
    fn plain_numbers_are_mb() {
        assert_eq!(parse_mem_to_mb("2048"), 2048);
        // The bug — v18.7.32 and earlier returned 0 here because
        // 16384 > 10000 triggered the "treat as bytes" heuristic
        // and then divided by 1 MiB, which floors to 0.
        assert_eq!(parse_mem_to_mb("16384"), 16384);
        assert_eq!(parse_mem_to_mb("32768"), 32768);
    }

    #[test]
    fn suffixes_work() {
        assert_eq!(parse_mem_to_mb("2G"), 2048);
        assert_eq!(parse_mem_to_mb("2g"), 2048);
        assert_eq!(parse_mem_to_mb("2GB"), 2048);
        assert_eq!(parse_mem_to_mb("2gb"), 2048);
        assert_eq!(parse_mem_to_mb("2048M"), 2048);
        assert_eq!(parse_mem_to_mb("2048m"), 2048);
        assert_eq!(parse_mem_to_mb("2048MB"), 2048);
        assert_eq!(parse_mem_to_mb("2048mb"), 2048);
        assert_eq!(parse_mem_to_mb("1024K"), 1);
        assert_eq!(parse_mem_to_mb("1024KB"), 1);
    }

    #[test]
    fn empty_and_garbage() {
        assert_eq!(parse_mem_to_mb(""), 0);
        assert_eq!(parse_mem_to_mb("   "), 0);
        assert_eq!(parse_mem_to_mb("not a number"), 0);
        assert_eq!(parse_mem_to_mb("12X"), 0);
    }

    #[test]
    fn whitespace_tolerated() {
        assert_eq!(parse_mem_to_mb(" 2048 "), 2048);
        assert_eq!(parse_mem_to_mb("2 G"), 2048);
    }

    #[test]
    fn pve_description_decodes_notes() {
        // PVE LXC configs URL-encode the description line just like qemu.
        assert_eq!(pve_decode_description("a%0Ab"), "a\nb");
        assert_eq!(pve_decode_description("win%0D%0Ab"), "win\nb");
        assert_eq!(pve_decode_description("50%25"), "50%");
        assert_eq!(pve_decode_description("plain notes"), "plain notes");
        // Trailing bare % and a bare % before a multibyte char must not panic.
        assert_eq!(pve_decode_description("end%"), "end%");
        assert_eq!(pve_decode_description("%ä"), "%ä");
    }

    #[test]
    fn lxc_vlan_key_is_type_aware() {
        // type=vlan interfaces take the tag via `vlan.id`; a veth on a
        // bridge takes it via `veth.vlan.id`. lxc.container.conf(5).
        assert_eq!(lxc_vlan_key_suffix("vlan"), "vlan.id");
        assert_eq!(lxc_vlan_key_suffix("veth"), "veth.vlan.id");
        assert_eq!(lxc_vlan_key_suffix(""), "veth.vlan.id");
    }
}

/// The `lxc.net.N.<suffix>` key that carries a VLAN tag — it differs by
/// interface type. Source: lxc.container.conf(5) — a `type=vlan`
/// interface takes the tag via `vlan.id`, while a `veth` in bridge mode
/// takes its untagged/access VLAN via `veth.vlan.id`. Writing `vlan.id`
/// on a veth (the editor's default type) is silently ignored by LXC.
fn lxc_vlan_key_suffix(net_type: &str) -> &'static str {
    if net_type == "vlan" { "vlan.id" } else { "veth.vlan.id" }
}

pub fn lxc_update_settings(container: &str, settings: &LxcSettingsUpdate) -> Result<String, String> {
    // Check if this is a Proxmox container
    let pve_path = format!("/etc/pve/lxc/{}.conf", container);
    if std::path::Path::new(&pve_path).exists() {
        return pct_update_settings(container, settings);
    }

    let base = lxc_base_dir(container);
    let path = format!("{}/{}/config", base, container);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Config not found: {}", e))?;

    // Backup
    let _ = std::fs::copy(&path, format!("{}.bak", path));

    // Keys we manage — we'll remove these and re-add them with new values
    let managed_keys = [
        "lxc.uts.name", "lxc.start.auto", "lxc.start.delay", "lxc.start.order",
    ];

    // Feature-related lines we'll manage
    let feature_markers = [
        "/dev/net/tun", "/dev/fuse", "nesting.conf",
        "nfsd", "proc:rw sys:rw cgroup:rw",
    ];

    // Cgroup resource keys we manage. Both "cpuset.cpus" and "cpu.max"
    // are listed so a switch between pinning and CFS-quota modes leaves
    // no stale line behind — without this, an old `cpuset.cpus = 0-26`
    // could survive next to a fresh `cpu.max = 2700000 100000` and the
    // kernel would still enforce the pin.
    let resource_patterns = [
        "memory.limit", "memory.max", "memory.memsw", "swap",
        "cpuset.cpus", "cpu.shares", "cpu.weight", "cpu.max",
    ];

    let mut preserved: Vec<String> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            preserved.push(line.to_string());
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
        if parts.len() != 2 {
            preserved.push(line.to_string());
            continue;
        }
        let key = parts[0].trim();
        let val = parts[1].trim();

        // Skip managed keys — we'll re-add them
        if managed_keys.contains(&key) { continue; }

        // Skip ALL lxc.net.N.* keys — we'll re-add them from network_interfaces
        if key.starts_with("lxc.net.") { continue; }

        // Skip feature mount entries we manage
        if key == "lxc.mount.entry" && feature_markers.iter().any(|m| val.contains(m)) { continue; }
        if key == "lxc.include" && (val.contains("nesting.conf") || val.contains("userns.conf")) { continue; }
        if key == "lxc.mount.auto" && val.contains("cgroup") { continue; }

        // Skip idmap lines (managed by privilege toggle)
        if key == "lxc.idmap" { continue; }

        // Skip cgroup2 device allows for TUN/FUSE that we manage
        if (key == "lxc.cgroup2.devices.allow" || key == "lxc.cgroup.devices.allow")
            && (val.contains("10:200") || val.contains("10:229")) { continue; }

        // Skip resource keys we manage
        if resource_patterns.iter().any(|p| key.contains(p)) { continue; }

        // Keep everything else
        preserved.push(line.to_string());
    }

    // Now re-add managed settings with new values
    // Read current config to get defaults for values not being changed
    let current = lxc_parse_config(container).unwrap_or_default();

    // General
    let hostname = settings.hostname.as_deref().unwrap_or(&current.hostname);
    if !hostname.is_empty() {
        preserved.push(format!("lxc.uts.name = {}", hostname));
    }

    let autostart = settings.autostart.unwrap_or(current.autostart);
    if autostart {
        preserved.push("lxc.start.auto = 1".to_string());
        let delay = settings.start_delay.unwrap_or(current.start_delay);
        if delay > 0 { preserved.push(format!("lxc.start.delay = {}", delay)); }
        let order = settings.start_order.unwrap_or(current.start_order);
        if order > 0 { preserved.push(format!("lxc.start.order = {}", order)); }
    }

    // Network — build list of interfaces to write
    let nics: Vec<LxcNetInterface> = if let Some(ref ifaces) = settings.network_interfaces {
        // Use full multi-NIC data from frontend
        ifaces.clone()
    } else {
        // Backward compat: build single NIC from flat fields + current config
        let mut nic0 = current.network_interfaces.first().cloned().unwrap_or_default();
        if let Some(ref v) = settings.net_link { nic0.link = v.clone(); }
        if let Some(ref v) = settings.net_name { nic0.name = v.clone(); }
        if let Some(ref v) = settings.net_hwaddr { nic0.hwaddr = v.clone(); }
        if let Some(ref v) = settings.net_ipv4 { nic0.ipv4 = v.clone(); }
        if let Some(ref v) = settings.net_ipv4_gw { nic0.ipv4_gw = v.clone(); }
        if let Some(ref v) = settings.net_ipv6 { nic0.ipv6 = v.clone(); }
        if let Some(ref v) = settings.net_ipv6_gw { nic0.ipv6_gw = v.clone(); }
        if let Some(ref v) = settings.net_mtu { nic0.mtu = v.clone(); }
        if let Some(ref v) = settings.net_vlan { nic0.vlan = v.clone(); }
        // Include other existing NICs beyond index 0
        let mut all = vec![nic0];
        for nic in current.network_interfaces.iter().skip(1) {
            all.push(nic.clone());
        }
        all
    };

    // Write all network interfaces
    for nic in &nics {
        let i = nic.index;
        let net_type = if nic.net_type.is_empty() { "veth" } else { &nic.net_type };
        preserved.push(format!("lxc.net.{}.type = {}", i, net_type));
        preserved.push(format!("lxc.net.{}.flags = up", i));
        if !nic.link.is_empty() {
            preserved.push(format!("lxc.net.{}.link = {}", i, nic.link));
        }
        let iface_name = if nic.name.is_empty() { format!("eth{}", i) } else { nic.name.clone() };
        preserved.push(format!("lxc.net.{}.name = {}", i, iface_name));
        if !nic.hwaddr.is_empty() {
            preserved.push(format!("lxc.net.{}.hwaddr = {}", i, nic.hwaddr));
        }
        if !nic.ipv4.is_empty() {
            preserved.push(format!("lxc.net.{}.ipv4.address = {}", i, nic.ipv4));
        }
        if !nic.ipv4_gw.is_empty() {
            preserved.push(format!("lxc.net.{}.ipv4.gateway = {}", i, nic.ipv4_gw));
        }
        if !nic.ipv6.is_empty() {
            preserved.push(format!("lxc.net.{}.ipv6.address = {}", i, nic.ipv6));
        }
        if !nic.ipv6_gw.is_empty() {
            preserved.push(format!("lxc.net.{}.ipv6.gateway = {}", i, nic.ipv6_gw));
        }
        if !nic.mtu.is_empty() {
            preserved.push(format!("lxc.net.{}.mtu = {}", i, nic.mtu));
        }
        if !nic.vlan.is_empty() {
            preserved.push(format!("lxc.net.{}.{} = {}",
                i, lxc_vlan_key_suffix(net_type), nic.vlan));
        }
        if nic.firewall {
            preserved.push(format!("lxc.net.{}.firewall = 1", i));
        }
    }

    // Resources — cgroup2 memory.max expects bytes, frontend sends MB
    let mem = settings.memory_limit.as_deref().unwrap_or(&current.memory_limit);
    if !mem.is_empty() {
        let mb = parse_mem_to_mb(mem);
        if mb > 0 {
            let bytes = mb * 1024 * 1024;
            preserved.push(format!("lxc.cgroup2.memory.max = {}", bytes));
        }
    }

    let swap = settings.swap_limit.as_deref().unwrap_or(&current.swap_limit);
    if !swap.is_empty() {
        let mb = parse_mem_to_mb(swap);
        if mb > 0 {
            let bytes = mb * 1024 * 1024;
            preserved.push(format!("lxc.cgroup2.memory.swap.max = {}", bytes));
        }
    }

    // A bare integer N is a CFS-quota soft limit (N cores' worth of CPU
    // time, scheduler free to use any host CPU). An explicit cpuset
    // spec ("0-3", "0,2") is hard pinning. See LxcCpuLimit for the
    // history of why bare-integer is NOT pinning any more.
    let cpus = settings.cpus.as_deref().unwrap_or(&current.cpus);
    if let Some(limit) = lxc_parse_cpu_input(cpus) {
        let (key, value) = limit.cgroup_entry();
        preserved.push(format!("{} = {}", key, value));
    }

    // Features
    let tun = settings.tun_enabled.unwrap_or(current.tun_enabled);
    if tun {
        preserved.push("lxc.mount.entry = /dev/net/tun dev/net/tun none bind,create=file 0 0".to_string());
        preserved.push("lxc.cgroup2.devices.allow = c 10:200 rwm".to_string());
    }

    let fuse = settings.fuse_enabled.unwrap_or(current.fuse_enabled);
    if fuse {
        preserved.push("lxc.mount.entry = /dev/fuse dev/fuse none bind,create=file 0 0".to_string());
        preserved.push("lxc.cgroup2.devices.allow = c 10:229 rwm".to_string());
    }

    let nesting = settings.nesting_enabled.unwrap_or(current.nesting_enabled);
    if nesting {
        preserved.push("lxc.include = /usr/share/lxc/config/nesting.conf".to_string());
        preserved.push("lxc.mount.auto = proc:rw sys:rw cgroup:rw".to_string());
    }

    let nfs = settings.nfs_enabled.unwrap_or(current.nfs_enabled);
    if nfs {
        preserved.push("lxc.mount.entry = nfsd nfsd nfsd defaults 0 0".to_string());
    }

    let keyctl = settings.keyctl_enabled.unwrap_or(current.keyctl_enabled);
    if keyctl && !nesting {
        // Only add if not already covered by nesting
        preserved.push("lxc.mount.auto = proc:rw sys:rw".to_string());
    }

    // Privilege mode (unprivileged = uses idmap for uid/gid remapping)
    let unprivileged = settings.unprivileged.unwrap_or(current.unprivileged);
    if unprivileged {
        preserved.push("lxc.idmap = u 0 100000 65536".to_string());
        preserved.push("lxc.idmap = g 0 100000 65536".to_string());
        preserved.push("lxc.include = /usr/share/lxc/config/userns.conf".to_string());
    }

    // Write final config
    let mut output = preserved.join("\n");
    if !output.ends_with('\n') {
        output.push('\n');
    }

    std::fs::write(&path, &output)
        .map_err(|e| format!("Failed to write config: {}", e))?;

    // Mirror the PRIMARY NIC's static IP (or a revert to DHCP) into the
    // container's OWN network config, so its init honours the address instead
    // of DHCP'ing over the liblxc-assigned one — the same gap the create path
    // had (wabil 2026-06-26, edit path). Skipped when WolfNet manages eth0
    // (handled just below) — detected from the payload OR an existing
    // `.wolfnet/ip` marker, so a save that omits wolfnet_ip can't trip the
    // DHCP revert on a WolfNet container; the helper further scopes to a real
    // user bridge.
    let wolfnet_active = settings.wolfnet_ip.as_deref()
        .map(|s| !s.trim().is_empty()).unwrap_or(false)
        || lxc_get_wolfnet_ip(container).is_some();
    // DNS is a sidecar too (native LXC has no nameserver directive). Persisted
    // BEFORE the in-container network write below, which re-renders every
    // backend from this store — stale here would mean a save that changes both
    // the IP and the DNS writes the old resolvers into the new config.
    let mut dns_changed = false;
    if settings.dns_servers.is_some() || settings.dns_search.is_some() {
        let current_dns = lxc_get_dns(container);
        let new_dns = ContainerDns {
            servers: settings.dns_servers.as_deref()
                .map(parse_dns_servers)
                .unwrap_or_else(|| current_dns.servers.clone()),
            search: settings.dns_search.as_deref()
                .map(parse_dns_search)
                .unwrap_or_else(|| current_dns.search.clone()),
        };
        if new_dns != current_dns {
            lxc_write_dns(container, &new_dns)?;
            dns_changed = true;
        }
    }

    let net_applied = apply_primary_nic_in_container_config(
        container, &nics, &current.network_interfaces, wolfnet_active);

    // Handle WolfNet IP separately (stored in .wolfnet/ip file)
    if let Some(ref wip) = settings.wolfnet_ip {
        let wolfnet_dir = format!("{}/{}/.wolfnet", base, container);
        let wolfnet_ip_file = format!("{}/ip", wolfnet_dir);
        let ip_trimmed = wip.trim();
        if ip_trimmed.is_empty() {
            // Read the old WolfNet IP before deleting the marker so the binding
            // can be torn down inside the container.
            let old_ip = std::fs::read_to_string(&wolfnet_ip_file).unwrap_or_default();
            // Remove WolfNet IP
            let _ = std::fs::remove_file(&wolfnet_ip_file);
            // Rewrite the rootfs net config without the WolfNet IP + drop the
            // live address — otherwise it's re-applied on next start.
            lxc_remove_wolfnet(container, old_ip.trim());
        } else {
            let _ = std::fs::create_dir_all(&wolfnet_dir);
            std::fs::write(&wolfnet_ip_file, ip_trimmed)
                .map_err(|e| format!("Failed to write WolfNet IP: {}", e))?;

            // Ensure the lxcbr0 bridge exists (needed for WolfNet routing)
            ensure_lxc_bridge();

            // Write bridge IP network config into the rootfs so networking
            // is correct even before lxc_apply_wolfnet runs at start time
            assign_container_bridge_ip(container);

            // Standalone LXC uses eth0 on lxcbr0 — make sure it's configured
            if !std::fs::read_to_string(&path).unwrap_or_default().contains("lxcbr0") {
                lxc_ensure_network_config(container);
            }

            // Apply live if the container is running
            let mut info_args: Vec<&str> = Vec::new();
            if base != LXC_DEFAULT_PATH { info_args.extend_from_slice(&["-P", &base]); }
            info_args.extend_from_slice(&["-n", container, "-sH"]);
            let running = Command::new("lxc-info")
                .args(&info_args)
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_uppercase().contains("RUNNING"))
                .unwrap_or(false);
            if running {
                lxc_apply_wolfnet(container);
            }
        }
    }

    // Notes / description — native LXC has no description directive, so it
    // lives in a WolfStack sidecar. Empty string clears it.
    if let Some(ref n) = settings.notes {
        lxc_write_notes(container, n)?;
    }

    // Push the new DNS into the container's /etc/resolv.conf now: a running
    // container re-reads that file on every lookup, so the change takes effect
    // without a restart. The other backends are re-rendered from the same store
    // on the next start (or just above, if the NIC changed too).
    let mut dns_live = false;
    if dns_changed {
        let rootfs = format!("{}/{}/rootfs", base, container);
        let dns = resolve_container_dns(container, &rootfs, &FALLBACK_DNS);
        dns_live = write_rootfs_resolv_conf(&rootfs, &dns);
    }

    // Drop the cached LXC list so the UI re-render picks up the new
    // settings immediately (see the equivalent invalidate in
    // pct_update_settings for the full rationale).
    invalidate_list_caches();

    Ok(match (net_applied, dns_changed, dns_live) {
        (true, _, _) => format!("Settings updated for '{}'. Restart the container to apply the network changes.", container),
        (false, true, true) => format!("Settings updated for '{}'. DNS applied — no restart needed.", container),
        (false, true, false) => format!("Settings updated for '{}'. DNS saved — restart the container to apply it.", container),
        (false, false, _) => format!("Settings updated for '{}'", container),
    })
}

/// Join LXC config lines into a file body, guaranteeing exactly one trailing
/// newline. `Vec<_>::join("\n")` drops the terminating newline, so a config
/// written straight from joined lines is POSIX-malformed — and, worse, any
/// later `>> config` append would land on the same line as the final
/// directive. Every config rewrite goes through this so no writer can
/// reintroduce that (the autostart toggle did, 2026-07: it wrote
/// `lxc.start.auto = 1` with no trailing newline).
fn lxc_config_body<S: AsRef<str>>(lines: &[S]) -> String {
    let mut body = lines.iter().map(|s| s.as_ref()).collect::<Vec<&str>>().join("\n");
    if !body.ends_with('\n') {
        body.push('\n');
    }
    body
}

/// Write an LXC container config from its line vector with a guaranteed
/// trailing newline. See `lxc_config_body`.
fn write_lxc_config<S: AsRef<str>>(path: &str, lines: &[S]) -> std::io::Result<()> {
    std::fs::write(path, lxc_config_body(lines))
}

#[cfg(test)]
mod lxc_config_body_tests {
    use super::lxc_config_body;

    #[test]
    fn always_ends_with_exactly_one_newline() {
        // The autostart-toggle regression: joined lines dropped the trailing
        // newline. The body must always end with exactly one.
        let owned = vec![
            "lxc.start.auto = 1".to_string(),
            "lxc.start.delay = 5".to_string(),
        ];
        assert_eq!(lxc_config_body(&owned), "lxc.start.auto = 1\nlxc.start.delay = 5\n");

        // Works with &str slices too (the mount-remove path uses Vec<&str>).
        assert_eq!(lxc_config_body(&["a", "b"]), "a\nb\n");

        // Idempotent: an already-terminated final line is not doubled.
        assert_eq!(lxc_config_body(&["x\n"]), "x\n");

        // Empty input still yields a newline-terminated (empty) body.
        let empty: [&str; 0] = [];
        assert_eq!(lxc_config_body(&empty), "\n");
    }
}

/// Update LXC container autostart specifically
pub fn lxc_set_autostart(container: &str, enabled: bool) -> Result<String, String> {
    if is_proxmox() {
        let val = if enabled { "1" } else { "0" };
        let output = Command::new("pct")
            .args(["set", container, "--onboot", val])
            .output()
            .map_err(|e| format!("Failed to run pct set: {}", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("pct set failed: {}", stderr));
        }
    } else {
        let path = format!("{}/{}/config", lxc_base_dir(container), container);
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("Config not found: {}", e))?;

        let mut new_lines: Vec<String> = content.lines()
            .filter(|l| !l.trim().starts_with("lxc.start.auto") && !l.trim().starts_with("lxc.start.delay"))
            .map(|l| l.to_string())
            .collect();

        if enabled {
            new_lines.push("lxc.start.auto = 1".to_string());
            new_lines.push("lxc.start.delay = 5".to_string());
        }

        write_lxc_config(&path, &new_lines).map_err(|e| e.to_string())?;
    }
    Ok(format!("Autostart set to {}", enabled))
}

/// Update LXC container network link (bridge/vlan)
pub fn lxc_set_network_link(container: &str, link: &str) -> Result<String, String> {
    let path = format!("{}/{}/config", lxc_base_dir(container), container);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Config not found: {}", e))?;

    let mut new_lines: Vec<String> = Vec::new();
    let mut replaced = false;

    for line in content.lines() {
        if line.trim().starts_with("lxc.net.0.link") {
            new_lines.push(format!("lxc.net.0.link = {}", link));
            replaced = true;
        } else {
            new_lines.push(line.to_string());
        }
    }

    if !replaced {
        new_lines.push(format!("lxc.net.0.link = {}", link));
    }

    write_lxc_config(&path, &new_lines).map_err(|e| e.to_string())?;
    Ok(format!("Network link set to {}", link))
}

/// Find the next available WolfNet IP not in use by any LXC container
/// The set of WolfNet IPs already in use, cluster-wide as far as this node can
/// see (config peers, live interfaces, local containers/VMs/Docker, WolfRun
/// service VIPs + instances on any node, IP mappings, and the poll route cache
/// which carries remote-node container IPs). Shared by the single- and N-IP
/// allocators so they apply identical exclusion rules.
fn wolfnet_used_ip_set() -> Option<(String, std::collections::HashSet<String>)> {
    let prefix = wolfnet_subnet_prefix()?;
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Scan WolfNet config for node's own IP and all peer IPs
    if let Ok(content) = std::fs::read_to_string("/etc/wolfnet/config.toml") {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("address") && trimmed.contains('=')
                && let Some(val) = trimmed.split('=').nth(1) {
                    let ip = val.trim().trim_matches('"').trim().to_string();
                    if !ip.is_empty() { used.insert(ip); }
                }
            // Peer allowed_ip: allowed_ip = "10.10.10.1"
            if trimmed.starts_with("allowed_ip") && trimmed.contains('=')
                && let Some(val) = trimmed.split('=').nth(1) {
                    let ip = val.trim().trim_matches('"').trim().to_string();
                    if !ip.is_empty() { used.insert(ip); }
                }
        }
    }

    // Also reserve .1 (usually gateway), .254 (VM TAP gateway), and .255 (broadcast)
    // Peers wolfnetd knows at runtime (VPN clients, PEX-learned nodes)
    // are not in config.toml, and a workload handed one of their
    // addresses is unreachable from everywhere: the daemon delivers to
    // the peer before it consults the container route map.
    for peer in wolfnet_live_peers() {
        used.insert(peer.address);
    }
    // Stopped workloads on other nodes: reserved there, so reserved here.
    for r in remote_wolfnet_ips() {
        for ip in r.reserved {
            used.insert(ip);
        }
    }

    used.insert(format!("{}.1", prefix));
    used.insert(format!("{}.254", prefix));
    used.insert(format!("{}.255", prefix));

    // Scan live IPs on wolfnet0 interface (catches VIPs, manual assignments)
    if let Ok(output) = std::process::Command::new("ip")
        .args(["addr", "show", "wolfnet0"])
        .output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            // Lines like: "inet 10.10.10.3/24 ..." or "inet 10.10.10.40/32 ..."
            if trimmed.starts_with("inet ")
                && let Some(cidr) = trimmed.split_whitespace().nth(1) {
                    let ip = cidr.split('/').next().unwrap_or("").to_string();
                    if !ip.is_empty() {
                        used.insert(ip);
                    }
                }
        }
    }

    // Scan all LXC containers for WolfNet IPs
    for lxc_path in lxc_storage_paths() {
        if let Ok(entries) = std::fs::read_dir(&lxc_path) {
            for entry in entries.flatten() {
                let ip_file = entry.path().join(".wolfnet/ip");
                if let Ok(ip) = std::fs::read_to_string(&ip_file) {
                    let ip = ip.trim().to_string();
                    if !ip.is_empty() {
                        used.insert(ip);
                    }
                }
            }
        }
    }

    // Scan VM configs for WolfNet IPs. The VM manager stores configs under
    // /var/lib/wolfstack/vms (VmManager::base_dir). We previously looked at
    // /etc/wolfstack/vms, which never existed, so this scan silently added
    // nothing — meaning allocated VM IPs were treated as free and the next
    // allocator call could hand out a colliding address.
    if let Ok(entries) = std::fs::read_dir("/var/lib/wolfstack/vms") {
        for entry in entries.flatten() {
            if let Ok(content) = std::fs::read_to_string(entry.path())
                && let Ok(vm) = serde_json::from_str::<serde_json::Value>(&content)
                    && let Some(ip) = vm.get("wolfnet_ip").and_then(|v| v.as_str())
                        && !ip.is_empty() {
                            used.insert(ip.to_string());
                        }
        }
    }

    // Also check Docker containers with WolfNet labels
    if let Ok(output) = std::process::Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Label \"wolfnet.ip\"}}"])
        .output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let ip = line.trim().to_string();
            if !ip.is_empty() && ip != "<no value>" {
                used.insert(ip);
            }
        }
    }

    // Scan WolfRun services for service VIPs and all instance WolfNet IPs
    // This prevents VIP or remote-node container IPs from being re-allocated
    if let Ok(content) = std::fs::read_to_string(&crate::paths::get().wolfrun_services)
        && let Ok(services) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
            for svc in &services {
                // Service VIP
                if let Some(vip) = svc.get("service_ip").and_then(|v| v.as_str())
                    && !vip.is_empty() {
                        used.insert(vip.to_string());
                    }
                // All instance WolfNet IPs (may be on remote nodes)
                if let Some(instances) = svc.get("instances").and_then(|v| v.as_array()) {
                    for inst in instances {
                        if let Some(ip) = inst.get("wolfnet_ip").and_then(|v| v.as_str())
                            && !ip.is_empty() {
                                used.insert(ip.to_string());
                            }
                    }
                }
            }
        }

    // Scan IP mappings to avoid colliding with port-forward destinations
    if let Ok(content) = std::fs::read_to_string(&crate::paths::get().ip_mappings)
        && let Ok(wrapper) = serde_json::from_str::<serde_json::Value>(&content)
            && let Some(mappings) = wrapper.get("mappings").and_then(|v| v.as_array()) {
                for m in mappings {
                    if let Some(ip) = m.get("wolfnet_ip").and_then(|v| v.as_str())
                        && !ip.is_empty() {
                            used.insert(ip.to_string());
                        }
                }
            }

    // Cluster-wide: check in-memory route cache (populated by poll_remote_nodes)
    // This is more up-to-date than routes.json since it's updated on every poll cycle
    {
        let cache = WOLFNET_ROUTES.lock().unwrap();
        for ip in cache.keys() {
            used.insert(ip.clone());
        }
    }

    // Also check routes.json as fallback (in case cache was reset on restart)
    if let Ok(content) = std::fs::read_to_string("/var/run/wolfnet/routes.json")
        && let Ok(routes) = serde_json::from_str::<std::collections::HashMap<String, String>>(&content) {
            for ip in routes.keys() {
                used.insert(ip.clone());
            }
        }

    Some((prefix, used))
}

/// Persistent record of every WolfNet IP we've ever handed out / seen in use.
/// Unlike the live used-set, entries are NEVER removed when an IP is released —
/// it's a HISTORY, so we can (a) prefer pristine addresses when allocating and
/// (b) warn an operator before they reuse one. Reusing a released IP is the
/// case that bit klasSponsor: stale routing on the old node black-holed the
/// reassigned address (2026-06-24).
const WOLFNET_IP_HISTORY_PATH: &str = "/var/lib/wolfstack/wolfnet-ip-history.json";

pub fn load_wolfnet_ip_history() -> std::collections::HashSet<String> {
    std::fs::read_to_string(WOLFNET_IP_HISTORY_PATH)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Add IPs to the ever-used history (bare addresses, CIDR suffix stripped).
/// Idempotent; only writes when something new is added.
pub fn record_wolfnet_ips_used(ips: &[String]) {
    if ips.is_empty() { return; }
    let mut hist = load_wolfnet_ip_history();
    let mut changed = false;
    for ip in ips {
        let bare = ip.split('/').next().unwrap_or(ip).trim().to_string();
        if !bare.is_empty() && hist.insert(bare) { changed = true; }
    }
    if changed {
        if let Some(parent) = std::path::Path::new(WOLFNET_IP_HISTORY_PATH).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(j) = serde_json::to_string(&hist) {
            let _ = std::fs::write(WOLFNET_IP_HISTORY_PATH, j);
        }
    }
}

/// Has this WolfNet IP ever been used before? (Whether or not it's free now.)
pub fn wolfnet_ip_previously_used(ip: &str) -> bool {
    let bare = ip.split('/').next().unwrap_or(ip).trim();
    !bare.is_empty() && load_wolfnet_ip_history().contains(bare)
}

pub fn next_available_wolfnet_ip() -> Option<String> {
    let (prefix, used) = wolfnet_used_ip_set()?;
    let history = load_wolfnet_ip_history();
    // First choice: a PRISTINE address — free AND never used before. Reusing a
    // released IP risks colliding with routing the old node never withdrew, so
    // we exhaust fresh addresses before recycling.
    for i in 2..=254u8 {
        let candidate = format!("{}.{}", prefix, i);
        if !used.contains(&candidate) && !history.contains(&candidate) {
            return Some(candidate);
        }
    }
    // Fallback: every fresh IP is taken — recycle the lowest released one.
    for i in 2..=254u8 {
        let candidate = format!("{}.{}", prefix, i);
        if !used.contains(&candidate) {
            return Some(candidate);
        }
    }

    None
}

/// Allocate `n` DISTINCT free WolfNet IPs in a single pass over the used set.
/// Used when one host provisions containers that will live on several hosts
/// (e.g. a cross-host Galera cluster): the per-call allocator would re-hand the
/// same lowest free address until each container's IP propagates, so we reserve
/// the whole batch at once. Returns None if fewer than `n` are free.
pub fn next_available_wolfnet_ips(n: usize) -> Option<Vec<String>> {
    if n == 0 { return Some(Vec::new()); }
    let (prefix, used) = wolfnet_used_ip_set()?;
    let history = load_wolfnet_ip_history();
    let mut out = Vec::with_capacity(n);
    // Pristine (never-used) addresses first…
    for i in 2..=254u8 {
        let candidate = format!("{}.{}", prefix, i);
        if !used.contains(&candidate) && !history.contains(&candidate) {
            out.push(candidate);
            if out.len() == n { return Some(out); }
        }
    }
    // …then recycle released ones only if we still need more.
    for i in 2..=254u8 {
        let candidate = format!("{}.{}", prefix, i);
        if !used.contains(&candidate) && !out.contains(&candidate) {
            out.push(candidate);
            if out.len() == n { return Some(out); }
        }
    }
    None
}

/// Detect duplicate MAC addresses and IP addresses across all LXC containers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConflict {
    pub conflict_type: String, // "mac" or "ip"
    pub severity: String,      // "error" or "warning"
    pub value: String,         // the duplicate MAC or IP
    pub containers: Vec<String>, // container names that share this value
}

pub fn detect_network_conflicts() -> Vec<NetworkConflict> {
    let mut mac_map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let mut ip_map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    // Scan all LXC containers
    for lxc_path in lxc_storage_paths() {
        if let Ok(entries) = std::fs::read_dir(&lxc_path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let config_path = entry.path().join("config");
                if let Ok(content) = std::fs::read_to_string(&config_path) {
                    for line in content.lines() {
                        let line = line.trim();
                        let parts: Vec<&str> = line.splitn(2, '=').collect();
                        if parts.len() != 2 { continue; }
                        let key = parts[0].trim();
                        let val = parts[1].trim().to_lowercase();

                        if key == "lxc.net.0.hwaddr" && !val.is_empty() {
                            mac_map.entry(val.clone()).or_default().push(name.clone());
                        }
                        if key == "lxc.net.0.ipv4.address" && !val.is_empty() {
                            // Strip CIDR notation for comparison
                            let ip = val.split('/').next().unwrap_or("").to_string();
                            if !ip.is_empty() {
                                ip_map.entry(ip).or_default().push(name.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    let mut conflicts = Vec::new();

    for (mac, containers) in &mac_map {
        if containers.len() > 1 {
            conflicts.push(NetworkConflict {
                conflict_type: "mac".to_string(),
                severity: "error".to_string(),
                value: mac.clone(),
                containers: containers.clone(),
            });
        }
    }

    for (ip, containers) in &ip_map {
        if containers.len() > 1 {
            conflicts.push(NetworkConflict {
                conflict_type: "ip".to_string(),
                severity: "warning".to_string(),
                value: ip.clone(),
                containers: containers.clone(),
            });
        }
    }

    conflicts
}

/// Autostart all enabled LXC containers, then re-apply WolfNet networking.
/// lxc-autostart doesn't call our lxc_apply_wolfnet(), so we do it afterwards.
pub fn lxc_autostart_all() {
    // Proxmox handles container autostart itself — skip
    if is_proxmox() { return; }

    // Autostart is a machine-boot action, not a WolfStack-restart one. Without
    // this, a WolfStack upgrade re-started onboot containers the operator had
    // deliberately stopped — the same bug reported for VMs (Restraint,
    // 2026-06-23). `lxc-autostart` only ever STARTS guests, so gate it on a real
    // machine boot.
    if !host_recently_booted() { return; }

    // Start containers with autostart enabled (timeout to prevent blocking startup)
    let _ = Command::new("timeout").args(["30", "lxc-autostart"]).output();

    // Give containers a moment to initialise their network interfaces
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Now re-apply WolfNet IPs and host routes for all running containers
    reapply_wolfnet_routes();
}

fn run_lxc_cmd(args: &[&str]) -> Result<String, String> {
    let cmd = args[0];
    let output = Command::new(cmd)
        .args(&args[1..])
        .output()
        .map_err(|e| format!("Failed to run {}: {}", cmd, e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

// ─── Templates & Container Creation ───

/// LXC template entry from the download server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LxcTemplate {
    pub distribution: String,
    pub release: String,
    pub architecture: String,
    pub variant: String,
}

/// List available LXC templates from the LXC image server (standalone) or pveam (Proxmox)
pub fn lxc_list_templates() -> Vec<LxcTemplate> {
    if is_proxmox() {
        return lxc_list_templates_proxmox();
    }

    // Standalone: fetch from lxc image server index
    let output = Command::new("wget")
        .args(["-qO-", "https://images.linuxcontainers.org/meta/1.0/index-system"])
        .output();

    // If wget isn't available, try curl
    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => {
            match Command::new("curl")
                .args(["-sL", "https://images.linuxcontainers.org/meta/1.0/index-system"])
                .output()
            {
                Ok(o) if o.status.success() => o,
                _ => {
                    // Return a curated list of common templates as fallback
                    return vec![
                        LxcTemplate { distribution: "ubuntu".into(), release: "24.04".into(), architecture: host_container_arch().into(), variant: "default".into() },
                        LxcTemplate { distribution: "ubuntu".into(), release: "22.04".into(), architecture: host_container_arch().into(), variant: "default".into() },
                        LxcTemplate { distribution: "ubuntu".into(), release: "20.04".into(), architecture: host_container_arch().into(), variant: "default".into() },
                        LxcTemplate { distribution: "debian".into(), release: "bookworm".into(), architecture: host_container_arch().into(), variant: "default".into() },
                        LxcTemplate { distribution: "debian".into(), release: "bullseye".into(), architecture: host_container_arch().into(), variant: "default".into() },
                        LxcTemplate { distribution: "alpine".into(), release: "3.19".into(), architecture: host_container_arch().into(), variant: "default".into() },
                        LxcTemplate { distribution: "alpine".into(), release: "3.18".into(), architecture: host_container_arch().into(), variant: "default".into() },
                        LxcTemplate { distribution: "fedora".into(), release: "39".into(), architecture: host_container_arch().into(), variant: "default".into() },
                        LxcTemplate { distribution: "centos".into(), release: "9-Stream".into(), architecture: host_container_arch().into(), variant: "default".into() },
                        LxcTemplate { distribution: "archlinux".into(), release: "current".into(), architecture: host_container_arch().into(), variant: "default".into() },
                        LxcTemplate { distribution: "rockylinux".into(), release: "9".into(), architecture: host_container_arch().into(), variant: "default".into() },
                        LxcTemplate { distribution: "opensuse".into(), release: "15.5".into(), architecture: host_container_arch().into(), variant: "default".into() },
                    ];
                }
            }
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut templates = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in text.lines() {
        // Format: distribution;release;architecture;variant;...
        let parts: Vec<&str> = line.split(';').collect();
        if parts.len() >= 4 {
            let dist = parts[0].trim();
            let rel = parts[1].trim();
            let arch = parts[2].trim();
            let variant = parts[3].trim();

            // Skip cloud variants - they require cloud-init and won't work with standard LXC
            let variant_str = if variant.is_empty() { "default" } else { variant };
            if !dist.is_empty() && !rel.is_empty() && !arch.is_empty() {
                let key = format!("{}-{}-{}-{}", dist, rel, arch, variant_str);
                if seen.insert(key) {
                    templates.push(LxcTemplate {
                        distribution: dist.to_string(),
                        release: rel.to_string(),
                        architecture: arch.to_string(),
                        variant: variant_str.to_string(),
                    });
                }
            }
        }
    }

    // Sort by distribution, then release descending
    templates.sort_by(|a, b| {
        a.distribution.cmp(&b.distribution)
            .then(b.release.cmp(&a.release))
    });

    if templates.is_empty() {
        // If parsing failed, return fallback
        return vec![
            LxcTemplate { distribution: "ubuntu".into(), release: "24.04".into(), architecture: host_container_arch().into(), variant: "default".into() },
            LxcTemplate { distribution: "debian".into(), release: "bookworm".into(), architecture: host_container_arch().into(), variant: "default".into() },
            LxcTemplate { distribution: "alpine".into(), release: "3.19".into(), architecture: host_container_arch().into(), variant: "default".into() },
        ];
    }

    templates
}

/// The container-template architecture string for THIS host, in the
/// Debian/LXC-image naming the template servers use (`amd64` / `arm64` /
/// `armhf`) — NOT Rust's `x86_64`/`aarch64`. The template fallback lists and
/// wolfrun-created LXCs use this so an ARM host (e.g. OrangePi 5 / RK3588)
/// requests a rootfs matching the host, instead of the old hardcoded `amd64`
/// which pulled a wrong-arch, unbootable image on ARM boards.
pub fn host_container_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "armhf",
        other => other,
    }
}

/// List available templates from Proxmox (pveam available --section system)
/// Parses template names like: debian-12-standard_12.2-1_amd64.tar.zst
fn lxc_list_templates_proxmox() -> Vec<LxcTemplate> {
    // Update template index first
    let _ = Command::new("pveam").arg("update").output();

    let output = Command::new("pveam")
        .args(["available", "--section", "system"])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => {

            return vec![
                LxcTemplate { distribution: "debian".into(), release: "12".into(), architecture: host_container_arch().into(), variant: "standard".into() },
                LxcTemplate { distribution: "ubuntu".into(), release: "24.04".into(), architecture: host_container_arch().into(), variant: "standard".into() },
                LxcTemplate { distribution: "ubuntu".into(), release: "22.04".into(), architecture: host_container_arch().into(), variant: "standard".into() },
                LxcTemplate { distribution: "alpine".into(), release: "3.20".into(), architecture: host_container_arch().into(), variant: "default".into() },
                LxcTemplate { distribution: "centos".into(), release: "9".into(), architecture: host_container_arch().into(), variant: "default".into() },
                LxcTemplate { distribution: "fedora".into(), release: "40".into(), architecture: host_container_arch().into(), variant: "default".into() },
                LxcTemplate { distribution: "rockylinux".into(), release: "9".into(), architecture: host_container_arch().into(), variant: "default".into() },
            ];
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut templates = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in text.lines() {
        // Format: "system          debian-12-standard_12.2-1_amd64.tar.zst"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 { continue; }
        let tpl_name = parts[1]; // e.g. "debian-12-standard_12.2-1_amd64.tar.zst"

        // Strip file extension (.tar.zst, .tar.gz, .tar.xz)
        let base = tpl_name
            .trim_end_matches(".tar.zst")
            .trim_end_matches(".tar.gz")
            .trim_end_matches(".tar.xz");

        // Parse: {distro}-{release}-{variant}_{version}_{arch}
        // Examples:
        //   debian-12-standard_12.7-1_amd64
        //   ubuntu-24.04-standard_24.04-2_amd64
        //   alpine-3.20-default_20240908_amd64
        //   archlinux-base_20230608-1_amd64  (no release number in name)

        // Extract architecture (last segment after _)
        let arch = if let Some(pos) = base.rfind('_') {
            &base[pos+1..]
        } else {
            host_container_arch()
        };

        // Get the part before the architecture
        let pre_arch = if let Some(pos) = base.rfind('_') {
            &base[..pos]
        } else {
            base
        };

        // Split on the first underscore to separate distro-release-variant from version
        let (dist_rel_var, _version) = if let Some(pos) = pre_arch.find('_') {
            (&pre_arch[..pos], &pre_arch[pos+1..])
        } else {
            (pre_arch, "")
        };

        // Parse distro-release-variant: split by '-' 
        // Common patterns: "debian-12-standard", "ubuntu-24.04-standard", "alpine-3.20-default"
        // Edge cases: "archlinux-base" (no numeric release)
        let segments: Vec<&str> = dist_rel_var.splitn(3, '-').collect();
        let (distro, release, variant) = match segments.len() {
            3 => (segments[0], segments[1], segments[2]),
            2 => {
                // Could be "archlinux-base" or "distro-release"
                let s1 = segments[1];
                if s1.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    (segments[0], s1, "default")
                } else {
                    (segments[0], "latest", s1)
                }
            },
            1 => (segments[0], "latest", "default"),
            _ => continue,
        };

        let key = format!("{}-{}-{}", distro, release, arch);
        if seen.insert(key) {
            templates.push(LxcTemplate {
                distribution: distro.to_string(),
                release: release.to_string(),
                architecture: arch.to_string(),
                variant: variant.to_string(),
            });
        }
    }

    // Sort by distribution, then release descending
    templates.sort_by(|a, b| {
        a.distribution.cmp(&b.distribution)
            .then(b.release.cmp(&a.release))
    });

    if templates.is_empty() {
        return vec![
            LxcTemplate { distribution: "debian".into(), release: "12".into(), architecture: host_container_arch().into(), variant: "standard".into() },
            LxcTemplate { distribution: "ubuntu".into(), release: "24.04".into(), architecture: host_container_arch().into(), variant: "standard".into() },
        ];
    }


    templates
}

// ─── Proxmox VE Detection & Helpers ───

/// Detect if we're running on a Proxmox VE node (cached after first check)
pub fn is_proxmox() -> bool {
    static IS_PVE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *IS_PVE.get_or_init(|| {
        Command::new("which").arg("pct").output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

/// True only if the *machine* booted recently — used to gate guest autostart.
///
/// "Autostart" means "start this guest when the machine boots", NOT when the
/// WolfStack service restarts (e.g. a binary upgrade). Without this gate,
/// updating WolfStack re-started VMs/containers the operator had deliberately
/// stopped — autostart is a reboot action, not a service-restart action
/// (Restraint, 2026-06-23). We approximate "just booted" from host uptime:
/// WolfStack comes up within the first minute or two of boot, so a generous
/// 10-minute window covers slow boots while excluding a service restart on a
/// host that's been up for hours. Reads `/proc/uptime`; if it can't be read we
/// return false (do NOT autostart) so an unexpected platform errs toward the
/// reported complaint — never re-starting a guest the operator stopped.
pub fn host_recently_booted() -> bool {
    const AUTOSTART_BOOT_WINDOW_SECS: f64 = 600.0;
    std::fs::read_to_string("/proc/uptime").ok()
        .map(|s| uptime_within_window(&s, AUTOSTART_BOOT_WINDOW_SECS))
        .unwrap_or(false)
}

/// Parse the first field of `/proc/uptime` (seconds since boot) and test it
/// against `window_secs`. Split out so the gating logic is unit-testable without
/// touching /proc. Unparseable/empty input → false (don't autostart).
fn uptime_within_window(proc_uptime: &str, window_secs: f64) -> bool {
    proc_uptime.split_whitespace().next()
        .and_then(|f| f.parse::<f64>().ok())
        .map(|up| up < window_secs)
        .unwrap_or(false)
}

#[cfg(test)]
mod autostart_gate_tests {
    use super::uptime_within_window;

    #[test]
    fn autostart_only_within_boot_window() {
        // /proc/uptime is "<seconds-since-boot> <idle-seconds>".
        assert!(uptime_within_window("42.13 100.00", 600.0));     // just booted → autostart
        assert!(uptime_within_window("599.9 1.0", 600.0));        // inside the window
        assert!(!uptime_within_window("600.0 1.0", 600.0));       // exactly at the edge → no
        assert!(!uptime_within_window("3601.00 9000.0", 600.0));  // up over an hour → no
        // Unreadable / malformed uptime errs toward NOT autostarting.
        assert!(!uptime_within_window("", 600.0));
        assert!(!uptime_within_window("garbage", 600.0));
    }
}

/// Detect if system has libvirt/virsh for VM management (but is NOT Proxmox)
pub fn is_libvirt() -> bool {
    static IS_LIBVIRT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *IS_LIBVIRT.get_or_init(|| {
        if is_proxmox() { return false; } // Proxmox takes priority
        // Check virsh can actually connect to the hypervisor (not just installed)
        Command::new("virsh").arg("uri").output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

/// True when this host's kernel has AppArmor — and therefore its LXC is built
/// WITH AppArmor support, so `lxc.apparmor.profile` is a valid config key. On
/// SELinux hosts (Fedora, RHEL/Rocky/Alma) AppArmor is absent AND the distro's
/// LXC is built WITHOUT it, so that key is invalid — `lxc-ls`/`lxc-start` fail
/// to parse the WHOLE config and the container silently vanishes from the list
/// (PapaSchlumpf 2026-06-13, Fedora lxc 6.0.6: "Built without AppArmor support").
///
/// We test for the kernel module's PRESENCE, not whether it's enforcing: a
/// Debian/Ubuntu host with AppArmor disabled at boot (`apparmor=0`) still has
/// the module dir and an AppArmor-built LXC, so the key is valid there and must
/// NOT be stripped. Only an entirely AppArmor-less build lacks the module —
/// that's the single case the key breaks. Erring toward "present" means we
/// never strip a valid line (fix, don't break). Cached — doesn't change without
/// a reboot.
pub fn host_has_apparmor() -> bool {
    static HAS_AA: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *HAS_AA.get_or_init(|| {
        // SELinux distros (Fedora, RHEL/Rocky/Alma/Oracle) ship an LXC built
        // WITHOUT AppArmor. The apparmor kernel MODULE can still be loaded there
        // (so the old `/sys/module/apparmor` check returned true), but
        // `lxc.apparmor.profile` is an invalid key for that LXC build and makes
        // it reject the whole config ("Built without AppArmor support") — the
        // container then can't be listed, started, OR destroyed. If SELinux is
        // the active LSM, treat AppArmor as unavailable to LXC regardless of the
        // module. (wabil 2026-06-14: Fedora, apparmor module present but LXC
        // without it — couldn't start or delete containers.)
        if std::path::Path::new("/sys/fs/selinux/enforce").exists() {
            return false;
        }
        std::path::Path::new("/sys/module/apparmor").exists()
    })
}

/// PVE storage entry from `pvesm status`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PveStorage {
    pub id: String,
    pub storage_type: String,
    pub status: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    /// Which content types are allowed (e.g. "images", "rootdir", "vztmpl", "iso")
    pub content: Vec<String>,
    /// Filesystem path for this storage (resolved from /etc/pve/storage.cfg)
    #[serde(default)]
    pub path: Option<String>,
}

/// List available Proxmox storage via `pvesm status`
pub fn pvesm_list_storage() -> Vec<PveStorage> {
    let output = match Command::new("pvesm").args(["status", "--output-format", "json"]).output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => {
            // Fallback: try text format
            return pvesm_list_storage_text();
        }
    };

    // Try JSON parsing first
    if let Ok(items) = serde_json::from_slice::<Vec<serde_json::Value>>(&output) {
        return items.iter().filter_map(|item| {
            let id = item.get("storage")?.as_str()?.to_string();
            let storage_type = item.get("type")?.as_str()?.to_string();
            let status = item.get("status").and_then(|v| v.as_str()).unwrap_or("active").to_string();
            let total = item.get("total").and_then(|v| v.as_u64()).unwrap_or(0) * 1024; // KB to bytes
            let used = item.get("used").and_then(|v| v.as_u64()).unwrap_or(0) * 1024;
            let avail = item.get("avail").and_then(|v| v.as_u64()).unwrap_or(0) * 1024;
            let content = item.get("content").and_then(|v| v.as_str())
                .unwrap_or("")
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let path = pvesm_resolve_path(&id);
            Some(PveStorage { id, storage_type, status, total_bytes: total, used_bytes: used, available_bytes: avail, content, path })
        }).collect();
    }

    pvesm_list_storage_text()
}

/// Fallback: parse `pvesm status` text output
fn pvesm_list_storage_text() -> Vec<PveStorage> {
    let output = match Command::new("pvesm").arg("status").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return vec![],
    };

    // Header: Name           Type     Status           Total            Used       Available        %
    output.lines().skip(1).filter_map(|line| {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 7 { return None; }
        let id = parts[0].to_string();
        let storage_type = parts[1].to_string();
        let status = parts[2].to_string();
        let total = parts[3].parse::<u64>().unwrap_or(0) * 1024;
        let used = parts[4].parse::<u64>().unwrap_or(0) * 1024;
        let avail = parts[5].parse::<u64>().unwrap_or(0) * 1024;

        // Get content types from `pvesm show <storage>`
        let content = pvesm_get_content(&id);
        let path = pvesm_resolve_path(&id);
        Some(PveStorage { id, storage_type, status, total_bytes: total, used_bytes: used, available_bytes: avail, content, path })
    }).collect()
}

/// Get content types for a specific PVE storage
fn pvesm_get_content(storage_id: &str) -> Vec<String> {
    // Try reading from /etc/pve/storage.cfg directly for speed
    if let Ok(cfg) = std::fs::read_to_string("/etc/pve/storage.cfg") {
        let mut in_section = false;
        for line in cfg.lines() {
            let trimmed = line.trim();
            // Section headers look like: dir: local
            if !trimmed.starts_with('#') && trimmed.contains(':') && !trimmed.starts_with('\t') && !trimmed.starts_with(' ') {
                let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                in_section = parts.get(1).map(|s| s.trim()) == Some(storage_id);
            } else if in_section && trimmed.starts_with("content") {
                return trimmed.split_whitespace().skip(1)
                    .flat_map(|s| s.split(','))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
    }
    vec![]
}

/// Resolve a Proxmox storage ID to its filesystem path from /etc/pve/storage.cfg.
/// For ZFS pools, the path is /<pool-name> (the ZFS mountpoint).
/// For dir-type storage, the path is read from the config.
/// The built-in "local" storage is always at /var/lib/vz.
pub fn pvesm_resolve_path(storage_id: &str) -> Option<String> {
    if storage_id == "local" {
        return Some("/var/lib/vz".to_string());
    }
    if let Ok(cfg) = std::fs::read_to_string("/etc/pve/storage.cfg") {
        let mut in_section = false;
        let mut section_type = String::new();
        let mut found_path: Option<String> = None;
        let mut found_pool: Option<String> = None;
        for line in cfg.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with('#') && trimmed.contains(':') && !trimmed.starts_with('\t') && !trimmed.starts_with(' ') {
                // Emit result for previous section if it was ours
                if in_section {
                    break;
                }
                let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                section_type = parts[0].trim().to_string();
                in_section = parts.get(1).map(|s| s.trim()) == Some(storage_id);
                found_path = None;
                found_pool = None;
            } else if in_section {
                if let Some(val) = trimmed.strip_prefix("path") {
                    found_path = Some(val.trim().to_string());
                } else if let Some(val) = trimmed.strip_prefix("pool") {
                    found_pool = Some(val.trim().to_string());
                }
            }
        }
        if in_section {
            // dir-type storages have an explicit path
            if let Some(p) = found_path {
                return Some(p);
            }
            // ZFS storages: the pool name is the ZFS dataset, mountpoint is /<pool>
            if section_type == "zfspool" || section_type == "zfs" {
                if let Some(pool) = found_pool {
                    // Try to get the actual mountpoint from `zfs get mountpoint`
                    if let Ok(output) = Command::new("zfs")
                        .args(["get", "-H", "-o", "value", "mountpoint", &pool])
                        .output()
                        && output.status.success() {
                            let mp = String::from_utf8_lossy(&output.stdout).trim().to_string();
                            if !mp.is_empty() && mp.starts_with('/') {
                                return Some(mp);
                            }
                        }
                    // Fallback: ZFS default mountpoint is /<pool>
                    return Some(format!("/{}", pool));
                }
                // No pool specified — storage ID is likely the pool name
                if let Ok(output) = Command::new("zfs")
                    .args(["get", "-H", "-o", "value", "mountpoint", storage_id])
                    .output()
                    && output.status.success() {
                        let mp = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        if !mp.is_empty() && mp.starts_with('/') {
                            return Some(mp);
                        }
                    }
                return Some(format!("/{}", storage_id));
            }
        }
    }
    None
}

/// Reverse of [`pvesm_resolve_path`]: given a filesystem path, return the PVE
/// storage ID whose `path` matches it. Needed because some UI storage pickers
/// hand back a storage's filesystem path (e.g. the App Store install modal,
/// which sends `s.path || s.id`), but `pct` addresses storage by ID. Returns
/// `None` for a path that isn't a PVE dir storage (e.g. a WolfStack mount),
/// so callers can fall back to the default storage.
pub fn pvesm_resolve_id(path: &str) -> Option<String> {
    let path = path.trim_end_matches('/');
    if path.is_empty() { return None; }
    // The default 'local' dir storage lives at /var/lib/vz.
    if path == "/var/lib/vz" { return Some("local".to_string()); }
    if let Ok(cfg) = std::fs::read_to_string("/etc/pve/storage.cfg") {
        let mut current_id: Option<String> = None;
        for line in cfg.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
            // Section header "type: id" sits flush-left; properties are indented.
            if trimmed.contains(':') && !line.starts_with('\t') && !line.starts_with(' ') {
                let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                current_id = parts.get(1).map(|s| s.trim().to_string());
            } else if let Some(val) = trimmed.strip_prefix("path ") {
                // PVE writes properties as "path <value>" (space-delimited);
                // requiring the space avoids matching keys like "pathname".
                if val.trim().trim_end_matches('/') == path {
                    return current_id.clone();
                }
            }
        }
    }
    None
}

/// Get next available VMID from Proxmox
fn pct_next_vmid() -> Result<u32, String> {
    let output = Command::new("pvesh").args(["get", "/cluster/nextid"])
        .output()
        .map_err(|e| format!("Failed to get next VMID: {}", e))?;
    if !output.status.success() {
        return Err("pvesh get /cluster/nextid failed".to_string());
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    // pvesh may return JSON string like "100" or just 100
    let cleaned = text.trim_matches('"');
    cleaned.parse::<u32>().map_err(|e| format!("Invalid VMID '{}': {}", cleaned, e))
}

/// Find a Proxmox VMID by container hostname/name
#[allow(dead_code)]
fn pct_find_vmid(name: &str) -> Option<u32> {
    let output = Command::new("pct").arg("list").output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let vmid = parts[0];
            let hostname = parts[2..].join(" ");
            // Match by hostname or VMID
            if hostname == name || vmid == name {
                return vmid.parse().ok();
            }
        }
    }
    None
}

/// Download a template to Proxmox's template storage if not already cached
fn pct_ensure_template(storage: &str, distribution: &str, release: &str, architecture: &str) -> Result<String, String> {
    // Check if template already exists
    let list_output = Command::new("pveam").args(["list", storage]).output()
        .map_err(|e| format!("Failed to list templates: {}", e))?;
    let list_text = String::from_utf8_lossy(&list_output.stdout);

    // Look for matching template (e.g. "ubuntu-24.04-standard" or "debian-12-standard")
    let search_term = format!("{}-{}", distribution, release);
    for line in list_text.lines() {
        if line.contains(&search_term) && line.contains(architecture) {
            // Already have this template — extract the volid
            let volid = line.split_whitespace().next().unwrap_or("").to_string();
            if !volid.is_empty() {

                return Ok(volid);
            }
        }
    }

    // Update available template list

    let _ = Command::new("pveam").arg("update").output();

    // Search available templates
    let avail_output = Command::new("pveam").args(["available", "--section", "system"]).output()
        .map_err(|e| format!("Failed to search templates: {}", e))?;
    let avail_text = String::from_utf8_lossy(&avail_output.stdout);

    // Find best matching template
    let mut best_template = String::new();
    for line in avail_text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let template_name = parts[1];
            if template_name.contains(&search_term) {
                // Prefer "standard" variant and matching architecture
                if template_name.contains("standard") || best_template.is_empty() {
                    best_template = template_name.to_string();
                }
            }
        }
    }

    if best_template.is_empty() {
        return Err(format!("No Proxmox template found matching '{} {} {}'. Available templates may not include this distribution/release. Check 'pveam available --section system' on the node.", distribution, release, architecture));
    }

    // Download the template

    let dl_output = Command::new("pveam").args(["download", storage, &best_template]).output()
        .map_err(|e| format!("Failed to download template: {}", e))?;

    if !dl_output.status.success() {
        let stderr = String::from_utf8_lossy(&dl_output.stderr);
        let stdout = String::from_utf8_lossy(&dl_output.stdout);
        return Err(format!("Template download failed for '{}' on storage '{}': {} {}", best_template, storage, stderr.trim(), stdout.trim()));
    }



    // Return the volid
    Ok(format!("{}:vztmpl/{}", storage, best_template))
}

/// Normalise a user-entered bridge IP into CIDR form. Both LXC
/// (`lxc.net.0.ipv4.address`) and Proxmox (`pct ... ip=`) require a prefix
/// length: a bare IPv4 like "192.168.0.99" is rejected by `pct create` and
/// silently ignored by NetworkManager, leaving the container unreachable at the
/// address the user typed. If the value is a bare IPv4 (no `/`), append `/24` —
/// the near-universal small-LAN prefix. Anything already containing `/`, empty,
/// or not a bare IPv4 is returned trimmed and unchanged so a deliberate entry is
/// never corrupted.
pub fn normalize_bridge_cidr(ip: &str) -> String {
    let t = ip.trim();
    if t.is_empty() || t.contains('/') {
        return t.to_string();
    }
    if t.parse::<std::net::Ipv4Addr>().is_ok() {
        format!("{}/24", t)
    } else {
        t.to_string()
    }
}

/// Build the `--net0` value for a Proxmox LXC. Returns `None` for host mode
/// (no network device — matches the standalone `lxc.net.0.type=none` semantics
/// the native path uses). For bridge mode the bridge defaults to `vmbr0` (the
/// Proxmox LAN bridge), NOT `lxcbr0` (the private WolfNet NAT bridge whose
/// dnsmasq hands out 10.0.3.x — the very address bridge-mode users did NOT
/// want). A non-empty `bridge_ip` (CIDR) yields a static config; otherwise DHCP.
fn pct_net0_arg(
    net_mode: &str,
    bridge: Option<&str>,
    bridge_ip: Option<&str>,
    bridge_gateway: Option<&str>,
) -> Option<String> {
    match net_mode {
        "host" => None,
        "bridge" => {
            let br = bridge
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("vmbr0");
            let ip_part = match bridge_ip.map(str::trim).filter(|s| !s.is_empty()) {
                Some(cidr) => match bridge_gateway.map(str::trim).filter(|s| !s.is_empty()) {
                    Some(gw) => format!("ip={},gw={}", cidr, gw),
                    None => format!("ip={}", cidr),
                },
                None => "ip=dhcp".to_string(),
            };
            Some(format!("name=eth0,bridge={},{}", br, ip_part))
        }
        // wolfnet / default / unknown: eth0 on the LAN bridge via DHCP. WolfNet
        // gets its own wn0 NIC on lxcbr0 added separately by the caller.
        _ => Some("name=eth0,bridge=vmbr0,ip=dhcp".to_string()),
    }
}

/// Fix in-container networking for NetworkManager-based distros (AlmaLinux,
/// Rocky, Fedora, CentOS, RHEL), where Proxmox's generated config is
/// unreliable. `static_ip` (CIDR, e.g. "192.168.0.99/24") with an optional
/// `gateway` writes a static keyfile; `None` writes a DHCP keyfile.
fn pct_fix_nm_networking(
    vmid: &str,
    distribution: &str,
    static_ip: Option<&str>,
    gateway: Option<&str>,
) {
    let dist = distribution.to_lowercase();
    let is_nm_distro = dist.contains("alma") || dist.contains("rocky")
        || dist.contains("centos") || dist.contains("fedora")
        || dist.contains("rhel");
    if !is_nm_distro { return; }

    // Mount the container rootfs
    let mount_out = Command::new("pct").args(["mount", vmid]).output();
    match mount_out {
        Ok(ref o) if o.status.success() => {}
        _ => return,
    }

    let rootfs = format!("/var/lib/lxc/{}/rootfs", vmid);
    // Same resolution order as every other writer: the CT config's own
    // `nameserver:` field wins, then whatever PVE seeded into the fresh rootfs
    // (it copies the host's resolvers when no --nameserver was given), then the
    // public fallback this path used unconditionally before.
    let dns = resolve_container_dns(vmid, &rootfs, &["8.8.8.8", "1.1.1.1"]);

    // Write NetworkManager keyfile for eth0 (static if a CIDR was supplied,
    // otherwise DHCP). A static bridge IP must NOT be clobbered by a DHCP
    // keyfile, which is what the old unconditional-DHCP version did.
    let nm_base = format!("{}/etc/NetworkManager", rootfs);
    if std::path::Path::new(&nm_base).exists() {
        let nm_dir = format!("{}/system-connections", nm_base);
        let _ = std::fs::create_dir_all(&nm_dir);
        let conf = match static_ip {
            Some(cidr) => {
                let gw_line = gateway
                    .map(|g| format!("gateway={}\n", g))
                    .unwrap_or_default();
                format!(
                    "[connection]\nid=eth0\ntype=ethernet\ninterface-name=eth0\nautoconnect=true\n\n\
                     [ipv4]\nmethod=manual\naddress1={}\n{}{}\n\
                     [ipv6]\nmethod=auto\n",
                    cidr, gw_line, dns_nm_lines(&dns)
                )
            }
            None => format!(
                "[connection]\nid=eth0\ntype=ethernet\ninterface-name=eth0\nautoconnect=true\n\n\
                 [ipv4]\nmethod=auto\n{}\n\
                 [ipv6]\nmethod=auto\n",
                dns_nm_lines(&dns)
            ),
        };
        let nm_file = format!("{}/eth0.nmconnection", nm_dir);
        let _ = std::fs::write(&nm_file, &conf);
        let _ = std::fs::set_permissions(
            &nm_file,
            std::fs::Permissions::from_mode(0o600),
        );
        // Remove legacy ifcfg files that might conflict
        let _ = std::fs::remove_file(format!(
            "{}/etc/sysconfig/network-scripts/ifcfg-eth0", rootfs
        ));
    }

    // Fallback resolv.conf (DHCP will overwrite if it gets DNS from server)
    write_rootfs_resolv_conf(&rootfs, &dns);

    // Unmount
    let _ = Command::new("pct").args(["unmount", vmid]).output();
}

/// Write the in-container static (or DHCP) network config for a PROXMOX LXC,
/// for EVERY distro — not just the NetworkManager families `pct_fix_nm_networking`
/// covered. `pct set --net0 ip=...` only assigns the address at the veth level;
/// many templates' own init then DHCPs over it (wabil 2026-06-26). `pct mount`
/// exposes the CT rootfs at `/var/lib/lxc/<vmid>/rootfs` — exactly where
/// `lxc_base_dir` resolves it — so we reuse the proven native writers, then
/// `pct unmount`. The CT should be STOPPED (pct refuses to mount a running CT);
/// callers treat a mount failure as warn-and-skip rather than a hard error.
/// `cidr` Some = static, None = DHCP.
fn pct_write_bridge_netconfig(vmid: &str, cidr: Option<&str>, gateway: Option<&str>) -> Result<(), String> {
    let mount = Command::new("pct").args(["mount", vmid]).output()
        .map_err(|e| format!("pct mount failed: {}", e))?;
    if !mount.status.success() {
        return Err(format!(
            "pct mount {} failed (stop the container to change its IP): {}",
            vmid, String::from_utf8_lossy(&mount.stderr).trim()
        ));
    }
    let result = match cidr {
        Some(c) => write_lxc_bridge_static_config(vmid, c, gateway),
        None => write_lxc_bridge_dhcp_config(vmid),
    };
    let _ = Command::new("pct").args(["unmount", vmid]).output();
    result
}

/// Create an LXC container via Proxmox's pct command (public API entry point)
#[allow(clippy::too_many_arguments)]
/// Best available Proxmox storage for container rootfs (content=rootdir) when
/// the caller didn't pick one. Hardcoding "local-lvm" breaks ZFS-only hosts —
/// a host that removed local-lvm years ago gets "storage 'local-lvm' does not
/// exist" on every `pct create` (wabil 2026-06-21). Prefers the conventional
/// local-lvm / local-zfs if present, else the first active rootdir storage.
/// Falls back to "local-lvm" only if `pvesm` can't be queried (preserves the
/// historical default so nothing regresses where detection is unavailable).
pub fn pve_default_container_storage() -> String {
    let text = match Command::new("pvesm").args(["status", "--content", "rootdir"]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => String::new(),
    };
    pick_default_container_storage(&text)
}

/// Pure parser for `pvesm status --content rootdir` output: pick a sensible
/// default container storage. Prefers local-lvm / local-zfs if active, else the
/// first active storage; falls back to "local-lvm" when nothing parses (so a
/// host where detection fails keeps the historical default).
fn pick_default_container_storage(pvesm_status: &str) -> String {
    let active: Vec<&str> = pvesm_status
        .lines()
        .skip(1) // header row
        .filter_map(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            // Columns: Name Type Status ... — keep active storages only.
            if cols.len() >= 3 && cols[2] == "active" { Some(cols[0]) } else { None }
        })
        .collect();
    for pref in ["local-lvm", "local-zfs"] {
        if active.contains(&pref) {
            return pref.to_string();
        }
    }
    active.first().map(|s| s.to_string()).unwrap_or_else(|| "local-lvm".to_string())
}

pub fn pct_create_api(name: &str, distribution: &str, release: &str, architecture: &str,
              storage_id: Option<&str>, template_storage_id: Option<&str>,
              root_password: Option<&str>,
              memory_mb: Option<u32>, cpu_cores: Option<u32>,
              wolfnet_ip: Option<&str>,
              net_mode: &str,
              bridge: Option<&str>, bridge_ip: Option<&str>, bridge_gateway: Option<&str>)
              -> Result<(u32, String), String> {
    let vmid = pct_next_vmid()?;
    // Detect a real rootdir storage when the caller didn't specify one.
    let storage_default = if storage_id.is_none() { pve_default_container_storage() } else { String::new() };
    let storage = storage_id.unwrap_or(&storage_default);

    // Prefer the caller-supplied template storage if they picked one in the
    // UI; otherwise fall back to the "'local' unless the rootfs storage can
    // hold templates" heuristic. LVM and ZFS pools can't hold vztmpl content.
    let template_storage_default = if storage == "local-lvm" || storage == "local-zfs" {
        "local"
    } else {
        storage
    };
    let template_storage = template_storage_id
        .filter(|s| !s.is_empty())
        .unwrap_or(template_storage_default);

    // Ensure the template is downloaded
    let template_volid = pct_ensure_template(template_storage, distribution, release, architecture)?;



    let mut args = vec![
        "create".to_string(),
        vmid.to_string(),
        template_volid,
        "--hostname".to_string(), name.to_string(),
        "--storage".to_string(), storage.to_string(),
        "--rootfs".to_string(), format!("{}:8", storage), // 8GB default rootfs
        "--start".to_string(), "0".to_string(),
        "--unprivileged".to_string(), "1".to_string(),
        "--swap".to_string(), "0".to_string(),
        "--cores".to_string(), "1".to_string(),
    ];

    // Normalise the static IP to CIDR form once, so the --net0 arg and the NM
    // keyfile below agree (a bare IP would be rejected by pct and ignored by NM).
    let norm_bridge_ip: Option<String> = bridge_ip
        .map(normalize_bridge_cidr)
        .filter(|s| !s.is_empty());

    // Honour the chosen network mode. Bridge mode puts eth0 on the user's
    // bridge (static or DHCP); host mode creates no network device; wolfnet
    // and the legacy default both use eth0 on vmbr0 via DHCP (WolfNet then
    // gets its own wn0 NIC below). Previously this was hardcoded to
    // vmbr0/DHCP, so bridge-mode + static IP was silently ignored.
    if let Some(net0) = pct_net0_arg(net_mode, bridge, norm_bridge_ip.as_deref(), bridge_gateway) {
        args.push("--net0".to_string());
        args.push(net0);
    }

    if let Some(pw) = root_password
        && !pw.is_empty() {
            args.push("--password".to_string());
            args.push(pw.to_string());
        }

    if let Some(mem) = memory_mb
        && mem > 0 {
            args.push("--memory".to_string());
            args.push(mem.to_string());
        }

    // Override default cores if user specified
    if let Some(cores) = cpu_cores
        && cores > 0 {
            // Remove the default --cores 1 and replace
            if let Some(pos) = args.iter().position(|a| a == "--cores") {
                args[pos + 1] = cores.to_string();
            }
        }


    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = Command::new("pct")
        .args(&args_ref)
        .output()
        .map_err(|e| format!("Failed to run pct create: {}", e))?;

    if output.status.success() {

        // Fix networking for NetworkManager-based distros (AlmaLinux, Rocky, Fedora, CentOS).
        // Proxmox doesn't always generate correct NM keyfiles for RHEL-family containers,
        // leaving them without working networking. Mount the rootfs, write a proper
        // eth0.nmconnection (static for a bridge-mode static IP, otherwise DHCP) and set
        // fallback DNS. Host mode has no network device, so skip the fixup entirely.
        if net_mode == "bridge" {
            // Bridge mode: write the FULL in-container config (all four backends)
            // for EVERY distro, so the static IP isn't DHCP'd over — pct only does
            // this reliably for some templates (wabil 2026-06-26). Supersedes the
            // NM-only fixup for this case. static_cidr Some = static, None = DHCP.
            let static_cidr = norm_bridge_ip.as_deref().filter(|s| is_ipv4_cidr(s));
            let gw = bridge_gateway.map(str::trim).filter(|s| !s.is_empty());
            if let Err(e) = pct_write_bridge_netconfig(&vmid.to_string(), static_cidr, gw) {
                warn!("VMID {}: in-container network config not written: {}", vmid, e);
            }
        } else if net_mode != "host" {
            // wolfnet / default: keep the NM-distro DHCP fixup (eth0 on vmbr0 via
            // DHCP); WolfNet's own wn0 handling runs separately below.
            pct_fix_nm_networking(&vmid.to_string(), distribution, None, None);
        }

        // Attach WolfNet: add wn0 on lxcbr0 with the WolfNet IP
        if let Some(ip) = wolfnet_ip {
            // Ensure lxcbr0 bridge exists before adding NIC
            ensure_lxc_bridge();

            // Add a second NIC on lxcbr0 for WolfNet traffic — NO ip/gw to avoid
            // conflicting with eth0's default gateway on vmbr0.
            // lxc_apply_wolfnet will assign bridge IP and WolfNet IP at runtime.
            let net1_cfg = "name=wn0,bridge=lxcbr0".to_string();
            let set_out = Command::new("pct")
                .args(["set", &vmid.to_string(), "--net1", &net1_cfg])
                .output();
            match set_out {
                Ok(ref o) if o.status.success() => {

                }
                Ok(ref o) => {
                    error!("Failed to add WolfNet NIC to VMID {}: {}", vmid, String::from_utf8_lossy(&o.stderr));
                }
                Err(e) => {
                    error!("Failed to run pct set for WolfNet NIC on VMID {}: {}", vmid, e);
                }
            }

            // Save the WolfNet marker for lxc_apply_wolfnet (host routing setup at start)
            if let Err(e) = lxc_attach_wolfnet(&vmid.to_string(), ip) {
                error!("WolfNet marker warning for VMID {}: {}", vmid, e);
            }
        }

        Ok((vmid, format!("Container '{}' created (VMID {}, {} {} {}, storage: {})", name, vmid, distribution, release, architecture, storage)))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        error!("pct create failed for '{}' (VMID {}): {} {}", name, vmid, stderr.trim(), stdout.trim());
        Err(format!("Container creation failed (VMID {}): {} {}", vmid, stderr.trim(), stdout.trim()))
    }
}

// ─── Clone, Export, Import ───

/// Clone an LXC container on the same node
pub fn lxc_clone_local(source: &str, new_name: &str, storage: Option<&str>, vmid: Option<u32>) -> Result<String, String> {



    if is_proxmox() {
        // Honour an operator-chosen VMID; fall back to the cluster's next free
        // id only when none was supplied. pct clone rejects a VMID that's
        // already taken (cluster-wide via pmxcfs), so we let it be the
        // authority on uniqueness and just bound the low end here.
        let new_vmid = match vmid {
            Some(v) if v >= 100 => v,
            Some(v) => return Err(format!("Invalid VMID {} — Proxmox VMIDs must be 100 or higher", v)),
            None => pct_next_vmid()?,
        };
        let mut args = vec![
            "clone".to_string(),
            source.to_string(),          // source VMID
            new_vmid.to_string(),        // target VMID
            "--hostname".to_string(), new_name.to_string(),
            "--full".to_string(), "1".to_string(),  // full clone, not linked
        ];
        if let Some(s) = storage
            && !s.is_empty() {
                args.push("--storage".to_string());
                args.push(s.to_string());
            }
    
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("pct").args(&args_ref).output()
            .map_err(|e| format!("Failed to run pct clone: {}", e))?;

        if output.status.success() {
            // Clone everything as-is: `pct clone --full` already made an exact
            // copy of the config + rootfs. We deliberately do NOT run
            // lxc_clone_fixup_ip (which reseats MAC/IP for standalone clones) —
            // the operator asked for a faithful duplicate. Carry the source's
            // WolfNet IP across too so the copy is truly identical; the operator
            // changes the new container's network identity before starting it
            // alongside the original, and the start-time WolfNet conflict check
            // refuses a duplicate if they forget.
            if let Some(ip) = lxc_get_wolfnet_ip(source) {
                lxc_set_wolfnet_marker(&new_vmid.to_string(), &ip);
            }
            Ok(format!("Container '{}' cloned to '{}' (VMID {}). Created stopped — review its IP / WolfNet identity before starting it alongside the original.", source, new_name, new_vmid))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(format!("Clone failed: {} {}", stderr.trim(), stdout.trim()))
        }
    } else {
        // Standalone: lxc-copy
        let mut args = vec!["-n", source, "-N", new_name];
        let path_str;
        if let Some(s) = storage
            && !s.is_empty() && s != LXC_DEFAULT_PATH {
                path_str = s.to_string();
                args.push("-P");
                args.push(&path_str);
            }
        let output = Command::new("lxc-copy").args(&args).output()
            .map_err(|e| format!("Failed to run lxc-copy: {}", e))?;

        if output.status.success() {
            // Register the storage path if non-default
            if let Some(s) = storage
                && !s.is_empty() && s != LXC_DEFAULT_PATH {
                    lxc_register_path(s);
                }
            lxc_clone_fixup_ip(new_name);
            Ok(format!("Container '{}' cloned to '{}'", source, new_name))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("Clone failed: {}", stderr.trim()))
        }
    }
}

/// Export container metadata for transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerExportMeta {
    pub name: String,
    pub distribution: String,
    pub release: String,
    pub architecture: String,
    pub memory_mb: Option<u32>,
    pub cpu_cores: Option<u32>,
    pub source_type: String, // "proxmox" or "standalone"
    pub archive_format: String, // "vzdump" or "tar.gz"
    /// The source container's full LXC config file, carried alongside the
    /// rootfs so a standalone import can reconstruct a *bootable* config
    /// (arch, idmap, apparmor, cgroup mounts, resource limits) instead of
    /// the old 3-line stub that left systemd containers in ABORTING.
    /// None for Proxmox sources — their config travels inside the vzdump.
    #[serde(default)]
    pub lxc_config: Option<String>,
}

/// Export an LXC container to an archive file
/// Returns (archive_path, metadata)
pub fn lxc_export(container: &str) -> Result<(std::path::PathBuf, ContainerExportMeta), String> {
    let export_dir = std::path::Path::new("/tmp/wolfstack-exports");
    std::fs::create_dir_all(export_dir).map_err(|e| format!("Failed to create export dir: {}", e))?;

    if is_proxmox() {
        // Use vzdump for Proxmox containers

        let output = Command::new("vzdump")
            .args([container, "--dumpdir", "/tmp/wolfstack-exports", "--mode", "stop", "--compress", "zstd"])
            .output()
            .map_err(|e| format!("vzdump failed to start: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("vzdump failed: {}", stderr.trim()));
        }

        // Find the generated vzdump file
        let stdout = String::from_utf8_lossy(&output.stdout);
        let archive_path = find_vzdump_archive(&stdout, export_dir, container)?;

        // Extract metadata from pct config. Proxmox carries the container
        // config inside the vzdump (etc/vzdump/pct.conf), so we leave
        // lxc_config None — the standalone-import path synthesises one if
        // it ever receives a vzdump on a non-Proxmox target.
        let meta = extract_pve_container_meta(container)?;

        Ok((archive_path, meta))
    } else {
        // Standalone: tar only the rootfs (not the LXC config or other host-side files)

        let container_dir = format!("{}/{}", lxc_base_dir(container), container);
        let rootfs_dir = format!("{}/rootfs", container_dir);
        // Use rootfs/ subdir if it exists, otherwise tar the container dir directly
        let tar_source = if std::path::Path::new(&rootfs_dir).exists() {
            &rootfs_dir
        } else if std::path::Path::new(&container_dir).exists() {
            &container_dir
        } else {
            return Err(format!("Container directory not found: {}", container_dir));
        };

        let archive_name = format!("{}.tar.gz", container);
        let archive_path = export_dir.join(&archive_name);

        let output = Command::new("tar")
            .args(["czf", archive_path.to_str().unwrap(),
                   "--exclude=./proc/*", "--exclude=./sys/*", "--exclude=./dev/*",
                   "-C", tar_source, "."])
            .output()
            .map_err(|e| format!("tar failed: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("tar failed: {}", stderr.trim()));
        }

        // Carry the source container's LXC config so the destination can
        // rebuild a bootable config rather than the old minimal stub. The
        // config lives one level up from the rootfs (container_dir/config).
        let lxc_config = std::fs::read_to_string(format!("{}/config", container_dir)).ok();

        let meta = ContainerExportMeta {
            name: container.to_string(),
            distribution: "unknown".to_string(),
            release: "unknown".to_string(),
            architecture: host_container_arch().to_string(),
            memory_mb: None,
            cpu_cores: None,
            source_type: "standalone".to_string(),
            archive_format: "tar.gz".to_string(),
            lxc_config,
        };


        Ok((archive_path, meta))
    }
}

/// Find the vzdump archive file from vzdump output
fn find_vzdump_archive(stdout: &str, export_dir: &std::path::Path, vmid: &str) -> Result<std::path::PathBuf, String> {
    // vzdump prints the archive path: "creating vzdump archive '/tmp/.../vzdump-lxc-100-...tar.zst'"
    for line in stdout.lines() {
        if line.contains("creating") && line.contains("vzdump")
            && let Some(start) = line.find('\'')
                && let Some(end) = line.rfind('\'')
                    && start < end {
                        let path = &line[start+1..end];
                        let p = std::path::PathBuf::from(path);
                        if p.exists() {
                            return Ok(p);
                        }
                    }
    }
    // Fallback: search the export dir for the newest vzdump file matching this vmid
    if let Ok(entries) = std::fs::read_dir(export_dir) {
        let mut best: Option<(std::path::PathBuf, std::time::SystemTime)> = None;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&format!("vzdump-lxc-{}-", vmid))
                && let Ok(meta) = entry.metadata()
                    && let Ok(modified) = meta.modified()
                        && best.as_ref().map(|(_, t)| modified > *t).unwrap_or(true) {
                            best = Some((entry.path(), modified));
                        }
        }
        if let Some((path, _)) = best {
            return Ok(path);
        }
    }
    Err(format!("Could not find vzdump archive for VMID {}", vmid))
}

/// Extract container metadata from Proxmox config
fn extract_pve_container_meta(vmid: &str) -> Result<ContainerExportMeta, String> {
    let output = Command::new("pct").args(["config", vmid]).output()
        .map_err(|e| format!("pct config failed: {}", e))?;
    let config_text = String::from_utf8_lossy(&output.stdout);

    let mut memory_mb = None;
    let mut cpu_cores = None;
    let mut hostname = vmid.to_string();
    // `pct config` reports the container's own arch (`arch: amd64` / `arm64`);
    // use it so a cross-arch container is labelled correctly. Fall back to the
    // host arch only when the field is absent.
    let mut architecture = None;

    for line in config_text.lines() {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() == 2 {
            let key = parts[0].trim();
            let val = parts[1].trim();
            match key {
                "hostname" => hostname = val.to_string(),
                "memory" => memory_mb = val.parse().ok(),
                "cores" => cpu_cores = val.parse().ok(),
                "arch" if !val.is_empty() => architecture = Some(val.to_string()),
                _ => {}
            }
        }
    }

    Ok(ContainerExportMeta {
        name: hostname,
        distribution: "unknown".to_string(),
        release: "unknown".to_string(),
        architecture: architecture.unwrap_or_else(|| host_container_arch().to_string()),
        memory_mb,
        cpu_cores,
        source_type: "proxmox".to_string(),
        archive_format: "vzdump".to_string(),
        lxc_config: None,
    })
}

/// Result of importing an LXC container: a human-readable message plus
/// the identifier the caller uses to start it. Proxmox addresses
/// containers by VMID, standalone LXC by name — so a migrate orchestrator
/// can't assume which to pass to `lxc_start`; this carries the right one.
pub struct LxcImportOutcome {
    pub message: String,
    pub start_id: String,
}

/// Remove every `lxc.apparmor.profile` line from a container config, preserving
/// the original line-ending style and trailing-newline shape. Pure for
/// testability. Scope: only the `lxc.apparmor.profile` key WolfStack writes —
/// any manually-added `lxc.apparmor.*` keys are left alone.
fn strip_apparmor_profile(content: &str) -> String {
    let nl = if content.contains("\r\n") { "\r\n" } else { "\n" };
    let trailing_nl = content.ends_with('\n');
    let mut out = content
        .lines()
        .filter(|l| !l.trim_start().starts_with("lxc.apparmor.profile"))
        .collect::<Vec<_>>()
        .join(nl);
    if trailing_nl { out.push_str(nl); }
    out
}

/// Reactively strip an unparseable `lxc.apparmor.profile` line from ONE
/// container's on-disk config, just before an operation that loads it
/// (start/destroy), on hosts whose LXC lacks AppArmor. Belt-and-suspenders
/// alongside the startup migration: heals a container that appeared after
/// startup, or one the migration skipped. No-op on AppArmor hosts, Proxmox, or
/// an already-clean config. Atomic (temp + rename) so it can never truncate.
fn heal_lxc_apparmor_config(container: &str) {
    if host_has_apparmor() || is_proxmox() { return; }
    let path = format!("{}/{}/config", lxc_base_dir(container), container);
    let Ok(content) = std::fs::read_to_string(&path) else { return };
    if !content.contains("lxc.apparmor.profile") { return; }
    let cleaned = strip_apparmor_profile(&content);
    if cleaned == content { return; }
    let tmp = format!("{}.wolfstack-heal.tmp", path);
    if std::fs::write(&tmp, &cleaned).is_ok() && std::fs::rename(&tmp, &path).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Repair existing container configs that carry an `lxc.apparmor.profile` line
/// this host's LXC can't parse. On AppArmor-less builds (Fedora/SELinux) that
/// key is invalid, so `lxc-ls`/`lxc-start` reject the WHOLE config and the
/// container silently disappears from the list (PapaSchlumpf 2026-06-13).
/// Strips the line from every container config under the registered storage
/// paths. No-op on AppArmor hosts (the line is valid there) and on Proxmox
/// (PVE owns its container configs). Runs at startup, before lxc_autostart_all,
/// so already-broken containers list AND start again with no manual re-create.
///
/// The rewrite is atomic (temp file + rename) so an interrupted run can never
/// truncate a config — this must FIX broken configs, never break intact ones.
pub fn lxc_migrate_apparmor_configs() {
    if host_has_apparmor() || is_proxmox() { return; }
    let mut fixed = 0usize;
    for base in lxc_storage_paths() {
        let entries = match std::fs::read_dir(&base) { Ok(e) => e, Err(_) => continue };
        for entry in entries.flatten() {
            let cfg = entry.path().join("config");
            if !cfg.is_file() { continue; }
            let Ok(content) = std::fs::read_to_string(&cfg) else { continue };
            if !content.contains("lxc.apparmor.profile") { continue; }
            let cleaned = strip_apparmor_profile(&content);
            // Atomic replace: write a sibling temp on the same filesystem, then
            // rename over the original. A crash mid-write leaves the original
            // config fully intact (never a truncated/0-byte config).
            let tmp = cfg.with_extension("wolfstack-tmp");
            let wrote = std::fs::write(&tmp, &cleaned)
                .and_then(|_| std::fs::rename(&tmp, &cfg));
            match wrote {
                Ok(()) => {
                    fixed += 1;
                    info!("LXC: stripped unsupported lxc.apparmor.profile from {}", cfg.display());
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp); // don't leave a stray temp
                    warn!("LXC: could not repair {}: {} (config left unchanged)", cfg.display(), e);
                }
            }
        }
    }
    if fixed > 0 {
        info!("LXC: repaired {} container config(s) carrying an AppArmor key this host's LXC can't parse (built without AppArmor)", fixed);
        invalidate_count_caches();
    }
}

/// True if the rootfs boots with systemd as PID 1 (Debian Bookworm+,
/// Ubuntu, Fedora, Rocky, Alma, openSUSE, Arch — everything bar Alpine
/// and Void). Such inits die on a missing cgroup mount, so they need
/// `lxc.mount.auto` + an apparmor decision in the config.
fn rootfs_uses_systemd(rootfs: &str) -> bool {
    std::path::Path::new(&format!("{}/lib/systemd/systemd", rootfs)).exists()
        || std::path::Path::new(&format!("{}/usr/lib/systemd/systemd", rootfs)).exists()
        || std::fs::read_link(format!("{}/sbin/init", rootfs))
            .map(|p| p.to_string_lossy().contains("systemd"))
            .unwrap_or(false)
}

/// Heuristic for an unprivileged container: its rootfs is stored
/// uid-shifted, so files that are root *inside* the container are owned
/// by 100000+ on the host. We read the actual extracted ownership rather
/// than guessing the privilege mode.
fn rootfs_is_unprivileged(rootfs: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    for probe in ["etc", "usr", "bin"] {
        if let Ok(md) = std::fs::metadata(format!("{}/{}", rootfs, probe)) {
            return md.uid() >= 100_000;
        }
    }
    false
}

/// Detect whether an LXC archive is a Proxmox vzdump (vs a native WolfStack
/// rootfs tar). WolfStack's own native LXC backups are always `lxc-*.tar.gz`
/// (gzip); a Proxmox vzdump is `vzdump-lxc-*.tar.zst` (zstd). Either signal —
/// the `vzdump` name or zstd compression — identifies it. Used by the restore
/// path to route a Proxmox-origin backup landing on a native host (and vice
/// versa) instead of feeding it to the wrong restorer. (Safe while native LXC
/// backups stay gzip — see `backup_lxc`, which always writes `.tar.gz`.)
pub(crate) fn lxc_archive_is_vzdump(archive_path: &str) -> bool {
    let p = archive_path.to_ascii_lowercase();
    p.contains("vzdump") || p.ends_with(".tar.zst") || p.ends_with(".zst")
}

/// Extract an LXC backup/export archive's root filesystem into `rootfs_target`.
/// Handles both gzip (native WolfStack) and zstd (Proxmox vzdump) compression,
/// and normalises the layouts a vzdump can land in: when the rootfs comes out
/// nested under `rootfs_target/rootfs/` it is flattened up, and (ONLY for a
/// vzdump source) the Proxmox `etc/vzdump` metadata dir is stripped. A native
/// backup's filesystem is taken verbatim — including any legitimate
/// `/etc/vzdump` it might carry. The caller still owns writing the LXC
/// `config` (see [`lxc_write_bootable_config`]).
///
/// Returns the salvaged `etc/vzdump/pct.conf` content for a vzdump source
/// (read before the dir is stripped) — the only record of the Proxmox
/// container's memory/cpu limits and autostart flag, which the caller can
/// translate into the native config. `None` for a native archive.
pub(crate) fn lxc_extract_archive_to_rootfs(archive_path: &str, rootfs_target: &str) -> Result<Option<String>, String> {
    let tar_args: Vec<&str> = if archive_path.ends_with(".tar.zst") || archive_path.ends_with(".zst") {
        vec!["--zstd", "-xf", archive_path, "-C", rootfs_target]
    } else {
        vec!["xzf", archive_path, "-C", rootfs_target]
    };
    let output = Command::new("tar")
        .args(&tar_args)
        .output()
        .map_err(|e| format!("tar extract failed: {}", e))?;
    if !output.status.success() {
        return Err(format!("tar extract failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }

    // A vzdump can land the rootfs nested under rootfs_target/rootfs/ — flatten
    // it up. (Paths are quoted in case rootfs_target ever contains a space.)
    let nested_rootfs = format!("{}/rootfs", rootfs_target);
    if std::path::Path::new(&nested_rootfs).exists() {
        let _ = Command::new("bash")
            .args(["-c", &format!(
                "shopt -s dotglob; mv \"{t}\"/rootfs/* \"{t}\"/ 2>/dev/null; rmdir \"{t}\"/rootfs 2>/dev/null; true",
                t = rootfs_target
            )])
            .output();
    }
    // Strip the Proxmox backup-bookkeeping dir ONLY for a vzdump source — a
    // native container can legitimately carry its own /etc/vzdump. Salvage
    // pct.conf first: deleting it unread is how a migrated container used to
    // lose its memory/cpu limits and autostart flag on a native destination.
    let mut pct_conf = None;
    if lxc_archive_is_vzdump(archive_path) {
        pct_conf = std::fs::read_to_string(format!("{}/etc/vzdump/pct.conf", rootfs_target)).ok();
        let _ = std::fs::remove_dir_all(format!("{}/etc/vzdump", rootfs_target));
    }
    Ok(pct_conf)
}

/// Write a *bootable* LXC config for a freshly-imported standalone
/// container. Prefers the source's own config (carried with the archive)
/// so arch/idmap/apparmor/cgroup/resource limits survive the move;
/// otherwise synthesises a complete config from the rootfs. The old code
/// wrote only `rootfs.path` + `uts.name` + `net.0.type = empty`, which
/// left systemd containers stuck in ABORTING for want of cgroup mounts,
/// an idmap and an apparmor decision — see `lxc_create`'s systemd block
/// for the authoritative list of what such a rootfs needs.
///
/// `pve_config` is the salvaged `pct.conf` of a vzdump source (see
/// [`lxc_extract_archive_to_rootfs`]): its memory/swap/cores limits and
/// onboot flag are translated into the synthesised config so a Proxmox
/// container landing on a native host keeps its resource envelope instead
/// of arriving unlimited, and its `net0` bridge/MAC/address are carried
/// where this host can honour them. Ignored when a carried native config
/// exists — that already holds the real limits.
///
/// Returns a warning when the source's network could not be reproduced
/// (its bridge doesn't exist here) — the caller MUST surface it to the
/// operator: a container silently dropped onto the wrong network looks
/// migrated until something can't reach it (RutgerDiehard, 2026-08-07).
///
/// `target_bridge` is an operator-chosen destination bridge for the
/// primary NIC — already validated to exist by the import endpoint. It
/// overrides both the carried config's `lxc.net.0.link` and the vzdump
/// translation's bridge choice, and suppresses the fallback warning
/// (the operator made the call).
pub(crate) fn lxc_write_bootable_config(
    container_dir: &str,
    new_name: &str,
    carried_config: Option<&str>,
    pve_config: Option<&str>,
    target_bridge: Option<&str>,
) -> Option<String> {
    let config_path = format!("{}/config", container_dir);
    if std::path::Path::new(&config_path).exists() {
        return None; // native tooling already wrote a real config — leave it
    }

    if let Some(cfg) = carried_config.filter(|c| !c.trim().is_empty()) {
        // The source's real config. rootfs.path/uts.name/networking are
        // host-specific and get rewritten by lxc_clone_fixup_ip after
        // this returns; everything else (arch, idmap, apparmor, cgroup
        // mounts, cpu/mem limits, mounts, features) is preserved as-is.
        // An explicit bridge choice re-points the primary NIC only.
        let cfg_out = match target_bridge {
            Some(bridge) => cfg.lines().map(|l| {
                if l.trim().starts_with("lxc.net.0.link") {
                    format!("lxc.net.0.link = {}", bridge)
                } else {
                    l.to_string()
                }
            }).collect::<Vec<_>>().join("\n") + "\n",
            None => cfg.to_string(),
        };
        let _ = std::fs::write(&config_path, cfg_out);
        return None;
    }

    // No carried config (a vzdump landing on a standalone node, or an
    // older source node that predates config-carrying). Synthesise.
    let rootfs = format!("{}/rootfs", container_dir);
    let unprivileged = rootfs_is_unprivileged(&rootfs);
    let systemd = rootfs_uses_systemd(&rootfs);

    let mut lines: Vec<String> = Vec::new();
    // lxc.arch must match the rootfs personality. A migrate stays within one
    // cluster, so the rootfs is this host's arch — set the personality to match
    // (arm64 on RK3588/OrangePi) instead of a hardcoded amd64, which would make
    // an ARM container refuse to exec.
    lines.push(format!("lxc.arch = {}", host_container_arch()));
    lines.push("lxc.include = /usr/share/lxc/config/common.conf".to_string());
    if unprivileged {
        lines.push("lxc.include = /usr/share/lxc/config/userns.conf".to_string());
        lines.push("lxc.idmap = u 0 100000 65536".to_string());
        lines.push("lxc.idmap = g 0 100000 65536".to_string());
    }
    lines.push(format!("lxc.rootfs.path = dir:{}/rootfs", container_dir));
    lines.push(format!("lxc.uts.name = {}", new_name));
    // A real veth — the source's own bridge/MAC/address where this host can
    // honour them (vzdump net0 translation), lxcbr0 otherwise. A clone's
    // lxc_clone_fixup_ip refines the hwaddr + IPv4 and lxc_attach_wolfnet
    // adds the WolfNet marker after.
    lines.push("lxc.net.0.type = veth".to_string());
    // With an explicit bridge choice the translator carries everything
    // (`|_| true` — no fallback, no warning) and the link line is then
    // re-pointed at the operator's bridge.
    let (net_lines, net_warning) = match target_bridge {
        Some(bridge) => {
            let (net_lines, _) = native_net0_from_pct_conf(pve_config.unwrap_or(""), &|_| true);
            (net_lines.into_iter().map(|l| {
                if l.starts_with("lxc.net.0.link") {
                    format!("lxc.net.0.link = {}", bridge)
                } else {
                    l
                }
            }).collect::<Vec<_>>(), None)
        }
        None => native_net0_from_pct_conf(
            pve_config.unwrap_or(""),
            &|bridge| std::path::Path::new(&format!("/sys/class/net/{}", bridge)).exists(),
        ),
    };
    lines.extend(net_lines);
    lines.push("lxc.net.0.flags = up".to_string());
    lines.push("lxc.net.0.name = eth0".to_string());
    if systemd {
        // Identical to lxc_create's systemd-compat toggles. Placed after
        // common.conf so the unconfined apparmor profile wins the include.
        lines.push("lxc.include = /usr/share/lxc/config/nesting.conf".to_string());
        // Only on AppArmor hosts — on SELinux/no-AppArmor LXC builds (Fedora)
        // this key is invalid and makes lxc-ls/lxc-start reject the config.
        if host_has_apparmor() {
            lines.push("lxc.apparmor.profile = unconfined".to_string());
        }
        lines.push("lxc.mount.auto = proc:rw sys:rw cgroup:rw".to_string());
    }

    // A vzdump source's resource envelope, translated from its pct.conf.
    if let Some(pct) = pve_config.filter(|c| !c.trim().is_empty()) {
        lines.extend(lxc_limits_from_pct_conf(pct));
    }

    let mut out = lines.join("\n");
    out.push('\n');
    let _ = std::fs::write(&config_path, out);
    net_warning
}

/// The reverse of [`pve_net0_from_lxc_config`]: translate a Proxmox
/// `pct.conf` `net0:` line into native `lxc.net.0.*` entries for a
/// synthesised config.
///
/// * `bridge=` is carried only when that bridge exists on THIS host
///   (`bridge_exists`); otherwise the container goes on `lxcbr0` and a
///   warning names the bridge (and old address) so the operator knows the
///   container changed networks — the silent fallback is exactly what
///   dropped RutgerDiehard's LXC onto the management VLAN (2026-08-07).
/// * `hwaddr=` is always carried — preserving the MAC keeps a DHCP lease
///   on a same-network move; a cross-cluster clone re-MACs it afterwards.
/// * A static `ip=`/`gw=` pair is carried only WITH its original bridge —
///   an address from the old network is meaningless on lxcbr0.
///
/// No `net0:` at all (or an empty pct.conf) yields the plain lxcbr0 line
/// and no warning. Only the live section is read (per-snapshot values
/// must not bleed in). Pure apart from the injected `bridge_exists`.
fn native_net0_from_pct_conf(
    pct_conf: &str,
    bridge_exists: &dyn Fn(&str) -> bool,
) -> (Vec<String>, Option<String>) {
    let (mut bridge, mut hwaddr, mut ip, mut gw) =
        (String::new(), String::new(), String::new(), String::new());
    for line in pct_conf.lines().take_while(|l| !l.trim_start().starts_with('[')) {
        let Some((k, v)) = line.split_once(':') else { continue };
        if k.trim() != "net0" { continue; }
        for part in v.trim().split(',') {
            let Some((pk, pv)) = part.trim().split_once('=') else { continue };
            match pk.trim() {
                "bridge" => bridge = pv.trim().to_string(),
                "hwaddr" => hwaddr = pv.trim().to_string(),
                "ip" => ip = pv.trim().to_string(),
                "gw" => gw = pv.trim().to_string(),
                _ => {}
            }
        }
        break;
    }

    let mut lines = Vec::new();
    let mut warning = None;
    let bridge_ok = !bridge.is_empty() && bridge_exists(&bridge);
    if bridge_ok {
        lines.push(format!("lxc.net.0.link = {}", bridge));
    } else {
        if !bridge.is_empty() {
            let had_ip = if ip.is_empty() || ip == "dhcp" {
                String::new()
            } else {
                format!(" (it had ip={})", ip)
            };
            warning = Some(format!(
                "the source's bridge '{}' does not exist on this host, so the container was attached to lxcbr0 with a fresh address instead{} — re-attach it to the right bridge in Settings → Resources if it needs its old network",
                bridge, had_ip
            ));
        }
        lines.push("lxc.net.0.link = lxcbr0".to_string());
    }
    if !hwaddr.is_empty() {
        lines.push(format!("lxc.net.0.hwaddr = {}", hwaddr));
    }
    if bridge_ok && !ip.is_empty() && ip != "dhcp" {
        lines.push(format!("lxc.net.0.ipv4.address = {}", ip));
        if !gw.is_empty() {
            lines.push(format!("lxc.net.0.ipv4.gateway = {}", gw));
        }
    }
    (lines, warning)
}

/// Translate a Proxmox `pct.conf`'s resource keys into native LXC config
/// lines, using the same cgroup2 keys the Settings UI writes (see
/// `lxc_update_config`): `memory:`/`swap:` are MB → `memory.max`/
/// `memory.swap.max` bytes, `cores:` becomes the same CFS-quota entry a
/// bare integer in the CPU field produces, `onboot: 1` → `lxc.start.auto`.
/// Only the live section is read — per-snapshot `[snap]` values must not
/// bleed into the restored container (mirrors `pct_list_all`). Pure —
/// unit-testable.
fn lxc_limits_from_pct_conf(pct_conf: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in pct_conf.lines().take_while(|l| !l.trim_start().starts_with('[')) {
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "memory" => {
                if let Ok(mb) = v.parse::<u64>()
                    && mb > 0 {
                        out.push(format!("lxc.cgroup2.memory.max = {}", mb * 1024 * 1024));
                    }
            }
            "swap" => {
                if let Ok(mb) = v.parse::<u64>()
                    && mb > 0 {
                        out.push(format!("lxc.cgroup2.memory.swap.max = {}", mb * 1024 * 1024));
                    }
            }
            "cores" => {
                if let Some(limit) = lxc_parse_cpu_input(v) {
                    let (key, value) = limit.cgroup_entry();
                    out.push(format!("{} = {}", key, value));
                }
            }
            "onboot"
                if v == "1" => {
                    out.push("lxc.start.auto = 1".to_string());
                }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod pct_conf_limit_tests {
    use super::lxc_limits_from_pct_conf;

    #[test]
    fn memory_swap_cores_and_onboot_translate() {
        let pct = "arch: amd64\ncores: 4\nhostname: prod-app\nmemory: 2048\nnet0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:CC,ip=192.168.1.50/24,gw=192.168.1.1\nonboot: 1\nostype: debian\nrootfs: local-lvm:vm-131-disk-0,size=8G\nswap: 512\nunprivileged: 1\n";
        let lines = lxc_limits_from_pct_conf(pct);
        assert!(lines.contains(&format!("lxc.cgroup2.memory.max = {}", 2048u64 * 1024 * 1024)));
        assert!(lines.contains(&format!("lxc.cgroup2.memory.swap.max = {}", 512u64 * 1024 * 1024)));
        assert!(lines.contains(&"lxc.cgroup2.cpu.max = 400000 100000".to_string()));
        assert!(lines.contains(&"lxc.start.auto = 1".to_string()));
    }

    #[test]
    fn zero_or_absent_values_write_nothing() {
        assert!(lxc_limits_from_pct_conf("hostname: x\nswap: 0\nonboot: 0\n").is_empty());
        assert!(lxc_limits_from_pct_conf("").is_empty());
        assert!(lxc_limits_from_pct_conf("memory: notanumber\n").is_empty());
    }

    #[test]
    fn snapshot_sections_do_not_bleed_into_the_live_config() {
        let pct = "memory: 1024\n[pre-upgrade]\nmemory: 8192\nonboot: 1\n";
        let lines = lxc_limits_from_pct_conf(pct);
        assert_eq!(lines, vec![format!("lxc.cgroup2.memory.max = {}", 1024u64 * 1024 * 1024)]);
    }
}

#[cfg(test)]
mod native_net0_tests {
    use super::native_net0_from_pct_conf;

    const NET0: &str = "hostname: prod-app\nnet0: name=eth0,bridge=vmbr40,firewall=1,hwaddr=BC:24:11:AA:BB:CC,ip=192.168.40.5/24,gw=192.168.40.1,type=veth\n";

    #[test]
    fn existing_bridge_carries_mac_and_static_address_with_no_warning() {
        let (lines, warning) = native_net0_from_pct_conf(NET0, &|b| b == "vmbr40");
        assert_eq!(lines, vec![
            "lxc.net.0.link = vmbr40".to_string(),
            "lxc.net.0.hwaddr = BC:24:11:AA:BB:CC".to_string(),
            "lxc.net.0.ipv4.address = 192.168.40.5/24".to_string(),
            "lxc.net.0.ipv4.gateway = 192.168.40.1".to_string(),
        ]);
        assert!(warning.is_none());
    }

    #[test]
    fn missing_bridge_falls_back_to_lxcbr0_and_warns_with_the_old_network() {
        let (lines, warning) = native_net0_from_pct_conf(NET0, &|_| false);
        // The stale static address must NOT be carried onto lxcbr0.
        assert_eq!(lines, vec![
            "lxc.net.0.link = lxcbr0".to_string(),
            "lxc.net.0.hwaddr = BC:24:11:AA:BB:CC".to_string(),
        ]);
        let w = warning.expect("fallback must warn");
        assert!(w.contains("vmbr40"), "{}", w);
        assert!(w.contains("192.168.40.5/24"), "{}", w);
    }

    #[test]
    fn dhcp_on_an_existing_bridge_writes_no_static_address() {
        let pct = "net0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:11:22,ip=dhcp\n";
        let (lines, warning) = native_net0_from_pct_conf(pct, &|_| true);
        assert_eq!(lines, vec![
            "lxc.net.0.link = vmbr0".to_string(),
            "lxc.net.0.hwaddr = BC:24:11:00:11:22".to_string(),
        ]);
        assert!(warning.is_none());
    }

    #[test]
    fn no_net0_yields_plain_lxcbr0_and_no_warning() {
        for pct in ["", "hostname: x\nmemory: 512\n"] {
            let (lines, warning) = native_net0_from_pct_conf(pct, &|_| true);
            assert_eq!(lines, vec!["lxc.net.0.link = lxcbr0".to_string()]);
            assert!(warning.is_none());
        }
    }

    #[test]
    fn snapshot_net0_does_not_bleed_into_the_live_config() {
        let pct = "memory: 512\n[snap]\nnet0: name=eth0,bridge=vmbr99,ip=10.9.9.9/24\n";
        let (lines, warning) = native_net0_from_pct_conf(pct, &|_| true);
        assert_eq!(lines, vec!["lxc.net.0.link = lxcbr0".to_string()]);
        assert!(warning.is_none());
    }

    #[test]
    fn bridge_swap_keeps_every_other_net_part() {
        use super::pve_net_value_with_bridge;
        assert_eq!(
            pve_net_value_with_bridge(
                "name=eth0,bridge=vmbr40,firewall=1,hwaddr=BC:24:11:AA:BB:CC,ip=192.168.40.5/24,gw=192.168.40.1",
                "vmbr4001",
            ),
            "name=eth0,bridge=vmbr4001,firewall=1,hwaddr=BC:24:11:AA:BB:CC,ip=192.168.40.5/24,gw=192.168.40.1",
        );
        // No bridge part → appended; empty value → minimal dhcp NIC.
        assert_eq!(pve_net_value_with_bridge("name=eth0,ip=dhcp", "vmbr1"), "name=eth0,ip=dhcp,bridge=vmbr1");
        assert_eq!(pve_net_value_with_bridge("", "vmbr1"), "name=eth0,bridge=vmbr1,ip=dhcp");
    }
}

/// Swap (or set) the `bridge=` part of a Proxmox `netN` value, leaving
/// every other part (name/hwaddr/ip/gw/firewall/…) untouched. An empty
/// input yields a minimal `name=eth0,bridge=<b>,ip=dhcp` NIC. Pure.
fn pve_net_value_with_bridge(net_value: &str, bridge: &str) -> String {
    let v = net_value.trim();
    if v.is_empty() {
        return format!("name=eth0,bridge={},ip=dhcp", bridge);
    }
    let mut parts: Vec<String> = Vec::new();
    let mut replaced = false;
    for part in v.split(',') {
        let part = part.trim();
        if part.is_empty() { continue; }
        if part.starts_with("bridge=") {
            parts.push(format!("bridge={}", bridge));
            replaced = true;
        } else {
            parts.push(part.to_string());
        }
    }
    if !replaced {
        parts.push(format!("bridge={}", bridge));
    }
    parts.join(",")
}

/// Build the `pct create --net0` value from the source's native LXC config,
/// carrying across what the source actually had instead of hard-coding
/// `bridge=vmbr0,ip=dhcp`:
///
/// * `lxc.net.0.link`     → `bridge=` — but only if that bridge exists on
///   THIS host (`bridge_exists`). A missing bridge falls back to `vmbr0`
///   with a returned warning, because `pct create` accepts any bridge name
///   and the container then simply fails to start later.
/// * `lxc.net.0.hwaddr`   → `hwaddr=` — preserving the MAC keeps the
///   container's DHCP lease, so it comes up on the SAME address it had.
/// * `lxc.net.0.ipv4.address` (+ `.gateway`) → static `ip=`/`gw=` when the
///   address is a valid CIDR; otherwise `ip=dhcp`.
///
/// `lxcbr0` (LXC's private NAT bridge) is deliberately treated as "no
/// specific network": PVE hosts don't have it, and the equivalent default
/// there is `vmbr0`.
///
/// Pure apart from the injected `bridge_exists` — unit-testable.
fn pve_net0_from_lxc_config(
    cfg: &str,
    bridge_exists: &dyn Fn(&str) -> bool,
) -> (String, Option<String>) {
    let (mut link, mut hwaddr, mut ipv4, mut gw) =
        (String::new(), String::new(), String::new(), String::new());
    for line in cfg.lines() {
        let Some((k, v)) = line.trim().split_once('=') else { continue };
        match k.trim() {
            "lxc.net.0.link" => link = v.trim().to_string(),
            "lxc.net.0.hwaddr" => hwaddr = v.trim().to_string(),
            "lxc.net.0.ipv4.address" => ipv4 = v.trim().to_string(),
            "lxc.net.0.ipv4.gateway" => gw = v.trim().to_string(),
            _ => {}
        }
    }

    let mut warning = None;
    let bridge = if link.is_empty() || link == "lxcbr0" {
        "vmbr0".to_string()
    } else if bridge_exists(&link) {
        link.clone()
    } else {
        warning = Some(format!(
            "the source container was attached to bridge '{}', which does not \
             exist on this host — it has been attached to vmbr0 (the management \
             bridge) instead. Create '{}' here, or edit the container's network \
             settings, before relying on its connectivity.",
            link, link,
        ));
        "vmbr0".to_string()
    };

    let mut net0 = format!("name=eth0,bridge={}", bridge);
    if !hwaddr.is_empty() {
        net0.push_str(&format!(",hwaddr={}", hwaddr));
    }
    if is_ipv4_cidr(&ipv4) {
        net0.push_str(&format!(",ip={}", ipv4));
        if !gw.is_empty() {
            net0.push_str(&format!(",gw={}", gw));
        }
    } else {
        net0.push_str(",ip=dhcp");
    }
    (net0, warning)
}

/// The source's memory limit in MB from `lxc.cgroup2.memory.max` (bytes) or
/// the legacy `lxc.cgroup.memory.limit_in_bytes`. None when unlimited or
/// unparseable — the caller keeps its default.
fn lxc_config_memory_mb(cfg: &str) -> Option<u64> {
    for line in cfg.lines() {
        let Some((k, v)) = line.trim().split_once('=') else { continue };
        let k = k.trim();
        if k == "lxc.cgroup2.memory.max" || k == "lxc.cgroup.memory.limit_in_bytes" {
            let bytes: u64 = v.trim().parse().ok()?;
            // Round up so a 512.5 MB limit doesn't become a 512 MB squeeze.
            return Some(bytes.div_ceil(1024 * 1024).max(16));
        }
    }
    None
}

/// The source's CPU allowance as a whole-core count for `pct create --cores`.
/// `lxc.cgroup2.cpu.max = "<quota> <period>"` → ceil(quota/period);
/// `lxc.cgroup2.cpuset.cpus = "0-3,8"` → the number of listed CPUs.
/// None when neither is set (unlimited) — pct then applies its own default.
fn lxc_config_cpu_cores(cfg: &str) -> Option<u64> {
    for line in cfg.lines() {
        let Some((k, v)) = line.trim().split_once('=') else { continue };
        match k.trim() {
            "lxc.cgroup2.cpu.max" => {
                let mut parts = v.split_whitespace();
                let quota: u64 = parts.next()?.parse().ok()?;
                let period: u64 = parts.next().unwrap_or("100000").parse().ok()?;
                if period == 0 { return None; }
                return Some(quota.div_ceil(period).max(1));
            }
            "lxc.cgroup2.cpuset.cpus" | "lxc.cgroup.cpuset.cpus" => {
                // "0-3,8" → 5 CPUs. A malformed range counts as 1 rather
                // than aborting the whole import over a cosmetic limit.
                let mut count: u64 = 0;
                for part in v.trim().split(',') {
                    let part = part.trim();
                    if let Some((a, b)) = part.split_once('-') {
                        match (a.trim().parse::<u64>(), b.trim().parse::<u64>()) {
                            (Ok(a), Ok(b)) if b >= a => count += b - a + 1,
                            _ => count += 1,
                        }
                    } else if !part.is_empty() {
                        count += 1;
                    }
                }
                return if count > 0 { Some(count) } else { None };
            }
            _ => {}
        }
    }
    None
}

/// Import an LXC container from an archive file.
///
/// `carried_config` is the source's LXC config (ContainerExportMeta
/// .lxc_config); on standalone targets it is used to rebuild a bootable
/// config instead of the old unbootable stub. Returns the start
/// identifier (VMID on Proxmox, name on standalone) so the caller can
/// start the destination on the right platform.
pub fn lxc_import(
    archive_path: &str,
    new_name: &str,
    storage: Option<&str>,
    carried_config: Option<&str>,
    target_bridge: Option<&str>,
) -> Result<LxcImportOutcome, String> {
    let path = std::path::Path::new(archive_path);
    if !path.exists() {
        return Err(format!("Archive not found: {}", archive_path));
    }



    if is_proxmox() {
        let new_vmid = pct_next_vmid()?;
        // Detect a real rootdir storage when the caller didn't specify one
        // (hardcoded "local-lvm" fails on ZFS-only hosts).
        let storage_default = if storage.is_none() { pve_default_container_storage() } else { String::new() };
        let storage_id = storage.unwrap_or(&storage_default);

        // Check if this is a vzdump archive by looking for etc/vzdump/pct.conf inside
        let is_vzdump = archive_path.contains("vzdump-") || {
            // Peek inside the archive for the vzdump config marker
            let check = Command::new("tar")
                .args(["tf", archive_path, "--wildcards", "*/etc/vzdump/pct.conf", "etc/vzdump/pct.conf"])
                .output();
            check.map(|o| o.status.success()).unwrap_or(false)
        };

        if is_vzdump {
            // vzdump archive — pct restore handles it natively (the vzdump
            // carries its own pct.conf, network settings included). An
            // operator-chosen destination bridge overrides net0's bridge=
            // while keeping the rest of the NIC (name/hwaddr/ip) — pulled
            // from the vzdump's own pct.conf so nothing else changes.
            let mut args: Vec<String> = vec![
                "restore".into(), new_vmid.to_string(), archive_path.to_string(),
                "--storage".into(), storage_id.to_string(),
                "--hostname".into(), new_name.to_string(),
            ];
            if let Some(bridge) = target_bridge {
                let pct_conf = Command::new("tar")
                    .args(["-xOf", archive_path, "--wildcards", "*/etc/vzdump/pct.conf", "etc/vzdump/pct.conf"])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_default();
                let net0 = pct_conf.lines()
                    .take_while(|l| !l.trim_start().starts_with('['))
                    .find_map(|l| l.trim().strip_prefix("net0:").map(|v| v.trim().to_string()))
                    .unwrap_or_default();
                args.push("--net0".into());
                args.push(pve_net_value_with_bridge(&net0, bridge));
            }
            let output = Command::new("pct")
                .args(&args)
                .output()
                .map_err(|e| format!("pct restore failed: {}", e))?;

            if output.status.success() {
                Ok(LxcImportOutcome {
                    message: format!("Container '{}' imported (VMID {}, storage: {})", new_name, new_vmid, storage_id),
                    start_id: new_vmid.to_string(),
                })
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                Err(format!("Import failed: {} {}", stderr.trim(), stdout.trim()))
            }
        } else {
            // Plain rootfs tar.gz from standalone WolfStack.
            // Use pct create with the archive as the ostemplate — Proxmox
            // handles it natively. The network and memory come from the
            // carried source config: this used to hard-code
            // `bridge=vmbr0,ip=dhcp` + 512 MB, which silently dropped a
            // container that lived on a VLAN bridge onto the management
            // LAN of the PVE host (RutgerDiehard, 2026-08-07, vlc→PVE).
            //
            // An operator-chosen bridge overrides the translation's bridge
            // choice but keeps the rest of the NIC (MAC, static address):
            // with `|_| true` the translator carries everything and emits
            // no fallback warning — the choice was explicit and the import
            // endpoint already validated the bridge exists here.
            let (net0, net_warning) = if let Some(bridge) = target_bridge {
                let (net0, _) = pve_net0_from_lxc_config(carried_config.unwrap_or(""), &|_| true);
                (pve_net_value_with_bridge(&net0, bridge), None)
            } else {
                pve_net0_from_lxc_config(
                    carried_config.unwrap_or(""),
                    &|bridge| std::path::Path::new(&format!("/sys/class/net/{}", bridge)).exists(),
                )
            };
            let memory_mb = lxc_config_memory_mb(carried_config.unwrap_or("")).unwrap_or(512);
            let rootfs_spec = format!("{}:4", storage_id);
            let mut args: Vec<String> = vec![
                "create".into(), new_vmid.to_string(), archive_path.to_string(),
                "--hostname".into(), new_name.to_string(),
                "--storage".into(), storage_id.to_string(),
                "--rootfs".into(), rootfs_spec,
                "--memory".into(), memory_mb.to_string(),
                "--swap".into(), "512".into(),
                "--net0".into(), net0,
                "--unprivileged".into(), "1".into(),
            ];
            if let Some(cores) = lxc_config_cpu_cores(carried_config.unwrap_or("")) {
                args.push("--cores".into());
                args.push(cores.to_string());
            }
            let output = Command::new("pct")
                .args(&args)
                .output()
                .map_err(|e| format!("pct create failed: {}", e))?;

            if output.status.success() {
                let mut message = format!(
                    "Container '{}' imported (VMID {}, storage: {})",
                    new_name, new_vmid, storage_id
                );
                // The warning must reach the operator, not a log file — a
                // container silently on the wrong network looks migrated
                // until something can't reach it.
                if let Some(w) = net_warning {
                    message.push_str(". WARNING: ");
                    message.push_str(&w);
                }
                Ok(LxcImportOutcome {
                    message,
                    start_id: new_vmid.to_string(),
                })
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                Err(format!("Import failed: {} {}", stderr.trim(), stdout.trim()))
            }
        }
    } else {
        // Standalone: create container dir with rootfs subdir and extract there
        let container_dir = format!("{}/{}", LXC_DEFAULT_PATH, new_name);
        let rootfs_target = format!("{}/rootfs", container_dir);
        if std::path::Path::new(&container_dir).exists() {
            return Err(format!(
                "Container '{}' already exists on this node — re-run with a different Destination name to import it alongside",
                new_name
            ));
        }

        std::fs::create_dir_all(&rootfs_target)
            .map_err(|e| format!("Failed to create container dir: {}", e))?;

        // Shared with the backup-restore path: handles gzip/zstd and the
        // nested-rootfs / etc/vzdump normalisation in one place.
        match lxc_extract_archive_to_rootfs(archive_path, &rootfs_target) {
            Ok(pct_conf) => {
                // Write a bootable config — the source's own config when it
                // travelled with the archive, otherwise a synthesised one
                // (with a vzdump source's limits and network translated from
                // its salvaged pct.conf). (Replaces the old 3-line stub that
                // left systemd containers stuck in ABORTING.)
                let net_warning = lxc_write_bootable_config(
                    &container_dir, new_name, carried_config, pct_conf.as_deref(), target_bridge);

                let mut message = format!("Container '{}' imported from archive", new_name);
                // Same rule as the Proxmox-destination branch: a network
                // fallback must reach the operator, not a log file.
                if let Some(w) = net_warning {
                    message.push_str(". WARNING: ");
                    message.push_str(&w);
                }
                Ok(LxcImportOutcome {
                    message,
                    start_id: new_name.to_string(),
                })
            }
            Err(e) => {
                // Cleanup on failure
                let _ = std::fs::remove_dir_all(&container_dir);
                Err(format!("Import failed: {}", e))
            }
        }
    }
}

/// Would an import under `new_name` collide on THIS node? Mirrors
/// `lxc_import`'s own collision rule exactly: native imports land in
/// `LXC_DEFAULT_PATH/<name>` and refuse an existing dir; Proxmox
/// destinations get a fresh VMID and allow duplicate hostnames, so a
/// name is never "taken" there. Used by the migrate orchestrators to
/// fail BEFORE the upload (RutgerDiehard 2026-08-08: "shouldn't we ask
/// the user for a different name rather than blocking?").
pub fn lxc_import_name_taken(new_name: &str) -> bool {
    if is_proxmox() {
        return false;
    }
    std::path::Path::new(&format!("{}/{}", LXC_DEFAULT_PATH, new_name)).exists()
}

/// Clean up export files after transfer
pub fn lxc_export_cleanup(archive_path: &str) {
    let _ = std::fs::remove_file(archive_path);
    // Also remove .meta.json if present
    let meta_path = format!("{}.meta.json", archive_path.trim_end_matches(".tar.gz").trim_end_matches(".tar.zst"));
    let _ = std::fs::remove_file(&meta_path);

}

/// A purely-numeric `/var/lib/lxc/<name>` is PVE's own VMID-keyed staging dir,
/// never a user's native `lxc-create` orphan (those carry human names). Stale
/// such dirs linger after a CT is migrated away or destroyed — adopting them
/// conjures ghost containers. Pure so it can be unit-tested without a host.
fn is_pve_vmid_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_digit())
}

/// List native `lxc-create` containers on a Proxmox host that PVE doesn't
/// know about — the footprint of the pre-fix App Store installer, which
/// created LXC containers with native tooling instead of `pct`. Such a
/// container lives at `/var/lib/lxc/<name>/` with its own `config` file but
/// has no `/etc/pve/lxc/<name>.conf`, so it's invisible both in the Proxmox
/// UI and in WolfStack's `pct list`-based container view.
///
/// Returns an empty list on non-Proxmox hosts, where native containers are
/// the norm rather than orphans.
pub fn list_native_lxc_orphans() -> Vec<String> {
    if !is_proxmox() { return Vec::new(); }

    let mut orphans = Vec::new();
    let entries = match std::fs::read_dir(LXC_DEFAULT_PATH) {
        Ok(e) => e,
        Err(_) => return orphans,
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().to_string();
        // Skip dot dirs (our own adopted-backup staging never lives here, but
        // be defensive) and anything without a native LXC config file.
        if name.starts_with('.') { continue; }
        let config_path = format!("{}/{}/config", LXC_DEFAULT_PATH, name);
        if !std::path::Path::new(&config_path).is_file() { continue; }

        // PVE-managed containers carry a /etc/pve/lxc/<vmid>.conf — and a
        // running CT also has a generated /var/lib/lxc/<vmid>/config. Either
        // way, presence of that PVE conf means it is NOT an orphan.
        let pve_conf = format!("/etc/pve/lxc/{}.conf", name);
        if std::path::Path::new(&pve_conf).is_file() { continue; }

        // GHOST GUARD #1 — never adopt a purely-numeric directory name.
        // /var/lib/lxc/<n> with a numeric name is PVE's own VMID-keyed staging
        // dir, not a user's native `lxc-create` container (those carry human
        // names; the App Store installer this feature targets always named its
        // containers). When a PVE CT is migrated away or destroyed — common on
        // a rebuilt/recovered cluster — its /var/lib/lxc/<vmid>/ staging dir
        // (config + an empty/stale rootfs) can linger after /etc/pve/lxc/<vmid>.conf
        // is gone. Without this guard the reconciler "adopts" those husks into
        // fresh VMIDs with the old id as the hostname, conjuring ghost CTs with
        // nothing behind them. Numeric names are never legitimate orphans here.
        if is_pve_vmid_name(&name) { continue; }

        // Skip orphans a prior adoption permanently failed on (e.g. their old
        // storage no longer exists) so we don't retry and re-warn on every
        // restart. The operator removes the marker file to force a retry.
        let failed_marker = format!("{}/{}/.wolfstack-adopt-failed", LXC_DEFAULT_PATH, name);
        if std::path::Path::new(&failed_marker).is_file() { continue; }

        orphans.push(name);
    }
    orphans
}

/// Adopt a single native `lxc-create` orphan into Proxmox so it becomes a
/// first-class PVE container (visible in the Proxmox UI and WolfStack's
/// container view). The orphan's root filesystem is tarred and handed to
/// `pct create` as an OS template — the same mechanism [`lxc_import`] uses
/// for a plain rootfs archive — which lets PVE lay it down on a real storage
/// with a fresh VMID and config. Any WolfNet IP marker is re-attached to the
/// new container.
///
/// Non-destructive: the original native directory is moved aside to
/// `/var/lib/wolfstack/adopted-backup/<name>` (not deleted) once the PVE
/// container is confirmed created, so a bad adoption stays recoverable.
///
/// Returns the new VMID as a string.
pub fn pct_adopt_native_orphan(name: &str) -> Result<String, String> {
    if !is_proxmox() {
        return Err("Orphan adoption only applies on Proxmox hosts".to_string());
    }

    let container_dir = format!("{}/{}", LXC_DEFAULT_PATH, name);
    let rootfs_dir = format!("{}/rootfs", container_dir);
    if !std::path::Path::new(&rootfs_dir).is_dir() {
        return Err(format!("Native container '{}' has no rootfs at {}", name, rootfs_dir));
    }

    let backup_root = "/var/lib/wolfstack/adopted-backup";
    let backup_dir = format!("{}/{}", backup_root, name);
    // Crash-recovery marker. Written into the native dir the instant `pct
    // create` succeeds (before the move-aside), recording the new VMID, so a
    // re-run after a crash can finish idempotently — WITHOUT guessing by
    // hostname (which could collide with an unrelated PVE container).
    let adopted_marker = format!("{}/.wolfstack-adopted-vmid", container_dir);

    // Idempotency / crash-safety: if a prior adoption already created the PVE
    // container but died before moving the native dir aside, the marker tells
    // us the exact VMID. Confirm that container still exists, then just finish
    // the move — never create a duplicate.
    if let Ok(recorded) = std::fs::read_to_string(&adopted_marker) {
        let recorded = recorded.trim().to_string();
        let pve_conf = format!("/etc/pve/lxc/{}.conf", recorded);
        if !recorded.is_empty() && std::path::Path::new(&pve_conf).is_file() {
            let _ = std::fs::create_dir_all(backup_root);
            if std::fs::rename(&container_dir, &backup_dir).is_err() {
                let _ = Command::new("mv").args([container_dir.as_str(), backup_dir.as_str()]).output();
            }
            return Ok(recorded);
        }
        // Stale marker (the recorded container is gone) — adopt afresh.
        let _ = std::fs::remove_file(&adopted_marker);
    }

    // The rootfs must be quiescent to tar it consistently — stop it if the
    // orphan happens to be running natively (the buggy installer left them
    // stopped, but an operator may have started one).
    let _ = Command::new("lxc-stop").args(["-n", name]).output();

    // Tar the rootfs (excluding virtual filesystems), mirroring the standalone
    // export path. Staged under /var/lib/wolfstack rather than /tmp so a large
    // rootfs doesn't risk overflowing a small tmpfs.
    let stage_dir = "/var/lib/wolfstack/adopt";
    std::fs::create_dir_all(stage_dir)
        .map_err(|e| format!("Failed to create adopt staging dir: {}", e))?;
    let archive_path = format!("{}/{}.tar.gz", stage_dir, name);
    let tar_out = Command::new("tar")
        .args(["czf", &archive_path,
               "--exclude=./proc/*", "--exclude=./sys/*", "--exclude=./dev/*",
               "-C", &rootfs_dir, "."])
        .output()
        .map_err(|e| format!("tar of orphan '{}' failed: {}", name, e))?;
    if !tar_out.status.success() {
        let _ = std::fs::remove_file(&archive_path);
        let stderr = String::from_utf8_lossy(&tar_out.stderr);
        return Err(format!("tar of orphan '{}' failed: {}", name, stderr.trim()));
    }

    // Hand the rootfs tarball to `pct create` via the shared import path.
    let outcome = match lxc_import(&archive_path, name, None, None, None) {
        Ok(o) => o,
        Err(e) => {
            let _ = std::fs::remove_file(&archive_path);
            // Mark this orphan so we don't retry + re-warn every restart on a
            // failure that won't fix itself (e.g. its old storage is gone).
            // list_native_lxc_orphans skips marked dirs; removing the marker
            // forces a retry. Best-effort — a write failure just means we warn
            // again next time, which is no worse than before.
            let failed_marker = format!("{}/.wolfstack-adopt-failed", container_dir);
            let _ = std::fs::write(&failed_marker, format!("{}\n", e));
            return Err(format!(
                "pct create for orphan '{}' failed: {} (won't retry — remove {} to try again)",
                name, e, failed_marker
            ));
        }
    };
    let _ = std::fs::remove_file(&archive_path);

    let vmid = outcome.start_id.clone();

    // Record the adopted VMID immediately so a crash before the move-aside is
    // recoverable on the next run (see the marker check at the top).
    let _ = std::fs::write(&adopted_marker, &vmid);

    // Re-attach WolfNet if the orphan carried an IP marker.
    let marker = format!("{}/.wolfnet/ip", container_dir);
    if let Ok(ip) = std::fs::read_to_string(&marker) {
        let ip = ip.trim().to_string();
        if !ip.is_empty() {
            ensure_lxc_bridge();
            let _ = Command::new("pct")
                .args(["set", &vmid, "--net1", "name=wn0,bridge=lxcbr0"])
                .output();
            if let Err(e) = lxc_attach_wolfnet(&vmid, &ip) {
                warn!("Adopted orphan '{}' (VMID {}): WolfNet re-attach warning: {}", name, vmid, e);
            }
        }
    }

    // Confirm PVE now owns it before moving the native copy aside.
    let pve_conf = format!("/etc/pve/lxc/{}.conf", vmid);
    if !std::path::Path::new(&pve_conf).is_file() {
        return Err(format!(
            "Adopted orphan '{}' but PVE config {} is missing — leaving the native copy in place",
            name, pve_conf
        ));
    }

    // Move the native directory aside (recoverable) rather than deleting it.
    std::fs::create_dir_all(backup_root)
        .map_err(|e| format!("Failed to create adopt-backup dir: {}", e))?;
    if let Err(e) = std::fs::rename(&container_dir, &backup_dir) {
        // Cross-filesystem rename fails with EXDEV — fall back to `mv`.
        let mv = Command::new("mv").args([container_dir.as_str(), backup_dir.as_str()]).output();
        if mv.map(|o| !o.status.success()).unwrap_or(true) {
            warn!("Adopted orphan '{}' to VMID {} but could not move native dir aside ({}); \
                   remove {} manually once verified", name, vmid, e, container_dir);
        }
    }

    invalidate_count_caches();
    Ok(vmid)
}

/// Create an LXC container from a download template
/// On Proxmox nodes, automatically uses `pct create` instead of `lxc-create`
pub fn lxc_create(name: &str, distribution: &str, release: &str, architecture: &str,
                  storage_path: Option<&str>, template_cache_path: Option<&str>) -> Result<String, String> {


    // On Proxmox, delegate to pct create. Template-storage hint passes
    // through so the user's choice of vztmpl storage is honoured.
    if is_proxmox() {
        let result = pct_create_api(name, distribution, release, architecture,
            storage_path, template_cache_path, None, None, None, None,
            "wolfnet", None, None, None);
        if result.is_ok() { invalidate_count_caches(); }
        return result.map(|(_vmid, msg)| msg);
    }

    // Standalone: use native lxc-create
    let mut args = vec![
        "-t", "download",
        "-n", name,
    ];

    // Custom storage path
    let path_str;
    if let Some(path) = storage_path
        && !path.is_empty() && path != LXC_DEFAULT_PATH {
            path_str = path.to_string();
            args.push("-P");
            args.push(&path_str);
        }

    args.extend_from_slice(&["--", "-d", distribution, "-r", release, "-a", architecture]);

    // LXC_CACHE_PATH tells the lxc-download template script where to
    // stash the downloaded tarball. Defaults to /var/cache/lxc when
    // unset; the UI's template-storage picker funnels into this.
    let mut cmd = Command::new("lxc-create");
    if let Some(cache) = template_cache_path
        && !cache.is_empty() {
            // Let the template land on the chosen storage (it'll live
            // in <cache>/lxc/cache/download/...).
            cmd.env("LXC_CACHE_PATH", format!("{}/lxc/cache", cache.trim_end_matches('/')));
        }
    let output = cmd
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to create LXC container: {}", e))?;

    if output.status.success() {

        // Register the storage path if non-default
        if let Some(path) = storage_path
            && !path.is_empty() && path != LXC_DEFAULT_PATH {
                lxc_register_path(path);
            }

        // Set sane defaults: swap=0 and 1 CPU core so containers start reliably
        let base = if let Some(p) = storage_path.filter(|p| !p.is_empty() && *p != LXC_DEFAULT_PATH) {
            p.to_string()
        } else {
            LXC_DEFAULT_PATH.to_string()
        };
        let cfg_path = format!("{}/{}/config", base, name);
        if let Ok(mut cfg_content) = std::fs::read_to_string(&cfg_path) {
            let mut modified = false;
            if !cfg_content.contains("memory.swap.max") && !cfg_content.contains("memory.memsw") {
                cfg_content.push_str("\nlxc.cgroup2.memory.swap.max = 0\n");
                modified = true;
            }
            // NB: do NOT inject a default `lxc.cgroup2.cpu.weight = 100` here.
            // It used to confuse lxc_set_resource_limits's "if line missing,
            // append" check — the user's chosen core count would get silently
            // dropped at creation time. CPU limits now go via `cpu.max`
            // (CFS quota, bare-integer N) or `cpuset.cpus` (explicit pin)
            // from lxc_set_resource_limits / Settings UI — see LxcCpuLimit.
            if modified {
                let _ = std::fs::write(&cfg_path, cfg_content);
            }
        }

        // Ensure LXC config has proper networking (the download template often
        // omits hwaddr, bridge, etc., leaving the container without networking)
        lxc_ensure_network_config(name);

        // Auto-apply systemd compatibility settings for systemd-based images
        // (Debian Bookworm+, Ubuntu, Linux Mint, Fedora, Rocky, AlmaLinux,
        // openSUSE, Arch — basically everything except Alpine and Void).
        // Without these, lxc-start daemonises, then systemd hits an AppArmor
        // block / missing cgroup mount and the container dies — surfacing
        // as "did not reach RUNNING (state: STOPPED)" through v20.9.2's
        // start verifier. The same toggles a user would apply manually
        // (Settings → Nesting + lxc.apparmor.profile = unconfined).
        let rootfs = format!("{}/{}/rootfs", base, name);
        let is_systemd = rootfs_uses_systemd(&rootfs);
        if is_systemd
            && let Ok(mut cfg) = std::fs::read_to_string(&cfg_path) {
                let mut additions: Vec<&str> = Vec::new();
                if !cfg.contains("nesting.conf") {
                    additions.push("lxc.include = /usr/share/lxc/config/nesting.conf");
                }
                if host_has_apparmor() && !cfg.contains("lxc.apparmor.profile") {
                    // Unconfined is what users converge on after fighting
                    // the default AppArmor profile with systemd. Container
                    // isolation still rests on user namespacing + cgroups
                    // when running unprivileged; AppArmor inside the LXC
                    // is defence-in-depth. Skipped on no-AppArmor LXC builds
                    // (Fedora/SELinux) where the key breaks config parsing.
                    additions.push("lxc.apparmor.profile = unconfined");
                }
                if !cfg.contains("lxc.mount.auto") {
                    additions.push("lxc.mount.auto = proc:rw sys:rw cgroup:rw");
                }
                if !additions.is_empty() {
                    cfg.push_str("\n# Systemd init compatibility — auto-applied by WolfStack\n");
                    for line in additions {
                        cfg.push_str(line);
                        cfg.push('\n');
                    }
                    let _ = std::fs::write(&cfg_path, cfg);
                    info!("LXC '{}': detected systemd init, applied nesting + apparmor unconfined", name);
                }
            }

        let storage_info = storage_path.filter(|p| !p.is_empty() && *p != LXC_DEFAULT_PATH)
            .map(|p| format!(" on {}", p))
            .unwrap_or_default();
        invalidate_count_caches();
        Ok(format!("Container '{}' created ({} {} {}){}", name, distribution, release, architecture, storage_info))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to create container: {}", stderr))
    }
}

/// Docker Hub search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerSearchResult {
    pub name: String,
    pub description: String,
    pub stars: u32,
    pub official: bool,
}

/// Search Docker Hub for images
/// Tries the Docker CLI first; if docker is not installed or fails,
/// falls back to the Docker Hub REST API (works on Proxmox without Docker).
pub fn docker_search(query: &str) -> Vec<DockerSearchResult> {
    // Try CLI first
    let output = Command::new("docker")
        .args(["search", "--format", "{{.Name}}\t{{.Description}}\t{{.StarCount}}\t{{.IsOfficial}}", "--limit", "100", query])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let results: Vec<DockerSearchResult> = String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    DockerSearchResult {
                        name: parts.first().unwrap_or(&"").to_string(),
                        description: parts.get(1).unwrap_or(&"").to_string(),
                        stars: parts.get(2).unwrap_or(&"0").parse().unwrap_or(0),
                        official: parts.get(3).unwrap_or(&"") == &"[OK]",
                    }
                })
                .collect();
            if !results.is_empty() {
                return results;
            }
        }
        _ => {}
    }

    // Fallback: Docker Hub REST API (no Docker required)

    docker_search_hub_api(query)
}

/// Query Docker Hub REST API directly (no Docker daemon needed)
fn docker_search_hub_api(query: &str) -> Vec<DockerSearchResult> {
    // Use curl -G --data-urlencode to safely encode the query parameter
    let output = Command::new("curl")
        .args(["-s", "--max-time", "10", "-G",
               "--data-urlencode", &format!("query={}", query),
               "--data-urlencode", "page_size=50",
               "https://hub.docker.com/v2/search/repositories/"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let body = String::from_utf8_lossy(&o.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
                && let Some(results) = json.get("results").and_then(|r| r.as_array()) {
                    return results.iter().filter_map(|r| {
                        let name = r.get("repo_name")
                            .or_else(|| r.get("slug"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        if name.is_empty() { return None; }
                        Some(DockerSearchResult {
                            name,
                            description: r.get("short_description")
                                .or_else(|| r.get("description"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            stars: r.get("star_count")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32,
                            official: r.get("is_official")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                        })
                    }).collect();
                }
            vec![]
        }
        _ => {

            vec![]
        }
    }
}

/// Pull a Docker image
pub fn docker_pull(image: &str) -> Result<String, String> {
    // Check if the image supports the current architecture before pulling.
    // On non-x86 systems (e.g. IBM Power ppc64le), many images are x86-only
    // and will fail with a confusing error. Give a clear message instead.
    let host_arch = std::env::consts::ARCH; // "x86_64", "aarch64", "powerpc64"
    if host_arch != "x86_64" {
        let docker_arch = match host_arch {
            "aarch64" => "arm64",
            "powerpc64" => "ppc64le",
            other => other,
        };
        // Use docker manifest inspect to check supported platforms
        if let Ok(manifest_out) = Command::new("docker")
            .args(["manifest", "inspect", image])
            .output()
            && manifest_out.status.success() {
                let manifest = String::from_utf8_lossy(&manifest_out.stdout);
                // Check if our architecture appears in the manifest
                if !manifest.contains(docker_arch) && !manifest.contains(host_arch) {
                    return Err(format!(
                        "Image '{}' does not support {} architecture. \
                         This image is only available for x86_64/amd64. \
                         Check Docker Hub for a ppc64le-compatible alternative or \
                         use the bare-metal install option instead.",
                        image, docker_arch
                    ));
                }
            }
            // If manifest inspect fails (e.g. private image), proceed with pull anyway
    }

    let output = Command::new("docker")
        .args(["pull", image])
        .output()
        .map_err(|e| format!("Failed to pull image: {}", e))?;

    if output.status.success() {
        let out = String::from_utf8_lossy(&output.stdout);

        Ok(format!("Image '{}' pulled successfully. {}", image, out.lines().last().unwrap_or("")))
    } else {
        Err(format!(
            "Pull failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Create a Docker container from an image
/// If wolfnet_ip is provided, the container will be connected to the WolfNet overlay network
/// volumes: list of volume mount specs, e.g. ["/host/path:/container/path", "myvolume:/data"]
pub fn docker_create(name: &str, image: &str, ports: &[String], env: &[String], wolfnet_ip: Option<&str>,
                     memory: Option<&str>, cpus: Option<&str>, _storage: Option<&str>,
                     volumes: &[String]) -> Result<String, String> {
    docker_create_with_cmd(name, image, ports, env, wolfnet_ip, memory, cpus, _storage, volumes, &[])
}

/// Like `docker_create` but also passes `cmd` as positional args
/// after the image name — used by the app store for images whose
/// ENTRYPOINT needs a subcommand (cloudflared `tunnel run`, etc.)
/// to actually do anything. Passing an empty slice is equivalent to
/// calling `docker_create`.
#[allow(clippy::too_many_arguments)]
pub fn docker_create_with_cmd(name: &str, image: &str, ports: &[String], env: &[String], wolfnet_ip: Option<&str>,
                     memory: Option<&str>, cpus: Option<&str>, _storage: Option<&str>,
                     volumes: &[String], cmd: &[String]) -> Result<String, String> {

    // Pre-flight: refuse the create if any requested host port is
    // already bound by another Docker container or a host process.
    // Without this guard, Docker happily creates the container — the
    // collision only surfaces at start time and (per the bug Klas
    // reported) sometimes silently as an unbound port instead of an
    // error. Failing at create time means the operator gets a clear
    // error in the UI before they even try to start the service.
    validate_host_ports_free(ports, name)?;

    let mut args = vec![
        "create".to_string(),
        "--name".to_string(), name.to_string(),
        "-it".to_string(),                           // interactive + tty (keeps container running)
        "--restart".to_string(), "unless-stopped".to_string(), // auto-restart
    ];

    // Add resource limits
    if let Some(mem) = memory
        && !mem.is_empty() {
            args.push("--memory".to_string());
            args.push(mem.to_string());
        }
    if let Some(cpu) = cpus
        && !cpu.is_empty() {
            args.push("--cpus".to_string());
            args.push(cpu.to_string());
        }

    // Inject real DNS servers — on systemd-resolved hosts,
    // /etc/resolv.conf points at 127.0.0.53 which is unreachable
    // from inside containers. Use the host's actual upstream DNS.
    for dns in docker_dns::get_docker_dns_servers() {
        args.push("--dns".to_string());
        args.push(dns);
    }

    // Add volume mounts (-v host:container or -v named_volume:container)
    for vol in volumes {
        let vol = vol.trim();
        if !vol.is_empty() {
            args.push("-v".to_string());
            args.push(vol.to_string());
        }
    }

    // Label with WolfNet IP so it can be re-applied on start/restart
    if let Some(ip) = wolfnet_ip {
        let ip = ip.trim();
        if !ip.is_empty() {
            // Validate IP format
            let parts: Vec<&str> = ip.split('.').collect();
            if parts.len() != 4 || parts.iter().any(|p| p.parse::<u8>().is_err()) {
                return Err(format!("Invalid WolfNet IP: '{}' — must be a valid IPv4 address", ip));
            }
            args.push("--label".to_string());
            args.push(format!("wolfnet.ip={}", ip));
        }
    }

    // Add port mappings
    for port in ports {
        if !port.is_empty() {
            args.push("-p".to_string());
            args.push(port.to_string());
        }
    }

    // Add environment variables
    for e in env {
        if !e.is_empty() {
            args.push("-e".to_string());
            args.push(e.to_string());
        }
    }

    args.push(image.to_string());

    // CMD arguments — positional args after the image name. Each one
    // becomes its own argv entry (no shell quoting), so `docker create
    // <image> tunnel --no-autoupdate run` is exactly `docker create`
    // + args `[..., image, "tunnel", "--no-autoupdate", "run"]`. The
    // appstore uses this for images whose ENTRYPOINT needs a subcommand
    // (cloudflared, traefik config-file overrides, etc).
    for c in cmd {
        if !c.is_empty() { args.push(c.clone()); }
    }

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = Command::new("docker")
        .args(&args_ref)
        .output()
        .map_err(|e| format!("Failed to run docker create: {}", e))?;

    if output.status.success() {
        let id = String::from_utf8_lossy(&output.stdout).trim().to_string();


        // WolfNet is applied on docker_start (reads wolfnet.ip label) — not here,
        // because the container isn't running yet and docker exec would fail.

        let wolfnet_msg = wolfnet_ip
            .filter(|ip| !ip.is_empty())
            .map(|ip| format!(" [WolfNet: {} — applied on start]", ip))
            .unwrap_or_default();

        invalidate_count_caches();
        invalidate_docker_list_cache();
        Ok(format!("Container '{}' created ({}){}", name, &id[..12.min(id.len())], wolfnet_msg))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        error!("Docker create failed: {}", stderr);
        Err(format!("Create failed: {}", stderr))
    }
}

/// One entry from `ss -tlnp` / `ss -ulnp`. Used by the pre-flight
/// validator and by `predictive::port_conflict` to know which host
/// processes already hold a port. Lives here (not in `predictive`)
/// so the data layer never reaches up into the analysis layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostListener {
    pub host_ip: String,
    pub host_port: u16,
    pub proto: String,
    /// Process name as ss reports it via `users:(("name",pid=N,fd=N))`.
    /// Empty when ss couldn't enumerate (run as non-root, missing
    /// proc), in which case the conflict still surfaces but the
    /// "owner" line will say "host process (unknown)".
    pub process: String,
}

/// Run `ss -tlnp` + `ss -ulnp` and parse listening sockets. Returns
/// an empty Vec when ss is missing or fails — callers fall back to
/// "no host-side listeners known" rather than blocking on a missing
/// tool.
pub fn sample_host_listeners() -> Vec<HostListener> {
    let mut out: Vec<HostListener> = Vec::new();
    for proto in &["tcp", "udp"] {
        let flag = match *proto {
            "tcp" => "-tlnp",
            "udp" => "-ulnp",
            _ => continue,
        };
        let output = match Command::new("ss").arg(flag).output() {
            Ok(o) if o.status.success() => o,
            _ => continue,
        };
        out.extend(parse_ss_output(&String::from_utf8_lossy(&output.stdout), proto));
    }
    out
}

/// Parse the body of `ss -tlnp` / `ss -ulnp`. Format:
///
/// ```text
/// State    Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process
/// LISTEN   0      4096   0.0.0.0:8553        0.0.0.0:*          users:(("wolfstack",pid=1485,fd=23))
/// ```
///
/// Local Address may be `0.0.0.0`, `127.0.0.1`, `::`, `[::1]`, or
/// `*`. We handle bracketed v6 (`[::1]:8080`) by splitting on the
/// closing bracket; everything else falls back to splitting on the
/// last colon.
pub fn parse_ss_output(text: &str, proto: &str) -> Vec<HostListener> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 5 { continue; }
        // For TCP `ss -tlnp`, the local-address column is index 3
        // (State, Recv-Q, Send-Q, Local). For UDP `ss -ulnp` the
        // first column is "UNCONN" instead of "LISTEN" but the
        // layout is the same. Some ss builds drop the State column
        // for UDP — be defensive: try col 3 first, then col 4.
        let local_addr_candidates = [cols[3], cols.get(4).copied().unwrap_or("")];
        let local = local_addr_candidates.iter()
            .find(|s| s.contains(':'))
            .copied()
            .unwrap_or(cols[3]);
        let (ip, port) = match split_host_port_for_ss(local) {
            Some(p) => p,
            None => continue,
        };
        // Process name: anything inside the first quoted span. Empty
        // when ss couldn't enumerate. Look across the whole line so
        // we don't miss it when extra columns push it past col 5.
        let proc_name = line.split('"').nth(1).unwrap_or("").to_string();
        out.push(HostListener {
            host_ip: ip,
            host_port: port,
            proto: proto.to_string(),
            process: proc_name,
        });
    }
    out
}

/// Split a "host:port" address as `ss` prints it. Handles
/// `[::1]:8080` (bracketed v6), `0.0.0.0:8080`, `127.0.0.1:8080`,
/// and `*:8080`. `*` is treated as `0.0.0.0` (ss's wildcard form).
fn split_host_port_for_ss(s: &str) -> Option<(String, u16)> {
    let (ip, port_str) = if let Some(close) = s.rfind(']') {
        // Bracketed v6: `[::1]:8080`
        let port_part = s.get(close + 1..).unwrap_or("").trim_start_matches(':');
        let host_part = s.get(1..close).unwrap_or("");
        (host_part.to_string(), port_part.to_string())
    } else {
        // v4 or `*`: split on the last `:`.
        let idx = s.rfind(':')?;
        let host = &s[..idx];
        let port = &s[idx + 1..];
        (host.to_string(), port.to_string())
    };
    let host = if ip == "*" { "0.0.0.0".to_string() } else { ip };
    let port: u16 = port_str.parse().ok()?;
    Some((host, port))
}

/// One requested host-port binding parsed out of a Docker `-p` string.
/// Public so the predictive port_conflict analyzer's tests can drive
/// the same parser without re-implementing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedHostPort {
    pub host_ip: String,
    pub host_port: u16,
    pub proto: String,
}

/// Parse a Docker `-p` argument like `"8080:80"`, `"127.0.0.1:8080:80"`,
/// `"8080:80/udp"`, or `"443"` (publish-only — host port chosen
/// randomly). Returns `None` when no specific host port is requested
/// (the random-port form), since there's nothing for the validator
/// to collide-check.
///
/// This deliberately rejects ranges (`8000-8010:8000-8010`) — those
/// are valid Docker syntax but rare in practice and the validator
/// doesn't need to handle them right now. Returns `None` for ranges
/// so the create proceeds; Docker itself will reject conflicts at
/// start time.
pub fn parse_docker_port_arg(arg: &str) -> Option<RequestedHostPort> {
    // Strip optional `/proto` suffix.
    let (body, proto) = match arg.rsplit_once('/') {
        Some((b, p)) => (b, p.to_ascii_lowercase()),
        None => (arg, "tcp".to_string()),
    };

    // Three valid shapes:
    //   "<container_port>"                          → random host port; nothing to check
    //   "<host_port>:<container_port>"              → wildcard host_ip = 0.0.0.0
    //   "<host_ip>:<host_port>:<container_port>"    → bound to host_ip
    let parts: Vec<&str> = body.split(':').collect();
    let (host_ip, host_port_str) = match parts.len() {
        1 => return None, // random host port
        2 => ("0.0.0.0".to_string(), parts[0].to_string()),
        3 => (parts[0].to_string(), parts[1].to_string()),
        _ => return None, // unexpected shape — let Docker handle it
    };
    // Reject ranges in the host port: dashes mean "8000-8010".
    if host_port_str.contains('-') { return None; }
    let host_port: u16 = host_port_str.parse().ok()?;
    if host_port == 0 { return None; }
    Some(RequestedHostPort { host_ip, host_port, proto })
}

/// Refuse a `docker create` if any requested host port is already
/// bound. Walks the same data sources as the predictive analyzer:
///   * existing Docker containers' published port bindings
///   * non-docker-proxy host listeners from `ss -tlnp`/`-ulnp`
///
/// `name` is only used in the error message — we don't try to be
/// "clever" and skip the validation when a container with that name
/// already exists (Docker rejects duplicate names anyway with a
/// clearer error).
pub fn validate_host_ports_free(ports: &[String], name: &str) -> Result<(), String> {
    let mut requested: Vec<RequestedHostPort> = Vec::new();
    for arg in ports {
        if arg.is_empty() { continue; }
        if let Some(r) = parse_docker_port_arg(arg) {
            requested.push(r);
        }
    }
    if requested.is_empty() { return Ok(()); }

    // Build the in-use set from Docker's view. Use the FRESH list
    // (not the 5-second cache) — back-to-back creates within the
    // cache window would otherwise miss the just-created container's
    // bindings and let a second create slip through with the same
    // host port.
    let mut in_use: Vec<(String, u16, String, String)> = Vec::new(); // (host_ip, host_port, proto, owner)
    for c in docker_list_all() {
        if c.runtime != "docker" { continue; }
        if c.name == name { continue; } // shouldn't be a hit; safety
        for m in &c.port_mappings {
            // We block on REQUESTED bindings, not just published.
            // If container A *requested* :8080 and didn't publish,
            // container B requesting :8080 is still going to lose.
            let ip = if m.host_ip.is_empty() { "0.0.0.0".to_string() } else { m.host_ip.clone() };
            in_use.push((ip, m.host_port, m.proto.clone(),
                format!("docker container `{}`", c.name)));
        }
    }

    // Add host listeners.
    for hl in sample_host_listeners() {
        if hl.process == "docker-proxy" { continue; }
        let proc_label = if hl.process.is_empty() {
            "host process".to_string()
        } else {
            format!("host process `{}`", hl.process)
        };
        in_use.push((hl.host_ip, hl.host_port, hl.proto, proc_label));
    }

    // Check each requested port. Match on (port, proto) and treat
    // wildcard-vs-specific as a conflict (binding `0.0.0.0:8080`
    // collides with `127.0.0.1:8080` and vice versa).
    for r in &requested {
        for (uip, uport, uproto, uowner) in &in_use {
            if *uport != r.host_port { continue; }
            if !uproto.eq_ignore_ascii_case(&r.proto) { continue; }
            let ips_collide = uip == &r.host_ip
                || uip == "0.0.0.0"
                || r.host_ip == "0.0.0.0"
                || uip == "::"
                || r.host_ip == "::";
            if !ips_collide { continue; }
            let ip_str = if r.host_ip == "0.0.0.0" { "*".to_string() } else { r.host_ip.clone() };
            return Err(format!(
                "Cannot create container `{name}`: requested host port \
                 {ip}:{port}/{proto} is already bound by {owner}. Pick a \
                 different host port for `{name}` (edit your compose file \
                 or the port mapping in the WolfStack UI), or stop the \
                 conflicting owner first.",
                name = name,
                ip = ip_str,
                port = r.host_port,
                proto = r.proto,
                owner = uowner,
            ));
        }
    }
    Ok(())
}

/// Set resource limits for an LXC container
/// Replace (or append) an `lxc.<key> = <value>` line in the given config
/// text. Matches by stripping whitespace + the `=`-prefix, so it catches
/// both `lxc.cgroup2.cpuset.cpus = 0-3` and `lxc.cgroup2.cpuset.cpus=0-3`.
fn lxc_replace_or_append(config: &mut String, key: &str, value: &str) -> bool {
    let new_line = format!("{} = {}", key, value);
    let mut found = false;
    let lines: Vec<String> = config.lines().map(|l| {
        let trimmed = l.trim_start();
        if trimmed.starts_with(key) {
            // accept both "key = …" and "key=…"
            let rest = trimmed[key.len()..].trim_start();
            if rest.starts_with('=') {
                found = true;
                return new_line.clone();
            }
        }
        l.to_string()
    }).collect();
    let mut joined = lines.join("\n");
    if !found {
        if !joined.ends_with('\n') { joined.push('\n'); }
        joined.push_str(&new_line);
    }
    if !joined.ends_with('\n') { joined.push('\n'); }
    let changed = joined != *config;
    *config = joined;
    changed
}

/// CFS period used for `lxc.cgroup2.cpu.max`. The kernel default is also
/// 100ms; matching it keeps the quota arithmetic trivial — `N * PERIOD`
/// microseconds buys exactly N cores' worth of CPU time per period.
const LXC_CPU_PERIOD_US: u32 = 100_000;

/// The two distinct meanings of the CPU Cores UI field. A bare integer
/// is a *soft limit*: cap the container's CPU time to N cores' worth via
/// `cpu.max`, leaving the scheduler free to spread it across any host
/// CPU. An explicit cpuset list/range is *pinning*: restrict the
/// container to exactly those host CPUs via `cpuset.cpus`.
///
/// History: bare-integer N used to expand to `cpuset.cpus = 0-(N-1)` —
/// hard pinning, not a quota. On a 32-core host, every container with a
/// numeric core setting was silently restricted to the same low-numbered
/// CPUs, while higher-numbered CPUs sat idle and the kernel could not
/// migrate work to relieve them. Multiple containers all sharing
/// `0-26` thrashed each other for 27 CPUs. Switched to a CFS-quota soft
/// limit to match operator expectation (and Proxmox's `pct set --cores`
/// semantics).
#[derive(Debug, Clone, PartialEq, Eq)]
enum LxcCpuLimit {
    Quota(u32),
    Pin(String),
}

impl LxcCpuLimit {
    /// The cgroup key + value to write into the container's lxc.config.
    fn cgroup_entry(&self) -> (&'static str, String) {
        match self {
            // cpu.max value format is `$MAX $PERIOD` in microseconds.
            // `2700000 100000` = 27 cores' worth of CPU time per 100ms.
            LxcCpuLimit::Quota(n) => (
                "lxc.cgroup2.cpu.max",
                format!("{} {}", n * LXC_CPU_PERIOD_US, LXC_CPU_PERIOD_US),
            ),
            LxcCpuLimit::Pin(s) => ("lxc.cgroup2.cpuset.cpus", s.clone()),
        }
    }

    /// Round-trip label for status messages / logs.
    fn describe(&self) -> String {
        match self {
            LxcCpuLimit::Quota(n) => format!("{} cores (CFS quota)", n),
            LxcCpuLimit::Pin(s) => format!("pinned to CPUs {}", s),
        }
    }
}

/// Interpret the CPU Cores UI field. Bare integer → CFS-quota soft
/// limit; explicit cpuset spec → pinning; empty / 0 / malformed → None.
fn lxc_parse_cpu_input(cpu: &str) -> Option<LxcCpuLimit> {
    let cpu = cpu.trim();
    if cpu.is_empty() {
        return None;
    }
    match cpu.parse::<u32>() {
        Ok(0) => None,
        Ok(n) => Some(LxcCpuLimit::Quota(n)),
        // Not a bare count — accept an explicit cpuset spec, but only a
        // well-formed one. Junk ("-1", "abc", "4.5", "0-") must never
        // reach the kernel as cpuset.cpus and break the container.
        Err(_) => is_valid_cpuset(cpu).then(|| LxcCpuLimit::Pin(cpu.to_string())),
    }
}

/// True when `s` is a well-formed cgroup cpuset list — comma-separated
/// CPU numbers and/or `lo-hi` ranges, e.g. "0-3", "0,2,4", "8-15".
fn is_valid_cpuset(s: &str) -> bool {
    !s.is_empty() && s.split(',').all(|part| match part.split_once('-') {
        Some((lo, hi)) => {
            // Both halves must parse, the range must be non-empty,
            // and "0-" / "-3" must not slip through (empty halves).
            !lo.is_empty() && !hi.is_empty()
                && lo.parse::<u32>().is_ok() && hi.parse::<u32>().is_ok()
        }
        None => part.parse::<u32>().is_ok(),
    })
}

/// Decode a value previously written by `LxcCpuLimit::Quota(n)` back to
/// N, so the UI can round-trip a saved quota as the same bare integer
/// the operator originally typed. Returns None for shapes we don't
/// model (unequal MAX/PERIOD, fractional cores, "max" sentinel).
fn lxc_quota_cores_from_cpu_max(val: &str) -> Option<u32> {
    let mut it = val.split_whitespace();
    let max: u32 = it.next()?.parse().ok()?;
    let period: u32 = it.next()?.parse().ok()?;
    if it.next().is_some() { return None; }
    if period != LXC_CPU_PERIOD_US { return None; }
    if max == 0 || !max.is_multiple_of(period) { return None; }
    Some(max / period)
}

#[cfg(test)]
mod cpu_limit_tests {
    use super::{lxc_parse_cpu_input, lxc_quota_cores_from_cpu_max, LxcCpuLimit};

    #[test]
    fn bare_integer_is_a_cfs_quota_not_a_pin() {
        assert_eq!(lxc_parse_cpu_input("28"), Some(LxcCpuLimit::Quota(28)));
        assert_eq!(lxc_parse_cpu_input("4"), Some(LxcCpuLimit::Quota(4)));
        assert_eq!(lxc_parse_cpu_input("1"), Some(LxcCpuLimit::Quota(1)));
    }

    #[test]
    fn quota_writes_cpu_max_with_matching_period() {
        let (k, v) = LxcCpuLimit::Quota(27).cgroup_entry();
        assert_eq!(k, "lxc.cgroup2.cpu.max");
        assert_eq!(v, "2700000 100000");
        let (k, v) = LxcCpuLimit::Quota(1).cgroup_entry();
        assert_eq!(k, "lxc.cgroup2.cpu.max");
        assert_eq!(v, "100000 100000");
    }

    #[test]
    fn empty_or_zero_means_no_limit() {
        assert_eq!(lxc_parse_cpu_input(""), None);
        assert_eq!(lxc_parse_cpu_input("   "), None);
        assert_eq!(lxc_parse_cpu_input("0"), None);
    }

    #[test]
    fn explicit_cpuset_specs_become_pin_not_quota() {
        assert_eq!(lxc_parse_cpu_input("0-3"), Some(LxcCpuLimit::Pin("0-3".into())));
        assert_eq!(lxc_parse_cpu_input("0,2,4"), Some(LxcCpuLimit::Pin("0,2,4".into())));
        assert_eq!(lxc_parse_cpu_input("8-15"), Some(LxcCpuLimit::Pin("8-15".into())));
    }

    #[test]
    fn pin_writes_cpuset_cpus_verbatim() {
        let (k, v) = LxcCpuLimit::Pin("0,3,7".into()).cgroup_entry();
        assert_eq!(k, "lxc.cgroup2.cpuset.cpus");
        assert_eq!(v, "0,3,7");
    }

    #[test]
    fn malformed_specs_are_rejected() {
        assert_eq!(lxc_parse_cpu_input("-1"), None);
        assert_eq!(lxc_parse_cpu_input("abc"), None);
        assert_eq!(lxc_parse_cpu_input("4.5"), None);
        assert_eq!(lxc_parse_cpu_input("0-"), None);
        assert_eq!(lxc_parse_cpu_input("0--3"), None);
        assert_eq!(lxc_parse_cpu_input("-3"), None);
    }

    #[test]
    fn cpu_max_round_trips_back_to_the_bare_count() {
        assert_eq!(lxc_quota_cores_from_cpu_max("2700000 100000"), Some(27));
        assert_eq!(lxc_quota_cores_from_cpu_max("100000 100000"), Some(1));
        // Different period — we don't try to map a foreign quota back to
        // the bare-count UI field; let the cpuset.cpus path or raw editor
        // handle it.
        assert_eq!(lxc_quota_cores_from_cpu_max("100000 50000"), None);
        // "max" or absent → not a finite quota we can show as N.
        assert_eq!(lxc_quota_cores_from_cpu_max("max 100000"), None);
        // Fractional cores aren't reachable from the UI today.
        assert_eq!(lxc_quota_cores_from_cpu_max("50000 100000"), None);
    }
}

/// Persist memory + CPU limits in the container's lxc.config. Bare
/// integer N becomes a CFS-quota soft limit via `lxc.cgroup2.cpu.max`;
/// an explicit cpuset spec ("0-3", "0,2") becomes hard pinning via
/// `lxc.cgroup2.cpuset.cpus`. The two are mutually exclusive — when
/// switching modes we strip both keys before writing the new one so a
/// stale `cpuset.cpus` can't survive next to a fresh `cpu.max` and pin
/// the container against the operator's intent.
pub fn lxc_set_resource_limits(container: &str, memory: Option<&str>, cpus: Option<&str>) -> Result<Option<String>, String> {
    let mut messages = Vec::new();

    let config_path = format!("{}/{}/config", lxc_base_dir(container), container);
    let mut config = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    let mut modified = false;

    if let Some(mem) = memory
        && !mem.is_empty() {
            let mb = parse_mem_to_mb(mem);
            if mb > 0 {
                let bytes = mb * 1024 * 1024;
                if lxc_replace_or_append(&mut config, "lxc.cgroup2.memory.max", &bytes.to_string()) {
                    modified = true;
                    messages.push(format!("Memory limit set to {} MB", mb));
                }
            }
        }

    if let Some(limit) = cpus.and_then(lxc_parse_cpu_input) {
        // Strip both possible old CPU keys so a switch between
        // pinning <-> quota leaves no stale line behind.
        let before = config.clone();
        config = lxc_strip_lines_with_key_prefix(&config, "lxc.cgroup2.cpuset.cpus");
        config = lxc_strip_lines_with_key_prefix(&config, "lxc.cgroup2.cpu.max");
        let stripped = config != before;
        let (key, value) = limit.cgroup_entry();
        let applied = lxc_replace_or_append(&mut config, key, &value);
        if applied || stripped {
            modified = true;
            messages.push(format!("CPU limit set: {}", limit.describe()));
        }
    }

    if modified
        && let Err(e) = std::fs::write(&config_path, config) {
            return Err(format!("Failed to write config: {}", e));
        }

    if messages.is_empty() {
        Ok(None)
    } else {
        Ok(Some(messages.join(", ")))
    }
}

/// Remove every line whose key (the part before `=`) starts with the
/// given prefix, regardless of whitespace around the `=`. Used to clear
/// stale cgroup keys before writing a new value of a different shape.
fn lxc_strip_lines_with_key_prefix(config: &str, key_prefix: &str) -> String {
    let mut out = String::with_capacity(config.len());
    for line in config.lines() {
        let trimmed = line.trim_start();
        let matches = trimmed.starts_with(key_prefix) && {
            let rest = trimmed[key_prefix.len()..].trim_start();
            rest.starts_with('=')
        };
        if !matches {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Stop an LXC container

/// Clone a Docker container — commits it as an image, then creates a new container
pub fn docker_clone(container: &str, new_name: &str) -> Result<String, String> {


    // Step 1: Commit the container to a new image
    let image_name = format!("wolfstack-clone/{}", new_name);
    let output = Command::new("docker")
        .args(["commit", container, &image_name])
        .output()
        .map_err(|e| format!("Failed to commit container: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to commit container: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Step 2: Create a new container from the committed image
    let output = Command::new("docker")
        .args(["create", "--name", new_name, &image_name])
        .output()
        .map_err(|e| format!("Failed to create cloned container: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to create cloned container: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let new_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

    Ok(format!("Container cloned as '{}' ({})", new_name, &new_id[..12.min(new_id.len())]))
}

// ─── Docker migration: runtime configuration ───
//
// `docker commit` snapshots the filesystem and the image-level Config — Env,
// Cmd, Entrypoint, WorkingDir, User, Labels all survive a commit/save/load
// round trip. What it does NOT capture is HostConfig and the network
// attachments: published ports, mounts, restart policy, resource limits,
// devices. Those are properties of the *container*, not the image.
//
// So a migrated container came up on the default bridge with no port bindings
// and no volumes — the destination was created with a bare
// `docker create --name X <image>`. RutgerDiehard's speedtest-tracker went from
// `speedtest_tracker_default` + 8543->443 + 8181->80 to `bridge` + nothing
// (2026-08-06). This spec carries the missing half across.

/// One mount to recreate on the destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateMount {
    /// `"volume"` (named, docker-managed) or `"bind"` (a host path).
    pub kind: String,
    /// Volume name, or the host path for a bind mount.
    pub source: String,
    pub target: String,
    pub read_only: bool,
}

/// The half of a container's configuration that `docker commit` loses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DockerRuntimeSpec {
    #[serde(default)]
    pub ports: Vec<PortMapping>,
    /// e.g. `unless-stopped`, or `on-failure:5`. Empty means unset.
    #[serde(default)]
    pub restart_policy: String,
    #[serde(default)]
    pub mounts: Vec<MigrateMount>,
    /// Named networks the source is attached to, excluding the default bridge.
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub memory_bytes: i64,
    #[serde(default)]
    pub nano_cpus: i64,
    #[serde(default)]
    pub privileged: bool,
    #[serde(default)]
    pub cap_add: Vec<String>,
    /// `PathOnHost:PathInContainer:CgroupPermissions`
    #[serde(default)]
    pub devices: Vec<String>,
    /// `hostname:ip`
    #[serde(default)]
    pub extra_hosts: Vec<String>,
    /// The registry image the container originally ran (e.g.
    /// `lscr.io/linuxserver/speedtest-tracker:latest`). Migration commits the
    /// container to a `wolfstack-migrate/<name>` snapshot, which severs the
    /// registry lineage — without this the destination's update checker has
    /// nothing to check (RutgerDiehard, 2026-08-07). Carried onto the created
    /// container as the `wolfstack.origin-image` label.
    #[serde(default)]
    pub origin_image: Option<String>,
    /// The origin image's repo digest hash (`sha256:…`, the part after `@`)
    /// at migration time. Lets the checker say whether upstream has moved
    /// since. None for locally-built images that were never pulled/pushed.
    #[serde(default)]
    pub origin_digest: Option<String>,
}

/// Migration snapshots: `wolfstack-migrate/<name>` is the current migrate
/// path's `docker commit` tag; `wolfrun-migrate:<name>` is the legacy one.
/// Both are local-only names no registry knows about.
pub fn is_migrated_snapshot_image(image: &str) -> bool {
    image.starts_with("wolfstack-migrate/") || image.starts_with("wolfrun-migrate:")
}

/// Label names carrying origin provenance on migrated containers.
pub const ORIGIN_IMAGE_LABEL: &str = "wolfstack.origin-image";
pub const ORIGIN_DIGEST_LABEL: &str = "wolfstack.origin-digest";

impl DockerRuntimeSpec {
    /// Every mount whose data we can actually move — named volumes AND bind
    /// mounts.
    ///
    /// Bind mounts were originally excluded on the theory that a host path
    /// "may or may not exist on the target". That reasoning was wrong in the
    /// case that matters: a container whose entire state lives in bind mounts
    /// (very common — anything created by a compose file with relative paths,
    /// or pointed inside another volume's _data) had NOTHING copyable, so the
    /// only option left re-declared the paths empty and the destination came up
    /// with no config at all. RutgerDiehard, 2026-08-06.
    pub fn copyable_mounts(&self) -> Vec<&MigrateMount> {
        self.mounts.iter()
            .filter(|m| m.kind == "volume" || m.kind == "bind")
            .filter(|m| !m.source.is_empty())
            .collect()
    }
}

/// Read the runtime configuration of `container` off the local daemon.
pub fn capture_runtime_spec(container: &str) -> Result<DockerRuntimeSpec, String> {
    let out = Command::new("docker")
        .args(["inspect", container])
        .output()
        .map_err(|e| format!("docker inspect failed: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "docker inspect failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("docker inspect returned unparseable JSON: {}", e))?;
    let c = parsed.get(0).ok_or_else(|| "docker inspect returned no container".to_string())?;
    let host = &c["HostConfig"];

    // Ports: HostConfig.PortBindings is {"80/tcp": [{"HostIp":"","HostPort":"8181"}]}.
    // A container port can have several host bindings, so this is a flat_map.
    let mut ports = Vec::new();
    if let Some(map) = host["PortBindings"].as_object() {
        for (key, bindings) in map {
            let (cport, proto) = match key.split_once('/') {
                Some((p, pr)) => (p, pr),
                None => (key.as_str(), "tcp"),
            };
            let container_port: u16 = match cport.parse() { Ok(v) => v, Err(_) => continue };
            for b in bindings.as_array().unwrap_or(&Vec::new()) {
                let host_port: u16 = match b["HostPort"].as_str().unwrap_or("").parse() {
                    Ok(v) => v,
                    Err(_) => continue,   // "" means "any free port" — not reproducible
                };
                ports.push(PortMapping {
                    host_ip: b["HostIp"].as_str().unwrap_or("").to_string(),
                    host_port,
                    container_port,
                    proto: proto.to_lowercase(),
                    published: true,
                });
            }
        }
    }
    // Stable order so the spec (and any diff of it) doesn't churn — docker
    // hands back a JSON object, whose iteration order is not guaranteed.
    ports.sort_by_key(|p| (p.container_port, p.host_port, p.proto.clone()));

    let restart_policy = {
        let name = host["RestartPolicy"]["Name"].as_str().unwrap_or("");
        let max = host["RestartPolicy"]["MaximumRetryCount"].as_i64().unwrap_or(0);
        match (name, max) {
            ("", _) | ("no", _) => String::new(),
            ("on-failure", n) if n > 0 => format!("on-failure:{}", n),
            (n, _) => n.to_string(),
        }
    };

    // .Mounts is the resolved view — typed, with the volume NAME for named
    // volumes, which HostConfig.Binds strings don't reliably give us.
    let mounts = c["Mounts"].as_array().map(|arr| {
        arr.iter().filter_map(|m| {
            let kind = m["Type"].as_str().unwrap_or("");
            if kind != "volume" && kind != "bind" { return None; }   // tmpfs has no data to carry
            let source = if kind == "volume" {
                m["Name"].as_str().unwrap_or("").to_string()
            } else {
                m["Source"].as_str().unwrap_or("").to_string()
            };
            if source.is_empty() { return None; }
            Some(MigrateMount {
                kind: kind.to_string(),
                source,
                target: m["Destination"].as_str().unwrap_or("").to_string(),
                read_only: !m["RW"].as_bool().unwrap_or(true),
            })
        }).collect::<Vec<_>>()
    }).unwrap_or_default();

    let networks = c["NetworkSettings"]["Networks"].as_object().map(|m| {
        m.keys()
            // `bridge` is the default and is attached anyway; `host`/`none` are
            // network modes rather than attachable networks.
            .filter(|n| !matches!(n.as_str(), "bridge" | "host" | "none"))
            .cloned()
            .collect::<Vec<_>>()
    }).unwrap_or_default();

    let str_list = |v: &serde_json::Value| -> Vec<String> {
        v.as_array().map(|a| {
            a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect()
        }).unwrap_or_default()
    };

    let devices = host["Devices"].as_array().map(|a| {
        a.iter().filter_map(|d| {
            let on_host = d["PathOnHost"].as_str()?;
            let in_ctr = d["PathInContainer"].as_str()?;
            let perms = d["CgroupPermissions"].as_str().unwrap_or("rwm");
            Some(format!("{}:{}:{}", on_host, in_ctr, perms))
        }).collect()
    }).unwrap_or_default();

    // Origin provenance. If the source container is ITSELF a migrated
    // snapshot (chained migration: host A → B → C), its Config.Image is
    // already a wolfstack-migrate name — carry the labels from the previous
    // hop forward instead of recording the snapshot as the "origin".
    let image = c.pointer("/Config/Image").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let label = |name: &str| -> Option<String> {
        c.pointer(&format!("/Config/Labels/{}", name))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let (origin_image, origin_digest) = if is_migrated_snapshot_image(&image) {
        (label(ORIGIN_IMAGE_LABEL), label(ORIGIN_DIGEST_LABEL))
    } else if !image.is_empty() {
        (Some(image.clone()), image_repo_digest_hash(&image))
    } else {
        (None, None)
    };

    Ok(DockerRuntimeSpec {
        ports,
        restart_policy,
        mounts,
        networks,
        memory_bytes: host["Memory"].as_i64().unwrap_or(0),
        nano_cpus: host["NanoCpus"].as_i64().unwrap_or(0),
        privileged: host["Privileged"].as_bool().unwrap_or(false),
        cap_add: str_list(&host["CapAdd"]),
        devices,
        extra_hosts: str_list(&host["ExtraHosts"]),
        origin_image,
        origin_digest,
    })
}

/// The repo-digest hash (`sha256:…`, after the `@`) of a local image, or None
/// when the image has none (built locally, never pulled/pushed). Stored bare —
/// the checker compares it directly against the registry manifest digest.
fn image_repo_digest_hash(image: &str) -> Option<String> {
    let out = Command::new("docker")
        .args(["image", "inspect", "--format", "{{index .RepoDigests 0}}", image])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let full = String::from_utf8_lossy(&out.stdout).trim().to_string();
    full.rsplit_once('@').map(|(_, h)| h.to_string()).filter(|h| !h.is_empty())
}

/// Build the `docker create` flags that reproduce `spec`.
///
/// `include_mounts` is the operator's choice from the migrate dialog: with it
/// false the container is created with no volumes at all, so it cannot start
/// against storage that isn't there yet.
///
/// Networks are deliberately NOT emitted here — only the first can be given to
/// `docker create`, and the rest need `docker network connect` afterwards, so
/// the caller handles all of them uniformly.
pub fn spec_to_create_args(spec: &DockerRuntimeSpec, include_mounts: bool) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();

    for p in &spec.ports {
        let host_side = if p.host_ip.is_empty() || p.host_ip == "0.0.0.0" {
            p.host_port.to_string()
        } else {
            format!("{}:{}", p.host_ip, p.host_port)
        };
        args.push("-p".into());
        args.push(format!("{}:{}/{}", host_side, p.container_port, p.proto));
    }

    if !spec.restart_policy.is_empty() {
        args.push("--restart".into());
        args.push(spec.restart_policy.clone());
    }

    if include_mounts {
        for m in &spec.mounts {
            args.push("-v".into());
            args.push(if m.read_only {
                format!("{}:{}:ro", m.source, m.target)
            } else {
                format!("{}:{}", m.source, m.target)
            });
        }
    }

    if spec.memory_bytes > 0 {
        args.push("--memory".into());
        args.push(spec.memory_bytes.to_string());
    }
    if spec.nano_cpus > 0 {
        args.push("--cpus".into());
        // NanoCpus is CPUs × 1e9. Three decimals matches what `--cpus` accepts.
        args.push(format!("{:.3}", spec.nano_cpus as f64 / 1_000_000_000.0));
    }
    if spec.privileged {
        args.push("--privileged".into());
    }
    for c in &spec.cap_add {
        args.push("--cap-add".into());
        args.push(c.clone());
    }
    for d in &spec.devices {
        args.push("--device".into());
        args.push(d.clone());
    }
    for h in &spec.extra_hosts {
        args.push("--add-host".into());
        args.push(h.clone());
    }
    // Origin provenance labels — what lets the destination's update checker
    // (and a later re-migration) see through the wolfstack-migrate snapshot
    // name to the real registry image.
    if let Some(origin) = spec.origin_image.as_deref().filter(|s| !s.is_empty()) {
        args.push("--label".into());
        args.push(format!("{}={}", ORIGIN_IMAGE_LABEL, origin));
    }
    if let Some(digest) = spec.origin_digest.as_deref().filter(|s| !s.is_empty()) {
        args.push("--label".into());
        args.push(format!("{}={}", ORIGIN_DIGEST_LABEL, digest));
    }
    args
}

/// What to do with the source container's volumes. The operator chooses this in
/// the migrate dialog — there is no safe default to assume. Copying multi-GB
/// volume data is slow and often unwanted; re-declaring without copying leaves
/// a database pointed at an empty directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeMode {
    /// Recreate the mounts and copy the contents of every named volume.
    Copy,
    /// Recreate the mounts, leave the data behind for the operator to move.
    Declare,
    /// Create the container with no volumes at all.
    Skip,
}

/// POST the runtime spec to the destination ahead of the image.
fn send_runtime_spec(
    target_url: &str,
    container: &str,
    spec: &DockerRuntimeSpec,
    include_mounts: bool,
    cluster_secret: &str,
) -> Result<(), String> {
    let payload = serde_json::json!({ "spec": spec, "include_mounts": include_mounts });
    let body = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
    let urls = crate::api::build_external_urls(
        target_url,
        &format!("/api/containers/docker/import-spec?name={}", container),
    );
    let mut last = String::from("no endpoint reachable");
    for url in &urls {
        let auth_hdrs = crate::node_identity::curl_headers_padded(cluster_secret, url);
        let out = Command::new("curl")
            .args([
                "-s", "-f", "-k",
                "--connect-timeout", "5",
                "--max-time", "30",     // a few KB of JSON; a real ceiling is fine here
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-H", &auth_hdrs[0], "-H", &auth_hdrs[1], "-H", &auth_hdrs[2],
                "-H", &auth_hdrs[3], "-H", &auth_hdrs[4], "-H", &auth_hdrs[5],
                "--data-binary", &body,   // small and in memory already, not a file
                url,
            ])
            .output();
        match out {
            Ok(o) if o.status.success() => return Ok(()),
            Ok(o) => last = String::from_utf8_lossy(&o.stderr).trim().to_string(),
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
}

/// Tar a mount's data and stream it to the destination.
///
/// Two shapes, because the kinds restore differently:
///
/// * **named volume** — archive the mountpoint's *contents* (`tar -C <mp> .`).
///   The volume's path differs per host, so only contents are portable; the
///   destination creates the volume and unpacks into it.
/// * **bind mount** — archive the entry itself from its parent
///   (`tar -C <dirname> <basename>`) so the destination recreates it at the
///   same absolute path. This also handles a bind mount of a single FILE,
///   common for config files, which a contents-only archive cannot represent.
///
/// A volume's on-disk location comes from `docker volume inspect`, never a
/// guessed path under /var/lib/docker — a non-default driver or a relocated
/// data-root makes that guess wrong.
fn send_mount_data(
    target_url: &str,
    container: &str,
    mount: &MigrateMount,
    cluster_secret: &str,
    staging: &str,
) -> Result<(), String> {
    // (dir to tar from, entry to tar, query telling the far end how to restore)
    let (tar_dir, tar_entry, query): (String, String, String) = if mount.kind == "volume" {
        if !crate::auth::is_safe_name(&mount.source) {
            return Err("unsafe volume name".into());
        }
        let out = Command::new("docker")
            .args(["volume", "inspect", "-f", "{{.Mountpoint}}", &mount.source])
            .output()
            .map_err(|e| format!("docker volume inspect: {}", e))?;
        if !out.status.success() {
            return Err(format!("docker volume inspect: {}",
                String::from_utf8_lossy(&out.stderr).trim()));
        }
        let mountpoint = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if mountpoint.is_empty() {
            return Err("volume has no local mountpoint (non-local driver?)".into());
        }
        (mountpoint, ".".to_string(), format!("volume={}", urlencode(&mount.source)))
    } else {
        // Bind mount: the path is the operator's, not ours. Refuse anything
        // that isn't a plain absolute path rather than trying to normalise it.
        let src = std::path::Path::new(&mount.source);
        if !src.is_absolute() || mount.source.contains("..") {
            return Err(format!("refusing a non-absolute or traversing path: {}", mount.source));
        }
        if !src.exists() {
            return Err(format!("source path does not exist: {}", mount.source));
        }
        let parent = src.parent()
            .ok_or_else(|| format!("no parent directory for {}", mount.source))?
            .to_string_lossy().to_string();
        let base = src.file_name()
            .ok_or_else(|| format!("no basename for {}", mount.source))?
            .to_string_lossy().to_string();
        (parent, base, format!("kind=bind&path={}", urlencode(&mount.source)))
    };

    let safe_tag: String = mount.source.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let tar_path = format!("{}/wolfstack-mnt-{}-{}.tar", staging, container, safe_tag);

    let tar = Command::new("tar")
        .args(["-C", &tar_dir, "-cf", &tar_path, &tar_entry])
        .output()
        .map_err(|e| format!("tar: {}", e))?;
    if !tar.status.success() {
        let _ = std::fs::remove_file(&tar_path);
        return Err(format!("tar: {}", String::from_utf8_lossy(&tar.stderr).trim()));
    }

    let urls = crate::api::build_external_urls(
        target_url,
        &format!("/api/containers/docker/import-volume?name={}&{}", container, query),
    );
    let mut last = String::from("no endpoint reachable");
    let mut ok = false;
    for url in &urls {
        let auth_hdrs = crate::node_identity::curl_headers_padded(cluster_secret, url);
        let o = Command::new("curl")
            .args([
                "-s", "-f", "-k",
                "--connect-timeout", "5",
                "--speed-limit", "1024",
                "--speed-time", "60",
                "-X", "POST",
                "-H", "Content-Type: application/octet-stream",
                "-H", &auth_hdrs[0], "-H", &auth_hdrs[1], "-H", &auth_hdrs[2],
                "-H", &auth_hdrs[3], "-H", &auth_hdrs[4], "-H", &auth_hdrs[5],
                "-T", &tar_path,      // stream — mount data is the big part
                url,
            ])
            .output();
        match o {
            Ok(r) if r.status.success() => { ok = true; break; }
            Ok(r) => last = String::from_utf8_lossy(&r.stderr).trim().to_string(),
            Err(e) => last = e.to_string(),
        }
    }
    let _ = std::fs::remove_file(&tar_path);
    if ok { Ok(()) } else { Err(last) }
}

/// Percent-encode a value for a query string. Bind-mount paths contain `/`
/// and may contain spaces, so they cannot be interpolated raw.
fn urlencode(v: &str) -> String {
    v.bytes().map(|b| match b {
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
        _ => format!("%{:02X}", b),
    }).collect()
}

/// Migrate a Docker container to a remote WolfStack node
/// Exports the container, sends it to the target, imports and optionally starts it
pub fn docker_migrate(
    container: &str,
    target_url: &str,
    _remove_source: bool,
    cluster_secret: &str,
    volume_mode: VolumeMode,
) -> Result<String, String> {
    // Validate container name to prevent path traversal in export path and URL
    if !crate::auth::is_safe_name(container) {
        return Err("Invalid container name".to_string());
    }

    // Capture the runtime configuration FIRST — before the commit, so a
    // container whose config we can't read fails the migration outright rather
    // than silently arriving stripped of its ports and volumes.
    let spec = capture_runtime_spec(container)?;
    let include_mounts = volume_mode != VolumeMode::Skip;

    // Step 1: Commit the running container to a temporary image (no stop needed)
    let temp_image = format!("wolfstack-migrate/{}", container);
    let output = Command::new("docker")
        .args(["commit", container, &temp_image])
        .output()
        .map_err(|e| format!("Failed to commit container for migration: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Commit failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Step 3: Export the image to a tar file.
    //
    // NOT /tmp: that is tmpfs on stock Debian 13 and most systemd distros, so
    // the export would land in RAM and compete with the transfer that follows.
    // transfer_staging_dir picks the operator's configured (disk-backed)
    // staging path — the same fix backups got after the 2026-07-21 incident.
    let staging = crate::paths::transfer_staging_dir();
    let export_path = format!("{}/wolfstack-migrate-{}.tar", staging, container);
    let output = Command::new("docker")
        .args(["save", "-o", &export_path, &temp_image])
        .output()
        .map_err(|e| format!("Failed to save image: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Save failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Step 3b: Ship the runtime spec ahead of the image, so the destination
    // knows how to create the container before it has one. Best-effort by
    // design: an older peer has no such endpoint, and a migration that lands
    // without its ports is still better than one that doesn't land at all —
    // but say so in the result rather than letting it pass silently.
    let mut warnings: Vec<String> = Vec::new();
    if let Err(e) = send_runtime_spec(target_url, container, &spec, include_mounts, cluster_secret) {
        warnings.push(format!(
            "runtime config (ports, networks, mounts) could not be sent — the destination \
             will be created with defaults: {}", e
        ));
    }

    // Step 3c: Volume data, only if the operator asked for it.
    if volume_mode == VolumeMode::Copy {
        for m in spec.copyable_mounts() {
            if let Err(e) = send_mount_data(target_url, container, m, cluster_secret, &staging) {
                warnings.push(format!("{} '{}' was not copied: {}", m.kind, m.source, e));
            }
        }
    }

    // Step 4: Send the tar to the remote node — try WolfStack (8553) and Proxmox (8006) ports
    let import_urls = crate::api::build_external_urls(target_url, &format!("/api/containers/docker/import?name={}", container));

    let mut transfer_ok = false;
    let mut last_response = String::new();
    let mut last_stderr = String::new();

    for import_url in &import_urls {
        let auth_hdrs = crate::node_identity::curl_headers_padded(cluster_secret, import_url);
        let output = Command::new("curl")
            .args([
                "-s", "-f", "-k",    // --fail + accept self-signed certs
                "--connect-timeout", "5",
                // No --max-time: a hard ceiling fails an otherwise healthy
                // multi-GB transfer purely for being big (300s only covers
                // ~1GB on a slow link). Abort on a STALL instead — under
                // 1 KB/s for 60s means the peer is gone, at any size.
                "--speed-limit", "1024",
                "--speed-time", "60",
                "-X", "POST",
                "-H", "Content-Type: application/octet-stream",
                "-H", &auth_hdrs[0], "-H", &auth_hdrs[1], "-H", &auth_hdrs[2],
                "-H", &auth_hdrs[3], "-H", &auth_hdrs[4], "-H", &auth_hdrs[5],
                // -T streams the file. `--data-binary @file` reads the WHOLE
                // file into curl's memory first and dies with
                // "option --data-binary: out of memory" on a large image, even
                // with GBs free (RutgerDiehard, 2026-08-06).
                "-T", &export_path,
                import_url,
            ])
            .output();

        match output {
            Ok(o) => {
                last_response = String::from_utf8_lossy(&o.stdout).to_string();
                last_stderr = String::from_utf8_lossy(&o.stderr).to_string();
                if o.status.success() && !last_response.contains("\"error\"") {
                    transfer_ok = true;
                    break;
                }
                // Got an HTTP response but it was an error — stop trying, the port was right
                if !last_stderr.contains("couldn't connect") && !last_stderr.contains("Connection refused") {
                    break;
                }
            }
            Err(e) => {
                last_stderr = e.to_string();
                continue;
            }
        }
    }

    // Clean up temp files
    let _ = std::fs::remove_file(&export_path);
    let _ = Command::new("docker").args(["rmi", &temp_image]).output();

    if !transfer_ok {
        error!("Migration transfer failed for {}: {} {}", container, last_stderr, last_response);
        return Err(format!(
            "Transfer failed (source still running): {}",
            if last_stderr.is_empty() { &last_response } else { &last_stderr }
        ));
    }

    // Source stays running — destination is imported but not started.
    // Anything that could not be carried across is reported here rather than
    // discovered later by a container that won't serve traffic.
    let mut msg = format!(
        "Container transferred to {}. Destination is stopped — start it manually when ready. {}",
        target_url, last_response
    );
    if volume_mode == VolumeMode::Declare && !spec.copyable_mounts().is_empty() {
        let names: Vec<String> = spec.copyable_mounts().iter()
            .map(|m| m.source.clone()).collect();
        msg.push_str(&format!(
            " Data was NOT copied ({}) — move it before starting the destination.",
            names.join(", ")
        ));
    }
    if volume_mode == VolumeMode::Skip && !spec.mounts.is_empty() {
        msg.push_str(" Volumes were omitted entirely at your request.");
    }
    for w in &warnings {
        msg.push_str(&format!(" WARNING: {}", w));
    }
    Ok(msg)
}

/// Import a Docker container image from a tar file
pub fn docker_import_image(tar_path: &str, container_name: &str) -> Result<String, String> {


    // Load the image
    let output = Command::new("docker")
        .args(["load", "-i", tar_path])
        .output()
        .map_err(|e| format!("Failed to load image: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Image load failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let load_output = String::from_utf8_lossy(&output.stdout).to_string();
    
    // Extract the loaded image name from output like "Loaded image: wolfstack-migrate/foo:latest"
    let image_name = load_output.lines()
        .find(|l| l.contains("Loaded image"))
        .and_then(|l| l.split(": ").nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| format!("wolfstack-migrate/{}", container_name));

    // Apply the sender's runtime spec if it arrived. Without it the container
    // is created bare — which is exactly the bug that lost speedtest-tracker's
    // ports and put it on the default bridge.
    let staged_spec = take_staged_spec(container_name);
    let mut notes: Vec<String> = Vec::new();

    let mut create_args: Vec<String> =
        vec!["create".into(), "--name".into(), container_name.into()];
    let mut extra_networks: Vec<String> = Vec::new();

    if let Some((spec, include_mounts)) = &staged_spec {
        // Named networks must exist on this node before we can attach. A
        // compose-created network like `speedtest_tracker_default` won't.
        for net in &spec.networks {
            if !crate::auth::is_safe_name(net) { continue; }
            let exists = Command::new("docker")
                .args(["network", "inspect", net])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !exists {
                let made = Command::new("docker")
                    .args(["network", "create", net])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if !made {
                    notes.push(format!("network '{}' could not be created", net));
                    continue;
                }
            }
            extra_networks.push(net.clone());
        }
        // `docker create` takes at most one --network; the rest are connected
        // after creation.
        if let Some(first) = extra_networks.first() {
            create_args.push("--network".into());
            create_args.push(first.clone());
        }
        create_args.extend(spec_to_create_args(spec, *include_mounts));
    }
    create_args.push(image_name.clone());

    let output = Command::new("docker")
        .args(&create_args)
        .output()
        .map_err(|e| format!("Failed to create container: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Container creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Attach any remaining networks.
    for net in extra_networks.iter().skip(1) {
        let ok = Command::new("docker")
            .args(["network", "connect", net, container_name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            notes.push(format!("could not attach network '{}'", net));
        }
    }

    // Clean up temp tar
    let _ = std::fs::remove_file(tar_path);

    let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let mut msg = format!("Container '{}' imported ({})", container_name, &id[..12.min(id.len())]);
    if staged_spec.is_none() {
        msg.push_str(" — no runtime config was received, so ports, networks and volumes are NOT set");
    }
    for n in &notes {
        msg.push_str(&format!(" WARNING: {}", n));
    }
    Ok(msg)
}

/// Path of the staged runtime spec for `container`, written by the
/// import-spec endpoint just before the image arrives.
pub fn staged_spec_path(container: &str) -> String {
    format!("{}/wolfstack-spec-{}.json", crate::paths::transfer_staging_dir(), container)
}

/// Read and consume the staged spec. Consumed rather than left in place so a
/// later manual import of the same name can't silently inherit a stale config.
fn take_staged_spec(container: &str) -> Option<(DockerRuntimeSpec, bool)> {
    let path = staged_spec_path(container);
    let raw = std::fs::read_to_string(&path).ok()?;
    let _ = std::fs::remove_file(&path);
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let spec: DockerRuntimeSpec = serde_json::from_value(v.get("spec")?.clone()).ok()?;
    let include_mounts = v.get("include_mounts").and_then(|b| b.as_bool()).unwrap_or(true);
    Some((spec, include_mounts))
}

/// Restore a bind mount's data at its original absolute path.
///
/// Far more dangerous than a volume restore: this writes to an arbitrary host
/// path chosen by the *sending* node, so every guard here matters.
///
/// * The path must be absolute and free of `..` — no traversal, no relative
///   surprises.
/// * An existing NON-EMPTY directory is refused outright. Unpacking over live
///   data to "help" is how a migration destroys the thing it was copying; the
///   operator is told instead, and moves it themselves.
/// * The archive is unpacked into the parent, because it contains the entry
///   itself (see send_mount_data) — which is what lets a single bind-mounted
///   FILE round-trip, not just a directory.
pub fn docker_restore_bind(path: &str, tar_path: &str) -> Result<String, String> {
    let p = std::path::Path::new(path);
    if !p.is_absolute() || path.contains("..") {
        return Err(format!("refusing a non-absolute or traversing path: {}", path));
    }
    if p.is_dir() {
        let empty = std::fs::read_dir(p).map(|mut d| d.next().is_none()).unwrap_or(false);
        if !empty {
            return Err(format!(
                "{} already exists and is not empty — refusing to unpack over it;                  move or clear it first", path
            ));
        }
    } else if p.exists() {
        return Err(format!("{} already exists — refusing to overwrite it", path));
    }
    let parent = p.parent()
        .ok_or_else(|| format!("no parent directory for {}", path))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("could not create {}: {}", parent.display(), e))?;
    let out = Command::new("tar")
        .args(["-C", &parent.to_string_lossy(), "-xf", tar_path])
        .output()
        .map_err(|e| format!("tar: {}", e))?;
    if !out.status.success() {
        return Err(format!("tar: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(format!("Bind mount '{}' restored", path))
}

/// Restore a named volume's contents from a tar staged by the import-volume
/// endpoint. Creates the volume if this node doesn't have it.
pub fn docker_restore_volume(volume: &str, tar_path: &str) -> Result<String, String> {
    if !crate::auth::is_safe_name(volume) {
        return Err("Invalid volume name".into());
    }
    // Idempotent: `docker volume create` on an existing volume is a no-op.
    let created = Command::new("docker")
        .args(["volume", "create", volume])
        .output()
        .map_err(|e| format!("docker volume create: {}", e))?;
    if !created.status.success() {
        return Err(format!(
            "docker volume create: {}",
            String::from_utf8_lossy(&created.stderr).trim()
        ));
    }
    let out = Command::new("docker")
        .args(["volume", "inspect", "-f", "{{.Mountpoint}}", volume])
        .output()
        .map_err(|e| format!("docker volume inspect: {}", e))?;
    let mountpoint = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || mountpoint.is_empty() {
        return Err("volume has no local mountpoint".into());
    }
    let untar = Command::new("tar")
        .args(["-C", &mountpoint, "-xf", tar_path])
        .output()
        .map_err(|e| format!("tar: {}", e))?;
    if !untar.status.success() {
        return Err(format!("tar: {}", String::from_utf8_lossy(&untar.stderr).trim()));
    }
    Ok(format!("Volume '{}' restored", volume))
}
/// Clone an LXC container (Proxmox-aware)
#[allow(dead_code)]
pub fn lxc_clone(container: &str, new_name: &str) -> Result<String, String> {


    if is_proxmox() {
        return lxc_clone_local(container, new_name, None, None);
    }

    let output = Command::new("lxc-copy")
        .args(["-n", container, "-N", new_name])
        .output()
        .map_err(|e| format!("Failed to clone LXC container: {}", e))?;

    if output.status.success() {
        lxc_clone_fixup_ip(new_name);
        Ok(format!("LXC container cloned as '{}'", new_name))
    } else {
        Err(format!(
            "LXC clone failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Clone an LXC container as a snapshot (faster, copy-on-write)
/// On Proxmox, uses linked clone (not full)
pub fn lxc_clone_snapshot(container: &str, new_name: &str, vmid: Option<u32>) -> Result<String, String> {


    if is_proxmox() {
        // Proxmox linked clone (--full 0)
        let new_vmid = match vmid {
            Some(v) if v >= 100 => v,
            Some(v) => return Err(format!("Invalid VMID {} — Proxmox VMIDs must be 100 or higher", v)),
            None => pct_next_vmid()?,
        };
        let vmid_str = new_vmid.to_string();
        let args = vec![
            "clone", container, &vmid_str,
            "--hostname", new_name,
        ];

        let output = Command::new("pct").args(&args).output()
            .map_err(|e| format!("pct clone failed: {}", e))?;

        if output.status.success() {
            // As-is copy (same rationale as lxc_clone_local): don't reseat
            // networking on Proxmox, just carry the source's WolfNet IP to the
            // new VMID so the linked clone is a faithful duplicate.
            if let Some(ip) = lxc_get_wolfnet_ip(container) {
                lxc_set_wolfnet_marker(&new_vmid.to_string(), &ip);
            }
            return Ok(format!("Container '{}' linked-cloned to '{}' (VMID {}). Created stopped — review its IP / WolfNet identity before starting it alongside the original.", container, new_name, new_vmid));
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Linked clone failed: {}", stderr.trim()));
        }
    }

    let output = Command::new("lxc-copy")
        .args(["-n", container, "-N", new_name, "-s"])
        .output()
        .map_err(|e| format!("Failed to snapshot-clone LXC container: {}", e))?;

    if output.status.success() {
        lxc_clone_fixup_ip(new_name);
        Ok(format!("LXC container snapshot-cloned as '{}'", new_name))
    } else {
        Err(format!(
            "LXC snapshot clone failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Read a container's stored WolfNet IP marker, if any. A migrate uses
/// this to carry the *exact* WolfNet identity to the destination instead
/// of allocating a fresh one (a move keeps everything as-is).
pub fn lxc_get_wolfnet_ip(container: &str) -> Option<String> {
    let base = lxc_base_dir(container);
    std::fs::read_to_string(format!("{}/{}/.wolfnet/ip", base, container))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Write the WolfNet IP marker directly, without reallocating or touching
/// the bridge IP — used by a migrate to restore the source's exact IP on
/// the destination. (lxc_attach_wolfnet would also reassign a bridge IP;
/// a move must not.)
pub fn lxc_set_wolfnet_marker(container: &str, ip: &str) {
    let base = lxc_base_dir(container);
    let dir = format!("{}/{}/.wolfnet", base, container);
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(format!("{}/ip", dir), ip);
}

/// Minimal fixup for a MOVE (not a clone): rewrite only the host-specific
/// rootfs path (and hostname, if the container was renamed). MAC, bridge
/// IP, WolfNet IP and every other setting are left exactly as the source
/// had them — a move stops the source, so there is no identity conflict
/// to avoid. Contrast with `lxc_clone_fixup_ip`, which reassigns a fresh
/// MAC + IP precisely because the original keeps existing.
pub fn lxc_migrate_fixup(new_name: &str) {
    let base = lxc_base_dir(new_name);
    let config_path = format!("{}/{}/config", base, new_name);
    if let Ok(config) = std::fs::read_to_string(&config_path) {
        let correct_rootfs = format!("dir:{}/{}/rootfs", base, new_name);
        let updated: Vec<String> = config.lines().map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("lxc.rootfs.path") {
                return format!("lxc.rootfs.path = {}", correct_rootfs);
            }
            if trimmed.starts_with("lxc.uts.name") {
                return format!("lxc.uts.name = {}", new_name);
            }
            line.to_string()
        }).collect();
        let _ = write_lxc_config(&config_path, &updated);
    }
    // Mark setup done so lxc_post_start_setup doesn't reassign a bridge IP
    // at first boot — the carried rootfs already holds the original network
    // config, and the WolfNet marker (restored separately) holds the IP.
    let marker = format!("{}/{}/.wolfstack_setup_done", base, new_name);
    let _ = std::fs::write(&marker, "migrated");
}

pub fn lxc_clone_fixup_ip(new_name: &str) {
    let new_last = find_free_bridge_ip();
    let new_ip = format!("10.0.3.{}", new_last);
    let base = lxc_base_dir(new_name);

    // Remove WolfNet IP marker from clone (it shouldn't inherit the original's WolfNet IP)
    let wolfnet_dir = format!("{}/{}/.wolfnet", base, new_name);
    let _ = std::fs::remove_dir_all(&wolfnet_dir);

    // Write multi-distro network config inside rootfs (no WolfNet IP — clone gets a fresh
    // bridge IP only; the user adds a WolfNet IP through the settings UI if desired)
    write_container_network_config(new_name, &new_ip, None);

    // Update the LXC config: rootfs path, hostname, hwaddr, ipv4.address, and ensure
    // all required networking fields are present
    let config_path = format!("{}/{}/config", base, new_name);
    if let Ok(config) = std::fs::read_to_string(&config_path) {
        let new_mac = format!("00:16:3e:{:02x}:{:02x}:{:02x}",
            rand_byte(), rand_byte(), new_last);
        let correct_rootfs = format!("dir:{}/{}/rootfs", base, new_name);
        let mut has_hwaddr = false;
        let mut has_type = false;
        let mut has_link = false;
        let mut has_name = false;
        let mut has_flags = false;
        let mut has_ipv4 = false;
        let mut updated: Vec<String> = config.lines().map(|line| {
            let trimmed = line.trim();
            // Fix rootfs path to point to the new container name
            if trimmed.starts_with("lxc.rootfs.path") {
                return format!("lxc.rootfs.path = {}", correct_rootfs);
            }
            // Fix hostname to match the new container name
            if trimmed.starts_with("lxc.uts.name") {
                return format!("lxc.uts.name = {}", new_name);
            }
            // Track and update network config fields
            if trimmed.starts_with("lxc.net.0.hwaddr") {
                has_hwaddr = true;
                return format!("lxc.net.0.hwaddr = {}", new_mac);
            }
            if trimmed.starts_with("lxc.net.0.type") { has_type = true; }
            if trimmed.starts_with("lxc.net.0.link") { has_link = true; }
            if trimmed.starts_with("lxc.net.0.name") { has_name = true; }
            if trimmed.starts_with("lxc.net.0.flags") { has_flags = true; }
            if trimmed.starts_with("lxc.net.0.ipv4.address") {
                has_ipv4 = true;
                return format!("lxc.net.0.ipv4.address = {}/24", new_ip);
            }
            // The address above was just forced onto lxcbr0's 10.0.3.0/24 —
            // a gateway carried from the source's network (e.g. a PVE
            // 192.168.x.1) would be unreachable from it. Follow the bridge.
            // Only rewrites an existing line: a deliberately gateway-less
            // net.0 (WolfNet-only NIC) stays gateway-less.
            if trimmed.starts_with("lxc.net.0.ipv4.gateway") {
                return "lxc.net.0.ipv4.gateway = 10.0.3.1".to_string();
            }
            line.to_string()
        }).collect();

        // Add any missing networking fields
        let mut net_additions = Vec::new();
        if !has_type  { net_additions.push("lxc.net.0.type = veth".to_string()); }
        if !has_link  { net_additions.push("lxc.net.0.link = lxcbr0".to_string()); }
        if !has_flags { net_additions.push("lxc.net.0.flags = up".to_string()); }
        if !has_name  { net_additions.push("lxc.net.0.name = eth0".to_string()); }
        if !has_hwaddr { net_additions.push(format!("lxc.net.0.hwaddr = {}", new_mac)); }
        // A synthesised config (vzdump → native import) has no ipv4.address
        // line — without this the fresh bridge IP lives only inside the
        // rootfs and the container shows no address while stopped.
        if !has_ipv4 { net_additions.push(format!("lxc.net.0.ipv4.address = {}/24", new_ip)); }

        if !net_additions.is_empty() {
            // Insert after existing lxc.net.0 lines, or at end
            let insert_pos = updated.iter().rposition(|l| l.trim().starts_with("lxc.net.0."))
                .map(|p| p + 1)
                .unwrap_or(updated.len());
            for (i, line) in net_additions.iter().enumerate() {
                updated.insert(insert_pos + i, line.clone());
            }

        }

        let _ = write_lxc_config(&config_path, &updated);
    }

    // Write the setup_done marker so lxc_post_start_setup doesn't
    // redundantly re-assign the bridge IP we just set
    let marker = format!("{}/{}/.wolfstack_setup_done", base, new_name);
    let _ = std::fs::write(&marker, "cloned");
}

/// Ensure an LXC container has proper networking config after creation.
/// The `lxc-create -t download` template often omits hwaddr, bridge, etc.
pub fn lxc_ensure_network_config(name: &str) {
    let config_path = format!("{}/{}/config", lxc_base_dir(name), name);
    let config = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut has_type = false;
    let mut has_link = false;
    let mut has_name = false;
    let mut has_flags = false;
    let mut has_hwaddr = false;

    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("lxc.net.0.type")  { has_type = true; }
        if trimmed.starts_with("lxc.net.0.link")  { has_link = true; }
        if trimmed.starts_with("lxc.net.0.name")  { has_name = true; }
        if trimmed.starts_with("lxc.net.0.flags") { has_flags = true; }
        if trimmed.starts_with("lxc.net.0.hwaddr") { has_hwaddr = true; }
    }

    let mut additions = Vec::new();
    if !has_type   { additions.push("lxc.net.0.type = veth".to_string()); }
    if !has_link   { additions.push("lxc.net.0.link = lxcbr0".to_string()); }
    if !has_flags  { additions.push("lxc.net.0.flags = up".to_string()); }
    if !has_name   { additions.push("lxc.net.0.name = eth0".to_string()); }
    if !has_hwaddr {
        let last = find_free_bridge_ip();
        let mac = format!("00:16:3e:{:02x}:{:02x}:{:02x}", rand_byte(), rand_byte(), last);
        additions.push(format!("lxc.net.0.hwaddr = {}", mac));
    }

    if additions.is_empty() { return; }

    let mut lines: Vec<String> = config.lines().map(|l| l.to_string()).collect();
    // Insert after existing lxc.net.0 lines, or at end
    let insert_pos = lines.iter().rposition(|l| l.trim().starts_with("lxc.net.0."))
        .map(|p| p + 1)
        .unwrap_or(lines.len());
    for (i, line) in additions.iter().enumerate() {
        lines.insert(insert_pos + i, line.clone());
    }
    let _ = write_lxc_config(&config_path, &lines);

}

fn rand_byte() -> u8 {
    let mut buf = [0u8; 1];
    if let Ok(f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let mut f = f;
        let _ = f.read_exact(&mut buf);
    }
    buf[0]
}

// ─── Installation ───

/// Install Docker
pub fn install_docker() -> Result<String, String> {


    // Use Docker's official convenience script
    let output = Command::new("bash")
        .args(["-c", "curl -fsSL https://get.docker.com | bash"])
        .output()
        .map_err(|e| format!("Failed to run Docker installer: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Docker installation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Enable and start Docker
    let _ = Command::new("systemctl")
        .args(["enable", "--now", "docker"])
        .output();


    Ok("Docker installed and started successfully".to_string())
}

/// Install LXC
pub fn install_lxc() -> Result<String, String> {


    // Detect package manager
    let (pkg_mgr, install_flag) = if std::path::Path::new("/usr/bin/apt-get").exists() {
        ("apt-get", "install")
    } else if std::path::Path::new("/usr/bin/dnf").exists() {
        ("dnf", "install")
    } else if std::path::Path::new("/usr/bin/yum").exists() {
        ("yum", "install")
    } else {
        return Err("Unsupported package manager".to_string());
    };

    // Update package cache for apt
    if pkg_mgr == "apt-get" {
        let _ = Command::new("apt-get")
            .args(["update", "-qq"])
            .output();
    }

    let packages = if pkg_mgr == "apt-get" {
        vec!["lxc", "lxc-templates", "lxcfs"]
    } else {
        vec!["lxc", "lxc-templates"]
    };

    let output = Command::new(pkg_mgr)
        .args([install_flag, "-y"])
        .args(&packages)
        .output()
        .map_err(|e| format!("Failed to install LXC: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "LXC installation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Start lxcfs if available
    let _ = Command::new("systemctl")
        .args(["enable", "--now", "lxcfs"])
        .output();


    Ok("LXC installed successfully".to_string())
}

// ─── Parsing helpers ───

fn parse_docker_mem(s: &str) -> (u64, u64) {
    // "150.3MiB / 31.27GiB" -> (usage_bytes, limit_bytes)
    let parts: Vec<&str> = s.split('/').collect();
    let usage = parts.first().map(|v| parse_size_str(v.trim())).unwrap_or(0);
    let limit = parts.get(1).map(|v| parse_size_str(v.trim())).unwrap_or(0);
    (usage, limit)
}

fn parse_docker_io(s: &str) -> (u64, u64) {
    // "1.23kB / 456B"
    let parts: Vec<&str> = s.split('/').collect();
    let input = parts.first().map(|v| parse_size_str(v.trim())).unwrap_or(0);
    let output = parts.get(1).map(|v| parse_size_str(v.trim())).unwrap_or(0);
    (input, output)
}

fn parse_size_str(s: &str) -> u64 {
    let s = s.trim();
    if s.is_empty() { return 0; }

    let multipliers = [
        ("TiB", 1024u64 * 1024 * 1024 * 1024),
        ("GiB", 1024u64 * 1024 * 1024),
        ("MiB", 1024u64 * 1024),
        ("KiB", 1024u64),
        ("TB", 1000u64 * 1000 * 1000 * 1000),
        ("GB", 1000u64 * 1000 * 1000),
        ("MB", 1000u64 * 1000),
        ("kB", 1000u64),
        ("B", 1u64),
    ];

    for (suffix, mult) in &multipliers {
        if s.ends_with(suffix) {
            let num = s.trim_end_matches(suffix).trim();
            return (num.parse::<f64>().unwrap_or(0.0) * *mult as f64) as u64;
        }
    }

    s.parse().unwrap_or(0)
}


/// Read a cgroup value via lxc-cgroup command
fn lxc_cgroup_read(name: &str, key: &str) -> Option<u64> {
    let base = lxc_base_dir(name);
    let mut args: Vec<&str> = Vec::new();
    if base != LXC_DEFAULT_PATH { args.extend_from_slice(&["-P", &base]); }
    args.extend_from_slice(&["-n", name, key]);
    Command::new("lxc-cgroup")
        .args(&args)
        .output()
        .ok()
        .and_then(|o| {
            let val = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if val == "max" || val.is_empty() { return None; }
            val.parse::<u64>().ok()
        })
}

/// Read one key from a multi-line cgroup stat file (e.g. `memory.stat`) via
/// lxc-cgroup. Matches the key as the exact first whitespace token so
/// `inactive_file` never accidentally matches `total_inactive_file`.
fn lxc_cgroup_stat_key(name: &str, file: &str, key: &str) -> Option<u64> {
    let base = lxc_base_dir(name);
    let mut args: Vec<&str> = Vec::new();
    if base != LXC_DEFAULT_PATH { args.extend_from_slice(&["-P", &base]); }
    args.extend_from_slice(&["-n", name, file]);
    let out = Command::new("lxc-cgroup").args(&args).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find(|l| l.split_whitespace().next() == Some(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
}

/// Read a whole multi-line cgroup stat file via lxc-cgroup in one call.
///
/// Use this over repeated [`lxc_cgroup_stat_key`] whenever more than one key is
/// wanted — each of those calls is a process spawn, multiplied by every
/// container on every stats poll.
fn lxc_cgroup_stat_map(name: &str, file: &str) -> std::collections::HashMap<String, u64> {
    let base = lxc_base_dir(name);
    let mut args: Vec<&str> = Vec::new();
    if base != LXC_DEFAULT_PATH { args.extend_from_slice(&["-P", &base]); }
    args.extend_from_slice(&["-n", name, file]);
    Command::new("lxc-cgroup")
        .args(&args)
        .output()
        .ok()
        .map(|o| parse_cgroup_stat(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default()
}

/// Reclaim a running LXC container's clean page cache via cgroup v2
/// `memory.reclaim`, BOUNDED to its reclaimable file cache (`inactive_file`)
/// so the kernel satisfies the request from clean file pages first and never
/// has to touch the container's anonymous / working-set memory — no app
/// disruption, no swap-out, no OOM risk. The bound is the whole safety story:
/// asking for exactly the easily-reclaimable cache means there's no reason for
/// the kernel to reach into anon. Returns the bytes actually freed (the
/// `memory.current` delta — best-effort). Requires cgroup v2; on cgroup v1
/// (no `memory.reclaim`) it returns a clear, non-fatal error.
pub fn lxc_reclaim_cache(name: &str) -> Result<u64, String> {
    if !lxc_is_running(name) {
        return Err("Container is not running — nothing to reclaim".to_string());
    }
    // The reclaimable clean file cache. Capping the reclaim request at this
    // keeps it cache-only.
    let reclaimable = lxc_cgroup_stat_key(name, "memory.stat", "inactive_file")
        .or_else(|| lxc_cgroup_stat_key(name, "memory.stat", "total_inactive_file"))
        .unwrap_or(0);
    if reclaimable == 0 {
        return Ok(0); // no reclaimable cache — nothing to do, not an error
    }

    let before = lxc_cgroup_read(name, "memory.current").unwrap_or(0);

    // Write the byte count to the cgroup's `memory.reclaim` (cgroup v2). lxc-cgroup
    // resolves the per-container cgroup path for us (same as the read path).
    let base = lxc_base_dir(name);
    let reclaim_str = reclaimable.to_string();
    let mut args: Vec<&str> = Vec::new();
    if base != LXC_DEFAULT_PATH { args.extend_from_slice(&["-P", &base]); }
    args.extend_from_slice(&["-n", name, "memory.reclaim", &reclaim_str]);
    let out = Command::new("lxc-cgroup").args(&args).output()
        .map_err(|e| format!("lxc-cgroup memory.reclaim: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "Cache reclaim not available for '{}' (needs cgroup v2): {}",
            name, stderr.trim()
        ));
    }

    let after = lxc_cgroup_read(name, "memory.current").unwrap_or(before);
    Ok(before.saturating_sub(after))
}

/// Get CPU usage percentage for an LXC container
/// Read one cgroup key for an LXC container.
fn lxc_cgroup_value(name: &str, key: &str) -> Option<String> {
    let base = lxc_base_dir(name);
    let mut args: Vec<&str> = Vec::new();
    if base != LXC_DEFAULT_PATH { args.extend_from_slice(&["-P", &base]); }
    args.extend_from_slice(&["-n", name, key]);
    let out = Command::new("lxc-cgroup").args(&args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Cumulative CPU time consumed by a container, in microseconds (cgroup v2).
fn lxc_cpu_usage_usec(name: &str) -> Option<u64> {
    lxc_cgroup_value(name, "cpu.stat")?
        .lines()
        .find(|l| l.starts_with("usage_usec"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
}

/// Effective CPU allowance for an LXC container, in cores.
///
/// `cpu.max` is `"<quota|max> <period>"` in microseconds; `cpuset.cpus` narrows
/// it further. Neither present means the whole host.
fn lxc_cpu_limit_cores(name: &str) -> f64 {
    let host_cores = host_cpu_cores();
    let mut cores = host_cores;

    if let Some(quota_cores) = lxc_cgroup_value(name, "cpu.max").as_deref().and_then(parse_cpu_max) {
        cores = cores.min(quota_cores);
    }
    if let Some(set_cores) = lxc_cgroup_value(name, "cpuset.cpus")
        .and_then(|set| cpuset_core_count(set.trim()))
    {
        cores = cores.min(set_cores);
    }
    cores.max(0.01)
}

/// Parse a cgroup v2 `cpu.max` value — `"<quota|max> <period>"` in
/// microseconds — into a core count. `max` means no limit, so None.
fn parse_cpu_max(raw: &str) -> Option<f64> {
    let mut fields = raw.split_whitespace();
    let quota: f64 = match fields.next()? {
        "max" => return None,
        q => q.parse().ok()?,
    };
    let period: f64 = fields.next().and_then(|p| p.parse().ok()).unwrap_or(100_000.0);
    if quota > 0.0 && period > 0.0 {
        Some(quota / period)
    } else {
        None
    }
}

/// Per-container `(cumulative usage_usec, when it was read)` from the previous
/// poll, so CPU can be reported as a rate rather than a lifetime average.
static LXC_CPU_SAMPLES: std::sync::LazyLock<Mutex<std::collections::HashMap<String, (u64, Instant)>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

/// Turn a CPU-time delta into a percentage on the same "100% == one core"
/// scale `docker stats` uses, so both runtimes mean the same thing in the UI.
fn cpu_percent_from_delta(delta_usec: u64, elapsed: std::time::Duration) -> f64 {
    let wall_usec = elapsed.as_micros() as f64;
    if wall_usec <= 0.0 {
        return 0.0;
    }
    ((delta_usec as f64 / wall_usec) * 100.0 * 10.0).round() / 10.0
}

/// Current CPU usage of an LXC container.
///
/// Was a lifetime average: cumulative usage divided by *system* uptime and by
/// the host core count. That answered a question nobody asked — it could never
/// show a busy container as busy, it understated any container started after
/// boot, and it was on a different scale from the Docker figure shown beside
/// it. This samples the delta between polls instead.
fn lxc_cpu_percent(name: &str) -> f64 {
    let usage = match lxc_cpu_usage_usec(name) {
        Some(u) => u,
        None => return 0.0,
    };
    let now = Instant::now();

    // Lock only to swap the sample in — never across the sleep below.
    let previous = LXC_CPU_SAMPLES.lock().unwrap().insert(name.to_string(), (usage, now));

    if let Some((prev_usage, prev_at)) = previous {
        return cpu_percent_from_delta(usage.saturating_sub(prev_usage), now.duration_since(prev_at));
    }

    // First time we've seen this container: take a second reading rather than
    // reporting a flat 0% until the next poll.
    std::thread::sleep(std::time::Duration::from_millis(100));
    let usage2 = match lxc_cpu_usage_usec(name) {
        Some(u) => u,
        None => return 0.0,
    };
    let now2 = Instant::now();
    LXC_CPU_SAMPLES.lock().unwrap().insert(name.to_string(), (usage2, now2));
    cpu_percent_from_delta(usage2.saturating_sub(usage), now2.duration_since(now))
}

fn read_container_net(name: &str) -> (u64, u64) {
    // Read network stats via container's PID
    let base = lxc_base_dir(name);
    let mut info_args: Vec<&str> = Vec::new();
    if base != LXC_DEFAULT_PATH { info_args.extend_from_slice(&["-P", &base]); }
    info_args.extend_from_slice(&["-n", name, "-pH"]);
    let pid = Command::new("lxc-info")
        .args(&info_args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok());

    if let Some(pid) = pid {
        let net_path = format!("/proc/{}/net/dev", pid);
        if let Ok(content) = std::fs::read_to_string(&net_path) {
            let mut rx_total: u64 = 0;
            let mut tx_total: u64 = 0;
            for line in content.lines().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    let iface = parts[0].trim_end_matches(':');
                    if iface != "lo" {
                        rx_total += parts[1].parse::<u64>().unwrap_or(0);
                        tx_total += parts[9].parse::<u64>().unwrap_or(0);
                    }
                }
            }
            return (rx_total, tx_total);
        }
    }
    (0, 0)
}

// ─── Install Wolf Components into Containers ───

/// Install a Wolf component into a Docker or LXC container
pub fn install_component_in_container(
    runtime: &str,
    container: &str,
    component: &str,
) -> Result<String, String> {


    // Validate the component name
    let install_script = match component {
        "wolfnet" => "https://raw.githubusercontent.com/intelligentwolf/WolfScale/main/wolfnet/setup.sh",
        // WolfProxy is a STANDALONE repo (not in the WolfScale monorepo), and it
        // ships a PREBUILT binary — setup.sh downloads it. The old
        // WolfScale/master/wolfproxy/install.sh URL 404'd (no such path in the
        // monorepo) and, where reachable, compiled from source and failed with
        // "could not find Cargo.toml" (klasSponsor 2026-06). Point at the
        // standalone repo's binary installer.
        "wolfproxy" => "https://raw.githubusercontent.com/intelligentwolf/wolfproxy/main/setup.sh",
        "wolfserve" => "https://raw.githubusercontent.com/intelligentwolf/wolfserve/main/setup.sh",
        // WolfScale/main/setup.sh installs WolfScale (DB replication), NOT
        // WolfDisk — using it here installed the wrong thing, so the wolfdisk
        // binary + wolfdisk.service never appeared ("Unit wolfdisk.service not
        // found"). The WolfDisk installer lives at wolfdisk/setup.sh.
        "wolfdisk" => "https://raw.githubusercontent.com/intelligentwolf/WolfScale/main/wolfdisk/setup.sh",
        "wolfscale" => "https://raw.githubusercontent.com/intelligentwolf/WolfScale/main/setup_lb.sh",
        other => return Err(format!("Unknown Wolf component: '{}'. Available: wolfnet, wolfproxy, wolfserve, wolfdisk, wolfscale", other)),
    };

    // Build the exec command based on runtime
    let exec_cmd = match runtime {
        "docker" => {
            // Verify container is running
            let check = Command::new("docker")
                .args(["inspect", "--format", "{{.State.Running}}", container])
                .output()
                .map_err(|e| format!("Failed to check container state: {}", e))?;
            let state = String::from_utf8_lossy(&check.stdout).trim().to_string();
            if state != "true" {
                return Err(format!("Container '{}' is not running. Start it first.", container));
            }

            // First ensure curl is available in the container
            let _ = Command::new("docker")
                .args(["exec", "-e", "DEBIAN_FRONTEND=noninteractive", container, "sh", "-c",
                    "apt-get update -qq && apt-get install -y -qq curl 2>/dev/null || yum install -y -q curl 2>/dev/null || apk add --quiet curl 2>/dev/null || true"])
                .output();

            // Download and run install script (DEBIAN_FRONTEND=noninteractive prevents dpkg prompts from hanging)
            Command::new("docker")
                .args(["exec", "-e", "DEBIAN_FRONTEND=noninteractive", container, "sh", "-c",
                    &format!("curl -fsSL '{}' | bash", install_script)])
                .output()
                .map_err(|e| format!("Failed to exec in container: {}", e))?
        }
        "lxc" => {
            let base = lxc_base_dir(container);
            let mut prefix: Vec<&str> = Vec::new();
            if base != LXC_DEFAULT_PATH { prefix.extend_from_slice(&["-P", &base]); }

            // Verify container is running
            let mut info_args = prefix.clone();
            info_args.extend_from_slice(&["-n", container, "-sH"]);
            let check = Command::new("lxc-info")
                .args(&info_args)
                .output()
                .map_err(|e| format!("Failed to check container state: {}", e))?;
            let state = String::from_utf8_lossy(&check.stdout).trim().to_string();
            if state != "RUNNING" {
                return Err(format!("Container '{}' is not running (state: {}). Start it first.", container, state));
            }

            // First ensure curl is available
            let mut args = prefix.clone();
            args.extend_from_slice(&["-n", container, "--", "sh", "-c",
                "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq curl 2>/dev/null || yum install -y -q curl 2>/dev/null || apk add --quiet curl 2>/dev/null || true"]);
            let _ = Command::new("lxc-attach").args(&args).output();

            // Download and run install script (DEBIAN_FRONTEND=noninteractive prevents dpkg prompts from hanging)
            let install_cmd = format!("export DEBIAN_FRONTEND=noninteractive; curl -fsSL '{}' | bash", install_script);
            let mut args = prefix.clone();
            args.extend_from_slice(&["-n", container, "--", "sh", "-c", &install_cmd]);
            Command::new("lxc-attach")
                .args(&args)
                .output()
                .map_err(|e| format!("Failed to attach to container: {}", e))?
        }
        _ => return Err(format!("Unsupported runtime: '{}'. Use 'docker' or 'lxc'.", runtime)),
    };

    if exec_cmd.status.success() {
        let stdout = String::from_utf8_lossy(&exec_cmd.stdout);

        Ok(format!("{} installed in {} container '{}'. {}", 
            component, runtime, container, 
            stdout.lines().last().unwrap_or("Done")))
    } else {
        let stderr = String::from_utf8_lossy(&exec_cmd.stderr).to_string();
        let stdout = String::from_utf8_lossy(&exec_cmd.stdout).to_string();
        error!("Failed to install {} in container {}: {}", component, container, stderr);
        Err(format!("Installation failed: {}{}", 
            if stderr.is_empty() { &stdout } else { &stderr },
            ""))
    }
}

/// List running containers (both Docker and LXC) for component installation UI
pub fn list_running_containers() -> Vec<(String, String, String)> {
    let mut result = Vec::new();

    // Docker containers
    if let Ok(output) = Command::new("docker")
        .args(["ps", "--format", "{{.Names}}\t{{.Image}}"])
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if line.is_empty() { continue; }
            let parts: Vec<&str> = line.split('\t').collect();
            let name = parts.first().unwrap_or(&"").to_string();
            let image = parts.get(1).unwrap_or(&"").to_string();
            result.push(("docker".to_string(), name, image));
        }
    }

    // LXC containers — scan all registered storage paths
    let mut seen_lxc = std::collections::HashSet::new();
    for lxc_path in lxc_storage_paths() {
        if let Ok(output) = Command::new("lxc-ls")
            .args(["-P", &lxc_path, "--running"])
            .output()
        {
            for name in String::from_utf8_lossy(&output.stdout).split_whitespace() {
                if seen_lxc.insert(name.to_string()) {
                    result.push(("lxc".to_string(), name.to_string(), "LXC".to_string()));
                }
            }
        }
    }

    result
}

// ─── Volume / Mount Management ───

/// A mount point for display in the UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerMount {
    pub host_path: String,
    pub container_path: String,
    pub mount_type: String,  // "bind", "volume", "tmpfs"
    pub read_only: bool,
}

/// Mount options supported across native LXC and Proxmox CTs. The
/// PVE-only flags (shared, backup, size_gb, quota) are silently
/// ignored on native containers — they have no equivalent in the
/// `lxc.mount.entry` syntax.
#[derive(Debug, Default, Clone)]
pub struct LxcMountOptions {
    pub host_path: String,
    pub container_path: String,
    pub read_only: bool,
    pub shared: bool,
    pub backup: bool,
    pub quota: bool,
    pub size_gb: Option<u64>,
}

/// Return Some(vmid) when this container name is registered with PVE
/// via `pct list`, None otherwise. The Name column is the last token
/// on the row; we match it strict-equal so "web" doesn't hit "webdb".
fn pct_vmid_for_name(container: &str) -> Option<u64> {
    if !is_proxmox() { return None; }
    // Numeric names (PVE uses VMIDs) can be passed straight through.
    if let Ok(vmid) = container.parse::<u64>() {
        let out = Command::new("pct").args(["config", &vmid.to_string()]).output().ok()?;
        if out.status.success() { return Some(vmid); }
    }
    let out = Command::new("pct").args(["list"]).output().ok()?;
    if !out.status.success() { return None; }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 { continue; }
        if *parts.last()? == container {
            return parts[0].parse().ok();
        }
    }
    None
}

fn pct_add_mount(vmid: u64, opts: &LxcMountOptions) -> Result<String, String> {
    // Find the next free mpN slot by scanning existing config.
    let out = Command::new("pct").args(["config", &vmid.to_string()])
        .output().map_err(|e| format!("pct config: {}", e))?;
    if !out.status.success() {
        return Err(format!("pct config failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let cfg = String::from_utf8_lossy(&out.stdout);
    let used: std::collections::HashSet<u32> = cfg.lines()
        .filter_map(|l| {
            let rest = l.trim().strip_prefix("mp")?;
            let colon = rest.find(':')?;
            rest[..colon].parse::<u32>().ok()
        })
        .collect();
    let mp_idx = (0..256u32).find(|i| !used.contains(i))
        .ok_or_else(|| "no free mpN slot (0-255 all used)".to_string())?;

    // Build the option string. Only bind-mount sources (host paths
    // starting with /) should skip `size=` — for those PVE doesn't
    // allocate a volume, so a size= key is invalid.
    let mut parts: Vec<String> = vec![opts.host_path.clone()];
    parts.push(format!("mp={}", opts.container_path));
    if opts.read_only { parts.push("ro=1".to_string()); }
    if opts.shared { parts.push("shared=1".to_string()); }
    if opts.backup { parts.push("backup=1".to_string()); }
    if opts.quota { parts.push("quota=1".to_string()); }
    if let Some(sz) = opts.size_gb
        && !opts.host_path.starts_with('/') { parts.push(format!("size={}G", sz)); }
    let mp_value = parts.join(",");

    let out = Command::new("pct")
        .args(["set", &vmid.to_string(), &format!("--mp{}", mp_idx), &mp_value])
        .output()
        .map_err(|e| format!("pct set: {}", e))?;
    if !out.status.success() {
        return Err(format!("pct set failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(format!("Mount mp{} added: {} → {}", mp_idx, opts.host_path, opts.container_path))
}

fn pct_list_mounts(vmid: u64) -> Vec<ContainerMount> {
    let out = match Command::new("pct").args(["config", &vmid.to_string()]).output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let cfg = String::from_utf8_lossy(&out.stdout);
    let mut mounts = Vec::new();
    for line in cfg.lines() {
        let rest = match line.trim().strip_prefix("mp") {
            Some(r) => r,
            None => continue,
        };
        let colon = match rest.find(':') { Some(c) => c, None => continue };
        let idx_str = &rest[..colon];
        if idx_str.parse::<u32>().is_err() { continue; }
        let value = rest[colon + 1..].trim();
        // First comma splits source from options; no comma means just
        // a source with no options (unusual but valid).
        let (host_path, opts_str) = match value.find(',') {
            Some(pos) => (value[..pos].to_string(), &value[pos + 1..]),
            None => (value.to_string(), ""),
        };
        let mut container_path = String::new();
        let mut read_only = false;
        for opt in opts_str.split(',') {
            let opt = opt.trim();
            if let Some(v) = opt.strip_prefix("mp=") { container_path = v.to_string(); }
            if opt == "ro=1" { read_only = true; }
        }
        if container_path.is_empty() { continue; }
        mounts.push(ContainerMount {
            host_path,
            container_path,
            mount_type: format!("mp{}", idx_str),
            read_only,
        });
    }
    mounts
}

fn pct_remove_mount(vmid: u64, host_path: &str) -> Result<String, String> {
    let out = Command::new("pct").args(["config", &vmid.to_string()])
        .output().map_err(|e| format!("pct config: {}", e))?;
    if !out.status.success() {
        return Err(format!("pct config failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let cfg = String::from_utf8_lossy(&out.stdout);
    let mut target: Option<u32> = None;
    for line in cfg.lines() {
        let rest = match line.trim().strip_prefix("mp") { Some(r) => r, None => continue };
        let colon = match rest.find(':') { Some(c) => c, None => continue };
        let idx_str = &rest[..colon];
        let idx = match idx_str.parse::<u32>() { Ok(i) => i, Err(_) => continue };
        let value = rest[colon + 1..].trim();
        let source = value.split(',').next().unwrap_or("").trim();
        if source == host_path { target = Some(idx); break; }
    }
    let idx = target.ok_or_else(|| format!("no mpN entry matching '{}'", host_path))?;
    let out = Command::new("pct")
        .args(["set", &vmid.to_string(), "--delete", &format!("mp{}", idx)])
        .output()
        .map_err(|e| format!("pct set --delete: {}", e))?;
    if !out.status.success() {
        return Err(format!("pct set failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(format!("Mount mp{} removed", idx))
}

/// Add a bind mount to an LXC container's config (container must be
/// stopped). Routes through `pct set` on Proxmox CTs so the mp entry
/// lives in `/etc/pve/lxc/<vmid>.conf` with full PVE metadata; falls
/// back to writing an `lxc.mount.entry` line on native LXC.
pub fn lxc_add_mount(container: &str, opts: &LxcMountOptions) -> Result<String, String> {
    if let Some(vmid) = pct_vmid_for_name(container) {
        return pct_add_mount(vmid, opts);
    }

    let host_path = &opts.host_path;
    let container_path = &opts.container_path;
    let config_path = format!("{}/{}/config", lxc_base_dir(container), container);
    let mut config = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Container '{}' config not found: {}", container, e))?;

    // Ensure host path exists (create it if it doesn't). Only makes
    // sense for a literal filesystem path — skip if the user passed a
    // PVE storage id on a non-PVE host (would fail and confuse).
    if host_path.starts_with('/') && !std::path::Path::new(host_path).exists() {
        std::fs::create_dir_all(host_path)
            .map_err(|e| format!("Failed to create host path '{}': {}", host_path, e))?;
    }

    // Build the mount entry
    let ro_flag = if opts.read_only { ",ro" } else { "" };
    // Container path must not have a leading / for lxc.mount.entry
    let clean_container_path = container_path.trim_start_matches('/');
    let entry = format!("\nlxc.mount.entry = {} {} none bind,create=dir{} 0 0\n",
        host_path, clean_container_path, ro_flag);

    // Check for duplicate
    if config.contains(&format!("{} {} none bind", host_path, clean_container_path)) {
        return Err(format!("Mount {} -> {} already exists", host_path, container_path));
    }

    config.push_str(&entry);
    std::fs::write(&config_path, config)
        .map_err(|e| format!("Failed to write config: {}", e))?;

    Ok(format!("Mount added: {} → {}", host_path, container_path))
}

/// Remove a bind mount from an LXC container's config
pub fn lxc_remove_mount(container: &str, host_path: &str) -> Result<String, String> {
    if let Some(vmid) = pct_vmid_for_name(container) {
        return pct_remove_mount(vmid, host_path);
    }

    let config_path = format!("{}/{}/config", lxc_base_dir(container), container);
    let config = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Container '{}' config not found: {}", container, e))?;

    let filtered: Vec<&str> = config.lines()
        .filter(|line| {
            !(line.trim().starts_with("lxc.mount.entry") && line.contains(host_path))
        })
        .collect();

    write_lxc_config(&config_path, &filtered)
        .map_err(|e| format!("Failed to write config: {}", e))?;


    Ok(format!("Mount removed: {}", host_path))
}

/// List current bind mounts for an LXC container
pub fn lxc_list_mounts(container: &str) -> Vec<ContainerMount> {
    if let Some(vmid) = pct_vmid_for_name(container) {
        return pct_list_mounts(vmid);
    }

    let config_path = format!("{}/{}/config", lxc_base_dir(container), container);
    let config = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    config.lines()
        .filter(|line| line.trim().starts_with("lxc.mount.entry"))
        .filter_map(|line| {
            // Format: lxc.mount.entry = /host/path container/path none bind,create=dir 0 0
            let entry = line.split('=').nth(1)?.trim();
            let parts: Vec<&str> = entry.split_whitespace().collect();
            if parts.len() >= 4 && parts[3].contains("bind") {
                Some(ContainerMount {
                    host_path: parts[0].to_string(),
                    container_path: format!("/{}", parts[1]),
                    mount_type: "bind".to_string(),
                    read_only: parts[3].contains("ro"),
                })
            } else {
                None
            }
        })
        .collect()
}

/// List volume mounts for a Docker container (uses docker inspect)
pub fn docker_list_volumes(container: &str) -> Vec<ContainerMount> {
    let output = Command::new("docker")
        .args(["inspect", "--format", "{{range .Mounts}}{{.Type}}\t{{.Source}}\t{{.Destination}}\t{{.RW}}{{println}}{{end}}", container])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .filter_map(|line| {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() >= 4 {
                        Some(ContainerMount {
                            host_path: parts[1].to_string(),
                            container_path: parts[2].to_string(),
                            mount_type: parts[0].to_string(),
                            read_only: parts[3] != "true",
                        })
                    } else {
                        None
                    }
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

/// Export a Docker container as a tar image for migration.
/// Uses `docker commit` to snapshot the container state, then `docker save` to tar.
#[allow(dead_code)]
pub fn docker_export(container_name: &str) -> Result<String, String> {
    let image_tag = format!("wolfrun-migrate:{}", container_name);
    let tar_path = format!("/tmp/wolfrun-migrate-{}.tar", container_name);


    // Commit the container to an image
    let output = Command::new("docker")
        .args(["commit", container_name, &image_tag])
        .output()
        .map_err(|e| format!("docker commit failed: {}", e))?;

    if !output.status.success() {
        return Err(format!("docker commit failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Save the image to a tar file
    let output = Command::new("docker")
        .args(["save", "-o", &tar_path, &image_tag])
        .output()
        .map_err(|e| format!("docker save failed: {}", e))?;

    // Clean up the temporary image
    let _ = Command::new("docker").args(["rmi", &image_tag]).output();

    if output.status.success() {

        Ok(tar_path)
    } else {
        Err(format!("docker save failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

/// Import a Docker image from a tar file, then create and start a container.
#[allow(dead_code)]
pub fn docker_import(
    container_name: &str,
    tar_path: &str,
    ports: &[String],
    env: &[String],
    volumes: &[String],
) -> Result<String, String> {


    // Load the image
    let output = Command::new("docker")
        .args(["load", "-i", tar_path])
        .output()
        .map_err(|e| format!("docker load failed: {}", e))?;

    if !output.status.success() {
        return Err(format!("docker load failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // Parse the loaded image name from stdout (e.g., "Loaded image: wolfrun-migrate:name")
    let stdout = String::from_utf8_lossy(&output.stdout);
    let image_name = stdout.lines()
        .find(|l| l.contains("Loaded image"))
        .and_then(|l| l.split(": ").nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| format!("wolfrun-migrate:{}", container_name));

    // Create container from the loaded image
    let wolfnet_ip = next_available_wolfnet_ip();
    docker_create(
        container_name, &image_name, ports, env,
        wolfnet_ip.as_deref(), None, None, None, volumes,
    )?;

    // Start it
    docker_start(container_name)?;

    // Clean up the migration image
    let _ = Command::new("docker").args(["rmi", &image_name]).output();


    Ok(format!("Container '{}' imported and running", container_name))
}

#[cfg(test)]
mod port_mapping_tests {
    use super::*;

    /// Empty driver map — used by tests that don't depend on driver
    /// information (the inspect JSON alone is sufficient to derive
    /// the expected outcome via the bridge / null-Ports fallbacks).
    fn no_drivers() -> std::collections::HashMap<String, String> {
        std::collections::HashMap::new()
    }

    #[test]
    fn parse_published_port_marks_published_true() {
        // PortBindings asks for 0.0.0.0:8080 → 80/tcp, NetworkSettings
        // confirms 0.0.0.0:8080 is bound. Result: published=true.
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": {
                "PortBindings": {
                    "80/tcp": [{ "HostIp": "", "HostPort": "8080" }]
                }
            },
            "NetworkSettings": {
                "Ports": {
                    "80/tcp": [{ "HostIp": "0.0.0.0", "HostPort": "8080" }]
                }
            }
        }"#).unwrap();
        let mappings = parse_port_mappings(&inspect, &no_drivers());
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].host_port, 8080);
        assert_eq!(mappings[0].container_port, 80);
        assert_eq!(mappings[0].proto, "tcp");
        assert!(mappings[0].published,
            "0.0.0.0 wildcard request must match a 0.0.0.0 published binding");
    }

    #[test]
    fn parse_unpublished_port_marks_published_false() {
        // The Klas case: PortBindings asks for 8080, but
        // NetworkSettings.Ports.80/tcp is null (no host binding).
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": {
                "PortBindings": {
                    "80/tcp": [{ "HostIp": "", "HostPort": "8080" }]
                }
            },
            "NetworkSettings": {
                "Ports": {
                    "80/tcp": null
                }
            }
        }"#).unwrap();
        let mappings = parse_port_mappings(&inspect, &no_drivers());
        assert_eq!(mappings.len(), 1);
        assert!(!mappings[0].published,
            "null NetworkSettings.Ports entry means the daemon never published the binding");
    }

    #[test]
    fn parse_dual_stack_v4_v6_publish_counts_as_published() {
        // Docker on a dual-stack host emits both 0.0.0.0 and ::
        // entries when a wildcard PortBindings request is published.
        // The matcher must accept either as a confirmation.
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": {
                "PortBindings": {
                    "443/tcp": [{ "HostIp": "0.0.0.0", "HostPort": "443" }]
                }
            },
            "NetworkSettings": {
                "Ports": {
                    "443/tcp": [
                        { "HostIp": "0.0.0.0", "HostPort": "443" },
                        { "HostIp": "::",      "HostPort": "443" }
                    ]
                }
            }
        }"#).unwrap();
        let mappings = parse_port_mappings(&inspect, &no_drivers());
        assert_eq!(mappings.len(), 1);
        assert!(mappings[0].published);
    }

    #[test]
    fn parse_specific_host_ip_does_not_match_wildcard() {
        // PortBindings asks for 127.0.0.1:5432 → 5432, but the
        // published entry is 0.0.0.0:5432. Different IP — different
        // binding, so the request was NOT honoured the way the
        // operator asked.
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": {
                "PortBindings": {
                    "5432/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "5432" }]
                }
            },
            "NetworkSettings": {
                "Ports": {
                    "5432/tcp": [{ "HostIp": "0.0.0.0", "HostPort": "5432" }]
                }
            }
        }"#).unwrap();
        let mappings = parse_port_mappings(&inspect, &no_drivers());
        assert_eq!(mappings.len(), 1);
        assert!(!mappings[0].published,
            "127.0.0.1 request != 0.0.0.0 published — operator's bind-IP intent wasn't met");
    }

    #[test]
    fn parse_udp_proto_preserved() {
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": {
                "PortBindings": {
                    "53/udp": [{ "HostIp": "", "HostPort": "53" }]
                }
            },
            "NetworkSettings": {
                "Ports": {
                    "53/udp": [{ "HostIp": "0.0.0.0", "HostPort": "53" }]
                }
            }
        }"#).unwrap();
        let mappings = parse_port_mappings(&inspect, &no_drivers());
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].proto, "udp");
        assert!(mappings[0].published);
    }

    #[test]
    fn parse_empty_port_bindings_yields_empty_vec() {
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": { "PortBindings": {} },
            "NetworkSettings": { "Ports": {} }
        }"#).unwrap();
        assert!(parse_port_mappings(&inspect, &no_drivers()).is_empty());
    }

    #[test]
    fn parse_host_network_mode_skips_publish_check() {
        // AdGuard Home running in `network_mode: host` (PapaSchlumpf's
        // case): compose declares ports so Docker keeps PortBindings,
        // but NetworkSettings.Ports is empty because there's no NAT
        // mapping — the container is on the host's network namespace.
        // The diff would flag every port as unpublished even though
        // AdGuard is binding :53 directly on the LAN. We must short-
        // circuit and return an empty vec.
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": {
                "NetworkMode": "host",
                "PortBindings": {
                    "53/tcp":  [{ "HostIp": "", "HostPort": "53" }],
                    "53/udp":  [{ "HostIp": "", "HostPort": "53" }],
                    "80/tcp":  [{ "HostIp": "", "HostPort": "80" }],
                    "443/tcp": [{ "HostIp": "", "HostPort": "443" }]
                }
            },
            "NetworkSettings": {
                "Ports": {}
            }
        }"#).unwrap();
        assert!(parse_port_mappings(&inspect, &no_drivers()).is_empty(),
            "host-mode containers must not produce port mappings — \
             NetworkSettings.Ports is empty by design and the diff is meaningless");
    }

    #[test]
    fn parse_container_namespace_mode_skips_publish_check() {
        // `network_mode: container:<id>` shares another container's
        // network namespace — same property as host mode: PortBindings
        // may exist but NetworkSettings.Ports never records a binding.
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": {
                "NetworkMode": "container:abcdef0123",
                "PortBindings": {
                    "8080/tcp": [{ "HostIp": "", "HostPort": "8080" }]
                }
            },
            "NetworkSettings": {
                "Ports": {}
            }
        }"#).unwrap();
        assert!(parse_port_mappings(&inspect, &no_drivers()).is_empty(),
            "shared-namespace containers must not produce port mappings");
    }

    #[test]
    fn parse_bridge_network_mode_still_runs_publish_check() {
        // Sanity guard: only `host` and `container:` short-circuit.
        // Bridge / default / custom networks must still produce the
        // PortBindings vs NetworkSettings.Ports diff (otherwise we'd
        // mask the silent-publish-failure detector entirely).
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": {
                "NetworkMode": "bridge",
                "PortBindings": {
                    "80/tcp": [{ "HostIp": "", "HostPort": "8080" }]
                }
            },
            "NetworkSettings": {
                "Ports": {
                    "80/tcp": [{ "HostIp": "0.0.0.0", "HostPort": "8080" }]
                }
            }
        }"#).unwrap();
        let mappings = parse_port_mappings(&inspect, &no_drivers());
        assert_eq!(mappings.len(), 1);
        assert!(mappings[0].published);
    }

    #[test]
    fn parse_macvlan_network_skips_publish_check() {
        // Fallback path (driver lookup unavailable): a user-defined
        // network with truly-empty Ports `{}` is conservatively assumed
        // to be macvlan/ipvlan/etc and skipped. This is what catches
        // macvlan containers that did NOT declare `ports:` in compose.
        // The with-`ports:` macvlan case (which produces null entries,
        // not empty `{}`) is caught by the driver-map lookup instead —
        // see parse_macvlan_with_declared_ports_skips_via_driver_map.
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": {
                "NetworkMode": "frigate_macvlan",
                "PortBindings": {
                    "5000/tcp": [{ "HostIp": "", "HostPort": "5000" }],
                    "8554/tcp": [{ "HostIp": "", "HostPort": "8554" }],
                    "8555/tcp": [{ "HostIp": "", "HostPort": "8555" }],
                    "8555/udp": [{ "HostIp": "", "HostPort": "8555" }]
                }
            },
            "NetworkSettings": {
                "Ports": {}
            }
        }"#).unwrap();
        assert!(parse_port_mappings(&inspect, &no_drivers()).is_empty(),
            "user-defined network with empty Ports = macvlan/ipvlan/etc; \
             port-mapping diff is meaningless");
    }

    #[test]
    fn parse_macvlan_with_declared_ports_skips_via_driver_map() {
        // PapaSchlumpf's actual Frigate case (the v22.10.3 fix):
        // container on a macvlan with its own LAN IP, and compose
        // declared `ports:` for the documented services. Docker still
        // records the port keys in NetworkSettings.Ports — but with
        // null values, because it doesn't NAT for macvlan. That shape
        // (`{"5000/tcp": null, ...}`) is byte-identical to a real
        // silent-publish failure on a bridge, so the empty-Ports
        // heuristic alone can't distinguish them.
        //
        // The driver map is the authoritative tiebreaker: ask Docker
        // what driver this network uses, and skip when it's macvlan or
        // ipvlan regardless of what Ports looks like.
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": {
                "NetworkMode": "frigate_macvlan",
                "PortBindings": {
                    "5000/tcp": [{ "HostIp": "", "HostPort": "5000" }],
                    "8554/tcp": [{ "HostIp": "", "HostPort": "8554" }],
                    "8555/tcp": [{ "HostIp": "", "HostPort": "8555" }],
                    "8555/udp": [{ "HostIp": "", "HostPort": "8555" }]
                }
            },
            "NetworkSettings": {
                "Ports": {
                    "5000/tcp": null,
                    "8554/tcp": null,
                    "8555/tcp": null,
                    "8555/udp": null
                }
            }
        }"#).unwrap();
        let mut drivers = std::collections::HashMap::new();
        drivers.insert("frigate_macvlan".to_string(), "macvlan".to_string());
        assert!(parse_port_mappings(&inspect, &drivers).is_empty(),
            "macvlan-driver lookup must short-circuit even when Ports has null entries (Frigate case)");
    }

    #[test]
    fn parse_ipvlan_with_declared_ports_skips_via_driver_map() {
        // Same as above but ipvlan — the other driver Docker provides
        // that doesn't NAT host ports. Treat identically.
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": {
                "NetworkMode": "lan_ipvlan",
                "PortBindings": {
                    "443/tcp": [{ "HostIp": "", "HostPort": "443" }]
                }
            },
            "NetworkSettings": {
                "Ports": { "443/tcp": null }
            }
        }"#).unwrap();
        let mut drivers = std::collections::HashMap::new();
        drivers.insert("lan_ipvlan".to_string(), "ipvlan".to_string());
        assert!(parse_port_mappings(&inspect, &drivers).is_empty(),
            "ipvlan-driver lookup must short-circuit the same way macvlan does");
    }

    #[test]
    fn parse_user_defined_bridge_driver_known_still_detects_silent_publish() {
        // Counter-test for the v22.10.3 fix: when the driver map is
        // populated and tells us the network is a *bridge*, the
        // silent-publish detector must still fire on null Ports
        // entries. This is the scenario the detector was built for —
        // we must not regress it while fixing the macvlan false
        // positive.
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": {
                "NetworkMode": "myapp_default",
                "PortBindings": {
                    "5000/tcp": [{ "HostIp": "", "HostPort": "5000" }]
                }
            },
            "NetworkSettings": {
                "Ports": { "5000/tcp": null }
            }
        }"#).unwrap();
        let mut drivers = std::collections::HashMap::new();
        drivers.insert("myapp_default".to_string(), "bridge".to_string());
        let mappings = parse_port_mappings(&inspect, &drivers);
        assert_eq!(mappings.len(), 1, "must still produce a mapping on a known-bridge network");
        assert!(!mappings[0].published,
            "null Ports entry on a known-bridge network = silent-publish failure; must be flagged");
    }

    #[test]
    fn parse_user_defined_bridge_with_null_port_entries_still_detects_silent_publish() {
        // Klas's original case (the bug the detector was built for) on a
        // user-defined bridge instead of the default. PortBindings asks
        // for a host port; NetworkSettings.Ports has the proto/cport key
        // present but a null host-list — meaning Docker started the
        // container but silently failed to bind the host port. Must NOT
        // be confused with macvlan: macvlan is `Ports: {}` (truly
        // empty), this case is `Ports: {"80/tcp": null}` (key present,
        // bind failed). The detector must still flag this.
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": {
                "NetworkMode": "myapp_default",
                "PortBindings": {
                    "5000/tcp": [{ "HostIp": "", "HostPort": "5000" }]
                }
            },
            "NetworkSettings": {
                "Ports": { "5000/tcp": null }
            }
        }"#).unwrap();
        let mappings = parse_port_mappings(&inspect, &no_drivers());
        assert_eq!(mappings.len(), 1, "must still produce a mapping");
        assert!(!mappings[0].published,
            "null Ports entry on a user-defined bridge = silent-publish failure (Klas case); must be flagged unpublished");
    }

    #[test]
    fn parse_user_defined_bridge_with_real_port_mapping_still_validates() {
        // Counter-test: a user-defined BRIDGE (e.g. compose's auto-
        // generated `<projectname>_default`) with port mapping must
        // still run the publish check. Docker DOES manage port
        // forwarding for these and populates NetworkSettings.Ports
        // properly — the silent-publish detector is still useful here.
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": {
                "NetworkMode": "myapp_default",
                "PortBindings": {
                    "8080/tcp": [{ "HostIp": "", "HostPort": "8080" }]
                }
            },
            "NetworkSettings": {
                "Ports": {
                    "8080/tcp": [{ "HostIp": "0.0.0.0", "HostPort": "8080" }]
                }
            }
        }"#).unwrap();
        let mappings = parse_port_mappings(&inspect, &no_drivers());
        assert_eq!(mappings.len(), 1, "user-defined bridge with real port mapping must produce a mapping");
        assert!(mappings[0].published, "the binding is genuinely published — must not be flagged unpublished");
    }

    #[test]
    fn parse_none_network_mode_skips_publish_check() {
        // `network_mode: none` containers have no networking at all.
        // PortBindings declarations are vestigial and the diff would
        // flag every one as unpublished — but there's nothing to publish
        // against because there's no network.
        let inspect: serde_json::Value = serde_json::from_str(r#"{
            "HostConfig": {
                "NetworkMode": "none",
                "PortBindings": {
                    "80/tcp": [{ "HostIp": "", "HostPort": "8080" }]
                }
            },
            "NetworkSettings": {
                "Ports": {}
            }
        }"#).unwrap();
        assert!(parse_port_mappings(&inspect, &no_drivers()).is_empty(),
            "`network_mode: none` containers have no networking; port mappings are meaningless");
    }

    #[test]
    fn parse_docker_port_arg_handles_all_canonical_shapes() {
        // "8080:80" — wildcard host, default tcp
        let r = parse_docker_port_arg("8080:80").unwrap();
        assert_eq!(r.host_ip, "0.0.0.0");
        assert_eq!(r.host_port, 8080);
        assert_eq!(r.proto, "tcp");

        // "127.0.0.1:8080:80" — specific host IP
        let r = parse_docker_port_arg("127.0.0.1:8080:80").unwrap();
        assert_eq!(r.host_ip, "127.0.0.1");
        assert_eq!(r.host_port, 8080);

        // "53:53/udp" — UDP suffix
        let r = parse_docker_port_arg("53:53/udp").unwrap();
        assert_eq!(r.proto, "udp");

        // "443" — random host port form: nothing to validate
        assert!(parse_docker_port_arg("443").is_none());

        // "8000-8010:8000-8010" — range form: skip (Docker handles)
        assert!(parse_docker_port_arg("8000-8010:8000-8010").is_none());
    }
}

#[cfg(test)]
mod apparmor_config_tests {
    use super::*;

    #[test]
    fn strip_apparmor_profile_removes_only_that_key_and_keeps_shape() {
        let cfg = "lxc.uts.name = web\n\
                   lxc.include = /usr/share/lxc/config/nesting.conf\n\
                   lxc.apparmor.profile = unconfined\n\
                   lxc.mount.auto = proc:rw sys:rw cgroup:rw\n";
        let out = strip_apparmor_profile(cfg);
        assert!(!out.contains("lxc.apparmor.profile"), "apparmor line must be gone");
        assert!(out.contains("lxc.uts.name = web"), "other keys preserved");
        assert!(out.contains("nesting.conf") && out.contains("lxc.mount.auto"), "neighbours preserved");
        assert!(out.ends_with('\n'), "trailing newline preserved");
        // Indented variants are stripped too; a config without the key is unchanged.
        assert!(!strip_apparmor_profile("  lxc.apparmor.profile = generated\n").contains("apparmor"));
        let untouched = "lxc.uts.name = x\n";
        assert_eq!(strip_apparmor_profile(untouched), untouched);
        // A config that is ONLY the key, with no trailing newline, becomes empty.
        assert_eq!(strip_apparmor_profile("lxc.apparmor.profile = unconfined"), "");
        // CRLF line endings are preserved (not normalised to LF).
        assert_eq!(
            strip_apparmor_profile("lxc.uts.name = w\r\nlxc.apparmor.profile = unconfined\r\n"),
            "lxc.uts.name = w\r\n"
        );
        // A sibling apparmor key WolfStack doesn't write is left alone (scope).
        assert!(strip_apparmor_profile("lxc.apparmor.allow_nesting = 1\n").contains("allow_nesting"));
    }
}

#[cfg(test)]
mod cross_platform_restore_tests {
    use super::*;

    #[test]
    fn vzdump_archives_are_detected_by_name_or_zstd() {
        // Proxmox vzdump: name carries "vzdump", compression is zstd.
        assert!(lxc_archive_is_vzdump("/var/lib/wolfstack/backups/vzdump-lxc-105-2026_06_06.tar.zst"));
        assert!(lxc_archive_is_vzdump("/tmp/VZDUMP-LXC-105.tar.zst")); // case-insensitive
        // A renamed vzdump that lost its name is still caught by zstd.
        assert!(lxc_archive_is_vzdump("/tmp/backup.tar.zst"));
        assert!(lxc_archive_is_vzdump("/tmp/whatever.zst"));
    }

    #[test]
    fn native_wolfstack_backups_are_not_vzdump() {
        // backup_lxc() always produces lxc-<name>-<ts>.tar.gz (gzip).
        assert!(!lxc_archive_is_vzdump("/var/lib/wolfstack/backups/lxc-web01-2026_06_06.tar.gz"));
        assert!(!lxc_archive_is_vzdump("/tmp/myct.tar.gz"));
        assert!(!lxc_archive_is_vzdump("/tmp/rootfs.tar"));
    }

    #[test]
    fn strip_apparmor_removes_the_unparseable_line_only() {
        // wabil 2026-06-14: Fedora LXC ("Built without AppArmor support") rejects
        // the whole config on this exact line, so the container can't start or be
        // destroyed. It must be removed; everything else must survive intact.
        let cfg = "lxc.uts.name = emergency desktop\n\
                   lxc.apparmor.profile = unconfined\n\
                   lxc.net.0.type = veth\n";
        let out = strip_apparmor_profile(cfg);
        assert!(!out.contains("lxc.apparmor.profile"), "the bad line must be gone");
        assert!(out.contains("lxc.uts.name = emergency desktop"), "other lines kept");
        assert!(out.contains("lxc.net.0.type = veth"), "other lines kept");
        assert!(out.ends_with('\n'), "trailing newline preserved");
        // A clean config is returned unchanged (so the heal is a no-op on it).
        let clean = "lxc.uts.name = web\nlxc.net.0.type = veth\n";
        assert_eq!(strip_apparmor_profile(clean), clean);
        // Other lxc.apparmor.* keys (e.g. allow_nesting) are intentionally left.
        let nested = "lxc.apparmor.allow_nesting = 1\nlxc.apparmor.profile = unconfined\n";
        let nested_out = strip_apparmor_profile(nested);
        assert!(nested_out.contains("lxc.apparmor.allow_nesting = 1"));
        assert!(!nested_out.contains("lxc.apparmor.profile"));
    }
}

#[cfg(test)]
mod pct_net0_tests {
    use super::*;

    #[test]
    fn host_mode_has_no_network_device() {
        // Matches the standalone lxc.net.0.type=none semantics — no eth0.
        assert_eq!(pct_net0_arg("host", None, None, None), None);
    }

    #[test]
    fn wolfnet_and_default_use_vmbr0_dhcp() {
        let expect = Some("name=eth0,bridge=vmbr0,ip=dhcp".to_string());
        assert_eq!(pct_net0_arg("wolfnet", None, None, None), expect);
        assert_eq!(pct_net0_arg("", None, None, None), expect);
    }

    #[test]
    fn bridge_static_includes_ip_and_gateway() {
        // wabil's case: a chosen LAN bridge + static IP + gateway must reach
        // pct verbatim — never the old hardcoded vmbr0/dhcp (or lxcbr0 10.0.3.x).
        assert_eq!(
            pct_net0_arg("bridge", Some("vmbr0"), Some("192.168.0.99/24"), Some("192.168.0.1")),
            Some("name=eth0,bridge=vmbr0,ip=192.168.0.99/24,gw=192.168.0.1".to_string())
        );
    }

    #[test]
    fn bridge_static_without_gateway_omits_gw() {
        assert_eq!(
            pct_net0_arg("bridge", Some("vmbr1"), Some("10.50.0.5/24"), None),
            Some("name=eth0,bridge=vmbr1,ip=10.50.0.5/24".to_string())
        );
        // Whitespace-only gateway is treated as absent.
        assert_eq!(
            pct_net0_arg("bridge", Some("vmbr1"), Some("10.50.0.5/24"), Some("  ")),
            Some("name=eth0,bridge=vmbr1,ip=10.50.0.5/24".to_string())
        );
    }

    #[test]
    fn bridge_without_ip_uses_dhcp_on_chosen_bridge() {
        assert_eq!(
            pct_net0_arg("bridge", Some("vmbr2"), None, None),
            Some("name=eth0,bridge=vmbr2,ip=dhcp".to_string())
        );
    }

    #[test]
    fn normalize_bridge_cidr_appends_24_to_bare_ip() {
        // wabil typed "192.168.0.99" — pct/NM need a prefix or it's unreachable.
        assert_eq!(normalize_bridge_cidr("192.168.0.99"), "192.168.0.99/24");
        assert_eq!(normalize_bridge_cidr("  10.0.0.5  "), "10.0.0.5/24");
        // Already has a prefix → left exactly as given (trimmed).
        assert_eq!(normalize_bridge_cidr("192.168.0.99/24"), "192.168.0.99/24");
        assert_eq!(normalize_bridge_cidr("10.0.0.5/16"), "10.0.0.5/16");
        // Not a bare IPv4 (empty, hostname, IPv6) → unchanged, never corrupted.
        assert_eq!(normalize_bridge_cidr(""), "");
        assert_eq!(normalize_bridge_cidr("dhcp"), "dhcp");
        assert_eq!(normalize_bridge_cidr("fe80::1/64"), "fe80::1/64");
    }

    #[test]
    fn prefix_to_netmask_covers_common_prefixes() {
        // /etc/network/interfaces needs a dotted-quad netmask, not a CIDR prefix.
        assert_eq!(super::prefix_to_netmask(24), "255.255.255.0");
        assert_eq!(super::prefix_to_netmask(16), "255.255.0.0");
        assert_eq!(super::prefix_to_netmask(8), "255.0.0.0");
        assert_eq!(super::prefix_to_netmask(25), "255.255.255.128");
        assert_eq!(super::prefix_to_netmask(32), "255.255.255.255");
        assert_eq!(super::prefix_to_netmask(0), "0.0.0.0");
        // Out-of-range prefix is clamped, never panics/overflows.
        assert_eq!(super::prefix_to_netmask(40), "255.255.255.255");
    }

    #[test]
    fn is_ipv4_cidr_rejects_non_addresses_and_injection() {
        // Real static IPs (post-normalize) are accepted.
        assert!(super::is_ipv4_cidr("192.168.0.99/24"));
        assert!(super::is_ipv4_cidr("10.0.0.5/16"));
        assert!(super::is_ipv4_cidr("0.0.0.0/0"));
        // normalize_bridge_cidr passes "dhcp" through unchanged — must NOT be
        // treated as a static address (the whole point of wabil's bug is DHCP).
        assert!(!super::is_ipv4_cidr("dhcp"));
        // Bare IP without a prefix is rejected (the writer wants a CIDR).
        assert!(!super::is_ipv4_cidr("192.168.0.99"));
        // Junk / out-of-range prefix / IPv6 rejected.
        assert!(!super::is_ipv4_cidr(""));
        assert!(!super::is_ipv4_cidr("192.168.0.99/33"));
        assert!(!super::is_ipv4_cidr("fe80::1/64"));
        // Embedded-newline injection attempt is rejected (defense in depth).
        assert!(!super::is_ipv4_cidr("192.168.1.1/24\n[Match]\nName=eth1"));
    }

    #[test]
    fn decide_primary_nic_net_action_branches() {
        use super::{decide_primary_nic_net_action as decide, PrimaryNicNetAction as A};
        // Static IP on a user bridge → write static (bare IP normalised to /24).
        assert_eq!(
            decide("br0", "192.168.0.99", "192.168.0.1", false),
            A::Static { cidr: "192.168.0.99/24".into(), gateway: Some("192.168.0.1".into()) }
        );
        // Static with no/invalid gateway → static, gateway dropped.
        assert_eq!(
            decide("br0", "10.0.0.5/16", "", false),
            A::Static { cidr: "10.0.0.5/16".into(), gateway: None }
        );
        assert_eq!(
            decide("br0", "10.0.0.5/16", "not-an-ip", false),
            A::Static { cidr: "10.0.0.5/16".into(), gateway: None }
        );
        // Cleared IP AND it was static before → DHCP revert (undo our pin).
        assert_eq!(decide("br0", "", "", true), A::Dhcp);
        // Cleared IP but it was ALREADY dhcp → Skip (don't clobber custom config).
        assert_eq!(decide("br0", "", "", false), A::Skip);
        // Private WolfNet bridge / unset link → never touched.
        assert_eq!(decide("lxcbr0", "192.168.0.99/24", "", false), A::Skip);
        assert_eq!(decide("", "192.168.0.99/24", "", false), A::Skip);
        // Non-IP junk in the IP field → not static; not previously static → Skip.
        assert_eq!(decide("br0", "dhcp", "", false), A::Skip);
    }

    #[test]
    fn primary_nic_edit_action_only_fires_on_real_change() {
        use super::{primary_nic_edit_action as act, PrimaryNicNetAction as A, LxcNetInterface};
        let nic = |link: &str, ipv4: &str, gw: &str| {
            let mut n = LxcNetInterface { index: 0, ..Default::default() };
            n.link = link.into(); n.ipv4 = ipv4.into(); n.ipv4_gw = gw.into();
            n
        };
        let cur = vec![nic("br0", "192.168.0.99/24", "192.168.0.1")];
        // Unchanged save (e.g. a memory-only edit re-sends the same NIC) → None,
        // so we never rewrite/clobber the in-container config on unrelated saves.
        assert_eq!(act(&cur.clone(), &cur, false), None);
        // Changed to a new static IP → Static.
        let newer = vec![nic("br0", "192.168.0.50/24", "192.168.0.1")];
        assert_eq!(
            act(&newer, &cur, false),
            Some(A::Static { cidr: "192.168.0.50/24".into(), gateway: Some("192.168.0.1".into()) })
        );
        // Static cleared → DHCP revert (it was static before).
        let dhcp = vec![nic("br0", "", "")];
        assert_eq!(act(&dhcp, &cur, false), Some(A::Dhcp));
        // WolfNet active → always None even on a change.
        assert_eq!(act(&newer, &cur, true), None);
    }

    #[test]
    fn pct_net0_fields_extracts_bridge_ip_gw() {
        use super::pct_net0_fields as p;
        // Full static net0 line.
        assert_eq!(
            p("name=eth0,bridge=br0,hwaddr=AA:BB:CC:DD:EE:FF,ip=192.168.0.99/24,gw=192.168.0.1,type=veth"),
            ("br0".into(), "192.168.0.99/24".into(), "192.168.0.1".into())
        );
        // DHCP line → ip is the literal "dhcp" (caller's is_ipv4_cidr rejects it).
        assert_eq!(
            p("name=eth0,bridge=vmbr0,ip=dhcp"),
            ("vmbr0".into(), "dhcp".into(), String::new())
        );
        // No gateway.
        assert_eq!(
            p("bridge=br0,ip=10.0.0.5/16"),
            ("br0".into(), "10.0.0.5/16".into(), String::new())
        );
    }

    #[test]
    fn bridge_defaults_to_vmbr0_not_lxcbr0() {
        // An empty/missing bridge name must fall back to the Proxmox LAN bridge
        // (vmbr0), NOT lxcbr0 — lxcbr0's dnsmasq is exactly the 10.0.3.x source
        // bridge-mode users were complaining about.
        assert_eq!(
            pct_net0_arg("bridge", None, Some("192.168.1.10/24"), None),
            Some("name=eth0,bridge=vmbr0,ip=192.168.1.10/24".to_string())
        );
        assert_eq!(
            pct_net0_arg("bridge", Some("  "), None, None),
            Some("name=eth0,bridge=vmbr0,ip=dhcp".to_string())
        );
    }
}

#[cfg(test)]
mod orphan_guard_tests {
    use super::*;

    #[test]
    fn numeric_dir_names_are_pve_vmid_husks() {
        // The ghost CTs (134, 120, 139, 133) were PVE VMID-keyed staging dirs
        // left behind by migrated/destroyed containers — never adopt these.
        for n in ["134", "120", "139", "133", "0", "100"] {
            assert!(is_pve_vmid_name(n), "{} should be treated as a PVE husk", n);
        }
    }

    #[test]
    fn human_names_are_adoptable() {
        // Genuine native lxc-create / App Store orphans carry human names and
        // must still be eligible for adoption — this is the path we mustn't break.
        for n in ["nextcloud", "ct-mariadb", "web01", "frigate", "node1"] {
            assert!(!is_pve_vmid_name(n), "{} should remain adoptable", n);
        }
        assert!(!is_pve_vmid_name(""), "empty name is not a vmid husk");
    }

    #[test]
    fn pct_list_ghost_count_matches_list_rule() {
        // `pct list` columns: VMID  Status  [Lock]  Name(hostname)
        // Ghost = stopped CT whose hostname is a bare VMID that isn't its own.
        assert!(pct_list_line_is_ghost("109   stopped   104"), "stopped + foreign-vmid hostname = ghost");
        // Running CT is in use — never a ghost, even with a numeric hostname.
        assert!(!pct_list_line_is_ghost("109   running   104"), "running is never a ghost");
        // Hostname == own vmid = an unnamed CT, not a husk.
        assert!(!pct_list_line_is_ghost("113   stopped   113"), "hostname == own vmid is not a ghost");
        // Real human-named container.
        assert!(!pct_list_line_is_ghost("116   running   regions11"), "human-named CT is not a ghost");
        assert!(!pct_list_line_is_ghost("116   stopped   regions11"), "stopped human-named CT is not a ghost");
        // Lock column present between status and name — still parsed correctly.
        assert!(pct_list_line_is_ghost("109   stopped   backup   104"), "lock column doesn't fool the parser");
    }

    #[test]
    fn host_container_arch_maps_rust_arch_to_lxc_naming() {
        // Maps Rust's ARCH to the Debian/LXC-image naming; never returns the
        // raw x86_64/aarch64 spelling for the two we care about.
        let a = super::host_container_arch();
        assert!(!a.is_empty());
        match std::env::consts::ARCH {
            "x86_64" => assert_eq!(a, "amd64"),
            "aarch64" => assert_eq!(a, "arm64"),
            "arm" => assert_eq!(a, "armhf"),
            other => assert_eq!(a, other), // best-effort passthrough
        }
    }

    #[test]
    fn lxc_macvlan_ipvlan_detection() {
        // Default veth on a bridge — host FORWARD covers it, NOT a target.
        let veth = "lxc.net.0.type = veth\nlxc.net.0.link = lxcbr0\n";
        assert!(!super::lxc_config_is_macvlan_or_ipvlan(veth));
        // macvlan — bypasses host netfilter, IS a target.
        let mac = "lxc.net.0.type = macvlan\nlxc.net.0.link = eth0\n";
        assert!(super::lxc_config_is_macvlan_or_ipvlan(mac));
        // ipvlan likewise.
        let ipv = "lxc.net.0.type = ipvlan\nlxc.net.0.link = eth0\n";
        assert!(super::lxc_config_is_macvlan_or_ipvlan(ipv));
        // A second NIC carrying macvlan still trips it.
        let second = "lxc.net.0.type = veth\nlxc.net.1.type = macvlan\n";
        assert!(super::lxc_config_is_macvlan_or_ipvlan(second));
        // No NIC type lines at all → not a target.
        assert!(!super::lxc_config_is_macvlan_or_ipvlan("arch: amd64\nhostname: x\n"));
    }

    #[test]
    fn first_reportable_ip_sanitises() {
        // Clean single address passes through.
        assert_eq!(super::first_reportable_ip("10.0.10.5"), Some("10.0.10.5".to_string()));
        // Multi-homed: take the first.
        assert_eq!(
            super::first_reportable_ip("10.0.10.5, 192.168.1.5"),
            Some("10.0.10.5".to_string())
        );
        // CIDR suffix (pct config fallback) stripped.
        assert_eq!(super::first_reportable_ip("10.0.10.5/24"), Some("10.0.10.5".to_string()));
        // " (wolfnet)" annotation dropped.
        assert_eq!(
            super::first_reportable_ip("10.0.10.5 (wolfnet)"),
            Some("10.0.10.5".to_string())
        );
        // Combined: CIDR + annotation, first of several.
        assert_eq!(
            super::first_reportable_ip("10.0.10.5/24 (wolfnet), 192.168.1.5"),
            Some("10.0.10.5".to_string())
        );
        // Empty / dash / junk → None (no route attempted).
        assert_eq!(super::first_reportable_ip(""), None);
        assert_eq!(super::first_reportable_ip("-"), None);
        assert_eq!(super::first_reportable_ip("not-an-ip"), None);
    }

    #[test]
    fn pve_net0_bridge_parse() {
        let cfg = "arch: amd64\n\
                   hostname: web01\n\
                   net0: name=eth0,bridge=vmbr1,hwaddr=AA:BB:CC:DD:EE:FF,ip=10.10.10.5/24,type=veth\n\
                   rootfs: local-lvm:vm-104-disk-0,size=8G\n";
        assert_eq!(super::bridge_from_pve_net0(cfg), Some("vmbr1".to_string()));
        // No net0 line → None.
        assert_eq!(super::bridge_from_pve_net0("arch: amd64\nhostname: x\n"), None);
        // net0 present but no bridge= (e.g. a NAT/none layout) → None, not a panic.
        assert_eq!(super::bridge_from_pve_net0("net0: name=eth0,ip=dhcp,type=veth\n"), None);
    }
}


#[cfg(test)]
mod cpu_capacity_tests {
    use super::*;

    #[test]
    fn cpuset_counts_ranges_and_singletons() {
        assert_eq!(cpuset_core_count("0-3"), Some(4.0));
        assert_eq!(cpuset_core_count("0,2,4"), Some(3.0));
        assert_eq!(cpuset_core_count("0-3,8"), Some(5.0));
        assert_eq!(cpuset_core_count("7"), Some(1.0));
        // Empty means "no cpuset restriction", not "zero cores" — returning
        // Some(0.0) would divide the gauge by zero.
        assert_eq!(cpuset_core_count(""), None);
        assert_eq!(cpuset_core_count("   "), None);
        // Malformed input must not be read as a limit.
        assert_eq!(cpuset_core_count("3-1"), None);
        assert_eq!(cpuset_core_count("a-b"), None);
    }

    #[test]
    fn cpu_max_parses_quota_and_unlimited() {
        assert_eq!(parse_cpu_max("200000 100000"), Some(2.0));
        assert_eq!(parse_cpu_max("50000 100000"), Some(0.5));
        // Period defaults to 100ms when the value omits it.
        assert_eq!(parse_cpu_max("100000"), Some(1.0));
        assert_eq!(parse_cpu_max("max 100000"), None);
        assert_eq!(parse_cpu_max(""), None);
        assert_eq!(parse_cpu_max("0 100000"), None);
    }

    #[test]
    fn cpu_percent_matches_docker_scale() {
        // Docker reports 100% per fully-used core (verified against docker
        // 2026-07-27: a two-core busy loop on a 24-core host reads 200.35%).
        // One core busy for one second of wall clock is 1_000_000us of CPU.
        let one_second = std::time::Duration::from_secs(1);
        assert_eq!(cpu_percent_from_delta(1_000_000, one_second), 100.0);
        assert_eq!(cpu_percent_from_delta(2_000_000, one_second), 200.0);
        assert_eq!(cpu_percent_from_delta(0, one_second), 0.0);
        // A zero-length sample window must not produce inf/NaN.
        assert_eq!(cpu_percent_from_delta(1_000_000, std::time::Duration::ZERO), 0.0);
    }

    #[test]
    fn host_cpu_cores_is_never_zero() {
        // Every capacity calculation divides by this.
        assert!(host_cpu_cores() >= 1.0);
    }
}

#[cfg(test)]
mod compose_command_tests {
    use super::*;

    #[test]
    fn probe_rejects_a_missing_binary() {
        assert!(!compose_probe("wolfstack-no-such-compose-binary", &[]));
    }

    #[test]
    fn resolves_to_one_of_the_two_supported_forms() {
        // Environment-dependent by nature: assert the shape, not the outcome.
        // Either form must be directly runnable, and the v2 form must carry
        // its `compose` subcommand — dropping it is what produced the
        // "unknown shorthand flag: 'f'" failure this replaced.
        match compose_command() {
            Ok((program, base_args)) => match program.as_str() {
                "docker" => assert_eq!(base_args, vec!["compose".to_string()]),
                "docker-compose" => assert!(base_args.is_empty()),
                other => panic!("unexpected compose program: {}", other),
            },
            Err(msg) => {
                // The error is operator-facing — it must say what to install.
                assert!(msg.contains("docker-compose"), "unhelpful error: {}", msg);
            }
        }
    }

    #[test]
    fn built_command_never_starts_with_a_flag() {
        // Whatever we resolve, appending "-f <file>" must not leave `-f` in
        // the global-flag position, which is exactly how the Unraid failure
        // presented (JJ, 2026-07-27).
        if let Ok((program, base_args)) = compose_command() {
            if program == "docker" {
                assert_eq!(base_args.first().map(|s| s.as_str()), Some("compose"));
            }
            assert!(base_args.iter().all(|a| !a.starts_with('-')));
        }
    }
}

#[cfg(test)]
mod migrate_spec_tests {
    use super::*;

    fn port(host_ip: &str, host: u16, ctr: u16, proto: &str) -> PortMapping {
        PortMapping {
            host_ip: host_ip.into(),
            host_port: host,
            container_port: ctr,
            proto: proto.into(),
            published: true,
        }
    }

    #[test]
    fn ports_render_as_docker_flags() {
        // RutgerDiehard's speedtest-tracker: 0.0.0.0:8543->443 and
        // 0.0.0.0:8181->80 arrived as a container with no bindings at all.
        let spec = DockerRuntimeSpec {
            ports: vec![port("0.0.0.0", 8543, 443, "tcp"), port("0.0.0.0", 8181, 80, "tcp")],
            ..Default::default()
        };
        let args = spec_to_create_args(&spec, true);
        assert!(args.windows(2).any(|w| w[0] == "-p" && w[1] == "8543:443/tcp"), "{:?}", args);
        assert!(args.windows(2).any(|w| w[0] == "-p" && w[1] == "8181:80/tcp"), "{:?}", args);
    }

    #[test]
    fn a_specific_listen_ip_is_preserved() {
        // 127.0.0.1:5432 must not silently become 0.0.0.0:5432 — that would
        // publish a database to the network the operator had kept it off.
        let spec = DockerRuntimeSpec {
            ports: vec![port("127.0.0.1", 5432, 5432, "tcp")],
            ..Default::default()
        };
        let args = spec_to_create_args(&spec, true);
        assert!(args.contains(&"127.0.0.1:5432:5432/tcp".to_string()), "{:?}", args);
    }

    #[test]
    fn mounts_are_omitted_when_the_operator_said_no_volumes() {
        let spec = DockerRuntimeSpec {
            mounts: vec![MigrateMount {
                kind: "volume".into(),
                source: "appdata".into(),
                target: "/data".into(),
                read_only: false,
            }],
            ..Default::default()
        };
        assert!(spec_to_create_args(&spec, true).contains(&"appdata:/data".to_string()));
        assert!(!spec_to_create_args(&spec, false).iter().any(|a| a == "-v"));
    }

    #[test]
    fn read_only_mounts_stay_read_only() {
        let spec = DockerRuntimeSpec {
            mounts: vec![MigrateMount {
                kind: "bind".into(),
                source: "/srv/conf".into(),
                target: "/etc/app".into(),
                read_only: true,
            }],
            ..Default::default()
        };
        assert!(spec_to_create_args(&spec, true).contains(&"/srv/conf:/etc/app:ro".to_string()));
    }

    #[test]
    fn copyable_mounts_includes_bind_mounts() {
        // This test previously asserted the OPPOSITE, and that assumption is
        // what left RutgerDiehard unable to move a container whose entire state
        // lived in bind mounts under another volume's _data (2026-08-06). Both
        // kinds carry data we can move.
        let spec = DockerRuntimeSpec {
            mounts: vec![
                MigrateMount { kind: "volume".into(), source: "appdata".into(), target: "/data".into(), read_only: false },
                MigrateMount { kind: "bind".into(), source: "/srv/conf".into(), target: "/etc/app".into(), read_only: true },
            ],
            ..Default::default()
        };
        let srcs: Vec<&str> = spec.copyable_mounts().iter().map(|m| m.source.as_str()).collect();
        assert_eq!(srcs, vec!["appdata", "/srv/conf"]);
    }

    #[test]
    fn a_mount_with_no_source_is_not_copyable() {
        // tmpfs and anonymous mounts have nothing to move; including them would
        // produce a confusing "was not copied" warning for something that never
        // had data.
        let spec = DockerRuntimeSpec {
            mounts: vec![
                MigrateMount { kind: "bind".into(), source: "".into(), target: "/x".into(), read_only: false },
                MigrateMount { kind: "tmpfs".into(), source: "".into(), target: "/tmp".into(), read_only: false },
            ],
            ..Default::default()
        };
        assert!(spec.copyable_mounts().is_empty());
    }

    #[test]
    fn restart_policy_and_limits_render() {
        let spec = DockerRuntimeSpec {
            restart_policy: "unless-stopped".into(),
            memory_bytes: 536_870_912,
            nano_cpus: 1_500_000_000,
            ..Default::default()
        };
        let args = spec_to_create_args(&spec, true);
        assert!(args.windows(2).any(|w| w[0] == "--restart" && w[1] == "unless-stopped"), "{:?}", args);
        assert!(args.windows(2).any(|w| w[0] == "--memory" && w[1] == "536870912"), "{:?}", args);
        // NanoCpus is CPUs x 1e9 — 1.5 CPUs, not 1500000000 of them.
        assert!(args.windows(2).any(|w| w[0] == "--cpus" && w[1] == "1.500"), "{:?}", args);
    }

    #[test]
    fn an_empty_spec_produces_no_flags() {
        // A container with nothing special must not gain stray arguments.
        assert!(spec_to_create_args(&DockerRuntimeSpec::default(), true).is_empty());
    }

    #[test]
    fn origin_labels_are_emitted_when_recorded() {
        // The whole point of the labels: the destination's update checker must
        // be able to see through the wolfstack-migrate snapshot name to the
        // real registry image (RutgerDiehard, 2026-08-07).
        let spec = DockerRuntimeSpec {
            origin_image: Some("lscr.io/linuxserver/speedtest-tracker:latest".into()),
            origin_digest: Some("sha256:abc123".into()),
            ..Default::default()
        };
        let args = spec_to_create_args(&spec, true);
        assert!(args.windows(2).any(|w| w[0] == "--label"
            && w[1] == "wolfstack.origin-image=lscr.io/linuxserver/speedtest-tracker:latest"), "{:?}", args);
        assert!(args.windows(2).any(|w| w[0] == "--label"
            && w[1] == "wolfstack.origin-digest=sha256:abc123"), "{:?}", args);
        // Digest may legitimately be unknown (locally-built origin) — the
        // image label must still be emitted alone, and an empty string must
        // not produce a dangling `--label k=`.
        let spec2 = DockerRuntimeSpec {
            origin_image: Some("myapp:dev".into()),
            origin_digest: Some(String::new()),
            ..Default::default()
        };
        let args2 = spec_to_create_args(&spec2, true);
        assert!(args2.windows(2).any(|w| w[0] == "--label" && w[1] == "wolfstack.origin-image=myapp:dev"));
        assert!(!args2.iter().any(|a| a == "wolfstack.origin-digest="), "{:?}", args2);
    }

    #[test]
    fn pve_net0_carries_the_source_bridge_mac_and_static_ip() {
        // The Rutger case (2026-08-07): source on a VLAN bridge; the import
        // used to hard-code bridge=vmbr0 and silently drop the container on
        // the PVE management LAN.
        let cfg = "lxc.net.0.type = veth\n\
                   lxc.net.0.link = vmbr100\n\
                   lxc.net.0.hwaddr = BC:24:11:05:3E:E0\n\
                   lxc.net.0.name = eth0\n";
        let (net0, warn) = pve_net0_from_lxc_config(cfg, &|b| b == "vmbr100");
        assert_eq!(net0, "name=eth0,bridge=vmbr100,hwaddr=BC:24:11:05:3E:E0,ip=dhcp");
        assert!(warn.is_none());

        // Static IPv4 + gateway carried verbatim.
        let cfg_static = "lxc.net.0.link = vmbr100\n\
                          lxc.net.0.ipv4.address = 10.0.1.7/24\n\
                          lxc.net.0.ipv4.gateway = 10.0.1.1\n";
        let (net0s, _) = pve_net0_from_lxc_config(cfg_static, &|_| true);
        assert_eq!(net0s, "name=eth0,bridge=vmbr100,ip=10.0.1.7/24,gw=10.0.1.1");
    }

    #[test]
    fn pve_net0_missing_bridge_falls_back_with_a_loud_warning() {
        // pct create accepts any bridge name and the container just fails to
        // start later — so a missing bridge must fall back AND say so.
        let cfg = "lxc.net.0.link = vmbr4000\n";
        let (net0, warn) = pve_net0_from_lxc_config(cfg, &|_| false);
        assert!(net0.starts_with("name=eth0,bridge=vmbr0"));
        let w = warn.expect("must warn when the source bridge is absent");
        assert!(w.contains("vmbr4000"), "warning must name the missing bridge: {}", w);

        // lxcbr0 (LXC's private NAT bridge) is 'no specific network' — the
        // vmbr0 default is correct and silent.
        let (net0d, warnd) = pve_net0_from_lxc_config("lxc.net.0.link = lxcbr0\n", &|_| false);
        assert_eq!(net0d, "name=eth0,bridge=vmbr0,ip=dhcp");
        assert!(warnd.is_none());
        // No carried config at all (older source): same silent default.
        let (net0e, warne) = pve_net0_from_lxc_config("", &|_| false);
        assert_eq!(net0e, "name=eth0,bridge=vmbr0,ip=dhcp");
        assert!(warne.is_none());
    }

    #[test]
    fn lxc_config_limits_parse_memory_and_cores() {
        // 1 GiB memory.max → 1024 MB; ceil so a hair over doesn't shrink.
        assert_eq!(lxc_config_memory_mb("lxc.cgroup2.memory.max = 1073741824\n"), Some(1024));
        assert_eq!(lxc_config_memory_mb("lxc.cgroup2.memory.max = 1073741825\n"), Some(1025));
        assert_eq!(lxc_config_memory_mb("lxc.cgroup.memory.limit_in_bytes = 536870912\n"), Some(512));
        assert_eq!(lxc_config_memory_mb(""), None);
        assert_eq!(lxc_config_memory_mb("lxc.cgroup2.memory.max = max\n"), None);

        // cpu.max "150000 100000" = 1.5 CPUs → 2 whole cores.
        assert_eq!(lxc_config_cpu_cores("lxc.cgroup2.cpu.max = 150000 100000\n"), Some(2));
        // cpuset "0-3,8" = 5 CPUs.
        assert_eq!(lxc_config_cpu_cores("lxc.cgroup2.cpuset.cpus = 0-3,8\n"), Some(5));
        assert_eq!(lxc_config_cpu_cores(""), None);
    }

    #[test]
    fn migrated_snapshot_images_are_recognised_and_real_ones_are_not() {
        // Both generations of migrate tag, and nothing else.
        assert!(is_migrated_snapshot_image("wolfstack-migrate/speedtest:latest"));
        assert!(is_migrated_snapshot_image("wolfrun-migrate:speedtest"));
        assert!(!is_migrated_snapshot_image("lscr.io/linuxserver/speedtest-tracker:latest"));
        assert!(!is_migrated_snapshot_image("nginx"));
        // A registry image that merely CONTAINS the word must not match.
        assert!(!is_migrated_snapshot_image("myrepo/wolfstack-migrate:v1"));
    }
}

#[cfg(test)]
mod bind_restore_tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("wolfstack-bindtest-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn refuses_a_relative_path() {
        let e = docker_restore_bind("etc/app", "/nonexistent.tar").unwrap_err();
        assert!(e.contains("non-absolute"), "{}", e);
    }

    #[test]
    fn refuses_path_traversal() {
        let e = docker_restore_bind("/srv/../etc/shadow", "/nonexistent.tar").unwrap_err();
        assert!(e.contains("traversing"), "{}", e);
    }

    #[test]
    fn refuses_to_unpack_over_a_non_empty_directory() {
        // The guard that matters: unpacking over live data to "help" is how a
        // migration destroys the thing it was copying.
        let d = tmpdir("nonempty");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("keep-me.conf"), b"important").unwrap();
        let e = docker_restore_bind(&d.to_string_lossy(), "/nonexistent.tar").unwrap_err();
        assert!(e.contains("not empty"), "{}", e);
        // and it really is untouched
        assert_eq!(std::fs::read(d.join("keep-me.conf")).unwrap(), b"important");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn refuses_to_overwrite_an_existing_file() {
        let d = tmpdir("file");
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("config.yml");
        std::fs::write(&f, b"live").unwrap();
        let e = docker_restore_bind(&f.to_string_lossy(), "/nonexistent.tar").unwrap_err();
        assert!(e.contains("already exists"), "{}", e);
        assert_eq!(std::fs::read(&f).unwrap(), b"live");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_empty_existing_directory_is_allowed_through() {
        // Re-declare-then-copy leaves an empty dir behind; that must not block
        // the copy, or the two options could never be combined.
        let d = tmpdir("empty");
        std::fs::create_dir_all(&d).unwrap();
        // Fails at the tar step (no archive), NOT at the guard — that is the
        // distinction being asserted.
        let e = docker_restore_bind(&d.to_string_lossy(), "/definitely-not-here.tar").unwrap_err();
        assert!(e.contains("tar"), "should have reached the tar step, got: {}", e);
        assert!(!e.contains("not empty"), "{}", e);
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod pve_task_lock_tests {
    use super::*;

    /// Real UPIDs taken from wolf1's `/var/log/pve/tasks/active` (2026-09-03).
    const VZDUMP_100: &str = "UPID:wolf1:0037A50B:94A55AE3:6A98D4B1:vzdump:100:root@pam:";
    const VNCSHELL: &str = "UPID:wolf1:002BE675:2B6FA99A:698B7E70:vncshell::root@pam:";

    #[test]
    fn decodes_a_real_upid() {
        let t = decode_upid(VZDUMP_100).expect("should decode");
        assert_eq!(t.pid, 0x0037A50B);
        assert_eq!(t.pstart, 0x94A55AE3);
        assert_eq!(t.vmid, "100");
    }

    #[test]
    fn node_wide_tasks_decode_with_an_empty_vmid() {
        let t = decode_upid(VNCSHELL).expect("should decode");
        assert_eq!(t.vmid, "");
    }

    #[test]
    fn rejects_upids_that_are_not_upids() {
        assert!(decode_upid("").is_none());
        assert!(decode_upid("not-a-upid").is_none());
        // Missing the trailing colon, so only 8 parts.
        assert!(decode_upid("UPID:wolf1:0037A50B:94A55AE3:6A98D4B1:vzdump:100:root@pam").is_none());
        // pid is not hex.
        assert!(decode_upid("UPID:wolf1:zzzzzzzz:94A55AE3:6A98D4B1:vzdump:100:root@pam:").is_none());
    }

    /// A line with an endtime is a FINISHED task and must never keep a lock
    /// alive; one without an endtime is still open. Both shapes are taken
    /// verbatim from wolf1's index.
    #[test]
    fn only_lines_without_an_endtime_count_as_open() {
        let active = format!(
            "{} 1 6A9783A4 OK\n{} 0\n",
            VZDUMP_100, VZDUMP_100
        );
        let open = open_tasks_for_guest(&active, "100");
        assert_eq!(open.len(), 1, "the finished line must be ignored");
        assert_eq!(open[0].pid, 0x0037A50B);
    }

    #[test]
    fn open_tasks_are_matched_by_guest() {
        let active = format!("{} 0\n{} 0\n", VZDUMP_100, VNCSHELL);
        assert_eq!(open_tasks_for_guest(&active, "100").len(), 1);
        assert!(open_tasks_for_guest(&active, "103").is_empty());
        // The node-wide vncshell task has an empty vmid and must not be
        // mistaken for a task on a container.
        assert_eq!(open_tasks_for_guest(&active, "").len(), 1);
    }

    #[test]
    fn garbage_lines_are_skipped_not_fatal() {
        let active = format!("\n junk \n{} 0\nUPID:broken 0\n", VZDUMP_100);
        assert_eq!(open_tasks_for_guest(&active, "100").len(), 1);
    }

    /// `pid_started_at` must read field 22 of /proc/<pid>/stat. Checked against
    /// this very process: the value is non-zero, stable across reads, and a
    /// pid that cannot exist yields None.
    #[test]
    fn reads_our_own_start_time() {
        let me = std::process::id();
        let first = pid_started_at(me).expect("own /proc/<pid>/stat must be readable");
        assert!(first > 0, "start time should be non-zero, got {}", first);
        assert_eq!(Some(first), pid_started_at(me), "must be stable across reads");
        // /proc/sys/kernel/pid_max is at most 2^22 on Linux, so this pid
        // cannot be allocated and has no /proc entry.
        assert_eq!(pid_started_at(u32::MAX), None);
    }

    /// The comm field can contain spaces and parentheses; the parse must key
    /// off the LAST ')' or every field after it shifts.
    #[test]
    fn start_time_survives_a_hostile_comm() {
        // Field 1 pid, 2 comm, 3 state, then fields 4..=21, then 22 = 4242.
        let fields: Vec<String> = (4..=21).map(|n| n.to_string()).collect();
        let stat = format!("7 ((weird) proc name) S {} 4242 rest\n", fields.join(" "));
        let dir = std::env::temp_dir().join(format!("wolfstack-stat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("stat");
        std::fs::write(&f, &stat).unwrap();
        // Mirror the parse against the file we just wrote.
        let raw = std::fs::read_to_string(&f).unwrap();
        let rest = &raw[raw.rfind(')').unwrap() + 1..];
        let got: u64 = rest.split_whitespace().nth(19).unwrap().parse().unwrap();
        assert_eq!(got, 4242, "field 22 must be found after the LAST ')'");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_tables_match_pve_and_stay_a_subset() {
        // PVE::LXC::Config.pm:514-518.
        assert_eq!(PVE_LXC_LOCKS.len(), 10);
        for l in ["backup", "create", "destroyed", "disk", "fstrim", "migrate",
                  "mounted", "rollback", "snapshot", "snapshot-delete"] {
            assert!(PVE_LXC_LOCKS.contains(&l), "PVE lock '{}' missing", l);
        }
        // Anything we auto-release must be a lock PVE can actually set.
        for l in RECLAIMABLE_LXC_LOCKS {
            assert!(PVE_LXC_LOCKS.contains(l), "'{}' is not a PVE lock", l);
        }
        // A half-created or migrating guest is never auto-unlocked.
        for l in ["create", "destroyed", "migrate"] {
            assert!(!RECLAIMABLE_LXC_LOCKS.contains(&l), "'{}' must not be reclaimed", l);
        }
    }
}
