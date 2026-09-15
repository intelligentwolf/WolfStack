// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Reverse-proxy entries — part of WolfRouter, not a separate product.
//!
//! ## What this actually does
//!
//! This is **not** an HTTP reverse proxy. Each `ProxyEntry` maps a
//! public IP (auto-resolved from the configured domain name, or pinned
//! manually) to a single backend — a VM, a container, or any IP — and
//! forwards *every* port of *every* protocol to it. Traffic hits the
//! public IP on this host, iptables DNAT rewrites the destination to
//! the backend, and SNAT ensures the reply comes back through this
//! node. HTTP, HTTPS, SSH, SMTP, anything.
//!
//! Implementation is plain iptables — no userspace proxy involved.
//! The forwarding primitive is the same one the existing IP Mapping
//! feature uses (see `src/networking/mod.rs::apply_mapping_rules`),
//! but without a port filter, so it catches every TCP + UDP stream.
//!
//! ## DNS resolution
//!
//! If the operator configures a domain with auto-resolve, apply_for_node
//! does a single A-record lookup at write time and caches the result in
//! `resolved_public_ip`. It does NOT re-resolve on every packet. If the
//! DNS record moves, re-save the entry (or click "Re-resolve" in the
//! UI, TODO). Using the cached IP means nginx-style "follow the DNS"
//! surprises are impossible — what the operator saved is what runs.
//!
//! ## Limits
//!
//! - One domain per public IP. You can't share a public IP across
//!   multiple domain forwards — there's no port/protocol field in the
//!   packet saying which domain it's for once you're past the TLS
//!   handshake, so the kernel would have to guess. Use the port-
//!   specific IP Mapping feature if you need to multiplex.
//! - This host must be the one receiving the domain's traffic —
//!   iptables on other nodes doesn't see packets destined for a
//!   public IP they don't hold.

use serde::{Deserialize, Serialize};
use std::process::Command;

/// A single domain-forwarding entry. Persisted as part of RouterConfig
/// so edits travel with the rest of the router config for backup/restore.
///
/// A single entry can target one backend (simple domain → IP) or many
/// backends with a load-balancing policy — the iptables `statistic`
/// module handles the distribution, matching what WolfRun VIPs already
/// do. See `apply_entry` for the generator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyEntry {
    pub id: String,
    /// Public hostname that resolves to this node's public IP. Used for
    /// display and, if `resolved_public_ip` is empty, as the DNS lookup
    /// seed at apply time.
    pub domain: String,
    /// Which cluster node hosts the public IP that receives this domain's
    /// traffic. apply_for_node only touches entries bound to the local
    /// node — iptables on other nodes doesn't see these packets.
    pub node_id: String,
    /// One or more backends to distribute traffic to. If exactly one,
    /// every packet goes there (no `statistic` match). If more than one,
    /// the `lb_policy` field picks the distribution scheme.
    #[serde(default)]
    pub backends: Vec<ProxyBackend>,
    /// Load-balancing policy when `backends.len() > 1`:
    /// - `round_robin`  — weighted round-robin via iptables
    ///   `statistic --mode nth`. Each backend is emitted `weight` times
    ///   in the rule chain, giving exact weighted distribution.
    /// - `ip_hash`      — weighted random via iptables
    ///   `statistic --mode random --probability`. Conntrack pins each
    ///   connection to its first-picked backend, so stickiness holds
    ///   for the lifetime of a TCP stream but not across reconnects.
    ///   The UI calls this "Random (per-connection)" to stop operators
    ///   mistaking it for real source-IP stickiness.
    /// - `source_hash`  — true source-IP stickiness via **nftables**
    ///   `ip saddr jhash N mod <total_weight>`. Generator lives in
    ///   `apply_source_hash_nft`. Requires the `nft` binary — we fall
    ///   back to `ip_hash` semantics with a warning if it isn't there.
    #[serde(default = "default_lb_policy")]
    pub lb_policy: String,
    /// Public IP on this node that receives packets for `domain`. Set
    /// manually or resolved via DNS at save/apply time. Kept explicit
    /// so iptables rules don't silently shift when DNS flaps.
    #[serde(default)]
    pub resolved_public_ip: String,
    /// Disable without deleting — lets the operator toggle a forward
    /// off when debugging without losing the config.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Free-text label for the operator — shown in the UI.
    #[serde(default)]
    pub description: Option<String>,
    /// If true, install iptables/nftables rules on **every** online
    /// WolfStack node — not just `node_id`. Lets a peer keep serving
    /// traffic when the primary goes down (assuming the public IP
    /// migrates via DNS, VIP, or operator action). When false, only
    /// the owning node installs rules — the existing default that
    /// matches the pre-failover behavior.
    #[serde(default)]
    pub failover: bool,
}

fn default_lb_policy() -> String { "round_robin".into() }

/// Where the proxy forwards traffic. The `Vm` / `Container` variants
/// carry a resolved host at save time so apply doesn't need to re-query
/// the VM/container manager every time rules are rebuilt.
///
/// `weight` governs per-backend distribution under every lb_policy.
/// Weight 0 is treated as 1 (backends with 0 weight would never be
/// picked — we silently coerce rather than drop them so the operator's
/// list matches what's installed).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProxyBackend {
    /// Free-form IP or hostname.
    Custom {
        host: String,
        #[serde(default = "default_weight")]
        weight: u32,
    },
    /// VM picked from the cluster.
    Vm {
        vm_id: String,
        vm_name: String,
        /// Which VM manager this came from — libvirt (WolfStack-native),
        /// proxmox, etc. Used for UI labeling and grouping.
        vm_type: String,
        host: String,
        #[serde(default = "default_weight")]
        weight: u32,
    },
    /// Docker or LXC container.
    Container {
        container_id: String,
        container_name: String,
        /// "docker" or "lxc".
        container_type: String,
        host: String,
        #[serde(default = "default_weight")]
        weight: u32,
    },
}

fn default_weight() -> u32 { 1 }

impl ProxyBackend {
    pub fn host(&self) -> &str {
        match self {
            ProxyBackend::Custom { host, .. } => host,
            ProxyBackend::Vm { host, .. } => host,
            ProxyBackend::Container { host, .. } => host,
        }
    }
    /// Weight for distribution, normalized so zero never means "never".
    pub fn weight(&self) -> u32 {
        let w = match self {
            ProxyBackend::Custom { weight, .. } => *weight,
            ProxyBackend::Vm { weight, .. } => *weight,
            ProxyBackend::Container { weight, .. } => *weight,
        };
        if w == 0 { 1 } else { w }
    }
}

fn default_true() -> bool { true }

/// Resolve a domain to its first IPv4 via the system resolver. We
/// deliberately use getaddrinfo (via std::net::ToSocketAddrs with a
/// dummy port) so /etc/hosts, systemd-resolved, and nsswitch all get
/// a vote. Returns None on NXDOMAIN or no IPv4 answer.
fn resolve_domain_v4(domain: &str) -> Option<String> {
    use std::net::ToSocketAddrs;
    let target = format!("{}:80", domain);
    target.to_socket_addrs().ok()?.find_map(|sa| match sa {
        std::net::SocketAddr::V4(v4) => Some(v4.ip().to_string()),
        _ => None,
    })
}

/// Ensure the entry has a public IP resolved. If the operator pinned
/// one, keep it; otherwise DNS-resolve the domain once. Returns the
/// effective public IP, or an error describing why resolution failed.
pub fn resolve_entry_public_ip(entry: &mut ProxyEntry) -> Result<String, String> {
    if !entry.resolved_public_ip.trim().is_empty() {
        return Ok(entry.resolved_public_ip.trim().to_string());
    }
    match resolve_domain_v4(&entry.domain) {
        Some(ip) => {
            entry.resolved_public_ip = ip.clone();
            Ok(ip)
        }
        None => Err(format!(
            "Could not resolve '{}' to an IPv4 address. \
             Configure DNS first or pin a public IP in the form.",
            entry.domain
        )),
    }
}

/// iptables comment tag used on every rule this module writes. Lets us
/// find and remove stale rules across restarts without tracking them
/// externally. Same pattern as the IP-mapping comment tag in
/// src/networking/mod.rs.
fn comment_tag(id: &str) -> String { format!("wolfstack-proxy-{}", id) }

/// Delete every iptables rule carrying a given comment, across the
/// chains/tables we actually write to. Best-effort — errors are
/// swallowed so a missing rule doesn't prevent the next apply.
fn purge_by_comment(comment: &str) {
    for (table, chain) in &[
        ("nat", "PREROUTING"),
        ("nat", "OUTPUT"),
        ("nat", "POSTROUTING"),
        ("filter", "FORWARD"),
    ] {
        loop {
            let out = Command::new("iptables")
                .args(["-t", table, "-L", chain, "--line-numbers", "-n"])
                .output();
            let text = match out {
                Ok(ref o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
                _ => break,
            };
            let mut found = None;
            for line in text.lines().rev() {
                if line.contains(comment)
                    && let Some(n) = line.split_whitespace().next().and_then(|x| x.parse::<u32>().ok()) {
                        found = Some(n);
                        break;
                    }
            }
            match found {
                Some(n) => {
                    let _ = Command::new("iptables")
                        .args(["-t", table, "-D", chain, &n.to_string()])
                        .output();
                }
                None => break,
            }
        }
    }
}

/// nftables table + chain names the source_hash policy writes into.
/// Kept in their own table so `nft flush table` only affects our rules
/// — it never touches anything another admin or tool installed.
const NFT_TABLE: &str = "wolfstack_proxy";
fn nft_chain(id: &str) -> String {
    // nftables chain names can't contain '-', so translate the id into
    // underscores. `id` is always an alphanumeric gen_id, so this is a
    // straight char replacement.
    format!("e_{}", id.replace('-', "_"))
}

/// True if `nft` is on PATH. Used to gate the source_hash policy —
/// without it we fall back to ip_hash with a warning.
fn nft_available() -> bool {
    Command::new("nft").arg("--version").output()
        .map(|o| o.status.success()).unwrap_or(false)
}

/// Remove any existing nftables chain for this entry id. Idempotent —
/// runs `nft delete chain ...` and discards errors (chain may not yet
/// exist). Table is created lazily in apply_source_hash_nft.
fn purge_nft_for_entry(id: &str) {
    if !nft_available() { return; }
    let chain = nft_chain(id);
    // Flush first to drop any jumps from PREROUTING/OUTPUT into this
    // chain, then delete. If the chain doesn't exist yet, both fail
    // silently — which is fine.
    let _ = Command::new("nft")
        .args(["flush", "chain", "ip", NFT_TABLE, &chain])
        .output();
    let _ = Command::new("nft")
        .args(["delete", "chain", "ip", NFT_TABLE, &chain])
        .output();
    // Also remove any jump rules in our root chains that reference this
    // per-entry chain (otherwise they'd dangle). We re-derive the rule
    // from the chain name rather than tracking handles.
    for root in &["wolfstack_pre", "wolfstack_out"] {
        // nft -a lists rule handles; we match jumps into our chain and
        // delete by handle. Errors swallowed.
        let out = Command::new("nft")
            .args(["-a", "list", "chain", "ip", NFT_TABLE, root])
            .output();
        if let Ok(o) = out
            && o.status.success() {
                let text = String::from_utf8_lossy(&o.stdout);
                let needle = format!("jump {}", chain);
                for line in text.lines() {
                    if !line.contains(&needle) { continue; }
                    // Extract "handle N" from the end of the line.
                    if let Some(idx) = line.rfind("handle ") {
                        let h = line[idx + 7..].trim().trim_end_matches(|c: char| !c.is_ascii_digit());
                        if !h.is_empty() {
                            let _ = Command::new("nft")
                                .args(["delete", "rule", "ip", NFT_TABLE, root, "handle", h])
                                .output();
                        }
                    }
                }
            }
    }
}

/// Ensure the nftables scaffolding exists: table + two root chains
/// hooked into prerouting/output at priority -100 so we run before the
/// built-in iptables DNAT (priority -100 is the same as nat type
/// prerouting, but nftables flat-priorities means whichever loads
/// first wins — for our hash-first semantics we use priority -110,
/// higher priority than iptables nat).
fn ensure_nft_scaffold() -> Result<(), String> {
    // `nft add table` and `nft add chain` are idempotent — adding an
    // existing object returns success on recent nft versions. If the
    // binary is older and errors on re-add, we don't care: subsequent
    // rule adds will still succeed.
    let _ = Command::new("nft")
        .args(["add", "table", "ip", NFT_TABLE])
        .output();
    for (root, hook) in [("wolfstack_pre", "prerouting"), ("wolfstack_out", "output")] {
        let spec = format!(
            "chain {} {{ type nat hook {} priority -110; }}",
            root, hook
        );
        let out = Command::new("nft")
            .args(["add", "chain", "ip", NFT_TABLE, &spec])
            .output()
            .map_err(|e| format!("nft add chain {}: {}", root, e))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            // "File exists" is the idempotent case; anything else is real.
            if !err.contains("File exists") && !err.contains("already exists") {
                return Err(format!("nft add chain {}: {}", root, err));
            }
        }
    }
    Ok(())
}

/// Emit nftables rules for the source_hash policy: true source-IP
/// stickiness via `jhash`. A client always lands on the same backend
/// (for the same backend set — reordering the list reshuffles the map,
/// which is inherent to hash-based LB).
///
/// Structure per entry:
///   chain e_<id> {
///     ip saddr jhash dport mod <total_weight> vmap {
///       0: dnat to <b0>, 1: dnat to <b0>, ..., k: dnat to <bk>, ...
///     }
///   }
///   wolfstack_pre { ip daddr <public_ip> jump e_<id> }
///   wolfstack_out { ip daddr <public_ip> jump e_<id> }
///
/// Weights are honored by assigning `weight` consecutive hash slots to
/// the same backend — same trick we use in the iptables round-robin
/// path.
fn apply_source_hash_nft(entry: &ProxyEntry, public_ip: &str, backends: &[(String, u32)])
    -> Result<(), String>
{
    ensure_nft_scaffold()?;
    let chain = nft_chain(&entry.id);
    let total: u32 = backends.iter().map(|(_, w)| *w).sum();
    if total == 0 {
        return Err("total backend weight is 0".into());
    }

    // Build the vmap contents: plain "slot : ip" pairs. nftables'
    // `dnat to ... map { ... }` form takes the DNAT destination (a
    // bare IP) as the map *value* — the outer `dnat to` keyword is
    // NOT repeated per entry.
    let mut entries: Vec<String> = Vec::with_capacity(total as usize);
    let mut slot: u32 = 0;
    for (host, weight) in backends {
        for _ in 0..*weight {
            entries.push(format!("{} : {}", slot, host));
            slot += 1;
        }
    }
    let vmap = entries.join(", ");

    // Create the per-entry chain (regular chain, not hooked — we jump
    // into it from wolfstack_pre/wolfstack_out).
    let add_chain = format!("chain {} {{ }}", chain);
    let out = Command::new("nft")
        .args(["add", "chain", "ip", NFT_TABLE, &add_chain])
        .output()
        .map_err(|e| format!("nft add chain {}: {}", chain, e))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if !err.contains("File exists") && !err.contains("already exists") {
            return Err(format!("nft add chain {}: {}", chain, err));
        }
    }

    // Stateless source-IP-hash DNAT. `jhash ip saddr mod N` produces a
    // slot in [0, N-1]; the vmap turns that slot into a backend IP.
    // 0xdeadbeef is a fixed seed so two nodes running the same config
    // send a given source IP to the same backend — matters when the
    // public IP migrates between cluster peers.
    let hash_rule = format!(
        "add rule ip {} {} ip daddr {} meta l4proto {{ tcp, udp }} \
         dnat to jhash ip saddr mod {} seed 0xdeadbeef map {{ {} }}",
        NFT_TABLE, chain, public_ip, total, vmap
    );
    let out = Command::new("nft").args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(hash_rule.as_bytes())?;
            }
            child.wait_with_output()
        })
        .map_err(|e| format!("nft add rule: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "nft add rule failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // Hook into our root chains — one jump per hook, filtered to this
    // entry's public IP so other entries aren't affected.
    for root in &["wolfstack_pre", "wolfstack_out"] {
        let jump = format!(
            "add rule ip {} {} ip daddr {} jump {}",
            NFT_TABLE, root, public_ip, chain
        );
        let out = Command::new("nft").args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    stdin.write_all(jump.as_bytes())?;
                }
                child.wait_with_output()
            })
            .map_err(|e| format!("nft add jump in {}: {}", root, e))?;
        if !out.status.success() {
            return Err(format!(
                "nft add jump in {} failed: {}",
                root, String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    Ok(())
}

/// Detect this host's first routable IPv4 — used as the SNAT source
/// when the backend lives on a private network the original client
/// can't reach. Falls back to the public_ip itself if nothing obvious
/// is found (works fine when backend is on the same LAN).
fn detect_snat_source(public_ip: &str) -> String {
    // Try `ip route get <backend>` equivalent via `ip -4 route get public_ip`.
    // We just need *some* source IP on this host that shares a route with
    // the backend — the kernel picks this anyway, but asking explicitly
    // lets us bake it into the SNAT rule so conntrack has a fixed answer.
    let out = Command::new("ip").args(["-4", "route", "get", public_ip]).output();
    if let Ok(o) = out
        && o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout);
            // Expected format: "1.2.3.4 dev eth0 src 1.2.3.5 uid 0"
            if let Some(idx) = s.find(" src ") {
                let rest = &s[idx + 5..];
                if let Some(end) = rest.find(char::is_whitespace) {
                    return rest[..end].to_string();
                }
            }
        }
    public_ip.to_string()
}

fn run_iptables(args: &[&str]) -> Result<(), String> {
    let out = Command::new("iptables").args(args).output()
        .map_err(|e| format!("iptables not available: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "iptables {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Write iptables/nftables rules for one entry across its backends.
/// Captures TCP+UDP on every port — no --dport, no -p filter — so
/// every service the backend listens on is reachable.
///
/// Policy dispatch:
/// - `round_robin`  — iptables `statistic --mode nth`, each backend
///   emitted once per weight unit so the distribution is exactly
///   weighted over `total_weight` consecutive packets.
/// - `ip_hash`      — iptables `statistic --mode random --probability`
///   cascade. rule i has probability `w_i / remaining_weight_total`;
///   fall-through guarantees every packet lands somewhere.
/// - `source_hash`  — nftables `jhash ip saddr mod total_weight vmap`
///   for real source-IP stickiness. Falls back to `ip_hash` with a
///   warning if nft isn't installed.
///
/// Return-path SNAT + FORWARD-ACCEPT always use plain iptables —
/// they're policy-agnostic.
fn apply_entry(entry: &ProxyEntry, public_ip: &str) -> Result<(), String> {
    // Collect (host, weight) pairs, rejecting backends with empty hosts.
    let backends: Vec<(String, u32)> = entry.backends.iter()
        .map(|b| (b.host().trim().to_string(), b.weight()))
        .filter(|(h, _)| !h.is_empty())
        .collect();
    if backends.is_empty() {
        return Err(format!(
            "no valid backend IPs for '{}' — pick a running VM/container or enter an IP",
            entry.domain
        ));
    }
    let tag = comment_tag(&entry.id);

    // Dispatch source_hash to nftables *before* installing any iptables
    // DNAT — nft hooks at priority -110 so it runs first, and we don't
    // want iptables statistic rules also rewriting traffic in parallel.
    let mut effective_policy = entry.lb_policy.clone();
    if effective_policy == "source_hash" {
        if nft_available() {
            apply_source_hash_nft(entry, public_ip, &backends)?;
            // SNAT + FORWARD-ACCEPT still needed so replies come back
            // through this host and the kernel forwards them.
            install_return_path(&backends, &tag)?;
            return Ok(());
        } else {
            // Graceful fallback: keep going with ip_hash semantics and
            // surface the missing-tool problem as a warning upstream.
            effective_policy = "ip_hash".into();
            tracing::warn!(
                "proxy '{}' requested source_hash but 'nft' is not installed — \
                 falling back to per-connection random. Install nftables for \
                 true source-IP stickiness.",
                entry.id
            );
        }
    }

    // round_robin: expand by weight. backends A,B,C with weights 3,1,2
    // become A,A,A,B,C,C. `statistic --mode nth --every total --packet k`
    // then picks exactly one per rule, giving perfect weighted RR.
    //
    // ip_hash: probability cascade. remaining_weight shrinks per-backend,
    // rule i probability = w_i / remaining_weight.
    let total_weight: u32 = backends.iter().map(|(_, w)| *w).sum();

    for chain in &["PREROUTING", "OUTPUT"] {
        match effective_policy.as_str() {
            "round_robin" => {
                let mut packet_idx: u32 = 0;
                for (host, weight) in &backends {
                    for _ in 0..*weight {
                        let mut args: Vec<String> = vec![
                            "-t".into(), "nat".into(), "-A".into(), (*chain).to_string(),
                            "-d".into(), public_ip.to_string(),
                        ];
                        if total_weight > 1 {
                            args.extend_from_slice(&[
                                "-m".into(), "statistic".into(),
                                "--mode".into(), "nth".into(),
                                "--every".into(), total_weight.to_string(),
                                "--packet".into(), packet_idx.to_string(),
                            ]);
                        }
                        args.extend_from_slice(&[
                            "-j".into(), "DNAT".into(),
                            "--to-destination".into(), host.clone(),
                            "-m".into(), "comment".into(),
                            "--comment".into(), tag.clone(),
                        ]);
                        run_iptables_vec(&args)?;
                        packet_idx += 1;
                    }
                }
            }
            _ => {
                // ip_hash (and anything we don't recognize — safest
                // default is probability cascade).
                let mut remaining = total_weight;
                for (i, (host, weight)) in backends.iter().enumerate() {
                    let mut args: Vec<String> = vec![
                        "-t".into(), "nat".into(), "-A".into(), (*chain).to_string(),
                        "-d".into(), public_ip.to_string(),
                    ];
                    // Last backend gets no probability match — it's the
                    // fall-through for anything the earlier rules didn't
                    // claim, which guarantees 100% delivery.
                    if i + 1 < backends.len() && remaining > *weight {
                        let prob = *weight as f64 / remaining as f64;
                        args.extend_from_slice(&[
                            "-m".into(), "statistic".into(),
                            "--mode".into(), "random".into(),
                            "--probability".into(), format!("{:.6}", prob),
                        ]);
                    }
                    args.extend_from_slice(&[
                        "-j".into(), "DNAT".into(),
                        "--to-destination".into(), host.clone(),
                        "-m".into(), "comment".into(),
                        "--comment".into(), tag.clone(),
                    ]);
                    run_iptables_vec(&args)?;
                    remaining = remaining.saturating_sub(*weight);
                }
            }
        }
    }

    install_return_path(&backends, &tag)?;
    Ok(())
}

/// SNAT + FORWARD-ACCEPT pair for each distinct backend. Shared between
/// the iptables policies and the nftables source_hash path — the return
/// path works the same regardless of how we DNAT'd going out.
fn install_return_path(backends: &[(String, u32)], tag: &str) -> Result<(), String> {
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (host, _) in backends {
        if !seen.insert(host.as_str()) { continue; }
        let snat_src = detect_snat_source(host);
        let snat_args: Vec<String> = vec![
            "-t".into(), "nat".into(), "-A".into(), "POSTROUTING".into(),
            "-d".into(), host.clone(),
            "-j".into(), "SNAT".into(),
            "--to-source".into(), snat_src,
            "-m".into(), "comment".into(),
            "--comment".into(), tag.to_string(),
        ];
        run_iptables_vec(&snat_args)?;

        let fwd_args: Vec<String> = vec![
            "-I".into(), "FORWARD".into(), "1".into(),
            "-d".into(), host.clone(),
            "-m".into(), "conntrack".into(),
            "--ctstate".into(), "DNAT".into(),
            "-j".into(), "ACCEPT".into(),
            "-m".into(), "comment".into(),
            "--comment".into(), tag.to_string(),
        ];
        run_iptables_vec(&fwd_args)?;
    }
    Ok(())
}

fn run_iptables_vec(args: &[String]) -> Result<(), String> {
    let str_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_iptables(&str_args)
}

/// Re-apply every enabled entry bound to this node. Idempotent — every
/// call first purges the rules it owns (matched by comment tag), then
/// rewrites them fresh. Called at startup and after every edit.
/// Returns per-entry warnings; empty vec = clean apply.
pub fn apply_for_node(proxies: &[ProxyEntry], self_node_id: &str) -> Vec<String> {
    let mut warnings = Vec::new();

    // Enable IP forwarding — should already be on if WolfStack is doing
    // any NAT, but cheap insurance.
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");

    for entry in proxies {
        // Always purge first (both iptables AND nftables), even for
        // disabled entries — an operator toggling `enabled=false`
        // expects the forward to go away regardless of which policy
        // installed the last set of rules.
        purge_by_comment(&comment_tag(entry.id.as_str()));
        purge_nft_for_entry(entry.id.as_str());

        if !entry.enabled { continue; }

        // Apply on this node if either (a) we're the declared owner,
        // or (b) the entry opts into cluster-wide failover — in which
        // case every WolfStack node installs the rules so any peer
        // that receives traffic (via DNS, VIP, or manual takeover)
        // can forward it to the backends.
        let owns = entry.node_id == self_node_id;
        let failover = entry.failover;
        if !owns && !failover { continue; }

        // Clone so we can write the resolved IP back without fighting
        // with the caller's borrow — the real persistence happens in
        // the API handler before calling us.
        let public_ip = if !entry.resolved_public_ip.trim().is_empty() {
            entry.resolved_public_ip.clone()
        } else {
            match resolve_domain_v4(&entry.domain) {
                Some(ip) => ip,
                None => {
                    warnings.push(format!(
                        "proxy '{}' ({}): DNS resolution failed — no forwards installed for this entry",
                        entry.id, entry.domain
                    ));
                    continue;
                }
            }
        };

        if let Err(e) = apply_entry(entry, &public_ip) {
            warnings.push(format!("proxy '{}' ({}): {}", entry.id, entry.domain, e));
        }
    }

    warnings
}

/// Remove all iptables AND nftables rules belonging to one entry id.
/// Called from the DELETE handler so stale rules don't linger between
/// the config write and the next apply, on every node — not just the
/// owner — so failover'd entries clean up everywhere.
pub fn remove_one(id: &str) {
    purge_by_comment(&comment_tag(id));
    purge_nft_for_entry(id);
}
