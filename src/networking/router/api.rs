// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd

//! REST endpoints for WolfRouter. Mounted under `/api/router/*`.
//!
//! Cluster model:
//!   • **Read endpoints** (topology, leases, rules, segments) aggregate
//!     from all cluster nodes. The master node fans out per-node queries
//!     via the existing cluster-secret RPC.
//!   • **Write endpoints** (create/update/delete rule or segment) persist
//!     to config on the owning node. If the edit targets a remote node,
//!     the master proxies the call via the existing `/api/nodes/{id}/proxy`
//!     machinery.

use super::*;
use actix_web::{web, HttpResponse, HttpRequest};
use serde::Deserialize;
use crate::node_identity::PeerAuth;

type S = web::Data<crate::api::AppState>;

/// Try to resolve a domain/hostname to its first IPv4 address.
/// Falls back to returning the input unchanged if resolution fails (assumes it's already an IP).
/// Uses the system resolver (/etc/hosts, systemd-resolved, nsswitch, etc).
/// Return the address as-is. For HTTPS connections (most common),
/// we must NOT resolve domain names to IPs because TLS certificate
/// verification requires the hostname. For nodes configured as
/// "node1.example.com", resolving to IP would cause the TLS handshake
/// to fail because the certificate is issued for the domain, not the IP.
///
/// Domains are DNS-resolvable by reqwest and will work for both
/// HTTP and HTTPS. IPs work for both. This is the correct, safe approach
/// that supports both domain-based and IP-based node configurations.
fn resolve_node_address(address: &str) -> String {
    address.to_string()
}

/// Guard helper — every WolfRouter endpoint requires either a logged-in
/// session cookie OR a valid cluster secret header. Without this, any
/// HTTP client could spray firewall rules or lock users out.
macro_rules! auth_or_return {
    ($req:expr, $state:expr) => {
        if let Err(resp) = crate::api::require_auth(&$req, &$state) { return resp; }
    };
}

/// Shared HTTP client for every router-level cluster RPC. Same pattern
/// as src/wolfrun/mod.rs (fixed in v19.8.1) and src/statuspage/mod.rs:
/// a Client owns a keep-alive pool + background worker, so constructing
/// one per call leaks pools on drop. Individual call sites pick their
/// own total timeout via `RequestBuilder::timeout` because the three
/// call sites (replicate 10s / topology fan-out 5s / proxy read 30s)
/// all want different deadlines. `connect_timeout` is not settable per
/// request, so we set it here to the shortest sensible value (3s) —
/// matches what `proxy_router_get_to_node` used before consolidation,
/// and replicate/topology both benefit from failing fast on dead peers
/// rather than burning their full budget on a TCP handshake that won't
/// complete.
static ROUTER_RPC_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        crate::api::ipv4_only_client_builder()
            .connect_timeout(std::time::Duration::from_secs(3))
            .danger_accept_invalid_certs(true)
            .pool_idle_timeout(std::time::Duration::from_secs(15))
            .pool_max_idle_per_host(4)
            .tcp_keepalive(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });

/// Drain a response body before discarding it so the socket returns
/// to the keep-alive pool. Non-success branches that only inspect
/// `.status()` would otherwise leak.
async fn drain_response(resp: reqwest::Response) {
    let _ = resp.bytes().await;
}

/// Push the current RouterConfig to every other cluster node so the
/// firewall, LANs, and zone assignments stay in sync. Fired (in the
/// background, doesn't block the originating user request) after every
/// successful write. Each peer accepts via `/api/router/config-receive`
/// authenticated with the X-WolfStack-Secret header.
///
/// "Settings should replicate across the cluster when they are changed
/// so nothing breaks" — this is that.

// ─── Subnet-route overlap helpers (Codex P2, v20.11.2) ───
//
// Determine whether two subnet routes can both apply on the same node. A
// route applies on node N iff its node_id is None (cluster-wide) or matches
// N. Two routes overlap iff their CIDRs match AND both apply on at least
// one shared node — that's exactly when:
//   • either route is cluster-wide (node_id is None), OR
//   • both pin to the same specific node.
//
// Disabled routes don't reach the kernel, so they can't conflict with
// anything in practice. We still skip them here so users can stash
// disabled "template" routes without false positives (Codex P2, v20.11.2).
fn routes_can_overlap(a: &SubnetRoute, b: &SubnetRoute) -> bool {
    if !a.enabled || !b.enabled { return false; }
    if a.subnet_cidr != b.subnet_cidr { return false; }
    a.node_id.is_none() || b.node_id.is_none() || a.node_id == b.node_id
}

fn scope_label(node_id: &Option<String>) -> String {
    match node_id {
        Some(id) => format!("node '{}'", id),
        None => "cluster-wide".to_string(),
    }
}

pub(crate) fn replicate_config_to_cluster(state: S) {
    // The clone of the config and nodes happens INSIDE the spawned task,
    // by which time the caller has returned and any write lock from the
    // handler has been dropped. Calling this with the lock still held
    // would deadlock — so the indirection is intentional.
    tokio::spawn(async move {
        let cfg = state.router.config.read().unwrap().clone();
        let nodes = state.cluster.get_all_nodes();
        let secret = state.cluster_secret.clone();
        let self_id = crate::agent::self_node_id();
        let body = match serde_json::to_string(&cfg) {
            Ok(b) => b,
            Err(e) => { tracing::warn!("router replicate: serialize failed: {}", e); return; }
        };
        // Process-wide pool — see ROUTER_RPC_CLIENT. Timeout is set
        // per request so this shared client can serve every call site
        // with their own deadline.
        let client = &*ROUTER_RPC_CLIENT;
        for node in nodes {
            // Skip ourselves, offline nodes, and non-WolfStack nodes
            // (Proxmox-only members can't host WolfRouter).
            if node.is_self || node.id == self_id { continue; }
            if !node.online { continue; }
            if node.node_type != "wolfstack" { continue; }
            let host = resolve_node_address(&node.address);
            // v23.12: canonical HTTPS-first chain via build_node_urls.
            // The pre-v23.12 chain led with http://addr:port+1 because
            // edge firewalls often whitelisted only 8554 between cluster
            // nodes; with the second listener gone for CA-signed-cert
            // peers, that approach silently dropped them, so we now
            // lead with HTTPS on the main port (cert bypass enabled).
            // Operators who rely on a firewall-isolated 8554 channel
            // either run self-signed (and still have it) or should
            // open 8553 between cluster nodes.
            let urls = crate::api::build_node_urls(&host, node.port, "/api/router/config-receive");
            let mut replicated = false;
            let mut last_err = String::new();
            for url in &urls {
                match client.post(url)
                    .peer_auth(&secret)
                    .header("Content-Type", "application/json")
                    .timeout(std::time::Duration::from_secs(10))
                    .body(body.clone())
                    .send().await
                {
                    Ok(r) if r.status().is_success() => {
                        tracing::debug!("router config replicated to {} via {}", node.id, url);
                        drain_response(r).await;
                        replicated = true;
                        break;
                    }
                    Ok(r) => {
                        last_err = format!("HTTP {} from {}", r.status(), url);
                        drain_response(r).await;
                    }
                    Err(e) => {
                        last_err = format!("{} ({})", e, url);
                    }
                }
            }
            if !replicated {
                tracing::warn!("router config replicate to {} failed — last error: {}", node.id, last_err);
            }
        }
    });
}

/// Proxy a read (GET) of `/api/{path}?{query}` to the node that owns a
/// given resource. Used by per-node read endpoints (lease list, query
/// log tail) so the user doesn't see empty lists when viewing a LAN
/// whose dnsmasq lives on a different node.
///
/// Mirrors the URL fallback + auth style of the existing
/// `replicate_config_to_cluster` and top-level `node_proxy`: try HTTPS
/// on the main port first, then plaintext HTTP on the main port (legacy
/// pre-v23.11 peers). Every attempt carries the cluster secret header so
/// the peer authorises the request.
///
/// Returns an `HttpResponse` that passes through the upstream status
/// and body. If every URL fails, returns 502 Bad Gateway.
async fn proxy_router_get_to_node(
    state: S,
    node_id: &str,
    api_path: &str,
    query_string: &str,
) -> HttpResponse {
    let node = match state.cluster.get_node(node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().body(format!("node {} not found", node_id)),
    };
    if node.is_self {
        return HttpResponse::BadRequest().body("refusing to proxy to self");
    }

    let qs = if query_string.is_empty() { String::new() } else { format!("?{}", query_string) };
    let host = resolve_node_address(&node.address);
    let path = format!("/api/{}{}", api_path, qs);
    let urls = crate::api::build_node_urls(&host, node.port, &path);

    // Process-wide pool — see ROUTER_RPC_CLIENT. Per-request timeout
    // replaces what used to be a per-call builder (30s overall, 3s
    // connect). connect_timeout isn't supported at request level, so
    // we bundle it into the overall request timeout; for a read
    // proxy this is close enough and avoids leaking a pool every
    // call.
    let client = &*ROUTER_RPC_CLIENT;

    let mut last_err = String::new();
    for url in &urls {
        let res = client.get(url)
            .peer_auth(&state.cluster_secret)
            .timeout(std::time::Duration::from_secs(30))
            .send().await;
        match res {
            Ok(r) => {
                let status = r.status();
                let actix_status = actix_web::http::StatusCode::from_u16(status.as_u16())
                    .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY);
                // Preserve the upstream content type so /leases stays
                // application/json and /query-log stays JSON too.
                let content_type = r.headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/json")
                    .to_string();
                match r.bytes().await {
                    Ok(body) => {
                        return HttpResponse::build(actix_status)
                            .insert_header(("content-type", content_type))
                            .body(body);
                    }
                    Err(e) => { last_err = format!("read body: {}", e); continue; }
                }
            }
            Err(e) => { last_err = format!("{} → {}", url, e); continue; }
        }
    }
    HttpResponse::BadGateway()
        .body(format!("all upstream URLs failed, last error: {}", last_err))
}

/// Sibling of `proxy_router_get_to_node` for POST routes. Used by the
/// LAN Health one-click actions (`restart-dnsmasq`, `set-interface`)
/// when the target LAN is owned by a remote node — the operator
/// triggered the action from any cluster node, but the actual side
/// effect (`dhcp::start`, write to `/etc/wolfstack/router.json`) only
/// makes sense on the owner.
///
/// Same URL fallback ladder as the GET variant. Body is JSON-encoded.
async fn proxy_router_post_to_node(
    state: S,
    node_id: &str,
    api_path: &str,
    body: serde_json::Value,
) -> HttpResponse {
    let node = match state.cluster.get_node(node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().body(format!("node {} not found", node_id)),
    };
    if node.is_self {
        return HttpResponse::BadRequest().body("refusing to proxy to self");
    }
    let host = resolve_node_address(&node.address);
    let path = format!("/api/{}", api_path);
    let urls = crate::api::build_node_urls(&host, node.port, &path);
    let client = &*ROUTER_RPC_CLIENT;
    let mut last_err = String::new();
    for url in &urls {
        let res = client.post(url)
            .peer_auth(&state.cluster_secret)
            .json(&body)
            .timeout(std::time::Duration::from_secs(30))
            .send().await;
        match res {
            Ok(r) => {
                let status = r.status();
                let actix_status = actix_web::http::StatusCode::from_u16(status.as_u16())
                    .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY);
                let content_type = r.headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/json")
                    .to_string();
                match r.bytes().await {
                    Ok(body) => {
                        return HttpResponse::build(actix_status)
                            .insert_header(("content-type", content_type))
                            .body(body);
                    }
                    Err(e) => { last_err = format!("read body: {}", e); continue; }
                }
            }
            Err(e) => { last_err = format!("{} → {}", url, e); continue; }
        }
    }
    HttpResponse::BadGateway()
        .body(format!("all upstream URLs failed, last error: {}", last_err))
}

/// Minimal query-param encoder — only escapes the handful of bytes that
/// actually break a URL. Sufficient for passing through `?lines=N`
/// style values we control on both ends.
fn urlencoding_minimal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.as_bytes() {
        let c = *byte;
        if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.' || c == b'~' {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{:02X}", c));
        }
    }
    out
}

/// Receive a RouterConfig from another cluster node. Persists it,
/// re-applies firewall, restarts dnsmasq for any LANs hosted here.
/// Called by the master/originator after a local edit.
pub async fn config_receive(
    req: HttpRequest,
    state: S,
    body: web::Json<RouterConfig>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let new_cfg = body.into_inner();
    let self_id = crate::agent::self_node_id();
    // Capture the set of proxy IDs we had BEFORE overwriting so we can
    // clean up rules for entries that were deleted on the originating
    // node. Without this, a delete-on-node-1 would leave stale iptables
    // /nftables rules on every other peer until a manual restart.
    //
    // Same problem applies to subnet routes — we capture the old set and
    // diff it against the incoming one below.
    let (removed_proxy_ids, old_routes) = {
        let cur = state.router.config.read().unwrap();
        let new_ids: std::collections::HashSet<&str> =
            new_cfg.proxies.iter().map(|p| p.id.as_str()).collect();
        let removed = cur.proxies.iter()
            .filter(|p| !new_ids.contains(p.id.as_str()))
            .map(|p| p.id.clone())
            .collect::<Vec<_>>();
        let old_routes: Vec<crate::networking::router::SubnetRoute> = cur.subnet_routes.clone();
        (removed, old_routes)
    };
    {
        let mut cur = state.router.config.write().unwrap();
        *cur = new_cfg.clone();
        if let Err(e) = cur.save() {
            return HttpResponse::InternalServerError().body(format!("save: {}", e));
        }
    }
    // Apply firewall locally if auto_apply is on.
    if new_cfg.auto_apply {
        let ruleset = firewall::build_ruleset(&new_cfg, &self_id);
        if let Err(e) = firewall::apply(&ruleset, false) {
            tracing::warn!("router config-receive: firewall apply failed: {}", e);
        }
    }
    // Re-render dnsmasq for LANs hosted on this node. Stops orphaned
    // instances for LANs that were removed; starts/restarts current ones.
    dhcp::start_all_for_node(&new_cfg, &self_id);
    // Purge rules for entries that no longer exist in the config —
    // otherwise failover'd or previously-owned forwards keep running
    // here long after the originator deleted them.
    for id in &removed_proxy_ids {
        proxy::remove_one(id);
    }
    // Re-render reverse-proxy iptables/nftables rules. Each entry now
    // may opt into failover, in which case apply_for_node installs its
    // rules here too — so every peer stays in sync with the authoritative
    // config, not just the owner.
    let pwarn = proxy::apply_for_node(&new_cfg.proxies, &self_id);
    for w in &pwarn {
        tracing::warn!("router config-receive: proxy apply: {}", w);
    }

    // L7 HTTP proxies — render every multi-target proxy whose target
    // list includes this node. `apply_for_node` already filters by
    // target node_id, so this is a fanout-receiver call: one node
    // pushes the new config to peers, each peer renders only what
    // touches it.
    let hwarn = crate::networking::router::http_proxy::apply_for_node(&new_cfg.http_proxies, &self_id);
    for w in &hwarn {
        tracing::warn!("router config-receive: http_proxy apply: {}", w);
    }

    // Reconcile subnet routes against the kernel.
    //
    // Bug fix v20.11.2 (sponsor report): previously this handler applied
    // firewall + dnsmasq + proxies, but ignored cfg.subnet_routes entirely.
    // A route created on node A and replicated to node B was saved into
    // B's config but never made it onto B's kernel routing table. Result:
    // adding a route on a peer node had no effect until that peer was
    // restarted (which is when apply_startup walked the list).
    //
    // Strategy: diff old vs new for routes that target THIS node.
    //   • Removed / disabled / moved-elsewhere → remove from kernel.
    //   • New / re-enabled / different cidr|gateway → install in kernel.
    use crate::networking::router::{
        apply_subnet_route as ws_apply_route,
        remove_subnet_route as ws_remove_route,
        node_handles_route as ws_node_handles_route,
        SubnetRoute,
    };
    // node_handles_route (v20.11.6) widens the filter to also include
    // routes where THIS node is the gateway — apply_subnet_route then
    // installs forwarding plumbing there even if the user pinned the
    // route's node_id to a different (consumer) node.
    let old_here: Vec<&SubnetRoute> = old_routes.iter()
        .filter(|r| r.enabled && ws_node_handles_route(r, &self_id))
        .collect();
    let new_here: Vec<&SubnetRoute> = new_cfg.subnet_routes.iter()
        .filter(|r| r.enabled && ws_node_handles_route(r, &self_id))
        .collect();

    // Helper: do two routes install the SAME kernel entry?
    let same_kernel_entry = |a: &SubnetRoute, b: &SubnetRoute| -> bool {
        a.subnet_cidr == b.subnet_cidr && a.gateway == b.gateway
    };

    // Helper: do two routes target the same kernel DESTINATION (the CIDR)?
    // A same-destination "edit" can be applied atomically with `ip route
    // replace`; we must NOT then `ip route del` the old entry, because that
    // would remove the route we just put in place.
    let same_kernel_destination = |a: &SubnetRoute, b: &SubnetRoute| -> bool {
        a.subnet_cidr == b.subnet_cidr
    };

    // Apply phase: install everything the new config wants here.
    // apply_subnet_route uses `ip route replace`, which is atomic — failure
    // leaves the previously-working entry on the kernel rather than
    // blackholing it (Codex P1, v20.11.2).
    //
    // We track which new entries succeeded by route id so the remove phase
    // below can safely delete only those old entries whose replacement (if
    // any) is confirmed to be in the kernel.
    let mut applied_ok_ids = std::collections::HashSet::<String>::new();
    for new in &new_here {
        let already = old_here.iter().any(|o| same_kernel_entry(o, new));
        // Look up the previous gateway for this CIDR among routes that
        // previously targeted THIS node. Match by CIDR alone — not (id,
        // CIDR) — so an admin who deleted route A and recreated it as B
        // with the same destination still gets the atomic swap on peers
        // (Codex P2, v20.11.2). Without this, a peer whose old config
        // owned the kernel entry under id A would refuse to overwrite it
        // when the new config presents id B for the same CIDR.
        let prev_gw = old_here.iter()
            .find(|o| o.subnet_cidr == new.subnet_cidr)
            .map(|o| o.gateway.clone());
        match ws_apply_route(new, prev_gw.as_deref()) {
            Ok(()) => {
                applied_ok_ids.insert(new.id.clone());
                if !already {
                    tracing::info!(
                        "config_receive: applied subnet route {} via {}",
                        new.subnet_cidr, new.gateway
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    "config_receive: apply subnet route {} via {} failed: {}",
                    new.subnet_cidr, new.gateway, e
                );
            }
        }
    }

    // Remove phase: drop kernel entries that no longer have a place in the
    // new config. We are conservative — if there is ANY chance the kernel
    // still holds the old destination as a working entry, we keep it.
    //
    // Cases for an old route O:
    //   • Same id present in new_here, same CIDR  →
    //         apply has overwritten the kernel entry. Calling `ip route del`
    //         would erase the replacement. Keep.
    //   • Same id present in new_here, different CIDR (the user edited the
    //     destination) →
    //         If the new apply succeeded, the kernel has the new CIDR; the
    //         old CIDR is stale and safe to delete. If the new apply failed,
    //         the kernel still holds the old destination and removing it
    //         would blackhole the previously-working subnet — keep.
    //   • Different id but the SAME CIDR present in new_here →
    //         apply already overwrote that kernel destination. Keep.
    //   • Old id absent from new_here AND no new entry shares the CIDR →
    //         The route was genuinely deleted (or moved off this node).
    //         Remove from the kernel.
    for old in &old_here {
        let by_id   = new_here.iter().find(|n| n.id == old.id);
        let by_cidr = new_here.iter().find(|n| same_kernel_destination(n, old));
        // by_cidr takes precedence over by_id (Codex P1, v20.11.2).
        // Reasoning: if ANY new entry shares this kernel destination, then
        // the apply phase has already (re)installed the kernel route for
        // that CIDR — `ip route del` would now delete the freshly-valid
        // entry. This case includes the cross-id swap "A: X→Y, B: new=X"
        // where deleting A's old kernel destination would erase B.
        //
        // Only when no new entry claims this CIDR do we consider deleting:
        //   • by_id present (CIDR was edited away from this destination)
        //     → safe iff the apply for id succeeded; otherwise keep so the
        //       peer doesn't lose connectivity.
        //   • by_id absent (route truly removed) → safe to delete.
        let drop_old = match (by_id, by_cidr) {
            (_, Some(_))      => false,
            (Some(n), None)   => applied_ok_ids.contains(&n.id),
            (None, None)      => true,
        };
        if drop_old {
            if let Err(e) = ws_remove_route(old) {
                tracing::warn!(
                    "config_receive: remove subnet route {} via {} failed: {}",
                    old.subnet_cidr, old.gateway, e
                );
            } else {
                tracing::info!(
                    "config_receive: removed stale subnet route {} via {}",
                    old.subnet_cidr, old.gateway
                );
            }
        }
    }

    // Re-sync the wolfnetd CIDR table now that we've replicated the new
    // config. This applies on every node, regardless of whether this
    // node is consumer or gateway for any of the routes — locally
    // originated traffic on this box may want to use a CIDR advertised
    // by some other peer.
    super::sync_subnet_routes_to_wolfnet(&new_cfg.subnet_routes);

    HttpResponse::Ok().body("synced")
}

/// Verify `value` is a syntactically valid IPv4 dotted-quad AND falls
/// inside `cidr`. Returns a descriptive error keyed by field name when
/// either check fails. Catches:
///   • typos like "10.1010.100" or "192.168..1" (parse failure)
///   • configurations like router_ip=10.0.0.1 with subnet 192.168.1.0/24
///     (parses but isn't in the network — clients DHCP'd in would have a
///     gateway off-segment, traffic gets routed but ARP fails)
fn validate_ipv4_in_cidr(field: &str, value: &str, cidr: &str) -> Result<(), String> {
    let value_trimmed = value.trim();
    let ip: std::net::Ipv4Addr = value_trimmed.parse()
        .map_err(|_| format!("'{}' = '{}' is not a valid IPv4 address", field, value_trimmed))?;
    let (net_str, prefix_str) = cidr.split_once('/')
        .ok_or_else(|| format!("subnet_cidr '{}' is malformed (missing '/')", cidr))?;
    let net: std::net::Ipv4Addr = net_str.parse()
        .map_err(|_| format!("subnet_cidr '{}' has invalid network part", cidr))?;
    let prefix: u8 = prefix_str.parse()
        .map_err(|_| format!("subnet_cidr '{}' has invalid prefix", cidr))?;
    if prefix > 32 {
        return Err(format!("subnet_cidr '{}' prefix > 32", cidr));
    }
    let mask: u32 = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
    if (u32::from(ip) & mask) != (u32::from(net) & mask) {
        return Err(format!(
            "'{}' = {} is not inside the LAN's subnet {} — \
             clients leased an IP from this LAN would have an off-segment gateway and traffic would silently fail",
            field, value_trimmed, cidr
        ));
    }
    Ok(())
}

/// Reject a LanSegment whose user-supplied fields contain newlines or
/// other dnsmasq directive separators. dhcp::render_config writes these
/// into a config file unescaped — without this guard a maliciously
/// crafted segment name or extra_options entry could inject directives
/// like `auth-server=` or `addn-hosts=/etc/shadow`.
fn validate_segment(seg: &LanSegment) -> Result<(), String> {
    let check = |field: &str, value: &str| -> Result<(), String> {
        if value.contains('\n') || value.contains('\r') {
            return Err(format!("{} contains newline characters", field));
        }
        Ok(())
    };
    // Require a non-empty name and interface — otherwise the error
    // surfaces deep inside dnsmasq with a cryptic "LAN ''" message.
    if seg.name.trim().is_empty() {
        return Err("LAN needs a name".into());
    }
    if seg.interface.trim().is_empty() {
        return Err("LAN needs an interface (e.g. br-lan0, enp3s0, eth0.100)".into());
    }
    if seg.subnet_cidr.trim().is_empty() {
        return Err("Subnet (CIDR) is required, e.g. 192.168.10.0/24".into());
    }
    if seg.router_ip.trim().is_empty() {
        return Err("Router IP is required".into());
    }
    if seg.dhcp.enabled
        && (seg.dhcp.pool_start.trim().is_empty() || seg.dhcp.pool_end.trim().is_empty()) {
            return Err("DHCP pool start and end are required when DHCP is enabled".into());
        }
    check("name", &seg.name)?;
    check("interface", &seg.interface)?;
    check("subnet_cidr", &seg.subnet_cidr)?;
    check("router_ip", &seg.router_ip)?;
    // Newline checks on DHCP-specific fields only matter when DHCP is
    // enabled — they'll otherwise be written into the dnsmasq config.
    if seg.dhcp.enabled {
        check("dhcp.pool_start", &seg.dhcp.pool_start)?;
        check("dhcp.pool_end", &seg.dhcp.pool_end)?;
        check("dhcp.lease_time", &seg.dhcp.lease_time)?;
    }
    // Format-level validation for IP-bearing fields. Without this, typos
    // like "10.1010.100" (missing dot) parse as plausible-looking strings,
    // sail through the empty/newline check, and only blow up later when
    // dnsmasq silently rejects the rendered config and starts with no
    // socket. Catch the typo at Save where the user's still in the form
    // and can fix it immediately.
    validate_ipv4_in_cidr("router_ip", &seg.router_ip, &seg.subnet_cidr)?;
    if seg.dhcp.enabled {
        validate_ipv4_in_cidr("dhcp.pool_start", &seg.dhcp.pool_start, &seg.subnet_cidr)?;
        validate_ipv4_in_cidr("dhcp.pool_end",   &seg.dhcp.pool_end,   &seg.subnet_cidr)?;
    }

    for (i, r) in seg.dhcp.reservations.iter().enumerate() {
        check(&format!("reservations[{}].mac", i), &r.mac)?;
        check(&format!("reservations[{}].ip", i), &r.ip)?;
        if let Some(h) = &r.hostname { check(&format!("reservations[{}].hostname", i), h)?; }
        // Reservation IP must be a real IPv4 inside the subnet — otherwise
        // dnsmasq accepts the line but never matches the lease request.
        validate_ipv4_in_cidr(&format!("reservations[{}].ip", i), &r.ip, &seg.subnet_cidr)?;
        // dnsmasq renders reservations as `dhcp-host=<mac>,<ip>[,<hostname>]`
        // — a literal comma in any field would inject an extra dnsmasq
        // option (e.g. `tag:foo`, `set:group`, `interface=eth0`). The
        // LAN editor's regex already blocks this, but wrPinLease takes
        // MAC/IP straight from the lease file without re-validating;
        // defence-in-depth here keeps the backend safe regardless of
        // how the field arrived.
        if r.mac.contains(',') { return Err(format!("reservations[{}].mac contains comma", i)); }
        if r.ip.contains(',')  { return Err(format!("reservations[{}].ip contains comma", i)); }
        if let Some(h) = &r.hostname
            && h.contains(',') { return Err(format!("reservations[{}].hostname contains comma", i)); }
    }
    for (i, opt) in seg.dhcp.extra_options.iter().enumerate() {
        check(&format!("extra_options[{}]", i), opt)?;
    }
    for (i, fwd) in seg.dns.forwarders.iter().enumerate() {
        check(&format!("forwarders[{}]", i), fwd)?;
    }
    for (i, rec) in seg.dns.local_records.iter().enumerate() {
        check(&format!("local_records[{}].hostname", i), &rec.hostname)?;
        check(&format!("local_records[{}].ip", i), &rec.ip)?;
    }
    for (i, wc) in seg.dns.wildcard_domains.iter().enumerate() {
        check(&format!("wildcard_domains[{}].domain", i), &wc.domain)?;
        check(&format!("wildcard_domains[{}].ip", i), &wc.ip)?;
        // Normalise the way the renderer will, then validate. dnsmasq's
        // `address=/<domain>/<ip>` breaks if the domain carries a slash or
        // whitespace, and a bad IP would make dnsmasq reject the whole config.
        let domain = wc.domain.trim().trim_start_matches("*.").trim_start_matches('.');
        if domain.is_empty() {
            return Err(format!("wildcard_domains[{}]: domain is empty (e.g. ai.home)", i));
        }
        if domain.contains('/') || domain.contains('#') || domain.chars().any(|c| c.is_whitespace()) {
            return Err(format!("wildcard_domains[{}]: domain '{}' must be a bare domain like ai.home (no slashes, '#', or spaces)", i, wc.domain));
        }
        if wc.ip.trim().parse::<std::net::IpAddr>().is_err() {
            return Err(format!("wildcard_domains[{}]: '{}' is not a valid IP address", i, wc.ip));
        }
    }
    // DNS mode / port / external_server sanity. The renderer falls back
    // to router_ip for DHCP option 6 when external_server is missing,
    // so "mode=External, no external_server" would silently advertise
    // the router that's no longer answering DNS — a footgun worth
    // blocking up-front.
    if let Some(ext) = &seg.dns.external_server {
        check("dns.external_server", ext)?;
        if ext.contains(',') {
            return Err("dns.external_server contains comma".into());
        }
    }
    match seg.dns.mode {
        DnsMode::External => {
            if seg.dns.external_server.as_deref().map(str::trim).unwrap_or("").is_empty() {
                return Err(
                    "DNS mode 'External' needs an external_server IP (the \
                     DNS box clients should use — AdGuard Home, Pi-hole, etc.)"
                        .into(),
                );
            }
        }
        DnsMode::WolfRouter => {
            // Anything outside 1..=65535 would render as an invalid
            // dnsmasq port= directive and crash startup.
            if seg.dns.listen_port == 0 {
                return Err(
                    "DNS mode 'WolfRouter' needs a listen_port between 1 and 65535 \
                     (use mode 'External' if you want DNS off entirely)"
                        .into(),
                );
            }
            // Non-53 port with no external_server means DHCP clients
            // will be told "use router_ip on port 53" — which is not
            // listening. Force the operator to pick a real DNS IP.
            if seg.dns.listen_port != 53
                && seg.dns.external_server.as_deref().map(str::trim).unwrap_or("").is_empty()
            {
                return Err(
                    "When listen_port isn't 53, external_server must be set — DHCP option 6 \
                     can only advertise a DNS resolver on the standard port :53, so clients \
                     need to be pointed at a separate resolver IP they can reach there. \
                     Typical setup: AdGuard Home or Pi-hole running in a container on this \
                     host with port 53 mapped, e.g. 172.17.0.5. \n\n\
                     IMPORTANT: this IP doesn't have to be running yet — it's just a string \
                     reference DHCP will hand out to clients. Set it to your AdGuard/Pi-hole \
                     container's planned IP, save this LAN, and dnsmasq will move off :53 — \
                     freeing it for AdGuard. Only THEN does AdGuard need to actually be up. \
                     (PapaSchlumpf 2026-04-30: this resolves the chicken-and-egg.)"
                        .into(),
                );
            }
        }
    }
    // Interface name must be a syntactically plausible Linux iface name
    // (alnum, dash, dot, underscore — no shell metacharacters).
    if !seg.interface.chars().all(|c| c.is_ascii_alphanumeric() || "-._".contains(c)) {
        return Err("interface name has illegal characters".into());
    }
    Ok(())
}

/// The node's display name — hostname is the cheapest universally
/// available identifier. Falls back to node id if hostname is empty.
fn self_node_name() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| if o.status.success() {
            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
        } else { None })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(crate::agent::self_node_id)
}

// ─── Topology ───

/// Optional `?cluster=<name>` query filter — when set, the topology
/// only includes nodes belonging to that cluster. WolfRouter is
/// per-cluster so the UI passes this on every fetch.
#[derive(Deserialize)]
pub struct TopologyQuery {
    #[serde(default)]
    pub cluster: Option<String>,
}

pub async fn get_topology(
    req: HttpRequest,
    state: S,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let cfg = state.router.config.read().unwrap().clone();
    let self_id = crate::agent::self_node_id();
    let self_name = self_node_name();
    let cluster_filter = query.cluster.clone();

    // Find self's cluster name. If a filter is set and self isn't in
    // that cluster, omit self from the result and only fan out to peers
    // in the requested cluster.
    // Cluster name normaliser — a node with no explicit cluster_name
    // is grouped as "WolfStack" in the sidebar tree (see app.js
    // `n.cluster_name || "WolfStack"`). Backend filtering must use
    // the same alias or nameless nodes leak into named-cluster views.
    let normalize = |n: Option<&str>| -> String {
        match n {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => "WolfStack".into(),
        }
    };
    let self_cluster = state.cluster.get_self_cluster_name();
    let self_cluster_norm = normalize(if self_cluster.is_empty() { None } else { Some(&self_cluster) });
    let include_self = match &cluster_filter {
        Some(want) => self_cluster_norm == *want,
        None => true,
    };

    let mut nodes = Vec::new();
    let mut local_error: Option<String> = None;
    if include_self {
        // C2 fix: compute_local fans out to `docker ps`, `docker inspect`
        // per container, `lxc-ls`, `lxc-info` per container, and
        // gateway-probe `curl`/`ping`/`dig` on cache misses. Up to
        // several seconds of blocking subprocess work. Offload to a
        // blocking pool thread so the actix worker stays free for
        // other requests (terminals, polls, etc).
        let self_id_clone = self_id.clone();
        let self_name_clone = self_name.clone();
        let cfg_clone = cfg.clone();
        let router_clone = state.router.clone();
        let local = web::block(move || {
            topology::compute_local(&self_id_clone, &self_name_clone, &cfg_clone, &router_clone)
        }).await;
        match local {
            Ok(t) => nodes.push(t),
            // Surface the failure rather than silently omitting self
            // from the topology — pre-fix-of-fix this dropped the
            // local node with no signal to the caller, making a
            // pool-exhaustion bug indistinguishable from "no nodes
            // exist".
            Err(e) => local_error = Some(format!("local topology task failed: {}", e)),
        }
    }

    // Fan out to every other online cluster node's topology-local
    // endpoint, filtered by cluster name when one was requested.
    let cluster_nodes = state.cluster.get_all_nodes();
    let secret = state.cluster_secret.clone();
    // Process-wide pool — see ROUTER_RPC_CLIENT. Per-request timeout
    // (5s) is set on the RequestBuilder below. Previously this site
    // built a fresh Client every topology fetch and handed it out to
    // N concurrent peer futures; each cloned Arc shared the same
    // pool but when the outer Client dropped at function exit the
    // pool's idle sockets were orphaned.
    let client = &*ROUTER_RPC_CLIENT;

    // Per-peer diagnostic trail so when a node is missing from the
    // rack view, the response tells you *why* (filtered out / offline /
    // HTTP error / etc) instead of leaving you guessing.
    let mut peer_diagnostics: Vec<serde_json::Value> = Vec::new();

    {
        let mut futures = Vec::new();
        for node in cluster_nodes {
            // Self isn't a "peer" — it's already in the result as the
            // local node. Don't include it in diagnostics or the user
            // sees confusing "wolf: is_self" lines in the missing-peers
            // banner.
            if node.is_self || node.id == self_id { continue; }
            if node.node_type != "wolfstack" {
                peer_diagnostics.push(serde_json::json!({
                    "node_id": node.id, "hostname": node.hostname,
                    "result": "skipped", "reason": format!("node_type={} (not wolfstack)", node.node_type)
                }));
                continue;
            }
            // Cluster scoping — strict, but uses the same None→"WolfStack"
            // alias the sidebar tree uses so nameless nodes show up where
            // the user expects (the WolfStack group, not every cluster).
            if let Some(ref want) = cluster_filter {
                let node_cluster = normalize(node.cluster_name.as_deref());
                if &node_cluster != want {
                    peer_diagnostics.push(serde_json::json!({
                        "node_id": node.id, "hostname": node.hostname,
                        "result": "skipped",
                        "reason": format!("cluster_name='{}' doesn't match filter '{}'", node_cluster, want)
                    }));
                    continue;
                }
            }
            // We deliberately do NOT skip "offline" peers: last_seen
            // can be stale (polling hiccup, recent restart) but the
            // peer is reachable. WolfRouter retries up to 5 times with
            // exponential backoff per peer; if every attempt fails the
            // node still appears as a stub chassis so the user sees it
            // exists. Subsequent 3s polls fill it in once the peer
            // answers.
            // Resolve domain names to IPs to support both IP and domain-based node configs.
            let host = resolve_node_address(&node.address);
            let port = node.port;
            let id = node.id.clone();
            let hostname = node.hostname.clone();
            let stub_name = if hostname.is_empty() { id.clone() } else { hostname.clone() };
            let secret_h = secret.clone();
            // `client` is `&reqwest::Client` (LazyLock deref). Method
            // resolution on `&T::clone()` picks the blanket
            // `Clone for &T` impl and returns another reference, which
            // can't cross into an `async move` future (not 'static).
            // UFCS forces the call to `<Client as Clone>::clone`, which
            // takes `&Client` and returns an owned `Client`. The clone
            // is cheap — Client is internally refcounted.
            let client_c: reqwest::Client = reqwest::Client::clone(client);
            futures.push(async move {
                // v23.12: HTTPS-first via build_node_urls (cert bypass on
                // the shared client makes self-signed peers reachable).
                let urls = crate::api::build_node_urls(&host, port, "/api/router/topology-local");
                let mut last_err = String::new();
                let mut backoff_ms = 100u64;
                for attempt in 1..=5 {
                    for url in &urls {
                        match client_c.get(url)
                            .peer_auth(&secret_h)
                            .timeout(std::time::Duration::from_secs(5))
                            .send().await
                        {
                            Ok(r) if r.status().is_success() => {
                                return match r.json::<topology::NodeTopology>().await {
                                    Ok(mut t) => {
                                        t.status = "live".into();
                                        t.status_note = String::new();
                                        Ok(t)
                                    }
                                    Err(e) => Err((id.clone(), stub_name.clone(),
                                        format!("decode error after {} attempt(s): {}", attempt, e))),
                                };
                            }
                            // Capture status + drain the body before
                            // dropping `r`. Previously `Ok(r)` let `r`
                            // fall out of scope unread, so the socket
                            // never went back to the keep-alive pool.
                            Ok(r) => {
                                let status = r.status();
                                last_err = format!("HTTP {} from {}", status, url);
                                let _ = r.bytes().await;
                            }
                            Err(e) => { last_err = format!("{} ({})", e, url); }
                        }
                    }
                    if attempt < 5 {
                        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(1500);
                    }
                }
                Err((id, stub_name, format!("5 attempts failed — last error: {}", last_err)))
            });
        }
        let results = futures::future::join_all(futures).await;
        for r in results {
            match r {
                Ok(t) => {
                    peer_diagnostics.push(serde_json::json!({
                        "node_id": t.node_id, "hostname": t.node_name,
                        "result": "ok"
                    }));
                    nodes.push(t);
                }
                Err((id, hostname, reason)) => {
                    peer_diagnostics.push(serde_json::json!({
                        "node_id": id.clone(), "hostname": hostname.clone(),
                        "result": "failed", "reason": reason.clone()
                    }));
                    // Emit a stub so the rack still draws a chassis for
                    // this peer; the next poll will overwrite it with
                    // live data once the peer responds.
                    nodes.push(topology::NodeTopology::stub(
                        id, hostname, "unreachable", reason,
                    ));
                }
            }
        }
    }

    // Cache the remotes so the next request can fall back if a node
    // goes offline mid-request. Skip self (it's regenerated each call).
    {
        let mut cache = state.router.remote_topologies.write().unwrap();
        cache.clear();
        for n in &nodes {
            if n.node_id != self_id {
                cache.insert(n.node_id.clone(), n.clone());
            }
        }
    }

    let links = topology::derive_links(&nodes);
    let generated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

    // Wrap the standard topology with the per-peer diagnostics so the
    // frontend can show "tried 3 peers, got 2 responses, 1 skipped
    // because cluster_name didn't match" on the rack header.
    // Aggregate routers from every node and dedup by IP. Each node
    // discovers its own default gateways (which may differ across
    // subnets/sites), and the master collects them all so the rack
    // view shows every upstream router the cluster talks through.
    let mut router_ips = std::collections::HashSet::new();
    let mut routers = Vec::new();
    for node in &nodes {
        for r in &node.routers {
            if router_ips.insert(r.ip.clone()) {
                routers.push(r.clone());
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "nodes": nodes,
        "links": links,
        "routers": routers,
        "generated_at": generated_at,
        "peer_diagnostics": peer_diagnostics,
        "cluster_filter": cluster_filter,
        // Surface the C2 web::block failure if it happened — caller
        // sees a structured signal instead of silently missing local.
        "local_error": local_error,
    }))
}

/// Local-only topology endpoint called by other cluster nodes during
/// agent polling. Unauthenticated at the HTTP layer; authenticated via
/// the X-WolfStack-Secret header.
pub async fn get_topology_local(
    state: S,
    req: actix_web::HttpRequest,
) -> HttpResponse {
    // Reuse the standard auth helper — accepts session cookie OR
    // X-WolfStack-Secret cluster header, same as every other endpoint.
    if let Err(resp) = crate::api::require_auth(&req, &state) {
        return resp;
    }
    let cfg = state.router.config.read().unwrap().clone();
    let self_id = crate::agent::self_node_id();
    let self_name = self_node_name();
    // C2 fix: blocking subprocess work — offload to blocking pool.
    let router_clone = state.router.clone();
    let t = web::block(move || {
        topology::compute_local(&self_id, &self_name, &cfg, &router_clone)
    }).await;
    match t {
        Ok(t) => HttpResponse::Ok().json(t),
        Err(e) => HttpResponse::InternalServerError().body(format!("topology task: {}", e)),
    }
}

// ─── Preflight ───
//
// Lightweight network-config sanity check the frontend hits BEFORE
// opening the WolfRouter page. The page fans out to half a dozen
// endpoints and on a misconfigured host failures look like "Failed
// to fetch" or "No nodes in topology" with no pointer at the cause.
// Preflight runs the checks most likely to explain those failures
// (hosts file, hostname resolution, interface UP state, cluster
// membership, API reachability) and returns a structured report so
// the UI can surface "what's wrong + how to fix it" instead of just
// showing an empty rack.

#[derive(serde::Serialize)]
struct PreflightCheck {
    id: &'static str,
    name: &'static str,
    ok: bool,
    severity: &'static str, // "error" | "warning" | "info"
    message: String,
    fix: Option<String>,
}

/// One-click Fix action returned alongside the checks list, keyed by
/// check id. The UI looks each row up by `c.id`; if there's a matching
/// entry it renders a "Fix" button that POSTs to `url`. Only safe
/// actions get attached — anything that could lock the operator out
/// (UDP/53 host-firewall edits on the management interface, etc.)
/// stays instructions-only.
#[derive(serde::Serialize, Clone)]
pub struct PreflightAction {
    /// Human label shown on the button (e.g. "Enable IP forwarding").
    pub label: String,
    /// API path. UI POSTs JSON `{}` (or the `body` field, if present).
    pub url: String,
    /// Short tooltip explaining what the action will do.
    pub detail: String,
    /// Confirmation text shown in `confirm()` before the POST. Empty
    /// for trivially safe actions.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub confirm: String,
    /// Optional JSON body to POST. Default is `{}`.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub body: serde_json::Value,
}

pub async fn preflight(
    req: HttpRequest,
    state: S,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);

    // C3 fix: the preflight body runs dozens of blocking subprocesses
    // (hostname, ip, iptables-save, ip link, ss, ip route, dig, ...)
    // — moving it to the blocking pool keeps the actix worker free.
    // The body is wrapped wholesale rather than per-check because the
    // checks share many of the same parsed values (e.g. `ip -j addr`
    // output) and splitting them per-call would multiply the context
    // switches without performance benefit.
    let state_for_block = state.clone();
    let query_inner = query.into_inner();
    let body_result = web::block(move || -> serde_json::Value {
        let state = state_for_block;
        let query = query_inner;

    let mut checks: Vec<PreflightCheck> = Vec::new();
    let mut actions: std::collections::HashMap<&'static str, PreflightAction>
        = std::collections::HashMap::new();

    // 1) /etc/hosts — needed for hostname resolution on most distros.
    // Allow for hosts files without an explicit entry for the local
    // hostname (systemd-resolved / NetworkManager handle this on some
    // setups), but flag the common broken case: a 127.0.1.1 mapping
    // and nothing else, leaving peers unable to address this node.
    match std::fs::read_to_string("/etc/hosts") {
        Ok(contents) => {
            let hostname_cmd = std::process::Command::new("hostname").output().ok();
            let hostname = hostname_cmd
                .and_then(|o| if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else { None })
                .unwrap_or_default();

            let has_loopback = contents.lines().any(|l| {
                let l = l.trim();
                !l.starts_with('#') && (l.starts_with("127.0.0.1") || l.starts_with("::1"))
            });
            let hostname_on_real_ip = !hostname.is_empty() && contents.lines().any(|l| {
                let l = l.trim();
                if l.starts_with('#') || l.is_empty() { return false; }
                let mut parts = l.split_whitespace();
                let addr = parts.next().unwrap_or("");
                if addr.is_empty() || addr.starts_with("127.") || addr == "::1" { return false; }
                parts.any(|tok| tok == hostname)
            });
            let hostname_on_127_0_1_1 = !hostname.is_empty() && contents.lines().any(|l| {
                let l = l.trim();
                !l.starts_with('#') && l.starts_with("127.0.1.1")
                    && l.split_whitespace().skip(1).any(|t| t == hostname)
            });
            let has_hostname_entry = hostname_on_real_ip || hostname_on_127_0_1_1
                || (!hostname.is_empty() && contents.lines().any(|l| {
                    let l = l.trim();
                    if l.starts_with('#') || l.is_empty() { return false; }
                    l.split_whitespace().skip(1).any(|tok| tok == hostname)
                }));
            // Flag the common Debian-leftover case: hostname ONLY on
            // 127.0.1.1 with no real-IP mapping. Peers resolving by
            // name will get a loopback address they can't route to.
            let only_127_0_1_1 = hostname_on_127_0_1_1 && !hostname_on_real_ip;

            if !has_loopback {
                checks.push(PreflightCheck {
                    id: "hosts_loopback",
                    name: "/etc/hosts loopback entry",
                    ok: false,
                    severity: "error",
                    message: "/etc/hosts has no `127.0.0.1 localhost` line. Local API calls through `localhost` will fail.".into(),
                    fix: Some("Add this line to /etc/hosts:\n  127.0.0.1   localhost".into()),
                });
            } else {
                checks.push(PreflightCheck {
                    id: "hosts_loopback",
                    name: "/etc/hosts loopback entry",
                    ok: true,
                    severity: "info",
                    message: "Loopback entry present.".into(),
                    fix: None,
                });
            }

            if !hostname.is_empty() && !has_hostname_entry {
                checks.push(PreflightCheck {
                    id: "hosts_hostname",
                    name: "/etc/hosts hostname entry",
                    ok: false,
                    severity: "warning",
                    message: format!("/etc/hosts has no entry for hostname `{}`. Cluster peers reaching you by hostname may fail.", hostname),
                    fix: Some(format!("Add a line like this to /etc/hosts (replace with your LAN IP):\n  192.168.x.y   {}", hostname)),
                });
            } else if !hostname.is_empty() && only_127_0_1_1 {
                checks.push(PreflightCheck {
                    id: "hosts_hostname",
                    name: "/etc/hosts hostname entry",
                    ok: false,
                    severity: "warning",
                    message: format!("Hostname `{}` is only mapped to 127.0.1.1. Peers can't reach this node by its hostname.", hostname),
                    fix: Some(format!("Add a LAN-address entry to /etc/hosts:\n  192.168.x.y   {}\n(keep the 127.0.1.1 line if Debian/Ubuntu put it there.)", hostname)),
                });
            }
        }
        Err(e) => {
            checks.push(PreflightCheck {
                id: "hosts_file",
                name: "/etc/hosts readable",
                ok: false,
                severity: "error",
                message: format!("/etc/hosts could not be read: {}", e),
                fix: Some("Check that /etc/hosts exists and wolfstack has permission to read it.".into()),
            });
        }
    }

    // 2) Hostname resolution.
    let hn_out = std::process::Command::new("hostname").arg("-f").output();
    let fqdn = hn_out.as_ref().ok()
        .and_then(|o| if o.status.success() {
            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
        } else { None })
        .filter(|s| !s.is_empty());
    match &fqdn {
        Some(h) => checks.push(PreflightCheck {
            id: "hostname_fqdn",
            name: "Fully-qualified hostname",
            ok: true,
            severity: "info",
            message: format!("hostname -f: {}", h),
            fix: None,
        }),
        None => checks.push(PreflightCheck {
            id: "hostname_fqdn",
            name: "Fully-qualified hostname",
            ok: false,
            severity: "warning",
            message: "`hostname -f` returned nothing. Peers may have trouble resolving this node.".into(),
            fix: Some("Set the hostname with:\n  sudo hostnamectl set-hostname your-host-name\nand add a matching entry to /etc/hosts.".into()),
        }),
    }

    // 3) Network interfaces — at least one non-loopback UP with an IPv4.
    let ip_addr_out = std::process::Command::new("ip")
        .args(["-j", "-4", "addr"])
        .output();
    let mut ipv4_interface_count = 0;
    let mut iface_list: Vec<String> = Vec::new();
    if let Ok(o) = ip_addr_out
        && o.status.success()
            && let Ok(arr) = serde_json::from_slice::<Vec<serde_json::Value>>(&o.stdout) {
                for i in arr {
                    let ifname = i["ifname"].as_str().unwrap_or("");
                    let is_up = i["operstate"].as_str() == Some("UP")
                        || i["flags"].as_array()
                            .map(|a| a.iter().any(|v| v.as_str() == Some("UP")))
                            .unwrap_or(false);
                    let has_ipv4 = i["addr_info"].as_array()
                        .map(|a| a.iter().any(|ai| {
                            ai["family"].as_str() == Some("inet")
                                && ai["scope"].as_str() != Some("host")
                        }))
                        .unwrap_or(false);
                    if ifname != "lo" && is_up && has_ipv4 {
                        ipv4_interface_count += 1;
                        iface_list.push(ifname.to_string());
                    }
                }
            }
    if ipv4_interface_count == 0 {
        checks.push(PreflightCheck {
            id: "network_interfaces",
            name: "IPv4 network interfaces",
            ok: false,
            severity: "error",
            message: "No non-loopback interface has an IPv4 address. WolfRouter needs one to build the topology.".into(),
            fix: Some("Bring a physical or virtual interface up and assign an IPv4 (DHCP or static).\nOn Debian/Ubuntu:\n  sudo ip link set eth0 up && sudo dhclient eth0\nOn RHEL/Fedora:\n  sudo nmcli device connect eth0".into()),
        });
    } else {
        checks.push(PreflightCheck {
            id: "network_interfaces",
            name: "IPv4 network interfaces",
            ok: true,
            severity: "info",
            message: format!("{} UP interface(s) with IPv4: {}", ipv4_interface_count, iface_list.join(", ")),
            fix: None,
        });
    }

    // 4) Cluster membership — most common cause of "No nodes in
    // topology" is that the requested cluster contains only Proxmox
    // peers (or only remote WolfStack peers that aren't responding).
    let self_id = crate::agent::self_node_id();
    let self_cluster = state.cluster.get_self_cluster_name();
    let normalize = |n: Option<&str>| -> String {
        match n {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => "WolfStack".into(),
        }
    };
    let self_cluster_norm = normalize(
        if self_cluster.is_empty() { None } else { Some(&self_cluster) }
    );
    // M6: When `get_self_cluster_name()` returns the hardcoded fallback,
    // we can't tell from the return value alone whether the operator
    // genuinely configured "WolfStack" or whether the fallback fired.
    // The disambiguation: presence of /etc/wolfstack/self_cluster.json
    // means the cluster name has been set (via agent_set_cluster_name
    // or gossip). Absence means this node has never been told its
    // cluster — the diagnostic should surface that explicitly instead
    // of misleadingly displaying "WolfStack".
    let self_cluster_configured = std::path::Path::new(
        &crate::paths::get().self_cluster_config
    ).exists();
    let self_cluster_display = if self_cluster_configured {
        self_cluster_norm.clone()
    } else {
        "(not yet configured — admin must set the cluster name when adding this node)".to_string()
    };
    let requested = query.cluster.clone();

    let all_nodes = state.cluster.get_all_nodes();
    let mut wolfstack_in_cluster = 0;
    let mut proxmox_in_cluster = 0;
    let mut other_in_cluster = 0;
    let mut online_wolfstack = 0;
    for n in &all_nodes {
        // get_all_nodes() already includes self with is_self=true —
        // iterate everything including self, don't double-count.
        let node_cluster = normalize(n.cluster_name.as_deref());
        let in_cluster = match &requested {
            Some(w) => {
                // For the self node, use the canonical self_cluster
                // resolved above (gossip can leave a stale name on the
                // map entry but ClusterState::get_self_cluster_name is
                // authoritative).
                if n.is_self || n.id == self_id {
                    self_cluster_norm == *w
                } else {
                    node_cluster == *w
                }
            }
            None => true,
        };
        if !in_cluster { continue; }
        match n.node_type.as_str() {
            "wolfstack" => {
                wolfstack_in_cluster += 1;
                // Self is always online from its own point of view; the
                // cluster-state `online` flag is driven by *peer* gossip.
                if n.is_self || n.id == self_id || n.online { online_wolfstack += 1; }
            }
            "proxmox"   => proxmox_in_cluster += 1,
            _           => other_in_cluster += 1,
        }
    }

    if wolfstack_in_cluster == 0 {
        let label = requested.clone().unwrap_or_else(|| "(all)".into());
        checks.push(PreflightCheck {
            id: "cluster_membership",
            name: "WolfStack nodes in cluster",
            ok: false,
            severity: "error",
            message: format!(
                "Cluster `{}` has 0 WolfStack nodes (this node is in cluster `{}`). WolfRouter can only render topology from WolfStack peers.",
                label, self_cluster_display
            ),
            fix: Some(format!(
                "Either open WolfRouter for cluster `{}` from the sidebar, or join/install a WolfStack node into cluster `{}`.\nProxmox peers ({}) and other-type peers ({}) are intentionally skipped from topology — they're managed through the Proxmox cluster view.",
                self_cluster_display, label, proxmox_in_cluster, other_in_cluster
            )),
        });
    } else if online_wolfstack == 0 {
        let label = requested.clone().unwrap_or_else(|| "(all)".into());
        checks.push(PreflightCheck {
            id: "cluster_online",
            name: "Online WolfStack nodes",
            ok: false,
            severity: "warning",
            message: format!(
                "Cluster `{}` has {} WolfStack node(s) but none are marked online. Topology will contain stubs until they respond.",
                label, wolfstack_in_cluster
            ),
            fix: Some("Check that each WolfStack node is reachable on its configured port and the cluster secret matches.\n  • `sudo ss -tlnp | grep 8553`\n  • `curl -k https://<peer>:8553/api/nodes`".into()),
        });
    } else {
        checks.push(PreflightCheck {
            id: "cluster_membership",
            name: "WolfStack nodes in cluster",
            ok: true,
            severity: "info",
            message: format!(
                "{} WolfStack node(s) in cluster (online: {}); {} Proxmox peer(s) shown but skipped from topology.",
                wolfstack_in_cluster, online_wolfstack, proxmox_in_cluster
            ),
            fix: None,
        });
    }

    // 5) If the requested cluster differs from self's cluster, surface
    // that as an info hint so the user knows WHY topology looks thin.
    if let Some(w) = &requested
        && &self_cluster_norm != w {
            checks.push(PreflightCheck {
                id: "cluster_scope",
                name: "Viewing remote cluster",
                ok: true,
                severity: "info",
                message: format!(
                    "This node is in `{}`; you're viewing WolfRouter for `{}`. The local chassis will be omitted.",
                    self_cluster_display, w
                ),
                fix: None,
            });
        }

    // 6) IPv6 — WolfStack is IPv4-only end-to-end. An IPv6 stack on
    // the host doesn't strictly break us (all our reqwest clients
    // bind to Ipv4Addr::UNSPECIFIED so AAAA candidates are skipped),
    // but on Proxmox hosts with IPv6 fully enabled we've seen peer
    // calls stall for seconds while the kernel tried IPv6 routes that
    // the LAN didn't actually carry. Warn loudly, because "it works
    // fine with IPv6" is the single most common customer-side symptom
    // of "WolfRouter intermittently fails to fetch".
    let ipv6_global_disabled = std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
    // Look for non-loopback, non-link-local IPv6 addresses on any
    // interface — those are the ones the kernel will actually try to
    // route via (ULA/GUA). Link-local (fe80::) is always present when
    // IPv6 isn't disabled and we don't care about it.
    let ip6_addr_out = std::process::Command::new("ip")
        .args(["-j", "-6", "addr"])
        .output();
    let mut ipv6_routable_ifaces: Vec<String> = Vec::new();
    if let Ok(o) = ip6_addr_out
        && o.status.success()
            && let Ok(arr) = serde_json::from_slice::<Vec<serde_json::Value>>(&o.stdout) {
                for i in arr {
                    let ifname = i["ifname"].as_str().unwrap_or("").to_string();
                    if ifname == "lo" { continue; }
                    let has_routable = i["addr_info"].as_array()
                        .map(|a| a.iter().any(|ai| {
                            if ai["family"].as_str() != Some("inet6") { return false; }
                            let scope = ai["scope"].as_str().unwrap_or("");
                            // "link" = fe80::/10 (link-local, auto-assigned,
                            // not routable off-link). Ignore. Anything else
                            // ("global", "site", "host") is a real address.
                            scope != "link" && scope != "host"
                        }))
                        .unwrap_or(false);
                    if has_routable { ipv6_routable_ifaces.push(ifname); }
                }
            }
    if ipv6_global_disabled {
        checks.push(PreflightCheck {
            id: "ipv6_stack",
            name: "IPv6 stack disabled",
            ok: true,
            severity: "info",
            message: "net.ipv6.conf.all.disable_ipv6 = 1. Good — WolfStack is IPv4-only end-to-end.".into(),
            fix: None,
        });
    } else if !ipv6_routable_ifaces.is_empty() {
        checks.push(PreflightCheck {
            id: "ipv6_stack",
            name: "IPv6 is enabled (WolfStack is IPv4-only)",
            ok: false,
            severity: "warning",
            message: format!(
                "{} interface(s) have routable IPv6 addresses: {}. On mixed-stack hosts we've seen cluster RPCs stall while the kernel tries IPv6 routes the LAN doesn't carry. WolfStack pins every outbound connection to IPv4, but your AI / Proxmox / external API calls can still try AAAA first.",
                ipv6_routable_ifaces.len(),
                ipv6_routable_ifaces.join(", ")
            ),
            fix: Some("Disable IPv6 system-wide (recommended on Proxmox):\n  # /etc/sysctl.d/99-wolfstack-no-ipv6.conf\n  net.ipv6.conf.all.disable_ipv6   = 1\n  net.ipv6.conf.default.disable_ipv6 = 1\n  net.ipv6.conf.lo.disable_ipv6    = 1\n  sudo sysctl --system\n\nOr disable per-interface via your network manager. Reboot is NOT required — sysctl --system applies immediately.".into()),
        });
    } else {
        checks.push(PreflightCheck {
            id: "ipv6_stack",
            name: "IPv6 status",
            ok: true,
            severity: "info",
            message: "IPv6 is enabled in the kernel but no interface has a routable IPv6 address. No risk to WolfRouter.".into(),
            fix: None,
        });
    }

    // 7) IP forwarding — WolfRouter doesn't require it for viewing,
    // but warn if it's off because most firewall/router features won't
    // do anything without it.
    let forward = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
    if !forward {
        checks.push(PreflightCheck {
            id: "ip_forward",
            name: "IPv4 forwarding",
            ok: false,
            severity: "warning",
            message: "net.ipv4.ip_forward = 0. Firewall rules and LAN segments won't actually route traffic until this is enabled. \
                      Why it matters: when forwarding is off, the kernel drops every packet whose destination isn't *this* host — including LAN-client traffic to the internet through your WAN. Symptom: clients get DHCP leases, ping the router, but `ping 1.1.1.1` times out. \
                      Safe to enable everywhere — Proxmox, libvirt, Docker, and LXC bridges all expect `ip_forward=1` themselves; this is the default on any box that routes for anything.".into(),
            fix: Some("Enable persistently with:\n  echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-wolfrouter.conf\n  sudo sysctl --system\n\nOr click the Fix button — WolfStack writes the same drop-in and reloads sysctl.".into()),
        });
        actions.insert("ip_forward", PreflightAction {
            label: "Enable IP forwarding".into(),
            url: "/api/router/fix/enable-ip-forward".into(),
            detail: "Writes net.ipv4.ip_forward=1 to /etc/sysctl.d/99-wolfrouter.conf and reloads sysctl. Idempotent. Proxmox/libvirt/Docker bridges all need this on too — never breaks them.".into(),
            confirm: String::new(),
            body: serde_json::Value::Null,
        });
    } else {
        checks.push(PreflightCheck {
            id: "ip_forward",
            name: "IPv4 forwarding",
            ok: true,
            severity: "info",
            message: "Enabled.".into(),
            fix: None,
        });
    }

    // 8) WAN routing & default route — without these the node itself
    // can't egress, and LAN clients masqueraded through it can't reach
    // anything either. The exact symptom that motivated this section:
    // PPPoE WAN dialed up fine, but `use_default_route` defaulted off
    // (sane default on a mixed box, lethal on a dedicated router) and
    // the box ended up with `nodefaultroute` written into the peer
    // file. `traceroute` from the router returned `!H` from its own
    // LAN IP because the kernel had no usable egress.
    //
    // Source: networking/router/wan.rs:227-228, 444-453 — the
    // use_default_route default and the resulting peer-file branch.
    let default_route_text = std::process::Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let has_default_route = !default_route_text.is_empty();

    // Snapshot enabled WAN connections owned by this node. Remote-node
    // WAN connections are checked when the user opens preflight against
    // that node — we can't read its iptables/ppp state from here.
    let local_wans: Vec<wan::WanConnection> = {
        let cfg = state.router.config.read().unwrap();
        cfg.wan_connections.iter()
            .filter(|w| w.enabled && w.node_id == self_id)
            .cloned()
            .collect()
    };

    if has_default_route {
        let first = default_route_text.lines().next().unwrap_or("").trim();
        checks.push(PreflightCheck {
            id: "default_route",
            name: "Default IPv4 route",
            ok: true,
            severity: "info",
            message: format!("Present: {}", first),
            fix: None,
        });
    } else if local_wans.is_empty() {
        checks.push(PreflightCheck {
            id: "default_route",
            name: "Default IPv4 route",
            ok: false,
            severity: "warning",
            message: "No default IPv4 route on this node, and no WolfRouter WAN connection is configured here. The node can't reach the internet, and any LAN clients routed through it will get host-unreachable.".into(),
            fix: Some("Either add a WAN connection in WolfRouter → WAN connections (DHCP / Static / PPPoE), or configure a default route via the host's network config.".into()),
        });
    } else {
        // There IS a WAN configured here but no default route. Almost
        // always either (a) PPPoE with `use_default_route` unticked, or
        // (b) the WAN link itself didn't come up. Pull out (a) so the
        // fix instructions point at the exact UI checkbox.
        let pppoe_no_default: Vec<&wan::WanConnection> = local_wans.iter()
            .filter(|w| matches!(&w.mode, wan::WanMode::Pppoe(p) if !p.use_default_route))
            .collect();
        if !pppoe_no_default.is_empty() {
            let names = pppoe_no_default.iter()
                .map(|w| format!("'{}'", w.name))
                .collect::<Vec<_>>()
                .join(", ");
            checks.push(PreflightCheck {
                id: "default_route",
                name: "Default IPv4 route",
                ok: false,
                severity: "error",
                message: format!(
                    "No default IPv4 route. PPPoE WAN(s) {} have 'Use as default route' unticked, so pppd writes `nodefaultroute` to the peer file. \
                     Why this kills you: without a default route, the kernel doesn't know where to send packets that aren't on a directly-connected subnet. The router itself can't reach the internet, and every LAN client masqueraded through it gets host-unreachable on anything outside its own LAN.",
                    names
                ),
                fix: Some("WolfRouter → WAN connections → edit each PPPoE entry → tick 'Use as default route' (and 'Use ISP DNS' unless you've configured DNS yourself), then Save. WolfRouter rewrites the peer file with `defaultroute replacedefaultroute` and redials.\n\nOr click the Fix button — WolfStack ticks the flag, saves, and redials pppd for you.".into()),
            });
            // Action targets the FIRST offending PPPoE — multi-PPPoE
            // setups are rare; the operator can repeat for any others.
            if let Some(w) = pppoe_no_default.first() {
                actions.insert("default_route", PreflightAction {
                    label: "Tick 'Use as default route' & redial".into(),
                    url: format!("/api/router/fix/wan/{}/tick-pppoe-default-route", w.id),
                    detail: "Sets use_default_route=true on this PPPoE WAN, saves, and redials pppd so the peer-file change takes effect.".into(),
                    confirm: "Redial PPPoE? You'll lose the WAN link for ~5–10s while pppd reconnects.".into(),
                    body: serde_json::Value::Null,
                });
            }
        } else {
            checks.push(PreflightCheck {
                id: "default_route",
                name: "Default IPv4 route",
                ok: false,
                severity: "error",
                message: "No default IPv4 route on this node, despite WAN connection(s) being configured here. The router itself has no internet and LAN clients routed through it can't reach anything either.".into(),
                fix: Some("The configured WAN link probably didn't come up. Check:\n  • PPPoE: `pgrep -af pppd` and `journalctl -u pppd -n 50`\n  • DHCP:  `ip -4 addr show <wan-iface>` should show a public IP\n  • Static: `ping <gateway>` should answer".into()),
            });
        }
    }

    // 8a') Self-loop default route — if a `default via X` route's
    // next-hop X is one of THIS host's own IPs, the kernel either
    // returns ENETUNREACH or emits ICMP host-unreachable from that
    // local IP, and traceroute/ping report `!H`.
    //
    // Real failure mode that motivated this check (PapaSchlumpf, April
    // 2026): on a router box with WolfRouter serving 10.10.10.0/24,
    // ens1 had primary 10.10.10.2 (the host's own LAN IP) AND
    // secondary 10.10.10.1 (the LAN gateway address dnsmasq listens
    // on). /etc/network/interfaces had `gateway 10.10.10.1`, so ifup
    // installed `default via 10.10.10.1 dev ens1 proto static`. With
    // metric 0 it beat the working Starlink DHCP default (metric 100),
    // and every egress packet from the router got rejected because the
    // gateway was the box itself. LAN clients masqueraded through the
    // box hit the same dead route.
    //
    // We catch this by collecting every IPv4 address on the host and
    // checking each `default via …` line against that set. A
    // next-hop matching a local IP is unambiguous misconfig — never a
    // legitimate setup.
    if has_default_route {
        // All non-loopback local IPv4s on this host.
        let mut local_ips: Vec<String> = Vec::new();
        if let Ok(out) = std::process::Command::new("ip")
            .args(["-j", "-4", "addr"])
            .output()
            && out.status.success()
                && let Ok(arr) = serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout) {
                    for entry in arr {
                        if let Some(addrs) = entry.get("addr_info").and_then(|v| v.as_array()) {
                            for ai in addrs {
                                if ai.get("family").and_then(|v| v.as_str()) != Some("inet") { continue; }
                                if ai.get("scope").and_then(|v| v.as_str()) == Some("host") { continue; }
                                if let Some(ip) = ai.get("local").and_then(|v| v.as_str()) {
                                    local_ips.push(ip.to_string());
                                }
                            }
                        }
                    }
                }
        // Walk each default route line; flag any whose `via` is local.
        let mut self_loops: Vec<(String, String)> = Vec::new(); // (via_ip, full_line)
        for line in default_route_text.lines() {
            let line = line.trim();
            if !line.starts_with("default") { continue; }
            // Parse `via <ip>` — token after "via".
            let via = line.split_whitespace()
                .skip_while(|t| *t != "via")
                .nth(1)
                .unwrap_or("");
            if !via.is_empty() && local_ips.iter().any(|ip| ip == via) {
                self_loops.push((via.to_string(), line.to_string()));
            }
        }
        if !self_loops.is_empty() {
            // Build a fix that lists every offending route + the explicit
            // `ip route del` for each, so the user can copy-paste exactly
            // what to remove. Then point at the persistent source.
            let mut bad = String::new();
            let mut del_cmds = String::new();
            for (via, line) in &self_loops {
                bad.push_str(&format!("\n  • {}", line));
                del_cmds.push_str(&format!("\n  sudo ip route del {}", line));
                let _ = via;
            }
            let total_defaults = default_route_text.lines()
                .filter(|l| l.trim().starts_with("default")).count();
            let context = if total_defaults > self_loops.len() {
                format!(
                    "\n\nThere are {} default route(s) total — at least one of them is real (e.g. your DHCP/PPPoE WAN). Removing the self-loop one(s) leaves the working route in charge.",
                    total_defaults
                )
            } else {
                "\n\nThis is your ONLY default route, so the box has no real path out. After removing it, add a WAN connection (or persist a DHCP lease on your WAN iface) so a real default route gets installed.".into()
            };
            checks.push(PreflightCheck {
                id: "default_route_self_loop",
                name: "Default route points to local IP (self-loop)",
                ok: false,
                severity: "error",
                message: format!(
                    "{} default route(s) point at this host's own IP, which the kernel rejects with ICMP host-unreachable:{}{}",
                    self_loops.len(), bad, context
                ),
                fix: Some(format!(
                    "Remove the self-loop route(s) live:{}\n\nThen find the persistent source so they don't come back on reboot. Common culprits:\n  • /etc/network/interfaces — a `gateway <local-ip>` line on a LAN-side iface (remove that line, leave `address` alone).\n  • /etc/netplan/*.yaml — a `gateway4:` or static `routes: - to: default` entry pointing at a local IP (remove it, then `sudo netplan apply`).\n  • NetworkManager — `nmcli connection show` and edit/remove the offending profile's gateway.\n\nAfter removal, run `ip route` again — only your WAN's default (DHCP / PPPoE) should remain.\n\nOr click the Fix button — WolfStack deletes them with the same `ip route del` lines.",
                    del_cmds
                )),
            });
            actions.insert("default_route_self_loop", PreflightAction {
                label: "Delete self-loop route(s)".into(),
                url: "/api/router/fix/purge-self-loop-routes".into(),
                detail: "Deletes ONLY routes whose next-hop is a local IP. Such routes can never deliver a packet, so this is bounded — Proxmox/libvirt bridges never use local-IP next-hops, so they're untouched.".into(),
                confirm: "Delete the self-loop default route(s)? This is safe — these routes can never deliver a packet, so removing them cannot make egress worse. Your WAN's real default route (if any) stays untouched.".into(),
                body: serde_json::Value::Null,
            });
        }
    }

    // 8b) Egress route resolution — `ip route get 1.1.1.1` answers
    // "if I sent to a public IP right now, which interface would the
    // kernel pick?" Cheap, generates zero traffic, and catches the
    // case where a default route exists but points to an iface without
    // an IP / a dead gateway (the route is in the table but the kernel
    // refuses to use it).
    if has_default_route {
        match std::process::Command::new("ip")
            .args(["-4", "route", "get", "1.1.1.1"])
            .output()
        {
            Ok(o) if o.status.success() => {
                let txt = String::from_utf8_lossy(&o.stdout).trim().to_string();
                let dev = txt.split_whitespace()
                    .skip_while(|t| *t != "dev")
                    .nth(1)
                    .unwrap_or("");
                if dev.is_empty() {
                    checks.push(PreflightCheck {
                        id: "egress_route",
                        name: "Egress route resolution",
                        ok: false,
                        severity: "error",
                        message: format!("`ip route get 1.1.1.1` returned no egress interface: {}", txt),
                        fix: Some("Default route exists but the kernel couldn't resolve a next-hop. Check that the WAN interface is up and has an IPv4 (`ip -4 addr`).".into()),
                    });
                } else {
                    checks.push(PreflightCheck {
                        id: "egress_route",
                        name: "Egress route resolution",
                        ok: true,
                        severity: "info",
                        message: format!("Egress via {} (kernel pick for 1.1.1.1)", dev),
                        fix: None,
                    });
                }
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
                checks.push(PreflightCheck {
                    id: "egress_route",
                    name: "Egress route resolution",
                    ok: false,
                    severity: "error",
                    message: format!("`ip route get 1.1.1.1` failed: {}", stderr),
                    fix: Some("Most often: WAN link is down. PPPoE → check `pppd` is running. DHCP → check the iface holds an IPv4. Static → check the gateway responds.".into()),
                });
            }
            Err(_) => {} // ip(8) missing — covered by other checks
        }
    }

    // 8c) Per-WAN checks for connections owned by this node. Each WAN
    // emits a link-state check (PPPoE: pppd is dialed and ppp* exists;
    // DHCP/Static: the configured iface has an IPv4) plus a MASQUERADE
    // rule check on the egress iface.
    //
    // The DHCP branch is critical for Starlink, cable modems, and any
    // ISP that doesn't need PPPoE — WolfRouter calls DHCP a passthrough
    // (the host's own dhclient/networkd owns the iface), which works
    // beautifully when the host is configured to DHCP that iface, and
    // catastrophically when it isn't. Symptom: WAN saved fine in
    // WolfRouter, no error, but the iface stays unconfigured because
    // nothing on the OS side ever sent a DHCPDISCOVER. No IP → no
    // default route → !H from the router's LAN IP on traceroute.
    // Source: networking/router/wan.rs:681-694 — the passthrough mode.
    let iface_has_ipv4 = |iface: &str| -> Option<String> {
        let out = std::process::Command::new("ip")
            .args(["-j", "-4", "addr", "show", "dev", iface])
            .output()
            .ok()?;
        if !out.status.success() { return None; }
        let arr: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).ok()?;
        for entry in arr {
            for ai in entry.get("addr_info")?.as_array()? {
                if ai.get("family").and_then(|v| v.as_str()) == Some("inet") {
                    if ai.get("scope").and_then(|v| v.as_str()) == Some("host") { continue; }
                    let ip = ai.get("local").and_then(|v| v.as_str())?;
                    return Some(ip.to_string());
                }
            }
        }
        None
    };

    for w in &local_wans {
        // Resolve egress iface + link status per mode.
        //   PPPoE: iface name is dynamic (ppp0/1/...) and only exists
        //   once pppd has dialed up. wan::pppoe_status reads the live
        //   state and returns the active iface + IP.
        //
        //   DHCP/Static: the configured physical iface IS the egress
        //   iface. "Up" here means it has a non-loopback IPv4 — for
        //   DHCP that's set by the host's DHCP client on lease, for
        //   Static by /etc/network/interfaces or equivalent.
        let mode_label = match &w.mode {
            wan::WanMode::Pppoe(_) => "PPPoE",
            wan::WanMode::Dhcp => "DHCP",
            wan::WanMode::Static(_) => "Static",
        };
        let (egress_iface, link_status) = match &w.mode {
            wan::WanMode::Pppoe(_) => match wan::pppoe_status(w) {
                Some((iface, ip)) => (Some(iface.clone()), Some(Ok(format!("PPPoE link up: {} ({})", iface, ip)))),
                None => (None, Some(Err((
                    format!(
                        "PPPoE link '{}' on {} is not up — no ppp* interface with the expected pid file.",
                        w.name, w.interface
                    ),
                    "Check pppd:\n  • `pgrep -af pppd`\n  • `journalctl -u pppd -n 50` (or `tail -n 50 /var/log/syslog | grep pppd`)\n  • Confirm ISP credentials in WolfRouter → WAN connections → Edit.".to_string(),
                )))),
            },
            wan::WanMode::Dhcp | wan::WanMode::Static(_) => match iface_has_ipv4(&w.interface) {
                Some(ip) => (Some(w.interface.clone()), Some(Ok(format!("{} link up: {} ({})", mode_label, w.interface, ip)))),
                None => (Some(w.interface.clone()), Some(Err((
                    format!(
                        "WAN '{}' ({}) on {}: interface has no IPv4 address. {}",
                        w.name, mode_label, w.interface,
                        if matches!(w.mode, wan::WanMode::Dhcp) {
                            "WolfRouter's DHCP mode is a passthrough — the host's own DHCP client (dhclient / systemd-networkd / NetworkManager) is supposed to own this iface, but nothing has given it a lease."
                        } else {
                            "Static mode is a passthrough — the host's network config is supposed to assign this iface, but no IPv4 is present."
                        }
                    ),
                    if matches!(w.mode, wan::WanMode::Dhcp) {
                        format!(
                            "Bring the iface up and request a lease manually to confirm the upstream is reachable:\n  sudo ip link set {iface} up\n  sudo dhclient -v {iface}\n\nIf that gets an IP, persist it. On Debian/Ubuntu (`/etc/network/interfaces`):\n  auto {iface}\n  iface {iface} inet dhcp\n\nOn netplan (`/etc/netplan/*.yaml`):\n  network:\n    ethernets:\n      {iface}:\n        dhcp4: true\n\nIf dhclient gets nothing, the upstream isn't handing out leases — for Starlink, check the dishy is online, the cable is plugged into the right WAN port, and the router boot order isn't racing the dishy bring-up.",
                            iface = w.interface
                        )
                    } else {
                        format!(
                            "Configure a static IP on {iface} via the host's network config. On Debian/Ubuntu (`/etc/network/interfaces`):\n  auto {iface}\n  iface {iface} inet static\n      address <CIDR>\n      gateway <gateway-ip>\n\nThen `sudo systemctl restart networking` (or `netplan apply` on netplan).",
                            iface = w.interface
                        )
                    },
                )))),
            },
        };

        if let Some(status) = link_status {
            match status {
                Ok(msg) => checks.push(PreflightCheck {
                    id: "wan_link",
                    name: "WAN link state",
                    ok: true,
                    severity: "info",
                    message: format!("WAN '{}': {}", w.name, msg),
                    fix: None,
                }),
                Err((msg, fix)) => {
                    checks.push(PreflightCheck {
                        id: "wan_link",
                        name: "WAN link state",
                        ok: false,
                        severity: "error",
                        message: msg,
                        fix: Some(fix),
                    });
                    // For DHCP-mode WANs, offer a one-click "request a
                    // lease via dhclient" — covers the Starlink boot-
                    // race trap. For Static, no auto-fix possible
                    // (operator must supply addresses). For PPPoE,
                    // the redial endpoint is the right tool.
                    match &w.mode {
                        wan::WanMode::Dhcp => {
                            actions.insert("wan_link", PreflightAction {
                                label: format!("dhclient {}", w.interface),
                                url: "/api/router/fix/dhclient".into(),
                                detail: "Brings the iface up and requests a DHCP lease. Safe — runs the same dhclient(8) the host's own networking would. Doesn't conflict with Proxmox: if Proxmox's networkd already manages this iface, this just renews the existing lease.".into(),
                                confirm: String::new(),
                                body: serde_json::json!({ "iface": &w.interface }),
                            });
                        }
                        wan::WanMode::Pppoe(_) => {
                            actions.insert("wan_link", PreflightAction {
                                label: "Re-apply WAN (redial)".into(),
                                url: format!("/api/router/fix/wan/{}/reapply", w.id),
                                detail: "Re-runs the WAN apply path: rewrites the pppd peer file and redials the link.".into(),
                                confirm: "Redial PPPoE? You'll lose the WAN link for ~5–10s while pppd reconnects.".into(),
                                body: serde_json::Value::Null,
                            });
                        }
                        wan::WanMode::Static(_) => {}
                    }
                }
            }
        }

        if let Some(iface) = egress_iface.as_deref() {
            let masq_present = std::process::Command::new("iptables")
                .args(["-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if masq_present {
                checks.push(PreflightCheck {
                    id: "wan_masquerade",
                    name: "WAN NAT (MASQUERADE)",
                    ok: true,
                    severity: "info",
                    message: format!("WAN '{}': POSTROUTING -o {} -j MASQUERADE present", w.name, iface),
                    fix: None,
                });
            } else {
                checks.push(PreflightCheck {
                    id: "wan_masquerade",
                    name: "WAN NAT (MASQUERADE)",
                    ok: false,
                    severity: "error",
                    message: format!(
                        "WAN '{}': no MASQUERADE rule on {}. \
                         Why this matters: without MASQUERADE on the egress iface, packets from your LAN leave with their original private source IP (e.g. 10.10.10.50). The upstream — your ISP / the wider internet — has no route back to that, so it drops the packet. Symptom: clients ping the router fine, ping each other fine, but `ping 1.1.1.1` from a client gets nothing.",
                        w.name, iface
                    ),
                    fix: Some(format!(
                        "WolfRouter installs this on apply — re-apply the WAN entry from WolfRouter → WAN connections → '{}' → Save. As a one-shot manual fix:\n  iptables -t nat -A POSTROUTING -o {} -j MASQUERADE\n\nOr click the Fix button — WolfStack re-runs the WAN apply path which re-installs the MASQUERADE rule.",
                        w.name, iface
                    )),
                });
                actions.insert("wan_masquerade", PreflightAction {
                    label: "Re-apply WAN".into(),
                    url: format!("/api/router/fix/wan/{}/reapply", w.id),
                    detail: "Re-runs the WAN apply path: re-installs MASQUERADE on the egress iface, rewrites pppd peer file if PPPoE.".into(),
                    confirm: String::new(),
                    body: serde_json::Value::Null,
                });
            }
        }
    }

    let has_error = checks.iter().any(|c| !c.ok && c.severity == "error");
    let has_warning = checks.iter().any(|c| !c.ok && c.severity == "warning");
    let status = if has_error { "error" } else if has_warning { "warning" } else { "ok" };

    serde_json::json!({
        "ok": !has_error,
        "status": status,
        "checks": checks,
        "actions": actions,
    })
    }).await;
    match body_result {
        Ok(json) => HttpResponse::Ok().json(json),
        Err(e) => HttpResponse::InternalServerError().body(format!("preflight task: {}", e)),
    }
}

// ─── Zones ───

#[derive(Deserialize)]
pub struct ZoneAssignRequest {
    pub node_id: String,
    pub interface: String,
    pub zone: Option<Zone>,  // None = remove
}

pub async fn assign_zone(req: HttpRequest, state: S, body: web::Json<ZoneAssignRequest>, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    // Cluster guard — refuse to set/clear a zone on a node that
    // belongs to a different cluster. This is the strict-cluster
    // isolation principle: cluster A's WolfRouter must not affect
    // cluster B's nodes.
    if let Some(resp) = cluster_guard_node_id(&state, &query, Some(&body.node_id)) { return resp; }
    // Apply the config change under the write lock, then release the
    // lock BEFORE shelling out to iptables-restore. Pre-v18.7.30 the
    // whole firewall apply ran with the write lock held — a slow
    // iptables-restore (hundreds of ms on busy boxes) stalled every
    // concurrent config.read() caller: topology polls, lease reads,
    // all the read paths. Now the lock is short-lived.
    let (ruleset_opt, zones_snapshot) = {
        let mut cfg = state.router.config.write().unwrap();
        let r = body.into_inner();
        match r.zone {
            Some(z) => cfg.zones.set(&r.node_id, &r.interface, z),
            None => cfg.zones.remove(&r.node_id, &r.interface),
        }
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        let ruleset_to_apply = if cfg.auto_apply {
            Some(firewall::build_ruleset(&cfg, &crate::agent::self_node_id()))
        } else {
            None
        };
        (ruleset_to_apply, cfg.zones.clone())
    }; // write lock dropped here
    if let Some(ruleset) = ruleset_opt {
        let _ = firewall::apply(&ruleset, false);
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(&zones_snapshot)
}

pub async fn get_zones(req: HttpRequest, state: S, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    let zones = state.router.config.read().unwrap().zones.clone();
    match cluster_node_id_set(&state, &query) {
        None => HttpResponse::Ok().json(zones),
        Some(set) => {
            // ZoneAssignments outer key is node_id. Drop entries for
            // nodes that aren't in the requested cluster.
            let filtered = ZoneAssignments {
                assignments: zones.assignments.into_iter()
                    .filter(|(node_id, _)| set.contains(node_id))
                    .collect(),
            };
            HttpResponse::Ok().json(filtered)
        }
    }
}

// ─── LAN segments ───

pub async fn list_segments(req: HttpRequest, state: S, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    let lans = state.router.config.read().unwrap().lans.clone();
    let filtered: Vec<&LanSegment> = match cluster_node_id_set(&state, &query) {
        None => lans.iter().collect(),
        Some(set) => lans.iter().filter(|l| set.contains(&l.node_id)).collect(),
    };
    HttpResponse::Ok().json(filtered)
}

pub async fn create_segment(req: HttpRequest, state: S, body: web::Json<LanSegment>, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    // Validate — no embedded newlines in any field that feeds into a
    // dnsmasq config line. See dhcp::render_config for the attack model.
    if let Err(e) = validate_segment(&body) {
        return HttpResponse::BadRequest().body(e);
    }
    if let Some(resp) = cluster_guard_node_id(&state, &query, Some(&body.node_id)) { return resp; }
    let mut segment = body.into_inner();
    if segment.id.is_empty() { segment.id = gen_id("lan"); }

    {
        let mut cfg = state.router.config.write().unwrap();
        cfg.lans.retain(|l| l.id != segment.id);
        cfg.lans.push(segment.clone());
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
    }
    // Start dnsmasq if this LAN is ours.
    if segment.node_id == crate::agent::self_node_id()
        && let Err(e) = dhcp::start(&segment) {
            return HttpResponse::InternalServerError().body(format!("dnsmasq start failed: {}", e));
        }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(&segment)
}

pub async fn update_segment(
    req: HttpRequest,
    state: S,
    path: web::Path<String>,
    body: web::Json<LanSegment>,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    if let Err(e) = validate_segment(&body) {
        return HttpResponse::BadRequest().body(e);
    }
    let id = path.into_inner();
    let updated = body.into_inner();
    if updated.id != id {
        return HttpResponse::BadRequest().body("id mismatch");
    }
    // Both the existing item AND the new node_id must be in the
    // active cluster — block re-pinning a LAN to a node in another
    // cluster, and block editing a LAN that belongs to another cluster.
    if let Some(resp) = cluster_guard_existing_lan(&state, &query, &id) { return resp; }
    if let Some(resp) = cluster_guard_node_id(&state, &query, Some(&updated.node_id)) { return resp; }
    {
        let mut cfg = state.router.config.write().unwrap();
        let idx = match cfg.lans.iter().position(|l| l.id == id) {
            Some(i) => i,
            None => return HttpResponse::NotFound().body("not found"),
        };
        cfg.lans[idx] = updated.clone();
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
    }
    if updated.node_id == crate::agent::self_node_id() {
        let _ = dhcp::start(&updated);
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(&updated)
}

pub async fn delete_segment(req: HttpRequest, state: S, path: web::Path<String>, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    if let Some(resp) = cluster_guard_existing_lan(&state, &query, &id) { return resp; }
    let removed = {
        let mut cfg = state.router.config.write().unwrap();
        let r = cfg.lans.iter().position(|l| l.id == id).map(|i| cfg.lans.remove(i));
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        r
    };
    if let Some(seg) = removed
        && seg.node_id == crate::agent::self_node_id() {
            let _ = dhcp::purge(&seg);
        }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().body("deleted")
}

pub async fn get_leases(req: HttpRequest, state: S, path: web::Path<String>) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    // Snapshot the segment owner, then drop the lock before any await.
    // Holding a std::sync::RwLock across .await would compile but would
    // stall any concurrent reader for the full RTT of the remote fetch.
    let owner_node_id = {
        let cfg = state.router.config.read().unwrap();
        match cfg.lans.iter().find(|l| l.id == id) {
            Some(s) => s.node_id.clone(),
            None => return HttpResponse::NotFound().body("LAN not found"),
        }
    };
    if owner_node_id != crate::agent::self_node_id() {
        return proxy_router_get_to_node(
            state, &owner_node_id,
            &format!("router/segments/{}/leases", id),
            "",
        ).await;
    }
    HttpResponse::Ok().json(dhcp::read_leases(&id))
}

#[derive(Deserialize)]
pub struct QueryLogToggle {
    pub enable: bool,
}

/// POST /api/router/segments/{id}/query-log
/// Toggle per-LAN dnsmasq query logging. On restart, dnsmasq re-spawns
/// with `log-queries` + a dedicated log file — every subsequent client
/// query is appended so the DNS Tools tab can show whether LAN clients
/// are actually reaching the resolver.
///
/// Debug-only — leaves a growing log file on disk while enabled. The
/// frontend is responsible for turning it off when the user is done.
pub async fn set_query_log(
    req: HttpRequest, state: S,
    path: web::Path<String>, body: web::Json<QueryLogToggle>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let enable = body.enable;

    // Flip the flag in RouterConfig + save + restart dnsmasq. Lock is
    // acquired + released before the restart so a slow dnsmasq spawn
    // doesn't block concurrent read paths (topology, list_segments).
    let lan = {
        let mut cfg = state.router.config.write().unwrap();
        let updated = {
            let seg = match cfg.lans.iter_mut().find(|l| l.id == id) {
                Some(s) => s,
                None => return HttpResponse::NotFound().body("LAN not found"),
            };
            seg.dns.query_log = enable;
            seg.clone()
        };
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(format!("save: {}", e));
        }
        updated
    };

    // Local node only: reapply the dnsmasq config. Remote nodes will
    // pick up the change from the next config replicate + restart via
    // their own dhcp::start path.
    if lan.node_id == crate::agent::self_node_id() {
        if enable {
            // Truncate any previous log so users don't mistake stale entries
            // for new activity when they re-enable.
            let log_path = format!("/var/lib/wolfstack-router/lan-{}.log", lan.id);
            let _ = std::fs::write(&log_path, "");
        }
        if let Err(e) = dhcp::start(&lan) {
            return HttpResponse::InternalServerError()
                .body(format!("restart dnsmasq: {}", e));
        }
    }

    replicate_config_to_cluster(state.clone());
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "enabled": enable,
        "message": if enable {
            "Query logging enabled — dnsmasq restarted. Try DNS from a LAN client and refresh the log panel."
        } else {
            "Query logging disabled — dnsmasq restarted without log-queries."
        },
    }))
}

/// GET /api/router/segments/{id}/query-log?lines=200
/// Return the tail of the per-LAN dnsmasq query log. Polled by the DNS
/// Tools tab so admins see queries arrive (or not) as they test from a
/// client machine.
pub async fn get_query_log(
    req: HttpRequest, state: S,
    path: web::Path<String>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    // Snapshot fields before any await — see note in get_leases.
    let (owner_node_id, query_log_enabled) = {
        let cfg = state.router.config.read().unwrap();
        match cfg.lans.iter().find(|l| l.id == id) {
            Some(s) => (s.node_id.clone(), s.dns.query_log),
            None => return HttpResponse::NotFound().body("LAN not found"),
        }
    };

    if owner_node_id != crate::agent::self_node_id() {
        // Preserve the caller's ?lines=N query so the remote node trims
        // the same amount before sending it back.
        let qs = query.get("lines")
            .map(|v| format!("lines={}", urlencoding_minimal(v)))
            .unwrap_or_default();
        return proxy_router_get_to_node(
            state, &owner_node_id,
            &format!("router/segments/{}/query-log", id),
            &qs,
        ).await;
    }
    let want_lines: usize = query.get("lines").and_then(|s| s.parse().ok()).unwrap_or(200).min(2000);
    let log_path = format!("/var/lib/wolfstack-router/lan-{}.log", id);
    let text = std::fs::read_to_string(&log_path).unwrap_or_default();
    // Only keep the last N lines — dnsmasq appends indefinitely.
    let all: Vec<&str> = text.lines().collect();
    let start = all.len().saturating_sub(want_lines);
    let tail: Vec<String> = all[start..].iter().map(|s| s.to_string()).collect();

    // Count unique client IPs seen in this tail — a quick "did anyone
    // actually query us?" signal the frontend can highlight.
    let mut unique_clients = std::collections::BTreeSet::new();
    for line in &tail {
        // dnsmasq query lines look like:
        //   "... dnsmasq[1234]: query[A] example.com from 192.168.10.42"
        if let Some(idx) = line.rfind(" from ") {
            let rest = &line[idx + 6..];
            let client = rest.split_whitespace().next().unwrap_or("").trim();
            if !client.is_empty() { unique_clients.insert(client.to_string()); }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "enabled": query_log_enabled,
        "lines": tail,
        "total_entries": all.len(),
        "unique_clients": unique_clients.into_iter().collect::<Vec<_>>(),
        "log_path": log_path,
    }))
}

// ─── Firewall rules ───

pub async fn list_rules(req: HttpRequest, state: S, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    let rules = state.router.config.read().unwrap().rules.clone();
    let filtered: Vec<&FirewallRule> = match cluster_node_id_set(&state, &query) {
        None => rules.iter().collect(),
        // Strict cluster isolation: when a cluster filter is active,
        // ONLY show rules pinned to a node in that cluster. Rules
        // with node_id=None ("legacy global, applies everywhere")
        // are hidden — they would otherwise leak across cluster
        // views since they apply to nodes the operator isn't
        // currently managing. Operators with legacy global rules
        // need to re-pin them to a specific node from the WolfRouter
        // → Firewall tab. Adam Cogswell 2026-04-29: "firewall rules
        // should be cluster only".
        Some(set) => rules.iter()
            .filter(|r| match &r.node_id {
                None => false,
                Some(nid) => set.contains(nid),
            })
            .collect(),
    };
    HttpResponse::Ok().json(filtered)
}

pub async fn create_rule(req: HttpRequest, state: S, body: web::Json<FirewallRule>, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    if let Some(resp) = cluster_guard_node_id(&state, &query, body.node_id.as_deref()) { return resp; }
    let mut rule = body.into_inner();
    if rule.id.is_empty() { rule.id = gen_id("rule"); }

    // Build ruleset under the write lock, apply OUTSIDE. See assign_zone
    // for the rationale — iptables-restore can take hundreds of ms
    // and should not starve config.read() callers (topology polls,
    // lease reads) that whole time.
    let ruleset_opt = {
        let mut cfg = state.router.config.write().unwrap();
        let next_order = cfg.rules.iter().map(|r| r.order).max().unwrap_or(-1) + 1;
        if rule.order == 0 { rule.order = next_order; }
        cfg.rules.retain(|r| r.id != rule.id);
        cfg.rules.push(rule.clone());
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        if cfg.auto_apply {
            Some(firewall::build_ruleset(&cfg, &crate::agent::self_node_id()))
        } else { None }
    };
    if let Some(ruleset) = ruleset_opt
        && let Err(e) = firewall::apply(&ruleset, false) {
            return HttpResponse::InternalServerError().body(format!("firewall apply failed: {}", e));
        }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(&rule)
}

pub async fn update_rule(
    req: HttpRequest,
    state: S,
    path: web::Path<String>,
    body: web::Json<FirewallRule>,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let updated = body.into_inner();
    if updated.id != id {
        return HttpResponse::BadRequest().body("id mismatch");
    }
    if let Some(resp) = cluster_guard_existing_rule(&state, &query, &id) { return resp; }
    if let Some(resp) = cluster_guard_node_id(&state, &query, updated.node_id.as_deref()) { return resp; }
    let ruleset_opt = {
        let mut cfg = state.router.config.write().unwrap();
        let idx = match cfg.rules.iter().position(|r| r.id == id) {
            Some(i) => i,
            None => return HttpResponse::NotFound().body("not found"),
        };
        cfg.rules[idx] = updated.clone();
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        if cfg.auto_apply {
            Some(firewall::build_ruleset(&cfg, &crate::agent::self_node_id()))
        } else { None }
    };
    if let Some(ruleset) = ruleset_opt {
        let _ = firewall::apply(&ruleset, false);
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(&updated)
}

pub async fn delete_rule(req: HttpRequest, state: S, path: web::Path<String>, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    if let Some(resp) = cluster_guard_existing_rule(&state, &query, &id) { return resp; }
    let ruleset_opt = {
        let mut cfg = state.router.config.write().unwrap();
        cfg.rules.retain(|r| r.id != id);
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        if cfg.auto_apply {
            Some(firewall::build_ruleset(&cfg, &crate::agent::self_node_id()))
        } else { None }
    };
    if let Some(ruleset) = ruleset_opt {
        let _ = firewall::apply(&ruleset, false);
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().body("deleted")
}

#[derive(Deserialize)]
pub struct ReorderRequest { pub order: Vec<String> }

pub async fn reorder_rules(req: HttpRequest, state: S, body: web::Json<ReorderRequest>) -> HttpResponse {
    auth_or_return!(req, state);
    let r = body.into_inner();
    let ruleset_opt = {
        let mut cfg = state.router.config.write().unwrap();
        let mut order_map: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
        for (i, id) in r.order.iter().enumerate() {
            order_map.insert(id.clone(), i as i32);
        }
        for rule in &mut cfg.rules {
            if let Some(o) = order_map.get(&rule.id) {
                rule.order = *o;
            }
        }
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        if cfg.auto_apply {
            Some(firewall::build_ruleset(&cfg, &crate::agent::self_node_id()))
        } else { None }
    };
    if let Some(ruleset) = ruleset_opt {
        let _ = firewall::apply(&ruleset, false);
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().body("reordered")
}

pub async fn test_rules(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    let cfg = state.router.config.read().unwrap();
    let issues = firewall::validate(&cfg, &crate::agent::self_node_id());
    let ruleset = firewall::build_ruleset(&cfg, &crate::agent::self_node_id());
    HttpResponse::Ok().json(serde_json::json!({
        "ok": issues.is_empty(),
        "issues": issues.iter().map(|(id, msg)| serde_json::json!({"id": id, "message": msg})).collect::<Vec<_>>(),
        "preview": ruleset,
    }))
}

pub async fn apply_rules_now(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    let cfg = state.router.config.read().unwrap();
    let ruleset = firewall::build_ruleset(&cfg, &crate::agent::self_node_id());

    // Pre-flight (Level 3) — parse the proposed ruleset and refuse
    // anything that would block the current session from reaching the
    // WolfStack management ports. Stops the operator-shoots-own-foot
    // case where an INPUT DROP rule matches the session's peer IP on
    // :8553 and the first real symptom is the browser going silent.
    //
    // Peer-IP resolution: we take the TCP peer by default. If that's
    // loopback (dashboard is behind an nginx/Caddy reverse proxy), we
    // fall back to the left-most X-Forwarded-For entry. Trusting XFF
    // for auth would be wrong, but this is a SAFETY check — the only
    // way a forged XFF hurts is if an attacker can forge the header
    // AND has already been authenticated AND is trying to apply rules
    // that lock out a *different* admin, in which case the analyser
    // would flag spurious concerns (the attacker's claimed IP) instead
    // of the real one. False positive, not an exploit path.
    let peer_ip = {
        // to_canonical: dual-stack [::] reports v4 peers (and proxied
        // loopback) as ::ffff:a.b.c.d — the loopback match and the v4
        // CIDR comparison in the analyser both need the plain v4 form.
        let raw = req.peer_addr().map(|a| a.ip().to_canonical().to_string());
        let is_loopback = matches!(raw.as_deref(), Some("127.0.0.1") | Some("::1"));
        if is_loopback {
            req.headers().get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or(raw)
        } else {
            raw
        }
    };
    let mgmt_ports: Vec<u16> = {
        let pc = crate::ports::PortConfig::load();
        vec![pc.api, pc.inter_node]
    };
    let mut concerns = firewall::analyse_ruleset_against_session(
        &ruleset,
        peer_ip.as_deref(),
        &mgmt_ports,
    );
    // Note in the concerns if the source IP came from XFF (proxied
    // deployment) so operators can verify the check was against the
    // right identity. Harmless to add even when there are no other
    // concerns: if the list is empty we don't emit this.
    if !concerns.is_empty() {
        if let Some("127.0.0.1") | Some("::1") = req.peer_addr().map(|a| a.ip().to_canonical().to_string()).as_deref() {
            concerns.push(format!(
                "(note: your TCP peer is loopback — evaluated against X-Forwarded-For = {}. \
                 If you run a reverse proxy, verify the right admin IP was checked.)",
                peer_ip.as_deref().unwrap_or("<unknown>"),
            ));
        }
        return HttpResponse::BadRequest().json(serde_json::json!({
            "applied": false,
            "error": "Pre-flight refused the ruleset — it would lock your current session out of this node.",
            "concerns": concerns,
            "hint": "Edit the offending rules (add a narrower -s scope that excludes your admin subnet, \
                     or remove the rule entirely) and re-apply. You can bypass the check only by editing \
                     rules from a node whose session source isn't affected.",
        }));
    }
    let safe_mode_seconds = cfg.safe_mode_seconds;
    drop(cfg);
    match firewall::apply(&ruleset, false) {
        Ok(prev) => {
            *state.router.last_applied_rules.write().unwrap() = Some(prev.clone());
            // Register with the Level-2 danger framework so the UI
            // gets a unified "Keep / Rollback now" banner across all
            // dangerous ops. TTL defaults to the existing safe_mode_seconds
            // value (30s) if set, else 120s — same envelope whether
            // the old safe-mode is on or off.
            let ttl = if safe_mode_seconds > 0 { safe_mode_seconds as u64 } else { 120 };
            let prev_for_rollback = prev.clone();
            let danger_id = crate::danger::schedule(
                "firewall_apply",
                "WolfRouter firewall rules applied",
                ttl,
                Box::new(move || {
                    super::firewall::revert(&prev_for_rollback)
                        .map(|_| "Firewall reverted to previous ruleset.".to_string())
                }),
            );
            // H5 fix: store the danger_id so confirm_rules can
            // cancel the timer via crate::danger::confirm. Without
            // this, the operator clicked Confirm, the legacy
            // rollback_deadline was cleared, but the danger
            // framework timer kept running and reverted the rules
            // ~30s later anyway.
            *state.router.firewall_apply_danger_id.write().unwrap() = Some(danger_id.clone());
            // Keep the legacy safe_mode deadline in step — when the
            // danger framework rolls back, the legacy path sees a
            // re-applied ruleset and no-ops. If the operator confirms
            // via the danger banner, we also clear the legacy deadline
            // so the old watcher doesn't double-revert.
            if safe_mode_seconds > 0 {
                let deadline = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
                    + safe_mode_seconds as u64;
                *state.router.rollback_deadline.write().unwrap() = Some(deadline);
            }
            HttpResponse::Ok().json(serde_json::json!({
                "applied": true,
                "rollback_in_seconds": ttl,
                "danger_id": danger_id,
                "confirm_required": true,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().body(e),
    }
}

pub async fn confirm_rules(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    // H5 fix: cancel the danger-framework rollback timer in addition
    // to clearing the legacy deadline. Pre-fix the timer kept ticking
    // and reverted the rules ~30 seconds after the operator clicked
    // Confirm. Take the ID under lock, drop the lock, then call
    // danger::confirm — the danger API takes an exclusive lock of
    // its own and we don't want to nest.
    let danger_id = state.router.firewall_apply_danger_id.write().unwrap().take();
    let raced_with_tick = if let Some(id) = danger_id {
        // H5-TTL-RACE: danger::confirm() returns Err if the op was
        // already rolled back by the background tick (the op status
        // transitioned to "rolled_back" between our take() above and
        // confirm(&id) here). Pre-fix that Err was silently discarded
        // and the operator saw "confirmed" while the firewall was
        // actually back to the old rules. Surface this as a 409 so
        // the operator knows the rules they were trying to keep have
        // already been reverted.
        crate::danger::confirm(&id).is_err()
    } else {
        false
    };
    *state.router.rollback_deadline.write().unwrap() = None;
    if raced_with_tick {
        HttpResponse::Conflict().json(serde_json::json!({
            "error": "rules were already reverted by the rollback timer before \
                      you confirmed. The cluster is back on the previous ruleset.",
            "status": "reverted-before-confirm",
        }))
    } else {
        HttpResponse::Ok().body("confirmed")
    }
}

// ─── Connections & Logs ───

pub async fn list_connections(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    // C4 fix: `conntrack -L` on a busy firewall blocks 100-500ms.
    // Offload to a blocking pool thread so the actix worker can
    // service other requests in the meantime.
    let result = web::block(|| {
        std::process::Command::new("conntrack").args(["-L"]).output()
    }).await.unwrap_or_else(|e|
        Err(std::io::Error::other(format!("blocking task: {}", e)))
    );
    let out = match result {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
            return HttpResponse::Ok().json(serde_json::json!({
                "rows": [],
                "error": format!("conntrack failed (exit {}): {}",
                    o.status.code().unwrap_or(-1),
                    if stderr.is_empty() { "no output".into() } else { stderr })
            }));
        }
        Err(e) => {
            return HttpResponse::Ok().json(serde_json::json!({
                "rows": [],
                "error": format!("couldn't run 'conntrack' — {} (install the 'conntrack' package?)", e)
            }));
        }
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut rows = Vec::new();
    // Default format (no -o extended): the line begins with the L4
    // protocol name, then a numeric proto id, timeout, state, then the
    // tuple key=value tokens. Example:
    //   tcp      6 431999 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=44321 dport=80 ...
    for line in text.lines().take(500) {
        let mut r = serde_json::Map::new();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 { continue; }
        r.insert("proto".into(), serde_json::Value::String(parts[0].into()));
        // parts[1] = numeric proto id (skip), parts[2] = timeout
        r.insert("timeout".into(), serde_json::Value::String(parts[2].into()));
        // State only present for tcp; UDP lines start key=value at parts[3].
        let mut start_kv = 3usize;
        if !parts[3].contains('=') {
            r.insert("state".into(), serde_json::Value::String(parts[3].into()));
            start_kv = 4;
        }
        for part in &parts[start_kv..] {
            if let Some((k, v)) = part.split_once('=') {
                // Only insert the FIRST occurrence of each key so we
                // capture the original tuple (src/dst/sport/dport),
                // not the reply tuple that conntrack appends.
                r.entry(k.to_string()).or_insert(serde_json::Value::String(v.to_string()));
            }
        }
        rows.push(serde_json::Value::Object(r));
    }
    HttpResponse::Ok().json(serde_json::json!({ "rows": rows }))
}

/// Firewall log viewer. Reads kernel messages matching our NFLOG prefix
/// via journalctl (dmesg is not reliably available on all distros).
pub async fn list_firewall_logs(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    // C4 fix: journalctl with -n 300 can take meaningful time on
    // busy hosts. Offload.
    let out = web::block(|| {
        std::process::Command::new("journalctl")
            .args(["-k", "--no-pager", "-n", "300", "-g", "wolfrouter"])
            .output()
    }).await.unwrap_or_else(|e|
        Err(std::io::Error::other(format!("blocking task: {}", e)))
    );
    let lines: Vec<String> = match out {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).lines().map(|s| s.to_string()).collect()
        }
        _ => vec![],
    };
    HttpResponse::Ok().json(lines)
}

// ─── Integration: surface things WolfStack already manages ───

/// Read-only view of WolfStack-managed networking primitives that
/// WolfRouter doesn't own but the user needs to see in one place:
///   • IP mappings (DNAT) — configured in the per-server Networking page
///   • WolfNet status + peers — managed by the wolfnet daemon
///
/// The intent is integration, not duplication. Users keep editing IP
/// mappings on the existing page; WolfRouter just shows them here so
/// the firewall view doesn't lie about what traffic actually flows.
pub async fn get_managed_overview(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);

    // IP mappings (DNAT entries owned by networking::mod.rs).
    let ip_mappings = crate::networking::list_ip_mappings();

    // WolfNet peers — best-effort. If the file doesn't exist (wolfnet
    // not installed) we simply return null and the UI hides the panel.
    let wolfnet_status: serde_json::Value = std::fs::read_to_string("/var/run/wolfnet/status.json")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::Value::Null);

    HttpResponse::Ok().json(serde_json::json!({
        "ip_mappings": ip_mappings,
        "wolfnet_status": wolfnet_status,
    }))
}

/// Snapshot of the host's current network reality — what's actually
/// running, regardless of who configured it. WolfRouter renders this
/// in the firewall / LANs / leases tabs so the user never sees a blank
/// page; they see what's already on the host plus anything WolfRouter
/// has added on top.
pub async fn get_host_snapshot(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);

    // C6 fix: iptables-save (twice), ps (via list_dnsmasq_processes),
    // and a filesystem walk (via list_lease_files) all block. Bundle
    // into one blocking task so the actix worker is free during.
    let snapshot = web::block(|| {
        let firewall_filter = run_capture(&["iptables-save", "-t", "filter"]);
        let firewall_nat    = run_capture(&["iptables-save", "-t", "nat"]);
        let parsed_filter   = parse_iptables(&firewall_filter, "filter");
        let parsed_nat      = parse_iptables(&firewall_nat, "nat");
        let dnsmasq_processes = list_dnsmasq_processes();
        let lease_files = list_lease_files();
        serde_json::json!({
            "firewall": {
                "filter": parsed_filter,
                "nat": parsed_nat,
                "raw_filter_lines": firewall_filter.lines().count(),
                "raw_nat_lines": firewall_nat.lines().count(),
            },
            "dhcp": {
                "dnsmasq_processes": dnsmasq_processes,
                "lease_files": lease_files,
            },
        })
    }).await.unwrap_or_else(|e| serde_json::json!({
        "error": format!("host snapshot task: {}", e),
    }));
    HttpResponse::Ok().json(snapshot)
}

fn run_capture(args: &[&str]) -> String {
    std::process::Command::new(args[0])
        .args(&args[1..])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// Parse `iptables-save` output into structured rule rows. Skips
/// chain definitions (`:CHAIN ACCEPT [0:0]`) and table headers — only
/// `-A CHAIN <args>` lines become rows. Tags each rule with its
/// "owner" by sniffing the comment / chain name (Docker, LXC,
/// WolfStack, WolfRouter, manual).
fn parse_iptables(text: &str, table: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with('*')
            || l.starts_with(':') || l == "COMMIT" {
            continue;
        }
        if !l.starts_with("-A ") { continue; }
        // Extract chain name (first token after -A)
        let rest = &l[3..];
        let chain = rest.split_whitespace().next().unwrap_or("").to_string();
        // Detect owner from chain name + comment
        let owner = if chain.starts_with("DOCKER") || chain == "FORWARD" && l.contains("docker") {
            "docker"
        } else if chain.contains("LXC") || l.contains("lxc") {
            "lxc"
        } else if chain.starts_with("WOLFROUTER") {
            "wolfrouter"
        } else if l.contains("wolfstack-") {
            "wolfstack"
        } else if chain == "INPUT" || chain == "FORWARD" || chain == "OUTPUT"
                  || chain == "PREROUTING" || chain == "POSTROUTING" {
            "system"
        } else {
            "user"
        };
        out.push(serde_json::json!({
            "table": table,
            "chain": chain,
            "owner": owner,
            "raw": l,
        }));
    }
    out
}

/// Find all dnsmasq processes running on the host. Each entry includes
/// PID and the config file from the command line so the UI can group
/// instances by purpose.
fn list_dnsmasq_processes() -> Vec<serde_json::Value> {
    let out = std::process::Command::new("ps")
        .args(["-eo", "pid,args"])
        .output()
        .ok();
    let text = match out {
        Some(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return vec![],
    };
    let mut procs = Vec::new();
    for line in text.lines().skip(1) {
        let line = line.trim();
        if !line.contains("dnsmasq") { continue; }
        // Skip the grep itself if anyone added it
        if line.contains("grep") { continue; }
        let mut parts = line.splitn(2, char::is_whitespace);
        let pid = parts.next().unwrap_or("").to_string();
        let cmd = parts.next().unwrap_or("").to_string();
        // Pull --conf-file=... or -C ... if present
        let conf_file = cmd.split_whitespace().find_map(|tok| {
            tok.strip_prefix("--conf-file=").map(|rest| rest.to_string())
        }).unwrap_or_default();
        let interface = cmd.split_whitespace().find_map(|tok| {
            tok.strip_prefix("--interface=").map(|s| s.to_string())
        }).unwrap_or_default();
        procs.push(serde_json::json!({
            "pid": pid,
            "command": cmd,
            "config_file": conf_file,
            "interface": interface,
        }));
    }
    procs
}

/// Lease files from common locations: WolfRouter's own dir, system
/// dnsmasq, ISC DHCPD (dhclient), dhcpcd. Each returned entry carries
/// a `format` tag so the frontend knows whether to render the leases
/// table ("dnsmasq"), the client-lease block list ("dhclient"), or
/// just the file path ("unknown").
///
/// Tagging rather than a single parser matters because dnsmasq and
/// dhclient use wildly different formats — feeding a dhclient file
/// through the dnsmasq parser produces garbage columns (date-as-IP,
/// weekday-number-as-MAC, etc) that's actively misleading.
fn list_lease_files() -> Vec<serde_json::Value> {
    let candidates = [
        "/var/lib/wolfstack-router",
        "/var/lib/misc",         // system dnsmasq default
        "/var/lib/dnsmasq",
        "/var/lib/dhcp",         // ISC DHCPD client + server
        "/run",                   // legacy WolfStack VM TAP DHCP
    ];
    let mut out = Vec::new();
    for dir in &candidates {
        let entries = match std::fs::read_dir(dir) { Ok(e) => e, Err(_) => continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.ends_with(".leases") && !name.contains("lease") { continue; }
            let path_str = path.to_string_lossy().to_string();
            let content = std::fs::read_to_string(&path).unwrap_or_default();

            // Format detection — dhclient writes `lease {` blocks with
            // `fixed-address ...;` lines; dnsmasq writes flat
            // whitespace-separated records. Match on the cheapest
            // signal first so a big dnsmasq file doesn't pay for a
            // scan it doesn't need.
            let looks_dhclient = content.contains("lease {") || content.contains("fixed-address");
            let (format, leases) = if looks_dhclient {
                ("dhclient", parse_dhclient_leases(&content))
            } else {
                let parsed = parse_dnsmasq_leases(&content);
                if parsed.is_empty() && !content.trim().is_empty() {
                    ("unknown", parsed)
                } else {
                    ("dnsmasq", parsed)
                }
            };
            out.push(serde_json::json!({
                "path": path_str,
                "format": format,
                "leases": leases,
            }));
        }
    }
    out
}

/// Parse a dnsmasq lease file. Each line is `expires mac ip host client_id`;
/// reject records whose "mac" field doesn't look like a MAC so a mis-classified
/// file doesn't smuggle garbage rows past the format gate.
fn parse_dnsmasq_leases(content: &str) -> Vec<serde_json::Value> {
    content.lines().filter_map(|l| {
        let parts: Vec<&str> = l.split_whitespace().collect();
        if parts.len() < 4 { return None; }
        // MAC plausibility check: two-hex-two-hex pattern, five colons.
        if !looks_like_mac(parts[1]) { return None; }
        Some(serde_json::json!({
            "expires": parts[0],
            "mac": parts[1],
            "ip": parts[2],
            "hostname": if parts[3] == "*" { "" } else { parts[3] },
        }))
    }).collect()
}

/// Parse an ISC dhclient `*.leases` file. Extracts one entry per
/// `lease { ... }` block with the IP, server, interface, and expiry
/// — enough for the "leases discovered on this host" panel to show
/// meaningful content instead of a garbled table.
fn parse_dhclient_leases(content: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let mut in_block = false;
    let mut cur: Option<(String, String, String, String)> = None;
    // tuple: (iface, ip, server, expire)
    for raw in content.lines() {
        let line = raw.trim();
        if line.starts_with("lease {") {
            in_block = true;
            cur = Some((String::new(), String::new(), String::new(), String::new()));
            continue;
        }
        if !in_block { continue; }
        if line.starts_with('}') {
            if let Some((iface, ip, server, expire)) = cur.take()
                && !ip.is_empty() {
                    out.push(serde_json::json!({
                        "interface": iface, "ip": ip, "server": server, "expires": expire,
                    }));
                }
            in_block = false;
            continue;
        }
        let Some(rec) = cur.as_mut() else { continue };
        // Strip trailing semicolon + the usual `key "value";` or `key value;` patterns.
        let line = line.trim_end_matches(';');
        if let Some(rest) = line.strip_prefix("interface ") {
            rec.0 = rest.trim().trim_matches('"').to_string();
        } else if let Some(rest) = line.strip_prefix("fixed-address ") {
            rec.1 = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("option dhcp-server-identifier ") {
            rec.2 = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("expire ") {
            // "expire 4 2026/04/09 15:35:30" — keep just the date+time bit.
            let parts: Vec<&str> = rest.splitn(2, ' ').collect();
            rec.3 = parts.get(1).map(|s| s.trim().to_string()).unwrap_or_default();
        }
    }
    out
}

fn looks_like_mac(s: &str) -> bool {
    // Six hex pairs separated by colons. dnsmasq always emits this form.
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 { return false; }
    parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Live packet capture (Wireshark-style). Spawns `tcpdump` on the
/// requested interface with an optional BPF filter, captures up to N
/// packets (or until the timeout fires), returns the parsed lines.
///
/// Security:
///   • Auth required (cookie or cluster secret).
///   • Interface name validated against [a-zA-Z0-9._-] — no shell
///     metacharacters can leak into the spawned process.
///   • BPF filter is passed as a single argv token to tcpdump (not
///     through a shell), so tcpdump's own parser sees it. tcpdump
///     parses BPF, not arbitrary commands; misuse = capture errors,
///     not RCE. Filter is also length-capped at 200 chars.
///   • Hard timeout via tokio::time::timeout so a runaway capture
///     can't consume resources indefinitely.
#[derive(Deserialize, Clone, Serialize)]
pub struct CaptureRequest {
    pub iface: String,
    #[serde(default)]
    pub filter: String,
    #[serde(default = "default_capture_count")]
    pub count: u32,
    /// Optional capture timeout in seconds (default 30, max 120).
    #[serde(default = "default_capture_timeout")]
    pub timeout_seconds: u64,
    /// Target cluster node id. If unset or matches self_node_id,
    /// runs locally. Otherwise the request is proxied to that node
    /// via the cluster secret so users can capture from any rack.
    #[serde(default)]
    pub node_id: Option<String>,
}
fn default_capture_count() -> u32 { 100 }
fn default_capture_timeout() -> u64 { 30 }

pub async fn packet_capture(
    req: HttpRequest,
    state: S,
    body: web::Json<CaptureRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let r = body.into_inner();

    // Cluster proxy: if the user picked a remote node, forward the
    // capture request to that node's WolfStack via the cluster secret.
    let self_id = crate::agent::self_node_id();
    if let Some(target) = r.node_id.as_ref()
        && !target.is_empty() && target != &self_id {
            let nodes = state.cluster.get_all_nodes();
            let target_node = match nodes.into_iter().find(|n| &n.id == target) {
                Some(n) => n,
                None => return HttpResponse::NotFound().body(format!("node '{}' not found in cluster", target)),
            };
            let secret = state.cluster_secret.clone();
            // Strip node_id from the proxied body so the remote node
            // doesn't recursively proxy back to us if a misconfigured
            // self_id mismatch happens.
            let mut proxy_body = r.clone();
            proxy_body.node_id = None;
            // v23.12: HTTPS-first chain via build_node_urls.
            let target_host = resolve_node_address(&target_node.address);
            let urls = crate::api::build_node_urls(&target_host, target_node.port, "/api/router/capture");
            // Shared pool — see ROUTER_RPC_CLIENT. Per-request timeout
            // below (user-controlled capture window + 10s slack)
            // replaces the client-level timeout that used to be set
            // per call.
            let client = &*ROUTER_RPC_CLIENT;
            let proxy_timeout = std::time::Duration::from_secs(r.timeout_seconds + 10);
            for url in &urls {
                match client.post(url)
                    .peer_auth(&secret)
                    .timeout(proxy_timeout)
                    .json(&proxy_body)
                    .send().await
                {
                    Ok(resp) if resp.status().is_success() => {
                        let val: serde_json::Value = resp.json().await.unwrap_or(serde_json::json!({}));
                        return HttpResponse::Ok().json(val);
                    }
                    Ok(resp) => {
                        let txt = resp.text().await.unwrap_or_default();
                        return HttpResponse::Ok().json(serde_json::json!({
                            "lines": [], "error": format!("remote node returned {}: {}", target_node.id, txt)
                        }));
                    }
                    Err(_) => continue,  // try next URL
                }
            }
            return HttpResponse::Ok().json(serde_json::json!({
                "lines": [], "error": format!("couldn't reach node '{}' (tried HTTPS then HTTP)", target_node.id)
            }));
        }

    // Interface allowlist: alnum + . _ -. Any other character means a
    // shell metachar attempt or an unsupported iface name; reject.
    if r.iface.is_empty() || r.iface.len() > 32
        || !r.iface.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    {
        return HttpResponse::BadRequest().body("invalid interface name");
    }
    if r.filter.len() > 200 {
        return HttpResponse::BadRequest().body("filter too long (max 200 chars)");
    }
    let count = r.count.clamp(1, 5000);
    let timeout = std::time::Duration::from_secs(r.timeout_seconds.clamp(1, 120));

    let mut args: Vec<String> = vec![
        "-nn".into(), "-l".into(),
        "-i".into(), r.iface.clone(),
        "-c".into(), count.to_string(),
        "-tttt".into(),  // human-readable timestamp
    ];
    if !r.filter.trim().is_empty() {
        args.push(r.filter.trim().to_string());
    }

    // Run tcpdump with timeout. Output is captured wholesale — for a
    // live-streaming variant we'd need SSE; this MVP is "give me N
    // packets that match".
    let cmd = tokio::process::Command::new("tcpdump")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    let output = match tokio::time::timeout(timeout, cmd).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            // Distinguish "tcpdump isn't installed" from other spawn
            // failures (permission denied, etc.) so the frontend can
            // show an inline install button — same convention as
            // /api/traceroute. The CAP_NET_RAW hint belongs only on
            // the privilege-error branch; mixing it into the missing
            // branch is noise.
            let is_missing = e.kind() == std::io::ErrorKind::NotFound
                || e.raw_os_error() == Some(2 /* ENOENT */);
            let install_command = if is_missing {
                let distro = crate::installer::detect_distro();
                if matches!(distro, crate::installer::DistroFamily::Unknown) {
                    None
                } else {
                    let (mgr, args) = crate::installer::pkg_install_cmd(distro);
                    Some(format!("sudo {} {} tcpdump", mgr, args))
                }
            } else { None };
            return HttpResponse::Ok().json(serde_json::json!({
                "lines": [],
                "error": if is_missing {
                    "tcpdump isn't installed on this host. Click the button below to install it, or run the install manually.".to_string()
                } else {
                    format!("couldn't run 'tcpdump' — {} (the WolfStack binary needs CAP_NET_RAW or root to capture)", e)
                },
                "missing_tool": if is_missing { Some("tcpdump") } else { None },
                "install_package": if is_missing { Some("tcpdump") } else { None },
                "install_command": install_command,
            }));
        }
        Err(_) => {
            return HttpResponse::Ok().json(serde_json::json!({
                "lines": [], "error": format!("capture timed out after {}s with fewer than {} packets matching", r.timeout_seconds, count),
            }));
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let lines: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();

    if lines.is_empty() && !output.status.success() {
        return HttpResponse::Ok().json(serde_json::json!({
            "lines": [],
            "error": format!("tcpdump exited {}: {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()),
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "lines": lines,
        "count": lines.len(),
        "iface": r.iface,
        "filter": r.filter,
    }))
}

/// Best-effort install of a network tool when WolfRouter detects it's
/// missing (currently used for tcpdump and conntrack). Detects the
/// host's package manager and runs the appropriate install command.
/// Requires WolfStack to be running as root or via sudo without
/// password — typical for managed appliances.
///
/// Allowlist of tool names — keeps the package name parameter from
/// becoming a shell-injection foothold.
#[derive(Deserialize)]
pub struct InstallToolRequest { pub tool: String }

pub async fn install_tool(
    req: HttpRequest,
    state: S,
    body: web::Json<InstallToolRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let r = body.into_inner();

    // Allowlist: only tools WolfRouter actually uses. Maps tool name
    // → package name (often identical, but e.g. some distros split).
    let pkg = match r.tool.as_str() {
        "tcpdump"   => "tcpdump",
        "conntrack" => "conntrack",
        "iptables"  => "iptables",
        "dnsmasq"   => "dnsmasq",
        _ => return HttpResponse::BadRequest().body(
            "tool must be one of: tcpdump, conntrack, iptables, dnsmasq"
        ),
    };

    // Already installed? Short-circuit with a friendly message.
    if std::process::Command::new("which").arg(pkg).status()
        .map(|s| s.success()).unwrap_or(false)
    {
        return HttpResponse::Ok().json(serde_json::json!({
            "success": true, "message": format!("'{}' is already installed", pkg)
        }));
    }

    // Detect package manager. Order matters — apt-get exists on
    // Debian-derived (most common), then dnf, yum, pacman, zypper.
    let install: Option<(&str, Vec<&str>)> = if which("apt-get") {
        Some(("apt-get", vec!["install", "-y", pkg]))
    } else if which("dnf") {
        Some(("dnf", vec!["install", "-y", pkg]))
    } else if which("yum") {
        Some(("yum", vec!["install", "-y", pkg]))
    } else if which("pacman") {
        // pacman wants --noconfirm to skip prompts and -Sy to refresh
        Some(("pacman", vec!["-Sy", "--noconfirm", pkg]))
    } else if which("zypper") {
        Some(("zypper", vec!["install", "-y", pkg]))
    } else {
        None
    };
    let (cmd, args) = match install {
        Some(p) => p,
        None => return HttpResponse::Ok().json(serde_json::json!({
            "success": false,
            "error": format!("no supported package manager found — install '{}' manually", pkg)
        })),
    };

    let out = match tokio::process::Command::new(cmd)
        .args(&args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output().await
    {
        Ok(o) => o,
        Err(e) => return HttpResponse::Ok().json(serde_json::json!({
            "success": false,
            "error": format!("couldn't run {}: {}", cmd, e),
        })),
    };

    if out.status.success() {
        HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("installed '{}' via {}", pkg, cmd),
        }))
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        HttpResponse::Ok().json(serde_json::json!({
            "success": false,
            "error": format!("{} install failed: {}", cmd, stderr),
        }))
    }
}

fn which(cmd: &str) -> bool {
    std::process::Command::new("which").arg(cmd).status()
        .map(|s| s.success()).unwrap_or(false)
}

// ─── WAN connections (DHCP / Static / PPPoE) ───

pub async fn list_wan(req: HttpRequest, state: S, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    let conns: Vec<wan::WanConnection> = state.router.config.read().unwrap().wan_connections.clone();
    let cluster_set = cluster_node_id_set(&state, &query);
    // Mask passwords on the way out — never roundtrip plaintext to UI.
    // Filter by cluster: each WAN is pinned to a specific node, so we
    // keep only those whose node is in the active cluster.
    let masked: Vec<wan::WanConnection> = conns.into_iter()
        .filter(|c| match &cluster_set {
            None => true,
            Some(set) => set.contains(&c.node_id),
        })
        .map(|c| {
            let mut clone = c;
            if let wan::WanMode::Pppoe(ref mut p) = clone.mode
                && !p.password.is_empty() { p.password = "***".into(); }
            clone
        })
        .collect();
    HttpResponse::Ok().json(masked)
}

pub async fn create_wan(req: HttpRequest, state: S, body: web::Json<wan::WanConnection>, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    if let Some(resp) = cluster_guard_node_id(&state, &query, Some(&body.node_id)) { return resp; }
    let mut conn = body.into_inner();
    if conn.id.is_empty() { conn.id = gen_id("wan"); }
    if let Err(e) = wan::validate(&conn) {
        return HttpResponse::BadRequest().body(e);
    }
    {
        let mut cfg = state.router.config.write().unwrap();
        cfg.wan_connections.retain(|c| c.id != conn.id);
        cfg.wan_connections.push(conn.clone());
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
    }
    if conn.node_id == crate::agent::self_node_id() || conn.node_id.is_empty() {
        // PPPoE prerequisite: ppp + pppoe packages.
        if matches!(conn.mode, wan::WanMode::Pppoe(_)) {
            ensure_pppoe_installed_async();
        }
        // C5 fix: wan::apply → pppoe_apply → pppoe_stop calls
        // std::thread::sleep up to 56 × 250ms = 14 seconds. Offload
        // to the blocking pool so the actix worker isn't pinned.
        let conn_clone = conn.clone();
        let res = web::block(move || wan::apply(&conn_clone)).await;
        match res {
            Ok(Err(e)) => tracing::warn!("WAN apply failed for {}: {}", conn.name, e),
            // C5-SILENT-PANIC fix: surface pool failure too. Pre-fix
            // a panicking blocking task would return Err here and
            // get silently dropped; operator saw HTTP 200 and a
            // normal-looking response while traffic didn't route.
            Err(e) => tracing::warn!("WAN apply blocking task failed for {}: {}", conn.name, e),
            Ok(Ok(())) => {}
        }
    }
    replicate_config_to_cluster(state);
    // Mask password before returning — never echo plaintext back to UI.
    let mut response = conn.clone();
    if let wan::WanMode::Pppoe(ref mut p) = response.mode
        && !p.password.is_empty() { p.password = "***".into(); }
    HttpResponse::Ok().json(&response)
}

pub async fn update_wan(
    req: HttpRequest, state: S,
    path: web::Path<String>, body: web::Json<wan::WanConnection>,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let mut updated = body.into_inner();
    if updated.id != id {
        return HttpResponse::BadRequest().body("id mismatch");
    }
    if let Err(e) = wan::validate(&updated) {
        return HttpResponse::BadRequest().body(e);
    }
    if let Some(resp) = cluster_guard_existing_wan(&state, &query, &id) { return resp; }
    if let Some(resp) = cluster_guard_node_id(&state, &query, Some(&updated.node_id)) { return resp; }
    // Preserve the existing password if the UI sent the masked "***"
    // sentinel (PUT bodies don't carry plaintext passwords back).
    {
        let mut cfg = state.router.config.write().unwrap();
        if let wan::WanMode::Pppoe(ref mut new_p) = updated.mode
            && new_p.password == "***"
                && let Some(existing) = cfg.wan_connections.iter().find(|c| c.id == id)
                    && let wan::WanMode::Pppoe(ref old_p) = existing.mode {
                        new_p.password = old_p.password.clone();
                    }
        let idx = match cfg.wan_connections.iter().position(|c| c.id == id) {
            Some(i) => i,
            None => return HttpResponse::NotFound().body("not found"),
        };
        cfg.wan_connections[idx] = updated.clone();
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
    }
    if updated.node_id == crate::agent::self_node_id() || updated.node_id.is_empty() {
        // C5 fix: same as create_wan — offload the wan::apply call.
        // Log inner errors AND pool failures (the latter would otherwise
        // be silently dropped — operator sees HTTP 200 while traffic
        // never routes).
        let updated_clone = updated.clone();
        let res = web::block(move || wan::apply(&updated_clone)).await;
        match res {
            Ok(Err(e)) => tracing::warn!("WAN update apply failed for {}: {}", updated.name, e),
            Err(e) => tracing::warn!("WAN update apply blocking task failed for {}: {}", updated.name, e),
            Ok(Ok(())) => {}
        }
    }
    replicate_config_to_cluster(state);
    // Mask password before returning — never echo plaintext back to UI.
    let mut response = updated.clone();
    if let wan::WanMode::Pppoe(ref mut p) = response.mode
        && !p.password.is_empty() { p.password = "***".into(); }
    HttpResponse::Ok().json(&response)
}

pub async fn delete_wan(req: HttpRequest, state: S, path: web::Path<String>, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    if let Some(resp) = cluster_guard_existing_wan(&state, &query, &id) { return resp; }
    let removed = {
        let mut cfg = state.router.config.write().unwrap();
        let r = cfg.wan_connections.iter().position(|c| c.id == id)
            .map(|i| cfg.wan_connections.remove(i));
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        r
    };
    if let Some(c) = removed
        && matches!(c.mode, wan::WanMode::Pppoe(_)) {
            let _ = wan::pppoe_purge(&c);
        }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().body("deleted")
}

pub async fn wan_status(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    let cfg = state.router.config.read().unwrap();
    let self_id = crate::agent::self_node_id();
    let entries: Vec<serde_json::Value> = cfg.wan_connections.iter()
        .filter(|c| c.node_id == self_id || c.node_id.is_empty())
        .map(|c| {
            let (iface, ip) = match &c.mode {
                wan::WanMode::Pppoe(_) => wan::pppoe_status(c)
                    .map(|(i, p)| (Some(i), Some(p)))
                    .unwrap_or((None, None)),
                _ => (None, None),
            };
            serde_json::json!({
                "id": c.id, "name": c.name, "interface": c.interface,
                "enabled": c.enabled,
                "live_iface": iface, "live_ip": ip,
            })
        }).collect();
    HttpResponse::Ok().json(entries)
}

/// Spawn a background task that ensures `ppp` and `pppoe` are
/// installed. Used right after a PPPoE connection is created so the
/// first apply has the binaries it needs.
fn ensure_pppoe_installed_async() {
    tokio::spawn(async {
        for tool in ["pppd", "pppoe"] {
            let installed = std::process::Command::new("which").arg(tool)
                .status().map(|s| s.success()).unwrap_or(false);
            if installed { continue; }
            // pkg name = same as binary on Debian/Ubuntu (ppp + pppoe);
            // RHEL family uses `ppp` and `rp-pppoe`. Try the common
            // package names — we don't require strict success here.
            let pkg_candidates: &[&str] = match tool {
                "pppd"  => &["ppp"],
                "pppoe" => &["pppoe", "rp-pppoe"],
                _ => &[],
            };
            for pkg in pkg_candidates {
                if which_install(pkg).await { break; }
            }
        }
    });
}

async fn which_install(pkg: &str) -> bool {
    let mgr = if which("apt-get") { Some(("apt-get", vec!["install", "-y", pkg])) }
        else if which("dnf")     { Some(("dnf", vec!["install", "-y", pkg])) }
        else if which("yum")     { Some(("yum", vec!["install", "-y", pkg])) }
        else if which("pacman")  { Some(("pacman", vec!["-Sy", "--noconfirm", pkg])) }
        else if which("zypper")  { Some(("zypper", vec!["install", "-y", pkg])) }
        else { None };
    let (cmd, args) = match mgr { Some(p) => p, None => return false };
    tokio::process::Command::new(cmd).args(&args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output().await
        .map(|o| o.status.success()).unwrap_or(false)
}

/// Bring an interface up (`ip link set <iface> up`). Deliberately
/// one-way — there's no "Bring Down" companion. Bringing a link down
/// from the WolfRouter UI is a good way for operators to accidentally
/// take themselves offline over a remote session.
///
/// If `node_id` targets a remote cluster node, the request is proxied
/// there via the cluster secret (same pattern as packet capture).
///
/// Security: iface name is allowlisted to alnum + `.-_` so it can
/// never carry shell metachars, and tokio::process::Command is invoked
/// with a fixed argv (no shell involvement at all).
#[derive(Deserialize)]
pub struct InterfaceUpRequest {
    pub iface: String,
    #[serde(default)]
    pub node_id: Option<String>,
}

pub async fn interface_up(
    req: HttpRequest,
    state: S,
    body: web::Json<InterfaceUpRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let r = body.into_inner();

    if r.iface.is_empty() || r.iface.len() > 32
        || !r.iface.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    {
        return HttpResponse::BadRequest().body("invalid interface name");
    }

    // Proxy to remote node when requested.
    let self_id = crate::agent::self_node_id();
    if let Some(target) = r.node_id.as_ref()
        && !target.is_empty() && target != &self_id {
            let nodes = state.cluster.get_all_nodes();
            let target_node = match nodes.into_iter().find(|n| &n.id == target) {
                Some(n) => n,
                None => return HttpResponse::NotFound().body(format!("node '{}' not found", target)),
            };
            let secret = state.cluster_secret.clone();
            let body_json = serde_json::json!({ "iface": r.iface });
            // Shared pool — see ROUTER_RPC_CLIENT. 10s total timeout
            // set per-request below replaces the old client-level one.
            let client = &*ROUTER_RPC_CLIENT;
            let target_host = resolve_node_address(&target_node.address);
            // v23.12: HTTPS-first chain via build_node_urls.
            let urls = crate::api::build_node_urls(&target_host, target_node.port, "/api/router/interface-up");
            for url in &urls {
                if let Ok(resp) = client.post(url)
                    .peer_auth(&secret)
                    .timeout(std::time::Duration::from_secs(10))
                    .json(&body_json).send().await
                {
                    if resp.status().is_success() {
                        let val: serde_json::Value = resp.json().await.unwrap_or(serde_json::json!({}));
                        return HttpResponse::Ok().json(val);
                    }
                    let txt = resp.text().await.unwrap_or_default();
                    return HttpResponse::Ok().json(serde_json::json!({
                        "success": false,
                        "error": format!("remote node returned: {}", txt)
                    }));
                }
            }
            return HttpResponse::Ok().json(serde_json::json!({
                "success": false,
                "error": "couldn't reach target node (tried HTTPS then HTTP)"
            }));
        }

    // Local: run `ip link set <iface> up`.
    let out = tokio::process::Command::new("ip")
        .args(["link", "set", &r.iface, "up"])
        .output().await
        .map_err(|e| format!("spawn ip: {}", e));
    match out {
        Ok(o) if o.status.success() => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("brought '{}' up", r.iface)
        })),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
            HttpResponse::Ok().json(serde_json::json!({
                "success": false,
                "error": format!("ip link set up failed: {}", stderr),
            }))
        }
        Err(e) => HttpResponse::Ok().json(serde_json::json!({
            "success": false,
            "error": e,
        })),
    }
}

#[derive(Deserialize)]
pub struct TestDnsRequest {
    /// IP the LAN segment's dnsmasq is expected to answer on.
    pub router_ip: String,
    /// Hostname to resolve. Defaults to cloudflare.com — a name that will
    /// exist regardless of the user's upstream forwarder choice.
    #[serde(default = "default_test_hostname")]
    pub hostname: String,
    /// Optional port for the dig query. Defaults to 53. Frontends that
    /// know the LAN's `dns.listen_port` should pass it explicitly so
    /// the test probes the actual dnsmasq listener — without this,
    /// LANs on a non-standard port (5353 etc., common when AdGuard or
    /// Pi-hole takes :53 in front of WolfRouter) get misleading
    /// "Connection refused on :53" failures even though dnsmasq is
    /// happily bound on the configured port. PapaSchlumpf 2026-04-30:
    /// "the health check blocks it because nothing else is listening
    /// on port 53 ... non-resolvable circle".
    #[serde(default = "default_test_port")]
    pub port: u16,
}

fn default_test_hostname() -> String { "cloudflare.com".into() }
fn default_test_port() -> u16 { 53 }

/// POST /api/router/test-dns — fire a single DNS query at a LAN's
/// router IP and report whether dnsmasq is actually answering. The
/// Quick Setup wizard calls this after creating a segment so users see
/// "DHCP works but DNS is broken" as a clear failure instead of
/// discovering it only when their client can't load a web page.
///
/// The shape matches the rest of WolfRouter's endpoints:
///   { success: bool, answer?: string, error?: string, duration_ms: u128 }
///
/// The host runs `dig @<router_ip> <hostname> +short` — note: this does
/// NOT validate from a LAN client's perspective. If a firewall rule
/// blocks LAN→host:53 but the host itself can reach :53, the test
/// still passes. That's a known limitation — the "real" test needs a
/// probe from the LAN side which we can't do from wolfstack itself.
pub async fn test_dns(
    req: HttpRequest, state: S,
    body: web::Json<TestDnsRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let r = body.into_inner();

    // Reject anything that isn't a plain IPv4 — router_ip is passed to
    // dig as a literal arg, and we don't want shell metacharacters or
    // names slipping through.
    if r.router_ip.parse::<std::net::Ipv4Addr>().is_err() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false, "error": "router_ip must be a valid IPv4 address"
        }));
    }
    let hostname = r.hostname.trim();
    if hostname.is_empty() ||
       !hostname.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') ||
       hostname.len() > 253
    {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false, "error": "hostname must be alphanumeric with . and -"
        }));
    }

    let port = if r.port == 0 { 53 } else { r.port };
    let start = std::time::Instant::now();
    // C4 fix: `dig` blocks for up to 3 seconds (+time=3). Offload.
    let router_ip = r.router_ip.clone();
    let hostname_owned = hostname.to_string();
    let out = web::block(move || {
        std::process::Command::new("dig")
            .args([
                &format!("@{}", router_ip),
                "-p", &port.to_string(),
                &hostname_owned,
                "+short", "+time=3", "+tries=1",
            ])
            .output()
    }).await.unwrap_or_else(|e|
        Err(std::io::Error::other(format!("blocking task: {}", e)))
    );
    let duration_ms = start.elapsed().as_millis() as u64;

    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
            // `dig +short` emits one line per answer record (IP or CNAME).
            // We treat an answer containing at least one IPv4 as success;
            // anything else (empty, NXDOMAIN, SERVFAIL, timeout) is a fail.
            let ip_answered = stdout.lines().any(|l| l.parse::<std::net::Ipv4Addr>().is_ok());
            if ip_answered {
                HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "answer": stdout,
                    "duration_ms": duration_ms,
                }))
            } else {
                // No usable answer. Craft a message that points at the
                // likely cause: dnsmasq not bound (:53 already taken by
                // systemd-resolved or another resolver), or upstream
                // forwarder unreachable from the host. Reports against
                // the actual queried port (not hardcoded :53) so LANs
                // on a non-standard port don't get misleading errors.
                let err = if stderr.contains("connection refused") || stdout.contains("connection refused") {
                    format!("Connection refused on {}:{} — dnsmasq isn't listening on that port. Run `ss -tulnp 'sport = :{}'` on the host to see what (if anything) holds it.", r.router_ip, port, port)
                } else if stderr.contains("timed out") || stdout.contains("timed out") || stdout.is_empty() {
                    format!("No answer from {}:{} within 3s — dnsmasq may not be bound on the LAN interface, or a firewall rule is blocking UDP/{}. Check `systemctl status` / `iptables -L WOLFROUTER_IN -nv`.", r.router_ip, port, port)
                } else {
                    format!("DNS server responded but did not return an A record. dig output: {}", stdout)
                };
                HttpResponse::Ok().json(serde_json::json!({
                    "success": false,
                    "error": err,
                    "answer": stdout,
                    "duration_ms": duration_ms,
                }))
            }
        }
        Err(e) => {
            HttpResponse::Ok().json(serde_json::json!({
                "success": false,
                "error": format!("Couldn't run `dig`: {}. Install 'dnsutils' (Debian/Ubuntu), 'bind-utils' (Fedora/RHEL), or 'bind' (Arch) and try again.", e),
                "duration_ms": duration_ms,
            }))
        }
    }
}

// ─── Network diagnostic tools (ping, traceroute, nslookup, whois) ───
//
// These power the "DNS Tools" tab — quick-diagnostic utilities the
// admin can run from the browser without SSH'ing in. All tools run
// on the wolfstack host (not from a LAN client) so they diagnose
// upstream reachability, not the LAN-side experience.
//
// Security posture:
//   • Target strings are strictly validated: alphanumerics + `. - : _`.
//     No shell invocation — Command::new() with args is argv-style.
//   • Every tool has an outer timeout so a user can't DoS the host by
//     submitting unreachable targets.
//   • Auth-gated like every other router endpoint.

#[derive(Deserialize)]
pub struct NetToolRequest {
    pub target: String,
    /// nslookup-specific: resolve against this server instead of the
    /// system default. Ignored for ping/traceroute/whois.
    #[serde(default)]
    pub server: String,
}

/// Shared target validator. Rejects shell metacharacters and overly
/// long strings. Returns the trimmed target or an error message.
fn validate_target(target: &str) -> Result<String, String> {
    let t = target.trim();
    if t.is_empty() { return Err("target is empty".into()); }
    if t.len() > 253 { return Err("target is too long (>253 chars)".into()); }
    if !t.chars().all(|c| c.is_ascii_alphanumeric() || ".-:_".contains(c)) {
        return Err("target must be a plain hostname or IP (a-z, 0-9, .-:_ only)".into());
    }
    Ok(t.to_string())
}

/// Run an external diag tool with a timeout. Returns the stdout/stderr
/// and the elapsed time. Tokio's wait-with-timeout kills the child
/// cleanly on expiry so we don't orphan processes on slow targets.
async fn run_with_timeout(
    cmd: &str, args: &[&str], timeout_secs: u64,
) -> (bool, String, String, u64) {
    let start = std::time::Instant::now();
    let fut = tokio::process::Command::new(cmd)
        .args(args)
        .output();
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs), fut
    ).await;
    let duration_ms = start.elapsed().as_millis() as u64;
    match out {
        Ok(Ok(o)) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            (o.status.success(), stdout, stderr, duration_ms)
        }
        Ok(Err(e)) => (false, String::new(),
            format!("Couldn't run `{}`: {} (is it installed?)", cmd, e),
            duration_ms),
        Err(_) => (false, String::new(),
            format!("`{}` timed out after {}s", cmd, timeout_secs),
            duration_ms),
    }
}

/// POST /api/router/tools/ping
pub async fn tool_ping(
    req: HttpRequest, state: S, body: web::Json<NetToolRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let target = match validate_target(&body.target) {
        Ok(t) => t, Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };
    // -c 4: send four packets. -W 1: wait at most 1s per reply.
    let (ok, stdout, stderr, ms) = run_with_timeout(
        "ping", &["-c", "4", "-W", "1", &target], 15,
    ).await;
    HttpResponse::Ok().json(serde_json::json!({
        "success": ok, "output": stdout, "error": if ok { String::new() } else { stderr },
        "duration_ms": ms,
    }))
}

/// POST /api/router/tools/traceroute
pub async fn tool_traceroute(
    req: HttpRequest, state: S, body: web::Json<NetToolRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let target = match validate_target(&body.target) {
        Ok(t) => t, Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };
    // -m 20: cap at 20 hops (most routes are <15). -w 2: 2s wait per
    // probe. -q 1: one probe per hop (faster, good enough for a browser UI).
    let (ok, stdout, stderr, ms) = run_with_timeout(
        "traceroute", &["-m", "20", "-w", "2", "-q", "1", &target], 60,
    ).await;
    HttpResponse::Ok().json(serde_json::json!({
        "success": ok, "output": stdout, "error": if ok { String::new() } else { stderr },
        "duration_ms": ms,
    }))
}

/// POST /api/router/tools/nslookup
pub async fn tool_nslookup(
    req: HttpRequest, state: S, body: web::Json<NetToolRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let target = match validate_target(&body.target) {
        Ok(t) => t, Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };
    let mut args: Vec<String> = vec![target];
    if !body.server.is_empty() {
        // server is a hostname or IP too — same validation.
        match validate_target(&body.server) {
            Ok(s) => args.push(s),
            Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("server: {}", e)})),
        };
    }
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let (ok, stdout, stderr, ms) = run_with_timeout(
        "nslookup", &args_ref, 10,
    ).await;
    HttpResponse::Ok().json(serde_json::json!({
        "success": ok, "output": stdout, "error": if ok { String::new() } else { stderr },
        "duration_ms": ms,
    }))
}

/// POST /api/router/tools/whois
pub async fn tool_whois(
    req: HttpRequest, state: S, body: web::Json<NetToolRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let target = match validate_target(&body.target) {
        Ok(t) => t, Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };
    let (ok, stdout, stderr, ms) = run_with_timeout(
        "whois", &[&target], 30,
    ).await;
    HttpResponse::Ok().json(serde_json::json!({
        "success": ok, "output": stdout, "error": if ok { String::new() } else { stderr },
        "duration_ms": ms,
    }))
}

/// GET /api/router/tools/status — returns which diag tools are installed.
/// Drives the "install missing tools" prompt in the DNS Tools tab.
pub async fn tool_status(
    req: HttpRequest, state: S,
) -> HttpResponse {
    auth_or_return!(req, state);
    // C4 fix: five `which` subprocess calls per request. Cheap individually
    // but executor-blocking under load. Offload them as a batch.
    let json = web::block(|| {
        let check = |name: &str| -> bool {
            std::process::Command::new("which").arg(name).output()
                .map(|o| o.status.success()).unwrap_or(false)
        };
        serde_json::json!({
            "ping": check("ping"),
            "traceroute": check("traceroute"),
            "nslookup": check("nslookup"),
            "dig": check("dig"),
            "whois": check("whois"),
        })
    }).await.unwrap_or_else(|_| serde_json::json!({
        "ping": false, "traceroute": false, "nslookup": false,
        "dig": false, "whois": false,
        "error": "tool-status blocking task failed",
    }));
    HttpResponse::Ok().json(json)
}

/// POST /api/router/tools/install — install any of the diag tools that
/// are missing. Detects the package manager (apt/dnf/yum/pacman/zypper)
/// and uses the appropriate package name for that distro since
/// dig/nslookup in particular ship under different names everywhere.
/// Returns per-tool success so the UI can reflect partial installs.
pub async fn tool_install(
    req: HttpRequest, state: S,
) -> HttpResponse {
    auth_or_return!(req, state);
    let pm = if which("apt-get") { "apt" }
        else if which("dnf")    { "dnf" }
        else if which("yum")    { "yum" }
        else if which("pacman") { "pacman" }
        else if which("zypper") { "zypper" }
        else { return HttpResponse::Ok().json(serde_json::json!({
            "success": false,
            "error": "No supported package manager found. Install ping, traceroute, nslookup, dig, and whois manually."
        })); };

    // Map a tool name → package name for the current package manager.
    // "dig" and "nslookup" both come from the same package (dnsutils/
    // bind-utils/bind/bind-tools), so we dedupe before installing.
    let pkg_for = |tool: &str| -> String {
        match (tool, pm) {
            ("ping", "apt") => "iputils-ping".into(),
            ("ping", _)     => "iputils".into(),
            ("traceroute", _) => "traceroute".into(),
            ("nslookup", "apt") | ("dig", "apt") => "dnsutils".into(),
            ("nslookup", "dnf") | ("dig", "dnf") |
            ("nslookup", "yum") | ("dig", "yum") |
            ("nslookup", "zypper") | ("dig", "zypper") => "bind-utils".into(),
            ("nslookup", "pacman") | ("dig", "pacman") => "bind".into(),
            ("whois", _) => "whois".into(),
            _ => tool.to_string(),  // fallback: assume pkg == tool
        }
    };

    let tools = ["ping", "traceroute", "nslookup", "dig", "whois"];
    let check_installed = |name: &str| -> bool {
        std::process::Command::new("which").arg(name).output()
            .map(|o| o.status.success()).unwrap_or(false)
    };

    // Build the unique package list for whatever's missing.
    let mut packages: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for t in &tools {
        if !check_installed(t) {
            packages.insert(pkg_for(t));
        }
    }

    if packages.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!({
            "success": true, "message": "All diagnostic tools already installed."
        }));
    }

    let pkg_vec: Vec<String> = packages.into_iter().collect();
    let pkg_ref: Vec<&str> = pkg_vec.iter().map(|s| s.as_str()).collect();

    let (cmd, args) = match pm {
        "apt"    => ("apt-get", {
            let mut a = vec!["install", "-y"];
            a.extend(pkg_ref.iter());
            a
        }),
        "dnf"    => ("dnf", { let mut a = vec!["install", "-y"]; a.extend(pkg_ref.iter()); a }),
        "yum"    => ("yum", { let mut a = vec!["install", "-y"]; a.extend(pkg_ref.iter()); a }),
        "pacman" => ("pacman", { let mut a = vec!["-Sy", "--noconfirm"]; a.extend(pkg_ref.iter()); a }),
        "zypper" => ("zypper", { let mut a = vec!["install", "-y"]; a.extend(pkg_ref.iter()); a }),
        _ => unreachable!(),
    };

    let out = tokio::process::Command::new(cmd)
        .args(&args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output().await;

    match out {
        Ok(o) if o.status.success() => {
            // Re-check after install so the client sees the current state
            // rather than assuming success applied uniformly.
            let status: std::collections::BTreeMap<&str, bool> = tools.iter()
                .map(|t| (*t, check_installed(t))).collect();
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": format!("Installed via {}: {}", cmd, pkg_vec.join(", ")),
                "tools": status,
            }))
        }
        Ok(o) => HttpResponse::Ok().json(serde_json::json!({
            "success": false,
            "error": format!("{} exited {}: {}", cmd,
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stderr).trim()),
        })),
        Err(e) => HttpResponse::Ok().json(serde_json::json!({
            "success": false, "error": format!("couldn't run {}: {}", cmd, e),
        })),
    }
}

// ─── Import / export — round-trip the entire RouterConfig ───
//
// One-file backup + restore so admins can snapshot their setup before
// experimenting, share a known-good config between clusters, or rebuild
// a lost node quickly. The JSON shape matches RouterConfig exactly, so
// it's also the same file the daemon writes to /etc/wolfstack/router/config.json
// on save — useful for out-of-band edits.

/// GET /api/router/export — download the full RouterConfig as JSON.
/// PPPoE passwords are masked to "***" so exported files are safe to
/// share. On import, "***" is treated as "keep existing" — no password
/// loss if you're restoring onto the same node.
pub async fn export_config(
    req: HttpRequest, state: S,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let mut cfg = state.router.config.read().unwrap().clone();

    // Cluster filter: when ?cluster=NAME is set, strip every item
    // that doesn't belong to a node in that cluster — same strict
    // shape as list_segments / list_rules / etc. Without this, the
    // export from Cluster A's WolfRouter view would dump every
    // cluster's items in one file. Adam Cogswell 2026-04-29:
    // "wolfrouter module is cluster only nothing in it should bleed
    // anywhere else to any other clusters".
    if let Some(set) = cluster_node_id_set(&state, &query) {
        cfg.lans.retain(|l| set.contains(&l.node_id));
        cfg.wan_connections.retain(|c| set.contains(&c.node_id));
        cfg.proxies.retain(|p| set.contains(&p.node_id));
        cfg.rules.retain(|r| match &r.node_id {
            None => false,
            Some(nid) => set.contains(nid),
        });
        cfg.subnet_routes.retain(|r| match &r.node_id {
            None => false,
            Some(nid) => set.contains(nid),
        });
        // ZoneAssignments outer key is node_id.
        cfg.zones.assignments.retain(|node_id, _| set.contains(node_id));
    }

    // Mask PPPoE passwords in-place.
    for w in cfg.wan_connections.iter_mut() {
        if let wan::WanMode::Pppoe(ref mut p) = w.mode
            && !p.password.is_empty() { p.password = "***".into(); }
    }
    let body = match serde_json::to_string_pretty(&cfg) {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().body(format!("serialize: {}", e)),
    };
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    // H3 fix: sanitise the operator-controlled cluster tag before
    // interpolating into Content-Disposition. Cluster names allow
    // hyphens and underscores; anything else is replaced with `_`
    // so an attacker-controlled name like `foo"; filename="evil`
    // can't break out of the quoted-string header value.
    let cluster_tag_raw = query.cluster.as_deref().unwrap_or("all");
    let cluster_tag: String = cluster_tag_raw.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let cluster_tag = if cluster_tag.is_empty() { "all".to_string() } else { cluster_tag };
    let filename = format!("wolfrouter-config-{}-{}.json", cluster_tag, ts);
    HttpResponse::Ok()
        .insert_header(("Content-Type", "application/json"))
        .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
        .body(body)
}

#[derive(Deserialize)]
pub struct ImportConfigRequest {
    /// Full RouterConfig as JSON. Passwords set to "***" are preserved
    /// from the current on-disk config.
    pub config: serde_json::Value,
    /// Apply (restart dnsmasq, re-dial PPPoE, re-apply firewall) after
    /// importing. Default true — the most common use is "restore then
    /// make it live".
    #[serde(default = "default_true_import")]
    pub apply: bool,
}

fn default_true_import() -> bool { true }

/// POST /api/router/import — replace the RouterConfig with a caller-
/// supplied JSON. Validates by deserialising into RouterConfig; returns
/// 400 with a readable parse error if the shape is wrong. Preserves
/// PPPoE passwords from the current config where the incoming value is
/// "***".
///
/// This is intentionally all-or-nothing: partial imports would leave
/// the node in a weird half-state. Callers should snapshot
/// via /api/router/export first if they want rollback.
pub async fn import_config(
    req: HttpRequest, state: S,
    body: web::Json<ImportConfigRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let incoming = body.into_inner();

    // Parse into the strongly-typed RouterConfig so we reject malformed
    // JSON before touching state.
    let mut new_cfg: RouterConfig = match serde_json::from_value(incoming.config) {
        Ok(c) => c,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": format!("Config JSON is invalid: {}. Expected a wolfrouter config export.", e),
        })),
    };

    // Validate every LAN segment and WAN connection against the same
    // rules the per-item create/update endpoints enforce. Without this,
    // a crafted import JSON could slip newlines into fields like
    // extra_options / local_records / pppoe username and forge
    // arbitrary dnsmasq or pppd directives (addn-hosts=/etc/shadow
    // and similar). Reject the whole import on the first invalid
    // entry — partial validation would leave the admin with a
    // half-persisted config that's worse than just refusing.
    for seg in &new_cfg.lans {
        if let Err(e) = validate_segment(seg) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": format!("LAN '{}' failed validation: {}", seg.name, e),
            }));
        }
    }
    for conn in &new_cfg.wan_connections {
        if let Err(e) = wan::validate(conn) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": format!("WAN '{}' failed validation: {}", conn.name, e),
            }));
        }
    }

    // M3 fix: firewall rule validation. Pre-fix imports could carry
    // rules referencing zone IDs / LAN IDs / interface names that
    // didn't exist in the imported config; compile_rule emitted a
    // skip-comment at apply time and the rule silently no-op'd. Run
    // the same validator the live config uses; surface findings as a
    // non-blocking warning (operator may be importing a partial
    // config they intend to fix manually) but record them in the
    // response so they aren't silent.
    let self_id_for_validate = crate::agent::self_node_id();
    let firewall_issues = crate::networking::router::firewall::validate(&new_cfg, &self_id_for_validate);

    // Preserve PPPoE passwords where the import carries the masked "***".
    // This lets users round-trip their own exports without losing creds.
    {
        let cur = state.router.config.read().unwrap();
        for new_w in new_cfg.wan_connections.iter_mut() {
            if let wan::WanMode::Pppoe(ref mut np) = new_w.mode
                && np.password == "***" {
                    // Find the same connection id in the current config.
                    if let Some(old) = cur.wan_connections.iter().find(|c| c.id == new_w.id) {
                        if let wan::WanMode::Pppoe(op) = &old.mode {
                            np.password = op.password.clone();
                        }
                    } else {
                        // Imported with "***" but no existing record to pull from —
                        // blank the password so pppd doesn't try to auth with literal "***".
                        np.password = String::new();
                    }
                }
        }
    }

    // Snapshot counts for the response summary.
    let summary = serde_json::json!({
        "lans": new_cfg.lans.len(),
        "wan_connections": new_cfg.wan_connections.len(),
        "rules": new_cfg.rules.len(),
        "zones": new_cfg.zones.assignments.values().map(|m| m.len() as u64).sum::<u64>(),
    });

    // Persist.
    {
        let mut cfg = state.router.config.write().unwrap();
        *cfg = new_cfg;
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false, "error": format!("save: {}", e),
            }));
        }
    }

    // Optionally apply. Each subsystem reports per-item; we aggregate a
    // count for the response so the UI can show exactly what happened.
    let mut applied = serde_json::json!({});
    if incoming.apply {
        let cfg = state.router.config.read().unwrap().clone();
        let self_id = crate::agent::self_node_id();

        // WAN — dial + MASQUERADE install.
        let mut wan_ok = 0u32;
        let mut wan_err: Vec<String> = Vec::new();
        for conn in &cfg.wan_connections {
            if conn.node_id != self_id { continue; }
            if !conn.enabled { continue; }
            match wan::apply(conn) {
                Ok(()) => wan_ok += 1,
                Err(e) => wan_err.push(format!("{}: {}", conn.name, e)),
            }
        }
        applied["wan_applied"] = serde_json::Value::from(wan_ok);
        applied["wan_errors"] = serde_json::Value::from(wan_err);

        // DHCP — restart each LAN's dnsmasq with the fresh config.
        dhcp::start_all_for_node(&cfg, &self_id);
        applied["dnsmasq_restarted"] = serde_json::Value::from(
            cfg.lans.iter().filter(|l| l.node_id == self_id).count() as u64
        );

        // Firewall — rebuild + swap.
        let ruleset = firewall::build_ruleset(&cfg, &self_id);
        match firewall::apply(&ruleset, false) {
            Ok(prev) => {
                *state.router.last_applied_rules.write().unwrap() = Some(prev);
                applied["firewall"] = serde_json::Value::from("applied");
            }
            Err(e) => applied["firewall"] = serde_json::Value::from(format!("error: {}", e)),
        }
    }

    replicate_config_to_cluster(state.clone());

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": if incoming.apply {
            "Config imported and applied. Firewall, DHCP/DNS, and WAN are live."
        } else {
            "Config imported (not applied). Hit Apply or toggle Auto-apply to make it live."
        },
        "summary": summary,
        "applied": applied,
        // M3 fix: surface firewall validation issues so an operator
        // importing a config with bad rule references sees them
        // immediately rather than discovering days later that the
        // rules silently no-op'd in the compiled iptables ruleset.
        "firewall_issues": firewall_issues.iter().map(|(id, msg)| serde_json::json!({
            "rule_id": id, "message": msg,
        })).collect::<Vec<_>>(),
    }))
}

// ─── Reverse-proxy entries ───

pub async fn list_proxies(req: HttpRequest, state: S, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    let proxies = state.router.config.read().unwrap().proxies.clone();
    let filtered: Vec<&proxy::ProxyEntry> = match cluster_node_id_set(&state, &query) {
        None => proxies.iter().collect(),
        Some(set) => proxies.iter().filter(|p| set.contains(&p.node_id)).collect(),
    };
    HttpResponse::Ok().json(filtered)
}

/// Returns every candidate backend the operator can point a proxy at,
/// grouped so the UI can show VMs by type (libvirt vs Proxmox vs …)
/// and containers by engine (Docker vs LXC) in separate lists. Each
/// entry carries the pre-resolved host+port so the UI doesn't need
/// extra round-trips to learn where the backend actually lives.
pub async fn list_proxy_backends(req: HttpRequest, state: S, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);

    // Cluster filter: only include backends owned by a node in the
    // requested cluster. VMs carry a host_id; local docker/lxc
    // containers belong to the bastion, so they're included only if
    // the bastion is in the requested cluster.
    let cluster_set = cluster_node_id_set(&state, &query);
    let self_id = crate::agent::self_node_id();
    let bastion_in_cluster = match &cluster_set {
        None => true,
        Some(set) => set.contains(&self_id),
    };

    // VMs — split by vm_type so the picker can group them. "libvirt"
    // covers WolfStack's native KVM-over-libvirt VMs; "proxmox" covers
    // VMs owned by a Proxmox VE cluster member (they carry a vmid).
    let mut vms_libvirt = Vec::new();
    let mut vms_proxmox = Vec::new();
    for v in state.vms.lock().unwrap().list_vms() {
        // Skip VMs whose hosting node isn't in the requested cluster.
        if let Some(set) = &cluster_set {
            match &v.host_id {
                Some(hid) if set.contains(hid) => {}
                _ => continue,
            }
        }
        let host = v.wolfnet_ip.clone().unwrap_or_default();
        let is_pve = v.vmid.is_some();
        let entry = serde_json::json!({
            "id": v.name,
            "name": v.name,
            "host": host,
            "running": v.running,
            "vm_type": if is_pve { "proxmox" } else { "libvirt" },
            "node_id": v.host_id,
        });
        if is_pve { vms_proxmox.push(entry); } else { vms_libvirt.push(entry); }
    }

    // Docker containers — only include those with an IP (otherwise
    // there's nowhere for nginx to proxy_pass to). docker_list_all_cached
    // fills ip_address with the bridge IP or WolfNet IP depending on
    // which network the container's on; either works from the host's
    // nginx as long as it's non-empty.
    let mut containers_docker = Vec::new();
    if bastion_in_cluster {
        for c in crate::containers::docker_list_all_cached() {
            if c.ip_address.is_empty() { continue; }
            containers_docker.push(serde_json::json!({
                "id": c.id,
                "name": c.name,
                "host": c.ip_address,
                "running": c.state == "running",
                "container_type": "docker",
            }));
        }
    }

    // LXC containers — same idea, different manager.
    let mut containers_lxc = Vec::new();
    if bastion_in_cluster {
        for c in crate::containers::lxc_list_all_cached() {
            if c.ip_address.is_empty() { continue; }
            containers_lxc.push(serde_json::json!({
                "id": c.name,
                "name": c.name,
                "host": c.ip_address,
                "running": c.state == "running",
                "container_type": "lxc",
            }));
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "vms": {
            "libvirt": vms_libvirt,
            "proxmox": vms_proxmox,
        },
        "containers": {
            "docker": containers_docker,
            "lxc":    containers_lxc,
        },
    }))
}

pub async fn create_proxy(req: HttpRequest, state: S, body: web::Json<proxy::ProxyEntry>, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    let mut entry = body.into_inner();
    if entry.id.is_empty() { entry.id = gen_id("proxy"); }
    if entry.domain.trim().is_empty() {
        return HttpResponse::BadRequest().body("domain is required");
    }
    if entry.node_id.is_empty() {
        entry.node_id = crate::agent::self_node_id();
    }
    if let Some(resp) = cluster_guard_node_id(&state, &query, Some(&entry.node_id)) { return resp; }

    // Resolve the domain up front so the stored entry always carries a
    // pinned IP. We don't want the forward silently following DNS flaps
    // — the operator picks what the rules bind to at save time.
    if let Err(e) = proxy::resolve_entry_public_ip(&mut entry) {
        return HttpResponse::BadRequest().body(e);
    }

    let (applies_here, proxies) = {
        let mut cfg = state.router.config.write().unwrap();
        cfg.proxies.retain(|p| p.id != entry.id);
        cfg.proxies.push(entry.clone());
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        let self_id = crate::agent::self_node_id();
        let applies = entry.node_id == self_id;
        (applies, cfg.proxies.clone())
    };
    let mut warnings = Vec::new();
    if applies_here {
        warnings = proxy::apply_for_node(&proxies, &crate::agent::self_node_id());
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(serde_json::json!({
        "entry": entry,
        "warnings": warnings,
    }))
}

pub async fn update_proxy(
    req: HttpRequest,
    state: S,
    path: web::Path<String>,
    body: web::Json<proxy::ProxyEntry>,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let mut updated = body.into_inner();
    if updated.id != id {
        return HttpResponse::BadRequest().body("id mismatch");
    }
    if updated.node_id.is_empty() {
        updated.node_id = crate::agent::self_node_id();
    }
    if let Some(resp) = cluster_guard_existing_proxy(&state, &query, &id) { return resp; }
    if let Some(resp) = cluster_guard_node_id(&state, &query, Some(&updated.node_id)) { return resp; }
    if let Err(e) = proxy::resolve_entry_public_ip(&mut updated) {
        return HttpResponse::BadRequest().body(e);
    }

    let (applies_here, proxies) = {
        let mut cfg = state.router.config.write().unwrap();
        let idx = match cfg.proxies.iter().position(|p| p.id == id) {
            Some(i) => i,
            None => return HttpResponse::NotFound().body("not found"),
        };
        cfg.proxies[idx] = updated.clone();
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        let self_id = crate::agent::self_node_id();
        let applies = updated.node_id == self_id;
        (applies, cfg.proxies.clone())
    };
    let mut warnings = Vec::new();
    if applies_here {
        warnings = proxy::apply_for_node(&proxies, &crate::agent::self_node_id());
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(serde_json::json!({
        "entry": updated,
        "warnings": warnings,
    }))
}

pub async fn delete_proxy(req: HttpRequest, state: S, path: web::Path<String>, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    if let Some(resp) = cluster_guard_existing_proxy(&state, &query, &id) { return resp; }
    let proxies = {
        let mut cfg = state.router.config.write().unwrap();
        cfg.proxies.retain(|p| p.id != id);
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(e);
        }
        cfg.proxies.clone()
    };
    // Best-effort cleanup of the on-disk nginx config + self-signed cert
    // for this id, then re-render everything else. Calling apply_for_node
    // would also remove the stale config, but being explicit keeps the
    // intent clear.
    proxy::remove_one(&id);
    let warnings = proxy::apply_for_node(&proxies, &crate::agent::self_node_id());
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(serde_json::json!({
        "deleted": id,
        "warnings": warnings,
    }))
}

// ─── HTTP (L7) Reverse Proxies ───────────────────────────────────────
//
// Multi-target proxy CRUD. Sister to the L4 ProxyEntry surface above:
// same `node_id`-per-entry cluster-scoping discipline, same auto-
// replication pattern via `replicate_config_to_cluster`. Render lives
// in `crate::networking::router::http_proxy`; the public-ingress /
// DNS / LB story (Cloudflare etc.) lives in `crate::edge`.

use crate::networking::router::http_proxy::HttpProxy;

/// GET /api/router/http-proxies — filtered by `?cluster=`. A multi-
/// target proxy is included if ANY of its targets is in the current
/// cluster's node set — operators editing a 3-node HA proxy from any
/// one cluster's view should see it.
pub async fn list_http_proxies(
    req: HttpRequest, state: S, query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let proxies = state.router.config.read().unwrap().http_proxies.clone();
    let filtered: Vec<&HttpProxy> = match cluster_node_id_set(&state, &query) {
        None => proxies.iter().collect(),
        Some(set) => proxies.iter()
            .filter(|p| p.targets.iter().any(|t| set.contains(&t.node_id)))
            .collect(),
    };
    HttpResponse::Ok().json(filtered)
}

/// GET /api/router/http-proxies/runtime — local nginx/wolfproxy
/// detection. Used by the UI's install-picker banner.
pub async fn http_proxy_runtime(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    // detect_runtime() shells out (nginx -v, systemctl, wolfproxy --version) —
    // blocking work that must not run on the async executor. The wolfproxy probe
    // is now timeout-bounded but can still cost a few seconds on a stale binary,
    // so offload the whole detection to the blocking pool.
    let status = match web::block(
        crate::networking::router::proxy_runtime::detect_runtime
    ).await {
        Ok(s) => s,
        Err(_) => return HttpResponse::InternalServerError()
            .body("reverse-proxy runtime detection failed"),
    };
    let active = status.active_runtime().unwrap_or("");
    HttpResponse::Ok().json(serde_json::json!({
        "nginx_installed":     status.nginx_installed,
        "nginx_active":        status.nginx_active,
        "wolfproxy_installed": status.wolfproxy_installed,
        "wolfproxy_active":    status.wolfproxy_active,
        "active":              active,
        "any_installed":       status.any_installed(),
    }))
}

/// POST /api/router/http-proxies/install/{which} — install nginx or
/// wolfproxy on this node via the local distro's package manager
/// (nginx) or the official setup.sh (wolfproxy).
pub async fn http_proxy_install_runtime(
    req: HttpRequest, state: S, path: web::Path<String>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let which = path.into_inner();
    let result = match which.as_str() {
        "nginx" => actix_web::web::block(crate::installer::install_nginx_pkg).await,
        "wolfproxy" => actix_web::web::block(|| {
            crate::installer::install_component(crate::installer::Component::WolfProxy)
        }).await,
        other => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("unsupported runtime '{}' — use 'wolfproxy' or 'nginx'", other)
            }));
        }
    };
    match result {
        Ok(Ok(log)) => HttpResponse::Ok().json(serde_json::json!({
            "ok": true, "which": which, "log": log,
        })),
        Ok(Err(e)) => HttpResponse::BadRequest().json(serde_json::json!({
            "ok": false, "which": which, "error": e,
        })),
        Err(join) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("install task failed: {}", join)
        })),
    }
}

/// Validate the proxy's edge strategy references stores that actually
/// exist and have the right plugin / kind. Runs at save time so the
/// operator sees a clear error immediately instead of discovering
/// the misconfiguration via a cryptic reconcile failure 30s later.
///
/// We don't make API calls here (no token-validation round-trip) —
/// that work belongs to the existing "Test connection" buttons.
/// Only schema integrity.
fn validate_edge_against_stores(proxy: &HttpProxy) -> Result<(), String> {
    use crate::edge::EdgeStrategy as E;
    let cloud = crate::edge::CloudProviderStore::load();
    let dns = crate::dns_providers::DnsProviderStore::load();

    let check_dns = |id: &str, want_plugins: &[&str]| -> Result<(), String> {
        let p = dns.get(id).ok_or_else(|| format!(
            "DNS provider '{}' not found — add one in Settings → DNS Providers", id
        ))?;
        if !want_plugins.iter().any(|w| *w == p.plugin) {
            return Err(format!(
                "DNS provider '{}' uses plugin '{}' — this edge strategy requires one of: {}",
                p.name, p.plugin, want_plugins.join(", ")
            ));
        }
        Ok(())
    };
    let check_cloud = |id: &str, want_kind: crate::edge::CloudProviderKind| -> Result<(), String> {
        let p = cloud.get(id).ok_or_else(|| format!(
            "cloud provider '{}' not found — add one in Settings → Cloud Providers", id
        ))?;
        if p.kind != want_kind {
            return Err(format!(
                "cloud provider '{}' is kind '{}' — this edge strategy requires kind '{}'",
                p.name, p.kind.label(), want_kind.label()
            ));
        }
        Ok(())
    };

    match &proxy.edge {
        E::Local => Ok(()),
        E::DnsRoundRobin { dns_provider_id, .. } => {
            check_dns(dns_provider_id, &["cloudflare", "hetzner", "digitalocean"])
        }
        E::CloudflareDns { dns_provider_id, .. } => {
            check_dns(dns_provider_id, &["cloudflare"])
        }
        E::HetznerLb { cloud_provider_id, lb_name, .. } => {
            if lb_name.trim().is_empty() {
                return Err("HetznerLb: lb_name is required".into());
            }
            check_cloud(cloud_provider_id, crate::edge::CloudProviderKind::Hetzner)
        }
        E::DigitalOceanLb { cloud_provider_id, lb_name, .. } => {
            if lb_name.trim().is_empty() {
                return Err("DigitalOceanLb: lb_name is required".into());
            }
            check_cloud(cloud_provider_id, crate::edge::CloudProviderKind::DigitalOcean)
        }
        E::CloudflareTunnel { cloud_provider_id, dns_provider_id, tunnel_name } => {
            if tunnel_name.trim().is_empty() {
                return Err("CloudflareTunnel: tunnel_name is required".into());
            }
            check_cloud(cloud_provider_id, crate::edge::CloudProviderKind::Cloudflare)?;
            check_dns(dns_provider_id, &["cloudflare"])
        }
    }
}

fn guard_targets_against_cluster(
    state: &S, query: &web::Query<TopologyQuery>, proxy: &HttpProxy,
) -> Option<HttpResponse> {
    for t in &proxy.targets {
        if let Some(resp) = cluster_guard_node_id(state, query, Some(t.node_id.as_str())) {
            return Some(resp);
        }
    }
    None
}

/// POST /api/router/http-proxies — create.
pub async fn create_http_proxy(
    req: HttpRequest, state: S,
    body: web::Json<HttpProxy>,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let proxy = body.into_inner();
    if let Err(e) = crate::networking::router::http_proxy::validate_id(&proxy.id) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": e }));
    }
    if proxy.server_names.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "at least one server_name is required"
        }));
    }
    if proxy.targets.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "at least one target is required — pick one cluster node, or check 'replicate to all'"
        }));
    }
    if let Err(e) = validate_edge_against_stores(&proxy) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": e }));
    }
    if let Some(resp) = guard_targets_against_cluster(&state, &query, &proxy) { return resp; }
    {
        let cur = state.router.config.read().unwrap();
        if cur.http_proxies.iter().any(|p| p.id == proxy.id) {
            return HttpResponse::Conflict().json(serde_json::json!({
                "error": format!("HTTP proxy '{}' already exists — use PUT to update", proxy.id)
            }));
        }
    }
    {
        let mut cur = state.router.config.write().unwrap();
        cur.http_proxies.push(proxy.clone());
        if let Err(e) = cur.save() {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("save router config: {}", e)
            }));
        }
    }
    let cfg_snapshot = state.router.config.read().unwrap().http_proxies.clone();
    let self_id = crate::agent::self_node_id();
    let warnings = crate::networking::router::http_proxy::apply_for_node(&cfg_snapshot, &self_id);
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(serde_json::json!({
        "ok": true, "proxy": proxy, "apply_warnings": warnings,
    }))
}

/// Request body for issuing a Let's Encrypt cert for an existing HTTP proxy.
#[derive(serde::Deserialize)]
pub struct ProxyCertRequest {
    #[serde(default)]
    pub email: String,
    /// "webroot" (HTTP-01, default). Ignored when `dns_provider_id` is set.
    #[serde(default)]
    pub challenge: String,
    /// Saved DNS provider id — when set, issue via DNS-01 (works behind a
    /// firewall / for wildcards) instead of the webroot HTTP-01 challenge.
    #[serde(default)]
    pub dns_provider_id: String,
}

/// POST /api/router/http-proxies/{id}/certificate — issue a Let's Encrypt
/// certificate for this proxy's server_names and wire it straight into the
/// site (TLS cert/key + force-HTTPS), then apply + reload. Removes the
/// "issue on the certs page, then come back and paste the paths" round-trip.
///
/// Deliberately NOT `certbot --nginx`: WolfStack owns the nginx config for
/// this proxy, so we issue via the existing webroot/DNS flow and wire the
/// cert paths into our own config — same one-click result, no config fight.
/// Runs on whichever node serves the request; proxy the call to a target
/// node to issue + install the cert on that node.
pub async fn issue_proxy_certificate(
    req: HttpRequest, state: S,
    path: web::Path<String>,
    body: web::Json<ProxyCertRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let b = body.into_inner();

    let domains: Vec<String> = {
        let cur = state.router.config.read().unwrap();
        match cur.http_proxies.iter().find(|p| p.id == id) {
            Some(p) => p.server_names.clone(),
            None => return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("HTTP proxy '{}' not found", id)
            })),
        }
    };
    if domains.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "this proxy has no server names to certify"
        }));
    }

    // Validate inputs at the boundary so a bad value yields a clear 400 rather
    // than a confusing certbot error deep inside the thread pool.
    if !b.email.is_empty() && (!b.email.contains('@') || b.email.chars().any(|c| c.is_whitespace()) || b.email.len() > 254) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "that doesn't look like a valid email address"
        }));
    }
    // The HTTP path only knows how to solve a webroot (HTTP-01) challenge;
    // DNS-01 must come through `dns_provider_id`. Reject anything else early.
    if b.dns_provider_id.is_empty() && !matches!(b.challenge.as_str(), "" | "webroot") {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("unsupported challenge '{}' without a DNS provider (use webroot, or pick a DNS provider for DNS-01)", b.challenge)
        }));
    }

    tracing::info!(
        "cert issuance requested for proxy '{}' domains={:?} via {}",
        id, domains,
        if b.dns_provider_id.is_empty() { "HTTP-01/webroot" } else { "DNS-01" }
    );

    // Issue the certificate (blocking — certbot takes ~a minute). A saved DNS
    // provider wins over the HTTP-01 challenge, exactly like the certs page.
    let email = b.email.clone();
    let issue_domains = domains.clone();
    let result = if !b.dns_provider_id.is_empty() {
        let pid = b.dns_provider_id.clone();
        web::block(move || crate::certbot::issue_via_provider(&issue_domains, &email, &pid, false)).await
    } else {
        let challenge = if b.challenge.is_empty() { "webroot".to_string() } else { b.challenge.clone() };
        web::block(move || crate::certbot::issue(&issue_domains, &email, &challenge, None, false)).await
    };
    let log = match result {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            tracing::warn!("cert issuance for proxy '{}' failed: {}", id, e);
            return HttpResponse::BadRequest().json(serde_json::json!({ "error": e }));
        }
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() })),
    };

    // Resolve the freshly-issued cert's real lineage (handles certbot's
    // `-0001` suffix) by matching SANs; fall back to the first domain.
    // `list_certs` walks /etc/letsencrypt + shells out to openssl per cert, so
    // it runs on the blocking pool, not the actix worker.
    let first = domains[0].clone();
    let first_for_block = first.clone();
    let resolved = web::block(move || {
        crate::certbot::list_certs().into_iter()
            .find(|c| c.domains.iter().any(|d| d == &first_for_block))
            .map(|c| {
                let cp = if c.cert_path.is_empty() { format!("/etc/letsencrypt/live/{}/fullchain.pem", c.name) } else { c.cert_path.clone() };
                let kp = if c.key_path.is_empty() { format!("/etc/letsencrypt/live/{}/privkey.pem", c.name) } else { c.key_path.clone() };
                (c.name.clone(), cp, kp)
            })
    }).await.unwrap_or(None);
    let (cert_name, cert_path, key_path) = resolved
        .unwrap_or_else(|| (first.clone(),
            format!("/etc/letsencrypt/live/{}/fullchain.pem", first),
            format!("/etc/letsencrypt/live/{}/privkey.pem", first)));

    // Wire the cert into the proxy + force HTTPS, then save.
    {
        let mut cur = state.router.config.write().unwrap();
        match cur.http_proxies.iter_mut().find(|p| p.id == id) {
            Some(p) => {
                p.tls = Some(crate::networking::router::http_proxy::TlsConfig {
                    cert_path: cert_path.clone(),
                    key_path: key_path.clone(),
                    cert_name: cert_name.clone(),
                });
                p.force_https = true;
            }
            None => return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("HTTP proxy '{}' was deleted while the certificate was issued", id)
            })),
        }
        if let Err(e) = cur.save() {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("certificate issued but saving the proxy failed: {}", e)
            }));
        }
    }

    let cfg_snapshot = state.router.config.read().unwrap().http_proxies.clone();
    let self_id = crate::agent::self_node_id();
    let warnings = crate::networking::router::http_proxy::apply_for_node(&cfg_snapshot, &self_id);
    replicate_config_to_cluster(state);

    tracing::info!("cert '{}' issued + wired into proxy '{}' ({} apply warning(s))", cert_name, id, warnings.len());
    HttpResponse::Ok().json(serde_json::json!({
        "ok": true,
        "cert_name": cert_name,
        "apply_warnings": warnings,
        "log": log,
    }))
}

/// PUT /api/router/http-proxies/{id} — update.
pub async fn update_http_proxy(
    req: HttpRequest, state: S,
    path: web::Path<String>,
    body: web::Json<HttpProxy>,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let new_proxy = body.into_inner();
    if id != new_proxy.id {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("URL id '{}' must match body id '{}'", id, new_proxy.id)
        }));
    }
    if new_proxy.targets.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "at least one target is required"
        }));
    }
    if let Err(e) = validate_edge_against_stores(&new_proxy) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": e }));
    }
    if let Some(resp) = guard_targets_against_cluster(&state, &query, &new_proxy) { return resp; }
    // Snapshot the *old* edge so we can tear down resources that the
    // update is leaving behind. Cases that need teardown:
    //   1. edge kind changed (e.g. HetznerLb → Local) — the old LB is
    //      orphaned, delete it.
    //   2. edge kind matches but the resource identity changed (LB
    //      renamed, tunnel renamed) — the old resource is orphaned.
    //   3. server_names were removed — the records / CNAMEs for the
    //      removed names are orphaned.
    // We compute the cleanup edge here and pass to teardown after the
    // local config has been persisted (so a crash mid-teardown leaves
    // the config consistent — the operator can retry).
    let old_proxy: Option<crate::networking::router::http_proxy::HttpProxy> = {
        let cur = state.router.config.read().unwrap();
        let existing = cur.http_proxies.iter().find(|p| p.id == id);
        match existing {
            None => return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("HTTP proxy '{}' not found", id)
            })),
            Some(old) => {
                for t in &old.targets {
                    if let Some(resp) = cluster_guard_node_id(&state, &query, Some(t.node_id.as_str())) {
                        return resp;
                    }
                }
                Some(old.clone())
            }
        }
    };
    {
        let mut cur = state.router.config.write().unwrap();
        match cur.http_proxies.iter_mut().find(|p| p.id == id) {
            Some(slot) => *slot = new_proxy.clone(),
            None => return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("HTTP proxy '{}' was deleted concurrently", id)
            })),
        }
        if let Err(e) = cur.save() {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("save router config: {}", e)
            }));
        }
    }
    // Run teardown for whatever the *old* config provisioned but the
    // *new* config doesn't keep.
    let mut edge_warnings = Vec::new();
    if let Some(old) = old_proxy {
        // 1. Edge kind changed → tear down the old edge entirely
        //    against the OLD server_names.
        // 2. Kind same but identity differs (lb_name / tunnel_name)
        //    → same teardown applies.
        if !edge_state_matches(&old, &new_proxy) {
            edge_warnings.extend(crate::edge::teardown::teardown_proxy(&old).await);
        } else {
            // 3. Same edge, same resource identity — clean up records
            //    for server_names that were dropped from this update.
            let new_names: std::collections::HashSet<&str> =
                new_proxy.server_names.iter().map(|s| s.as_str()).collect();
            let removed: Vec<String> = old.server_names.iter()
                .filter(|n| !new_names.contains(n.as_str()))
                .cloned()
                .collect();
            if !removed.is_empty() {
                edge_warnings.extend(
                    crate::edge::teardown::teardown_edge(&old.edge, &removed).await
                );
            }
        }
    }
    let cfg_snapshot = state.router.config.read().unwrap().http_proxies.clone();
    let self_id = crate::agent::self_node_id();
    let mut warnings = crate::networking::router::http_proxy::apply_for_node(&cfg_snapshot, &self_id);
    warnings.extend(edge_warnings);
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(serde_json::json!({
        "ok": true, "proxy": new_proxy, "apply_warnings": warnings,
    }))
}

/// Two proxies share an "edge state identity" when their edge strategy
/// is the same kind AND the resource name within that strategy is
/// unchanged. If either differs, the old resource is orphaned and
/// needs teardown. Server-name diff is handled separately by the
/// caller — this only covers the LB / tunnel name itself.
fn edge_state_matches(
    a: &crate::networking::router::http_proxy::HttpProxy,
    b: &crate::networking::router::http_proxy::HttpProxy,
) -> bool {
    use crate::edge::EdgeStrategy as E;
    match (&a.edge, &b.edge) {
        (E::Local, E::Local) => true,
        (E::DnsRoundRobin { dns_provider_id: a1, .. },
         E::DnsRoundRobin { dns_provider_id: b1, .. }) => a1 == b1,
        (E::CloudflareDns { dns_provider_id: a1, .. },
         E::CloudflareDns { dns_provider_id: b1, .. }) => a1 == b1,
        (E::HetznerLb { cloud_provider_id: a1, lb_name: a2, .. },
         E::HetznerLb { cloud_provider_id: b1, lb_name: b2, .. }) => a1 == b1 && a2 == b2,
        (E::DigitalOceanLb { cloud_provider_id: a1, lb_name: a2, .. },
         E::DigitalOceanLb { cloud_provider_id: b1, lb_name: b2, .. }) => a1 == b1 && a2 == b2,
        (E::CloudflareTunnel { cloud_provider_id: a1, tunnel_name: a2, .. },
         E::CloudflareTunnel { cloud_provider_id: b1, tunnel_name: b2, .. }) => a1 == b1 && a2 == b2,
        _ => false,
    }
}

/// DELETE /api/router/http-proxies/{id} — remove. If the proxy has a
/// non-Local edge strategy we also tear down the cloud resources
/// (Hetzner/DigitalOcean LB, Cloudflare Tunnel, DNS records) so the
/// operator doesn't keep paying for orphaned infrastructure. Teardown
/// is best-effort: any provider errors come back as warnings, the
/// local delete still succeeds.
pub async fn delete_http_proxy(
    req: HttpRequest, state: S,
    path: web::Path<String>,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    // Capture the proxy we're about to delete so we can run edge
    // teardown against it after dropping the read lock.
    let to_delete = {
        let cur = state.router.config.read().unwrap();
        let existing = cur.http_proxies.iter().find(|p| p.id == id);
        match existing {
            None => return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("HTTP proxy '{}' not found", id)
            })),
            Some(old) => {
                for t in &old.targets {
                    if let Some(resp) = cluster_guard_node_id(&state, &query, Some(t.node_id.as_str())) {
                        return resp;
                    }
                }
                old.clone()
            }
        }
    };
    // Tear down cloud resources before removing the config — if
    // teardown fails we still proceed with the local delete (the
    // warnings list is surfaced to the operator).
    let edge_warnings = crate::edge::teardown::teardown_proxy(&to_delete).await;
    {
        let mut cur = state.router.config.write().unwrap();
        cur.http_proxies.retain(|p| p.id != id);
        if let Err(e) = cur.save() {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("save router config: {}", e)
            }));
        }
    }
    let cfg_snapshot = state.router.config.read().unwrap().http_proxies.clone();
    let self_id = crate::agent::self_node_id();
    let mut warnings = crate::networking::router::http_proxy::apply_for_node(&cfg_snapshot, &self_id);
    warnings.extend(edge_warnings);
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(serde_json::json!({
        "ok": true, "removed": id, "apply_warnings": warnings,
    }))
}

// ─── Subnet Routing ───

pub async fn list_subnet_routes(req: HttpRequest, state: S, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    let routes = state.router.config.read().unwrap().subnet_routes.clone();
    let filtered: Vec<&SubnetRoute> = match cluster_node_id_set(&state, &query) {
        None => routes.iter().collect(),
        // Strict cluster isolation, same as list_rules — a route with
        // node_id=None ("apply cluster-wide") would leak across
        // cluster views since it operates on nodes the operator
        // isn't currently managing. Hide them; operators need to
        // pin to a specific node when creating from a cluster view.
        Some(set) => routes.iter()
            .filter(|r| match &r.node_id {
                None => false,
                Some(nid) => set.contains(nid),
            })
            .collect(),
    };
    HttpResponse::Ok().json(filtered)
}

/// GET /api/router/subnet-routes/ipv6 — report the IPv6 subnet-routing
/// opt-in for this node plus whether the host has a working IPv6 stack, so
/// the UI can render the toggle and an accurate "IPv6 disabled on this
/// host" hint.
pub async fn get_ipv6_subnet_setting(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    let enabled = state.router.config.read().unwrap().ipv6_subnet_routing;
    HttpResponse::Ok().json(serde_json::json!({
        "ipv6_subnet_routing": enabled,
        "ipv6_available": super::ipv6_available(),
    }))
}

#[derive(serde::Deserialize)]
pub struct Ipv6SubnetSettingBody {
    pub enabled: bool,
}

/// POST /api/router/subnet-routes/ipv6 — flip the IPv6 subnet-routing
/// opt-in. Turning it ON applies any enabled v6 routes that target this
/// node and publishes them to wolfnetd; turning it OFF tears down this
/// node's v6 kernel routes / ip6tables plumbing and re-syncs wolfnetd so
/// the v6 CIDRs vanish from the daemon's table. The flag lives in
/// RouterConfig, so it replicates cluster-wide via the normal config push.
pub async fn set_ipv6_subnet_setting(
    req: HttpRequest,
    state: S,
    body: web::Json<Ipv6SubnetSettingBody>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let enable = body.enabled;
    let self_id = crate::agent::self_node_id();

    // Persist the flag first so apply_subnet_route (which reads it from
    // disk via v6_subnet_routing_enabled) sees the new value below.
    {
        let mut cfg = state.router.config.write().unwrap();
        cfg.ipv6_subnet_routing = enable;
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "ok": false,
                "error": format!("Failed to save config: {}", e),
            }));
        }
    }

    // The enabled v6 routes this node actually handles (consumer or
    // gateway). Snapshot under the read lock, act outside it.
    let v6_routes: Vec<SubnetRoute> = {
        let cfg = state.router.config.read().unwrap();
        cfg.subnet_routes.iter()
            .filter(|r| r.enabled && super::is_ipv6_cidr(&r.subnet_cidr))
            .filter(|r| super::node_handles_route(r, &self_id))
            .cloned()
            .collect()
    };

    let mut warnings: Vec<String> = Vec::new();
    if enable {
        if !super::ipv6_available() {
            warnings.push("IPv6 is disabled on this host (net.ipv6.conf.all.disable_ipv6=1); IPv6 routes will not pass traffic until you enable IPv6 and forwarding.".to_string());
        }
        for r in &v6_routes {
            if let Err(e) = super::apply_subnet_route(r, None) {
                warnings.push(format!("{}: {}", r.subnet_cidr, e));
            }
        }
    } else {
        // Turning off — tear down this node's v6 kernel state. remove_* is
        // not gated on the flag, so cleanup always runs.
        for r in &v6_routes {
            if let Err(e) = super::remove_subnet_route(r) {
                warnings.push(format!("{}: {}", r.subnet_cidr, e));
            }
        }
    }

    // Re-sync wolfnetd (now includes/excludes v6 CIDRs per the flag) and
    // replicate the flag to the cluster.
    {
        let snapshot = state.router.config.read().unwrap().subnet_routes.clone();
        super::sync_subnet_routes_to_wolfnet(&snapshot);
    }
    replicate_config_to_cluster(state);

    let mut resp = serde_json::json!({
        "ok": true,
        "ipv6_subnet_routing": enable,
        "ipv6_available": super::ipv6_available(),
    });
    if !warnings.is_empty() {
        resp["warnings"] = serde_json::Value::Array(
            warnings.into_iter().map(serde_json::Value::String).collect()
        );
    }
    HttpResponse::Ok().json(resp)
}

pub async fn create_subnet_route(req: HttpRequest, state: S, body: web::Json<SubnetRoute>, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    if let Some(resp) = cluster_guard_node_id(&state, &query, body.node_id.as_deref()) { return resp; }
    let mut route = body.into_inner();

    // Generate ID if not provided
    if route.id.is_empty() {
        route.id = gen_id("subnet-route");
    }
    // Hand-created, so hand-owned: auto-apply never tracks gossip's gateway for
    // it. (Belt and braces — the refresh also only considers `auto-wolfnet-`
    // ids, and `gen_id` never produces one.)
    route.operator_edited = true;

    // Basic validation
    if route.subnet_cidr.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "ok": false,
            "error": "subnet_cidr is required"
        }));
    }
    if route.gateway.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "ok": false,
            "error": "gateway is required"
        }));
    }

    // IPv6 subnet routing is opt-in (default off). Reject an ENABLED v6
    // destination up front with a clear, actionable message rather than
    // saving a dormant entry that never reaches the kernel. A disabled v6
    // route is allowed (staging) since it never applies. The gateway is
    // always an IPv4 WolfNet IP, so only the destination CIDR's family
    // matters here.
    if route.enabled && super::is_ipv6_cidr(route.subnet_cidr.trim()) {
        if !state.router.config.read().unwrap().ipv6_subnet_routing {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "ok": false,
                "error": "IPv6 subnet routing is disabled on this node. Turn on the 'IPv6 subnet routing' toggle in WolfRouter → Subnet Routes before adding an IPv6 route."
            }));
        }
        if !super::ipv6_available() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "ok": false,
                "error": "IPv6 is disabled on this node (net.ipv6.conf.all.disable_ipv6=1). Enable IPv6 and IPv6 forwarding before adding an IPv6 subnet route."
            }));
        }
    }

    // Reject overlapping subnet-route destinations. Codex P2 (v20.11.2):
    // apply uses `ip route replace`, which is atomic — but two routes that
    // both apply to the same node with the same CIDR silently overwrite
    // each other at the kernel level even though both still live in
    // `cfg.subnet_routes`. Subsequent deletes of either id then remove the
    // only kernel route. Reject the overlap up front.
    //
    // Two routes A and B overlap on node N iff their CIDRs match AND both
    // apply on N. A route applies on N iff node_id is None (cluster-wide)
    // or equals N. So the overlap predicate is:
    //   • either route is cluster-wide, OR
    //   • both pin to the same specific node.
    // Re-check overlap inside the write lock to defeat TOCTOU races
    // (Codex P2, v20.11.2): two concurrent overlapping creates could both
    // pass a read-lock check and then both push, leaving duplicate
    // entries. Doing the check + push under one write lock makes the
    // operation atomic with respect to peer writers.
    {
        let mut cfg = state.router.config.write().unwrap();
        let conflict = cfg.subnet_routes.iter()
            .find(|r| r.id != route.id && routes_can_overlap(r, &route))
            .cloned();
        if let Some(conflict) = conflict {
            let r_scope = scope_label(&route.node_id);
            let c_scope = scope_label(&conflict.node_id);
            return HttpResponse::Conflict().json(serde_json::json!({
                "ok": false,
                "error": format!(
                    "A subnet route for {} already exists ({}). The new entry ({}) would overlap on at least one node — edit the existing entry or delete it first.",
                    route.subnet_cidr, c_scope, r_scope
                )
            }));
        }
        cfg.subnet_routes.push(route.clone());
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "ok": false,
                "error": format!("Failed to save config: {}", e)
            }));
        }
    }

    // Apply to the kernel on this node if the route targets us. Bug fix
    // (sponsor report v20.11.2): prior versions saved the route to config
    // and replicated it cluster-wide, but never called `ip route add` on
    // any node — so the route was visible in the UI but unreachable until
    // the next service restart.
    let self_id = crate::agent::self_node_id();
    let mut apply_warning: Option<String> = None;
    // v20.11.6: node_handles_route widens the filter so the gateway node
    // also runs apply (and installs forwarding plumbing) — pre-fix the
    // gateway was excluded and packets reached the LAN but couldn't
    // return.
    if route.enabled && super::node_handles_route(&route, &self_id) {
        // Fresh create — no previous gateway to authorize a swap with.
        if let Err(e) = super::apply_subnet_route(&route, None) {
            tracing::warn!("create_subnet_route: apply failed on this node: {}", e);
            apply_warning = Some(e);
        } else {
            tracing::info!(
                "create_subnet_route: applied {} via {} on {}",
                route.subnet_cidr, route.gateway, self_id
            );
        }
    }

    // Tell wolfnetd about the new CIDR. Without this, kernel routes
    // pointing at wolfnet0 stay invisible to the userspace daemon and
    // packets get dropped before encapsulation. Order doesn't matter
    // vs replication — wolfnet sync is local-only.
    {
        let cfg = state.router.config.read().unwrap();
        super::sync_subnet_routes_to_wolfnet(&cfg.subnet_routes);
    }

    // Replication tells peer nodes to re-read config. config_receive on each
    // peer now diffs old vs new subnet_routes and applies any that target it.
    replicate_config_to_cluster(state);

    let mut resp = serde_json::json!({ "ok": true, "route": route });
    if let Some(w) = apply_warning {
        resp["apply_warning"] = serde_json::Value::String(w);
    }
    HttpResponse::Ok().json(resp)
}

pub async fn update_subnet_route(
    req: HttpRequest,
    state: S,
    path: web::Path<String>,
    body: web::Json<SubnetRoute>,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let mut updated = body.into_inner();
    // The operator has saved this route by hand — auto-apply must stop
    // tracking gossip's gateway for it, or it will overwrite this edit on the
    // next tick (klasSponsor 2026-07-30). Set server-side rather than trusting
    // the client to send it.
    updated.operator_edited = true;

    if updated.subnet_cidr.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "ok": false,
            "error": "subnet_cidr is required"
        }));
    }
    if updated.gateway.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "ok": false,
            "error": "gateway is required"
        }));
    }

    // IPv6 opt-in gate (mirrors create). Only blocks ENABLING a v6 route
    // while the feature is off — editing or DISABLING an existing v6 route
    // is always allowed so the operator can clean up after turning the
    // feature off.
    if updated.enabled && super::is_ipv6_cidr(updated.subnet_cidr.trim()) {
        if !state.router.config.read().unwrap().ipv6_subnet_routing {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "ok": false,
                "error": "IPv6 subnet routing is disabled on this node. Turn on the 'IPv6 subnet routing' toggle in WolfRouter → Subnet Routes before enabling an IPv6 route."
            }));
        }
        if !super::ipv6_available() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "ok": false,
                "error": "IPv6 is disabled on this node (net.ipv6.conf.all.disable_ipv6=1). Enable IPv6 and IPv6 forwarding before enabling an IPv6 subnet route."
            }));
        }
    }
    if let Some(resp) = cluster_guard_existing_subnet_route(&state, &query, &id) { return resp; }
    if let Some(resp) = cluster_guard_node_id(&state, &query, updated.node_id.as_deref()) { return resp; }

    // Capture the OLD route before overwriting so we can correctly remove
    // its kernel entry if the CIDR/gateway changed or the route flipped to
    // disabled. Without this, edits leave stale `ip route` entries behind.
    let old_route = {
        let cfg = state.router.config.read().unwrap();
        cfg.subnet_routes.iter().find(|r| r.id == id).cloned()
    };

    // 404 BEFORE 409 (Codex P3, v20.11.2) — if the id doesn't exist, return
    // Not Found regardless of whether the body would have collided with
    // some other route. Otherwise stale-id PUTs misreport as Conflict.
    if old_route.is_none() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "ok": false,
            "error": "Subnet route not found"
        }));
    }

    // Atomic overlap-check + write (Codex P2, v20.11.2): combining both
    // under one write lock prevents two concurrent updates from each
    // passing a read-lock check and then both committing. The 404 was
    // already returned above, but we still re-look-up the row here in
    // case a concurrent delete removed it between then and now.
    {
        let mut cfg = state.router.config.write().unwrap();
        let conflict = cfg.subnet_routes.iter()
            .find(|r| r.id != id && routes_can_overlap(r, &updated))
            .cloned();
        if let Some(conflict) = conflict {
            let u_scope = scope_label(&updated.node_id);
            let c_scope = scope_label(&conflict.node_id);
            return HttpResponse::Conflict().json(serde_json::json!({
                "ok": false,
                "error": format!(
                    "Another subnet route for {} already exists ({}). This update ({}) would overlap on at least one node — edit that entry or delete one of them first.",
                    updated.subnet_cidr, c_scope, u_scope
                )
            }));
        }
        match cfg.subnet_routes.iter_mut().find(|r| r.id == id) {
            Some(route) => *route = updated.clone(),
            None => {
                // Race: someone deleted us between the early 404 check
                // and acquiring the write lock. Treat as 404 too.
                return HttpResponse::NotFound().json(serde_json::json!({
                    "ok": false,
                    "error": "Subnet route not found"
                }));
            }
        }
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "ok": false,
                "error": format!("Failed to save config: {}", e)
            }));
        }
    }

    // Reconcile kernel state on this node.
    //
    // Order matters (Codex P1, v20.11.2): we apply the NEW route first
    // (apply_subnet_route uses `ip route replace`, which is atomic — failure
    // leaves the existing route untouched), and only remove the OLD entry if
    //   (a) the apply succeeded (or there's nothing to apply because the
    //       route was disabled/moved off this node), AND
    //   (b) the old destination CIDR actually differs from the new one,
    //       because for same-CIDR edits the `replace` already overwrote it
    //       in place — running `ip route del` would then take the route off
    //       the kernel entirely.
    //
    // This means a typo in the new gateway never blackholes the previously-
    // working route.
    let self_id = crate::agent::self_node_id();
    let mut apply_warning: Option<String> = None;
    // v20.11.6: node_handles_route covers both "configured target" and
    // "gateway" roles so the gateway re-installs plumbing on update.
    let new_should_apply = updated.enabled && super::node_handles_route(&updated, &self_id);
    // For an update, pass the OLD gateway so apply_subnet_route can tell
    // "this is our route, swap it" from "this is someone else's, leave it".
    // We only carry the OLD gateway when the OLD route was a *consumer*
    // role on this node (route_targets_self) — that's the only role that
    // installed an `ip route` entry. Gateway-role on this node never
    // installed a route entry, so there's nothing to authorise a swap of.
    let prev_gw_for_apply = old_route.as_ref().and_then(|o| {
        if o.enabled && super::route_targets_self(o, &self_id)
            && o.subnet_cidr == updated.subnet_cidr {
            Some(o.gateway.clone())
        } else {
            None
        }
    });
    let new_apply_ok = if new_should_apply {
        match super::apply_subnet_route(&updated, prev_gw_for_apply.as_deref()) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("update_subnet_route: apply failed on this node: {}", e);
                apply_warning = Some(e);
                false
            }
        }
    } else {
        true // nothing to apply, treat as "succeeded" so removal of obsolete old can proceed
    };

    if let Some(old) = &old_route {
        // v20.11.6: include the gateway role here too — if this node was
        // the gateway for the OLD route, plumbing was installed and must
        // be cleaned when the route is removed/disabled/moved.
        let old_was_applied_here = old.enabled && super::node_handles_route(old, &self_id);
        if old_was_applied_here {
            let cidr_changed = updated.subnet_cidr != old.subnet_cidr;
            let gateway_changed = updated.gateway != old.gateway;
            // Remove the old entry/plumbing when the destination CIDR
            // changed, the gateway IP changed (which can shift the
            // gateway role onto a different node), or the new route
            // doesn't apply here at all.
            if (cidr_changed || gateway_changed || !new_should_apply) && new_apply_ok
                && let Err(e) = super::remove_subnet_route(old) {
                    tracing::warn!("update_subnet_route: remove old failed: {}", e);
                }
        }
    }

    {
        let cfg = state.router.config.read().unwrap();
        super::sync_subnet_routes_to_wolfnet(&cfg.subnet_routes);
    }
    replicate_config_to_cluster(state);
    let mut resp = serde_json::json!({ "ok": true, "route": updated });
    if let Some(w) = apply_warning {
        resp["apply_warning"] = serde_json::Value::String(w);
    }
    HttpResponse::Ok().json(resp)
}

pub async fn delete_subnet_route(req: HttpRequest, state: S, path: web::Path<String>, query: web::Query<TopologyQuery>) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    if let Some(resp) = cluster_guard_existing_subnet_route(&state, &query, &id) { return resp; }

    let deleted_route = {
        let mut cfg = state.router.config.write().unwrap();
        let initial_len = cfg.subnet_routes.len();
        let deleted = cfg.subnet_routes.iter().find(|r| r.id == id).cloned();
        cfg.subnet_routes.retain(|r| r.id != id);

        if cfg.subnet_routes.len() == initial_len {
            return HttpResponse::NotFound().json(serde_json::json!({
                "ok": false,
                "error": "Subnet route not found"
            }));
        }

        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "ok": false,
                "error": format!("Failed to save config: {}", e)
            }));
        }

        deleted
    };

    // Try to remove the route from the kernel if it was applied here.
    // Codex P2 (v20.11.2): the previous version did this in a spawned
    // blocking task, which let a fast delete→recreate sequence race —
    // the spawned remove could fire AFTER the recreate's apply, deleting
    // the just-installed kernel entry. Doing it synchronously matches
    // create/update and keeps the API response well-ordered with the
    // kernel mutation.
    if let Some(route) = deleted_route {
        let self_id = crate::agent::self_node_id();
        // H2 fix: use the SAME predicate the apply path uses
        // (`node_handles_route`, which is target OR gateway).
        // Pre-fix this used `route_targets_self` (target only), so
        // routes where this node is the gateway-but-not-target had
        // their kernel entries installed at apply time but never
        // cleaned up on delete — stale `ip route` entries persisted
        // until reboot, and traffic kept getting forwarded.
        if super::node_handles_route(&route, &self_id)
            && let Err(e) = super::remove_subnet_route(&route) {
                tracing::warn!("delete_subnet_route: remove failed: {}", e);
            }
    }

    {
        let cfg = state.router.config.read().unwrap();
        super::sync_subnet_routes_to_wolfnet(&cfg.subnet_routes);
    }
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(serde_json::json!({
        "ok": true,
        "deleted": id
    }))
}

/// Per-node diagnostics for subnet routes. The handler runs on whichever
/// node receives the request, so the "kernel state" fields describe THIS
/// node only — the frontend fans the call out to every node in the
/// cluster (via /api/nodes/{id}/proxy/...) to compose a full picture.
///
/// Sponsor report 2026-04-27: a configured subnet route was reported as
/// missing from `ip route show` on the targeted VPS. Without per-node
/// kernel introspection the operator had no way to tell the difference
/// between (a) the config didn't replicate, (b) the apply failed silently,
/// (c) the config is on a different node than they expected. This handler
/// exposes all three.
pub async fn diagnostics_subnet_routes(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    let self_id = crate::agent::self_node_id();
    let routes: Vec<crate::networking::router::SubnetRoute> = {
        let cfg = state.router.config.read().unwrap();
        cfg.subnet_routes.clone()
    };

    let mut entries: Vec<serde_json::Value> = Vec::with_capacity(routes.len());
    for r in &routes {
        let targets_here = super::route_targets_self(r, &self_id);
        // v20.11.6: a node can also have a "gateway" role for a route —
        // when its wolfnet0 IP equals route.gateway it forwards traffic
        // INTO the subnet (and never installs an `ip route` entry of its
        // own). Diagnostics must distinguish so we don't report
        // "kernel route missing" on a node that's correctly acting as
        // the gateway — there's no kernel route to find there.
        let is_gateway_here = super::node_is_route_gateway(r);

        // Read raw `ip route show <cidr>` so we can report both the
        // present/absent answer and let the operator see exotic forms
        // (dev/blackhole/multipath) that don't fit the parsed shape.
        let (kernel_raw, kernel_error) = match super::read_kernel_route_raw(&r.subnet_cidr) {
            Ok(s) => (s, None),
            Err(e) => (String::new(), Some(e)),
        };
        let is_v6 = super::is_ipv6_cidr(&r.subnet_cidr);
        let kernel_present = !kernel_raw.trim().is_empty();
        // IPv6 consumer routes are device routes (`<cidr> dev wolfnet0`, no
        // `via`), so "matches our config" means the kernel route resolves
        // out the wolfnet interface — there is no gateway to compare. IPv4
        // is byte-identical to the previous via-gateway match.
        let (kernel_gw, kernel_matches) = if is_v6 {
            let wn = crate::networking::detect_wolfnet_iface()
                .unwrap_or_else(|| "wolfnet0".to_string());
            let dev = super::kernel_route6_dev_for_diagnostics(&r.subnet_cidr);
            (None, dev.as_deref() == Some(wn.as_str()))
        } else {
            let gw = super::parse_kernel_route_gateway_for_diagnostics(&kernel_raw);
            let m = kernel_present && gw.as_deref() == Some(r.gateway.as_str());
            (gw, m)
        };

        // Map the (config × kernel) cross-product to a single status code
        // the frontend can colour-code without re-deriving the rules.
        // Detail messages are written for beginners — plain English, with
        // the exact command to fix and why it's broken in one sentence.
        let (status, detail) = if !r.enabled {
            (
                "disabled",
                "This route is switched off, so we don't expect it on any node. Re-enable it from the route list to install it.".to_string(),
            )
        } else if is_gateway_here {
            // Gateway role: this node owns the route's gateway IP and is
            // responsible for forwarding packets INTO the subnet. It
            // installs iptables/sysctl plumbing instead of a kernel
            // route entry. Status here is determined ENTIRELY by the
            // forwarding plumbing — no kernel route is expected.
            let fwd = super::read_forwarding_state(r);
            let mut missing: Vec<&str> = Vec::new();
            if fwd.ip_forward.as_deref() != Some("1") {
                missing.push("ip_forward (kernel forwarding disabled)");
            }
            if !fwd.forward_in {
                missing.push("FORWARD ACCEPT (incoming on WolfNet)");
            }
            if !fwd.forward_out {
                missing.push("FORWARD ACCEPT (return via WolfNet)");
            }
            if !fwd.masquerade {
                missing.push("POSTROUTING MASQUERADE (LAN reply path)");
            }

            // v22.0.2 — even with all four plumbing pieces in place, the
            // gateway needs an actual LAN-side path to forward packets
            // onto. If `ip route get <first IP in subnet>` resolves out
            // the wolfnet iface, we'd loop traffic back into the mesh
            // (gateway has no physical connection to the LAN). Sponsor
            // klasSponsor 2026-04-28 hit exactly this — diagnostics all
            // green, but the gateway VPS wasn't wired into 10.10.0.0/16.
            let egress_loop = fwd.subnet_egress_iface.as_deref()
                == Some(fwd.wolfnet_iface.as_str());
            let egress_unknown = fwd.subnet_egress_iface.is_none();

            if !missing.is_empty() {
                (
                    "gateway_misconfigured",
                    format!(
                        "Gateway role broken — this node owns `{}` (the route's gateway) and should be forwarding peer traffic into `{}`, but the following forwarding pieces are missing: {}. Fix: edit the route → save (re-applies plumbing), or restart WolfStack on this node.",
                        r.gateway, r.subnet_cidr, missing.join(", ")
                    ),
                )
            } else if egress_loop {
                (
                    "gateway_no_lan_path",
                    format!(
                        "Plumbing is correct, but this node has no LAN-side path to `{}`. The kernel says traffic to that subnet would go back out `{}` — the same WolfNet interface peers come in on — which would loop forever. WolfStack can't forward packets the kernel itself can't reach: you need a NIC on this gateway that's physically (or via VLAN) connected to `{}` and configured with an IP in that subnet. Check `ip route get` on this node and `ip -4 addr` to confirm a LAN-facing interface exists.",
                        r.subnet_cidr, fwd.wolfnet_iface, r.subnet_cidr
                    ),
                )
            } else if egress_unknown {
                (
                    "gateway_egress_unknown",
                    format!(
                        "Plumbing is correct, but we couldn't determine where this node would actually send packets destined for `{}` — `ip route get` returned no result. Usually means the destination is unreachable from this node (no specific route AND no default route applies). Verify with `ip route get {}` on this gateway.",
                        r.subnet_cidr,
                        super::first_addr_in_cidr(&r.subnet_cidr).unwrap_or_else(|| r.subnet_cidr.clone())
                    ),
                )
            } else {
                let egress_summary = match (&fwd.subnet_egress_iface, &fwd.subnet_egress_src) {
                    (Some(i), Some(s)) => format!(" Egress for `{}` resolves via `{}` (src `{}`).", r.subnet_cidr, i, s),
                    (Some(i), None) => format!(" Egress for `{}` resolves via `{}`.", r.subnet_cidr, i),
                    _ => String::new(),
                };
                (
                    "gateway_ok",
                    format!(
                        "Working — this node is the gateway for `{}` (wolfnet0 owns `{}`). All forwarding plumbing (ip_forward, FORWARD ACCEPT, MASQUERADE) is in place. Packets from peers will be forwarded into the LAN and replies routed back.{}",
                        r.subnet_cidr, r.gateway, egress_summary
                    ),
                )
            }
        } else if !targets_here {
            let owner = r.node_id.clone().unwrap_or_else(|| "(cluster-wide)".into());
            (
                "not_targeted_here",
                format!(
                    "Not relevant — you asked for this route to live on `{}`, not this node. That's fine. (We're showing this row so you can see it didn't accidentally end up here too.)",
                    owner
                ),
            )
        } else if let Some(err) = &kernel_error {
            (
                "kernel_query_failed",
                format!(
                    "We couldn't ask the Linux kernel about this route on this node — the `ip` command failed: {}. Usually means WolfStack isn't running with enough permissions. Check the service logs.",
                    err
                ),
            )
        } else if !kernel_present {
            // `ip route show <exact-cidr>` returned nothing — but the
            // destination may still be reachable through a wider prefix
            // already in the kernel (e.g. configured /24 covered by an
            // existing /16 via the same gateway). Probe `ip route get` to
            // distinguish "truly missing" from "covered by broader route".
            // klasSponsor 2026-05-13: `ip r` showed the route and ping
            // worked, but diagnostics said missing.
            let wn_iface = crate::networking::detect_wolfnet_iface()
                .unwrap_or_else(|| "wolfnet0".to_string());
            if super::route_covered_by_broader_prefix(&r.subnet_cidr, &r.gateway, &wn_iface) {
                (
                    "ok",
                    format!(
                        "Working — `{} via {}` isn't an exact entry in Linux's table, but a wider route already covers it via the same gateway on `{}`. Traffic to addresses in `{}` will be routed correctly through `{}`. No action needed.",
                        r.subnet_cidr, r.gateway, wn_iface, r.subnet_cidr, r.gateway
                    ),
                )
            } else {
                (
                    "missing",
                    format!(
                        "Broken — this node was supposed to install `{} via {}` into Linux, but the route is not there and no broader route covers it via `{}`. The most common cause is that the route's Node Assignment doesn't match a real node in this cluster (look at the route's settings — if it shows a hostname like `myserver` instead of a `ws-…` ID, edit the route and pick the node from the dropdown). Other possible causes: the WolfStack service restarted at the wrong moment, or another program holds a conflicting route. Try: edit the route → save (re-applies on save), or restart WolfStack on this node.",
                        r.subnet_cidr, r.gateway, r.gateway
                    ),
                )
            }
        } else if kernel_matches {
            // Consumer role (gateway role short-circuited above via
            // `is_gateway_here`). Per `apply_subnet_route`, consumers only
            // get the kernel `ip route` entry — NO iptables/sysctl plumbing.
            // The plumbing exists on whichever node owns the gateway IP.
            // klasSponsor 2026-05-13: diagnostics was reporting "Half-broken
            // — forwarding missing" on consumer VPSes whose route actually
            // worked end-to-end (ping passed). The plumbing it was looking
            // for is *never installed here* and its absence is correct.
            //
            // rp_filter strict (1) is the only forwarding-state knob that
            // can still bite a consumer (strict reverse-path can drop
            // wolfnet-sourced replies on some kernels), so we surface it
            // as an advisory without blocking "ok".
            let fwd = super::read_forwarding_state(r);
            let rp_strict = fwd.rp_filter_wolfnet.as_deref() == Some("1")
                || fwd.rp_filter_all.as_deref() == Some("1");
            let advisory = if rp_strict {
                format!(" Note: rp_filter is in strict mode on `{}` — usually fine, but switch to loose (0) if pings still fail.", fwd.wolfnet_iface)
            } else {
                String::new()
            };
            let installed_desc = if is_v6 {
                format!(
                    "IPv6 route `{}` is installed in Linux as a device route on `{}` (wolfnetd forwards it to gateway peer `{}`)",
                    r.subnet_cidr, fwd.wolfnet_iface, r.gateway
                )
            } else {
                format!("route `{} via {}` is installed in Linux", r.subnet_cidr, r.gateway)
            };
            (
                "ok",
                format!(
                    "Working — {}. As the consumer side, this node only needs the route entry (no iptables/sysctl plumbing — that lives on the gateway node `{}`).{}",
                    installed_desc, r.gateway, advisory
                ),
            )
        } else if let Some(gw) = &kernel_gw {
            (
                "wrong_gateway",
                format!(
                    "Conflict — Linux already has a route to `{}` but it points to `{}`, not your configured gateway `{}`. Something else (a VPN client, a manual `ip route add`, or another routing tool) installed it first. WolfStack will NOT silently overwrite that. To fix: SSH into this node and run `sudo ip route del {}` to remove the conflicting route, then come back here and click Re-run.",
                    r.subnet_cidr, gw, r.gateway, r.subnet_cidr
                ),
            )
        } else {
            (
                "unsupported_form",
                format!(
                    "Special route — Linux has a route to `{}` but in a shape WolfStack doesn't know how to manage (for example a route bound directly to a network card, a `blackhole` or `unreachable` route, or a load-balanced route). SSH into this node and run `ip route show {}` to see what's there, then either delete it or pick a different destination subnet.",
                    r.subnet_cidr, r.subnet_cidr
                ),
            )
        };

        // Inspect forwarding plumbing for the JSON payload whenever this
        // node has a role to play in the route: it's a configured target
        // with a kernel route in place, OR it's the gateway. Both roles
        // depend on the plumbing.
        let fwd_state = if r.enabled && (is_gateway_here || (targets_here && kernel_matches)) {
            Some(super::read_forwarding_state(r))
        } else {
            None
        };

        entries.push(serde_json::json!({
            "id": r.id,
            "subnet_cidr": r.subnet_cidr,
            "configured_gateway": r.gateway,
            "configured_node_id": r.node_id,
            "enabled": r.enabled,
            "description": r.description,
            "targets_this_node": targets_here,
            "is_gateway_here": is_gateway_here,
            "kernel_present": kernel_present,
            "kernel_gateway": kernel_gw,
            "kernel_matches_config": kernel_matches,
            "kernel_raw": kernel_raw,
            "kernel_error": kernel_error,
            "forwarding": fwd_state,
            "status": status,
            "status_detail": detail,
        }));
    }

    // Full IPv4 routing table — useful when a route appears missing but
    // the destination is actually covered by something broader (e.g. a
    // default route or a /16 that subsumes a /24).
    let (ip_route_dump, ip_route_error) = match super::read_kernel_route_table() {
        Ok(s) => (s, None),
        Err(e) => (String::new(), Some(e)),
    };

    // IPv4 forwarding state. Routes on a transit node are useless if
    // /proc/sys/net/ipv4/ip_forward is 0 — the kernel will accept the
    // route but drop traffic that needs to traverse it.
    let ip_forward = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .ok()
        .map(|s| s.trim().to_string());

    // ─── Orphan detection ───
    //
    // Klas (2026-05-04): "There is no way to remove an orphaned subnet
    // route". The diagnostics endpoint above only iterates CONFIGURED
    // routes — kernel entries that go via the WolfNet interface but
    // aren't in the config silently fall off the page, with no UI
    // surface to remove them. Surface them here so the frontend can
    // render an "Orphaned routes" section with a one-click remove.
    let orphans = super::list_orphan_subnet_routes(&routes);

    HttpResponse::Ok().json(serde_json::json!({
        "node_id": self_id,
        "routes": entries,
        "orphans": orphans,
        "ip_route_dump": ip_route_dump,
        "ip_route_error": ip_route_error,
        "ip_forward": ip_forward,
    }))
}

/// POST /api/router/subnet-routes/orphan/remove — force-delete a
/// kernel subnet route that has no matching config row. Body:
/// `{ "cidr": "10.0.0.0/24", "gateway": "10.10.0.5" }`.
///
/// Verifies the kernel currently has a route for `cidr` whose gateway
/// matches `gateway` before deleting — if they've diverged since the
/// operator clicked Remove, we refuse rather than blindly remove a
/// route some other tool installed.
#[derive(serde::Deserialize)]
pub struct RemoveOrphanRouteRequest {
    pub cidr: String,
    pub gateway: String,
}

pub async fn remove_orphan_subnet_route(
    req: HttpRequest,
    state: S,
    body: web::Json<RemoveOrphanRouteRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let body = body.into_inner();

    // Cross-check against the live config: if the operator-supplied
    // (cidr, gateway) pair somehow IS in the config now (race vs
    // edits since they loaded the diagnostics page), refuse the
    // orphan-remove and tell them to use the regular delete-route
    // endpoint instead — we don't want to silently bypass the
    // config-aware code path.
    {
        let cfg = state.router.config.read().unwrap();
        let matched = cfg.subnet_routes.iter().any(|r|
            r.subnet_cidr.trim() == body.cidr.trim()
            && r.gateway.trim() == body.gateway.trim()
        );
        if matched {
            return HttpResponse::Conflict().json(serde_json::json!({
                "ok": false,
                "error": "This route exists in the configuration — use the regular Delete button on the route, not the orphan cleanup. (The orphan-remove path is only for kernel entries with no matching config row.)"
            }));
        }
    }

    match super::remove_orphan_kernel_route(&body.cidr, &body.gateway) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "ok": true,
            "removed": { "cidr": body.cidr, "gateway": body.gateway }
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "ok": false,
            "error": e
        })),
    }
}

/// POST /api/router/subnet-routes/{id}/reapply — force `apply_subnet_route`
/// to run for the named route on THIS node, return the result. This is
/// the operator-visible path for the case where edit+save left the
/// kernel state wrong (silent apply failure during config_receive on a
/// peer, missing iptables binary, etc.). The frontend fans this out via
/// the existing `/api/nodes/{id}/proxy/...` wrapper so the operator can
/// re-apply on the specific node that diagnostics flagged as broken.
///
/// klasSponsor 2026-05-13: gateway diagnostics reported "gateway plumbing
/// missing" and edit+save didn't fix it because the apply on the gateway
/// node was failing silently inside `config_receive`. This endpoint
/// surfaces those errors so the operator can see WHY the plumbing won't
/// install.
pub async fn reapply_subnet_route(
    req: HttpRequest,
    state: S,
    path: web::Path<String>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let self_id = crate::agent::self_node_id();

    let route = {
        let cfg = state.router.config.read().unwrap();
        cfg.subnet_routes.iter().find(|r| r.id == id).cloned()
    };
    let route = match route {
        Some(r) => r,
        None => return HttpResponse::NotFound().json(serde_json::json!({
            "ok": false,
            "error": "Subnet route not found"
        })),
    };

    if !route.enabled {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "ok": false,
            "error": "Route is disabled — enable it from the route list before re-applying"
        }));
    }

    let role = if super::node_is_route_gateway(&route) {
        "gateway"
    } else if super::route_targets_self(&route, &self_id) {
        "consumer"
    } else {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "ok": false,
            "error": "This node is neither the configured consumer nor the gateway for this route — re-apply on the right node instead.",
            "node_id": self_id,
        }));
    };

    match super::apply_subnet_route(&route, None) {
        Ok(()) => {
            // Keep wolfnetd's longest-prefix-match map in sync with the
            // configured set so any side-effect on the userspace daemon
            // (e.g. dropped CIDR after a previous bad apply) is also
            // resolved by the same operator click. Snapshot the routes
            // and drop the read lock before the disk write so we don't
            // block concurrent writers during I/O. (wolfnetd reloads the
            // file on its own 15s tick — no SIGHUP, see sync_subnet_routes_to_wolfnet.)
            let snapshot = {
                let cfg = state.router.config.read().unwrap();
                cfg.subnet_routes.clone()
            };
            super::sync_subnet_routes_to_wolfnet(&snapshot);
            HttpResponse::Ok().json(serde_json::json!({
                "ok": true,
                "node_id": self_id,
                "role": role,
                "applied": {
                    "subnet_cidr": route.subnet_cidr,
                    "gateway": route.gateway,
                },
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "ok": false,
            "node_id": self_id,
            "role": role,
            "error": e,
        })),
    }
}

/// POST /api/router/wolfnet/routes/resync — recompute the local route
/// map from cluster gossip + local containers and flush to
/// `/var/run/wolfnet/routes.json` (wolfnetd reloads it on its own 15s tick;
/// no SIGHUP — see containers::flush_routes_to_disk). Returns the route map
/// that was written so the operator can verify the propagation actually landed.
///
/// klasSponsor 2026-05-13: container/VM WolfNet IPs unreachable from the
/// VPS while peer-to-peer ping kept working — symptom of routes.json
/// being stale on the VPS. The poll loop is supposed to keep it fresh,
/// but a wedged poll or transient parse failure can leave entries
/// missing. This button gives the operator a way to force a resync
/// without restarting WolfStack.
pub async fn wolfnet_routes_resync(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);

    // Build the route table the same way the periodic poll does, but
    // synchronously and from the current cluster snapshot. We don't
    // re-poll peers here — `poll_remote_nodes` is the canonical
    // gatherer; this just re-applies what we've already collected.
    let mut routes: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    // Local container / VM / VIP IPs → this node's wolfnet IP.
    let local_ips = crate::containers::wolfnet_active_ips(); // running only
    let local_host_wn_ip = local_ips.first().cloned().unwrap_or_default();
    if local_ips.len() > 1
        && local_host_wn_ip.parse::<std::net::Ipv4Addr>().is_ok()
    {
        for ip in &local_ips[1..] {
            if ip.is_empty() || ip == &local_host_wn_ip { continue; }
            if ip.parse::<std::net::Ipv4Addr>().is_err() { continue; }
            routes.insert(ip.clone(), local_host_wn_ip.clone());
        }
    }

    // Remote nodes — pick up their advertised wolfnet_ips by re-polling
    // the agent endpoint.
    //
    // M1 fix: reuse the process-wide ROUTER_RPC_CLIENT instead of
    // building a fresh reqwest::Client per request. The process-wide
    // pool keeps connections to peers warm across calls; the per-request
    // builder discarded them every time.
    let client = &*ROUTER_RPC_CLIENT;
    let nodes = state.cluster.get_all_nodes();
    let mut polled_peers: usize = 0;
    for node in &nodes {
        if node.is_self { continue; }
        if !node.online { continue; }
        // Proxmox-type members don't run a WolfStack agent — they're
        // PVE hosts surfaced through the standalone integration and
        // don't have `/api/agent/status`. Match the skip in
        // `poll_remote_nodes` so we don't waste a 10-second timeout on
        // every Proxmox peer in the cluster.
        if node.node_type == "proxmox" { continue; }
        let urls = crate::api::build_node_urls(&node.address, node.port, "/api/agent/status");
        let mut got = false;
        for url in &urls {
            let resp = client.get(url)
                .peer_auth(&state.cluster_secret)
                .send().await;
            let resp = match resp {
                Ok(r) if r.status().is_success() => r,
                _ => continue,
            };
            let msg: Result<crate::agent::AgentMessage, _> = resp.json().await;
            if let Ok(crate::agent::AgentMessage::StatusReport { wolfnet_ips, .. }) = msg {
                if wolfnet_ips.len() > 1 {
                    let host_wn_ip = &wolfnet_ips[0];
                    if !host_wn_ip.is_empty()
                        && host_wn_ip.parse::<std::net::Ipv4Addr>().is_ok()
                    {
                        for container_ip in &wolfnet_ips[1..] {
                            if container_ip.is_empty() || container_ip == host_wn_ip { continue; }
                            if container_ip.parse::<std::net::Ipv4Addr>().is_err() { continue; }
                            routes.insert(container_ip.clone(), host_wn_ip.clone());
                        }
                    }
                }
                got = true;
                break;
            }
        }
        if got { polled_peers += 1; }
    }

    let count = routes.len();
    crate::containers::replace_wolfnet_routes(routes.clone());

    HttpResponse::Ok().json(serde_json::json!({
        "ok": true,
        "node_id": crate::agent::self_node_id(),
        "polled_peers": polled_peers,
        "route_count": count,
        "routes": routes,
    }))
}

// ─── LAN Health ───
//
// Per-LAN runtime health for the WolfRouter "Health" tab. Each endpoint
// is read-only except `restart_dnsmasq` and `set_lan_interface`, which
// are explicit one-click actions surfaced as `action: "..."` on the
// health checks themselves. Cross-node calls proxy via the existing
// `proxy_router_get_to_node`.

/// GET /api/router/segments/{id}/health
/// Returns a `LanHealth` for one LAN. When the LAN is owned by another
/// node, proxies the call to the owner so the operator gets the *live*
/// runtime state, not stale cluster cache.
pub async fn get_lan_health(
    req: HttpRequest, state: S, path: web::Path<String>
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let (lan_opt, owner_id) = {
        let cfg = state.router.config.read().unwrap();
        let lan = cfg.lans.iter().find(|l| l.id == id).cloned();
        let owner = lan.as_ref().map(|l| l.node_id.clone());
        (lan, owner)
    };
    let Some(lan) = lan_opt else {
        return HttpResponse::NotFound().body("LAN not found");
    };
    let self_id = crate::agent::self_node_id();
    if owner_id.as_deref() != Some(&self_id) {
        let owner = owner_id.unwrap_or_default();
        return proxy_router_get_to_node(
            state, &owner,
            &format!("router/segments/{}/health", id),
            "",
        ).await;
    }
    // Local: run health checks on the blocking pool — `ss`, iptables-save
    // and the UDP probe all do syscalls that shouldn't block the runtime.
    let lan2 = lan.clone();
    let report = tokio::task::spawn_blocking(move || {
        super::health::lan_health(&lan2, &self_id)
    }).await.unwrap_or_else(|_| super::health::lan_health(&lan, &crate::agent::self_node_id()));
    HttpResponse::Ok().json(report)
}

/// GET /api/router/health[?cluster=NAME]
/// Aggregate every LAN's health across the requested cluster. Used by
/// the Health tab's overview list. **Cluster-scoped**: WolfRouter is
/// per-cluster, so a bastion managing multiple clusters must NOT mix
/// LANs from cluster A into cluster B's view. When `?cluster=NAME` is
/// set, LANs whose owning node isn't in that cluster are filtered out.
pub async fn list_lan_health(
    req: HttpRequest, state: S,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let cluster_filter = query.cluster.clone();
    let lans_all: Vec<LanSegment> = state.router.config.read().unwrap().lans.clone();
    let self_id = crate::agent::self_node_id();

    // Build a node_id → cluster_name map once so filtering N LANs is
    // O(N) instead of O(N²) cluster lookups. Node cluster name uses the
    // same "WolfStack" alias as the topology endpoint for nameless nodes.
    let nodes = state.cluster.get_all_nodes();
    let normalize = |n: Option<&str>| -> String {
        match n {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => "WolfStack".into(),
        }
    };
    let self_cluster_raw = state.cluster.get_self_cluster_name();
    let self_cluster_norm = normalize(
        if self_cluster_raw.is_empty() { None } else { Some(self_cluster_raw.as_str()) }
    );
    let mut node_cluster: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for n in &nodes {
        // Use the canonical self_cluster for self — gossip can leave a
        // stale name on the in-memory entry.
        let cname = if n.is_self || n.id == self_id {
            self_cluster_norm.clone()
        } else {
            normalize(n.cluster_name.as_deref())
        };
        node_cluster.insert(n.id.clone(), cname);
    }

    // Filter LANs by cluster_filter. LANs whose owning node we don't
    // know about (stale config? gone-but-not-tombstoned?) fall through
    // to "WolfStack" so they don't silently disappear.
    let lans: Vec<LanSegment> = lans_all.into_iter()
        .filter(|l| {
            let lan_cluster = node_cluster.get(&l.node_id)
                .cloned()
                .unwrap_or_else(|| "WolfStack".into());
            match &cluster_filter {
                Some(want) => &lan_cluster == want,
                None => true,
            }
        })
        .collect();

    let mut out: Vec<super::health::LanHealth> = Vec::with_capacity(lans.len());
    for lan in lans {
        if lan.node_id == self_id {
            let lan2 = lan.clone();
            let nid = self_id.clone();
            let report = tokio::task::spawn_blocking(move || {
                super::health::lan_health(&lan2, &nid)
            }).await.unwrap_or_else(|_|
                super::health::lan_health(&lan, &self_id)
            );
            out.push(report);
        } else {
            // Stub for remote LANs — the per-LAN endpoint can drill in.
            out.push(super::health::LanHealth {
                lan_id: lan.id.clone(),
                lan_name: lan.name.clone(),
                node_id: lan.node_id.clone(),
                status: "remote",
                checks: vec![],
                apply_resolution: None,
                breaker: None,
            });
        }
    }
    HttpResponse::Ok().json(serde_json::json!({
        "lans": out,
        "cluster_filter": cluster_filter,
    }))
}

/// POST /api/router/segments/{id}/restart-dnsmasq
/// One-click "Restart dnsmasq for this LAN". Resets the watchdog circuit
/// breaker so the next tick gives it another chance, then runs
/// `dhcp::start` with self-heal. Cross-node proxied to the owner.
pub async fn restart_lan_dnsmasq(
    req: HttpRequest, state: S, path: web::Path<String>
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let (lan_opt, owner_id) = {
        let cfg = state.router.config.read().unwrap();
        let lan = cfg.lans.iter().find(|l| l.id == id).cloned();
        let owner = lan.as_ref().map(|l| l.node_id.clone());
        (lan, owner)
    };
    let Some(lan) = lan_opt else {
        return HttpResponse::NotFound().body("LAN not found");
    };
    let self_id = crate::agent::self_node_id();
    if owner_id.as_deref() != Some(&self_id) {
        let owner = owner_id.unwrap_or_default();
        // Reuse the GET proxy path — the inter-node port accepts POST
        // through the same `/proxy/{path}` machinery.
        return proxy_router_post_to_node(
            state, &owner,
            &format!("router/segments/{}/restart-dnsmasq", id),
            serde_json::json!({}),
        ).await;
    }
    super::health::breaker_reset(&lan.id);
    let lan2 = lan.clone();
    let result = tokio::task::spawn_blocking(move || dhcp::start(&lan2)).await;
    match result {
        Ok(Ok(resolution)) => {
            super::health::breaker_record_success(&lan.id);
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "resolution": resolution,
            }))
        }
        Ok(Err(e)) => {
            super::health::breaker_record_failure(&lan.id, &e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": e,
            }))
        }
        Err(_) => HttpResponse::InternalServerError().body("blocking task panicked"),
    }
}

#[derive(Deserialize)]
pub struct SetLanInterfaceRequest {
    pub interface: String,
}

/// POST /api/router/segments/{id}/set-interface
/// One-click "Use the actual interface" from the LAN Health panel —
/// rewrites the saved LAN config so `interface` matches the iface that
/// actually carries `router_ip`. Validates the new value the same way
/// PUT /segments/{id} would, then re-applies dnsmasq.
pub async fn set_lan_interface(
    req: HttpRequest, state: S,
    path: web::Path<String>, body: web::Json<SetLanInterfaceRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    let new_iface = body.interface.trim().to_string();
    if new_iface.is_empty() {
        return HttpResponse::BadRequest().body("interface must be non-empty");
    }
    // Same character whitelist as validate_segment uses for interfaces:
    // letters, digits, '.', '-', '_' (Linux netdev names allow these).
    if !new_iface.chars().all(|c|
        c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'
    ) {
        return HttpResponse::BadRequest().body("interface contains invalid characters");
    }

    let (lan_opt, owner_id) = {
        let cfg = state.router.config.read().unwrap();
        let lan = cfg.lans.iter().find(|l| l.id == id).cloned();
        let owner = lan.as_ref().map(|l| l.node_id.clone());
        (lan, owner)
    };
    let Some(_lan) = lan_opt else {
        return HttpResponse::NotFound().body("LAN not found");
    };
    let self_id = crate::agent::self_node_id();
    if owner_id.as_deref() != Some(&self_id) {
        let owner = owner_id.unwrap_or_default();
        return proxy_router_post_to_node(
            state, &owner,
            &format!("router/segments/{}/set-interface", id),
            serde_json::json!({ "interface": new_iface }),
        ).await;
    }

    // Mutate config under the write lock, save, then drop the lock
    // BEFORE shelling out to dhcp::start. Same pattern as set_query_log.
    let updated_lan = {
        let mut cfg = state.router.config.write().unwrap();
        let seg = match cfg.lans.iter_mut().find(|l| l.id == id) {
            Some(s) => s,
            None => return HttpResponse::NotFound().body("LAN not found"),
        };
        seg.interface = new_iface;
        let updated = seg.clone();
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(format!("save: {}", e));
        }
        updated
    };

    super::health::breaker_reset(&updated_lan.id);
    let lan2 = updated_lan.clone();
    let result = tokio::task::spawn_blocking(move || dhcp::start(&lan2)).await;
    replicate_config_to_cluster(state.clone());
    match result {
        Ok(Ok(resolution)) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "resolution": resolution,
            "lan": updated_lan,
        })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": e,
        })),
        Err(_) => HttpResponse::InternalServerError().body("blocking task panicked"),
    }
}

// ─── Preflight one-click Fix actions ────────────────────────────────
//
// Each handler does exactly ONE narrowly-scoped fix surfaced as a Fix
// button on a preflight row. Strictly safe — anything that could lock
// the operator out (host firewall edits on the management interface,
// say) stays instructions-only.

/// POST /api/router/fix/enable-ip-forward
/// Persist `net.ipv4.ip_forward=1` to /etc/sysctl.d/99-wolfrouter.conf
/// and reload sysctl. Idempotent — overwriting the drop-in is the
/// behaviour we want when a previous run wrote a stale value.
pub async fn fix_enable_ip_forward(
    req: HttpRequest, state: S, query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    // H1 fix: this fix mutates THIS node's sysctl. If the operator is
    // viewing a different cluster's WolfRouter, refuse — cross-cluster
    // "fix" buttons firing on the wrong node was a real risk.
    if let Some(resp) = cluster_guard_node_id(&state, &query, Some(&crate::agent::self_node_id())) {
        return resp;
    }
    let res = tokio::task::spawn_blocking(|| {
        let dropin = "/etc/sysctl.d/99-wolfrouter.conf";
        let body = "# Written by WolfRouter — required for any LAN/firewall forwarding to work.\n\
                    net.ipv4.ip_forward=1\n";
        if let Err(e) = std::fs::write(dropin, body) {
            return Err(format!("write {}: {}", dropin, e));
        }
        // Reload via `sysctl --system` so the change takes effect now,
        // not just at next reboot. Fallback to a direct write if sysctl
        // isn't available — most distros have it but containers often
        // don't ship it.
        let out = std::process::Command::new("sysctl").arg("--system").output();
        match out {
            Ok(o) if o.status.success() => Ok(format!(
                "Wrote {} and reloaded sysctl. IP forwarding is now ON.",
                dropin
            )),
            _ => {
                // Direct kernel write — works without sysctl(8).
                if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n") {
                    return Err(format!(
                        "wrote {} but couldn't apply live (`sysctl --system` failed AND direct /proc write failed: {}). \
                         The change will take effect at next reboot.",
                        dropin, e
                    ));
                }
                Ok(format!(
                    "Wrote {} and applied via /proc (sysctl(8) wasn't available). \
                     IP forwarding is now ON.",
                    dropin
                ))
            }
        }
    }).await.unwrap_or_else(|_| Err("blocking task panicked".into()));
    match res {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "success": true, "message": msg })),
        Err(e)  => HttpResponse::InternalServerError().json(serde_json::json!({ "success": false, "error": e })),
    }
}

/// POST /api/router/fix/purge-self-loop-routes
/// Delete every `default via <local-ip>` self-loop route. Same logic
/// the startup hook uses (`purge_self_loop_defaults`) — deletes ONLY
/// routes whose next-hop is one of THIS host's own IPs. Such routes
/// can never deliver a packet, so this can never make egress worse.
pub async fn fix_purge_self_loop_routes(
    req: HttpRequest, state: S, query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    // H1 fix: this fix mutates THIS node's kernel routes. Cluster-scope.
    if let Some(resp) = cluster_guard_node_id(&state, &query, Some(&crate::agent::self_node_id())) {
        return resp;
    }
    let removed = tokio::task::spawn_blocking(|| {
        super::purge_self_loop_defaults()
    }).await.unwrap_or_default();
    if removed.is_empty() {
        HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "No self-loop default routes found — nothing to remove. \
                        If preflight still flags this, find the persistent source \
                        (/etc/network/interfaces, /etc/netplan/*.yaml, \
                        NetworkManager profile) and remove it from there too.",
            "removed": removed,
        }))
    } else {
        HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!(
                "Removed {} self-loop default route(s) live. \
                 Edit the persistent source (e.g. `gateway <local-ip>` line in \
                 /etc/network/interfaces) so they don't come back at next reboot.",
                removed.len()
            ),
            "removed": removed,
        }))
    }
}

#[derive(Deserialize)]
pub struct DhclientIfaceRequest { pub iface: String }

/// POST /api/router/fix/dhclient
/// Bring an interface up and request a DHCP lease via dhclient(8).
/// Used by the WAN-DHCP "interface has no IPv4" preflight row when
/// the host's own DHCP client never grabbed a lease (Starlink trap,
/// boot-order race against the dishy bring-up).
pub async fn fix_dhclient_iface(
    req: HttpRequest, state: S, query: web::Query<TopologyQuery>,
    body: web::Json<DhclientIfaceRequest>,
) -> HttpResponse {
    auth_or_return!(req, state);
    // H1 fix: dhclient runs against THIS node's iface. Cluster-scope.
    if let Some(resp) = cluster_guard_node_id(&state, &query, Some(&crate::agent::self_node_id())) {
        return resp;
    }
    let iface = body.iface.trim().to_string();
    if iface.is_empty() || !iface.chars().all(|c|
        c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'
    ) {
        return HttpResponse::BadRequest().body("invalid iface");
    }
    let res = tokio::task::spawn_blocking(move || {
        // Bring it up (idempotent — `set up` on an up iface is a no-op).
        let _ = std::process::Command::new("ip")
            .args(["link", "set", &iface, "up"]).output();
        // dhclient -v writes verbose output to stderr; we propagate
        // the first error line so the operator sees what happened.
        let out = std::process::Command::new("dhclient")
            .args(["-v", "-1", "-nw", &iface])  // -1 = exit if lease can't be obtained
            .output()
            .map_err(|e| format!("spawn dhclient: {} (is dhclient installed?)", e))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!("dhclient on {} failed: {}", iface, stderr.trim()));
        }
        Ok(format!(
            "Requested a DHCP lease on {}. Re-run preflight in a few seconds — \
             the iface should now show an IPv4 address.",
            iface
        ))
    }).await.unwrap_or_else(|_| Err("blocking task panicked".into()));
    match res {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({ "success": true, "message": msg })),
        Err(e)  => HttpResponse::InternalServerError().json(serde_json::json!({ "success": false, "error": e })),
    }
}

/// POST /api/router/fix/wan/{id}/reapply
/// Re-apply a WAN connection — installs MASQUERADE, redials PPPoE if
/// needed, etc. Same logic the WAN editor's Save button runs.
pub async fn fix_reapply_wan(
    req: HttpRequest, state: S, path: web::Path<String>,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    // H1 fix: WAN belongs to a specific node; check that node is in
    // the caller's cluster scope before touching it. Pre-fix, an
    // operator on cluster A could re-apply cluster B's PPPoE WAN by
    // knowing its UUID — the proxy-to-owning-node code path would
    // happily forward the fix to cluster B's node.
    if let Some(resp) = cluster_guard_existing_wan(&state, &query, &id) { return resp; }
    let conn = {
        let cfg = state.router.config.read().unwrap();
        cfg.wan_connections.iter().find(|w| w.id == id).cloned()
    };
    let Some(conn) = conn else {
        return HttpResponse::NotFound().body("WAN connection not found");
    };
    if conn.node_id != crate::agent::self_node_id() {
        // Cross-node: proxy to the owning node so the kernel changes
        // happen there, not here.
        return proxy_router_post_to_node(
            state, &conn.node_id,
            &format!("router/fix/wan/{}/reapply", id),
            serde_json::json!({}),
        ).await;
    }
    let res = tokio::task::spawn_blocking(move || wan::apply(&conn)).await;
    match res {
        Ok(Ok(())) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "WAN re-applied. MASQUERADE rule should be back; PPPoE redialed if applicable.",
        })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false, "error": e,
        })),
        Err(_) => HttpResponse::InternalServerError().body("blocking task panicked"),
    }
}

/// POST /api/router/fix/wan/{id}/tick-pppoe-default-route
/// Set `use_default_route=true` on a PPPoE WAN, save, redial. The
/// preflight row that asks for this exists because pppd writes
/// `nodefaultroute` to the peer file when the flag is off — clearing
/// it requires a redial.
pub async fn fix_tick_pppoe_default_route(
    req: HttpRequest, state: S, path: web::Path<String>,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let id = path.into_inner();
    // H1 fix: same cluster-scope guard as fix_reapply_wan above.
    if let Some(resp) = cluster_guard_existing_wan(&state, &query, &id) { return resp; }
    let updated = {
        let mut cfg = state.router.config.write().unwrap();
        let Some(conn) = cfg.wan_connections.iter_mut().find(|w| w.id == id) else {
            return HttpResponse::NotFound().body("WAN connection not found");
        };
        let owner = conn.node_id.clone();
        if owner != crate::agent::self_node_id() {
            // Drop the lock before the proxy so we don't hold it across .await.
            drop(cfg);
            return proxy_router_post_to_node(
                state, &owner,
                &format!("router/fix/wan/{}/tick-pppoe-default-route", id),
                serde_json::json!({}),
            ).await;
        }
        match &mut conn.mode {
            wan::WanMode::Pppoe(p) => { p.use_default_route = true; }
            _ => return HttpResponse::BadRequest().body("WAN is not PPPoE — flag doesn't apply"),
        }
        let updated = conn.clone();
        if let Err(e) = cfg.save() {
            return HttpResponse::InternalServerError().body(format!("save: {}", e));
        }
        updated
    };
    let res = tokio::task::spawn_blocking(move || wan::apply(&updated)).await;
    replicate_config_to_cluster(state.clone());
    match res {
        Ok(Ok(())) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Ticked 'use_default_route' on the PPPoE WAN, saved, and redialed. \
                        pppd should now install a default route.",
        })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false, "error": e,
        })),
        Err(_) => HttpResponse::InternalServerError().body("blocking task panicked"),
    }
}

/// GET /api/router/preflight-cluster[?cluster=NAME]
/// Fan out to every WolfStack node in the requested cluster, ask each
/// one for its /api/router/preflight, and aggregate. **Cluster-scoped**:
/// without `?cluster=NAME` we return every node, but the UI always
/// passes the current cluster.
pub async fn get_cluster_preflight(
    req: HttpRequest, state: S,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let cluster_filter = query.cluster.clone();
    let nodes = state.cluster.get_all_nodes();
    let normalize = |n: Option<&str>| -> String {
        match n {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => "WolfStack".into(),
        }
    };
    let self_cluster_raw = state.cluster.get_self_cluster_name();
    let self_cluster_norm = normalize(
        if self_cluster_raw.is_empty() { None } else { Some(self_cluster_raw.as_str()) }
    );
    let include_self = match &cluster_filter {
        Some(want) => &self_cluster_norm == want,
        None => true,
    };
    let client = &*ROUTER_RPC_CLIENT;
    let mut peer_futs = Vec::new();
    let mut local_row: Option<serde_json::Value> = None;

    // Local first — direct call into preflight() would need refactoring
    // its current signature, so we just hit our own HTTP endpoint to
    // keep one code path. 4s timeout against ourselves should never
    // miss.
    let self_id = crate::agent::self_node_id();
    let self_node = nodes.iter().find(|n| n.is_self).cloned();
    if include_self && let Some(sn) = self_node {
        let host = resolve_node_address(&sn.address);
        // v23.12: self-loopback over HTTPS on the api port (cert bypass
        // on ROUTER_RPC_CLIENT covers our own self-signed cert if any).
        // The pre-v23.12 path hit `http://127.0.0.1:{port+1}` which
        // only worked when the second listener was bound; for CA-cert
        // operators it now isn't.
        let url = format!("https://127.0.0.1:{}/api/router/preflight", sn.port);
        let secret = state.cluster_secret.clone();
        let res = client.get(&url)
            .peer_auth(&secret)
            .timeout(std::time::Duration::from_secs(8))
            .send().await;
        match res {
            Ok(r) if r.status().is_success() => {
                if let Ok(v) = r.json::<serde_json::Value>().await {
                    local_row = Some(serde_json::json!({
                        "node_id": self_id,
                        "is_self": true,
                        "preflight": v,
                    }));
                }
            }
            _ => {
                // Loopback failed for some reason — emit an error row
                // rather than silently dropping the local node.
                local_row = Some(serde_json::json!({
                    "node_id": self_id,
                    "is_self": true,
                    "error": format!("loopback preflight call to {} failed", url),
                }));
            }
        }
        let _ = host; // resolve_node_address result not needed for the loopback URL
    } // close `if include_self {` and `if let Some(sn)`

    for node in &nodes {
        if node.is_self { continue; }
        // Skip peers whose cluster doesn't match the filter.
        let node_cluster = normalize(node.cluster_name.as_deref());
        if let Some(want) = &cluster_filter
            && &node_cluster != want { continue; }
        let host = resolve_node_address(&node.address);
        let urls = crate::api::build_node_urls(&host, node.port, "/api/router/preflight");
        let secret = state.cluster_secret.clone();
        let nid = node.id.clone();
        let cluster = node.cluster_name.clone().unwrap_or_default();
        peer_futs.push(async move {
            let mut last_err = String::new();
            for url in &urls {
                let res = client.get(url)
                    .peer_auth(&secret)
                    .timeout(std::time::Duration::from_secs(8))
                    .send().await;
                match res {
                    Ok(r) if r.status().is_success() => {
                        match r.json::<serde_json::Value>().await {
                            Ok(v) => return serde_json::json!({
                                "node_id": nid,
                                "cluster_name": cluster,
                                "is_self": false,
                                "preflight": v,
                            }),
                            Err(e) => { last_err = format!("decode: {}", e); continue; }
                        }
                    }
                    Ok(r) => { last_err = format!("HTTP {}", r.status()); continue; }
                    Err(e) => { last_err = format!("{}: {}", url, e); continue; }
                }
            }
            serde_json::json!({
                "node_id": nid,
                "cluster_name": cluster,
                "is_self": false,
                "error": last_err,
            })
        });
    }
    let mut rows = futures::future::join_all(peer_futs).await;
    if let Some(local) = local_row { rows.insert(0, local); }
    HttpResponse::Ok().json(serde_json::json!({ "nodes": rows }))
}

/// GET /api/router/validation
/// Return this node's most recent ValidationReport. If none stored yet
/// (process just started, watchdog hasn't ticked), runs one inline so
/// callers always get a fresh answer. Cheap — same checks the per-LAN
/// health endpoint runs.
pub async fn get_local_validation(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    let cached = state.router.last_validation.read().unwrap().clone();
    if let Some(r) = cached {
        return HttpResponse::Ok().json(r);
    }
    let state_clone = state.clone();
    let self_id = crate::agent::self_node_id();
    let report = tokio::task::spawn_blocking(move || {
        super::run_validation_and_store(&state_clone.router, &self_id);
        state_clone.router.last_validation.read().unwrap().clone()
    }).await.ok().flatten();
    match report {
        Some(r) => HttpResponse::Ok().json(r),
        None => HttpResponse::InternalServerError().body("validation produced no report"),
    }
}

/// GET /api/router/validation-cluster[?cluster=NAME]
/// Fan out to every peer in the requested cluster, ask for their
/// /api/router/validation, and aggregate. **Cluster-scoped**:
/// WolfRouter is per-cluster; without `?cluster=NAME` we return
/// every node, but the UI always passes the current cluster.
pub async fn get_cluster_validation(
    req: HttpRequest, state: S,
    query: web::Query<TopologyQuery>,
) -> HttpResponse {
    auth_or_return!(req, state);
    let cluster_filter = query.cluster.clone();
    let self_id = crate::agent::self_node_id();
    let nodes = state.cluster.get_all_nodes();
    let normalize = |n: Option<&str>| -> String {
        match n {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => "WolfStack".into(),
        }
    };
    let self_cluster_raw = state.cluster.get_self_cluster_name();
    let self_cluster_norm = normalize(
        if self_cluster_raw.is_empty() { None } else { Some(self_cluster_raw.as_str()) }
    );
    // Self is included only when its cluster matches (or no filter).
    let include_self = match &cluster_filter {
        Some(want) => &self_cluster_norm == want,
        None => true,
    };

    // Local snapshot only when we'll actually include self in the
    // result — saves a spawn_blocking when the bastion isn't in the
    // filtered cluster.
    let local_report = if include_self {
        let cached = state.router.last_validation.read().unwrap().clone();
        match cached {
            Some(r) => Some(r),
            None => {
                let st = state.clone();
                let nid = self_id.clone();
                tokio::task::spawn_blocking(move || {
                    super::run_validation_and_store(&st.router, &nid);
                    st.router.last_validation.read().unwrap().clone()
                }).await.ok().flatten()
            }
        }
    } else {
        None
    };

    // Build per-peer futures, filtering by requested cluster. The
    // existing topology endpoint applies the same normalisation: a
    // node with no `cluster_name` is grouped under "WolfStack".
    let client = &*ROUTER_RPC_CLIENT;
    let mut peer_futs = Vec::new();
    let mut local_row: Option<serde_json::Value> = None;
    for node in &nodes {
        if node.is_self {
            if include_self {
                local_row = Some(serde_json::json!({
                    "node_id": node.id,
                    "is_self": true,
                    "report": local_report,
                }));
            }
            continue;
        }
        // Skip peers whose cluster doesn't match the filter.
        let node_cluster = normalize(node.cluster_name.as_deref());
        if let Some(want) = &cluster_filter
            && &node_cluster != want { continue; }
        let host = resolve_node_address(&node.address);
        let urls = crate::api::build_node_urls(&host, node.port, "/api/router/validation");
        let secret = state.cluster_secret.clone();
        let nid = node.id.clone();
        let cluster = node.cluster_name.clone().unwrap_or_default();
        peer_futs.push(async move {
            let mut last_err = String::new();
            for url in &urls {
                let res = client.get(url)
                    .peer_auth(&secret)
                    .timeout(std::time::Duration::from_secs(4))
                    .send().await;
                match res {
                    Ok(r) if r.status().is_success() => {
                        match r.json::<serde_json::Value>().await {
                            Ok(v) => return serde_json::json!({
                                "node_id": nid,
                                "cluster_name": cluster,
                                "is_self": false,
                                "report": v,
                            }),
                            Err(e) => { last_err = format!("decode: {}", e); continue; }
                        }
                    }
                    Ok(r) => { last_err = format!("HTTP {}", r.status()); continue; }
                    Err(e) => { last_err = format!("{}: {}", url, e); continue; }
                }
            }
            serde_json::json!({
                "node_id": nid,
                "cluster_name": cluster,
                "is_self": false,
                "error": last_err,
            })
        });
    }
    let mut rows = futures::future::join_all(peer_futs).await;
    if let Some(local) = local_row { rows.insert(0, local); }
    HttpResponse::Ok().json(serde_json::json!({ "nodes": rows }))
}

// ─── Cluster-scoping helper ─────────────────────────────────────────
//
// WolfRouter is per-cluster. Every list endpoint that returns config
// items must filter by the active cluster — otherwise a bastion with
// (say) 5 clusters / 14 servers shows every cluster's LANs / rules /
// WANs / proxies / zones in every cluster's WolfRouter view, which
// is a real cross-cluster leak (Adam Cogswell 2026-04-29: "the user
// should NEVER EVER see anything from another cluster in wolfrouter
// they are on distinct networks").
//
// `cluster_node_id_set` returns the set of node IDs that belong to
// the requested cluster (None = no filter, return everything). Each
// list endpoint then keeps items whose `node_id` is in that set
// (plus optionally items with `node_id = None`, which apply globally
// and are inherently cluster-agnostic).

fn cluster_node_id_set(
    state: &S,
    query: &TopologyQuery,
) -> Option<std::collections::HashSet<String>> {
    let want = match &query.cluster {
        Some(c) if !c.is_empty() => c.clone(),
        _ => return None, // no filter requested
    };
    let normalize = |n: Option<&str>| -> String {
        match n {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => "WolfStack".into(),
        }
    };
    let self_cluster_raw = state.cluster.get_self_cluster_name();
    let self_cluster_norm = normalize(
        if self_cluster_raw.is_empty() { None } else { Some(self_cluster_raw.as_str()) }
    );
    let self_id = crate::agent::self_node_id();
    let mut set = std::collections::HashSet::new();
    for n in state.cluster.get_all_nodes() {
        let cname = if n.is_self || n.id == self_id {
            self_cluster_norm.clone()
        } else {
            normalize(n.cluster_name.as_deref())
        };
        if cname == want {
            // A node can be referenced two ways in cluster-scoped
            // config: by its locally-assigned key (`node-xxxx`, generated
            // by add_server when the operator clicked "Add Node") OR by
            // its own stable self_id (`ws-xxxx`, the value of
            // /etc/wolfstack/node_id on the peer). Subnet routes,
            // node_handles_route, and the analyzer all use self_id for
            // cluster-wide stability — but for peers added via "Add
            // Node" the local key differs from self_id, so a guard that
            // only matches on `n.id` rejects every legitimately-pinned
            // route. Insert both so the guard mirrors what the rest of
            // the codebase actually does (see `ClusterState::get_node`
            // which already falls back to a self_id scan).
            set.insert(n.id.clone());
            if let Some(sid) = n.self_id.as_ref()
                && !sid.is_empty() {
                    set.insert(sid.clone());
                }
        }
    }
    Some(set)
}

/// Block a write that would affect a node outside the requested
/// cluster. Returns `None` when the operation is allowed:
///   • no `?cluster=` filter (admin / no scope) → allow
///   • node_id is in the cluster's node set → allow
///
/// Returns `Some(HttpResponse)` to short-circuit the handler when:
///   • node_id is None and a cluster filter is active (legacy
///     "global" item — banned per strict cluster isolation)
///   • node_id is in a different cluster (cross-cluster affect)
///
/// Adam Cogswell 2026-04-29: "WOLFROUTER IS cluster limited, cluster
/// 1's wolfrouter must not display or affect anything on cluster 2".
/// The "affect" half lives here — every create/update/delete on
/// router config calls this before mutating.
/// Verify the operator's WolfRouter view (the `?cluster=NAME` query
/// param the browser sends) matches the cluster that owns `node_id`.
///
/// **Permissive when no `?cluster=` is supplied.** `cluster_node_id_set`
/// returns `None` for "no cluster context", and we `?`-propagate that
/// into a top-level `None` (allow). This is intentional: many handlers
/// share this helper, and not all browser views supply the query (e.g.
/// global Settings → System Check, scripted callers). Cluster isolation
/// is enforced ONLY for requests that carry a `?cluster=` — those are
/// the ones the operator clicked from a specific cluster's UI surface.
/// Direct API callers (curl, automation) without the parameter inherit
/// the same trust they had before this guard existed (operator-session
/// or cluster-secret auth, no per-cluster check).
///
/// If you want a handler to REQUIRE a cluster context, check
/// `query.cluster.is_some()` explicitly before calling this helper.
fn cluster_guard_node_id(state: &S, query: &TopologyQuery, node_id: Option<&str>) -> Option<HttpResponse> {
    let set = cluster_node_id_set(state, query)?;
    match node_id {
        None => Some(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "this WolfRouter view is cluster-scoped — items must be pinned to a node in this cluster (cluster-agnostic / global items aren't allowed)",
        }))),
        Some(nid) if set.contains(nid) => None,
        Some(nid) => Some(HttpResponse::Forbidden().json(serde_json::json!({
            "error": format!("node '{}' is not in this cluster — cross-cluster operations are blocked", nid),
        }))),
    }
}

/// Same as `cluster_guard_node_id` but resolves the node_id by
/// looking up an existing config item by id. Used by PUT/DELETE
/// handlers that don't carry the node_id in the URL — they need to
/// check what node OWNS the item before allowing the operation.
fn cluster_guard_existing_lan(state: &S, query: &TopologyQuery, lan_id: &str) -> Option<HttpResponse> {
    let nid = state.router.config.read().unwrap()
        .lans.iter().find(|l| l.id == lan_id).map(|l| l.node_id.clone());
    cluster_guard_node_id(state, query, nid.as_deref())
}
fn cluster_guard_existing_wan(state: &S, query: &TopologyQuery, wan_id: &str) -> Option<HttpResponse> {
    let nid = state.router.config.read().unwrap()
        .wan_connections.iter().find(|w| w.id == wan_id).map(|w| w.node_id.clone());
    cluster_guard_node_id(state, query, nid.as_deref())
}
fn cluster_guard_existing_proxy(state: &S, query: &TopologyQuery, proxy_id: &str) -> Option<HttpResponse> {
    let nid = state.router.config.read().unwrap()
        .proxies.iter().find(|p| p.id == proxy_id).map(|p| p.node_id.clone());
    cluster_guard_node_id(state, query, nid.as_deref())
}
fn cluster_guard_existing_rule(state: &S, query: &TopologyQuery, rule_id: &str) -> Option<HttpResponse> {
    // Rules have node_id: Option<String>. Look up the item; flatten
    // the outer Option (item-not-found) into the inner Option that
    // cluster_guard_node_id understands. A None node_id (legacy
    // "global" rule) gets rejected by the strict guard.
    let cfg = state.router.config.read().unwrap();
    let rule = cfg.rules.iter().find(|r| r.id == rule_id);
    let inner: Option<String> = rule.and_then(|r| r.node_id.clone());
    drop(cfg);
    cluster_guard_node_id(state, query, inner.as_deref())
}
fn cluster_guard_existing_subnet_route(state: &S, query: &TopologyQuery, route_id: &str) -> Option<HttpResponse> {
    let cfg = state.router.config.read().unwrap();
    let route = cfg.subnet_routes.iter().find(|r| r.id == route_id);
    let inner: Option<String> = route.and_then(|r| r.node_id.clone());
    drop(cfg);
    cluster_guard_node_id(state, query, inner.as_deref())
}

// ─── Internet Exposure ───────────────────────────────────────────────
//
// One page to give a workload a public URL on a wildcard zone. Exposing
// a workload creates an `expose-<subdomain>` HttpProxy pointed at the
// ingress node; because the router config is cluster-replicated + rendered
// on the target node, the URL works cluster-wide and survives moves.

/// GET /api/exposure/status — zone config + every currently exposed
/// workload with its URL.
pub async fn exposure_status(req: HttpRequest, state: S) -> HttpResponse {
    auth_or_return!(req, state);
    let cfg = crate::exposure::ExposureConfig::load();
    let entries: Vec<serde_json::Value> = {
        let rcfg = state.router.config.read().unwrap();
        rcfg.http_proxies.iter()
            .filter(|p| p.id.starts_with(crate::exposure::ID_PREFIX))
            .map(|p| {
                let src = p.exposure.clone().unwrap_or_else(|| crate::networking::router::http_proxy::ExposureSource {
                    workload_kind: "manual".into(), workload_ref: String::new(), port: 0,
                    scheme: "http".into(),
                });
                serde_json::json!({
                    "subdomain": p.id.strip_prefix(crate::exposure::ID_PREFIX).unwrap_or(&p.id),
                    "url": crate::exposure::public_url(&cfg, p),
                    "server_name": p.server_names.first().cloned().unwrap_or_default(),
                    "upstream": p.upstreams.first().map(|u| u.url.clone()).unwrap_or_default(),
                    "workload_kind": src.workload_kind,
                    "workload_ref": src.workload_ref,
                    "port": src.port,
                    "scheme": src.scheme,
                    "tls": p.tls.is_some(),
                    "enabled": p.enabled,
                })
            })
            .collect()
    };
    HttpResponse::Ok().json(serde_json::json!({
        "config": cfg,
        "ready": cfg.is_ready(),
        "self_node_id": crate::agent::self_node_id(),
        "entries": entries,
    }))
}

#[derive(Deserialize)]
pub struct ExposureZoneRequest {
    pub zone: String,
    #[serde(default)]
    pub ingress_node_id: String,
    #[serde(default)]
    pub cert_path: String,
    #[serde(default)]
    pub key_path: String,
    #[serde(default)]
    pub cert_name: String,
}

/// POST /api/exposure/zone — set the wildcard zone / ingress / cert once.
pub async fn exposure_set_zone(req: HttpRequest, state: S, body: web::Json<ExposureZoneRequest>) -> HttpResponse {
    auth_or_return!(req, state);
    let b = body.into_inner();
    let zone = b.zone.trim().trim_start_matches('*').trim_start_matches('.').to_ascii_lowercase();
    if zone.is_empty() || !zone.contains('.') {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Enter a valid zone like apps.example.com" }));
    }
    let ingress = if b.ingress_node_id.trim().is_empty() {
        crate::agent::self_node_id()
    } else {
        b.ingress_node_id.trim().to_string()
    };
    let cfg = crate::exposure::ExposureConfig {
        zone,
        ingress_node_id: ingress,
        cert_path: b.cert_path.trim().to_string(),
        key_path: b.key_path.trim().to_string(),
        cert_name: b.cert_name.trim().to_string(),
    };
    if let Err(e) = cfg.save() {
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }));
    }
    HttpResponse::Ok().json(serde_json::json!({ "config": cfg, "ready": cfg.is_ready() }))
}

#[derive(Deserialize)]
pub struct ExposureAddRequest {
    pub subdomain: String,
    pub workload_kind: String,          // docker | lxc | manual
    #[serde(default)]
    pub workload_ref: String,           // container name, or IP/host for manual
    pub port: u16,
    /// "http" (default) or "https" for backends that only serve TLS.
    #[serde(default)]
    pub scheme: String,
}

/// POST /api/exposure/expose — publish a workload on `<subdomain>.<zone>`.
pub async fn exposure_add(req: HttpRequest, state: S, body: web::Json<ExposureAddRequest>) -> HttpResponse {
    auth_or_return!(req, state);
    let b = body.into_inner();
    let cfg = crate::exposure::ExposureConfig::load();
    if !cfg.is_ready() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Set up the wildcard zone first (top of this page)."
        }));
    }
    let subdomain = match crate::exposure::normalise_subdomain(&b.subdomain) {
        Ok(s) => s,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };
    // Cluster-wide lookup: the workload may live on any node, not just
    // the one whose UI the operator happens to be using. The resolved
    // upstream is always something the INGRESS node can reach.
    let upstream = match crate::exposure::resolve_upstream_cluster(
        &b.workload_kind, &b.workload_ref, b.port, &b.scheme,
        &cfg.ingress_node_id, &state.cluster, &state.cluster_secret,
    ).await {
        Ok(u) => u,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    };
    let proxy = crate::exposure::build_proxy(&cfg, &subdomain, &b.workload_kind, &b.workload_ref, b.port, &b.scheme, &upstream);
    let proxies = {
        let mut rcfg = state.router.config.write().unwrap();
        rcfg.http_proxies.retain(|p| p.id != proxy.id);
        rcfg.http_proxies.push(proxy.clone());
        if let Err(e) = rcfg.save() {
            return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }));
        }
        rcfg.http_proxies.clone()
    };
    let warnings = crate::networking::router::http_proxy::apply_for_node(&proxies, &crate::agent::self_node_id());
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(serde_json::json!({
        "url": crate::exposure::public_url(&cfg, &proxy),
        "upstream": upstream,
        "warnings": warnings,
    }))
}

#[derive(Deserialize)]
pub struct ExposureRemoveRequest {
    pub subdomain: String,
}

/// POST /api/exposure/unexpose — take a workload's URL down.
pub async fn exposure_remove(req: HttpRequest, state: S, body: web::Json<ExposureRemoveRequest>) -> HttpResponse {
    auth_or_return!(req, state);
    let id = format!("{}{}", crate::exposure::ID_PREFIX, body.subdomain.trim().to_ascii_lowercase());
    let proxies = {
        let mut rcfg = state.router.config.write().unwrap();
        let before = rcfg.http_proxies.len();
        rcfg.http_proxies.retain(|p| p.id != id);
        if rcfg.http_proxies.len() == before {
            return HttpResponse::NotFound().json(serde_json::json!({ "error": "No such exposure." }));
        }
        if let Err(e) = rcfg.save() {
            return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }));
        }
        rcfg.http_proxies.clone()
    };
    // apply_for_node prunes orphaned confs only while the node still has a
    // live bucket; explicitly drop this one so removing the last exposure
    // still tears the route down.
    let warnings = crate::networking::router::http_proxy::apply_for_node(&proxies, &crate::agent::self_node_id());
    crate::exposure::cleanup_local_conf(&id);
    replicate_config_to_cluster(state);
    HttpResponse::Ok().json(serde_json::json!({ "removed": id, "warnings": warnings }))
}

// ─── Mount ───

pub fn configure(cfg: &mut actix_web::web::ServiceConfig) {
    cfg
        .route("/api/exposure/status",    web::get().to(exposure_status))
        .route("/api/exposure/zone",      web::post().to(exposure_set_zone))
        .route("/api/exposure/expose",    web::post().to(exposure_add))
        .route("/api/exposure/unexpose",  web::post().to(exposure_remove))
        .route("/api/router/topology", web::get().to(get_topology))
        .route("/api/router/topology-local", web::get().to(get_topology_local))
        .route("/api/router/preflight", web::get().to(preflight))
        .route("/api/router/config-receive", web::post().to(config_receive))
        .route("/api/router/zones", web::get().to(get_zones))
        .route("/api/router/zones", web::post().to(assign_zone))
        .route("/api/router/segments", web::get().to(list_segments))
        .route("/api/router/segments", web::post().to(create_segment))
        .route("/api/router/segments/{id}", web::put().to(update_segment))
        .route("/api/router/segments/{id}", web::delete().to(delete_segment))
        .route("/api/router/segments/{id}/leases", web::get().to(get_leases))
        .route("/api/router/segments/{id}/query-log", web::get().to(get_query_log))
        .route("/api/router/segments/{id}/query-log", web::post().to(set_query_log))
        .route("/api/router/segments/{id}/health", web::get().to(get_lan_health))
        .route("/api/router/segments/{id}/restart-dnsmasq", web::post().to(restart_lan_dnsmasq))
        .route("/api/router/segments/{id}/set-interface", web::post().to(set_lan_interface))
        .route("/api/router/health", web::get().to(list_lan_health))
        .route("/api/router/validation", web::get().to(get_local_validation))
        .route("/api/router/validation-cluster", web::get().to(get_cluster_validation))
        .route("/api/router/preflight-cluster", web::get().to(get_cluster_preflight))
        .route("/api/router/fix/enable-ip-forward", web::post().to(fix_enable_ip_forward))
        .route("/api/router/fix/purge-self-loop-routes", web::post().to(fix_purge_self_loop_routes))
        .route("/api/router/fix/dhclient", web::post().to(fix_dhclient_iface))
        .route("/api/router/fix/wan/{id}/reapply", web::post().to(fix_reapply_wan))
        .route("/api/router/fix/wan/{id}/tick-pppoe-default-route", web::post().to(fix_tick_pppoe_default_route))
        .route("/api/router/rules", web::get().to(list_rules))
        .route("/api/router/rules", web::post().to(create_rule))
        .route("/api/router/rules/{id}", web::put().to(update_rule))
        .route("/api/router/rules/{id}", web::delete().to(delete_rule))
        .route("/api/router/rules/reorder", web::post().to(reorder_rules))
        .route("/api/router/rules/test", web::post().to(test_rules))
        .route("/api/router/rules/apply", web::post().to(apply_rules_now))
        .route("/api/router/rules/confirm", web::post().to(confirm_rules))
        .route("/api/router/connections", web::get().to(list_connections))
        .route("/api/router/logs", web::get().to(list_firewall_logs))
        .route("/api/router/managed-overview", web::get().to(get_managed_overview))
        .route("/api/router/host-snapshot", web::get().to(get_host_snapshot))
        .route("/api/router/capture", web::post().to(packet_capture))
        .route("/api/router/install-tool", web::post().to(install_tool))
        .route("/api/router/test-dns",     web::post().to(test_dns))
        .route("/api/router/tools/status",    web::get().to(tool_status))
        .route("/api/router/tools/install",   web::post().to(tool_install))
        .route("/api/router/tools/ping",      web::post().to(tool_ping))
        .route("/api/router/tools/traceroute",web::post().to(tool_traceroute))
        .route("/api/router/tools/nslookup",  web::post().to(tool_nslookup))
        .route("/api/router/tools/whois",     web::post().to(tool_whois))
        .route("/api/router/export", web::get().to(export_config))
        .route("/api/router/import", web::post().to(import_config))
        .route("/api/router/wan",          web::get().to(list_wan))
        .route("/api/router/wan",          web::post().to(create_wan))
        .route("/api/router/wan/{id}",     web::put().to(update_wan))
        .route("/api/router/wan/{id}",     web::delete().to(delete_wan))
        // HTTP (L7) reverse-proxy CRUD + runtime detection + install.
        // Multi-target shape: each entry carries Vec<ProxyTarget> so
        // operators can replicate a proxy across cluster nodes for HA.
        .route("/api/router/http-proxies",                  web::get().to(list_http_proxies))
        .route("/api/router/http-proxies",                  web::post().to(create_http_proxy))
        .route("/api/router/http-proxies/{id}/certificate", web::post().to(issue_proxy_certificate))
        .route("/api/router/http-proxies/runtime",          web::get().to(http_proxy_runtime))
        .route("/api/router/http-proxies/install/{which}",  web::post().to(http_proxy_install_runtime))
        .route("/api/router/http-proxies/{id}",             web::put().to(update_http_proxy))
        .route("/api/router/http-proxies/{id}",             web::delete().to(delete_http_proxy))
        .route("/api/router/wan-status",   web::get().to(wan_status))
        .route("/api/router/interface-up", web::post().to(interface_up))
        .route("/api/router/host-dns",              web::get().to(get_host_dns))
        .route("/api/router/host-dns/release",      web::post().to(release_host_dns))
        .route("/api/router/host-dns/restore",      web::post().to(restore_host_dns))
        .route("/api/router/host-dns/lan-dns-port", web::post().to(set_lan_dns_port))
        .route("/api/router/proxies",          web::get().to(list_proxies))
        .route("/api/router/proxies",          web::post().to(create_proxy))
        .route("/api/router/proxies/{id}",     web::put().to(update_proxy))
        .route("/api/router/proxies/{id}",     web::delete().to(delete_proxy))
        .route("/api/router/proxy-backends",   web::get().to(list_proxy_backends))
        .route("/api/router/subnet-routes",                 web::get().to(list_subnet_routes))
        .route("/api/router/subnet-routes",                 web::post().to(create_subnet_route))
        .route("/api/router/subnet-routes/diagnostics",     web::get().to(diagnostics_subnet_routes))
        .route("/api/router/subnet-routes/ipv6",            web::get().to(get_ipv6_subnet_setting))
        .route("/api/router/subnet-routes/ipv6",            web::post().to(set_ipv6_subnet_setting))
        .route("/api/router/subnet-routes/orphan/remove",   web::post().to(remove_orphan_subnet_route))
        .route("/api/router/subnet-routes/{id}/reapply",    web::post().to(reapply_subnet_route))
        .route("/api/router/subnet-routes/{id}",            web::put().to(update_subnet_route))
        .route("/api/router/subnet-routes/{id}",            web::delete().to(delete_subnet_route))
        .route("/api/router/wolfnet/routes/resync",         web::post().to(wolfnet_routes_resync))
        // Recovery — surfaces parse-error state, lists rollback
        // snapshots, and lets the user restore one or commit an
        // artefact-reconstructed config when no snapshot is left.
        .route("/api/router/recovery",                      web::get().to(get_recovery_state))
        .route("/api/router/recovery/restore",              web::post().to(restore_recovery))
        .route("/api/router/recovery/acknowledge-auto",     web::post().to(acknowledge_auto_recovery))
        .route("/api/router/recovery/reconstruct",          web::get().to(preview_artifact_reconstruction))
        .route("/api/router/recovery/reconstruct",          web::post().to(commit_artifact_reconstruction));
}

// ─── Recovery API ───
//
// Three endpoints, dead simple:
//   * GET  /api/router/recovery        — full state for the UI banner.
//   * POST /api/router/recovery/restore { path } — atomic rollback.
//   * GET  /api/router/recovery/reconstruct — preview reconstructed
//                                             config from artefacts.
//   * POST /api/router/recovery/reconstruct — commit it.
//
// Auth: same session-cookie auth as every other /api/router endpoint.
// Authorization: any logged-in user — these are admin operations on a
// box the user already has shell-equivalent access to via the
// WolfStack UI, so we don't gate by role beyond that.

#[derive(serde::Serialize)]
struct RecoveryState {
    /// True when the most recent startup load failed and saves are
    /// currently blocked. Frontend uses this to decide whether to
    /// render the rollback banner at the top of the WolfRouter page.
    load_failed: bool,
    /// Detail of the load failure (serde error + quarantine path)
    /// when `load_failed=true`. Null otherwise.
    load_error: Option<super::LoadError>,
    /// Detail of an auto-recovery that happened at startup — set
    /// when `config.json` failed to parse but a `.bak.<ts>` snapshot
    /// did and was promoted to the live file. The UI surfaces a
    /// soft banner so the operator can audit and dismiss. Null
    /// when there's nothing to audit. Added v24.7.9.
    auto_recovery: Option<super::AutoRecoveryNotice>,
    /// All available recovery targets (`.bak.<ts>` rolling backups
    /// and `.broken-<ts>` quarantined parse failures), newest first.
    snapshots: Vec<super::RecoverySnapshot>,
    /// True when artefact reconstruction would yield at least one
    /// LAN or WAN — used by the UI to decide whether to show the
    /// "Reconstruct from system artefacts" button as active.
    artifact_reconstruction_available: bool,
}

async fn get_recovery_state(
    req: actix_web::HttpRequest,
    state: actix_web::web::Data<crate::api::AppState>,
) -> actix_web::HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }
    let load_failed = super::save_blocked_by_load_failure();
    let load_error = state.router.load_error.read().ok()
        .and_then(|g| g.clone());
    let auto_recovery = state.router.auto_recovery.read().ok()
        .and_then(|g| g.clone());
    // Snapshot listing is fast (a single readdir + per-entry parse
    // probe of small JSON files), safe to run inline. The artefact
    // reconstruction probe walks /etc/ppp/peers + dnsmasq.d and
    // parses each — only worth doing when the banner will actually
    // render, i.e. when load_failed is true. The frontend uses
    // `load_failed` itself as the banner gate, so when that's
    // false we just return `false` for the button state without
    // spending the I/O.
    let snapshots = super::list_recovery_snapshots();
    let recon_available = if load_failed {
        let r = tokio::task::spawn_blocking(super::reconstruct_from_artifacts)
            .await.ok();
        r.map(|r| !r.recovered_items.is_empty()).unwrap_or(false)
    } else {
        false
    };
    actix_web::HttpResponse::Ok().json(RecoveryState {
        load_failed,
        load_error,
        auto_recovery,
        snapshots,
        artifact_reconstruction_available: recon_available,
    })
}

/// POST /api/router/recovery/acknowledge-auto — clear the soft
/// auto-recovery banner once the operator has audited the restored
/// config. Idempotent; returns `{ ok: true }` whether or not a
/// notice was set. Added v24.7.9 alongside startup self-heal.
async fn acknowledge_auto_recovery(
    req: actix_web::HttpRequest,
    state: actix_web::web::Data<crate::api::AppState>,
) -> actix_web::HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }
    if let Ok(mut g) = state.router.auto_recovery.write() {
        *g = None;
    }
    actix_web::HttpResponse::Ok().json(serde_json::json!({ "ok": true }))
}

#[derive(serde::Deserialize)]
struct RestoreReq {
    /// Absolute path to the snapshot to restore. Validated by
    /// `restore_recovery_snapshot` to live inside ROUTER_DIR and
    /// match a known prefix — anything else is rejected.
    path: String,
}

#[derive(serde::Serialize)]
struct RestoreResp {
    ok: bool,
    /// Human-readable message — "restored, restart required" or the
    /// underlying error.
    message: String,
}

async fn restore_recovery(
    req: actix_web::HttpRequest,
    state: actix_web::web::Data<crate::api::AppState>,
    body: actix_web::web::Json<RestoreReq>,
) -> actix_web::HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }
    let path = body.path.clone();
    // restore_recovery_snapshot does the disk work; spawn_blocking
    // because std::fs blocks the executor.
    let result = tokio::task::spawn_blocking(move || {
        super::restore_recovery_snapshot(&path)
    }).await.unwrap_or_else(|_| Err("restore task panicked".into()));

    match result {
        Ok(()) => {
            // Reload in-memory config from the freshly-restored
            // file so the running process reflects the rollback
            // without requiring a service restart. We re-run
            // load_with_status so all the latches and load_error
            // state get updated coherently.
            let (cfg, outcome) = super::RouterConfig::load_with_status();
            *state.router.config.write().unwrap() = cfg;
            match outcome {
                super::LoadOutcome::Loaded | super::LoadOutcome::Fresh => {
                    state.router.mark_clean();
                }
                super::LoadOutcome::AutoRecovered {
                    from_backup, from_timestamp, broken_quarantine, parse_error,
                } => {
                    // Restore wrote a parseable file to disk, but then the
                    // very next load_with_status above ALSO hit an auto-
                    // recover path? That means restore_recovery_snapshot's
                    // direct write got clobbered (it doesn't use the unique
                    // tmp + atomic rename pattern). Treat as clean — the
                    // in-memory cfg is now whatever the latest auto-recovery
                    // pulled out of a backup — and surface the notice so
                    // the operator can audit.
                    if let Ok(mut g) = state.router.auto_recovery.write() {
                        *g = Some(super::AutoRecoveryNotice {
                            from_backup,
                            from_timestamp,
                            broken_quarantine,
                            parse_error,
                            observed_at: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs()).unwrap_or(0),
                        });
                    }
                    state.router.mark_clean();
                }
                super::LoadOutcome::RecoveredFromTornWrite {
                    discarded_trailing_bytes, broken_quarantine, parse_error,
                } => {
                    // Same shape as AutoRecovered for the UI banner —
                    // the in-place torn-write fix.
                    if let Ok(mut g) = state.router.auto_recovery.write() {
                        *g = Some(super::AutoRecoveryNotice {
                            from_backup: format!(
                                "(in-place torn-write recovery — stripped {} \
                                 trailing byte(s))",
                                discarded_trailing_bytes,
                            ),
                            from_timestamp: 0,
                            broken_quarantine,
                            parse_error,
                            observed_at: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs()).unwrap_or(0),
                        });
                    }
                    state.router.mark_clean();
                }
                super::LoadOutcome::ParseError { error, .. } => {
                    // The user picked a snapshot that doesn't parse
                    // either — keep the latch up and surface the
                    // error so they pick a different one.
                    if let Ok(mut g) = state.router.load_error.write() {
                        *g = Some(super::LoadError {
                            quarantine_path: String::new(),
                            error: error.clone(),
                            observed_at: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs()).unwrap_or(0),
                        });
                    }
                    return actix_web::HttpResponse::Ok().json(RestoreResp {
                        ok: false,
                        message: format!(
                            "Snapshot restored to disk but it does not parse \
                             with the current binary ({}). Pick another \
                             snapshot or use 'Reconstruct from artefacts'.",
                            error
                        ),
                    });
                }
            }
            actix_web::HttpResponse::Ok().json(RestoreResp {
                ok: true,
                message: "Config restored. The running ruleset still reflects \
                          the previous (lost) state — review the LANs/WANs in \
                          WolfRouter, then click Apply to push the restored \
                          config into the kernel.".into(),
            })
        }
        Err(e) => actix_web::HttpResponse::Ok().json(RestoreResp {
            ok: false,
            message: e,
        }),
    }
}

async fn preview_artifact_reconstruction(
    req: actix_web::HttpRequest,
    state: actix_web::web::Data<crate::api::AppState>,
) -> actix_web::HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }
    let r = tokio::task::spawn_blocking(super::reconstruct_from_artifacts)
        .await.unwrap_or_else(|_| super::ArtifactReconstruction {
            config: super::RouterConfig::default(),
            recovered_items: Vec::new(),
            notes: vec!["reconstruction task panicked".into()],
        });
    actix_web::HttpResponse::Ok().json(r)
}

async fn commit_artifact_reconstruction(
    req: actix_web::HttpRequest,
    state: actix_web::web::Data<crate::api::AppState>,
) -> actix_web::HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }
    // Reconstruct, write to disk DIRECTLY (the save() latch is
    // currently set), then clear the latch so future edits persist.
    let result = tokio::task::spawn_blocking(|| -> Result<super::ArtifactReconstruction, String> {
        let r = super::reconstruct_from_artifacts();
        if r.recovered_items.is_empty() {
            return Err(
                "Artefact reconstruction found nothing to recover. The \
                 dnsmasq.d snippets and PPPoE peer files are also gone — \
                 there's no automated path back. The WolfRouter config \
                 must be rebuilt by hand.".into()
            );
        }
        let json = serde_json::to_string_pretty(&r.config)
            .map_err(|e| format!("serialize failed: {}", e))?;
        std::fs::create_dir_all(super::ROUTER_DIR)
            .map_err(|e| format!("create_dir_all failed: {}", e))?;
        let live = super::RouterConfig::path();
        // Pre-rotate any existing live file so the user can roll
        // back the reconstruction itself if it's wrong.
        if std::path::Path::new(&live).exists() {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0);
            let bak = format!("{}.bak.{}", live, ts);
            let _ = std::fs::copy(&live, &bak);
        }
        // Unique tmp suffix — see save() in router/mod.rs. A fixed
        // `.tmp` path races against concurrent save() callers and
        // produces torn writes (trailing characters from the longer
        // write tailing the shorter one).
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // ThreadId added as defense-in-depth alongside pid+nanos —
        // see RouterConfig::save() for the rationale.
        let tmp = format!(
            "{}.tmp.{}.{}.{:?}",
            live,
            std::process::id(),
            nanos,
            std::thread::current().id(),
        );
        if let Err(e) = std::fs::write(&tmp, json) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("write failed: {}", e));
        }
        if let Err(e) = std::fs::rename(&tmp, &live) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("atomic rename failed: {}", e));
        }
        Ok(r)
    }).await.unwrap_or_else(|_| Err("reconstruction task panicked".into()));

    match result {
        Ok(r) => {
            // Reload + clear the latch.
            let (cfg, _outcome) = super::RouterConfig::load_with_status();
            *state.router.config.write().unwrap() = cfg;
            state.router.mark_clean();
            actix_web::HttpResponse::Ok().json(r)
        }
        Err(e) => actix_web::HttpResponse::BadRequest().json(serde_json::json!({
            "ok": false,
            "error": e,
        })),
    }
}

/// GET /api/router/host-dns — detect what's holding port 53 on this
/// node. Read-only. Returns the HostDnsStatus struct from host_dns::detect.
///
/// Snapshots the LAN list before handing to a blocking task so the
/// detect function can report per-LAN WolfRouter DNS mode/port without
/// racing against concurrent config writes.
async fn get_host_dns(
    req: actix_web::HttpRequest,
    state: actix_web::web::Data<crate::api::AppState>,
) -> actix_web::HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }
    let lans = state.router.config.read().unwrap().lans.clone();
    let self_id = crate::agent::self_node_id();
    let status = tokio::task::spawn_blocking(move || super::host_dns::detect(&lans, &self_id))
        .await.unwrap_or_else(|_| super::host_dns::HostDnsStatus {
            resolver: "error".into(), port_53_owner: None,
            port_53_bindings: Vec::new(),
            stub_listener: false,
            release_applied: false, wolfrouter_owns_53: false,
            wolfrouter_lans: Vec::new(),
            resolv_conf_servers: Vec::new(),
            distro: "unknown".into(), network_manager_active: false,
            resolv_conf_immutable: false, tools_ok: false,
            message: "Detection task panicked".into(),
        });
    actix_web::HttpResponse::Ok().json(status)
}

#[derive(serde::Deserialize)]
struct HostDnsReleaseRequest {
    /// Optional host DNS upstream to point /etc/resolv.conf at after
    /// releasing port 53. Defaults to 1.1.1.1 when omitted so host
    /// resolution keeps working without the stub.
    #[serde(default)]
    upstream: Option<String>,
}

/// POST /api/router/host-dns/release — disable systemd-resolved's stub
/// listener so a containerised DNS server can claim port 53. Writes a
/// drop-in at /etc/systemd/resolved.conf.d/99-wolfstack-release-53.conf
/// and rewrites /etc/resolv.conf so host DNS still works. Undoable via
/// /restore.
async fn release_host_dns(
    req: actix_web::HttpRequest,
    state: actix_web::web::Data<crate::api::AppState>,
    body: actix_web::web::Json<HostDnsReleaseRequest>,
) -> actix_web::HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }
    let upstream = body.upstream.clone();
    let res = tokio::task::spawn_blocking(move || {
        super::host_dns::release_port_53(upstream.as_deref())
    }).await.unwrap_or_else(|e| Err(format!("release task panicked: {}", e)));
    match res {
        Ok(msg) => {
            // Schedule an automatic rollback after 120s unless the
            // operator hits Confirm in the UI. If the release broke
            // host DNS (upstream unreachable, NM clobbered resolv.conf,
            // whatever), the operator's browser will fail to reach the
            // node, no Confirm call arrives, and danger::tick fires
            // host_dns::restore() to put the stub back. This is the
            // PapaSchlumpf-incident preventer — they released, DNS
            // broke, they had no UI to hit Restore from.
            let upstream_for_desc = body.upstream.clone().unwrap_or_else(|| "1.1.1.1".to_string());
            let danger_id = crate::danger::schedule(
                "host_dns_release",
                &format!("systemd-resolved stub released; host DNS pointed at {}", upstream_for_desc),
                120,
                Box::new(|| {
                    super::host_dns::restore()
                }),
            );
            actix_web::HttpResponse::Ok().json(serde_json::json!({
                "ok": true,
                "message": msg,
                "danger_id": danger_id,
                "ttl_secs": 120,
                "confirm_required": true,
            }))
        }
        Err(e) => actix_web::HttpResponse::BadRequest().json(serde_json::json!({ "ok": false, "error": e })),
    }
}

/// POST /api/router/host-dns/restore — undo the release: delete the
/// drop-in, restore the backup of /etc/resolv.conf, restart the
/// resolver so the stub listener comes back.
async fn restore_host_dns(
    req: actix_web::HttpRequest,
    state: actix_web::web::Data<crate::api::AppState>,
) -> actix_web::HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }
    let res = tokio::task::spawn_blocking(super::host_dns::restore)
        .await.unwrap_or_else(|e| Err(format!("restore task panicked: {}", e)));
    match res {
        Ok(msg) => actix_web::HttpResponse::Ok().json(serde_json::json!({ "ok": true, "message": msg })),
        Err(e) => actix_web::HttpResponse::BadRequest().json(serde_json::json!({ "ok": false, "error": e })),
    }
}

#[derive(serde::Deserialize)]
struct SetLanDnsPortRequest {
    lan_id: String,
    /// New dnsmasq port for this LAN. 5353 is the common "move out of
    /// AdGuard's way" value; anything 1..=65535 is accepted. Hitting
    /// 53 here is effectively a no-op unless the LAN was previously
    /// moved.
    new_port: u16,
    /// DNS server to advertise via DHCP option 6 once dnsmasq is off
    /// :53. Required when new_port != 53 because DHCP can't signal a
    /// non-standard port — clients would try router_ip:53 and get
    /// nothing. Typically the AdGuard/Pi-hole container IP.
    #[serde(default)]
    external_server: Option<String>,
}

/// POST /api/router/host-dns/lan-dns-port — move one WolfRouter LAN's
/// dnsmasq DNS listener off :53 (or back onto it) so a containerised
/// resolver can claim :53 on that LAN's interface. Restarts that
/// LAN's dnsmasq to apply.
///
/// This is the per-LAN counterpart to the systemd-resolved stub
/// release: both may be needed to fully vacate :53 on a host that
/// runs both WolfRouter's dnsmasq and systemd-resolved's stub.
async fn set_lan_dns_port(
    req: actix_web::HttpRequest,
    state: actix_web::web::Data<crate::api::AppState>,
    body: actix_web::web::Json<SetLanDnsPortRequest>,
) -> actix_web::HttpResponse {
    if let Err(resp) = crate::api::require_auth(&req, &state) { return resp; }
    if body.new_port == 0 {
        return actix_web::HttpResponse::BadRequest().json(serde_json::json!({
            "ok": false,
            "error": "new_port must be between 1 and 65535 (use DNS mode 'External' to disable dnsmasq DNS entirely)",
        }));
    }
    let external = body.external_server.as_deref().map(str::trim).unwrap_or("").to_string();
    if body.new_port != 53 && external.is_empty() {
        return actix_web::HttpResponse::BadRequest().json(serde_json::json!({
            "ok": false,
            "error": "external_server is required when new_port isn't 53 — DHCP option 6 can only advertise a resolver on the standard port :53, so clients need to be pointed at a separate IP they can reach there (typically the AdGuard/Pi-hole container IP). NOTE: this IP doesn't need to be running yet — it's just a future reference. Set it now, dnsmasq will move off :53 freeing it, then start AdGuard on that IP.",
        }));
    }
    // Build the candidate LAN outside the write lock first, then
    // validate it, then commit. Mutating in place before validating
    // would leave RouterConfig in an invalid state on a validation
    // failure (config saved + dnsmasq restarted are cheap to skip,
    // but in-memory drift isn't).
    let candidate = {
        let cfg = state.router.config.read().unwrap();
        
        match cfg.lans.iter().find(|l| l.id == body.lan_id) {
            Some(s) => s.clone(),
            None => return actix_web::HttpResponse::NotFound().json(serde_json::json!({
                "ok": false, "error": "LAN not found",
            })),
        }
    };
    let mut candidate = candidate;
    candidate.dns.listen_port = body.new_port;
    if !external.is_empty() {
        candidate.dns.external_server = Some(external.clone());
    } else if body.new_port == 53 {
        // Reverting to :53 without an explicit external_server ==
        // "back to defaults" — DHCP option 6 should advertise the
        // router IP again, not the old container IP from when the
        // LAN was temporarily moved to a non-standard port.
        candidate.dns.external_server = None;
    }
    if let Err(e) = validate_segment(&candidate) {
        return actix_web::HttpResponse::BadRequest().json(serde_json::json!({
            "ok": false, "error": e,
        }));
    }
    // Validation passed — commit the change under the write lock. Lock
    // is dropped before the dhcp::start restart for the same reason as
    // set_query_log above (don't stall readers on spawn).
    let updated_lan = {
        let mut cfg = state.router.config.write().unwrap();
        match cfg.lans.iter_mut().find(|l| l.id == body.lan_id) {
            Some(seg) => { *seg = candidate.clone(); }
            None => return actix_web::HttpResponse::NotFound().json(serde_json::json!({
                "ok": false, "error": "LAN not found (it was deleted after we validated — retry)",
            })),
        };
        if let Err(e) = cfg.save() {
            return actix_web::HttpResponse::InternalServerError().json(serde_json::json!({
                "ok": false, "error": format!("save: {}", e),
            }));
        }
        candidate
    };
    if updated_lan.node_id == crate::agent::self_node_id()
        && let Err(e) = dhcp::start(&updated_lan) {
            return actix_web::HttpResponse::InternalServerError().json(serde_json::json!({
                "ok": false, "error": format!("restart dnsmasq: {}", e),
            }));
        }
    replicate_config_to_cluster(state.clone());
    let msg = if body.new_port == 53 {
        format!("LAN '{}' dnsmasq DNS is back on port 53. Clients will resolve via WolfRouter directly again.", updated_lan.name)
    } else {
        format!(
            "LAN '{}' dnsmasq moved to port {}. Port 53 on {} is now free for a containerised resolver. DHCP option 6 points clients at {}.",
            updated_lan.name, body.new_port, updated_lan.interface, external,
        )
    };
    actix_web::HttpResponse::Ok().json(serde_json::json!({
        "ok": true, "message": msg,
    }))
}

#[cfg(test)]
mod ipv4_validation_tests {
    use super::*;

    #[test]
    fn rejects_missing_dot_typo() {
        // The exact case PapaSchlumpf hit: "10.10.10.100" → "10.1010.100".
        let r = validate_ipv4_in_cidr("dhcp.pool_start", "10.1010.100", "10.10.10.0/24");
        assert!(r.is_err());
        let msg = r.unwrap_err();
        assert!(msg.contains("not a valid IPv4"), "unexpected: {}", msg);
    }

    #[test]
    fn rejects_quad_outside_subnet() {
        let r = validate_ipv4_in_cidr("router_ip", "192.168.1.1", "10.0.0.0/24");
        assert!(r.is_err());
        let msg = r.unwrap_err();
        assert!(msg.contains("is not inside the LAN's subnet"), "unexpected: {}", msg);
    }

    #[test]
    fn accepts_valid_in_subnet() {
        assert!(validate_ipv4_in_cidr("router_ip", "192.168.1.1", "192.168.1.0/24").is_ok());
        assert!(validate_ipv4_in_cidr("dhcp.pool_start", "10.10.10.100", "10.10.10.0/24").is_ok());
    }

    #[test]
    fn rejects_malformed_cidr() {
        // No slash.
        assert!(validate_ipv4_in_cidr("router_ip", "192.168.1.1", "192.168.1.0").is_err());
        // Bad prefix.
        assert!(validate_ipv4_in_cidr("router_ip", "192.168.1.1", "192.168.1.0/abc").is_err());
        assert!(validate_ipv4_in_cidr("router_ip", "192.168.1.1", "192.168.1.0/40").is_err());
        // Bad network part.
        assert!(validate_ipv4_in_cidr("router_ip", "192.168.1.1", "not.an.ip/24").is_err());
    }

    #[test]
    fn slash_zero_accepts_anything() {
        assert!(validate_ipv4_in_cidr("any", "8.8.8.8", "0.0.0.0/0").is_ok());
    }

    #[test]
    fn empty_value_rejected() {
        assert!(validate_ipv4_in_cidr("router_ip", "", "192.168.1.0/24").is_err());
        assert!(validate_ipv4_in_cidr("router_ip", "   ", "192.168.1.0/24").is_err());
    }

    #[test]
    fn boundary_addresses_in_24() {
        // Network address (.0) and broadcast (.255) DO live inside the
        // /24 mathematically — we accept them at format-validation time.
        // Whether they make sense as router_ip / pool endpoint is a
        // higher-level concern dnsmasq itself catches.
        assert!(validate_ipv4_in_cidr("x", "192.168.1.0", "192.168.1.0/24").is_ok());
        assert!(validate_ipv4_in_cidr("x", "192.168.1.255", "192.168.1.0/24").is_ok());
    }
}
