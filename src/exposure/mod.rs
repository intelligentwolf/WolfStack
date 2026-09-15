// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Internet Exposure.
//!
//! One place to give a running workload (Docker/LXC container, or any
//! host/VM addressed by IP) its own public HTTPS URL on a wildcard
//! domain — without editing DNS per workload.
//!
//! How it fits together:
//!   * The operator sets a **wildcard zone** once (e.g. `apps.example.com`,
//!     with `*.apps.example.com` pointed at the ingress node and a wildcard
//!     TLS cert). That lives in [`ExposureConfig`].
//!   * Exposing a workload creates an ordinary WolfRouter [`HttpProxy`]
//!     entry (`expose-<subdomain>`) whose `server_name` is
//!     `<subdomain>.<zone>` and whose upstream is the workload's current
//!     `IP:port`. Because WolfRouter config is already cluster-replicated
//!     and rendered on the target node, the URL works cluster-wide and
//!     survives the workload restarting/moving — the reconcile just
//!     refreshes the upstream IP.
//!
//! Nothing is exposed until the operator explicitly turns it on for a
//! specific workload — everything else stays private.

use serde::{Deserialize, Serialize};

use crate::networking::router::http_proxy::{
    ExposureSource, HttpProxy, TlsConfig, Upstream,
};
use crate::edge::{EdgeStrategy, ProxyTarget, TargetRuntime};
use crate::node_identity::PeerAuth;

/// Every exposure proxy id starts with this so operator-created proxies
/// (which never carry it) are never touched by the exposure reconcile.
pub const ID_PREFIX: &str = "expose-";

fn config_path() -> String {
    format!("{}/internet-exposure.json", crate::paths::get().config_dir)
}

/// Cluster-level exposure setup. Set once; drives the FQDN and TLS of
/// every exposed workload.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExposureConfig {
    /// Wildcard base zone, e.g. `apps.example.com`. Empty until set up.
    #[serde(default)]
    pub zone: String,
    /// Node that fronts the traffic (`*.zone` points here). The generated
    /// proxies render on this node.
    #[serde(default)]
    pub ingress_node_id: String,
    /// Wildcard TLS cert covering `*.zone`. Empty = serve plain HTTP only
    /// (the UI warns). Obtained via the Certificates page (DNS-01).
    #[serde(default)]
    pub cert_path: String,
    #[serde(default)]
    pub key_path: String,
    /// Name under /etc/letsencrypt/live for the cert, if it came from the
    /// certbot flow — lets the cert-distribution reconciler ship it to the
    /// ingress node. Empty for hand-pasted paths.
    #[serde(default)]
    pub cert_name: String,
}

impl ExposureConfig {
    pub fn load() -> Self {
        std::fs::read_to_string(config_path())
            .ok()
            .and_then(|d| serde_json::from_str(&d).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::paths::write_secure(&config_path(), json).map_err(|e| e.to_string())
    }

    pub fn is_ready(&self) -> bool {
        !self.zone.trim().is_empty() && !self.ingress_node_id.trim().is_empty()
    }
}

/// Validate + normalise a subdomain label (the part before the zone).
/// Lowercase DNS label rules — this becomes both an nginx `server_name`
/// segment and part of a config filename.
pub fn normalise_subdomain(s: &str) -> Result<String, String> {
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Err("Subdomain can't be empty.".into());
    }
    if s.len() > 63 {
        return Err("Subdomain is too long (max 63 characters).".into());
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("Subdomain may only contain letters, numbers and hyphens.".into());
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err("Subdomain can't start or end with a hyphen.".into());
    }
    Ok(s)
}

/// Validate the backend scheme ("http"/"https"); anything else falls
/// back to http so a hand-edited config can't render a garbage URL.
pub fn normalise_scheme(s: &str) -> &'static str {
    if s.trim().eq_ignore_ascii_case("https") { "https" } else { "http" }
}

/// Parse docker's PORTS column entries (`0.0.0.0:8080->80/tcp`,
/// `[::]:8080->80/tcp`; entries without `->` are container-only) and
/// return the HOST port that publishes `container_port`, if any.
pub fn published_host_port(ports: &[String], container_port: u16) -> Option<u16> {
    for entry in ports {
        let Some((host_side, ct_side)) = entry.split_once("->") else { continue };
        let ct_port = ct_side.split('/').next().unwrap_or("");
        if ct_port.parse::<u16>().ok() != Some(container_port) {
            continue;
        }
        // Host side ends in ":PORT"; the address part may itself contain
        // ':' (IPv6), so split on the LAST colon.
        if let Some(idx) = host_side.rfind(':')
            && let Ok(hp) = host_side[idx + 1..].parse::<u16>()
        {
            return Some(hp);
        }
    }
    None
}

/// Turn a locally-listed container into an upstream URL **the ingress
/// node can reach**. Container bridge IPs (docker0/lxcbr0) only route
/// from the host that owns them, so they're used only when the hosting
/// node IS the ingress; otherwise the workload must publish the port on
/// its host, and the upstream becomes `hosting node address:host port`.
fn reachable_upstream(
    c: &crate::containers::ContainerInfo,
    port: u16,
    scheme: &str,
    hosting_is_ingress: bool,
    hosting_addr: &str,
    hosting_label: &str,
    ingress_label: &str,
) -> Result<String, String> {
    if hosting_is_ingress {
        let ip = c.ip_address.trim();
        if ip.is_empty() {
            return Err(format!("Container '{}' has no IP address yet (is it started?).", c.name));
        }
        return Ok(format!("{scheme}://{}:{port}", crate::netaddr::bracket_host(ip)));
    }
    if let Some(hp) = published_host_port(&c.ports, port) {
        return Ok(format!("{scheme}://{}:{hp}", crate::netaddr::bracket_host(hosting_addr)));
    }
    Err(format!(
        "'{}' runs on {hosting_label}, but the ingress node is {ingress_label} — the container's bridge IP isn't reachable from there. Publish port {port} on the host (e.g. docker -p {port}:{port}) so the ingress can reach it, or use a manual IP.",
        c.name
    ))
}

/// The self node's (is-ingress?, address, hostname) — the facts
/// `reachable_upstream` needs when the workload lives on THIS node.
fn self_facts(cluster: &crate::agent::ClusterState, ingress_node_id: &str) -> (bool, String, String) {
    let nodes = cluster.get_all_nodes();
    let me = nodes.iter().find(|n| n.is_self);
    let is_ingress = me
        .map(|n| crate::wolfrun::node_matches_id(n, ingress_node_id))
        .unwrap_or(false);
    let addr = me.map(|n| n.address.clone()).unwrap_or_default();
    let host = me.map(|n| n.hostname.clone()).unwrap_or_else(|| "this node".into());
    (is_ingress, addr, host)
}

fn ingress_label(cluster: &crate::agent::ClusterState, ingress_node_id: &str) -> String {
    cluster
        .get_node(ingress_node_id)
        .map(|n| n.hostname)
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| ingress_node_id.to_string())
}

/// Resolve a workload to an ingress-reachable upstream URL using only
/// THIS node's cached container lists (no network I/O — safe for the
/// 30s reconcile).
/// - `Ok(Some(url))` — the workload runs here and is reachable.
/// - `Ok(None)`      — not running on this node (caller may look wider).
/// - `Err(..)`       — bad input, or it runs here but the ingress can't
///   reach it (message says how to fix that).
pub fn resolve_upstream_local(
    kind: &str,
    workload_ref: &str,
    port: u16,
    scheme: &str,
    ingress_node_id: &str,
    cluster: &crate::agent::ClusterState,
) -> Result<Option<String>, String> {
    if port == 0 {
        return Err("Pick the port the workload listens on.".into());
    }
    let scheme = normalise_scheme(scheme);
    match kind {
        "manual" => {
            let host = workload_ref.trim();
            if host.is_empty() {
                return Err("Enter the workload's IP address or hostname.".into());
            }
            Ok(Some(format!("{scheme}://{host}:{port}")))
        }
        "docker" | "lxc" => {
            let list = if kind == "docker" {
                crate::containers::docker_list_all_cached()
            } else {
                crate::containers::lxc_list_all_cached()
            };
            let Some(c) = list.iter().find(|c| c.name == workload_ref) else {
                return Ok(None);
            };
            let (is_ingress, addr, label) = self_facts(cluster, ingress_node_id);
            reachable_upstream(
                c, port, scheme, is_ingress, &addr, &label,
                &ingress_label(cluster, ingress_node_id),
            )
            .map(Some)
        }
        other => Err(format!("Unknown workload type '{other}'.")),
    }
}

/// Expose-time resolution: local lists first, then every online peer's
/// container list — so the operator can expose a workload from ANY
/// node's UI, not just the one hosting it. Peer lookups reuse the same
/// /api/containers/{docker,lxc} endpoints the cluster containers view
/// fans out to, authenticated with the cluster secret.
pub async fn resolve_upstream_cluster(
    kind: &str,
    workload_ref: &str,
    port: u16,
    scheme: &str,
    ingress_node_id: &str,
    cluster: &crate::agent::ClusterState,
    cluster_secret: &str,
) -> Result<String, String> {
    // Local (also covers manual + input validation).
    match resolve_upstream_local(kind, workload_ref, port, scheme, ingress_node_id, cluster) {
        Ok(Some(url)) => return Ok(url),
        Ok(None) => {}
        Err(e) => return Err(e),
    }
    let scheme = normalise_scheme(scheme);
    let ingress_lbl = ingress_label(cluster, ingress_node_id);
    let path = if kind == "docker" { "/api/containers/docker" } else { "/api/containers/lxc" };
    let peers: Vec<_> = cluster
        .get_all_nodes()
        .into_iter()
        .filter(|n| !n.is_self && n.online && n.node_type == "wolfstack")
        .collect();
    let client = &*crate::api::API_HTTP_CLIENT;
    for peer in peers {
        let urls = crate::api::build_node_urls(&peer.address, peer.port, path);
        let mut list: Option<Vec<crate::containers::ContainerInfo>> = None;
        for url in &urls {
            let resp = client
                .get(url)
                .timeout(std::time::Duration::from_secs(5))
                .peer_auth(cluster_secret)
                .send()
                .await;
            if let Ok(r) = resp
                && r.status().is_success()
                && let Ok(v) = r.json::<Vec<crate::containers::ContainerInfo>>().await
            {
                list = Some(v);
                break;
            }
        }
        let Some(list) = list else { continue };
        let Some(c) = list.iter().find(|c| c.name == workload_ref) else { continue };
        let hosting_is_ingress = crate::wolfrun::node_matches_id(&peer, ingress_node_id);
        let label = if peer.hostname.is_empty() { peer.id.clone() } else { peer.hostname.clone() };
        return reachable_upstream(c, port, scheme, hosting_is_ingress, &peer.address, &label, &ingress_lbl);
    }
    Err(format!(
        "{kind} container '{workload_ref}' isn't running on any reachable cluster node — check the name, or use a manual IP."
    ))
}

/// Build the WolfRouter proxy that fronts one exposed workload.
pub fn build_proxy(
    cfg: &ExposureConfig,
    subdomain: &str,
    kind: &str,
    workload_ref: &str,
    port: u16,
    scheme: &str,
    upstream_url: &str,
) -> HttpProxy {
    let fqdn = format!("{}.{}", subdomain, cfg.zone.trim());
    let tls = if cfg.cert_path.trim().is_empty() {
        None
    } else {
        Some(TlsConfig {
            cert_path: cfg.cert_path.trim().to_string(),
            key_path: cfg.key_path.trim().to_string(),
            cert_name: cfg.cert_name.trim().to_string(),
        })
    };
    let has_tls = tls.is_some();
    HttpProxy {
        id: format!("{ID_PREFIX}{subdomain}"),
        server_names: vec![fqdn],
        enabled: true,
        listen_ports: Vec::new(), // 80 always, + 443 when TLS present
        targets: vec![ProxyTarget {
            node_id: cfg.ingress_node_id.clone(),
            runtime: TargetRuntime::Host,
        }],
        edge: EdgeStrategy::default(),
        upstreams: vec![Upstream {
            url: upstream_url.to_string(),
            weight: 1,
            max_conns: 0,
        }],
        lb_strategy: Default::default(),
        tls,
        force_https: has_tls,
        hsts: false,
        http2: has_tls,
        websocket: true,
        upstream_headers: Vec::new(),
        response_headers: Vec::new(),
        connect_timeout_s: 0,
        send_timeout_s: 0,
        read_timeout_s: 0,
        error_pages: Vec::new(),
        access: Default::default(),
        description: "Managed by Internet Exposure".to_string(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        exposure: Some(ExposureSource {
            workload_kind: kind.to_string(),
            workload_ref: workload_ref.to_string(),
            port,
            scheme: normalise_scheme(scheme).to_string(),
        }),
    }
}

/// Re-resolve the upstream of every exposure proxy whose workload can
/// move (docker/lxc). Runs on every node with LOCAL data only: the node
/// hosting a workload is the one that sees it and rewrites its upstream
/// to something the ingress can reach (bridge IP when hosting == ingress,
/// otherwise node address + published host port). Returns true if
/// anything changed so the caller saves, re-applies AND replicates —
/// without replication the ingress node would never learn a move that
/// happened elsewhere. Manual upstreams are left alone.
pub fn reconcile_upstreams(
    proxies: &mut [HttpProxy],
    cluster: &crate::agent::ClusterState,
) -> bool {
    let cfg = ExposureConfig::load();
    let mut changed = false;
    for p in proxies.iter_mut() {
        let Some(src) = p.exposure.clone() else { continue };
        if src.workload_kind == "manual" {
            continue;
        }
        // Ok(None): the workload doesn't run on THIS node — its hosting
        // node's reconcile owns the entry; leave the last-known upstream.
        // Err: it runs here but the ingress can't reach it (e.g. the port
        // stopped being published) — also leave last-known rather than
        // blanking a route that may still work.
        let Ok(Some(url)) = resolve_upstream_local(
            &src.workload_kind, &src.workload_ref, src.port, &src.scheme,
            &cfg.ingress_node_id, cluster,
        ) else {
            continue;
        };
        if p.upstreams.len() != 1 || p.upstreams[0].url != url {
            p.upstreams = vec![Upstream { url, weight: 1, max_conns: 0 }];
            changed = true;
        }
    }
    changed
}

/// Explicitly drop an exposure proxy's nginx conf on the local node and
/// reload the proxy runtime. `apply_for_node` only prunes + reloads when
/// the node still has at least one proxy (a live "bucket"); removing the
/// LAST exposure would otherwise leave a stale conf file that nginx keeps
/// serving until something reloads it. Best-effort: a no-op when there's
/// no running nginx/wolfproxy.
pub fn cleanup_local_conf(id: &str) {
    use crate::configurator::ExecTarget;
    let t = ExecTarget::Host;
    let path = format!(
        "{}/{}{}.conf",
        crate::networking::router::http_proxy::CONFIG_DIR,
        crate::networking::router::http_proxy::FILE_PREFIX,
        id
    );
    let _ = t.exec(&format!("rm -f '{}'", path.replace('\'', "'\\''")));
    let _ = t.exec(
        "nginx -t >/dev/null 2>&1 && \
         (nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || \
          systemctl reload wolfproxy 2>/dev/null) || true",
    );
}

/// The public URL an exposed proxy serves on.
pub fn public_url(cfg: &ExposureConfig, p: &HttpProxy) -> String {
    let scheme = if p.tls.is_some() { "https" } else { "http" };
    let host = p.server_names.first().cloned().unwrap_or_default();
    let _ = cfg;
    format!("{scheme}://{host}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_host_port_parses_docker_ps_formats() {
        // Standard v4 + v6 publish of the same port.
        let ports = vec![
            "0.0.0.0:8989->7878/tcp".to_string(),
            "[::]:8989->7878/tcp".to_string(),
        ];
        assert_eq!(published_host_port(&ports, 7878), Some(8989));
        // Container-only (unpublished) entries never match.
        let unpublished = vec!["7878/tcp".to_string()];
        assert_eq!(published_host_port(&unpublished, 7878), None);
        // Wrong container port doesn't match.
        assert_eq!(published_host_port(&ports, 80), None);
        // Bound to a specific host address.
        let bound = vec!["192.168.1.5:8080->80/tcp".to_string()];
        assert_eq!(published_host_port(&bound, 80), Some(8080));
        // udp entries parse the same way.
        let udp = vec!["0.0.0.0:5353->53/udp".to_string()];
        assert_eq!(published_host_port(&udp, 53), Some(5353));
    }

    #[test]
    fn normalise_scheme_defaults_to_http() {
        assert_eq!(normalise_scheme("https"), "https");
        assert_eq!(normalise_scheme("HTTPS "), "https");
        assert_eq!(normalise_scheme("http"), "http");
        assert_eq!(normalise_scheme(""), "http");
        assert_eq!(normalise_scheme("gopher"), "http");
    }
}
