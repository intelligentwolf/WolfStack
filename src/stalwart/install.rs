// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com
//
//! The cross-node install job. Runs on the owner node (where the chosen
//! Galera cluster is defined) on a dedicated OS thread, streaming progress
//! lines to the browser.
//!
//! Order (each step's reason cited where it is done):
//!   1. pre-install checks on every chosen node
//!   2. database + user on the Galera cluster
//!   3. coordinator (Keep members, or Valkey + Sentinel)
//!   4. Stalwart bootstrap on the first mail node
//!   5. first node in normal mode → API key → coordinator object → restart
//!   6. remaining mail nodes join with the same config.json
//!   7. verify every node holds a cluster lease

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use super::deploy::{self, KeepDeploy, KeepMemberSpec, StalwartDeploy, StalwartMode, ValkeyDeploy};
use super::preflight::Preflight;
use super::{CoordMember, CoordinatorKind, MailCluster, MailNode};
use crate::node_identity::PeerAuth;

/// Runtime context for routing per-node work, built once per request.
pub struct MailOpCtx {
    pub self_id: String,
    pub nodes: Vec<crate::agent::Node>,
    pub cluster_secret: String,
    pub rt: tokio::runtime::Handle,
}

impl MailOpCtx {
    /// Resolve by either the locally-minted `node-…` key or the peer's stable
    /// self_id (the two namespaces differ — see galera::GaleraOpCtx).
    pub fn resolve(&self, id: &str) -> Option<&crate::agent::Node> {
        self.nodes.iter().find(|n| n.id == id || n.self_id.as_deref() == Some(id))
    }

    pub fn is_self(&self, id: &str) -> bool {
        id == self.self_id
            || self.nodes.iter().any(|n| n.is_self && (n.id == id || n.self_id.as_deref() == Some(id)))
    }

    /// The stable id we record for a node.
    pub fn stable_id(&self, id: &str) -> String {
        if self.is_self(id) {
            return self.self_id.clone();
        }
        self.resolve(id).and_then(|n| n.self_id.clone()).unwrap_or_else(|| id.to_string())
    }

    pub fn label(&self, id: &str) -> String {
        self.resolve(id)
            .map(|n| n.display_name.clone().filter(|d| !d.is_empty()).unwrap_or_else(|| n.hostname.clone()))
            .unwrap_or_else(|| id.to_string())
    }

    /// Call a node-local route on a peer (cluster-secret authenticated).
    /// Errors carry the peer's `error` string.
    pub fn peer(&self, id: &str, method: reqwest::Method, path: &str, body: Option<&Value>, timeout_secs: u64) -> Result<Value, String> {
        let n = self.resolve(id).ok_or_else(|| format!("node '{}' is not in this cluster", id))?;
        let urls = crate::api::build_node_urls(&n.address, n.port, path);
        let secret = self.cluster_secret.clone();
        let label = self.label(id);
        let body = body.cloned();
        self.rt.block_on(async move {
            let mut last = format!("could not reach {}", label);
            for url in &urls {
                let mut req = crate::api::API_HTTP_CLIENT.request(method.clone(), url)
                    .peer_auth(&secret)
                    .timeout(Duration::from_secs(timeout_secs));
                if let Some(b) = &body { req = req.json(b); }
                match req.send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        let v: Value = resp.json().await.unwrap_or(Value::Null);
                        if status.is_success() { return Ok(v); }
                        // A peer on an older WolfStack has no /api/stalwart routes.
                        if status == reqwest::StatusCode::NOT_FOUND && v.get("error").is_none() {
                            return Err(format!("{}: its WolfStack is too old for Mail Manager — update WolfStack on {} first", label, label));
                        }
                        last = v.get("error").and_then(|e| e.as_str()).map(|s| s.to_string())
                            .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
                        return Err(format!("{}: {}", label, last));
                    }
                    Err(e) => last = format!("{}: {}", label, e),
                }
            }
            Err(last)
        })
    }
}

fn logln(log: &Sender<String>, msg: impl Into<String>) {
    let _ = log.send(msg.into());
}

#[derive(Debug, Clone, Deserialize)]
pub struct InstallRequest {
    pub id: String,
    pub name: String,
    pub public_hostname: String,
    pub default_domain: String,
    pub galera_cluster_id: String,
    pub mail_nodes: Vec<String>,
    /// "keep" or "redis". Ignored for a single mail node.
    #[serde(default)]
    pub coordinator: String,
    /// Coordinator members. Empty → the mail nodes.
    #[serde(default)]
    pub coordinator_nodes: Vec<String>,
    /// Stalwart's built-in ACME for the hostname (Bootstrap
    /// `requestTlsCertificate`, default true per docs ref/object/bootstrap.md).
    #[serde(default = "yes")]
    pub request_tls_certificate: bool,
    /// WolfStack cluster name (UI scope).
    #[serde(default)]
    pub cluster: String,
    /// Build a new Galera cluster for the mail database instead of using an
    /// existing one (`galera_cluster_id` is then empty).
    #[serde(default)]
    pub new_galera: Option<NewGalera>,
}

/// A Galera cluster the install builds with WolfStack's own provisioner.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NewGalera {
    /// Hosts for the members. Empty → the mail servers. Always 3 members: a
    /// Galera cluster needs a majority to keep accepting writes, so 2
    /// survive nothing 1 doesn't; fewer hosts than 3 means some host carries
    /// two members (quorum, but no protection from that host failing).
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// Galera members a new mail database cluster gets.
const NEW_GALERA_MEMBERS: usize = 3;

/// Member hosts for a new Galera cluster: the chosen hosts cycled to 3.
pub fn galera_member_hosts(hosts: &[String]) -> Vec<String> {
    (0..NEW_GALERA_MEMBERS).map(|i| hosts[i % hosts.len()].clone()).collect()
}

fn yes() -> bool { true }

/// The preflight result of one node, as the wizard shows it.
#[derive(Debug, Clone, Serialize)]
pub struct NodeCheck {
    pub node_id: String,
    pub label: String,
    pub ok: bool,
    pub error: String,
    pub report: Option<Preflight>,
    /// Other chosen servers this one could NOT reach over WolfNet.
    pub wolfnet_unreachable: Vec<String>,
}

/// Run preflight on each node (local fast path, else the peer route).
pub fn preflight_nodes(ctx: &MailOpCtx, cluster_id: &str, node_ids: &[String]) -> Vec<NodeCheck> {
    let checks = node_ids.iter().map(|id| {
        let label = ctx.label(id);
        let r = if ctx.is_self(id) {
            Ok(super::preflight::run_local(cluster_id))
        } else {
            let path = format!("/api/stalwart/local/preflight?cluster_id={}", cluster_id);
            ctx.peer(id, reqwest::Method::GET, &path, None, 40)
                .and_then(|v| serde_json::from_value::<Preflight>(v).map_err(|e| format!("{}: unreadable preflight reply ({}) — is WolfStack up to date there?", label, e)))
        };
        match r {
            Ok(p) => NodeCheck { node_id: ctx.stable_id(id), label, ok: true, error: String::new(), report: Some(p), wolfnet_unreachable: vec![] },
            Err(e) => NodeCheck { node_id: ctx.stable_id(id), label, ok: false, error: e, report: None, wolfnet_unreachable: vec![] },
        }
    }).collect::<Vec<_>>();
    check_wolfnet_paths(ctx, node_ids, checks)
}

/// Second pass: every checked node tries each other's WolfStack port on its
/// WolfNet address.
fn check_wolfnet_paths(ctx: &MailOpCtx, node_ids: &[String], mut checks: Vec<NodeCheck>) -> Vec<NodeCheck> {
    // (index, label, "wolfnet_ip:wolfstack_port")
    let endpoints: Vec<(usize, String, String)> = checks.iter().enumerate().filter_map(|(i, c)| {
        let ip = c.report.as_ref()?.wolfnet_ip.clone()?;
        let port = ctx.resolve(&node_ids[i]).map(|n| n.port).unwrap_or(8553);
        Some((i, c.label.clone(), format!("{}:{}", ip, port)))
    }).collect();
    if endpoints.len() < 2 {
        return checks;
    }
    for (i, _, mine) in &endpoints {
        let targets: Vec<String> = endpoints.iter().filter(|(_, _, t)| t != mine).map(|(_, _, t)| t.clone()).collect();
        let results: Vec<(String, bool)> = if ctx.is_self(&node_ids[*i]) {
            super::preflight::reach(&targets).into_iter().map(|(t, r)| (t, r.is_ok())).collect()
        } else {
            match ctx.peer(&node_ids[*i], reqwest::Method::POST, "/api/stalwart/local/reach", Some(&json!({ "targets": targets })), 30) {
                Ok(v) => v.as_array().cloned().unwrap_or_default().iter()
                    .map(|r| (r.get("target").and_then(|t| t.as_str()).unwrap_or("").to_string(), r.get("ok").and_then(|o| o.as_bool()).unwrap_or(false)))
                    .collect(),
                // Couldn't ask: leave it to the per-node error already shown.
                Err(_) => continue,
            }
        };
        checks[*i].wolfnet_unreachable = results.into_iter().filter(|(_, ok)| !ok)
            .filter_map(|(t, _)| endpoints.iter().find(|(_, _, e)| *e == t).map(|(_, l, _)| l.clone()))
            .collect();
    }
    checks
}

/// Ed25519 key pair as (PKCS#8 private PEM, SPKI public PEM). Keep accepts
/// "PEM (PKCS#8 or SEC1)" private keys and "PEM `PUBLIC KEY` blocks" (keep
/// docs/DEPLOYMENT.md §2 `--tls-key`, `--tls-clients`); its README generates
/// them with `openssl genpkey -algorithm ed25519` — the same primitive.
fn ed25519_pair() -> Result<(String, String), String> {
    let k = openssl::pkey::PKey::generate_ed25519().map_err(|e| format!("generate key: {}", e))?;
    let private = k.private_key_to_pem_pkcs8().map_err(|e| e.to_string())?;
    let public = k.public_key_to_pem().map_err(|e| e.to_string())?;
    Ok((String::from_utf8_lossy(&private).to_string(), String::from_utf8_lossy(&public).to_string()))
}

/// Mail database + user names derived from the cluster id. MariaDB
/// identifiers: letters, digits, `_` (the id is validated to [a-z0-9-]).
pub fn db_names(id: &str) -> (String, String) {
    let base = id.replace('-', "_");
    (format!("stalwart_{}", base), format!("stalwart_{}", base))
}

/// Create the database and its user on the Galera cluster through the first
/// reachable member (Galera replicates DDL and grants to all members).
fn create_database(gc: &crate::galera::GaleraCluster, db: &str, user: &str, password: &str, rt: &tokio::runtime::Handle) -> Result<(), String> {
    let admin_pw = crate::galera::dec_secret(&gc.db_password_enc);
    if admin_pw.is_empty() {
        return Err(format!("the Galera cluster '{}' has no stored admin password — re-enter it on the Galera page first", gc.name));
    }
    let stmts = [
        format!("CREATE DATABASE IF NOT EXISTS `{}` CHARACTER SET utf8mb4", db),
        format!("CREATE USER IF NOT EXISTS '{}'@'%' IDENTIFIED BY '{}'", user, password),
        format!("ALTER USER '{}'@'%' IDENTIFIED BY '{}'", user, password),
        format!("GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'%'", db, user),
        "FLUSH PRIVILEGES".to_string(),
    ];
    let nodes = gc.nodes.clone();
    let admin = gc.db_user.clone();
    rt.block_on(async move {
        let mut last = "no reachable Galera member".to_string();
        for n in &nodes {
            let params = crate::mysql_editor::ConnParams {
                host: n.address.clone(), port: n.port, user: admin.clone(),
                password: admin_pw.clone(), database: None,
                db_type: crate::mysql_editor::DbType::default(),
            };
            if crate::mysql_editor::execute_query(&params, "", "SELECT 1").await.is_err() {
                last = format!("[{}] unreachable", n.container);
                continue;
            }
            for s in &stmts {
                crate::mysql_editor::execute_query(&params, "", s).await
                    .map_err(|e| format!("[{}] {}", n.container, e))?;
            }
            return Ok(());
        }
        Err(last)
    })
}

/// Log in AS the new mail user THROUGH the MaxScale proxy until it works.
///
/// MaxScale authenticates clients against its own cached copy of the
/// backend's user table and only reloads it after a failed login, rate
/// limited — found live 2026-11-13: Stalwart's bootstrap hit "Access
/// denied" seconds after the user was (re)created, and the same login
/// succeeded right after MaxScale logged "Read 6 user@host entries". This
/// makes the same connection Stalwart will, so the install only continues
/// once it would succeed.
fn wait_db_login(host: &str, port: u16, db: &str, user: &str, password: &str, rt: &tokio::runtime::Handle) -> Result<(), String> {
    let params = crate::mysql_editor::ConnParams {
        host: host.to_string(), port, user: user.to_string(), password: password.to_string(),
        database: Some(db.to_string()), db_type: crate::mysql_editor::DbType::default(),
    };
    let start = Instant::now();
    loop {
        let r = rt.block_on(crate::mysql_editor::execute_query(&params, db, "SELECT 1"));
        match r {
            Ok(_) => return Ok(()),
            Err(e) if start.elapsed() > Duration::from_secs(90) => {
                return Err(format!("The mail database user cannot log in through MaxScale at {}:{} ({}). Check MaxScale on the Galera page.", host, port, e));
            }
            Err(_) => std::thread::sleep(Duration::from_secs(5)),
        }
    }
}

/// Deploy helper: local call or the matching peer route.
fn on_node<T: Serialize>(ctx: &MailOpCtx, node: &str, route: &str, body: &T, timeout_secs: u64, local: impl FnOnce() -> Result<Value, String>) -> Result<Value, String> {
    if ctx.is_self(node) {
        local()
    } else {
        let v = serde_json::to_value(body).map_err(|e| e.to_string())?;
        ctx.peer(node, reqwest::Method::POST, &format!("/api/stalwart/local/{}", route), Some(&v), timeout_secs)
    }
}

pub fn install(req: &InstallRequest, ctx: &MailOpCtx, log: &Sender<String>) -> Result<MailCluster, String> {
    // ── Validate ────────────────────────────────────────────────────
    if !super::valid_cluster_id(&req.id) {
        return Err("Cluster id must be 1–24 lowercase letters, digits or '-', starting with a letter.".into());
    }
    if super::get_cluster(&req.id).is_some() {
        return Err(format!("A mail cluster with id '{}' already exists.", req.id));
    }
    if !super::valid_domain(&req.public_hostname) {
        return Err(format!("'{}' is not a valid hostname (e.g. mx.example.com).", req.public_hostname));
    }
    if !super::valid_domain(&req.default_domain) {
        return Err(format!("'{}' is not a valid mail domain.", req.default_domain));
    }
    if req.mail_nodes.is_empty() {
        return Err("Choose at least one server for Stalwart.".into());
    }
    let mut seen = std::collections::HashSet::new();
    for n in &req.mail_nodes {
        if !seen.insert(ctx.stable_id(n)) {
            return Err("A server is listed twice — each mail server runs one Stalwart node.".into());
        }
    }
    let clustered = req.mail_nodes.len() > 1;
    let kind = if !clustered {
        CoordinatorKind::None
    } else {
        match req.coordinator.as_str() {
            "keep" => CoordinatorKind::Keep,
            "redis" => CoordinatorKind::Redis,
            _ => return Err("Choose a coordinator: Stalwart Keep or Redis.".into()),
        }
    };
    let coord_ids: Vec<String> = if kind == CoordinatorKind::None {
        vec![]
    } else if req.coordinator_nodes.is_empty() {
        req.mail_nodes.clone()
    } else {
        req.coordinator_nodes.clone()
    };
    // A Keep member or Sentinel that can't reach a majority stops serving
    // (keep docs/DESIGN.md:42; valkey-doc sentinel.md:119), so two members
    // survive nothing that one wouldn't.
    if kind != CoordinatorKind::None && coord_ids.len() == 2 {
        return Err("The coordinator needs 1 server (no failover) or 3 or more (survives one failure). With 2, losing either one stops the whole mail cluster, because the survivor no longer has a majority. Add a third server — any small node will do — or use one.".into());
    }

    let existing_galera = if req.new_galera.is_some() {
        if !req.galera_cluster_id.is_empty() {
            return Err("Choose either an existing Galera cluster or a new one, not both.".into());
        }
        None
    } else {
        let gc = crate::galera::get_cluster(&req.galera_cluster_id)
            .ok_or_else(|| format!("Galera cluster '{}' is not defined on this server — open the wizard from the server that owns it.", req.galera_cluster_id))?;
        if gc.proxies.is_empty() {
            return Err(format!(
                "Galera cluster '{}' has no MaxScale proxy. Stalwart connects to ONE database address, so without the proxy the mail cluster would stop whenever that one Galera member does. Add a MaxScale proxy on the Galera page, then run the wizard again.", gc.name));
        }
        Some(gc)
    };

    // ── 1. Pre-install checks ───────────────────────────────────────
    logln(log, "Checking the chosen servers…");
    let mut all_ids: Vec<String> = req.mail_nodes.clone();
    for c in &coord_ids {
        if !all_ids.iter().any(|a| ctx.stable_id(a) == ctx.stable_id(c)) {
            all_ids.push(c.clone());
        }
    }
    let checks = preflight_nodes(ctx, &req.id, &all_ids);
    let mut problems = vec![];
    let report = |id: &str| -> Option<Preflight> {
        checks.iter().find(|c| c.node_id == ctx.stable_id(id)).and_then(|c| c.report.clone())
    };
    for c in &checks {
        if !c.ok { problems.push(c.error.clone()); continue; }
        let p = c.report.as_ref().unwrap();
        if !p.docker { problems.push(format!("{}: {}", c.label, p.docker_detail)); }
        if p.wolfnet_ip.is_none() { problems.push(format!("{}: WolfNet is not running, and the mail cluster talks over WolfNet.", c.label)); }
        if !c.wolfnet_unreachable.is_empty() {
            problems.push(format!("{} cannot reach {} over WolfNet — the mail servers talk to each other over it. Check WolfNet peering between them (Networking → WolfNet).", c.label, c.wolfnet_unreachable.join(", ")));
        }
        if p.ntp_synchronized == Some(false) {
            logln(log, format!("  ⚠ {}: the clock is not NTP-synchronised. Stalwart cluster leases need synchronised clocks — enable NTP (timedatectl set-ntp true).", c.label));
        }
    }
    for id in &req.mail_nodes {
        if let Some(p) = report(id) {
            for pc in &p.port_conflicts { problems.push(format!("{}: {}", ctx.label(id), pc)); }
            if p.outbound_smtp == Some(false) {
                logln(log, format!("  ⚠ {}: {}", ctx.label(id), p.outbound_smtp_detail));
            }
        }
    }
    for id in &coord_ids {
        if let Some(p) = report(id) {
            for pc in &p.coordinator_port_conflicts { problems.push(format!("{}: {}", ctx.label(id), pc)); }
        }
    }
    if kind == CoordinatorKind::Keep {
        for id in all_ids.iter() {
            if let Some(p) = report(id)
                && !p.kernel_ok_for_keep {
                    problems.push(format!("{}: kernel {} is older than 6.12, which Stalwart Keep requires. Upgrade the kernel, or choose Redis.", ctx.label(id), p.kernel));
                }
        }
    }
    if !problems.is_empty() {
        return Err(format!("The servers aren't ready:\n  • {}", problems.join("\n  • ")));
    }
    logln(log, "  ✓ all servers passed");

    // ── 1b. New Galera cluster, built with WolfStack's own provisioner ──
    let gc = match existing_galera {
        Some(gc) => gc,
        None => {
            let ng = req.new_galera.clone().unwrap_or_default();
            let hosts: Vec<String> = if ng.hosts.is_empty() { req.mail_nodes.clone() } else { ng.hosts.clone() };
            let hosts: Vec<String> = hosts.iter().map(|h| ctx.stable_id(h)).collect();
            let member_hosts = galera_member_hosts(&hosts);
            let gctx = crate::galera::GaleraOpCtx {
                self_id: ctx.self_id.clone(), nodes: ctx.nodes.clone(),
                cluster_secret: ctx.cluster_secret.clone(), rt: ctx.rt.clone(),
            };
            let distinct = member_hosts.iter().collect::<std::collections::HashSet<_>>().len();
            logln(log, format!("Building a {}-member Galera cluster for mail on {} server(s) (takes several minutes)…", NEW_GALERA_MEMBERS, distinct));
            if distinct < NEW_GALERA_MEMBERS {
                logln(log, "  ⚠ fewer than 3 servers: some carry two database members — the database keeps quorum if one member stops, but not if a whole server fails.");
            }
            // Same defaults the Galera page's create wizard uses
            // (galera::default_distro / default_release / default_sst).
            let preq = crate::galera::ProvisionRequest {
                cluster_name: format!("{}-mail-db", req.id),
                cluster: req.cluster.clone(),
                node_count: NEW_GALERA_MEMBERS,
                name_prefix: format!("{}-galera", req.id),
                container_names: vec![],
                container_hosts: member_hosts,
                distribution: "debian".into(),
                release: "bookworm".into(),
                root_password: super::random_secret(32),
                sst_method: "mariabackup".into(),
                node_id: ctx.self_id.clone(),
            };
            let built = crate::galera::provision_cluster(&preq, log, &gctx)?;
            logln(log, "Adding a MaxScale proxy in front of it…");
            let mreq = crate::galera::MaxScaleRequest {
                container_name: format!("{}-maxscale", req.id),
                distribution: "debian".into(),
                release: "bookworm".into(),
                proxy_user: "maxscale".into(),
                proxy_password: super::random_secret(32),
                listener_port: 3306,
            };
            crate::galera::provision_maxscale(&built, &mreq, log, &gctx)?
        }
    };
    // Stalwart writes then reads straight back (e.g. a domain, then the
    // settings that reference it), so it must use MaxScale's master-only
    // route, never the read/write split (galera::ensure_master_listener).
    let gctx = crate::galera::GaleraOpCtx {
        self_id: ctx.self_id.clone(), nodes: ctx.nodes.clone(),
        cluster_secret: ctx.cluster_secret.clone(), rt: ctx.rt.clone(),
    };
    let (db_host, db_port) = crate::galera::ensure_master_listener(&gc, &gctx)
        .map_err(|e| format!("could not set up MaxScale's master-only route: {}", e))?;

    let wn = |id: &str| report(id).and_then(|p| p.wolfnet_ip).unwrap_or_default();
    let needs_rto = |id: &str| report(id).map(|p| p.needs_rto_sysctl).unwrap_or(false);
    let public_ip = |id: &str| ctx.resolve(id).and_then(|n| n.public_ip.clone()).unwrap_or_default();

    // ── Record (saved early so a failure can be cleaned up) ─────────
    let (db_name, db_user) = db_names(&req.id);
    let db_password = super::random_secret(40);
    let mail_nodes: Vec<MailNode> = req.mail_nodes.iter().enumerate().map(|(i, id)| MailNode {
        node_id: ctx.stable_id(id),
        label: ctx.label(id),
        // Distinct per node; Stalwart leases node ids by hostname.
        stalwart_hostname: format!("{}-node{}", req.id, i + 1),
        wolfnet_ip: wn(id),
        public_ip: public_ip(id),
    }).collect();
    let coordinator_members: Vec<CoordMember> = coord_ids.iter().enumerate().map(|(i, id)| CoordMember {
        node_id: ctx.stable_id(id),
        label: ctx.label(id),
        wolfnet_ip: wn(id),
        member_id: (i + 1) as u32,
    }).collect();
    let keep_secret = super::random_hex32();
    let keep_peer_secret = super::random_hex32();
    let redis_password = super::random_secret(40);
    let sentinel_password = super::random_secret(40);
    let mut rec = MailCluster {
        id: req.id.clone(), name: if req.name.trim().is_empty() { req.id.clone() } else { req.name.trim().to_string() },
        cluster: req.cluster.clone(), owner_node: ctx.self_id.clone(),
        public_hostname: req.public_hostname.to_lowercase(), default_domain: req.default_domain.to_lowercase(),
        galera_cluster_id: gc.id.clone(), db_host: db_host.clone(), db_port,
        db_name: db_name.clone(), db_user: db_user.clone(), db_password_enc: super::seal(&db_password)?,
        coordinator: kind, coordinator_members: coordinator_members.clone(),
        keep_secret_enc: if kind == CoordinatorKind::Keep { super::seal(&keep_secret)? } else { String::new() },
        keep_peer_secret_enc: if kind == CoordinatorKind::Keep { super::seal(&keep_peer_secret)? } else { String::new() },
        redis_password_enc: if kind == CoordinatorKind::Redis { super::seal(&redis_password)? } else { String::new() },
        sentinel_password_enc: if kind == CoordinatorKind::Redis { super::seal(&sentinel_password)? } else { String::new() },
        mail_nodes: mail_nodes.clone(),
        admin_user: String::new(), admin_password_enc: String::new(), api_key_enc: String::new(),
        created_at: chrono::Utc::now().to_rfc3339(),
        status: "installing".into(), last_error: String::new(),
        request_tls_certificate: req.request_tls_certificate,
    };
    super::upsert_cluster(rec.clone())?;

    // ── 2. Database ─────────────────────────────────────────────────
    logln(log, format!("Creating database `{}` on Galera cluster '{}'…", db_name, gc.name));
    create_database(&gc, &db_name, &db_user, &db_password, &ctx.rt)?;
    wait_db_login(&db_host, db_port, &db_name, &db_user, &db_password, &ctx.rt)?;
    logln(log, format!("  ✓ database ready (Stalwart connects through MaxScale's master-only route at {}:{})", db_host, db_port));

    // ── 3. Coordinator ──────────────────────────────────────────────
    let mut keep_client_keys: Vec<(String, String)> = vec![]; // per mail node: (private, public)
    let mut keep_servers_pem = String::new();
    let in_memory_store: Value = match kind {
        // Single node: the local in-memory store (docs storage/in-memory.md:
        // `Default` — local, single node only).
        CoordinatorKind::None => json!({ "@type": "Default" }),
        CoordinatorKind::Keep => {
            logln(log, format!("Deploying Stalwart Keep on {} server(s)…", coordinator_members.len()));
            let mut server_keys = vec![];
            for _ in &coordinator_members { server_keys.push(ed25519_pair()?); }
            for _ in &mail_nodes { keep_client_keys.push(ed25519_pair()?); }
            keep_servers_pem = server_keys.iter().map(|k| k.1.clone()).collect::<Vec<_>>().join("");
            let clients_pem: String = keep_client_keys.iter().map(|k| k.1.clone()).collect::<Vec<_>>().join("");
            let specs: Vec<KeepMemberSpec> = coordinator_members.iter().map(|m| KeepMemberSpec {
                member_id: m.member_id,
                wolfnet_ip: m.wolfnet_ip.clone(),
                // ≤2 shards: plenty for a mail cluster's locks and events.
                shards: report(&m.node_id).map(|p| p.cpus.clamp(1, 2) as u32).unwrap_or(1),
            }).collect();
            for (i, m) in coordinator_members.iter().enumerate() {
                let d = KeepDeploy {
                    cluster_id: req.id.clone(), member_id: m.member_id, members: specs.clone(),
                    cluster_secret: keep_secret.clone(), peer_secret: keep_peer_secret.clone(),
                    server_key_pem: server_keys[i].0.clone(), servers_pem: keep_servers_pem.clone(),
                    clients_pem: clients_pem.clone(), needs_rto_sysctl: needs_rto(&m.node_id),
                };
                logln(log, format!("  Keep member {} on {}…", m.member_id, m.label));
                on_node(ctx, &m.node_id, "keep", &d, 600, || deploy::deploy_keep(&d).map(|_| json!({})))?;
            }
            logln(log, "  Waiting for Keep members to settle…");
            let start = Instant::now();
            loop {
                let unsettled: Vec<String> = coordinator_members.iter().filter(|m| {
                    if ctx.is_self(&m.node_id) {
                        !deploy::keep_settled(&req.id)
                    } else {
                        ctx.peer(&m.node_id, reqwest::Method::GET, &format!("/api/stalwart/local/keep-settled?cluster_id={}", req.id), None, 15)
                            .map(|v| !v.get("settled").and_then(|s| s.as_bool()).unwrap_or(false))
                            .unwrap_or(true)
                    }
                }).map(|m| m.label.clone()).collect();
                if unsettled.is_empty() { break; }
                if start.elapsed() > Duration::from_secs(180) {
                    return Err(format!("Keep did not settle on: {}. Check that these servers reach each other over WolfNet on ports 7000 and 7100 (TCP and UDP).", unsettled.join(", ")));
                }
                std::thread::sleep(Duration::from_secs(3));
            }
            logln(log, "  ✓ Keep is settled");
            // Source: docs cluster/keep/stalwart.md — Keep InMemoryStore with
            // cluster discovery, cluster secret and raw-public-key TLS.
            let hosts: serde_json::Map<String, Value> = coordinator_members.iter()
                .map(|m| (format!("{}:{}", m.wolfnet_ip, super::preflight::KEEP_CLIENT_PORT), json!(true))).collect();
            json!({
                "@type": "Keep",
                "hosts": hosts,
                "clusterDiscovery": true,
                "secret": { "@type": "File", "filePath": format!("{}/keep-secret", deploy::SECRET_DIR_IN_CONTAINER) },
                "tls": { "@type": "RawPublicKeys", "keyPath": deploy::KEEP_KEY_IN_CONTAINER, "serverKeysPath": deploy::KEEP_SERVERS_IN_CONTAINER },
            })
        }
        CoordinatorKind::Redis => {
            logln(log, format!("Deploying Valkey + Sentinel on {} server(s)…", coordinator_members.len()));
            let primary = coordinator_members[0].wolfnet_ip.clone();
            // Quorum = majority of Sentinels; failover needs a majority anyway
            // (valkey-doc sentinel.md:119, :1065).
            let quorum = (coordinator_members.len() as u32) / 2 + 1;
            for m in &coordinator_members {
                let d = ValkeyDeploy {
                    cluster_id: req.id.clone(), wolfnet_ip: m.wolfnet_ip.clone(), primary_ip: primary.clone(),
                    password: redis_password.clone(), sentinel_password: sentinel_password.clone(), quorum,
                };
                logln(log, format!("  Valkey + Sentinel on {}…", m.label));
                on_node(ctx, &m.node_id, "valkey", &d, 600, || deploy::deploy_valkey(&d).map(|_| json!({})))?;
            }
            let first = &coordinator_members[0];
            let start = Instant::now();
            loop {
                let r = if ctx.is_self(&first.node_id) {
                    deploy::sentinel_ckquorum(&req.id, &first.wolfnet_ip, &sentinel_password)
                } else {
                    ctx.peer(&first.node_id, reqwest::Method::POST, "/api/stalwart/local/sentinel-quorum",
                        Some(&json!({ "cluster_id": req.id, "wolfnet_ip": first.wolfnet_ip, "sentinel_password": sentinel_password })), 15)
                        .and_then(|v| if v.get("ok").and_then(|o| o.as_bool()).unwrap_or(false) { Ok(String::new()) }
                                      else { Err(v.get("detail").and_then(|d| d.as_str()).unwrap_or("").to_string()) })
                };
                match r {
                    Ok(_) => break,
                    Err(e) if start.elapsed() > Duration::from_secs(120) =>
                        return Err(format!("Sentinel cannot reach quorum: {}. Check that the servers reach each other over WolfNet on ports 6379 and 26379.", e)),
                    Err(_) => std::thread::sleep(Duration::from_secs(3)),
                }
            }
            logln(log, "  ✓ Sentinel quorum reached");
            let urls: serde_json::Map<String, Value> = coordinator_members.iter()
                .map(|m| (format!("redis://{}:{}", m.wolfnet_ip, super::preflight::SENTINEL_PORT), json!(true))).collect();
            // Source: docs storage/backends/redis.md "Sentinel configuration".
            json!({
                "@type": "RedisSentinel",
                "urls": urls,
                "serviceName": deploy::SENTINEL_SERVICE,
                "authSecret": { "@type": "File", "filePath": format!("{}/redis-password", deploy::SECRET_DIR_IN_CONTAINER) },
                "sentinelSecret": { "@type": "File", "filePath": format!("{}/sentinel-password", deploy::SECRET_DIR_IN_CONTAINER) },
            })
        }
    };

    // Secret files every Stalwart node mounts at the same paths.
    let mut secrets = vec![("db-password".to_string(), db_password.clone())];
    match kind {
        CoordinatorKind::Keep => secrets.push(("keep-secret".into(), keep_secret.clone())),
        CoordinatorKind::Redis => {
            secrets.push(("redis-password".into(), redis_password.clone()));
            secrets.push(("sentinel-password".into(), sentinel_password.clone()));
        }
        CoordinatorKind::None => {}
    }
    let node_deploy = |i: usize, mode: StalwartMode, config_json: String, bootstrap: Option<Value>| StalwartDeploy {
        cluster_id: req.id.clone(), mode,
        stalwart_hostname: mail_nodes[i].stalwart_hostname.clone(),
        wolfnet_ip: mail_nodes[i].wolfnet_ip.clone(),
        config_json, bootstrap, secrets: secrets.clone(),
        keep_client_key_pem: keep_client_keys.get(i).map(|k| k.0.clone()).unwrap_or_default(),
        keep_servers_pem: keep_servers_pem.clone(),
        needs_rto_sysctl: kind == CoordinatorKind::Keep && needs_rto(&mail_nodes[i].node_id),
    };

    // ── 4. Bootstrap on the first node ──────────────────────────────
    let first = &mail_nodes[0];
    logln(log, format!("Setting up Stalwart on {} (first-time setup)…", first.label));
    // Bootstrap fields: docs ref/object/bootstrap.md. dataStore = MySql
    // (docs storage/backends/mysql.md), password read from a file so
    // config.json carries no secret. Tracer Stdout: in a container the
    // default Log tracer writes nowhere (install/platform/docker.md "Docker
    // needs Console"; the Tracer variant is `Stdout`, ref/object/tracer.md).
    let bootstrap = json!({
        "defaultHostname": rec.public_hostname,
        "defaultDomain": rec.default_domain,
        "requestTlsCertificate": req.request_tls_certificate,
        "generateDkimKeys": true,
        "dataStore": {
            "@type": "MySql",
            "host": db_host,
            "port": db_port,
            "database": db_name,
            "authUsername": db_user,
            "authSecret": { "@type": "File", "filePath": format!("{}/db-password", deploy::SECRET_DIR_IN_CONTAINER) },
        },
        "inMemoryStore": in_memory_store,
        "tracer": { "@type": "Stdout", "level": "info" },
    });
    let d0 = node_deploy(0, StalwartMode::Bootstrap, String::new(), Some(bootstrap));
    let rt = ctx.rt.clone();
    let br: deploy::BootstrapResult = {
        let v = on_node(ctx, &first.node_id, "stalwart", &d0, 900, || {
            deploy::deploy_stalwart(&d0, &rt).and_then(|r| serde_json::to_value(r.unwrap_or_default()).map_err(|e| e.to_string()))
        })?;
        serde_json::from_value(v).map_err(|e| format!("unreadable setup result: {}", e))?
    };
    if br.config_json.trim().is_empty() || br.admin_password.is_empty() {
        return Err("Stalwart's setup finished without returning its configuration.".into());
    }
    rec.admin_user = br.admin_user.clone();
    rec.admin_password_enc = super::seal(&br.admin_password)?;
    super::upsert_cluster(rec.clone())?;
    logln(log, format!("  ✓ setup complete — administrator {}", br.admin_user));

    // ── 5. First node live, API key, coordinator ────────────────────
    logln(log, format!("Starting Stalwart on {}…", first.label));
    let d1 = node_deploy(0, StalwartMode::Normal, br.config_json.clone(), None);
    on_node(ctx, &first.node_id, "stalwart", &d1, 900, || deploy::deploy_stalwart(&d1, &rt).map(|_| json!({})))?;
    logln(log, "  ✓ running");
    let base = format!("http://{}:{}", first.wolfnet_ip, super::preflight::STALWART_MGMT_PORT);
    let admin = super::jmap::Auth::Basic { user: br.admin_user.clone(), password: br.admin_password.clone() };
    // API key for WolfStack itself. `Inherit` = the admin's permissions;
    // creating a key for one's own account needs no impersonation (docs
    // auth/authentication/api-key.md). The secret comes back once in
    // `created.<id>.secret` (stalwart registry/mapping/account.rs:510-523).
    let created = super::jmap::create(&ctx.rt, &base, &admin, "ApiKey",
        json!({ "description": "WolfStack Mail Manager", "permissions": { "@type": "Inherit" } }), None)
        .map_err(|e| format!("could not create WolfStack's API key: {}", e))?;
    let api_key = created.get("secret").and_then(|s| s.as_str()).unwrap_or("").to_string();
    if !api_key.starts_with("API_") {
        return Err("Stalwart created the API key but did not return its secret.".into());
    }
    rec.api_key_enc = super::seal(&api_key)?;
    super::upsert_cluster(rec.clone())?;
    let auth = super::jmap::Auth::Bearer(api_key);

    if kind != CoordinatorKind::None {
        // Coordinator `Default` reuses the in-memory store's Keep/Redis
        // connection (docs cluster/configuration/coordination.md; cluster/
        // keep/stalwart.md). The in-memory store was set first, as required
        // ("A cluster coordinator requires a Stalwart Keep or Redis in-memory
        // store, configure one first"). Takes effect after a restart.
        logln(log, "Enabling cluster coordination…");
        super::jmap::update(&ctx.rt, &base, &auth, "Coordinator", "singleton", json!({ "@type": "Default" }), None)
            .map_err(|e| format!("could not enable the coordinator: {}", e))?;
        if ctx.is_self(&first.node_id) {
            deploy::restart_stalwart(&req.id, &first.wolfnet_ip, &ctx.rt)?;
        } else {
            ctx.peer(&first.node_id, reqwest::Method::POST, "/api/stalwart/local/restart",
                Some(&json!({ "cluster_id": req.id, "wolfnet_ip": first.wolfnet_ip })), 300)?;
        }
        logln(log, "  ✓ coordination enabled");
    }

    // ── 6. Remaining nodes ──────────────────────────────────────────
    for (i, n) in mail_nodes.iter().enumerate().skip(1) {
        logln(log, format!("Starting Stalwart on {}…", n.label));
        let d = node_deploy(i, StalwartMode::Normal, br.config_json.clone(), None);
        on_node(ctx, &n.node_id, "stalwart", &d, 900, || deploy::deploy_stalwart(&d, &rt).map(|_| json!({})))?;
        logln(log, "  ✓ joined");
    }

    // ── 7. Verify cluster membership ────────────────────────────────
    if clustered {
        logln(log, "Checking every node holds a cluster lease…");
        let start = Instant::now();
        loop {
            let leases = super::jmap::query_get(&ctx.rt, &base, &auth, "ClusterNode", json!({}), None).unwrap_or_default();
            let active: Vec<String> = leases.iter()
                .filter(|l| l.get("status").and_then(|s| s.as_str()) == Some("active"))
                .filter_map(|l| l.get("hostname").and_then(|h| h.as_str()).map(|s| s.to_string()))
                .collect();
            let missing: Vec<&MailNode> = mail_nodes.iter().filter(|n| !active.contains(&n.stalwart_hostname)).collect();
            if missing.is_empty() {
                logln(log, format!("  ✓ {} nodes active", mail_nodes.len()));
                break;
            }
            if start.elapsed() > Duration::from_secs(90) {
                logln(log, format!("  ⚠ not yet active: {}. They may still be starting — check the Mail Manager status in a minute.",
                    missing.iter().map(|n| n.label.clone()).collect::<Vec<_>>().join(", ")));
                break;
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    }
    if kind == CoordinatorKind::Keep {
        logln(log, "Note: Keep holds its locks back for about 10½ minutes after a cold start (keep docs, \"Restarts and the quarantine\"), so queued deliveries may wait that long right after install.");
    }

    rec.status = "ready".into();
    super::upsert_cluster(rec.clone())?;
    Ok(rec)
}

/// Retry a FAILED install with the settings it was given: clear what the
/// failed attempt left on the servers, then install again. The mail database
/// is dropped and recreated — safe only because a failed install never
/// reached "ready", so no mail can be in it. A Galera cluster the first
/// attempt built is kept and reused.
pub fn retry(c: &MailCluster, ctx: &MailOpCtx, log: &Sender<String>) -> Result<MailCluster, String> {
    if c.status != "failed" {
        return Err(format!("Only a failed install can be retried; '{}' is {}.", c.id, if c.status.is_empty() { "unknown" } else { &c.status }));
    }
    logln(log, "Clearing what the failed attempt left behind…");
    uninstall(c, true, ctx, log)?;
    let req = InstallRequest {
        id: c.id.clone(),
        name: c.name.clone(),
        public_hostname: c.public_hostname.clone(),
        default_domain: c.default_domain.clone(),
        galera_cluster_id: c.galera_cluster_id.clone(),
        mail_nodes: c.mail_nodes.iter().map(|n| n.node_id.clone()).collect(),
        coordinator: match c.coordinator {
            CoordinatorKind::Keep => "keep".into(),
            CoordinatorKind::Redis => "redis".into(),
            CoordinatorKind::None => String::new(),
        },
        coordinator_nodes: c.coordinator_members.iter().map(|m| m.node_id.clone()).collect(),
        request_tls_certificate: c.request_tls_certificate,
        cluster: c.cluster.clone(),
        new_galera: None,
    };
    logln(log, "Installing again…");
    install(&req, ctx, log)
}

/// Mark an install failed (keeps the record so the operator can remove it).
pub fn mark_failed(id: &str, err: &str) {
    if let Some(mut c) = super::get_cluster(id)
        && c.status == "installing" {
            c.status = "failed".into();
            c.last_error = err.chars().take(2000).collect();
            let _ = super::upsert_cluster(c);
        }
}

/// Remove a cluster's containers from every node, optionally drop its
/// database, then forget it.
pub fn uninstall(c: &MailCluster, drop_database: bool, ctx: &MailOpCtx, log: &Sender<String>) -> Result<(), String> {
    let mut nodes: Vec<String> = c.mail_nodes.iter().map(|n| n.node_id.clone()).collect();
    for m in &c.coordinator_members {
        if !nodes.contains(&m.node_id) { nodes.push(m.node_id.clone()); }
    }
    let mut errors = vec![];
    for n in &nodes {
        logln(log, format!("Removing mail containers on {}…", ctx.label(n)));
        let r = if ctx.is_self(n) {
            deploy::remove_local(&c.id).map(|_| json!({}))
        } else {
            ctx.peer(n, reqwest::Method::POST, "/api/stalwart/local/remove", Some(&json!({ "cluster_id": c.id })), 120)
        };
        if let Err(e) = r { errors.push(e); }
    }
    if drop_database {
        logln(log, format!("Dropping database `{}`…", c.db_name));
        match crate::galera::get_cluster(&c.galera_cluster_id) {
            Some(gc) => {
                if let Err(e) = drop_database_on(&gc, &c.db_name, &c.db_user, &ctx.rt) { errors.push(e); }
            }
            None => errors.push(format!("Galera cluster '{}' is gone; database `{}` not dropped", c.galera_cluster_id, c.db_name)),
        }
    }
    if !errors.is_empty() {
        return Err(format!("Some parts could not be removed (the mail cluster record is kept so you can retry):\n  • {}", errors.join("\n  • ")));
    }
    super::remove_cluster(&c.id)
}

fn drop_database_on(gc: &crate::galera::GaleraCluster, db: &str, user: &str, rt: &tokio::runtime::Handle) -> Result<(), String> {
    let admin_pw = crate::galera::dec_secret(&gc.db_password_enc);
    let stmts = [format!("DROP DATABASE IF EXISTS `{}`", db), format!("DROP USER IF EXISTS '{}'@'%'", user)];
    let nodes = gc.nodes.clone();
    let admin = gc.db_user.clone();
    rt.block_on(async move {
        let mut last = "no reachable Galera member".to_string();
        for n in &nodes {
            let params = crate::mysql_editor::ConnParams {
                host: n.address.clone(), port: n.port, user: admin.clone(), password: admin_pw.clone(),
                database: None, db_type: crate::mysql_editor::DbType::default(),
            };
            if crate::mysql_editor::execute_query(&params, "", "SELECT 1").await.is_err() {
                last = format!("[{}] unreachable", n.container);
                continue;
            }
            for s in &stmts {
                crate::mysql_editor::execute_query(&params, "", s).await.map_err(|e| format!("[{}] {}", n.container, e))?;
            }
            return Ok(());
        }
        Err(last)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_galera_always_gets_three_members() {
        let h = |v: &[&str]| galera_member_hosts(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(h(&["a"]), vec!["a", "a", "a"]);
        assert_eq!(h(&["a", "b"]), vec!["a", "b", "a"]);
        assert_eq!(h(&["a", "b", "c", "d"]), vec!["a", "b", "c"]);
    }

    #[test]
    fn db_names_are_sql_safe() {
        assert_eq!(db_names("mail-2"), ("stalwart_mail_2".into(), "stalwart_mail_2".into()));
    }

    #[test]
    fn ed25519_pems() {
        let (k, p) = ed25519_pair().unwrap();
        assert!(k.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(p.starts_with("-----BEGIN PUBLIC KEY-----"));
    }
}
