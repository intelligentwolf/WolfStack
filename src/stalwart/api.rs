// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com
//
//! HTTP routes for the Stalwart Mail Manager.
//!
//! Operator routes use `require_auth` (read-only sessions are refused on
//! every mutating method centrally). Node-local routes move secrets between
//! nodes, so they accept only another node holding the cluster secret
//! (`require_cluster_auth`). Blocking work runs in `web::block` or on the
//! dedicated SSE job thread — never on the async runtime.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use serde_json::json;

use crate::api::{require_auth, require_cluster_auth, AppState};
use super::install::{InstallRequest, MailOpCtx};

fn ctx(state: &web::Data<AppState>) -> MailOpCtx {
    MailOpCtx {
        self_id: crate::agent::self_node_id(),
        nodes: state.cluster.get_all_nodes(),
        cluster_secret: state.cluster_secret.clone(),
        rt: tokio::runtime::Handle::current(),
    }
}

fn bad(e: impl Into<String>) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({ "error": e.into() }))
}

fn not_found(id: &str) -> HttpResponse {
    HttpResponse::NotFound().json(json!({ "error": format!("mail cluster '{}' is not defined on this server", id) }))
}

/// Run blocking `f` off the runtime, mapping Ok → 200 JSON, Err → 400.
async fn blocking<T: serde::Serialize + Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> HttpResponse {
    match web::block(f).await {
        Ok(Ok(v)) => HttpResponse::Ok().json(v),
        Ok(Err(e)) => bad(e),
        Err(e) => HttpResponse::InternalServerError().json(json!({ "error": e.to_string() })),
    }
}

fn load(id: &str) -> Result<super::MailCluster, HttpResponse> {
    super::get_cluster(id).ok_or_else(|| not_found(id))
}

// ── Operator routes ──────────────────────────────────────────────────

/// GET /api/stalwart/clusters — mail clusters whose record lives on this
/// node, secrets blanked. The UI aggregates across nodes.
async fn list(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let self_id = crate::agent::self_node_id();
    let v: Vec<_> = super::load_config().clusters.iter().map(|c| {
        let mut r = super::redacted(c);
        r.owner_node = self_id.clone();
        r
    }).collect();
    HttpResponse::Ok().json(v)
}

#[derive(Deserialize)]
struct PreflightReq {
    #[serde(default)]
    cluster_id: String,
    nodes: Vec<String>,
}

/// POST /api/stalwart/preflight — run the pre-install checks on each node.
async fn preflight(req: HttpRequest, state: web::Data<AppState>, body: web::Json<PreflightReq>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let b = body.into_inner();
    let id = if super::valid_cluster_id(&b.cluster_id) { b.cluster_id } else { "new".to_string() };
    let c = ctx(&state);
    blocking(move || Ok(super::install::preflight_nodes(&c, &id, &b.nodes))).await
}

/// POST /api/stalwart/install — the whole install, streamed as SSE.
async fn install(req: HttpRequest, state: web::Data<AppState>, body: web::Json<InstallRequest>) -> HttpResponse {
    let user = match require_auth(&req, &state) { Ok(u) => u, Err(e) => return e };
    let r = body.into_inner();
    let c = ctx(&state);
    tracing::info!("stalwart: install of mail cluster '{}' on {} node(s) started by {}", r.id, r.mail_nodes.len(), user);
    crate::api::galera_stream_job(move |tx| {
        let _ = tx.send(format!("Installing mail cluster '{}'…", r.id));
        match super::install::install(&r, &c, &tx) {
            Ok(rec) => {
                let _ = tx.send(format!("RESULT:OK:Mail cluster '{}' is running on {} server(s). Administrator: {}", rec.name, rec.mail_nodes.len(), rec.admin_user));
            }
            Err(e) => {
                super::install::mark_failed(&r.id, &e);
                let _ = tx.send(format!("RESULT:ERR:{}", e));
            }
        }
    })
}

#[derive(Deserialize)]
struct RemoveReq {
    #[serde(default)]
    drop_database: bool,
}

/// POST /api/stalwart/clusters/{id}/remove — remove containers everywhere
/// (and optionally the database), streamed as SSE.
async fn remove(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<RemoveReq>) -> HttpResponse {
    let user = match require_auth(&req, &state) { Ok(u) => u, Err(e) => return e };
    let id = path.into_inner();
    let c = match load(&id) { Ok(c) => c, Err(e) => return e };
    let drop_db = body.drop_database;
    let o = ctx(&state);
    tracing::warn!("stalwart: removal of mail cluster '{}' (drop database: {}) started by {}", id, drop_db, user);
    crate::api::galera_stream_job(move |tx| {
        match super::install::uninstall(&c, drop_db, &o, &tx) {
            Ok(()) => { let _ = tx.send(format!("RESULT:OK:Mail cluster '{}' removed.", c.name)); }
            Err(e) => { let _ = tx.send(format!("RESULT:ERR:{}", e)); }
        }
    })
}

/// POST /api/stalwart/clusters/{id}/retry — rerun a failed install with its
/// original settings, streamed as SSE.
async fn retry(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    let user = match require_auth(&req, &state) { Ok(u) => u, Err(e) => return e };
    let c = match load(&path.into_inner()) { Ok(c) => c, Err(e) => return e };
    let o = ctx(&state);
    tracing::info!("stalwart: retry of mail cluster '{}' started by {}", c.id, user);
    crate::api::galera_stream_job(move |tx| {
        match super::install::retry(&c, &o, &tx) {
            Ok(rec) => { let _ = tx.send(format!("RESULT:OK:Mail cluster '{}' is running on {} server(s). Administrator: {}", rec.name, rec.mail_nodes.len(), rec.admin_user)); }
            Err(e) => {
                super::install::mark_failed(&c.id, &e);
                let _ = tx.send(format!("RESULT:ERR:{}", e));
            }
        }
    })
}

/// GET /api/stalwart/clusters/{id}/health
async fn health(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let c = match load(&path.into_inner()) { Ok(c) => c, Err(e) => return e };
    let rt = tokio::runtime::Handle::current();
    blocking(move || Ok(super::manage::health(&c, &rt))).await
}

/// GET /api/stalwart/clusters/{id}/admin-password — Stalwart's own admin
/// sign-in, for its web admin. WolfStack administrators only; every reveal
/// is logged.
async fn admin_password(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    let user = match require_auth(&req, &state) { Ok(u) => u, Err(e) => return e };
    if !crate::api::caller_is_admin(&req, &user) {
        return HttpResponse::Forbidden().json(json!({ "error": "Only WolfStack administrators can view the Stalwart admin password." }));
    }
    let c = match load(&path.into_inner()) { Ok(c) => c, Err(e) => return e };
    tracing::warn!("stalwart: admin password of mail cluster '{}' revealed to {}", c.id, user);
    HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .json(json!({
            "user": c.admin_user,
            "password": super::unseal(&c.admin_password_enc),
            "admin_url": format!("https://{}/admin", c.public_hostname),
        }))
}

async fn domains(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let c = match load(&path.into_inner()) { Ok(c) => c, Err(e) => return e };
    let rt = tokio::runtime::Handle::current();
    blocking(move || super::manage::list_domains(&c, &rt)).await
}

async fn create_domain(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<super::manage::NewDomain>) -> HttpResponse {
    let user = match require_auth(&req, &state) { Ok(u) => u, Err(e) => return e };
    let c = match load(&path.into_inner()) { Ok(c) => c, Err(e) => return e };
    let d = body.into_inner();
    tracing::info!("stalwart: {} adds domain '{}' to mail cluster '{}'", user, d.name, c.id);
    let rt = tokio::runtime::Handle::current();
    blocking(move || super::manage::create_domain(&c, &rt, &d)).await
}

async fn delete_domain(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    let user = match require_auth(&req, &state) { Ok(u) => u, Err(e) => return e };
    let (id, did) = path.into_inner();
    let c = match load(&id) { Ok(c) => c, Err(e) => return e };
    tracing::warn!("stalwart: {} deletes domain {} from mail cluster '{}'", user, did, c.id);
    let rt = tokio::runtime::Handle::current();
    blocking(move || super::manage::delete_domain(&c, &rt, &did).map(|_| json!({ "ok": true }))).await
}

async fn domain_dns(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let (id, did) = path.into_inner();
    let c = match load(&id) { Ok(c) => c, Err(e) => return e };
    let rt = tokio::runtime::Handle::current();
    blocking(move || super::manage::domain_dns(&c, &rt, &did)).await
}

async fn accounts(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    if let Err(e) = require_auth(&req, &state) { return e; }
    let (id, did) = path.into_inner();
    let c = match load(&id) { Ok(c) => c, Err(e) => return e };
    let rt = tokio::runtime::Handle::current();
    blocking(move || super::manage::list_accounts(&c, &rt, &did)).await
}

async fn create_account(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>, body: web::Json<super::manage::NewAccount>) -> HttpResponse {
    let user = match require_auth(&req, &state) { Ok(u) => u, Err(e) => return e };
    let c = match load(&path.into_inner()) { Ok(c) => c, Err(e) => return e };
    let n = body.into_inner();
    if n.admin && !crate::api::caller_is_admin(&req, &user) {
        return HttpResponse::Forbidden().json(json!({ "error": "Only WolfStack administrators can create Stalwart administrator accounts." }));
    }
    tracing::info!("stalwart: {} creates mailbox '{}' (admin: {}) in mail cluster '{}'", user, n.name, n.admin, c.id);
    let rt = tokio::runtime::Handle::current();
    blocking(move || super::manage::create_account(&c, &rt, &n)).await
}

/// One account action, chosen by the last path segment.
#[derive(Deserialize, Default)]
struct AccountAction {
    #[serde(default)]
    password: String,
    #[serde(default)]
    suspended: bool,
    #[serde(default)]
    quota_bytes: u64,
    #[serde(default)]
    aliases: Vec<AliasIn>,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize, Default)]
struct AliasIn {
    name: String,
    domain_id: String,
}

async fn account_action(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String, String)>, body: web::Json<AccountAction>) -> HttpResponse {
    let user = match require_auth(&req, &state) { Ok(u) => u, Err(e) => return e };
    let (id, aid, action) = path.into_inner();
    let c = match load(&id) { Ok(c) => c, Err(e) => return e };
    let b = body.into_inner();
    let rt = tokio::runtime::Handle::current();
    tracing::info!("stalwart: {} runs '{}' on account {} in mail cluster '{}'", user, action, aid, c.id);
    match action.as_str() {
        "password" => blocking(move || super::manage::set_password(&c, &rt, &aid, &b.password).map(|_| json!({ "ok": true }))).await,
        "reset-two-factor" => blocking(move || super::manage::reset_two_factor(&c, &rt, &aid).map(|_| json!({ "ok": true }))).await,
        "suspend" => blocking(move || super::manage::set_suspended(&c, &rt, &aid, b.suspended).map(|_| json!({ "ok": true }))).await,
        "quota" => blocking(move || super::manage::set_quota(&c, &rt, &aid, b.quota_bytes).map(|_| json!({ "ok": true }))).await,
        "aliases" => {
            let list: Vec<(String, String)> = b.aliases.into_iter().map(|a| (a.name, a.domain_id)).collect();
            blocking(move || super::manage::set_aliases(&c, &rt, &aid, &list).map(|_| json!({ "ok": true }))).await
        }
        "app-password" => blocking(move || super::manage::create_app_password(&c, &rt, &aid, &b.description).map(|s| json!({ "secret": s }))).await,
        _ => bad(format!("unknown account action '{}'", action)),
    }
}

async fn delete_account(req: HttpRequest, state: web::Data<AppState>, path: web::Path<(String, String)>) -> HttpResponse {
    let user = match require_auth(&req, &state) { Ok(u) => u, Err(e) => return e };
    let (id, aid) = path.into_inner();
    let c = match load(&id) { Ok(c) => c, Err(e) => return e };
    tracing::warn!("stalwart: {} deletes account {} from mail cluster '{}'", user, aid, c.id);
    let rt = tokio::runtime::Handle::current();
    blocking(move || super::manage::delete_account(&c, &rt, &aid).map(|_| json!({ "ok": true }))).await
}

// ── Node-local routes (peers only) ───────────────────────────────────

#[derive(Deserialize)]
struct ClusterIdQuery {
    #[serde(default)]
    cluster_id: String,
}

async fn local_preflight(req: HttpRequest, state: web::Data<AppState>, q: web::Query<ClusterIdQuery>) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }
    let id = if super::valid_cluster_id(&q.cluster_id) { q.cluster_id.clone() } else { "new".to_string() };
    blocking(move || Ok(super::preflight::run_local(&id))).await
}

async fn local_keep(req: HttpRequest, state: web::Data<AppState>, body: web::Json<super::deploy::KeepDeploy>) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }
    let d = body.into_inner();
    blocking(move || super::deploy::deploy_keep(&d).map(|_| json!({ "ok": true }))).await
}

async fn local_keep_settled(req: HttpRequest, state: web::Data<AppState>, q: web::Query<ClusterIdQuery>) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }
    if !super::valid_cluster_id(&q.cluster_id) { return bad("invalid cluster id"); }
    let id = q.cluster_id.clone();
    blocking(move || Ok(json!({ "settled": super::deploy::keep_settled(&id) }))).await
}

async fn local_valkey(req: HttpRequest, state: web::Data<AppState>, body: web::Json<super::deploy::ValkeyDeploy>) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }
    let d = body.into_inner();
    blocking(move || super::deploy::deploy_valkey(&d).map(|_| json!({ "ok": true }))).await
}

#[derive(Deserialize)]
struct QuorumReq {
    cluster_id: String,
    wolfnet_ip: String,
    sentinel_password: String,
}

async fn local_sentinel_quorum(req: HttpRequest, state: web::Data<AppState>, body: web::Json<QuorumReq>) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }
    let b = body.into_inner();
    if !super::valid_cluster_id(&b.cluster_id) { return bad("invalid cluster id"); }
    blocking(move || Ok(match super::deploy::sentinel_ckquorum(&b.cluster_id, &b.wolfnet_ip, &b.sentinel_password) {
        Ok(m) => json!({ "ok": true, "detail": m }),
        Err(e) => json!({ "ok": false, "detail": e }),
    })).await
}

async fn local_stalwart(req: HttpRequest, state: web::Data<AppState>, body: web::Json<super::deploy::StalwartDeploy>) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }
    let d = body.into_inner();
    let rt = tokio::runtime::Handle::current();
    blocking(move || super::deploy::deploy_stalwart(&d, &rt)
        .and_then(|r| serde_json::to_value(r.unwrap_or_default()).map_err(|e| e.to_string()))).await
}

#[derive(Deserialize)]
struct RestartReq {
    cluster_id: String,
    wolfnet_ip: String,
}

async fn local_restart(req: HttpRequest, state: web::Data<AppState>, body: web::Json<RestartReq>) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }
    let b = body.into_inner();
    if !super::valid_cluster_id(&b.cluster_id) { return bad("invalid cluster id"); }
    let rt = tokio::runtime::Handle::current();
    blocking(move || super::deploy::restart_stalwart(&b.cluster_id, &b.wolfnet_ip, &rt).map(|_| json!({ "ok": true }))).await
}

#[derive(Deserialize)]
struct ReachReq {
    targets: Vec<String>,
}

/// POST /api/stalwart/local/reach — TCP reachability from THIS node to the
/// given WolfNet `ip:port`s (the other chosen servers' WolfStack ports).
async fn local_reach(req: HttpRequest, state: web::Data<AppState>, body: web::Json<ReachReq>) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }
    let targets = body.into_inner().targets;
    if targets.len() > 64 { return bad("too many targets"); }
    blocking(move || Ok(super::preflight::reach(&targets).into_iter()
        .map(|(t, r)| json!({ "target": t, "ok": r.is_ok(), "error": r.err().unwrap_or_default() }))
        .collect::<Vec<_>>())).await
}

#[derive(Deserialize)]
struct LocalRemoveReq {
    cluster_id: String,
}

async fn local_remove(req: HttpRequest, state: web::Data<AppState>, body: web::Json<LocalRemoveReq>) -> HttpResponse {
    if let Err(e) = require_cluster_auth(&req, &state) { return e; }
    let id = body.into_inner().cluster_id;
    blocking(move || super::deploy::remove_local(&id).map(|_| json!({ "ok": true }))).await
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        .route("/api/stalwart/clusters", web::get().to(list))
        .route("/api/stalwart/preflight", web::post().to(preflight))
        .route("/api/stalwart/install", web::post().to(install))
        .route("/api/stalwart/clusters/{id}/remove", web::post().to(remove))
        .route("/api/stalwart/clusters/{id}/retry", web::post().to(retry))
        .route("/api/stalwart/clusters/{id}/health", web::get().to(health))
        .route("/api/stalwart/clusters/{id}/admin-password", web::get().to(admin_password))
        .route("/api/stalwart/clusters/{id}/domains", web::get().to(domains))
        .route("/api/stalwart/clusters/{id}/domains", web::post().to(create_domain))
        .route("/api/stalwart/clusters/{id}/domains/{did}", web::delete().to(delete_domain))
        .route("/api/stalwart/clusters/{id}/domains/{did}/dns", web::get().to(domain_dns))
        .route("/api/stalwart/clusters/{id}/domains/{did}/accounts", web::get().to(accounts))
        .route("/api/stalwart/clusters/{id}/accounts", web::post().to(create_account))
        .route("/api/stalwart/clusters/{id}/accounts/{aid}", web::delete().to(delete_account))
        .route("/api/stalwart/clusters/{id}/accounts/{aid}/{action}", web::post().to(account_action))
        .route("/api/stalwart/local/preflight", web::get().to(local_preflight))
        .route("/api/stalwart/local/keep", web::post().to(local_keep))
        .route("/api/stalwart/local/keep-settled", web::get().to(local_keep_settled))
        .route("/api/stalwart/local/valkey", web::post().to(local_valkey))
        .route("/api/stalwart/local/sentinel-quorum", web::post().to(local_sentinel_quorum))
        .route("/api/stalwart/local/stalwart", web::post().to(local_stalwart))
        .route("/api/stalwart/local/restart", web::post().to(local_restart))
        .route("/api/stalwart/local/remove", web::post().to(local_remove))
        .route("/api/stalwart/local/reach", web::post().to(local_reach));
}

#[cfg(test)]
mod tests {
    use actix_web::test::TestRequest;

    #[test]
    fn proxied_admin_role_is_only_trusted_on_a_proxied_cluster_call() {
        use crate::api::{caller_is_admin, PROXIED_ACTOR_ROLE_HEADER};
        // A forwarded operator call from an admin session.
        let proxied = TestRequest::default()
            .insert_header(("X-WolfStack-Proxied", "1"))
            .insert_header((PROXIED_ACTOR_ROLE_HEADER, "admin"))
            .to_http_request();
        assert!(caller_is_admin(&proxied, "cluster-node"));
        // Same header without the proxied stamp: a plain peer sync — refused.
        let not_proxied = TestRequest::default()
            .insert_header((PROXIED_ACTOR_ROLE_HEADER, "admin"))
            .to_http_request();
        assert!(!caller_is_admin(&not_proxied, "cluster-node"));
        // A read-only operator forwarded through the proxy — refused.
        let viewer = TestRequest::default()
            .insert_header(("X-WolfStack-Proxied", "1"))
            .insert_header((PROXIED_ACTOR_ROLE_HEADER, "read-only"))
            .to_http_request();
        assert!(!caller_is_admin(&viewer, "cluster-node"));
        // A browser session can't claim admin with the header: a session
        // user is judged by the user store, never by the header.
        let forged = TestRequest::default()
            .insert_header(("X-WolfStack-Proxied", "1"))
            .insert_header((PROXIED_ACTOR_ROLE_HEADER, "admin"))
            .to_http_request();
        assert!(!caller_is_admin(&forged, "no-such-user-xyz"));
    }
}
