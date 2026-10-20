// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! HTTP surface of the MCP server: the `/mcp` endpoint, the OAuth 2.1
//! authorization server (metadata, consent, token, registration,
//! revocation) and the admin settings API.
//!
//! Every handler first checks that MCP is enabled (404 otherwise) and that
//! the request arrived over TLS or from loopback — see `mcp` module docs.

use actix_web::http::header;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::AppState;

use super::oauth::{self, PendingAuth, TokenError};
use super::protocol::{self, RequestHeaders, Step};
use super::{config, user_authority, Principal, PrincipalKind, OAUTH};

const MAX_MCP_BODY: usize = 64 * 1024;
const MAX_FORM_BODY: usize = 16 * 1024;
/// Upper bound on one tool call (a graceful VM shutdown can be slow).
const TOOL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/mcp")
            .app_data(web::PayloadConfig::new(MAX_MCP_BODY))
            .route(web::post().to(mcp_post))
            .route(web::get().to(mcp_method_not_allowed))
            .route(web::delete().to(mcp_method_not_allowed)),
    )
    .route("/.well-known/oauth-protected-resource", web::get().to(protected_resource_metadata))
    .route("/.well-known/oauth-protected-resource/mcp", web::get().to(protected_resource_metadata))
    .route("/.well-known/oauth-authorization-server", web::get().to(authorization_server_metadata))
    .service(
        web::resource("/oauth/authorize")
            .app_data(web::FormConfig::default().limit(MAX_FORM_BODY))
            .route(web::get().to(authorize_get))
            .route(web::post().to(authorize_post)),
    )
    .service(
        web::resource("/oauth/token")
            .app_data(web::FormConfig::default().limit(MAX_FORM_BODY))
            .route(web::post().to(token)),
    )
    .service(
        web::resource("/oauth/register")
            .app_data(web::PayloadConfig::new(MAX_FORM_BODY))
            .route(web::post().to(register)),
    )
    .service(
        web::resource("/oauth/revoke")
            .app_data(web::FormConfig::default().limit(MAX_FORM_BODY))
            .route(web::post().to(revoke)),
    )
    .route("/api/mcp/settings", web::get().to(admin_get_settings))
    .route("/api/mcp/settings", web::post().to(admin_save_settings))
    .route("/api/mcp/test", web::post().to(admin_test_connection))
    .route("/api/mcp/grants", web::get().to(admin_list_grants))
    .route("/api/mcp/grants/{id}", web::delete().to(admin_revoke_grant))
    .route("/api/mcp/clients", web::get().to(admin_list_clients))
    .route("/api/mcp/clients/{id}", web::delete().to(admin_delete_client));
}

// ─── Shared checks ───

/// The client's address. The transport peer — except when the peer is
/// loopback (the supported same-host TLS reverse proxy), where the proxy's
/// own `X-Forwarded-For` entry (the rightmost one; proxies append) names
/// the real client. Without that every client shares 127.0.0.1 and one
/// attacker's failures would rate-limit and lock out everyone. A header
/// from any non-loopback peer is ignored: anyone can set it.
fn client_addr(req: &HttpRequest) -> Option<std::net::IpAddr> {
    let peer = req.peer_addr()?.ip().to_canonical();
    if peer.is_loopback()
        && let Some(fwd) = req.headers().get("X-Forwarded-For").and_then(|v| v.to_str().ok())
        && let Some(ip) = fwd.rsplit(',').next().and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
    {
        return Some(ip.to_canonical());
    }
    Some(peer)
}

/// Display form of the client address, for logs and the login lockout.
fn client_ip(req: &HttpRequest) -> String {
    client_addr(req).map(|a| a.to_string()).unwrap_or_else(|| "unknown".to_string())
}

/// Rate-limit bucket for the client (IPv6 grouped by /64).
fn rate_key(req: &HttpRequest) -> String {
    client_addr(req).map(super::limiter_key).unwrap_or_else(|| "unknown".to_string())
}

/// Attacker-supplied text bound for a log line: no control characters
/// (no forged log lines), bounded length.
fn clean(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).take(128).collect()
}

fn peer_is_loopback(req: &HttpRequest) -> bool {
    req.peer_addr().is_some_and(|a| a.ip().to_canonical().is_loopback())
}

/// TLS listener, or a loopback peer (a reverse proxy on this host that
/// terminates TLS). `AppConfig::secure` reflects how the listener was
/// bound; X-Forwarded-Proto is attacker-controlled and ignored.
fn transport_ok(req: &HttpRequest) -> bool {
    req.app_config().secure() || peer_is_loopback(req)
}

fn not_found() -> HttpResponse {
    HttpResponse::NotFound().finish()
}

fn insecure_transport() -> HttpResponse {
    HttpResponse::Forbidden().json(json!({
        "error": "insecure_transport",
        "error_description": "MCP is only served over HTTPS. Connect to this node's TLS port (or through a TLS reverse proxy on the same host).",
    }))
}

/// Requests from a browser page carry Origin; it must be this server's
/// own origin (DNS-rebinding protection, Streamable HTTP §Security).
fn origin_ok(req: &HttpRequest, issuer: &str) -> bool {
    match req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        None => true,
        Some(o) => o.eq_ignore_ascii_case(issuer),
    }
}

fn no_store(mut b: actix_web::HttpResponseBuilder) -> actix_web::HttpResponseBuilder {
    b.insert_header((header::CACHE_CONTROL, "no-store"));
    b.insert_header((header::PRAGMA, "no-cache"));
    b
}

/// Record an MCP event in the journal and the API audit log (Settings →
/// API Keys → Audit Log). The audit file write runs on the blocking pool.
fn audit(principal_label: &str, key_id: &str, ip: &str, what: &str, status: u16) {
    let (label, what) = (clean(principal_label), clean(what));
    tracing::info!("mcp audit: {} from {} — {} → {}", label, ip, what, status);
    let entry = crate::compat::AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        key_name: format!("mcp:{}", label),
        key_id: key_id.to_string(),
        method: "MCP".to_string(),
        path: what,
        ip: ip.to_string(),
        status,
    };
    tokio::task::spawn_blocking(move || crate::compat::audit_log(&entry));
}

// ─── /mcp ───

fn resource_metadata_url(issuer: &str) -> String {
    format!("{}/.well-known/oauth-protected-resource/mcp", issuer)
}

fn unauthorized(issuer: &str, error: Option<(&str, &str)>) -> HttpResponse {
    let mut challenge = format!("Bearer resource_metadata=\"{}\", scope=\"read\"", resource_metadata_url(issuer));
    if let Some((code, desc)) = error {
        challenge.push_str(&format!(", error=\"{}\", error_description=\"{}\"", code, desc.replace('"', "'")));
    }
    HttpResponse::Unauthorized()
        .insert_header((header::WWW_AUTHENTICATE, challenge))
        .json(json!({
            "error": error.map(|e| e.0).unwrap_or("unauthorized"),
            "error_description": error.map(|e| e.1).unwrap_or("Authorization required"),
        }))
}

fn bearer(req: &HttpRequest) -> Option<String> {
    let v = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim().to_string()).filter(|t| !t.is_empty())
}

/// Resolve the bearer token to a caller with effective scopes. Reads the
/// user store, auth config, /etc/shadow and the API-key file — blocking
/// work, so `mcp_post` runs it on the blocking pool.
fn authenticate(token: &str, ip: &str, cluster: &crate::agent::ClusterState, cfg: &super::McpConfig, resource: &str)
    -> Result<Principal, (&'static str, String)>
{
    if token.is_empty() {
        return Err(("", String::new()));
    }
    if token.starts_with("wsk_") {
        if !cfg.allow_api_keys {
            return Err(("invalid_token", "API keys are not enabled for MCP on this node — use OAuth".into()));
        }
        if !crate::compat::platform_ready() {
            return Err(("invalid_token", "API keys need a licensed WolfStack".into()));
        }
        let Some(key) = crate::compat::validate_key(token, Some(ip)) else {
            return Err(("invalid_token", "invalid or expired API key".into()));
        };
        // Only keys made FOR agents: the explicit `mcp` scope, and only the
        // explicitly listed tool scopes. `*` deliberately counts for
        // neither — enabling API keys for MCP must not turn every existing
        // full-access script key into an agent key.
        let has = |s: &str| key.scopes.iter().any(|k| k == s);
        if !has("mcp") {
            return Err(("invalid_token", "this API key does not have the 'mcp' scope".into()));
        }
        let scopes: Vec<String> = oauth::ALL_SCOPES.iter()
            .filter(|s| has(s))
            .map(|s| s.to_string())
            .collect();
        return Ok(Principal { kind: PrincipalKind::ApiKey { name: key.name, id: key.id }, scopes });
    }
    let Some(info) = OAUTH.validate_access(token, resource) else {
        return Err(("invalid_token", "the access token is invalid, expired or for another server".into()));
    };
    let self_cluster = super::self_cluster_name(cluster);
    let Some(authority) = user_authority(&info.username, info.source, self_cluster.as_deref()) else {
        return Err(("invalid_token", "this account may no longer use MCP on this node".into()));
    };
    if authority.credential_fp != info.credential_fp {
        // Password or 2FA changed since approval (possibly on another
        // node — users replicate). End the grant here too.
        let _ = OAUTH.revoke_grant(&info.grant_id);
        return Err(("invalid_token", "the account's password or two-factor setup changed — authorize again".into()));
    }
    let scopes: Vec<String> = info.scopes.iter()
        .filter(|s| authority.allowed_scopes.contains(s))
        .cloned()
        .collect();
    let client_name = OAUTH.get_client(&info.client_id).map(|c| c.client_name).unwrap_or_default();
    Ok(Principal {
        kind: PrincipalKind::User { username: info.username, client_id: info.client_id, client_name },
        scopes,
    })
}

fn header_str(req: &HttpRequest, name: &str) -> Option<String> {
    req.headers().get(name).and_then(|v| v.to_str().ok()).map(|s| s.to_string())
}

async fn mcp_method_not_allowed(req: HttpRequest) -> HttpResponse {
    let cfg = config();
    if cfg.issuer().is_none() { return not_found(); }
    if !transport_ok(&req) { return insecure_transport(); }
    // No standalone SSE stream and no sessions to DELETE.
    HttpResponse::MethodNotAllowed().insert_header((header::ALLOW, "POST")).finish()
}

async fn mcp_post(req: HttpRequest, state: web::Data<AppState>, body: web::Bytes) -> HttpResponse {
    let cfg = config();
    let (Some(issuer), Some(resource)) = (cfg.issuer(), cfg.resource()) else { return not_found() };
    if !transport_ok(&req) { return insecure_transport(); }
    if !origin_ok(&req, &issuer) {
        return HttpResponse::Forbidden().json(protocol::rpc_error(None, protocol::INVALID_REQUEST, "Origin not allowed", None));
    }
    let ip = client_ip(&req);
    let rk = rate_key(&req);
    // Over its failure budget, an IP gets no answer at all — not even for
    // a valid token — so the limit can't be used as an oracle.
    if super::AUTH_FAIL_LIMIT.exhausted(&rk) {
        audit("unauthenticated", "", &ip, "refused: too many failed authentications", 429);
        return HttpResponse::TooManyRequests().insert_header((header::RETRY_AFTER, "60")).finish();
    }
    let token = bearer(&req).unwrap_or_default();
    let auth = {
        let (ip, cluster, cfg, resource) = (ip.clone(), state.cluster.clone(), cfg.clone(), resource.clone());
        web::block(move || authenticate(&token, &ip, &cluster, &cfg, &resource)).await
            .unwrap_or_else(|e| Err(("server_error", format!("authentication task failed: {}", e))))
    };
    let principal = match auth {
        Ok(p) => p,
        Err((code, desc)) => {
            super::AUTH_FAIL_LIMIT.allow(&rk);
            if !code.is_empty() {
                audit("unauthenticated", "", &ip, &format!("refused: {}", desc), 401);
            }
            return unauthorized(&issuer, (!code.is_empty()).then_some((code, desc.as_str())));
        }
    };
    if !super::REQUEST_LIMIT.allow(&principal.rate_key()) {
        audit(&principal.label(), "", &ip, "refused: request rate limit", 429);
        return HttpResponse::TooManyRequests().insert_header((header::RETRY_AFTER, "60")).finish();
    }
    if body.len() > MAX_MCP_BODY {
        return HttpResponse::PayloadTooLarge().finish();
    }
    let headers = RequestHeaders {
        protocol_version: header_str(&req, "MCP-Protocol-Version"),
        mcp_method: header_str(&req, "Mcp-Method"),
        mcp_name: header_str(&req, "Mcp-Name"),
    };
    match protocol::handle(&body, &headers, &principal.scopes) {
        Step::Reply { status, body } => {
            let code = actix_web::http::StatusCode::from_u16(status).unwrap_or(actix_web::http::StatusCode::OK);
            HttpResponse::build(code).json(body)
        }
        Step::Accepted => HttpResponse::Accepted().finish(),
        Step::InsufficientScope { scope } => {
            audit(&principal.label(), "", &ip, &format!("denied: needs scope '{}'", scope), 403);
            HttpResponse::Forbidden()
                .insert_header((header::WWW_AUTHENTICATE, format!(
                    "Bearer error=\"insufficient_scope\", scope=\"{}\", resource_metadata=\"{}\", error_description=\"This tool needs the '{}' permission\"",
                    scope, resource_metadata_url(&issuer), scope)))
                .json(json!({ "error": "insufficient_scope", "scope": scope }))
        }
        Step::CallTool { id, era, tool, arguments } => {
            let what = describe_call(tool, &arguments);
            let key_id = match &principal.kind {
                PrincipalKind::ApiKey { id, .. } => id.clone(),
                PrincipalKind::User { client_id, .. } => client_id.clone(),
            };
            if !tool.read_only && !super::ACTION_LIMIT.allow(&principal.rate_key()) {
                audit(&principal.label(), &key_id, &ip, &format!("refused (action rate limit): {}", what), 429);
                return HttpResponse::TooManyRequests().insert_header((header::RETRY_AFTER, "60")).finish();
            }
            // Record an action BEFORE it runs: if the client hangs up, the
            // handler is cancelled but the blocking work still completes,
            // and the attempt must not go unlogged.
            if !tool.read_only {
                audit(&principal.label(), &key_id, &ip, &format!("starting: {}", what), 102);
            }
            let result = match tokio::time::timeout(TOOL_TIMEOUT, super::tools::run(&state, &principal, tool, &arguments)).await {
                Ok(r) => r,
                Err(_) => Err(format!("{} is still running after {}s — check its state before retrying", tool.name, TOOL_TIMEOUT.as_secs())),
            };
            let status = if result.is_ok() { 200 } else { 500 };
            // Reads are logged too, so an operator can see exactly what an
            // agent looked at.
            audit(&principal.label(), &key_id, &ip, &what, status);
            HttpResponse::Ok().json(protocol::tool_result(&id, &era, result))
        }
    }
}

/// Audit line for a call: the tool plus, for actions, exactly what it
/// targeted. Free-form arguments are never logged verbatim.
fn describe_call(tool: &super::tools::ToolDef, args: &Value) -> String {
    let field = |k: &str| args.get(k).and_then(|v| v.as_str()).unwrap_or("").chars().take(128).collect::<String>();
    match tool.name {
        "container_action" => format!("tools/call container_action {} {} {}", field("action"), field("runtime"), field("name")),
        "vm_action" => format!("tools/call vm_action {} {}", field("action"), field("name")),
        "run_backup_schedule" => format!("tools/call run_backup_schedule {}", field("schedule_id")),
        "get_container_logs" => format!("tools/call get_container_logs {} {}", field("runtime"), field("name")),
        other => format!("tools/call {}", other),
    }
}

// ─── Metadata ───

async fn protected_resource_metadata(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let cfg = config();
    let (Some(issuer), Some(resource)) = (cfg.issuer(), cfg.resource()) else { return not_found() };
    if !transport_ok(&req) { return insecure_transport(); }
    let host = crate::mcp::self_hostname(&state.cluster);
    HttpResponse::Ok().json(json!({
        "resource": resource,
        "authorization_servers": [issuer],
        "scopes_supported": ["read"],
        "bearer_methods_supported": ["header"],
        "resource_name": format!("WolfStack ({})", host),
    }))
}

async fn authorization_server_metadata(req: HttpRequest) -> HttpResponse {
    let cfg = config();
    let Some(issuer) = cfg.issuer() else { return not_found() };
    if !transport_ok(&req) { return insecure_transport(); }
    HttpResponse::Ok().json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/oauth/authorize", issuer),
        "token_endpoint": format!("{}/oauth/token", issuer),
        "registration_endpoint": format!("{}/oauth/register", issuer),
        "revocation_endpoint": format!("{}/oauth/revoke", issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": oauth::ALL_SCOPES,
        "authorization_response_iss_parameter_supported": true,
        "client_id_metadata_document_supported": false,
    }))
}

// ─── Consent ───

#[derive(Deserialize)]
struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    resource: Option<String>,
}

fn esc(s: &str) -> String {
    s.chars().map(|c| match c {
        '&' => "&amp;".to_string(),
        '<' => "&lt;".to_string(),
        '>' => "&gt;".to_string(),
        '"' => "&quot;".to_string(),
        '\'' => "&#39;".to_string(),
        c => c.to_string(),
    }).collect()
}

/// Strict headers for the consent page: no scripts at all, not frameable
/// (clickjacking), forms may only post back here or follow the redirect
/// to the client (Chrome applies form-action to the post-submit redirect).
fn html_page(status: actix_web::http::StatusCode, form_redirect_origin: Option<&str>, body: String) -> HttpResponse {
    let form_action = match form_redirect_origin {
        Some(o) => format!("'self' {}", o),
        None => "'self'".to_string(),
    };
    no_store(HttpResponse::build(status))
        .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
        .insert_header(("Content-Security-Policy", format!(
            "default-src 'none'; style-src 'unsafe-inline'; form-action {}; frame-ancestors 'none'; base-uri 'none'",
            form_action)))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(body)
}

const PAGE_STYLE: &str = "body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#0f1115;color:#e6e8ec;margin:0;padding:24px 16px}\
main{max-width:520px;margin:0 auto;background:#171a21;border:1px solid #2a2f3a;border-radius:12px;padding:24px}\
h1{font-size:20px;margin:0 0 16px}p{line-height:1.5;margin:0 0 12px}\
.warn{background:#3a2a0b;border:1px solid #b7791f;color:#fde7b0;border-radius:8px;padding:10px 12px}\
.err{background:#3b1219;border:1px solid #e5484d;color:#ffd1d4;border-radius:8px;padding:10px 12px}\
.muted{color:#a8afbd;font-size:14px}code{background:#0f1115;padding:2px 6px;border-radius:4px;word-break:break-all}\
fieldset{border:1px solid #2a2f3a;border-radius:8px;margin:0 0 16px;padding:12px}legend{padding:0 6px}\
label{display:block;margin:8px 0}input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:10px;border-radius:6px;border:1px solid #3a4150;background:#0f1115;color:#e6e8ec;font-size:16px}\
.row{display:flex;gap:12px;margin-top:16px}button{flex:1;padding:12px;border-radius:8px;border:0;font-size:16px;cursor:pointer}\
.approve{background:#2563eb;color:#fff}.deny{background:#2a2f3a;color:#e6e8ec}\
@media (prefers-color-scheme: light){body{background:#f4f5f7;color:#16181d}main{background:#fff;border-color:#d8dce3}\
code,input[type=text],input[type=password]{background:#f4f5f7;color:#16181d;border-color:#c5cad3}.muted{color:#4b5263}\
.warn{background:#fff4d6;color:#5c3d00}.err{background:#ffe4e6;color:#7a0d19}.deny{background:#e4e7ec;color:#16181d}}";

fn error_page(title: &str, message: &str) -> HttpResponse {
    html_page(actix_web::http::StatusCode::BAD_REQUEST, None, format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>WolfStack — {t}</title><style>{s}</style></head><body><main><h1>{t}</h1>\
<p class=\"err\" role=\"alert\">{m}</p><p class=\"muted\">You can close this window and start again from your app.</p></main></body></html>",
        t = esc(title), m = esc(message), s = PAGE_STYLE))
}

fn scope_label(s: &str) -> &'static str {
    match s {
        "read" => "Read this node's status, containers, VMs, backups, storage and Inbox findings",
        "logs" => "Read container logs — these can contain passwords and other secrets, and are sent to the app's AI",
        "containers" => "Start, stop and restart containers",
        "vms" => "Start, shut down and restart virtual machines",
        "backup" => "Run backup schedules now",
        _ => "Unknown permission",
    }
}

/// Redirect the user agent back to the client with OAuth parameters
/// (and `iss`, RFC 9207 mix-up protection).
fn redirect_to_client(redirect_uri: &str, params: &[(&str, &str)], issuer: &str) -> HttpResponse {
    let Ok(mut url) = url::Url::parse(redirect_uri) else {
        return error_page("Authorization failed", "The app's redirect address is invalid.");
    };
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in params {
            q.append_pair(k, v);
        }
        q.append_pair("iss", issuer);
    }
    no_store(HttpResponse::SeeOther()).insert_header((header::LOCATION, url.to_string())).finish()
}

fn redirect_origin(redirect_uri: &str) -> Option<String> {
    url::Url::parse(redirect_uri).ok().map(|u| u.origin().ascii_serialization())
}

fn login_disabled(state: &web::Data<AppState>) -> bool {
    let nodes = state.cluster.nodes_read();
    nodes.get(&state.cluster.self_id).is_some_and(|n| n.login_disabled)
}

struct ConsentView<'a> {
    pending_id: &'a str,
    pending: &'a PendingAuth,
    issuer: &'a str,
    hostname: &'a str,
    error: Option<&'a str>,
    /// Previously typed username, to refill after a failed attempt.
    username: &'a str,
}

/// The consent page. Always asks for the password (and 2FA code): a
/// browser session is never enough, because a session's username can come
/// from an SSO provider and must not be matched against local accounts.
/// Only `read` is pre-ticked — the app chose what to ask for; the user
/// opts in to anything more.
fn render_consent(v: &ConsentView) -> HttpResponse {
    let p = v.pending;
    let redirect_host = url::Url::parse(&p.redirect_uri).ok()
        .and_then(|u| u.host_str().map(|h| h.to_string())).unwrap_or_default();
    let local = oauth::is_loopback_host(&redirect_host);
    let mut html = String::new();
    html.push_str(&format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>WolfStack — Authorize app</title><style>{}</style></head><body><main>\
<h1>Allow an app to use WolfStack?</h1>", PAGE_STYLE));
    if let Some(e) = v.error {
        html.push_str(&format!("<p class=\"err\" role=\"alert\">{}</p>", esc(e)));
    }
    html.push_str(&format!(
        "<p>An app calling itself <strong>{name}</strong> <span class=\"muted\">(name not verified)</span> wants access to \
WolfStack on <strong>{host}</strong> (<code>{issuer}</code>).</p>\
<p>If you approve, access is sent to <code>{ruri}</code>.</p>",
        name = esc(&p.client_name), host = esc(v.hostname), issuer = esc(v.issuer), ruri = esc(&p.redirect_uri)));
    if local {
        html.push_str("<p class=\"warn\">That is an app on your own computer. Only approve if you started this from an AI app \
you trust in the last few minutes. If you did not, press Deny.</p>");
    } else {
        html.push_str(&format!("<p class=\"warn\">That is a website, <strong>{}</strong>. Only approve if you know and trust \
that site and started this from it just now. If not, press Deny.</p>", esc(&redirect_host)));
    }
    html.push_str(&format!("<form method=\"post\" action=\"/oauth/authorize\" autocomplete=\"off\">\
<input type=\"hidden\" name=\"pending_id\" value=\"{}\"><fieldset><legend>Permissions — tick only what you want to allow</legend>", esc(v.pending_id)));
    for s in &p.scopes {
        let checked = if s == "read" { " checked" } else { "" };
        html.push_str(&format!(
            "<label><input type=\"checkbox\" name=\"scope_{s}\" value=\"1\"{checked}> {label}</label>",
            s = esc(s), checked = checked, label = esc(scope_label(s))));
    }
    html.push_str("<p class=\"muted\">Read-only accounts can only grant the read permissions. The app can never run commands, \
open shells, read files or delete anything.</p></fieldset>");
    html.push_str(&format!(
        "<fieldset><legend>Confirm it is you</legend>\
<label for=\"u\">Username</label><input id=\"u\" type=\"text\" name=\"username\" value=\"{}\" required autocapitalize=\"none\">\
<label for=\"pw\">Password</label><input id=\"pw\" type=\"password\" name=\"password\" required>\
<label for=\"totp\">Two-factor code <span class=\"muted\">(if your account uses 2FA)</span></label>\
<input id=\"totp\" type=\"text\" name=\"totp_code\" inputmode=\"numeric\" pattern=\"[0-9]*\" maxlength=\"8\">\
</fieldset>", esc(v.username)));
    html.push_str("<div class=\"row\"><button class=\"deny\" type=\"submit\" name=\"decision\" value=\"deny\">Deny</button>\
<button class=\"approve\" type=\"submit\" name=\"decision\" value=\"approve\">Approve</button></div>\
<p class=\"muted\" style=\"margin-top:16px\">You can revoke this access at any time in WolfStack → Settings → AI Agents (MCP).</p>\
</form></main></body></html>");
    let origin = redirect_origin(&p.redirect_uri);
    html_page(actix_web::http::StatusCode::OK, origin.as_deref(), html)
}

async fn authorize_get(req: HttpRequest, state: web::Data<AppState>, q: web::Query<AuthorizeQuery>) -> HttpResponse {
    let cfg = config();
    let (Some(issuer), Some(resource)) = (cfg.issuer(), cfg.resource()) else { return not_found() };
    if !transport_ok(&req) { return insecure_transport(); }
    // Each view holds a pending authorization for 10 minutes.
    if !super::AUTHORIZE_LIMIT.allow(&rate_key(&req)) {
        audit("unauthenticated", "", &client_ip(&req), "refused: consent page rate limit", 429);
        return error_page("Too many requests", "Too many authorization requests from your address. Wait a few minutes and try again.");
    }
    let q = q.into_inner();

    // Until the client and its redirect URI are verified, errors are shown
    // here and NEVER redirected (open-redirect protection).
    let Some(client) = q.client_id.as_deref().and_then(|id| OAUTH.get_client(id)) else {
        return error_page("Unknown app", "This app is not registered with this WolfStack node (or its registration expired).");
    };
    let Some(redirect_uri) = q.redirect_uri.clone().filter(|r| client.redirect_uris.iter().any(|x| x == r)) else {
        return error_page("Invalid redirect", "The app asked to return to an address it did not register.");
    };
    let state_param = q.state.clone();
    let fail = |code: &str, desc: &str| {
        let mut params = vec![("error", code), ("error_description", desc)];
        if let Some(s) = state_param.as_deref() { params.push(("state", s)); }
        redirect_to_client(&redirect_uri, &params, &issuer)
    };
    if q.response_type.as_deref() != Some("code") {
        return fail("unsupported_response_type", "only response_type=code is supported");
    }
    if q.code_challenge_method.as_deref() != Some("S256") {
        return fail("invalid_request", "PKCE with code_challenge_method=S256 is required");
    }
    let Some(code_challenge) = q.code_challenge.clone().filter(|c| oauth::valid_code_challenge(c)) else {
        return fail("invalid_request", "code_challenge is missing or malformed");
    };
    match q.resource.as_deref() {
        Some(r) if r == resource => {}
        _ => return fail("invalid_target", "resource must be this server's MCP endpoint"),
    }
    let scopes = match oauth::parse_scopes(q.scope.as_deref()) {
        Ok(s) => s,
        Err(e) => return fail("invalid_scope", &e),
    };
    if login_disabled(&state) {
        return fail("access_denied", "sign-in is disabled on this node");
    }
    let pending = PendingAuth {
        client_id: client.client_id.clone(),
        client_name: client.client_name.clone(),
        redirect_uri: redirect_uri.clone(),
        state: q.state.clone(),
        code_challenge,
        scopes,
        resource,
        created_at: oauth::now(),
        from: rate_key(&req),
    };
    let pending_id = match OAUTH.begin_pending(pending.clone()) {
        Ok(id) => id,
        Err(e) => return fail("temporarily_unavailable", &e),
    };
    let hostname = crate::mcp::self_hostname(&state.cluster);
    render_consent(&ConsentView {
        pending_id: &pending_id, pending: &pending, issuer: &issuer, hostname: &hostname,
        error: None, username: "",
    })
}

#[derive(Deserialize)]
struct ConsentForm {
    pending_id: String,
    decision: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    totp_code: String,
    #[serde(default)]
    scope_read: Option<String>,
    #[serde(default)]
    scope_logs: Option<String>,
    #[serde(default)]
    scope_containers: Option<String>,
    #[serde(default)]
    scope_vms: Option<String>,
    #[serde(default)]
    scope_backup: Option<String>,
}

/// Check credentials exactly as the dashboard login does (lockout, auth
/// mode, WolfStack users then Linux), except that a configured TOTP is
/// always required. Returns the username and WHICH store accepted it —
/// authority is later read from that store only.
async fn verify_credentials(state: &web::Data<AppState>, ip: &str, f: &ConsentForm) -> Result<(String, oauth::AuthSource), String> {
    if state.login_limiter.is_locked_out(ip) {
        state.login_limiter.audit_blocked(ip, &f.username);
        return Err("Access denied — this IP is blocked. Contact the operator.".into());
    }
    if f.username.is_empty() || f.password.is_empty() {
        return Err("Enter your username and password.".into());
    }
    let (username, password, totp) = (f.username.clone(), f.password.clone(), f.totp_code.trim().to_string());
    // Password hashing is CPU-bound — blocking pool.
    let outcome = web::block(move || -> Result<oauth::AuthSource, &'static str> {
        let mode = crate::auth::users::AuthConfig::load().auth_mode;
        if (mode == "wolfstack" || mode == "both")
            && let Some(user) = crate::auth::users::authenticate_wolfstack_user(&username, &password) {
                if user.totp_enabled {
                    if totp.is_empty() {
                        return Err("This account uses two-factor authentication — enter the code from your authenticator app.");
                    }
                    if !crate::auth::users::verify_totp(&user.totp_secret, &totp) {
                        return Err("Invalid username, password or code.");
                    }
                }
                return Ok(oauth::AuthSource::WolfStack);
            }
        if (mode == "linux" || mode == "both") && crate::auth::authenticate_user(&username, &password) {
            return Ok(oauth::AuthSource::Linux);
        }
        Err("Invalid username, password or code.")
    }).await.map_err(|e| format!("sign-in failed: {}", e))?;
    match outcome {
        Ok(source) => {
            state.login_limiter.clear_with(ip, &f.username);
            Ok((f.username.clone(), source))
        }
        Err(msg) => {
            state.login_limiter.record_failure_with(ip, &f.username);
            Err(msg.to_string())
        }
    }
}

async fn authorize_post(req: HttpRequest, state: web::Data<AppState>, form: web::Form<ConsentForm>) -> HttpResponse {
    let cfg = config();
    let Some(issuer) = cfg.issuer() else { return not_found() };
    if !transport_ok(&req) { return insecure_transport(); }
    if !origin_ok(&req, &issuer) {
        return error_page("Request refused", "This form must be submitted from this WolfStack page.");
    }
    let ip = client_ip(&req);
    if !super::CONSENT_LIMIT.allow(&rate_key(&req)) {
        audit("unauthenticated", "", &ip, "refused: consent rate limit", 429);
        return error_page("Too many attempts", "Too many authorization attempts from your address. Wait a few minutes and try again.");
    }
    let form = form.into_inner();
    let Some(pending) = OAUTH.peek_pending(&form.pending_id) else {
        return error_page("Request expired", "This authorization request has expired or was already used.");
    };
    let deny = |pending: &PendingAuth| {
        let mut params = vec![("error", "access_denied"), ("error_description", "the user denied the request")];
        if let Some(s) = pending.state.as_deref() { params.push(("state", s)); }
        redirect_to_client(&pending.redirect_uri, &params, &issuer)
    };
    if form.decision != "approve" {
        OAUTH.take_pending(&form.pending_id);
        tracing::info!("mcp oauth: access for client '{}' denied by user at {}", pending.client_name, ip);
        return deny(&pending);
    }
    if login_disabled(&state) {
        OAUTH.take_pending(&form.pending_id);
        return error_page("Sign-in disabled", "Direct sign-in is disabled on this server.");
    }
    let hostname = crate::mcp::self_hostname(&state.cluster);
    let rerender = |error: &str, username: &str| render_consent(&ConsentView {
        pending_id: &form.pending_id, pending: &pending, issuer: &issuer, hostname: &hostname,
        error: Some(error), username,
    });
    let (username, source) = match verify_credentials(&state, &ip, &form).await {
        Ok(v) => v,
        Err(e) => {
            audit(&format!("user '{}'", form.username), &pending.client_id, &ip,
                "refused: consent sign-in failed", 401);
            return rerender(&e, &form.username);
        }
    };
    let self_cluster = super::self_cluster_name(&state.cluster);
    let authority = {
        let u = username.clone();
        web::block(move || user_authority(&u, source, self_cluster.as_deref())).await.unwrap_or(None)
    };
    let Some(authority) = authority else {
        OAUTH.take_pending(&form.pending_id);
        return error_page("Not permitted", "This account may not authorize apps on this WolfStack node.");
    };
    let ticked = |s: &str| match s {
        "read" => form.scope_read.is_some(),
        "logs" => form.scope_logs.is_some(),
        "containers" => form.scope_containers.is_some(),
        "vms" => form.scope_vms.is_some(),
        "backup" => form.scope_backup.is_some(),
        _ => false,
    };
    let granted: Vec<String> = pending.scopes.iter()
        .filter(|s| ticked(s) && authority.allowed_scopes.contains(s))
        .cloned()
        .collect();
    if granted.is_empty() {
        return rerender("Select at least one permission your account is allowed to grant (viewer accounts can only grant read access).", &username);
    }
    // Single use: a double-submit finds nothing here.
    let Some(pending) = OAUTH.take_pending(&form.pending_id) else {
        return error_page("Request expired", "This authorization request has expired or was already used.");
    };
    let code = match web::block({
        let (p, u, g) = (pending.clone(), username.clone(), granted.clone());
        move || OAUTH.issue_code(&p, &u, source, g)
    }).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return error_page("Authorization failed", &e),
        Err(e) => return error_page("Authorization failed", &format!("internal error: {}", e)),
    };
    tracing::info!("mcp oauth: user '{}' granted [{}] to client '{}' ({}) from {}",
        username, granted.join(" "), pending.client_name, pending.client_id, ip);
    audit(&format!("user '{}' via '{}'", username, pending.client_name), &pending.client_id, &ip,
        &format!("oauth consent granted [{}]", granted.join(" ")), 200);
    let mut params = vec![("code", code.as_str())];
    if let Some(s) = pending.state.as_deref() { params.push(("state", s)); }
    redirect_to_client(&pending.redirect_uri, &params, &issuer)
}

// ─── Token / registration / revocation ───

#[derive(Deserialize)]
struct TokenForm {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    resource: Option<String>,
    scope: Option<String>,
}

fn token_error(e: &TokenError) -> HttpResponse {
    use actix_web::http::StatusCode;
    // invalid_client is 400, not 401: these are public clients that never
    // send credentials, and a 401 would oblige a WWW-Authenticate challenge
    // for an authentication scheme that doesn't exist here (RFC 6749 §5.2).
    let status = match e {
        TokenError::ServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    no_store(HttpResponse::build(status))
        .json(json!({ "error": e.code(), "error_description": e.description() }))
}

async fn token(req: HttpRequest, state: web::Data<AppState>, form: web::Form<TokenForm>) -> HttpResponse {
    let cfg = config();
    let (Some(_issuer), Some(resource)) = (cfg.issuer(), cfg.resource()) else { return not_found() };
    if !transport_ok(&req) { return insecure_transport(); }
    let ip = client_ip(&req);
    if !super::TOKEN_LIMIT.allow(&rate_key(&req)) {
        audit("unauthenticated", "", &ip, "refused: token rate limit", 429);
        return no_store(HttpResponse::TooManyRequests())
            .insert_header((header::RETRY_AFTER, "60"))
            .json(json!({ "error": "temporarily_unavailable", "error_description": "too many token requests" }));
    }
    let f = form.into_inner();
    let Some(client_id) = f.client_id.clone().filter(|c| OAUTH.get_client(c).is_some()) else {
        return token_error(&TokenError::InvalidClient("unknown client_id".into()));
    };
    // The resource, if sent, must be ours (MCP clients MUST send it).
    if let Some(r) = f.resource.as_deref()
        && r != resource {
            return token_error(&TokenError::InvalidTarget("resource must be this server's MCP endpoint".into()));
        }
    let self_cluster = super::self_cluster_name(&state.cluster);
    let authority = move |u: &str, src: oauth::AuthSource| user_authority(u, src, self_cluster.as_deref());
    let grant_type = f.grant_type.clone().unwrap_or_default();
    let result = match grant_type.as_str() {
        "authorization_code" => {
            let (Some(code), Some(redirect_uri), Some(verifier)) = (f.code.clone(), f.redirect_uri.clone(), f.code_verifier.clone()) else {
                return token_error(&TokenError::InvalidRequest("code, redirect_uri and code_verifier are required".into()));
            };
            let res = f.resource.clone();
            let cid = client_id.clone();
            web::block(move || OAUTH.exchange_code(&code, &cid, &redirect_uri, &verifier, res.as_deref(), authority)).await
        }
        "refresh_token" => {
            let Some(rt) = f.refresh_token.clone() else {
                return token_error(&TokenError::InvalidRequest("refresh_token is required".into()));
            };
            let requested = match f.scope.as_deref() {
                None => None,
                Some(s) => match oauth::parse_scopes(Some(s)) {
                    Ok(v) => Some(v),
                    Err(e) => return token_error(&TokenError::InvalidScope(e)),
                },
            };
            let res = f.resource.clone();
            let cid = client_id.clone();
            web::block(move || OAUTH.refresh(&rt, &cid, res.as_deref(), requested, authority)).await
        }
        _ => {
            return no_store(HttpResponse::BadRequest())
                .json(json!({ "error": "unsupported_grant_type", "error_description": "use authorization_code or refresh_token" }));
        }
    };
    match result {
        Ok(Ok(tokens)) => {
            tracing::info!("mcp oauth: {} grant issued tokens to client {} from {}", grant_type, client_id, ip);
            no_store(HttpResponse::Ok()).json(tokens)
        }
        Ok(Err(e)) => {
            audit("unauthenticated", &client_id, &ip,
                &format!("refused: {} grant — {}", clean(&grant_type), e.description()), 400);
            token_error(&e)
        }
        Err(e) => token_error(&TokenError::ServerError(format!("token task failed: {}", e))),
    }
}

#[derive(Deserialize)]
struct RegisterRequest {
    #[serde(default)]
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    token_endpoint_auth_method: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
}

fn register_error(code: &str, desc: &str) -> HttpResponse {
    no_store(HttpResponse::BadRequest()).json(json!({ "error": code, "error_description": desc }))
}

async fn register(req: HttpRequest, body: web::Bytes) -> HttpResponse {
    let cfg = config();
    if cfg.issuer().is_none() { return not_found(); }
    if !transport_ok(&req) { return insecure_transport(); }
    let ip = client_ip(&req);
    if !super::REGISTER_LIMIT.allow(&rate_key(&req)) {
        audit("unauthenticated", "", &ip, "refused: registration rate limit", 429);
        return no_store(HttpResponse::TooManyRequests()).insert_header((header::RETRY_AFTER, "3600"))
            .json(json!({ "error": "temporarily_unavailable", "error_description": "too many registrations from this address" }));
    }
    let r: RegisterRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return register_error("invalid_client_metadata", &format!("invalid JSON: {}", e)),
    };
    if let Some(m) = r.token_endpoint_auth_method.as_deref()
        && m != "none" {
            return register_error("invalid_client_metadata", "only public clients (token_endpoint_auth_method=none) are supported");
        }
    if let Some(g) = &r.grant_types
        && g.iter().any(|x| x != "authorization_code" && x != "refresh_token") {
            return register_error("invalid_client_metadata", "grant_types may only contain authorization_code and refresh_token");
        }
    if let Some(rt) = &r.response_types
        && rt.iter().any(|x| x != "code") {
            return register_error("invalid_client_metadata", "response_types may only contain code");
        }
    let client = match web::block(move || OAUTH.register_client(r.client_name.as_deref(), &r.redirect_uris, &ip)).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return register_error("invalid_redirect_uri", &e),
        Err(e) => return no_store(HttpResponse::InternalServerError()).json(json!({ "error": "server_error", "error_description": e.to_string() })),
    };
    tracing::info!("mcp oauth: registered client {:?} ({}) redirect {:?}", client.client_name, client.client_id, client.redirect_uris);
    no_store(HttpResponse::Created()).json(json!({
        "client_id": client.client_id,
        "client_id_issued_at": client.created_at,
        "client_name": client.client_name,
        "redirect_uris": client.redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }))
}

#[derive(Deserialize)]
struct RevokeForm {
    token: Option<String>,
    client_id: Option<String>,
}

async fn revoke(req: HttpRequest, form: web::Form<RevokeForm>) -> HttpResponse {
    let cfg = config();
    if cfg.issuer().is_none() { return not_found(); }
    if !transport_ok(&req) { return insecure_transport(); }
    let f = form.into_inner();
    let Some(token) = f.token else {
        return no_store(HttpResponse::BadRequest()).json(json!({ "error": "invalid_request", "error_description": "token is required" }));
    };
    // RFC 7009 §2.2: 200 whether or not the token was known.
    let _ = web::block(move || OAUTH.revoke_token(&token, f.client_id.as_deref())).await;
    no_store(HttpResponse::Ok()).finish()
}

// ─── Admin settings API (dashboard) ───

fn require_admin(req: &HttpRequest, state: &web::Data<AppState>) -> Result<String, HttpResponse> {
    let caller = crate::api::require_auth(req, state)?;
    // Only a signed-in admin: never an API key or a peer's cluster secret.
    if caller.starts_with("apikey:") || caller == "cluster-node" || !crate::auth::session_user_is_admin(&caller) {
        return Err(HttpResponse::Forbidden().json(json!({ "error": "Only an administrator can manage MCP access." })));
    }
    Ok(caller)
}

async fn admin_get_settings(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(r) = require_admin(&req, &state) { return r; }
    let cfg = config();
    HttpResponse::Ok().json(json!({
        "config": cfg,
        "issuer": cfg.issuer(),
        "mcp_url": cfg.resource(),
        "tls_listener": state.tls_enabled,
        "api_keys_licensed": crate::compat::platform_ready(),
        "scopes": oauth::ALL_SCOPES,
    }))
}

async fn admin_save_settings(req: HttpRequest, state: web::Data<AppState>, body: web::Json<super::McpConfig>) -> HttpResponse {
    let caller = match require_admin(&req, &state) { Ok(c) => c, Err(r) => return r };
    let before = config();
    let incoming = body.into_inner();
    let result = web::block(move || {
        let saved = super::save_config(incoming)?;
        // Tokens are bound to the old URL; moving the endpoint ends every
        // grant rather than leaving orphans that can never be used.
        if saved.public_url != before.public_url {
            OAUTH.revoke_all()?;
        }
        Ok::<_, String>(saved)
    }).await;
    match result {
        Ok(Ok(saved)) => {
            tracing::warn!("mcp: settings changed by '{}' from {}: enabled={} url='{}' api_keys={}",
                caller, client_ip(&req), saved.enabled, saved.public_url, saved.allow_api_keys);
            HttpResponse::Ok().json(json!({ "config": saved, "mcp_url": saved.resource() }))
        }
        Ok(Err(e)) => HttpResponse::BadRequest().json(json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(json!({ "error": e.to_string() })),
    }
}

// ─── Connection test ───
//
// An agent that reaches something other than this endpoint fails with an
// error that names neither the cause nor the fix: Claude Code reports
// "CLIENT_HTTP_UNEXPECTED_CONTENT" when a reverse proxy's SSO page answers
// the POST (klas, 2026-10-20). So the node makes the same three requests an
// agent makes, against its own saved public URL, and says in words what
// answered each one. Admin-only, and the URL is the saved one — never one
// from the request — so this cannot be pointed at an arbitrary host.

/// Most of a response body worth reading for a diagnosis.
const PROBE_BODY_LIMIT: usize = 16 * 1024;

#[derive(Debug, serde::Serialize)]
struct ProbeCheck {
    step: &'static str,
    url: String,
    ok: bool,
    detail: String,
}

/// What came back from one probe request, reduced to what the diagnosis needs.
struct ProbeReply {
    status: u16,
    content_type: String,
    location: Option<String>,
    www_authenticate: Option<String>,
    body: String,
}

/// The `<title>` of an HTML page, so the admin can recognise who answered
/// ("Authelia", "Sign in – Cloudflare Access").
fn html_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let open_end = start + lower[start..].find('>')? + 1;
    let close = open_end + lower[open_end..].find("</title")?;
    let title = clean(body.get(open_end..close)?.trim());
    (!title.is_empty()).then_some(title)
}

/// Shared reading of a reply that is not what WolfStack sends.
fn explain_foreign(reply: &ProbeReply) -> String {
    if (300..400).contains(&reply.status) {
        let to = reply.location.as_deref().map(clean).unwrap_or_else(|| "an unnamed address".into());
        return format!(
            "Got a redirect (HTTP {}) to {} instead of WolfStack. A sign-in layer on your reverse proxy \
             (Authelia, Authentik, Cloudflare Access, forward-auth) or an http→https rule is catching this path. \
             Exempt /mcp, /oauth/ and /.well-known/ from it — WolfStack does its own sign-in for agents.",
            reply.status, to);
    }
    let ct = reply.content_type.to_ascii_lowercase();
    if ct.starts_with("text/html") || reply.body.trim_start().starts_with('<') {
        let who = html_title(&reply.body).map(|t| format!(" titled \"{}\"", t)).unwrap_or_default();
        if reply.body.contains("WolfStack Agent Node") {
            return "An agent-only WolfStack node older than v25.36.0 answered with its information page. \
                    Upgrade the node this URL points at, then enable MCP on it.".into();
        }
        return format!(
            "Got an HTML page{} (HTTP {}) instead of WolfStack. Something in front of this node answered: \
             most often a sign-in page on the reverse proxy, or a proxy rule that sends this path to another site. \
             This is what makes Claude Code report CLIENT_HTTP_UNEXPECTED_CONTENT.",
            who, reply.status);
    }
    if reply.status == 404 {
        return "Not found (HTTP 404). Either MCP is not enabled on the node this URL reaches — the public URL may \
                point at a different node — or the reverse proxy does not forward this path.".into();
    }
    if reply.status == 403 && reply.body.contains("insecure_transport") {
        return "WolfStack refused the request because it arrived over plain HTTP from another machine. Point your \
                reverse proxy at this node's HTTPS port (8553), or run the proxy on this same machine.".into();
    }
    if reply.status == 429 {
        return "Rate-limited (HTTP 429) after too many unauthenticated tries from this address. Wait a minute and test again.".into();
    }
    if reply.status == 502 || reply.status == 503 || reply.status == 504 {
        return format!("The reverse proxy could not reach WolfStack (HTTP {}). Check the proxy's upstream address and port.", reply.status);
    }
    let ct = if reply.content_type.is_empty() { "no content type".to_string() } else { clean(&reply.content_type) };
    format!("Unexpected answer: HTTP {} with {}.", reply.status, ct)
}

/// Step 1: an agent's first, unauthenticated `initialize` must be refused
/// with 401 and a challenge naming this node's metadata document.
fn judge_mcp(reply: &ProbeReply, issuer: &str) -> (bool, String) {
    if reply.status == 401 {
        let expected = resource_metadata_url(issuer);
        return match reply.www_authenticate.as_deref() {
            Some(c) if c.contains(&expected) => (true, "WolfStack answered and asked the agent to sign in — correct.".into()),
            Some(c) => (false, format!(
                "Got a sign-in challenge, but not WolfStack's: {}. Something in front of this node demands its own authentication.",
                clean(c))),
            None => (false, "Got HTTP 401 without a WWW-Authenticate challenge — not WolfStack. A reverse proxy or another \
                             service is answering this path.".into()),
        };
    }
    (false, explain_foreign(reply))
}

/// Steps 2 and 3: the discovery documents must be WolfStack's JSON and name
/// this node, or the agent cannot find where to sign in.
fn judge_metadata(reply: &ProbeReply, field: &str, expected: &str) -> (bool, String) {
    if reply.status == 200 && reply.content_type.to_ascii_lowercase().starts_with("application/json") {
        return match serde_json::from_str::<Value>(&reply.body).ok().and_then(|v| v.get(field).and_then(|f| f.as_str()).map(String::from)) {
            Some(v) if v == expected => (true, "Served by WolfStack — correct.".into()),
            Some(v) => (false, format!(
                "Served, but it names {} instead of {}. Another node or service answers this address — check the public URL.",
                clean(&v), expected)),
            None => (false, format!("Got JSON that is not WolfStack's discovery document (no \"{}\").", field)),
        };
    }
    (false, explain_foreign(reply))
}

async fn probe(req: reqwest::RequestBuilder) -> Result<ProbeReply, String> {
    let resp = req.send().await.map_err(|e| {
        let mut msg = e.to_string();
        let mut src = std::error::Error::source(&e);
        while let Some(s) = src {
            msg.push_str(": ");
            msg.push_str(&s.to_string());
            src = s.source();
        }
        msg
    })?;
    let header = |name: reqwest::header::HeaderName| resp.headers().get(name).and_then(|v| v.to_str().ok()).map(String::from);
    let status = resp.status().as_u16();
    let content_type = header(reqwest::header::CONTENT_TYPE).unwrap_or_default();
    let location = header(reqwest::header::LOCATION);
    let www_authenticate = header(reqwest::header::WWW_AUTHENTICATE);
    // Always consume the body so the connection is released (see
    // tests/resource_safety.rs), keeping only the start of it.
    let bytes = resp.bytes().await.unwrap_or_default();
    let body = String::from_utf8_lossy(&bytes[..bytes.len().min(PROBE_BODY_LIMIT)]).into_owned();
    Ok(ProbeReply { status, content_type, location, www_authenticate, body })
}

fn unreachable_detail(err: &str) -> String {
    let lower = err.to_ascii_lowercase();
    if lower.contains("certificate") || lower.contains("unknownissuer") || lower.contains("invalid peer") {
        return format!(
            "The TLS certificate was not accepted: {}. Agents check certificates too, so the public URL needs a \
             certificate a normal client trusts (for example Let's Encrypt).", clean(err));
    }
    format!(
        "This node could not reach its own public URL: {}. If the URL works from other machines, your router may \
         not let a server reach its own public address — test with the claude command from another computer.",
        clean(err))
}

async fn admin_test_connection(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let caller = match require_admin(&req, &state) { Ok(c) => c, Err(r) => return r };
    let cfg = config();
    let (Some(issuer), Some(resource)) = (cfg.issuer(), cfg.resource()) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Enable MCP and save the public URL first, then test." }));
    };
    let client = match reqwest::Client::builder()
        // Bound the connect, not just the request (tests/resource_safety.rs).
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        // A redirect is itself the finding — an agent following it to a
        // sign-in page is exactly the failure being diagnosed.
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().json(json!({ "error": format!("could not build HTTP client: {}", e) })),
    };

    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "wolfstack-connection-test", "version": env!("CARGO_PKG_VERSION") } },
    });
    let prm_url = resource_metadata_url(&issuer);
    let asm_url = format!("{}/.well-known/oauth-authorization-server", issuer);

    let mut checks = Vec::new();
    let mcp = probe(client.post(&resource)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::ACCEPT, "application/json, text/event-stream")
        .body(init.to_string())).await;
    let reached = mcp.is_ok();
    let (ok, detail) = match &mcp {
        Ok(r) => judge_mcp(r, &issuer),
        Err(e) => (false, unreachable_detail(e)),
    };
    checks.push(ProbeCheck { step: "MCP endpoint", url: resource.clone(), ok, detail });

    // Without a connection there is nothing more to learn — the same error
    // three times would only bury it.
    if reached {
        for (step, url, field, expected) in [
            ("Sign-in discovery (protected resource)", prm_url, "resource", resource.as_str()),
            ("Sign-in discovery (authorization server)", asm_url, "issuer", issuer.as_str()),
        ] {
            let (ok, detail) = match probe(client.get(&url).header(reqwest::header::ACCEPT, "application/json")).await {
                Ok(r) => judge_metadata(&r, field, expected),
                Err(e) => (false, unreachable_detail(&e)),
            };
            checks.push(ProbeCheck { step, url, ok, detail });
        }
    }

    let ok = checks.iter().all(|c| c.ok);
    tracing::info!("mcp: connection test by '{}' against {}: {}", caller, issuer, if ok { "passed" } else { "failed" });
    HttpResponse::Ok().json(json!({ "ok": ok, "checks": checks }))
}

async fn admin_list_grants(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(r) = require_admin(&req, &state) { return r; }
    match web::block(|| OAUTH.list_grants()).await {
        Ok(g) => HttpResponse::Ok().json(g),
        Err(e) => HttpResponse::InternalServerError().json(json!({ "error": e.to_string() })),
    }
}

async fn admin_revoke_grant(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    let caller = match require_admin(&req, &state) { Ok(c) => c, Err(r) => return r };
    let id = path.into_inner();
    let id2 = id.clone();
    match web::block(move || OAUTH.revoke_grant(&id2)).await {
        Ok(Ok(true)) => {
            tracing::warn!("mcp: grant {} revoked by '{}'", id, caller);
            HttpResponse::Ok().json(json!({ "revoked": true }))
        }
        Ok(Ok(false)) => HttpResponse::NotFound().json(json!({ "error": "No such grant (it may already have expired)." })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(json!({ "error": e.to_string() })),
    }
}

async fn admin_list_clients(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    if let Err(r) = require_admin(&req, &state) { return r; }
    match web::block(|| OAUTH.list_clients()).await {
        Ok(c) => HttpResponse::Ok().json(c),
        Err(e) => HttpResponse::InternalServerError().json(json!({ "error": e.to_string() })),
    }
}

async fn admin_delete_client(req: HttpRequest, state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    let caller = match require_admin(&req, &state) { Ok(c) => c, Err(r) => return r };
    let id = path.into_inner();
    let id2 = id.clone();
    match web::block(move || OAUTH.delete_client(&id2)).await {
        Ok(Ok(true)) => {
            tracing::warn!("mcp: client {} and its grants removed by '{}'", id, caller);
            HttpResponse::Ok().json(json!({ "deleted": true }))
        }
        Ok(Ok(false)) => HttpResponse::NotFound().json(json!({ "error": "No such client." })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(json!({ "error": e })),
        Err(e) => HttpResponse::InternalServerError().json(json!({ "error": e.to_string() })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(status: u16, content_type: &str, body: &str) -> ProbeReply {
        ProbeReply { status, content_type: content_type.into(), location: None, www_authenticate: None, body: body.into() }
    }

    const ISSUER: &str = "https://ws.example.com";

    #[test]
    fn connection_test_passes_only_on_wolfstacks_own_challenge() {
        let mut r = reply(401, "application/json", "{}");
        r.www_authenticate = Some(format!("Bearer resource_metadata=\"{}\", scope=\"read\"", resource_metadata_url(ISSUER)));
        assert!(judge_mcp(&r, ISSUER).0);

        r.www_authenticate = Some("Basic realm=\"proxy\"".into());
        let (ok, detail) = judge_mcp(&r, ISSUER);
        assert!(!ok && detail.contains("not WolfStack's"), "{detail}");

        r.www_authenticate = None;
        assert!(!judge_mcp(&r, ISSUER).0);
    }

    #[test]
    fn connection_test_names_an_sso_page_that_answered_the_post() {
        // The klas failure: a 200 HTML page where WolfStack's JSON belongs.
        let r = reply(200, "text/html; charset=utf-8", "<html><head><TITLE> Authelia </TITLE></head></html>");
        let (ok, detail) = judge_mcp(&r, ISSUER);
        assert!(!ok);
        assert!(detail.contains("\"Authelia\"") && detail.contains("CLIENT_HTTP_UNEXPECTED_CONTENT"), "{detail}");

        let mut r = reply(302, "", "");
        r.location = Some("https://auth.example.com/login?rd=x".into());
        let (ok, detail) = judge_mcp(&r, ISSUER);
        assert!(!ok && detail.contains("https://auth.example.com/login") && detail.contains("/.well-known/"), "{detail}");
    }

    #[test]
    fn connection_test_recognises_wolfstack_refusals() {
        assert!(judge_mcp(&reply(404, "", ""), ISSUER).1.contains("MCP is not enabled"));
        let r = reply(403, "application/json", r#"{"error":"insecure_transport"}"#);
        assert!(judge_mcp(&r, ISSUER).1.contains("8553"));
        let r = reply(200, "text/html", "<title>WolfStack Agent Node</title>");
        assert!(judge_mcp(&r, ISSUER).1.contains("v25.36.0"));
    }

    #[test]
    fn connection_test_checks_discovery_documents_name_this_node() {
        let resource = format!("{}/mcp", ISSUER);
        let ok_body = json!({ "resource": resource }).to_string();
        assert!(judge_metadata(&reply(200, "application/json", &ok_body), "resource", &resource).0);

        let other = json!({ "resource": "https://other.example.com/mcp" }).to_string();
        let (ok, detail) = judge_metadata(&reply(200, "application/json", &other), "resource", &resource);
        assert!(!ok && detail.contains("other.example.com"), "{detail}");

        assert!(!judge_metadata(&reply(200, "text/html", "<html></html>"), "resource", &resource).0);
    }

    /// One canned HTTP response on a local socket, per request accepted.
    fn canned_server(responses: Vec<&'static str>) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for resp in responses {
                let (mut s, _) = listener.accept().unwrap();
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(resp.as_bytes());
            }
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn probe_reports_a_redirect_instead_of_following_it() {
        let base = canned_server(vec![
            "HTTP/1.1 302 Found\r\nLocation: https://auth.example.com/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 34\r\nConnection: close\r\n\r\n<html><title>Login</title></html>\n",
        ]);
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .build().unwrap();
        let r = probe(client.post(format!("{}/mcp", base)).body("{}")).await.unwrap();
        assert_eq!(r.status, 302);
        assert_eq!(r.location.as_deref(), Some("https://auth.example.com/"));

        let r = probe(client.post(format!("{}/mcp", base)).body("{}")).await.unwrap();
        assert_eq!((r.status, r.content_type.as_str()), (200, "text/html"));
        assert!(judge_mcp(&r, ISSUER).1.contains("\"Login\""));
    }

    #[test]
    fn html_title_is_cleaned_and_optional() {
        assert_eq!(html_title("<title>Sign\nin</title>").as_deref(), Some("Sign in"));
        assert_eq!(html_title("<html>no title</html>"), None);
        assert_eq!(html_title("<title></title>"), None);
    }

    #[test]
    fn html_escaping_covers_attribute_and_text_contexts() {
        assert_eq!(esc("<script>\"x\"&'y'</script>"), "&lt;script&gt;&quot;x&quot;&amp;&#39;y&#39;&lt;/script&gt;");
    }

    #[test]
    fn redirect_carries_issuer_and_encodes_params() {
        let r = redirect_to_client("http://127.0.0.1:5000/cb?x=1", &[("code", "a b&c"), ("state", "s")], "https://ws.example.com");
        let loc = r.headers().get(header::LOCATION).unwrap().to_str().unwrap().to_string();
        assert!(loc.starts_with("http://127.0.0.1:5000/cb?x=1&code=a+b%26c&state=s&iss=https%3A%2F%2Fws.example.com"), "{}", loc);
        assert_eq!(r.status(), actix_web::http::StatusCode::SEE_OTHER);
    }

    #[test]
    fn consent_page_is_locked_down() {
        let r = error_page("t", "<b>m</b>");
        let csp = r.headers().get("Content-Security-Policy").unwrap().to_str().unwrap();
        assert!(csp.contains("frame-ancestors 'none'") && csp.contains("default-src 'none'"));
        assert!(!csp.contains("script-src"), "no script source may be allowed");
        assert_eq!(r.headers().get("X-Frame-Options").unwrap(), "DENY");
        assert_eq!(r.headers().get(header::CACHE_CONTROL).unwrap(), "no-store");
    }
}
