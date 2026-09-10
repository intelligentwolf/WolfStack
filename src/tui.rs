// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! Terminal UI — server-side rendered HTML interface optimized for text browsers (lynx, w3m, links).
//! Accessible at /tui/* routes. Uses the same session cookie auth as the main web UI.

use actix_web::{web, HttpRequest, HttpResponse};
use crate::api::AppState;

// ─── Helpers ───

fn require_tui_auth(req: &HttpRequest, state: &web::Data<AppState>) -> Result<String, HttpResponse> {
    // Check cluster secret header first (for inter-node or CLI access).
    // Centralised three-way check (in-memory, on-disk, optional default)
    // lives in `auth::validate_inter_node_secret` — see Stage 5 docs.
    if let Some(val) = req.headers().get("X-WolfStack-Secret") {
        let provided = val.to_str().unwrap_or("");
        if crate::auth::validate_inter_node_secret_from(
            provided, &state.cluster_secret, crate::api::peer_ip(req))
        {
            return Ok("cluster-node".to_string());
        }
    }
    // Then check session cookie
    match req.cookie("wolfstack_session") {
        Some(cookie) => match state.sessions.validate(cookie.value()) {
            Some(username) => Ok(username),
            None => Err(HttpResponse::Found().append_header(("Location", "/tui/login")).finish()),
        },
        None => Err(HttpResponse::Found().append_header(("Location", "/tui/login")).finish()),
    }
}

/// Auth for the two TUI routes that CHANGE something (container start /
/// stop / restart). They are plain GET links, so the method rule in
/// `api::require_auth` cannot cover them; refuse read-only sessions here.
fn require_tui_operator(req: &HttpRequest, state: &web::Data<AppState>) -> Result<String, HttpResponse> {
    let user = require_tui_auth(req, state)?;
    if crate::api::session_is_read_only(req, state) {
        return Err(HttpResponse::Forbidden()
            .insert_header((crate::api::READ_ONLY_HEADER, "read-only"))
            .content_type("text/html; charset=utf-8")
            .body("<html><body style=\"font-family:monospace;background:#181a20;color:#e74c3c;padding:40px;\">\
                   <h1>Read-only account</h1><p>Your account is a viewer: container actions are not available.</p>\
                   <p><a href=\"/tui\" style=\"color:#ef4444;\">Back</a></p></body></html>"));
    }
    Ok(user)
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000_000 { format!("{:.1} TB", bytes as f64 / 1e12) }
    else if bytes >= 1_000_000_000 { format!("{:.1} GB", bytes as f64 / 1e9) }
    else if bytes >= 1_000_000 { format!("{:.0} MB", bytes as f64 / 1e6) }
    else { format!("{:.0} KB", bytes as f64 / 1e3) }
}

fn format_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    if d > 0 { format!("{}d {}h {}m", d, h, m) }
    else if h > 0 { format!("{}h {}m", h, m) }
    else { format!("{}m", m) }
}

fn bar(pct: f32, width: usize) -> String {
    let filled = ((pct / 100.0) * width as f32).round() as usize;
    let empty = width.saturating_sub(filled);
    let color = if pct >= 90.0 { "#e74c3c" } else if pct >= 70.0 { "#f39c12" } else { "#2ecc71" };
    // Plain text version for text browsers + styled version for graphical
    format!(
        "<span style=\"color:{}\">{}</span>{}  {:.0}%",
        color,
        "#".repeat(filled),
        ".".repeat(empty),
        pct,
    )
}

// ─── Page Layout ───

fn page(title: &str, nav: &str, username: &str, body: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WolfStack TUI — {title}</title>
<style>
  body {{ font-family: monospace; background: #181a20; color: #e8e8ed; margin: 0; padding: 8px; font-size: 14px; }}
  a {{ color: #ef4444; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  h1 {{ font-size: 18px; margin: 4px 0 8px; }}
  h2 {{ font-size: 16px; margin: 12px 0 6px; border-bottom: 1px solid #333; padding-bottom: 4px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 8px 0; }}
  th, td {{ text-align: left; padding: 4px 12px 4px 0; border-bottom: 1px solid #272a33; white-space: nowrap; }}
  th {{ color: #6e6e82; font-size: 12px; text-transform: uppercase; }}
  .online {{ color: #2ecc71; }} .offline {{ color: #e74c3c; }}
  .running {{ color: #2ecc71; }} .stopped {{ color: #e74c3c; }} .paused {{ color: #f39c12; }}
  .nav {{ margin: 4px 0 12px; padding: 4px 0; border-bottom: 1px solid #333; }}
  .nav a {{ margin-right: 16px; }}
  .nav a.active {{ color: #fff; font-weight: bold; text-decoration: underline; }}
  .header {{ display: flex; justify-content: space-between; align-items: baseline; border-bottom: 1px solid #333; padding-bottom: 4px; margin-bottom: 4px; }}
  .card {{ border: 1px solid #272a33; padding: 8px 12px; margin: 8px 0; }}
  .muted {{ color: #6e6e82; }}
  pre {{ margin: 0; }}
  form {{ margin: 8px 0; }}
  input {{ font-family: monospace; font-size: 14px; padding: 4px 8px; background: #272a33; border: 1px solid #444; color: #e8e8ed; }}
  button {{ font-family: monospace; font-size: 14px; padding: 4px 12px; background: #dc2626; border: none; color: #fff; cursor: pointer; }}
  button:hover {{ background: #ef4444; }}
  .action {{ font-size: 12px; padding: 2px 8px; background: #272a33; border: 1px solid #444; color: #ef4444; }}
  .warn {{ color: #f39c12; }}
</style>
</head>
<body>
<div class="header">
  <span><strong>WolfStack TUI</strong> v{version}</span>
  <span>{username} | <a href="/tui/logout">Logout</a></span>
</div>
<div class="nav">{nav}</div>
{body}
<hr style="border-color:#272a33;margin-top:16px;">
<div class="muted" style="font-size:12px;">WolfStack Terminal UI — works in lynx, w3m, links, or any browser | <a href="/">Full Web UI</a></div>
</body>
</html>"#,
        title = esc(title),
        version = env!("CARGO_PKG_VERSION"),
        username = esc(username),
        nav = nav,
        body = body,
    )
}

fn dc_nav(active: &str) -> String {
    let items = [
        ("dashboard", "/tui", "Dashboard"),
        ("containers", "/tui/containers", "Containers"),
        ("backups", "/tui/backups", "Backups"),
        ("settings", "/tui/settings", "Settings"),
    ];
    items.iter().map(|(id, href, label)| {
        let cls = if *id == active { " class=\"active\"" } else { "" };
        format!("<a href=\"{}\"{}>[{}]</a>", href, cls, label)
    }).collect::<Vec<_>>().join(" ")
}

fn node_nav(node_id: &str, active: &str) -> String {
    let items = [
        ("overview", "Overview"),
        ("containers", "Containers"),
        ("lxc", "LXC"),
        ("services", "Services"),
        ("storage", "Storage"),
        ("networking", "Networking"),
        ("backups", "Backups"),
        ("logs", "Logs"),
    ];
    let mut parts: Vec<String> = vec![
        format!("<a href=\"/tui\">[&lt; Back]</a>"),
    ];
    for (id, label) in &items {
        let cls = if *id == active { " class=\"active\"" } else { "" };
        parts.push(format!("<a href=\"/tui/node/{}/{}\"{}>[{}]</a>", node_id, id, cls, label));
    }
    parts.join(" ")
}

// ─── Route Handlers ───

/// GET /tui/login
pub async fn tui_login_page() -> HttpResponse {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WolfStack TUI — Login</title>
<style>
  body { font-family: monospace; background: #181a20; color: #e8e8ed; margin: 0; padding: 40px; font-size: 14px; }
  a { color: #ef4444; }
  input { font-family: monospace; font-size: 14px; padding: 4px 8px; background: #272a33; border: 1px solid #444; color: #e8e8ed; width: 200px; }
  button { font-family: monospace; font-size: 14px; padding: 4px 16px; background: #dc2626; border: none; color: #fff; cursor: pointer; }
  .box { border: 1px solid #333; padding: 16px; max-width: 320px; }
</style>
</head>
<body>
<h1>WolfStack TUI — Login</h1>
<div class="box">
<form method="POST" action="/tui/login">
  <p>Username:<br><input type="text" name="username" autofocus></p>
  <p>Password:<br><input type="password" name="password"></p>
  <p><button type="submit">Login</button></p>
</form>
</div>
</body>
</html>"#;
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// POST /tui/login — form-based login (application/x-www-form-urlencoded)
pub async fn tui_login_submit(
    req: HttpRequest,
    state: web::Data<AppState>,
    form: web::Form<std::collections::HashMap<String, String>>,
) -> HttpResponse {
    let username = form.get("username").cloned().unwrap_or_default();
    let password = form.get("password").cloned().unwrap_or_default();

    // Rate limiting. canonical_ip_str: a dual-stack [::] listener reports
    // v4 clients as ::ffff:a.b.c.d — same lockout bucket as the main login.
    let client_ip = crate::netaddr::canonical_ip_str(
        req.connection_info().peer_addr().unwrap_or("unknown")).into_owned();
    if state.login_limiter.is_locked_out(&client_ip) {
        return HttpResponse::Ok().content_type("text/html").body(
            "<html><body style=\"font-family:monospace;background:#181a20;color:#e74c3c;padding:40px;\"><h1>Too many attempts</h1><p>Please try again later.</p><p><a href=\"/tui/login\" style=\"color:#ef4444;\">Back to login</a></p></body></html>"
        );
    }

    if crate::auth::authenticate_user(&username, &password) {
        state.login_limiter.clear(&client_ip);
        // TUI login is Linux-account only (no WolfStack role): full access.
        let token = state.sessions.create_session(&username, false);
        let mut cookie = actix_web::cookie::Cookie::build("wolfstack_session", &token)
            .path("/")
            .http_only(true)
            // Lax, not Strict — Strict drops the cookie on top-level
            // navigation and broke login on Microsoft Edge. See api/mod.rs.
            .same_site(actix_web::cookie::SameSite::Lax)
            .max_age(actix_web::cookie::time::Duration::hours(8))
            .finish();
        if state.tls_enabled {
            cookie.set_secure(true);
        }
        HttpResponse::Found()
            .cookie(cookie)
            .append_header(("Location", "/tui"))
            .finish()
    } else {
        state.login_limiter.record_failure(&client_ip);
        HttpResponse::Ok().content_type("text/html").body(
            "<html><body style=\"font-family:monospace;background:#181a20;color:#e74c3c;padding:40px;\"><h1>Login failed</h1><p>Invalid username or password.</p><p><a href=\"/tui/login\" style=\"color:#ef4444;\">Try again</a></p></body></html>"
        )
    }
}

/// POST /tui/logout
pub async fn tui_logout() -> HttpResponse {
    let cookie = actix_web::cookie::Cookie::build("wolfstack_session", "")
        .path("/")
        .max_age(actix_web::cookie::time::Duration::ZERO)
        .finish();
    HttpResponse::Found()
        .cookie(cookie)
        .append_header(("Location", "/tui/login"))
        .finish()
}

/// GET /tui — Datacenter dashboard (all nodes)
pub async fn tui_dashboard(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let username = match require_tui_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let nodes = state.cluster.get_all_nodes();

    // Group by cluster
    let mut clusters: std::collections::BTreeMap<String, Vec<&crate::agent::Node>> = std::collections::BTreeMap::new();
    for node in &nodes {
        let name = node.cluster_name.as_deref().unwrap_or("Default");
        clusters.entry(name.to_string()).or_default().push(node);
    }

    let mut body = String::new();
    body.push_str("<h1>Datacenter Overview</h1>");

    // Summary
    let online = nodes.iter().filter(|n| n.online).count();
    let total_docker: u32 = nodes.iter().map(|n| n.docker_count).sum();
    let total_lxc: u32 = nodes.iter().map(|n| n.lxc_count).sum();
    body.push_str(&format!(
        "<p>{} node{} ({} online) | {} Docker containers | {} LXC containers</p>",
        nodes.len(), if nodes.len() != 1 { "s" } else { "" },
        online, total_docker, total_lxc,
    ));

    for (cluster_name, cluster_nodes) in &clusters {
        body.push_str(&format!("<h2>{}</h2>", esc(cluster_name)));
        body.push_str("<table>");
        body.push_str("<tr><th>Hostname</th><th>Status</th><th>CPU</th><th>Memory</th><th>Disk</th><th>Docker</th><th>LXC</th><th>Uptime</th></tr>");

        for node in cluster_nodes {
            let status = if node.online {
                "<span class=\"online\">online</span>".to_string()
            } else {
                "<span class=\"offline\">offline</span>".to_string()
            };

            let (cpu, mem, disk, uptime) = if let Some(ref m) = node.metrics {
                let root_disk = m.disks.iter()
                    .find(|d| d.mount_point == "/")
                    .map(|d| d.usage_percent)
                    .unwrap_or(0.0);
                (
                    bar(m.cpu_usage_percent, 12),
                    bar(m.memory_percent, 12),
                    bar(root_disk, 12),
                    format_uptime(m.uptime_secs),
                )
            } else {
                ("-".into(), "-".into(), "-".into(), "-".into())
            };

            let this_marker = if node.is_self { " <span class=\"muted\">(this)</span>" } else { "" };

            body.push_str(&format!(
                "<tr><td><a href=\"/tui/node/{id}/overview\">{hostname}</a>{this}</td><td>{status}</td><td><pre>{cpu}</pre></td><td><pre>{mem}</pre></td><td><pre>{disk}</pre></td><td>{docker}</td><td>{lxc}</td><td>{uptime}</td></tr>",
                id = esc(&node.id),
                hostname = esc(&node.hostname),
                this = this_marker,
                status = status,
                cpu = cpu,
                mem = mem,
                disk = disk,
                docker = node.docker_count,
                lxc = node.lxc_count,
                uptime = uptime,
            ));
        }
        body.push_str("</table>");
    }

    let html = page("Dashboard", &dc_nav("dashboard"), &username, &body);
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// GET /tui/node/{id}/overview — Node detail page
pub async fn tui_node_overview(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let username = match require_tui_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let node_id = path.into_inner();
    let node = match state.cluster.get_node(&node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().body("Node not found"),
    };

    let mut body = String::new();
    body.push_str(&format!("<h1>{}</h1>", esc(&node.hostname)));

    if let Some(ref m) = node.metrics {
        // System info
        body.push_str("<div class=\"card\">");
        body.push_str(&format!("<strong>{}</strong>", esc(&m.cpu_model)));
        if let Some(ref os) = m.os_name {
            body.push_str(&format!(" | {}", esc(os)));
        }
        if let Some(ref ver) = m.os_version {
            body.push_str(&format!(" {}", esc(ver)));
        }
        if let Some(ref kern) = m.kernel_version {
            body.push_str(&format!(" | Kernel {}", esc(kern)));
        }
        body.push_str(&format!(" | Uptime: {}", format_uptime(m.uptime_secs)));
        body.push_str("</div>");

        // Gauges
        body.push_str("<h2>Resources</h2>");
        body.push_str("<table>");
        body.push_str(&format!(
            "<tr><td>CPU ({} cores)</td><td><pre>{}</pre></td></tr>",
            m.cpu_count, bar(m.cpu_usage_percent, 30)
        ));
        body.push_str(&format!(
            "<tr><td>Memory ({}/{})</td><td><pre>{}</pre></td></tr>",
            format_bytes(m.memory_used_bytes), format_bytes(m.memory_total_bytes),
            bar(m.memory_percent, 30)
        ));
        if m.swap_total_bytes > 0 {
            let swap_pct = if m.swap_total_bytes > 0 {
                (m.swap_used_bytes as f32 / m.swap_total_bytes as f32) * 100.0
            } else { 0.0 };
            body.push_str(&format!(
                "<tr><td>Swap ({}/{})</td><td><pre>{}</pre></td></tr>",
                format_bytes(m.swap_used_bytes), format_bytes(m.swap_total_bytes),
                bar(swap_pct, 30)
            ));
        }
        body.push_str(&format!(
            "<tr><td>Load Average</td><td>{:.2} / {:.2} / {:.2}</td></tr>",
            m.load_avg.one, m.load_avg.five, m.load_avg.fifteen
        ));
        body.push_str(&format!("<tr><td>Processes</td><td>{}</td></tr>", m.processes));
        body.push_str("</table>");

        // Disks
        if !m.disks.is_empty() {
            body.push_str("<h2>Filesystems</h2>");
            body.push_str("<table>");
            body.push_str("<tr><th>Mount</th><th>Device</th><th>Type</th><th>Size</th><th>Used</th><th>Free</th><th>Usage</th></tr>");
            for d in &m.disks {
                body.push_str(&format!(
                    "<tr><td>{mount}</td><td>{dev}</td><td>{fs}</td><td>{total}</td><td>{used}</td><td>{free}</td><td><pre>{bar}</pre></td></tr>",
                    mount = esc(&d.mount_point),
                    dev = esc(&d.name),
                    fs = esc(&d.fs_type),
                    total = format_bytes(d.total_bytes),
                    used = format_bytes(d.used_bytes),
                    free = format_bytes(d.available_bytes),
                    bar = bar(d.usage_percent, 16),
                ));
            }
            body.push_str("</table>");
        }

        // Network
        if !m.network.is_empty() {
            body.push_str("<h2>Network Interfaces</h2>");
            body.push_str("<table>");
            body.push_str("<tr><th>Interface</th><th>RX</th><th>TX</th></tr>");
            for n in &m.network {
                body.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc(&n.interface), format_bytes(n.rx_bytes), format_bytes(n.tx_bytes),
                ));
            }
            body.push_str("</table>");
        }
    } else {
        body.push_str("<p class=\"offline\">Node is offline — no metrics available.</p>");
    }

    // Components
    if !node.components.is_empty() {
        body.push_str("<h2>Components</h2>");
        body.push_str("<table>");
        body.push_str("<tr><th>Component</th><th>Installed</th><th>Running</th><th>Enabled</th><th>Version</th></tr>");
        for c in &node.components {
            let installed = if c.installed { "<span class=\"online\">yes</span>" } else { "no" };
            let running = if c.running { "<span class=\"online\">running</span>" } else if c.installed { "<span class=\"stopped\">stopped</span>" } else { "-" };
            let enabled = if c.enabled { "yes" } else if c.installed { "no" } else { "-" };
            let version = c.version.as_deref().unwrap_or("-");
            body.push_str(&format!(
                "<tr><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                c.component, installed, running, enabled, esc(version),
            ));
        }
        body.push_str("</table>");
    }

    let nav = node_nav(&node_id, "overview");
    let html = page(&node.hostname, &nav, &username, &body);
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// GET /tui/node/{id}/containers — Docker containers
pub async fn tui_node_containers(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let username = match require_tui_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let node_id = path.into_inner();
    let node = match state.cluster.get_node(&node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().body("Node not found"),
    };

    let mut body = String::new();
    body.push_str(&format!("<h1>{} — Docker Containers</h1>", esc(&node.hostname)));

    if node.is_self {
        // Local node — call docker directly
        let containers = crate::containers::docker_list_all();
        if containers.is_empty() {
            body.push_str("<p class=\"muted\">No Docker containers found.</p>");
        } else {
            let running = containers.iter().filter(|c| c.state == "running").count();
            body.push_str(&format!("<p>{} containers ({} running)</p>", containers.len(), running));
            body.push_str("<table>");
            body.push_str("<tr><th>Name</th><th>Image</th><th>State</th><th>IP</th><th>Ports</th><th>Actions</th></tr>");
            for c in &containers {
                let state_cls = match c.state.as_str() {
                    "running" => "running",
                    "paused" => "paused",
                    _ => "stopped",
                };
                let ports = if c.ports.is_empty() { "-".to_string() } else { c.ports.join(", ") };
                let actions = if c.state == "running" {
                    format!(
                        "<a class=\"action\" href=\"/tui/node/{}/containers/docker/{}/stop\">[Stop]</a> <a class=\"action\" href=\"/tui/node/{}/containers/docker/{}/restart\">[Restart]</a>",
                        node_id, esc(&c.name), node_id, esc(&c.name),
                    )
                } else {
                    format!(
                        "<a class=\"action\" href=\"/tui/node/{}/containers/docker/{}/start\">[Start]</a>",
                        node_id, esc(&c.name),
                    )
                };
                body.push_str(&format!(
                    "<tr><td>{name}</td><td>{image}</td><td><span class=\"{cls}\">{state}</span></td><td>{ip}</td><td>{ports}</td><td>{actions}</td></tr>",
                    name = esc(&c.name),
                    image = esc(&c.image),
                    cls = state_cls,
                    state = esc(&c.state),
                    ip = esc(&c.ip_address),
                    ports = esc(&ports),
                    actions = actions,
                ));
            }
            body.push_str("</table>");
        }
    } else {
        body.push_str(&format!(
            "<p class=\"muted\">Remote node — container data available via <a href=\"/tui/node/{}/overview\">node overview</a>. Docker: {}, LXC: {}</p>",
            esc(&node_id), node.docker_count, node.lxc_count,
        ));
    }

    let nav = node_nav(&node_id, "containers");
    let html = page(&format!("{} — Docker", node.hostname), &nav, &username, &body);
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// GET /tui/node/{id}/lxc — LXC containers
pub async fn tui_node_lxc(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let username = match require_tui_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let node_id = path.into_inner();
    let node = match state.cluster.get_node(&node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().body("Node not found"),
    };

    let mut body = String::new();
    body.push_str(&format!("<h1>{} — LXC Containers</h1>", esc(&node.hostname)));

    if node.is_self {
        let containers = crate::containers::lxc_list_all();
        if containers.is_empty() {
            body.push_str("<p class=\"muted\">No LXC containers found.</p>");
        } else {
            let running = containers.iter().filter(|c| c.state == "running").count();
            body.push_str(&format!("<p>{} containers ({} running)</p>", containers.len(), running));
            body.push_str("<table>");
            body.push_str("<tr><th>Name</th><th>State</th><th>IP</th><th>Autostart</th><th>Actions</th></tr>");
            for c in &containers {
                let state_cls = match c.state.as_str() {
                    "running" => "running",
                    _ => "stopped",
                };
                let actions = if c.state == "running" {
                    format!(
                        "<a class=\"action\" href=\"/tui/node/{}/containers/lxc/{}/stop\">[Stop]</a> <a class=\"action\" href=\"/tui/node/{}/containers/lxc/{}/restart\">[Restart]</a>",
                        node_id, esc(&c.name), node_id, esc(&c.name),
                    )
                } else {
                    format!(
                        "<a class=\"action\" href=\"/tui/node/{}/containers/lxc/{}/start\">[Start]</a>",
                        node_id, esc(&c.name),
                    )
                };
                body.push_str(&format!(
                    "<tr><td>{name}</td><td><span class=\"{cls}\">{state}</span></td><td>{ip}</td><td>{auto}</td><td>{actions}</td></tr>",
                    name = esc(&c.name),
                    cls = state_cls,
                    state = esc(&c.state),
                    ip = esc(&c.ip_address),
                    auto = if c.autostart { "yes" } else { "no" },
                    actions = actions,
                ));
            }
            body.push_str("</table>");
        }
    } else {
        body.push_str("<p class=\"muted\">Remote node — LXC data not available from here.</p>");
    }

    let nav = node_nav(&node_id, "lxc");
    let html = page(&format!("{} — LXC", node.hostname), &nav, &username, &body);
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// GET /tui/node/{id}/services — Installed components
pub async fn tui_node_services(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let username = match require_tui_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let node_id = path.into_inner();
    let node = match state.cluster.get_node(&node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().body("Node not found"),
    };

    let mut body = String::new();
    body.push_str(&format!("<h1>{} — Services</h1>", esc(&node.hostname)));

    if node.components.is_empty() {
        body.push_str("<p class=\"muted\">No component data available.</p>");
    } else {
        body.push_str("<table>");
        body.push_str("<tr><th>Component</th><th>Installed</th><th>Running</th><th>Enabled</th><th>Version</th></tr>");
        for c in &node.components {
            let installed = if c.installed { "<span class=\"online\">yes</span>" } else { "no" };
            let running = if c.running { "<span class=\"running\">running</span>" } else if c.installed { "<span class=\"stopped\">stopped</span>" } else { "-" };
            let enabled = if c.enabled { "yes" } else if c.installed { "no" } else { "-" };
            let version = c.version.as_deref().unwrap_or("-");
            body.push_str(&format!(
                "<tr><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                c.component, installed, running, enabled, esc(version),
            ));
        }
        body.push_str("</table>");
    }

    let nav = node_nav(&node_id, "services");
    let html = page(&format!("{} — Services", node.hostname), &nav, &username, &body);
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// GET /tui/node/{id}/storage — Storage mounts (local node only)
pub async fn tui_node_storage(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let username = match require_tui_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let node_id = path.into_inner();
    let node = match state.cluster.get_node(&node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().body("Node not found"),
    };

    let mut body = String::new();
    body.push_str(&format!("<h1>{} — Storage</h1>", esc(&node.hostname)));

    // Show filesystem data from metrics
    if let Some(ref m) = node.metrics {
        if !m.disks.is_empty() {
            body.push_str("<h2>Filesystems</h2>");
            body.push_str("<table>");
            body.push_str("<tr><th>Mount</th><th>Device</th><th>FS</th><th>Total</th><th>Used</th><th>Free</th><th>Usage</th></tr>");
            for d in &m.disks {
                body.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><pre>{}</pre></td></tr>",
                    esc(&d.mount_point), esc(&d.name), esc(&d.fs_type),
                    format_bytes(d.total_bytes), format_bytes(d.used_bytes),
                    format_bytes(d.available_bytes), bar(d.usage_percent, 16),
                ));
            }
            body.push_str("</table>");
        }
    } else {
        body.push_str("<p class=\"muted\">Node offline — no storage data.</p>");
    }

    let nav = node_nav(&node_id, "storage");
    let html = page(&format!("{} — Storage", node.hostname), &nav, &username, &body);
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// GET /tui/node/{id}/networking — Network interfaces
pub async fn tui_node_networking(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let username = match require_tui_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let node_id = path.into_inner();
    let node = match state.cluster.get_node(&node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().body("Node not found"),
    };

    let mut body = String::new();
    body.push_str(&format!("<h1>{} — Networking</h1>", esc(&node.hostname)));

    body.push_str("<div class=\"card\">");
    body.push_str(&format!("Address: <strong>{}</strong>:{}", esc(&node.address), node.port));
    if let Some(ref pip) = node.public_ip {
        body.push_str(&format!(" | Public IP: <strong>{}</strong>", esc(pip)));
    }
    body.push_str("</div>");

    if let Some(ref m) = node.metrics
        && !m.network.is_empty() {
            body.push_str("<h2>Interfaces</h2>");
            body.push_str("<table>");
            body.push_str("<tr><th>Interface</th><th>RX</th><th>TX</th></tr>");
            for n in &m.network {
                body.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc(&n.interface), format_bytes(n.rx_bytes), format_bytes(n.tx_bytes),
                ));
            }
            body.push_str("</table>");
        }

    let nav = node_nav(&node_id, "networking");
    let html = page(&format!("{} — Networking", node.hostname), &nav, &username, &body);
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// GET /tui/node/{id}/backups — Backup info
pub async fn tui_node_backups(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let username = match require_tui_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let node_id = path.into_inner();
    let node = match state.cluster.get_node(&node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().body("Node not found"),
    };

    let mut body = String::new();
    body.push_str(&format!("<h1>{} — Backups</h1>", esc(&node.hostname)));

    if node.is_self {
        // Load backup config
        let config = crate::backup::load_config();
        if config.entries.is_empty() && config.schedules.is_empty() {
            body.push_str("<p class=\"muted\">No backups configured. Use the <a href=\"/\">web UI</a> to set up backup schedules.</p>");
        } else {
            if !config.schedules.is_empty() {
                body.push_str("<h2>Schedules</h2>");
                body.push_str("<table>");
                body.push_str("<tr><th>Name</th><th>Frequency</th><th>Time</th><th>Storage</th><th>Enabled</th></tr>");
                for s in &config.schedules {
                    body.push_str(&format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        esc(&s.name),
                        format!("{:?}", s.frequency).to_lowercase(),
                        esc(&s.time),
                        format!("{}", s.storage.storage_type),
                        if s.enabled { "<span class=\"online\">yes</span>" } else { "no" },
                    ));
                }
                body.push_str("</table>");
            }

            if !config.entries.is_empty() {
                body.push_str("<h2>Backup History</h2>");
                body.push_str("<table>");
                body.push_str("<tr><th>Target</th><th>Type</th><th>Storage</th><th>Date</th><th>Size</th><th>Status</th></tr>");
                // Show last 20 entries
                for e in config.entries.iter().rev().take(20) {
                    let status_str = format!("{:?}", e.status).to_lowercase();
                    let status_cls = if e.status == crate::backup::BackupStatus::Completed { "online" } else { "stopped" };
                    body.push_str(&format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><span class=\"{}\">{}</span></td></tr>",
                        esc(&e.target.name), format!("{}", e.target.target_type),
                        format!("{}", e.storage.storage_type),
                        esc(&e.created_at), format_bytes(e.size_bytes),
                        status_cls, esc(&status_str),
                    ));
                }
                body.push_str("</table>");
            }
        }
    } else {
        body.push_str("<p class=\"muted\">Remote node — backup data available via the web UI.</p>");
    }

    let nav = node_nav(&node_id, "backups");
    let html = page(&format!("{} — Backups", node.hostname), &nav, &username, &body);
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// GET /tui/node/{id}/logs — System logs
pub async fn tui_node_logs(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let username = match require_tui_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let node_id = path.into_inner();
    let node = match state.cluster.get_node(&node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().body("Node not found"),
    };

    let mut body = String::new();
    body.push_str(&format!("<h1>{} — System Logs</h1>", esc(&node.hostname)));

    if node.is_self {
        // Read last 100 lines of journalctl
        let output = std::process::Command::new("journalctl")
            .args(["--no-pager", "-n", "100", "--output=short-iso"])
            .output();

        match output {
            Ok(o) => {
                let logs = String::from_utf8_lossy(&o.stdout);
                body.push_str("<p><a href=\"?\">[Refresh]</a></p>");
                body.push_str("<pre style=\"font-size:12px;overflow-x:auto;max-height:600px;border:1px solid #272a33;padding:8px;\">");
                body.push_str(&esc(&logs));
                body.push_str("</pre>");
            }
            Err(_) => {
                body.push_str("<p class=\"warn\">Could not read system logs (journalctl not available).</p>");
            }
        }
    } else {
        body.push_str("<p class=\"muted\">Remote node — logs not available from here.</p>");
    }

    let nav = node_nav(&node_id, "logs");
    let html = page(&format!("{} — Logs", node.hostname), &nav, &username, &body);
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// GET /tui/containers — All containers across the datacenter
pub async fn tui_all_containers(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let username = match require_tui_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let nodes = state.cluster.get_all_nodes();
    let mut body = String::new();
    body.push_str("<h1>All Containers</h1>");

    // Local containers
    let self_node = nodes.iter().find(|n| n.is_self);
    if let Some(sn) = self_node {
        let docker = crate::containers::docker_list_all();
        let lxc = crate::containers::lxc_list_all();

        if !docker.is_empty() {
            body.push_str(&format!("<h2>Docker — {}</h2>", esc(&sn.hostname)));
            body.push_str("<table>");
            body.push_str("<tr><th>Name</th><th>Image</th><th>State</th><th>IP</th></tr>");
            for c in &docker {
                let cls = if c.state == "running" { "running" } else { "stopped" };
                body.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td><span class=\"{}\">{}</span></td><td>{}</td></tr>",
                    esc(&c.name), esc(&c.image), cls, esc(&c.state), esc(&c.ip_address),
                ));
            }
            body.push_str("</table>");
        }

        if !lxc.is_empty() {
            body.push_str(&format!("<h2>LXC — {}</h2>", esc(&sn.hostname)));
            body.push_str("<table>");
            body.push_str("<tr><th>Name</th><th>State</th><th>IP</th></tr>");
            for c in &lxc {
                let cls = if c.state == "running" { "running" } else { "stopped" };
                body.push_str(&format!(
                    "<tr><td>{}</td><td><span class=\"{}\">{}</span></td><td>{}</td></tr>",
                    esc(&c.name), cls, esc(&c.state), esc(&c.ip_address),
                ));
            }
            body.push_str("</table>");
        }
    }

    // Remote node container counts
    let remote_nodes: Vec<_> = nodes.iter().filter(|n| !n.is_self && n.online).collect();
    if !remote_nodes.is_empty() {
        body.push_str("<h2>Remote Nodes</h2>");
        body.push_str("<table>");
        body.push_str("<tr><th>Node</th><th>Docker</th><th>LXC</th></tr>");
        for n in &remote_nodes {
            body.push_str(&format!(
                "<tr><td><a href=\"/tui/node/{}/containers\">{}</a></td><td>{}</td><td>{}</td></tr>",
                esc(&n.id), esc(&n.hostname), n.docker_count, n.lxc_count,
            ));
        }
        body.push_str("</table>");
    }

    let html = page("All Containers", &dc_nav("containers"), &username, &body);
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// GET /tui/backups — Cluster backup overview
pub async fn tui_all_backups(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let username = match require_tui_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let mut body = String::new();
    body.push_str("<h1>Backups</h1>");

    let config = crate::backup::load_config();
    if config.schedules.is_empty() && config.entries.is_empty() {
        body.push_str("<p class=\"muted\">No backups configured on this node.</p>");
    } else {
        if !config.schedules.is_empty() {
            body.push_str("<h2>Schedules</h2>");
            body.push_str("<table>");
            body.push_str("<tr><th>Name</th><th>Frequency</th><th>Time</th><th>Storage</th><th>Enabled</th></tr>");
            for s in &config.schedules {
                body.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc(&s.name), format!("{:?}", s.frequency).to_lowercase(), esc(&s.time),
                    format!("{}", s.storage.storage_type),
                    if s.enabled { "<span class=\"online\">yes</span>" } else { "no" },
                ));
            }
            body.push_str("</table>");
        }

        if !config.entries.is_empty() {
            body.push_str("<h2>Recent Backups</h2>");
            body.push_str("<table>");
            body.push_str("<tr><th>Target</th><th>Type</th><th>Storage</th><th>Date</th><th>Size</th><th>Status</th></tr>");
            for e in config.entries.iter().rev().take(30) {
                let status_str = format!("{:?}", e.status).to_lowercase();
                let cls = if e.status == crate::backup::BackupStatus::Completed { "online" } else { "stopped" };
                body.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><span class=\"{}\">{}</span></td></tr>",
                    esc(&e.target.name), format!("{}", e.target.target_type),
                    format!("{}", e.storage.storage_type),
                    esc(&e.created_at), format_bytes(e.size_bytes), cls, esc(&status_str),
                ));
            }
            body.push_str("</table>");
        }
    }

    let html = page("Backups", &dc_nav("backups"), &username, &body);
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// GET /tui/settings — Settings overview
pub async fn tui_settings(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let username = match require_tui_auth(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let nodes = state.cluster.get_all_nodes();
    let mut body = String::new();
    body.push_str("<h1>Settings</h1>");

    body.push_str("<div class=\"card\">");
    body.push_str(&format!("WolfStack v{}<br>", env!("CARGO_PKG_VERSION")));
    body.push_str(&format!("TLS: {}<br>", if state.tls_enabled { "<span class=\"online\">enabled</span>" } else { "disabled" }));
    body.push_str(&format!("Nodes: {}<br>", nodes.len()));
    body.push_str(&format!("Node ID: {}", esc(&state.cluster.self_id)));
    body.push_str("</div>");

    body.push_str("<h2>Cluster Nodes</h2>");
    body.push_str("<table>");
    body.push_str("<tr><th>ID</th><th>Hostname</th><th>Address</th><th>Cluster</th><th>Status</th></tr>");
    for n in &nodes {
        let status = if n.online { "<span class=\"online\">online</span>" } else { "<span class=\"offline\">offline</span>" };
        let cluster = n.cluster_name.as_deref().unwrap_or("-");
        body.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}:{}</td><td>{}</td><td>{}</td></tr>",
            esc(&n.id), esc(&n.hostname), esc(&n.address), n.port, esc(cluster), status,
        ));
    }
    body.push_str("</table>");

    body.push_str("<p class=\"muted\">Full settings available in the <a href=\"/\">web UI</a>.</p>");

    let html = page("Settings", &dc_nav("settings"), &username, &body);
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// GET /tui/node/{id}/containers/docker/{name}/{action} — Docker container action
pub async fn tui_docker_action(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String, String)>,
) -> HttpResponse {
    let _username = match require_tui_operator(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let (node_id, container_name, action) = path.into_inner();

    let node = match state.cluster.get_node(&node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().body("Node not found"),
    };

    if !node.is_self {
        return HttpResponse::BadRequest().body("Can only control containers on the local node");
    }

    let _result = match action.as_str() {
        "start" => crate::containers::docker_start(&container_name),
        "stop" => crate::containers::docker_stop(&container_name),
        "restart" => crate::containers::docker_restart(&container_name),
        _ => return HttpResponse::BadRequest().body("Invalid action"),
    };
    // Brief pause to let Docker process the action
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    HttpResponse::Found()
        .append_header(("Location", format!("/tui/node/{}/containers", node_id)))
        .finish()
}

/// GET /tui/node/{id}/containers/lxc/{name}/{action} — LXC container action
pub async fn tui_lxc_action(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<(String, String, String)>,
) -> HttpResponse {
    let _username = match require_tui_operator(&req, &state) {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let (node_id, container_name, action) = path.into_inner();

    let node = match state.cluster.get_node(&node_id) {
        Some(n) => n,
        None => return HttpResponse::NotFound().body("Node not found"),
    };

    if !node.is_self {
        return HttpResponse::BadRequest().body("Can only control containers on the local node");
    }

    let _result = match action.as_str() {
        "start" => crate::containers::lxc_start(&container_name),
        "stop" => crate::containers::lxc_stop(&container_name),
        "restart" => crate::containers::lxc_restart(&container_name),
        _ => return HttpResponse::BadRequest().body("Invalid action"),
    };
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    HttpResponse::Found()
        .append_header(("Location", format!("/tui/node/{}/lxc", node_id)))
        .finish()
}

// ─── Route registration ───

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        .route("/tui", web::get().to(tui_dashboard))
        .route("/tui/login", web::get().to(tui_login_page))
        .route("/tui/login", web::post().to(tui_login_submit))
        .route("/tui/logout", web::get().to(tui_logout))
        .route("/tui/containers", web::get().to(tui_all_containers))
        .route("/tui/backups", web::get().to(tui_all_backups))
        .route("/tui/settings", web::get().to(tui_settings))
        .route("/tui/node/{id}/overview", web::get().to(tui_node_overview))
        .route("/tui/node/{id}/containers", web::get().to(tui_node_containers))
        .route("/tui/node/{id}/lxc", web::get().to(tui_node_lxc))
        .route("/tui/node/{id}/services", web::get().to(tui_node_services))
        .route("/tui/node/{id}/storage", web::get().to(tui_node_storage))
        .route("/tui/node/{id}/networking", web::get().to(tui_node_networking))
        .route("/tui/node/{id}/backups", web::get().to(tui_node_backups))
        .route("/tui/node/{id}/logs", web::get().to(tui_node_logs))
        .route("/tui/node/{id}/containers/docker/{name}/{action}", web::get().to(tui_docker_action))
        .route("/tui/node/{id}/containers/lxc/{name}/{action}", web::get().to(tui_lxc_action));
}
