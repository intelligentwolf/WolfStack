// Written by Paul Clevett
// (C)Copyright IntelligentWolf Ltd
// https://wolf.uk.com

//! WolfStack — Server Management Platform for the Wolf Software Suite
//!
//! A Proxmox-like management dashboard that:
//! - Monitors system health (CPU, RAM, disk, network)
//! - Installs and manages Wolf suite components (WolfNet, WolfDisk, etc.)
//! - Manages systemd services
//! - Handles SSL certificates via Certbot
//! - Communicates with other WolfStack nodes over WolfNet or direct IP

use crate::node_identity::PeerAuth;
mod api;
mod stack_transfer;
mod agent;
mod diagnostics;
mod ai;
mod auth;
mod monitoring;
mod installer;
mod containers;
mod console;
mod vr_terminal;
mod storage;
mod networking;
mod backup;
mod secrets;
mod browse;
mod galera;
mod postgres_ha;
mod mail_tier;
mod site_failover;
mod wolfscale;
mod vms;
mod proxmox;
mod xo;
mod truenas;
mod unraid;
mod pools;
mod mysql_editor;
mod appstore;
mod alerting;
mod notify;
mod predictive;
mod wolfrun;
mod wolfha;
mod statuspage;
mod ceph;
mod gluster;
mod gateway;
mod federation;
mod array;
mod configurator;
mod patreon;
mod kubernetes;
mod icons;
mod tui;
mod wolfflow;
mod wolfagents;
mod wolfhost;
mod discord_bot;
mod telegram_bot;
mod whatsapp_bot;
mod mcp;
mod wolfnote;
mod wolffunctions;
mod wolfusb;
mod dashboard_sync;
mod paths;
mod mtls;
mod loghub;
mod ports;
mod reverse_proxy;
mod control_panel;
mod github_backup;
mod deps;
mod exposure;
mod bruteforce;
mod mail_relay;
mod ups;
mod systemcheck;
mod security;
mod ssh_keys;
mod secret_audit;
mod secret_rotation;
mod at_rest_crypto;
mod services_discovery;
mod cluster_browser;
mod compat;
mod support;
mod danger;
mod plugins;
mod sql_connections;
mod netguard;
mod certbot;
mod dns_providers;
mod edge;
mod threat_intel;
mod security_audit;
mod scan_detector;
mod antivirus;
mod abuse_report;
mod diag;
mod netaddr;
mod local_ca;
#[allow(dead_code)]
mod integrations;
mod cluster_join;
mod node_identity;

use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};
use clap::{CommandFactory, Parser};
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use std::time::Duration;
use tracing::{info, warn};

/// WolfStack — IntelligentWolf Management Platform
#[derive(Parser)]
#[command(name = "wolfstack", version, about = "Server management for the Wolf software suite")]
struct Cli {
    /// Port to listen on (overrides ports.json `api`; defaults to 8553)
    #[arg(short, long)]
    port: Option<u16>,

    /// Bind address (IPv4 or IPv6 — e.g. 0.0.0.0, 192.168.1.5, ::, 2001:db8::1)
    #[arg(short, long, default_value = "0.0.0.0")]
    bind: String,

    /// TLS certificate path (PEM). Auto-detected from Let's Encrypt if not set.
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS private key path (PEM). Auto-detected from Let's Encrypt if not set.
    #[arg(long)]
    tls_key: Option<String>,

    /// Domain name for auto-detecting Let's Encrypt certificates
    #[arg(long)]
    tls_domain: Option<String>,

    /// Disable TLS and run in HTTP-only mode
    #[arg(long)]
    no_tls: bool,

    /// Print this server's join token and exit
    #[arg(long)]
    show_token: bool,

    /// Switch an unused portmapper (rpcbind) off and exit. Run by setup.sh
    /// after the package step: `nfs-common` (needed to mount NFS shares) pulls
    /// rpcbind in as a dependency, and its socket unit listens on 0.0.0.0:111
    /// — a public-facing host then answers portmapper queries from the whole
    /// internet, which is a 7-28x UDP amplification vector (CERT TA14-017A).
    /// Refuses, and says why, on a host that actually uses RPC.
    #[arg(long)]
    secure_rpcbind: bool,

    /// Run in agent-only mode — exposes the cluster API for a master node to
    /// proxy through, but does NOT serve the management SPA. Use this on
    /// every node except the one you want to log into. Persisted via the
    /// systemd ExecStart line written by setup.sh --agent.
    #[arg(long)]
    agent: bool,

    /// Run the daemon in the foreground from a shell instead of under
    /// systemd. Without this, a shell launch prints this help and exits
    /// rather than starting a second daemon alongside the service. Use it
    /// for debugging, or on a host with no systemd (a container) where you
    /// supervise the process yourself. Stop `wolfstack.service` first —
    /// otherwise the two instances fight over every port.
    #[arg(long)]
    foreground: bool,

    /// Print available WolfRouter recovery snapshots and exit. Use when
    /// the WolfRouter UI itself isn't reachable (or you want to confirm
    /// what's available before logging in). Lists each snapshot with
    /// its kind (backup / quarantine), age, size, and whether it
    /// parses cleanly with this binary.
    #[arg(long)]
    wolfrouter_recover: bool,

    /// Restore a specific WolfRouter recovery snapshot to the live
    /// config.json. Pass the absolute path printed by
    /// `--wolfrouter-recover`. The currently-live config (if any)
    /// is rotated to a new `.bak.<ts>` so the rollback itself is
    /// reversible. After running this, restart the wolfstack service
    /// (`systemctl restart wolfstack`) so the restored config takes
    /// effect in the running ruleset.
    #[arg(long, value_name = "PATH")]
    wolfrouter_restore: Option<String>,

    /// Emergency unblock: remove an IP from EVERY WolfStack enforcement
    /// surface — login-lockout / NMAP-protection kernel blocks, both
    /// threat-intelligence blocklists — and persist it to the threat-intel
    /// allowlists so the next feed sync can't re-block it. Run this from
    /// SSH when you can reach the server but not the dashboard (e.g. a
    /// feed update listed your own IP). Takes effect immediately; no
    /// service restart needed.
    #[arg(long, value_name = "IP")]
    unblock: Option<String>,

    /// Wipe this node's cluster membership state and exit. Deletes
    /// `self_cluster.json`, `nodes.json`, `deleted_nodes.json`, and
    /// `node_id` so that the daemon comes back up as a fresh
    /// single-node cluster on its next start. Use this when a node is
    /// stranded in a phantom old cluster (typically because the cluster
    /// name was changed on another node while this one was offline) and
    /// the management UI can't reach it cross-cluster to recover.
    /// Refuses to run while the `wolfstack` systemd unit is active —
    /// stop it first so file ops don't race the running daemon's saves.
    #[arg(long)]
    leave_cluster: bool,

    /// Modifier for `--leave-cluster`: also rotate the cluster-secret
    /// file (`/etc/wolfstack/custom-cluster-secret`) so old peers can
    /// no longer authenticate inter-node calls to this server. Has no
    /// effect without `--leave-cluster`.
    #[arg(long)]
    rotate_cluster_secret: bool,
}

/// Was this process started by systemd as a service?
///
/// `INVOCATION_ID` alone is not enough. systemd sets it for every unit it
/// launches, and **it is inherited by everything that unit spawns** — including
/// the terminal emulator of a desktop session (an `app-*.scope` under
/// `user@N.service`) and any script run from a unit or timer. A shell in that
/// position looks exactly like a service to a bare environment check, and would
/// sail past the guard to start the second daemon it exists to prevent.
///
/// The cgroup path disambiguates cleanly: a real service lives under
/// `system.slice`, every user session under `user.slice`. We use it in one
/// direction only — to downgrade service→shell, never the reverse — because
/// wrongly refusing a genuine service start is far worse than missing a manual
/// launch. That asymmetry is safe here: wolfstack needs root (it reads
/// /etc/shadow), so it can never legitimately run as a `systemctl --user` unit
/// inside `user.slice`.
///
/// `cgroup` is the contents of `/proc/self/cgroup`, or `None` if unreadable —
/// in which case we fall back to the environment variable alone rather than
/// risk refusing to boot.
fn systemd_service_context(invocation_id_present: bool, cgroup: Option<&str>) -> bool {
    if !invocation_id_present {
        return false;
    }
    match cgroup {
        Some(c) => !c.contains("/user.slice"),
        None => true,
    }
}

/// [`systemd_service_context`] against the live process.
fn detect_systemd_service_context() -> bool {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok();
    systemd_service_context(
        std::env::var_os("INVOCATION_ID").is_some(),
        cgroup.as_deref(),
    )
}

/// Should this invocation refuse to start the daemon and print help instead?
///
/// ONLY for a bare `wolfstack` with no arguments at all, outside systemd.
///
/// The original rule refused every non-systemd launch unless `--foreground` was
/// passed, and that broke every host WITHOUT systemd. Unraid runs the agent from
/// a bash supervisor as `wolfstack --agent`: no INVOCATION_ID, no --foreground,
/// so the guard printed help and exited 1 in a 60-second restart loop, and the
/// node never came up (customer report, 25.10.14, 2026-08-07). Docker images and
/// any other non-systemd supervisor would hit exactly the same wall.
///
/// Passing ANY argument — `--agent`, `--port`, `--bind`, `--foreground` — is a
/// deliberate invocation and is honoured. The thing actually worth stopping is
/// someone typing `wolfstack` at a prompt to see if the service is up, and that
/// is precisely the zero-argument case.
/// A bare `wolfstack` typed at a prompt is nearly always someone checking
/// whether the service is up, and answering that by starting a second daemon
/// is actively harmful — it contends for every port with the real one, and the
/// port-fallback scans drift the node's config on the way past.
///
/// Only reached after the one-shot modes (`--show-token`, `--unblock`,
/// `--leave-cluster`, `--wolfrouter-*`) have already returned, so this never
/// blocks an operator's break-glass commands.
fn should_refuse_shell_launch(running_as_service: bool, foreground: bool, has_args: bool) -> bool {
    !running_as_service && !foreground && !has_args
}

/// Agent-mode root handler — returned for any path the SPA would normally
/// serve. The node is functional (cluster API still bound) but this user
/// hit the wrong door: they should manage it from the cluster's master
/// node UI, not by hitting this node directly.
async fn agent_index_handler() -> HttpResponse {
    let html = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WolfStack Agent Node</title>
<style>
body { font-family: system-ui, -apple-system, sans-serif; max-width: 640px; margin: 8vh auto; padding: 0 24px; color: #1a1a1a; line-height: 1.55; }
h1 { color: #dc2626; margin-bottom: 4px; }
.muted { color: #666; font-size: 14px; }
.box { background: #f5f5f5; border-left: 3px solid #dc2626; padding: 16px 20px; border-radius: 4px; margin: 24px 0; }
code { background: #ececec; padding: 2px 6px; border-radius: 3px; font-size: 13px; }
ol { padding-left: 22px; }
ol li { margin-bottom: 8px; }
</style>
</head>
<body>
<h1>WolfStack Agent Node</h1>
<p class="muted">This server is running in agent-only mode &mdash; the cluster API is up but the management UI is intentionally not served from this node.</p>
<div class="box">
<strong>Manage this node from your master server&rsquo;s UI.</strong> Log into the management node you set up first, then add this server via <em>Add Node</em> using its hostname or IP and the join token below.
</div>
<ol>
<li>Find this node&rsquo;s join token: <code>sudo cat /etc/wolfstack/join-token</code></li>
<li>Open the management UI on your master server (port 8553).</li>
<li>Cluster &rarr; Add Node &rarr; paste the token, hostname, and IP.</li>
</ol>
<p class="muted"><strong>If you rotated the cluster secret</strong> on the master (Settings &rarr; Security), copy <code>/etc/wolfstack/custom-cluster-secret</code> from the master to this node before the first connection &mdash; otherwise inter-node calls will fail X-WolfStack-Secret authentication.</p>
<p class="muted">To convert this node into a full management server, edit the systemd unit at <code>/etc/systemd/system/wolfstack.service</code>, remove the <code>--agent</code> flag from <code>ExecStart=</code>, then run <code>sudo systemctl daemon-reload &amp;&amp; sudo systemctl restart wolfstack</code>.</p>
</body>
</html>"#;
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// Web-UI pages that are only meaningful with a live operator session. Each is
/// served through `gated_page`, so a logged-out or expired browser gets the
/// login screen instead of an app shell whose every API call 401s.
///
/// `/` and `/index.html` BOTH map to the dashboard because every login path
/// lands the browser on one or the other: the password form and the OIDC
/// callback redirect to `/index.html`, the passkey flow to `/`. Only `/` used
/// to be gated — `/index.html` fell through to the `actix_files` service below
/// and handed the full dashboard to a logged-out browser, which then painted a
/// half-rendered page while its API calls came back 401. That is the "session
/// timed out and I got a broken page instead of the login screen" report.
///
/// console.html and vnc.html are here too: both are opened from inside the
/// authenticated dashboard (`window.open`/hidden iframe, same-origin, so the
/// cookie always rides along) and neither handles a 401 — on a dead session
/// they used to render a black terminal or an empty VNC canvas forever.
///
/// Anything not listed here is public and served straight off disk by the
/// fallback service: login.html, /css, /js, /images, manifest.json, sw.js, and
/// wolfnet-global.html — that last one is a landing page that deliberately
/// works logged-out, showing its own "not authenticated, log in →" panel when
/// its node lookup comes back 401.
const GATED_PAGES: &[(&str, &str)] = &[
    ("/",             "index.html"),
    ("/index.html",   "index.html"),
    ("/console.html", "console.html"),
    ("/vnc.html",     "vnc.html"),
];

/// Serve `file` from the web directory to a request carrying a valid session
/// cookie; serve login.html to everyone else.
///
/// The logged-out answer is a 200 carrying login.html's body under the URL that
/// was requested, NOT a 302 to /login.html. That is deliberate: the service
/// worker's `cache.addAll(SHELL_ASSETS)` covers `/` and `/index.html`, and
/// `Cache.put` rejects redirected responses — a redirect here is what broke SW
/// installs the last time this path 302'd (see the comment in web/sw.js). All
/// of login.html's own asset URLs are root-relative, so it renders identically
/// from `/`, `/index.html` or `/console.html`, and submitting the form lands on
/// `/index.html` as usual.
async fn gated_page(
    req: HttpRequest,
    state: web::Data<api::AppState>,
    file: &'static str,
) -> HttpResponse {
    let authenticated = req.cookie("wolfstack_session")
        .and_then(|c| state.sessions.validate(c.value()))
        .is_some();

    let name = if authenticated { file } else { "login.html" };
    let path = format!("{}/{}", find_web_dir(), name);

    // index.html is ~600 KB — read it off the worker thread. A synchronous
    // read here parks an actix worker on disk I/O for every page load.
    //
    // No cache-busting rewrite happens here any more: the two `.replace()`
    // calls this function used to run matched nothing (index.html carries
    // `?v=…` on both the stylesheet and app.js already, so the literals
    // `/css/style.css"` and `/js/app.js"` no longer appear in the file). The
    // busting itself is still done, by index.html's own inline Date.now()
    // query strings.
    match web::block(move || std::fs::read_to_string(&path)).await {
        Ok(Ok(content)) => HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            // This URL renders either the dashboard or the login page depending
            // purely on a cookie, so no cache may hand one to the other.
            .insert_header(("Cache-Control", "no-store"))
            .insert_header(("Vary", "Cookie"))
            .body(content),
        _ => HttpResponse::InternalServerError()
            .content_type("text/plain; charset=utf-8")
            .body(format!("Web UI not found: {} is missing from the WolfStack web directory.", name)),
    }
}

/// Register the operator web UI: session-gated HTML pages first, then the
/// public static tree. Shared by all three non-agent listeners so the gate
/// cannot drift between the HTTPS, inter-node and plain-HTTP servers.
fn configure_web_ui(cfg: &mut web::ServiceConfig, web_dir: &str) {
    for &(route, file) in GATED_PAGES {
        cfg.route(
            route,
            web::get().to(move |req: HttpRequest, state: web::Data<api::AppState>| {
                gated_page(req, state, file)
            }),
        );
    }
    cfg.service(actix_files::Files::new("/", web_dir).index_file("login.html"));
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("wolfstack=info".parse().unwrap())
                .add_directive("actix_web=info".parse().unwrap())
                .add_directive("actix_http=off".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    // --show-token: print join token and exit (for CLI access without web UI)
    if cli.show_token {
        let token = api::load_join_token();
        println!("{}", token);
        return Ok(());
    }

    // --secure-rpcbind: close an open portmapper and exit. One implementation
    // shared with the inbox's one-click action (predictive::rpcbind) rather
    // than a second copy of the same decision in shell.
    if cli.secure_rpcbind {
        let usage = predictive::rpcbind::inspect();
        match predictive::rpcbind::lock_down() {
            Ok(msg) => {
                println!("{}", msg);
                return Ok(());
            }
            Err(e) => {
                // Not a fatal install error: the host needs RPC, or systemd
                // refused. Say what was found and what to do instead, and exit
                // non-zero so a script can tell the difference.
                eprintln!("rpcbind left as it is: {}", e);
                eprintln!("what was found: {}", usage.summary());
                std::process::exit(1);
            }
        }
    }

    // --wolfrouter-recover: print recovery snapshots and exit. Used
    // when the WolfRouter UI is unreachable (e.g. the wipe regression
    // happened and the user can't get to the rollback banner because
    // the running config is empty). Prints a copy-pasteable
    // `--wolfrouter-restore <path>` invocation per snapshot.
    if cli.wolfrouter_recover {
        let snapshots = networking::router::list_recovery_snapshots();
        if snapshots.is_empty() {
            println!("No WolfRouter recovery snapshots found in {}.",
                     networking::router::ROUTER_DIR);
            println!("Looked for: config.json.bak.<unix-ts>  (rolling backups)");
            println!("            config.json.broken-<unix-ts>  (quarantined parse failures)");
            println!();
            println!("If you upgraded from a pre-fix build the wipe happened");
            println!("BEFORE rolling backups existed, so there's nothing here.");
            println!("Try `wolfstack` then visit /api/router/recovery/reconstruct");
            println!("from the WolfRouter UI to rebuild from on-disk artefacts");
            println!("(dnsmasq.d snippets + /etc/ppp/peers files).");
            return Ok(());
        }
        println!("WolfRouter recovery snapshots (newest first):");
        println!();
        for s in &snapshots {
            let age = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs().saturating_sub(s.timestamp))
                .unwrap_or(0);
            let parses = if s.parses { "parses OK " } else { "DOES NOT PARSE" };
            println!("  [{}] {}  ({} bytes, {}s old, {})",
                     s.kind, s.path, s.size_bytes, age, parses);
        }
        println!();
        println!("Restore the newest one with:");
        println!("    sudo wolfstack --wolfrouter-restore {}",
                 snapshots[0].path);
        println!();
        println!("(Then `sudo systemctl restart wolfstack` to apply.)");
        return Ok(());
    }

    // --wolfrouter-restore <path>: atomic restore of a snapshot to the
    // live config.json, then exit. The next service start picks it up.
    if let Some(snapshot_path) = cli.wolfrouter_restore.as_deref() {
        match networking::router::restore_recovery_snapshot(snapshot_path) {
            Ok(()) => {
                println!("Restored {} to live WolfRouter config.", snapshot_path);
                println!("Run `sudo systemctl restart wolfstack` to apply the");
                println!("restored config in the running ruleset.");
                return Ok(());
            }
            Err(e) => {
                eprintln!("Restore failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    // --unblock <ip>: emergency removal of an address from every
    // enforcement surface, then exit. The operator's break-glass path
    // when a threat-intel feed update blocks their own client IP
    // (klas 2026-07-05 — dashboard unreachable, SSH fine).
    if let Some(raw) = cli.unblock.as_deref() {
        if !deps::is_root() {
            eprintln!("--unblock needs root (it edits ipsets, iptables, and /etc/wolfstack). Re-run with sudo.");
            std::process::exit(1);
        }
        match raw.trim().parse::<std::net::IpAddr>() {
            Ok(parsed) => {
                let ip = parsed.to_canonical().to_string();
                println!("Unblocking {} from every WolfStack enforcement surface:", ip);
                println!("{}", auth::kernel_unblock_ip(&ip).describe());
                // The kernel rule is only half of a login lockout. The half
                // that refuses the password lives in the running daemon's
                // memory and cannot be reached from this process — ask the
                // daemon to clear it, then prune the on-disk snapshot so a
                // restart can't restore what we just removed. ORDER MATTERS:
                // the daemon re-persists the snapshot from memory when it
                // unblocks, so pruning first would simply be overwritten.
                match auth::cli_clear_daemon_lockout(&ip).await {
                    Ok(()) => println!("  ✓ login-lockout: cleared in the running daemon — logins accepted now"),
                    Err(e) => {
                        println!("  • login-lockout: could not reach the local daemon ({})", e);
                        println!("    Clearing on disk instead — it will be gone once the service starts.");
                    }
                }
                if auth::cli_prune_persisted_lockout(&ip) {
                    println!("  ✓ login-lockout: removed from auth-active-lockouts.json (a restart can't bring it back)");
                }
                predictive::threat_intel::cli_unblock_ip(&ip);
                threat_intel::cli_unblock_ip(&ip);
                println!("Done. Changes are live now; the allowlist entries stop the next feed sync from re-blocking it.");
                return Ok(());
            }
            Err(_) => {
                eprintln!("--unblock: '{}' is not a valid IP address", raw);
                std::process::exit(2);
            }
        }
    }

    // --leave-cluster: wipe this node's cluster membership state and exit.
    // Refuses while the wolfstack service is active to avoid the running
    // daemon's `save_nodes()` racing the file deletions back into existence.
    if cli.leave_cluster {
        match agent::leave_is_service_active() {
            Some(true) => {
                eprintln!("Refusing to wipe cluster state while wolfstack.service is active.");
                eprintln!("Stop it first, then re-run this command:");
                eprintln!();
                eprintln!("    sudo systemctl stop wolfstack");
                eprintln!("    sudo wolfstack --leave-cluster{}",
                          if cli.rotate_cluster_secret { " --rotate-cluster-secret" } else { "" });
                eprintln!("    sudo systemctl start wolfstack");
                std::process::exit(1);
            }
            Some(false) => {}
            None => {
                eprintln!("warning: could not query systemctl — proceeding anyway. If the");
                eprintln!("         daemon is running it may re-create the files we delete.");
            }
        }

        let result = agent::leave_wipe_membership_files();
        println!("Cluster leave: wiping local membership state.");
        if let Some(prev) = &result.previous_cluster_name {
            println!("  Previous cluster name: {}", prev);
        }
        for f in &result.files {
            if f.cleared {
                println!("  removed  {}", f.path);
            } else if f.already_absent {
                println!("  (absent) {}", f.path);
            } else if let Some(err) = &f.error {
                eprintln!("  FAILED   {}  ({})", f.path, err);
            }
        }
        let any_failed = result.files.iter().any(|f| f.error.is_some());

        if cli.rotate_cluster_secret {
            // ORDERING: capture OLD on-disk secret before save so this
            // node's local at-rest stores (SQL / OIDC / integrations /
            // DNS / cloud / XO — none of them membership files) can be
            // re-keyed old→new. The node comes back up standalone; without
            // this its stored credentials would be undecryptable.
            let old_secret = auth::load_cluster_secret();
            let new_secret = auth::generate_cluster_secret();
            match auth::save_cluster_secret(&new_secret) {
                Ok(()) => {
                    println!("  rotated  {} (new secret written)",
                             paths::get().cluster_secret);
                    let report = secret_rotation::reencrypt_all_at_rest(&old_secret, &new_secret);
                    println!("  re-keyed {} at-rest secret(s){}",
                             report.total(),
                             if report.errors.is_empty() { String::new() }
                             else { format!(" ({} store error(s): {})",
                                            report.errors.len(), report.errors.join("; ")) });
                }
                Err(e) => {
                    eprintln!("  FAILED   rotate cluster secret: {}", e);
                    std::process::exit(2);
                }
            }
        }

        println!();
        if any_failed {
            eprintln!("Done with errors — see above. The daemon may still come up");
            eprintln!("partially cleared on next start; investigate the failed paths.");
            std::process::exit(2);
        }
        println!("Done. Start the daemon to bring this node up as a fresh");
        println!("single-node cluster:");
        println!();
        println!("    sudo systemctl start wolfstack");
        return Ok(());
    }

    if cli.rotate_cluster_secret {
        eprintln!("--rotate-cluster-secret has no effect without --leave-cluster.");
        eprintln!("To rotate the cluster secret on a running cluster, use the");
        eprintln!("management UI: Settings → Security → Generate New Cluster Secret.");
        std::process::exit(1);
    }

    // A daemon launch is expected to come from systemd. A bare `wolfstack`
    // typed at a shell is nearly always someone checking whether the service
    // is up — and silently starting a SECOND daemon is the worst possible
    // answer to that question. It fights the real one for every port, and the
    // status / inter-node fallback scans walk ports.json upward on the way
    // past (see ports::should_persist_fallback). A test node reached
    // inter_node 8555 / status 8551 exactly that way, which sent its operator
    // hunting for a dashboard that had never moved off 8553.
    //
    // So: no systemd, no explicit --foreground, no daemon. Print help and get
    // out of the way. Every one-shot mode (--show-token, --unblock,
    // --leave-cluster, --wolfrouter-*) has already returned above and is
    // unaffected — those are precisely the things an operator runs by hand.
    //
    // See systemd_service_context for how a unit launch is told apart from a
    // shell one — INVOCATION_ID is necessary but NOT sufficient, because a
    // desktop terminal or a unit-spawned script inherits it.
    let running_as_systemd_service = detect_systemd_service_context();
    // std::env::args() includes argv[0], so >1 means the operator passed
    // something. Read from the real argv rather than inspecting `cli`, whose
    // defaults make "not supplied" and "supplied the default" indistinguishable.
    let has_cli_args = std::env::args().len() > 1;
    if should_refuse_shell_launch(running_as_systemd_service, cli.foreground, has_cli_args) {
        eprintln!("wolfstack is a system service — it is not meant to be started by hand.");
        eprintln!();
        eprintln!("Refusing to launch a second daemon alongside the running one.");
        eprintln!("To check on it:");
        eprintln!();
        // Not every host has systemd — Unraid runs the agent from a bash
        // supervisor, and telling that operator to run journalctl sends them
        // somewhere that does not exist.
        if std::path::Path::new("/run/systemd/system").exists() {
            eprintln!("    systemctl status wolfstack");
            eprintln!("    journalctl -u wolfstack -f");
        } else {
            eprintln!("    pgrep -af 'wolfstack --agent'");
            eprintln!("    tail -f /var/log/wolfstack-agent.log");
        }
        eprintln!();
        eprintln!("The dashboard is HTTPS on the `api` port from /etc/wolfstack/ports.json");
        eprintln!("(8553 by default) — not the status-page or inter-node port.");
        eprintln!();
        eprintln!("If you really do want it in the foreground — debugging, or a host with");
        eprintln!("no systemd — pass --foreground, after stopping the service.");
        eprintln!();
        eprint!("{}", Cli::command().render_help());
        std::process::exit(1);
    }

    // ports.json is the persistent source of truth (the Node Ports UI writes
    // it). A CLI --port is a genuine one-off override ONLY for manual shell
    // launches. setup.sh historically baked --port into the systemd unit, which
    // silently overrode ports.json for BOTH the api port and inter_node (forced
    // to api+1) — making the Node Ports panel a no-op and pinning inter_node to
    // api+1 (the 8554/go2rtc clash). When we are the systemd service we detect
    // that baked flag (INVOCATION_ID is set only for systemd units), reconcile
    // it into ports.json once — preserving any custom/UI value, never moving the
    // port the node currently runs on — and then ignore it so ports.json wins.
    // inter_node here is just the *preferred* value — the actual bind (only on
    // self-signed installs in v23.12+) goes through ports::reserve_inter_node_port
    // and may shift if it's taken by Frigate/MediaMTX/etc.
    // `running_as_systemd_service` is bound above, at the shell-launch guard.
    let port_cfg = ports::PortConfig::load();
    let status_preferred = port_cfg.status; // captured before port_cfg is moved below
    let resolved = ports::resolve_api_ports(cli.port, running_as_systemd_service, port_cfg);
    if let Some(cfg_to_save) = &resolved.persist {
        match cfg_to_save.save() {
            Ok(()) => info!(
                "Reconciled systemd unit --port into ports.json (api={}, inter_node={}); \
                 ports.json is now authoritative — change ports via the Node Ports panel",
                resolved.api, resolved.inter_node_pref
            ),
            Err(e) => warn!("failed to persist reconciled ports.json: {}", e),
        }
    }
    let api_port: u16 = resolved.api;
    let inter_node_pref: u16 = resolved.inter_node_pref;
    // Status-port auto-fallback: try the configured port, scan upward if taken.
    // The service persists the chosen port back to ports.json so restarts are
    // stable; a manual shell launch (which normally finds the port busy because
    // the service itself holds it) uses the fallback for that run only.
    // `|| cli.agent`: on a host with no systemd (Unraid, containers) an agent
    // is supervised and long-lived, but running_as_systemd_service is always
    // false — so a port fallback was never persisted and the node could pick a
    // DIFFERENT inter-node/status port on every restart while its master held
    // the old one. The rule this guards against is a transient shell poke
    // rewriting config; a supervised agent is not that.
    let may_persist_ports = running_as_systemd_service || cli.agent;
    let status_port: u16 = ports::reserve_status_port(
        &cli.bind,
        status_preferred,
        8550..=8599,
        may_persist_ports,
    );

    // Lock down /etc/wolfstack and known sensitive files. Pre-v18.7.27
    // installs left cluster-secret, nodes.json (containing PVE tokens),
    // join-token, license.key world-readable (0644). This is a no-op on
    // already-locked-down installs; on upgraded installs it migrates
    // the permissions in place. See paths::harden_existing for scope.
    // Stage 2 of the cluster-secret migration: if this is a fresh
    // install (no on-disk custom secret + no peers in nodes.json),
    // generate a per-install secret right now so we never start up
    // using the built-in default that every WolfStack installation
    // shares. The helper refuses to act on anything that looks like
    // an existing install — see auth::auto_generate_for_fresh_install.
    // MUST run before the fresh-install check below and before the secret is
    // read. On Unraid the config dir is a symlink into appdata: if the array
    // has not mounted yet, an EXISTING install looks empty, so
    // auto_generate_for_fresh_install would mint a brand-new cluster secret
    // and load_cluster_secret would fall back to the built-in default —
    // either way the node comes up with the wrong identity, reports itself
    // online, and has every proxied request rejected by its peers with 401
    // (klas, 2026-07-31). Returns immediately on a healthy host.
    paths::wait_for_config_dir(120).await;

    // MOVED ABOVE harden_existing and the node-ID block (2026-08-07). Both
    // touch the config dir, and the node ID was being read, regenerated and
    // written 76 lines BEFORE this wait — so on an Unraid box whose array had
    // not mounted, an existing node minted a fresh ws-xxxxxxxx identity on
    // every boot and could not persist it. Exactly the churn this wait was
    // added to prevent for the cluster secret, one field over.

    paths::harden_existing();

    // Load or generate node ID. An empty / whitespace-only file is
    // treated the same as a missing file — pre-fix, an empty file
    // silently produced `node_id = ""`, which then leaked through
    // every StatusReport. Peers stored `self_id: null` for this node
    // forever (poll handler at agent/mod.rs preserves the previous
    // self_id when the incoming string is empty), and any subnet
    // route or other config pinned to this node's self_id became
    // unmatchable in the strict-cluster guard.
    let node_id_file = paths::get().node_id_file;
    let existing = std::fs::read_to_string(&node_id_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let node_id = match existing {
        Some(id) => id,
        None => {
            let id = format!("ws-{}", &uuid::Uuid::new_v4().to_string()[..8]);
            if let Some(dir) = std::path::Path::new(&node_id_file).parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Err(e) = std::fs::write(&node_id_file, &id) {
                tracing::error!("Failed to persist node ID: {}", e);
            }
            id
        }
    };
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // Per-node signing key (generated on first start). Failure is not
    // fatal: the node then runs unsigned, i.e. exactly as before.
    if let Err(e) = node_identity::init(&node_id) {
        tracing::error!("node identity: {} — running without a signing key", e);
    }

    info!("");
    // Start the /api/ready uptime clock before anything else can read it.
    api::init_process_start();

    info!("  🐺 WolfStack v{}", env!("CARGO_PKG_VERSION"));
    info!("  ──────────────────────────────────");
    info!("  Node ID:    {}", node_id);
    info!("  Hostname:   {}", hostname);
    // Scheme mirrors the TLS decision made later in startup: HTTPS is the
    // default since v23.11 (self-signed generated when nothing is found);
    // plain http only when the operator passed --no-tls.
    info!("  Dashboard:  {}://{}", if cli.no_tls { "http" } else { "https" }, netaddr::host_port(&cli.bind, api_port));
    info!("  (C)Copyright IntelligentWolf Ltd — https://wolf.uk.com");
    info!("  By Paul Clevett and my mate Claude - I have Autism");
    // Seed LXC storage paths from any mounted storage that has LXC containers
    if let Ok(entries) = std::fs::read_dir(&paths::get().storage_mount_base) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Check if this mount has LXC containers (subdirs with 'config' files)
                if let Ok(subdirs) = std::fs::read_dir(&path) {
                    for sub in subdirs.flatten() {
                        if sub.path().join("config").exists() && sub.path().join("rootfs").exists() {
                            containers::lxc_register_path(&path.to_string_lossy());
                            break;
                        }
                    }
                }
            }
        }
    }

    // Set kernel networking prerequisites for WolfNet container routing
    containers::wolfnet_init();
    // Ensure lxcbr0 bridge + reapply WolfNet routes in background (can be slow on Proxmox)
    std::thread::spawn(|| {
        containers::ensure_lxc_bridge();
        containers::reapply_wolfnet_routes();
    });


    let _ = auth::auto_generate_for_fresh_install();

    // Load per-installation cluster secret for inter-node authentication
    let cluster_secret = auth::load_cluster_secret();

    // Initialise the shared at-rest crypto module with the active
    // cluster secret. After this point, dns_providers / edge::store /
    // xo can use AES-256-GCM v2 encryption for new credential values;
    // legacy v1 XOR values still decrypt transparently via the
    // fallback path. Must run BEFORE any module that might encrypt.
    at_rest_crypto::init(&cluster_secret);

    // Auto-migrate any legacy v1 (XOR) at-rest credentials to v2 AES-256-GCM now
    // that the crypto module is initialised. Idempotent + backup-on-write, so
    // it's safe on every boot and a no-op once migrated; this is what closes the
    // High "legacy XOR" audit findings on upgraded installs without waiting for
    // the manual operator migration. Must run AFTER at_rest_crypto::init.
    secret_rotation::run_startup_at_rest_migration();

    // Stage 5 of the cluster-secret migration: log whether the
    // built-in default is currently accepted, so operators can see
    // their WOLFSTACK_REJECT_DEFAULT_SECRET env flag is being honoured.
    if !auth::default_secret_accepted() {
        info!("Cluster secret: built-in default REJECTED (WOLFSTACK_REJECT_DEFAULT_SECRET set). \
               Only the per-install secret will authenticate inter-node calls.");
    }
    if secret_audit::is_using_default_cluster_secret() {
        warn!("Cluster secret: this node is running on the BUILT-IN DEFAULT secret. \
               That value is a constant in the source, so any host that can reach this \
               node's inter-node port could authenticate as a cluster peer. Rotate to a \
               per-install secret now — Settings → Security → Rotate cluster secret — \
               especially if this node is network-reachable.");
    }

    // Public IP detection runs in the BACKGROUND, never in front of the bind.
    //
    // This used to be awaited here: four external services tried serially with
    // a 3-second timeout each — up to 12 seconds, and measured at 5.3s on
    // wolfstack-1 — during which nothing is listening on 8553 and every client
    // gets connection-refused. That is the bulk of the 7.4-second dark window
    // after an upgrade (Started 11:47:57.13, listener bound 11:48:04.52), and
    // it is the window that leaves a reloading dashboard bouncing off a closed
    // port. The rule directly below this — monitoring "must not be able to
    // block the HTTP bind" — always applied here too; this call simply predated
    // it.
    //
    // Nothing needs the address to bind. Its only consumer is
    // `cluster.update_self`, which runs on a repeating tick, so a value that
    // arrives a second or two later is advertised on the very next cycle. Until
    // then the node advertises `None`, which is what it already did whenever
    // detection failed.
    // WolfNotify — container/VM lifecycle events -> rules -> the existing
    // alerting channels. Supervised internally: the docker event stream dies
    // whenever the daemon restarts, and a source that has silently stopped is
    // worse than none, so it reconnects with backoff and reports itself
    // degraded when it can't. No rules configured = no work done.
    {
        let notify_node = std::process::Command::new("hostname")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        let poll_node = notify_node.clone();
        tokio::spawn(async move {
            notify::run_docker_source(notify_node).await;
        });
        // LXC, libvirt and Proxmox have no event stream — polled instead.
        tokio::spawn(async move {
            notify::run_poll_sources(poll_node).await;
        });
    }

    let public_ip: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
    {
        let slot = public_ip.clone();
        tokio::spawn(async move {
            let services = [
                "https://api.ipify.org",
                "https://ifconfig.me/ip",
                "https://icanhazip.com",
                "https://checkip.amazonaws.com",
            ];
            let Ok(client) = crate::api::ipv4_only_client_builder()
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(3))
                .build()
            else {
                warn!("public IP: client build failed — detection skipped");
                return;
            };
            for url in &services {
                if let Ok(resp) = client.get(*url).send().await
                    && resp.status().is_success()
                        && let Ok(text) = resp.text().await {
                            let ip = text.trim().to_string();
                            if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                                info!("  Public IP:  {}", ip);
                                *slot.write().await = Some(ip);
                                return;
                            }
                        }
            }
            info!("  Public IP:  (detection failed)");
        });
    }
    info!("");

    // Monitoring is initialized inside the timeout-guarded block below —
    // its first collect() statvfs()'s every mount and must not be able to
    // block the HTTP bind (masterpier's athena, 2026-07-03).

    // Initialize session manager
    let sessions = Arc::new(auth::SessionManager::new());

    // Initialize cluster state
    let cluster = Arc::new(agent::ClusterState::new(
        node_id.clone(),
        cli.bind.clone(),
        api_port,
    ));
    node_identity::register_cluster(cluster.clone());

    // Initialize VM manager (cheap — just ensures the config dir exists).
    // autostart_vms moved into the background thread below: on libvirt it
    // shells out to virsh, which can hang exactly like docker/pct on a sick
    // just-booted host, and VM autostart has no business gating the bind.
    let vms_manager = vms::manager::VmManager::new();

    // Run potentially slow startup tasks in background so HTTP server can bind immediately
    std::thread::spawn(move || {
        vms::manager::VmManager::new().autostart_vms();
        storage::auto_mount_all();
        // Unraid only (no-op elsewhere): restore/download static tools
        // (proxmox-backup-client, pxar, smartctl) into RAM-backed
        // /usr/local/bin — Unraid recreates it every boot (klas 2026-07-03).
        // After auto_mount_all so /mnt/user (the persistence home) is up.
        installer::unraid_tools::ensure_unraid_tools();
        networking::apply_ip_mappings();
        // Heal LXC configs that carry an apparmor key this host's LXC can't
        // parse (Fedora/SELinux builds) BEFORE autostart, so broken containers
        // list and start again. No-op on AppArmor hosts / Proxmox.
        containers::lxc_migrate_apparmor_configs();
        containers::lxc_autostart_all();
        networking::apply_all_wireguard_bridges();
        kubernetes::apply_all_wolfnet_routes();
        plugins::start_all_backends();
        // WolfStack does not bring compose stacks up at daemon start — Docker's
        // restart policy resurrects containers that exist. On a host where a
        // stack's containers have never been created (a standby that only
        // received the compose directory) nothing resurrects them and "the
        // daemon is running" would be a misleading health signal (Colt
        // 2026-09-06). Say which stacks are in that state, once Docker is up.
        api::warn_stacks_never_started();
    });

    // HTTPS-by-default: if the operator has NOT opted out (--no-tls),
    // has NOT supplied --tls-cert/--tls-key, and there's no existing
    // cert anywhere `find_tls_certificate()` would discover (operator
    // wolfstack/tls/, certbot CLI, /etc/letsencrypt/live, Proxmox VE),
    // auto-generate a self-signed cert at the standard
    // /etc/wolfstack/tls/{cert,key}.pem path. The existing TLS
    // discovery below picks it up via wolfstack_local_cert_paths()
    // with zero changes to the decision tree.
    //
    // Pre-v23.11 behaviour was to silently fall back to HTTP-only in
    // this case — which broke inter-node federation HTTPS calls and
    // surprised browsers expecting HTTPS on :8553. Self-signed is the
    // right default for the thousands of installs without a public
    // domain; operators who configure Let's Encrypt or supply their
    // own cert are unaffected (early-returns above keep their path).
    if !cli.no_tls && cli.tls_cert.is_none() && cli.tls_key.is_none()
        && installer::find_tls_certificate(cli.tls_domain.as_deref()).is_none() {
            let detected_hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "wolfstack".into());
            let ips = installer::self_signed::detect_local_ips();
            if let Err(e) = installer::self_signed::ensure_self_signed_cert(
                &detected_hostname, &ips,
            ) {
                tracing::warn!(
                    "TLS: could not auto-generate self-signed cert ({}) — will fall back to HTTP-only. Run wolfstack with --tls-cert/--tls-key to provide one manually.",
                    e
                );
            }
        }

    // Check if TLS will be available (so the frontend knows the correct protocol for URLs)
    let tls_enabled = if cli.no_tls {
        false
    } else if cli.tls_cert.is_some() && cli.tls_key.is_some() {
        true
    } else {
        installer::find_tls_certificate(cli.tls_domain.as_deref()).is_some()
    };

    // Initial self-update — minimal blocking, polling loop fills in details within seconds
    {
        // The ENTIRE initial collection runs on a guarded thread with a hard
        // timeout: the first sysinfo collect statvfs()'s every mount (a dead
        // FUSE mount — /etc/pve while pve-cluster is still starting — hangs
        // uninterruptibly), and the component/runtime checks shell out to
        // docker & friends (a wedged dockerd hangs forever). None of it may
        // gate the HTTP bind: masterpier's athena sat "active (running)" for
        // 26 hours with port 8553 closed because of exactly this
        // (2026-07-03). On timeout we bind anyway with a fresh cheap monitor
        // (its construction no longer touches disks) and let the polling
        // loop fill everything in once the system responds.
        let mon = {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut mon = monitoring::SystemMonitor::new();
                let metrics = mon.collect();
                let comps = installer::get_all_status();
                let docker = containers::docker_status().installed;
                let lxc = containers::lxc_status().installed;
                let kvm = containers::kvm_installed();
                let _ = tx.send((mon, metrics, comps, docker, lxc, kvm));
            });
            match rx.recv_timeout(std::time::Duration::from_secs(10)) {
                Ok((mon, metrics, components, has_docker, has_lxc, has_kvm)) => {
                    // Detection runs in the background and has almost
                    // certainly not landed yet — the 2s self-monitor loop
                    // below re-advertises the moment it does.
                    let ip_now = public_ip.try_read().ok().and_then(|g| g.clone());
                    cluster.update_self(metrics, components, 0, 0, 0, 0, ip_now, has_docker, has_lxc, has_kvm, tls_enabled);
                    mon
                }
                Err(_) => {
                    tracing::warn!("Startup: initial metrics/component collection timed out (10s) — binding the dashboard anyway; a wedged docker daemon or a dead FUSE mount is the usual cause. Details fill in via the polling loop once the system responds.");
                    monitoring::SystemMonitor::new()
                }
            }
        };

        // Initialize AI agent
        let ai_agent = Arc::new(ai::AiAgent::new());

        let cached_status: Arc<std::sync::RwLock<Option<serde_json::Value>>> = Arc::new(std::sync::RwLock::new(None));

        // Initialize WolfRun orchestration state
        let wolfrun_state = Arc::new(wolfrun::WolfRunState::new());
        let wolfflow_state = Arc::new(wolfflow::WolfFlowState::new());
        let wolffunctions_state = Arc::new(wolffunctions::WolfFunctionsState::new());
        // Event-trigger hook: lets alerting/backup fire wolffunction
        // events without threading state through their call sites.
        wolffunctions::init_event_hook(
            wolffunctions_state.clone(), cluster.clone(), cluster_secret.clone());

        // Initialize Status Page monitoring state
        let statuspage_state = Arc::new(statuspage::StatusPageState::new());

        // Predictive ops — load proposals/acks/history from disk so a
        // restart doesn't blind the analyzer for 24 hours. Acks get
        // an immediate prune of any expired entries to keep the file
        // bounded over years of operator use.
        let predictive_proposals = Arc::new(std::sync::RwLock::new(
            predictive::ProposalStore::load(),
        ));
        let predictive_acks = Arc::new(std::sync::RwLock::new({
            let mut a = predictive::AckStore::load();
            a.prune_expired();
            a
        }));
        let predictive_metrics = Arc::new(std::sync::RwLock::new(
            predictive::MetricsHistory::load(),
        ));

        // Create app state
        let monitor_arc = Arc::new(Mutex::new(mon));
        let ups_state = Arc::new(ups::UpsState::new());
        // Hoisted so the brute-force monitor shares the *same* limiter as the
        // login page + SSH monitor — one ban engine, one ipset, one fleet
        // propagation path.
        let login_limiter = Arc::new(auth::LoginRateLimiter::new());
        let bruteforce_state = bruteforce::BruteforceState::new(login_limiter.clone());
        let app_state = web::Data::new(api::AppState {
            monitor: monitor_arc.clone(),
            metrics_history: Mutex::new(monitoring::MetricsHistory::new()),
            cluster: cluster.clone(),
            sessions: sessions.clone(),
            vms: Mutex::new(vms_manager),
            ups: ups_state.clone(),
            cluster_secret: cluster_secret.clone(),
            join_token: api::load_join_token(),
            one_time_join_tokens: Arc::new(cluster_join::OneTimeTokens::new()),
            // Bootstrap grants are consumed seconds after minting (handshake →
            // immediate secret push), so a tight 120s TTL minimises the window.
            bootstrap_grants: Arc::new(cluster_join::OneTimeTokens::with_ttl(
                std::time::Duration::from_secs(120),
            )),
            pbs_restore_progress: Mutex::new(Default::default()),
            ai_agent: ai_agent.clone(),
            cached_status: cached_status.clone(),
            wolfrun: wolfrun_state.clone(),
            wolffunctions: wolffunctions_state.clone(),
            wolfflow: wolfflow_state.clone(),
            statuspage: statuspage_state.clone(),
            tls_enabled,
            login_limiter: login_limiter.clone(),
            bruteforce: bruteforce_state.clone(),
            scan_detector: Arc::new(scan_detector::ScanDetector::new()),
            diag_control: Arc::new(diag::Control::new()),
            wireguard_bridges: Arc::new(std::sync::RwLock::new(networking::load_wireguard_bridges())),
            patreon: Arc::new(patreon::PatreonState::new()),
            loghub: Arc::new(loghub::LogHubState::new(node_id.clone())),
            migration_tasks: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            alert_log: Arc::new(std::sync::RwLock::new(Vec::new())),
            password_reset_tokens: Arc::new(auth::PasswordResetTokens::new()),
            oidc_pending_flows: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            image_watcher_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            image_watcher_wake: Arc::new(tokio::sync::Notify::new()),
            integrations: Arc::new(crate::integrations::IntegrationState::new(&cluster_secret)),
            router: Arc::new(crate::networking::router::RouterState::new()),
            predictive_proposals: predictive_proposals.clone(),
            predictive_acks: predictive_acks.clone(),
            predictive_metrics: predictive_metrics.clone(),
            predictive_cluster_cache: Arc::new(std::sync::Mutex::new(None)),
            node_id: node_id.clone(),
            gateways: Arc::new(std::sync::RwLock::new(gateway::GatewayStore::load())),
            federations: Arc::new(std::sync::RwLock::new(federation::FederationStore::load())),
            gateway_cluster_cache: Arc::new(std::sync::Mutex::new(None)),
            array_cluster_cache: Arc::new(std::sync::Mutex::new(None)),
            xo: Arc::new(std::sync::RwLock::new(xo::XoStore::load())),
            antivirus: Arc::new(antivirus::AntivirusState::load()),
        });

        // Let the networking module refresh the live bridge map when a
        // cluster rename re-keys a WireGuard bridge from outside an HTTP
        // handler (gossip self-adoption / agent push have no AppState).
        networking::register_shared_wireguard_bridges(app_state.wireguard_bridges.clone());

        // Strict cluster scoping self-heal (v24.38.4): NAS instances
        // registered before cluster tags existed are unassigned. They live
        // in THIS node's store, and this node belongs to exactly one
        // cluster — adopt them into it so every Storage page is strictly
        // one cluster's view. One-time per instance; no-op once tagged.
        {
            let label = agent::ClusterState::self_cluster_label();
            let tn = truenas::TrueNasStore::load().adopt_unassigned_into_cluster(&label);
            let ur = unraid::UnraidStore::load().adopt_unassigned_into_cluster(&label);
            if tn + ur > 0 {
                tracing::info!("storage scoping: adopted {} TrueNAS + {} Unraid unassigned instance(s) into cluster '{}'", tn, ur, label);
            }
        }

        // Wire fleet-wide lockout propagation hooks into the limiter.
        // The limiter calls these whenever a lock/unlock happens —
        // regardless of whether the source was the WolfStack web UI,
        // sshd, or pvedaemon. One pathway, three covered surfaces.
        //
        // **CRITICAL THREADING**: these hooks are called from BOTH
        // the async actix-web handlers (tokio context, fine) AND from
        // log_monitor's blocking std::thread (NOT in tokio context).
        // Using bare `tokio::spawn(..)` panics when called from a
        // non-tokio thread, which silently killed the log_monitor
        // thread and made SSH/PVE brute-force blocks never propagate.
        //
        // Fix: capture a `tokio::runtime::Handle` at hook install
        // time and use `handle.spawn(..)` from inside the closure.
        // Handle is the runtime-agnostic spawn API — callable from
        // any thread that knows the runtime exists.
        let rt_handle = tokio::runtime::Handle::current();
        {
            let cluster_block = app_state.cluster.clone();
            let cluster_unblock = app_state.cluster.clone();
            let self_id_block = app_state.cluster.self_id.clone();
            let self_id_fed = self_id_block.clone();
            let federations_block = app_state.federations.clone();
            // Use the LOADED cluster secret (the operator's custom value
            // if they have one set in /etc/wolfstack/cluster-secret),
            // NOT the hardcoded builtin default. Existing federation
            // calls all use this — and the receiving endpoints'
            // require_auth() accepts loaded + builtin + on-disk so the
            // sender always authenticates correctly.
            let secret_block = app_state.cluster_secret.clone();
            let secret_unblock = secret_block.clone();
            let rt_block = rt_handle.clone();
            let rt_unblock = rt_handle.clone();
            app_state.login_limiter.install_propagation_hooks(
                std::sync::Arc::new(move |ip, secs| {
                    let cluster = cluster_block.clone();
                    let secret = secret_block.clone();
                    let ip = ip.to_string();
                    let self_id = self_id_block.clone();
                    let federations = federations_block.clone();
                    let self_id_fed = self_id_fed.clone();
                    rt_block.spawn(async move {
                        // Local cluster fan-out — every WolfStack peer
                        // in THIS cluster gets the block via the
                        // existing X-WolfStack-Secret path.
                        api::propagate_kernel_block_to_peers(
                            cluster, secret, ip.clone(), secs, self_id).await;
                        // Federation fan-out — every cross-cluster
                        // federation we know about gets the block via
                        // its api_key. The federation's fleet endpoint
                        // applies + fans out within its own cluster.
                        // Loops are prevented by the federation
                        // endpoint NOT re-pushing to federations.
                        api::propagate_kernel_block_to_federations(
                            federations, ip, secs, self_id_fed).await;
                    });
                }),
                std::sync::Arc::new(move |ip| {
                    let cluster = cluster_unblock.clone();
                    let secret = secret_unblock.clone();
                    let ip = ip.to_string();
                    rt_unblock.spawn(async move {
                        api::propagate_kernel_unblock_to_peers(cluster, secret, ip).await;
                    });
                }),
            );
        }
        // Install the alert hooks on the limiter + scan detector so
        // every security event (lockout, scan detection) sends a
        // Discord / Slack / Telegram / email alert stamped with the
        // cluster name + hostname. Both modules call the same shape
        // of hook (title, body) — the hook decorates with node context
        // and dispatches via alerting::send_node_alert.
        //
        // Same threading caveat as the propagation hooks above —
        // scan_detector's run_loop is a std::thread, so use rt_handle.
        {
            let cluster_for_alert_lim = app_state.cluster.clone();
            let rt_alert_lim = rt_handle.clone();
            app_state.login_limiter.install_alert_hook(std::sync::Arc::new(move |title, body| {
                let cluster_name = cluster_for_alert_lim.get_self_cluster_name();
                let hostname = hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "unknown".into());
                rt_alert_lim.spawn(async move {
                    // Failed-login / IP-blocked events — BruteForce category.
                    // Public boxes get these constantly; Simple mode suppresses.
                    crate::alerting::send_node_alert(
                        &cluster_name, &hostname,
                        crate::alerting::AlertCategory::BruteForce,
                        &title, &body,
                    ).await;
                });
            }));
            let cluster_for_alert_scan = app_state.cluster.clone();
            let rt_alert_scan = rt_handle.clone();
            app_state.scan_detector.install_alert_hook(std::sync::Arc::new(move |title, body| {
                let cluster_name = cluster_for_alert_scan.get_self_cluster_name();
                let hostname = hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "unknown".into());
                rt_alert_scan.spawn(async move {
                    // Outbound scan from THIS host — compromise indicator.
                    // Always fires (Simple AND Verbose).
                    crate::alerting::send_node_alert(
                        &cluster_name, &hostname,
                        crate::alerting::AlertCategory::Compromise,
                        &title, &body,
                    ).await;
                });
            }));
        }
        // Populate the protected-address guards BEFORE re-applying persisted
        // kernel blocks. Without this, restore_persisted_lockouts() raced the
        // 10s protection task below: it ran while both guard sets were still
        // empty, so a persisted lockout for a container IP (or a peer node)
        // was re-applied with INPUT+FORWARD DROP on every restart — the
        // klasSponsor "wolfstack made iptables rules to drop traffic from
        // those containers" symptom returning after each upgrade (round 3,
        // 2026-06-10). Heals newly-protected node IPs immediately instead of
        // 10s later, then sweeps stale WolfStack-shaped DROP rules left in
        // the kernel by versions that predate the guard.
        crate::auth::set_protected_workload_subnets(
            networking::collect_workload_subnets(),
        );
        // Install `ipset` if missing BEFORE the first ipset_available() probe
        // below (it caches its result). Debian 13 / nftables-default hosts often
        // ship without it, so the O(1) blocklist match-set never engaged and
        // WolfStack walked one DROP rule per IP — on a router that per-packet
        // FORWARD walk saturates ksoftirqd (PapaSchlumpf, recurred 2026-06-22:
        // 546 per-IP rules, no ipset). migrate_legacy_block_rules() below then
        // folds those legacy rules into the set.
        crate::auth::ensure_ipset_installed();
        // Self-heal the systemd unit: KillMode=process so a WolfStack
        // restart/upgrade no longer kills daemonized QEMU VMs (PapaSchlumpf
        // 2026-06), and a missing /opt/wolfstack no longer fails the service
        // with 200/CHDIR (Colt 2026-09-06). setup.sh writes both on install;
        // this covers hosts that swap the binary without re-running setup.sh.
        ensure_unit_self_heal();
        for ip in crate::auth::set_protected_node_ips(app_state.cluster.wolfstack_node_ips()) {
            crate::auth::kernel_unblock_ip(&ip);
        }
        crate::auth::sweep_protected_drop_rules();
        // Migrate any legacy per-IP kernel-block rules into the ipset so an
        // existing install with a large accumulated blocklist gets the O(1)
        // match-set behaviour immediately (fixes router ksoftirqd/throughput
        // collapse — PapaSchlumpf 2026-06-17), not just for newly-blocked IPs.
        crate::auth::migrate_legacy_block_rules();
        // Restore kernel iptables rules for any non-expired lockouts
        // from the previous WolfStack process. Kernel rules survive a
        // service restart; this keeps our in-memory state aligned.
        app_state.login_limiter.restore_persisted_lockouts();

        // Agent nodes are lightweight cluster members — the MANAGER reads
        // their container/VM/metrics lists on-demand via proxied API
        // handlers, and runs all fleet aggregation + orchestration itself.
        // So an agent has no reason to run the manager-weight background
        // loops (daily report, fleet threshold monitor, AI health probe,
        // scheduler orchestration…). On RAM-constrained hosts (Unraid) that
        // redundant work drives the OOM kills klas reported. Gate the
        // verified-manager-only loops off here. KEPT on agents: self-report
        // (self-monitor), node polling (feeds the agent's own WolfNet
        // self-heal), per-node security/SMART/predictive diagnostics (so the
        // manager keeps fleet coverage of the node), and all networking
        // self-heal. See the loop-by-loop audit, 2026-07-15.
        let agent_mode = cli.agent;

        // Start the sshd/pvedaemon log monitor. Feeds the same limiter
        // so SSH and Proxmox brute-force attacks trigger the same
        // kernel-block + fleet propagation as WolfStack-UI attacks.
        crate::auth::log_monitor::start_monitor(app_state.login_limiter.clone());
        // Start brute-force protection: extends the ban engine to each LXC
        // container's own sshd + web auth logs. Idle (spawns nothing) while
        // disabled in bruteforce.json; re-applied live on config change. Feeds
        // the same limiter, so a container-side hit blocks + propagates exactly
        // like an SSH/UI one.
        app_state.bruteforce.apply();
        // Start the Fleet Logs shipper + janitor threads. Both idle cheaply
        // while the feature is disabled (off by default), so this is a no-op
        // on installs that never opt in. They re-read config each tick, so
        // enabling/configuring at runtime takes effect without a restart.
        crate::loghub::start(
            app_state.loghub.clone(),
            app_state.cluster.clone(),
            app_state.cluster_secret.clone(),
        );
        // Diagnostic listener — see src/diag.rs.
        crate::diag::start(
            app_state.login_limiter.clone(),
            app_state.cluster.clone(),
            app_state.diag_control.clone(),
        );
        // Start the outbound-scan detector. Periodically samples
        // /proc/net/tcp[6] for SYN_SENT-state sockets, counts distinct
        // destinations per process across the rolling window, and
        // kills + UID-blocks any process that crosses the threshold.
        // This is what would have caught the zmap incident at minute 1.
        app_state.scan_detector.clone().start();

        // Cluster-node block protection (klasSponsor 2026-06-08). Keep the auth
        // guard's protected-IP set in sync with cluster membership so WolfStack
        // nodes never kernel-block each other, heal any pre-existing bad ban
        // once per newly-seen node IP, and fire an alert when a peer-block is
        // refused (the red banner is driven by /api/security/protected-block-events).
        {
            let cluster = app_state.cluster.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
                let mut last_alerted_id: u64 = 0;
                loop {
                    tick.tick().await;
                    // Also exempt this host's own container/workload bridges
                    // (docker0/br-*/lxcbr*/virbr*) so the auto-block never
                    // firewalls a local container (klasSponsor 2026-06-08).
                    let subnets_changed = crate::auth::set_protected_workload_subnets(
                        crate::networking::collect_workload_subnets(),
                    );
                    // set_protected_node_ips now also maintains the sticky
                    // known-peer-ips.json store (file read each tick, write
                    // at most daily) — off the executor like the iptables
                    // work below.
                    let node_ips = cluster.wolfstack_node_ips();
                    let newly = tokio::task::spawn_blocking(move || {
                        crate::auth::set_protected_node_ips(node_ips)
                    }).await.unwrap_or_default();
                    // Heal pre-existing bad bans (the ones klas hit before this
                    // shipped). One-shot per newly-protected IP, plus a sweep of
                    // stale WolfStack-shaped DROP rules whenever a workload
                    // bridge appears (Docker starting late, a new compose
                    // network). iptables is a sync subprocess, so off the
                    // executor.
                    if !newly.is_empty() || subnets_changed {
                        tokio::task::spawn_blocking(move || {
                            for ip in newly { crate::auth::kernel_unblock_ip(&ip); }
                            if subnets_changed {
                                crate::auth::sweep_protected_drop_rules();
                            }
                        }).await.ok();
                    }
                    // Safety-net: re-sync the host block set INTO any macvlan/
                    // ipvlan container the host FORWARD chain can't reach. Blocks
                    // already trigger this on the spot; this catches containers
                    // STARTED since the last block. Single-flight + self-detached,
                    // and a no-op (one cheap `docker network ls`) when no such
                    // container exists.
                    crate::auth::trigger_macvlan_reconcile();
                    // Alert once per new refused-block event.
                    let events = crate::auth::recent_protected_block_events();
                    let newest = events.last().map(|e| e.id).unwrap_or(0);
                    if newest > last_alerted_id {
                        let fresh = events.iter().filter(|e| e.id > last_alerted_id).count();
                        let latest_ip = events.last().map(|e| e.ip.clone()).unwrap_or_default();
                        last_alerted_id = newest;
                        let extra = if fresh > 1 {
                            format!(" (and {} other peer-block attempt(s))", fresh - 1)
                        } else { String::new() };
                        crate::alerting::send_local_alert(
                            crate::alerting::AlertCategory::Posture,
                            "Refused a block against a cluster node",
                            &format!(
                                "A security trigger tried to block WolfStack cluster node IP {}{} — it is \
                                 auto-whitelisted, so the block was refused. This usually means a node \
                                 tripped brute-force/scan detection against a peer; review the Security page.",
                                latest_ip, extra
                            ),
                        ).await;
                    }
                }
            });
        }

        // Storage-array health watcher — every 60s, scan /proc/mdstat
        // and per-disk SMART. Fire an alert_log entry on first
        // observation of a degraded array, faulty disk, or
        // SMART-FAILED drive. Suppression is per-condition so we
        // don't spam the operator every minute while the same disk is
        // still faulty — only on transitions.
        {
            let alert_log = app_state.alert_log.clone();
            let cluster = app_state.cluster.clone();
            let cluster_for_label = cluster.clone();
            tokio::spawn(async move {
                let mut last_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
                // Counts 60s iterations so the SMART self-test pass can run
                // hourly off this same loop, reusing the readings it already
                // took instead of running a second smartctl sweep.
                let mut ticks: u64 = 0;
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    ticks = ticks.wrapping_add(1);
                    // list_arrays() is fast (just /proc/mdstat) but
                    // doesn't populate per-disk SMART. We need SMART
                    // for the FAILED-disk alert path, so hydrate via
                    // array_detail() per array. spawn_blocking because
                    // smartctl is a sync subprocess call.
                    let arrays = tokio::task::spawn_blocking(|| {
                        crate::array::list_arrays().into_iter()
                            .filter_map(|a| crate::array::array_detail(&a.name))
                            .collect::<Vec<_>>()
                    }).await.unwrap_or_default();
                    let hostname = cluster.get_all_nodes().into_iter()
                        .find(|n| n.is_self).map(|n| n.hostname).unwrap_or_default();
                    let cluster_name = cluster_for_label.get_self_cluster_name();

                    let mut current = std::collections::HashSet::new();
                    let mut new_alerts: Vec<(String, String, String)> = Vec::new();
                    // `last_seen = current` at the end of each tick is what
                    // de-duplicates alerts. The self-test pass only runs on the
                    // hourly tick, so on the other 59 its keys would vanish
                    // from the set and the same failure would re-alert every
                    // hour. Carry them forward on the ticks that don't re-test.
                    if !ticks.is_multiple_of(60) {
                        for k in last_seen.iter().filter(|k| k.starts_with("selftest:")) {
                            current.insert(k.clone());
                        }
                    }
                    for arr in &arrays {
                        if arr.state == "degraded" {
                            let key = format!("array_degraded:{}", arr.name);
                            current.insert(key.clone());
                            if !last_seen.contains(&key) {
                                new_alerts.push((
                                    "critical".into(),
                                    format!("Array degraded: /dev/{}", arr.name),
                                    format!("level={} disks=[{}]", arr.level,
                                        arr.disks.iter().map(|d| format!("{}({})", d.device, d.state)).collect::<Vec<_>>().join(", ")),
                                ));
                            }
                        }
                        for d in &arr.disks {
                            if d.state == "faulty" || d.state == "missing" {
                                let key = format!("array_disk:{}:{}", arr.name, d.device);
                                current.insert(key.clone());
                                if !last_seen.contains(&key) {
                                    new_alerts.push((
                                        "critical".into(),
                                        format!("Disk {} on /dev/{} is {}", d.device, arr.name, d.state),
                                        format!("model={} role={}",
                                            d.model.clone().unwrap_or_default(), d.role),
                                    ));
                                }
                            }
                            // NOTE: per-disk SMART health (overall-health AND the
                            // Backblaze attribute set) is evaluated once for every
                            // physical disk below — including array members, which
                            // are physical disks — so it isn't repeated here.
                        }
                    }

                    // Every physical disk's SMART health. A disk that only
                    // showed a red "N realloc / N pending" indicator on the
                    // Storage page — but whose vendor overall-health still says
                    // PASSED — used to raise NOTHING in Issues (RutgerDiehard,
                    // 2026-06-30). We now use the SAME evaluator the Storage page
                    // renders (Backblaze SMART 5/187/197/198 raw>0, NVMe spare/
                    // wear, plus overall-health FAILED), so the Issues alert
                    // mirrors exactly what the operator sees under Storage. This
                    // covers array members too (they ARE physical disks), so the
                    // array loop above no longer needs its own SMART check.
                    //
                    // The standby guard (`-n standby`, ATA-only — smartmontools
                    // ignores it for NVMe/SCSI) is applied ONLY to disks the
                    // kernel reports as rotational. It exists to avoid spinning up
                    // a sleeping HDD on the 60s poll; on solid-state it's pointless
                    // (nothing to spin) and, for a SATA SSD that reports a low-power
                    // ATA state, it can make smartctl skip the read — so gate it on
                    // rotational-ness: SSD/NVMe are ALWAYS read, HDDs keep the
                    // no-wake guard. (The failing SSD that raised nothing on the
                    // Issues page was primarily collect_issues never checking SMART
                    // at all — fixed there — plus USB drives needing `-d sat`, now
                    // retried in disk_smart_health. PapaSchlumpf, 2026-07-01.)
                    let phys = tokio::task::spawn_blocking(|| {
                        // Auto-install smartmontools if absent (one-shot, cached
                        // verdict) — without smartctl this whole SMART sweep is
                        // a silent no-op and disks go unmonitored.
                        if !crate::array::ensure_smartmontools() {
                            return Vec::new();
                        }
                        // Standby policy lives in disk_smart_health_watchdog:
                        // never wake a disk on this 60s cadence, but force one
                        // guard-free read if it has gone a day without a
                        // successful one. Before that, a permanently spun-down
                        // HDD was dropped by filter_map on every poll and was
                        // therefore never monitored at all (klas, 2026-07-31).
                        crate::array::list_physical_disks().into_iter()
                            .map(|dev| {
                                let check = crate::array::disk_smart_health_watchdog(&dev);
                                (dev, check)
                            })
                            .collect::<Vec<(String, crate::array::SmartCheck)>>()
                    }).await.unwrap_or_default();
                    for (dev, check) in &phys {
                        // A disk we cannot read is NOT a healthy disk. Say so
                        // once it has been unreadable long enough that the
                        // silence is a fault rather than a spun-down moment.
                        if check.smart.is_none()
                            && check.stale_secs >= crate::array::SMART_UNREADABLE_ALERT_SECS
                        {
                            let key = format!("smart_unreadable:{}", dev);
                            current.insert(key.clone());
                            if !last_seen.contains(&key) {
                                new_alerts.push((
                                    "warning".into(),
                                    format!("Disk {} health is unreadable", dev),
                                    format!("{} — no successful SMART read in {} day(s), so this disk is NOT being monitored. Check cabling/enclosure, or inspect manually: smartctl -a {}",
                                        dev, check.stale_secs / 86_400, dev),
                                ));
                            }
                        }
                        let health = match check.smart.as_ref() {
                            Some(h) => h,
                            None => continue,
                        };
                        let reasons = health.failing_reasons();
                        if reasons.is_empty() { continue; }
                        let key = format!("smart:{}", dev);
                        current.insert(key.clone());
                        if !last_seen.contains(&key) {
                            new_alerts.push((
                                "critical".into(),
                                format!("Disk {} is failing (SMART)", dev),
                                format!("{} — back up and plan replacement: {}",
                                    dev, reasons.join("; ")),
                            ));
                        }
                    }

                    // ─── Scheduled SMART short self-tests (hourly) ───
                    // Runs off the same loop, one pass an hour, reusing the
                    // readings above. A disk we could read is a disk that is
                    // already spinning, so testing it costs no extra spin-up;
                    // sleeping disks are skipped entirely unless the operator
                    // set allow_wake. First pass is an hour after start, which
                    // keeps a reboot from kicking off a fleet-wide test storm.
                    if ticks.is_multiple_of(60) {
                        let candidates: Vec<(String, Option<crate::array::DiskSmart>)> = phys
                            .iter()
                            .map(|(d, c)| (d.clone(), c.smart.clone()))
                            .collect();
                        let tested = tokio::task::spawn_blocking(move || {
                            let cfg = crate::array::ArrayConfig::load().smart_tests;
                            let mut out: Vec<(String, crate::array::SelfTestStatus)> = Vec::new();
                            for (dev, smart) in candidates {
                                let smart = match smart {
                                    Some(s) => s,
                                    None => {
                                        if !cfg.allow_wake { continue; }
                                        match crate::array::disk_smart_health(&dev, false) {
                                            Some(s) => s,
                                            None => continue,
                                        }
                                    }
                                };
                                let status = match crate::array::self_test_status(&dev) {
                                    Some(s) => s,
                                    None => continue,
                                };
                                if crate::array::self_test_due(&dev, &smart, &status, &cfg) {
                                    // A drive that refuses (no self-test support
                                    // behind its enclosure) is logged, not
                                    // alerted — it would otherwise raise the same
                                    // alert every cycle forever. The manual
                                    // "run now" API surfaces the error directly
                                    // to whoever asked for it. Silence it for
                                    // good by adding the device to `exclude`.
                                    let kind = crate::array::next_self_test_kind(
                                        &dev, smart.power_on_hours, &cfg);
                                    if let Err(e) = crate::array::start_self_test(&dev, kind) {
                                        tracing::warn!("SMART {kind} self-test on {dev} refused: {e}");
                                    } else {
                                        tracing::info!("SMART {kind} self-test started on {dev} (stage: {})",
                                            crate::array::life_stage(smart.power_on_hours));
                                    }
                                }
                                out.push((dev, status));
                            }
                            out
                        }).await.unwrap_or_default();

                        for (dev, status) in &tested {
                            // Only an explicit failure alerts. An aborted or
                            // interrupted test reports no verdict at all and
                            // must never be shown as a failure.
                            if status.passed != Some(false) { continue; }
                            let key = format!("selftest:{}", dev);
                            current.insert(key.clone());
                            if !last_seen.contains(&key) {
                                new_alerts.push((
                                    "critical".into(),
                                    format!("Disk {} failed its SMART self-test", dev),
                                    format!("{} — {}. The drive itself reports a fault; back up and plan replacement.",
                                        dev,
                                        status.result.clone().unwrap_or_else(|| "self-test reported a failure".into())),
                                ));
                            }
                        }
                        // Disks we could not evaluate this pass — asleep, or
                        // unreadable — keep whatever verdict they already had.
                        // Without this they drop out of the dedup set and the
                        // same failure re-alerts every time the disk happens
                        // to be awake on an hourly tick.
                        for k in last_seen.iter().filter(|k| k.starts_with("selftest:")) {
                            let dev = &k["selftest:".len()..];
                            if !tested.iter().any(|(d, _)| d == dev) {
                                current.insert(k.clone());
                            }
                        }
                    }

                    // ─── Node-level config faults ───
                    // Both present to the operator as "the node is online but
                    // nothing on it works", and neither was visible anywhere
                    // in the UI — only as a log line nobody reads.
                    if crate::auth::using_default_cluster_secret() {
                        let peers = cluster.get_all_nodes().into_iter()
                            .filter(|n| !n.is_self).count();
                        if peers > 0 {
                            let key = "cluster_secret_default".to_string();
                            current.insert(key.clone());
                            if !last_seen.contains(&key) {
                                new_alerts.push((
                                    "critical".into(),
                                    "This node is using the built-in default cluster secret".into(),
                                    format!("{} peer(s) are configured. Every proxied per-node request is signed with the public default secret and will be rejected with 401 by any peer using its own — this node keeps reporting online while none of its pages load. Copy /etc/wolfstack/custom-cluster-secret from a working node (chmod 600) and restart the agent.", peers),
                                ));
                            }
                        }
                    }
                    // load_config() refreshes the unreadable flag; it is a
                    // small file read, and running it here means the fault is
                    // reported even on a node nobody has opened Storage on.
                    let storage_bad = tokio::task::spawn_blocking(|| {
                        let _ = crate::storage::load_config();
                        crate::storage::config_is_unreadable()
                    }).await.unwrap_or(false);
                    if crate::storage::config_was_repaired() {
                        let key = "storage_config_repaired".to_string();
                        current.insert(key.clone());
                        if !last_seen.contains(&key) {
                            new_alerts.push((
                                "warning".into(),
                                "Storage configuration was damaged and has been repaired".into(),
                                "WolfStack found trailing data after the end of storage.json, recovered the mount definitions it still contained, and rewrote the file. The damaged original was kept alongside it as storage.json.corrupt-<timestamp>. Check the Storage page to confirm your mounts are all present.".into(),
                            ));
                        }
                    }
                    if storage_bad {
                        let key = "storage_config_unreadable".to_string();
                        current.insert(key.clone());
                        if !last_seen.contains(&key) {
                            new_alerts.push((
                                "critical".into(),
                                "Storage configuration could not be read".into(),
                                "WolfStack is holding an EMPTY storage config in memory and has blocked writes so the on-disk file cannot be overwritten. Mounts will not be applied until it is repaired, and saving from the Storage page is refused on purpose — writing now would destroy the mounts and credentials the file still contains. A copy has been preserved next to it.".into(),
                            ));
                        }
                    }

                    if !new_alerts.is_empty() {
                        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
                        // 1. Write to the in-memory alert_log so the
                        //    dashboard's Tasks panel shows the event
                        //    immediately.
                        {
                            let mut log = alert_log.write().unwrap_or_else(|e| e.into_inner());
                            let mut next_id = log.last().map(|e| e.id + 1).unwrap_or(1);
                            for (sev, title, detail) in &new_alerts {
                                log.push(api::AlertLogEntry {
                                    id: next_id,
                                    timestamp: now.clone(),
                                    severity: sev.clone(),
                                    title: title.clone(),
                                    detail: detail.clone(),
                                    hostname: hostname.clone(),
                                    cluster: cluster_name.clone(),
                                });
                                next_id += 1;
                            }
                            while log.len() > 200 { log.remove(0); }
                        }
                        // 2. Fan out to the operator's selected delivery
                        //    paths: Discord/Slack/Telegram/ntfy via the
                        //    alerting module, email via the AI module's SMTP
                        //    creds (the same ones the daily report uses).
                        //    Both are best-effort — a failed dispatch logs a
                        //    warning but never blocks the watcher.
                        let alert_cfg = crate::alerting::AlertConfig::load();
                        // Storage / SMART failures — Lifecycle category. The
                        // event itself is rare (state-change-gated, not per-tick)
                        // but operators told us Simple mode should stay minimal:
                        // dashboard surfaces these, switch to Verbose to push.
                        let cat = crate::alerting::AlertCategory::Lifecycle;
                        let category_allowed = crate::alerting::should_send(&alert_cfg, cat);
                        for (_sev, title, detail) in new_alerts {
                            // decorate_local prepends `[<cluster> / <host>]`
                            // and a Cluster:/Host:/When: header — same shape
                            // every other WolfStack alert uses. We pass the
                            // bare detail as the body since decorate_local
                            // already owns the host/cluster labelling; a
                            // manual prefix here would just duplicate it.
                            let (title, body) = crate::alerting::decorate_local(&title, &detail);
                            // Webhook (Discord/Slack/Telegram). send_alert
                            // re-checks `enabled + allows(category)`, so the
                            // category_allowed guard for the email path
                            // doesn't need to be repeated here.
                            crate::alerting::send_alert(&alert_cfg, cat, &title, &body).await;
                            // Email, if the operator kept it among their
                            // delivery paths (and SMTP is set up — the helper
                            // owns both checks).
                            if category_allowed {
                                crate::alerting::send_alert_email_if_selected(
                                    &alert_cfg, &title, &body,
                                ).await;
                            }
                        }
                    }
                    last_seen = current;
                }
            });
        }

        // Storage-array scheduler — runs every 60s, fires parity
        // checks when their cron expression matches the current
        // minute. Lightweight (one /etc/wolfstack/arrays.json read +
        // one cron-match per schedule per minute); doesn't run anything
        // until an actual schedule is configured.
        {
            tokio::spawn(async move {
                let mut last_minute = String::new();
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                    let now = chrono::Local::now().naive_local();
                    let minute_key = now.format("%Y-%m-%dT%H:%M").to_string();
                    if minute_key == last_minute { continue; }
                    last_minute = minute_key;

                    let cfg = crate::array::ArrayConfig::load();
                    for sched in cfg.schedules {
                        if !sched.enabled { continue; }
                        if !crate::wolfflow::cron_matches(&sched.cron, &now) { continue; }
                        let array = sched.array.clone();
                        let action = sched.action.clone();
                        tokio::task::spawn_blocking(move || {
                            match crate::array::parity_check(&array, &action) {
                                Ok(_) => tracing::info!(target: "wolfstack::array",
                                    "scheduled parity {} started on /dev/{}", action, array),
                                Err(e) => tracing::warn!(target: "wolfstack::array",
                                    "scheduled parity on /dev/{} failed: {}", array, e),
                            }
                        });
                    }
                }
            });
        }

        // Reconcile orphan daemon configs (Samba snippets / NFS exports
        // / mount trees that aren't backed by a gateway in our store)
        // and re-apply every persisted gateway. Mounts and daemon
        // configs may have been wiped by a reboot; this brings them
        // back without operator action.
        //
        // KNOWN restart-window: this runs as an async task spawned
        // alongside the HTTP listener, so during the first few seconds
        // after start-up the API will report each gateway with a
        // "not running" runtime row before the apply loop completes.
        // The reconciler purges orphans before the loop runs so we
        // never serve stale state — just briefly report it as
        // not-yet-applied. Acceptable trade-off vs. blocking the API
        // listener on a potentially slow mount sequence (NFS sources
        // can stall for tens of seconds on a missing server).
        {
            let store = app_state.gateways.clone();
            let node_id_for_apply = node_id.clone();
            tokio::spawn(async move {
                {
                    let s = store.read().unwrap_or_else(|e| e.into_inner());
                    crate::gateway::reconcile_on_startup(&s, &node_id_for_apply);
                }
                let snapshot: Vec<crate::gateway::Gateway> = {
                    let s = store.read().unwrap_or_else(|e| e.into_inner());
                    s.gateways.values().cloned().collect()
                };
                let me = node_id_for_apply.clone();
                for g in snapshot {
                    // Only the owner node serves a gateway in v1.0.
                    // Peers hold the config (so the cluster panel can
                    // surface it) but don't write Samba snippets or
                    // mount sources locally — that would mean two
                    // hosts serving the same share name with diverged
                    // tdbsam state.
                    let owner = if g.origin_node_id.is_empty() {
                        // Pre-v22.9 configs that pre-dated the field
                        // get retroactively assigned to whichever node
                        // first re-applies them. This mirrors the
                        // "first node that boots is the owner" model
                        // and is fine because pre-v22.9 there was only
                        // one node anyway.
                        true
                    } else {
                        g.origin_node_id == me
                    };
                    if !owner {
                        tracing::debug!(
                            target: "wolfstack::gateway",
                            "skipping startup apply for '{}' — owned by '{}'",
                            g.name, g.origin_node_id
                        );
                        continue;
                    }
                    match crate::gateway::orchestrator::apply(&g) {
                        Ok(rt) => {
                            let mut s = store.write().unwrap_or_else(|e| e.into_inner());
                            s.runtime.insert(g.id.clone(), rt);
                            tracing::info!(target: "wolfstack::gateway", "gateway '{}' re-applied on startup", g.name);
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: "wolfstack::gateway",
                                "gateway '{}' failed to re-apply on startup: {}",
                                g.name, e
                            );
                        }
                    }
                }
            });
        }

        // v23.2.2 safety migration: tear down any FireHOL Level 1
        // iptables/ipset state left over from v23.2.0/v23.2.1's
        // auto-enable behaviour. Idempotent; the second-run check
        // (sentinel file) short-circuits in under a millisecond.
        // Runs BEFORE the predictive orchestrator first ticks so the
        // analyzer never observes a stale "enabled" state and tries
        // to re-install rules. Synchronous (blocking iptables calls)
        // but cheap.
        let _ = crate::predictive::threat_intel::run_safety_migration_once();

        // Predictive ops orchestrator — 5-min loop that samples
        // disks, records into history, runs analyzers, and upserts
        // proposals into the inbox. Ack/snooze/dismiss are honoured
        // before any proposal is materialised. Threshold + first-
        // appearance notification dispatch landed in convergence
        // A+B — orchestrator now reads SystemMetrics off the shared
        // monitor and fires alerting channels on Critical/High.
        {
            let p = predictive_proposals.clone();
            let a = predictive_acks.clone();
            let m = predictive_metrics.clone();
            let mon = monitor_arc.clone();
            let n = node_id.clone();
            tokio::spawn(predictive::orchestrator::run_loop(p, a, m, mon, n));
        }

        // One-shot PBS runtime-dir self-heal. Ensures every running PBS
        // LXC has the persistent /run/proxmox-backup ownership fix so it
        // stops losing the web GUI + backups on every reboot (wabil).
        // Idempotent + PBS-only; runs off the bind path (post-startup
        // delay) per the masterpier lesson. One-shot is enough — the
        // installed tmpfiles.d drop-in persists across reboots.
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(45)).await;
            let _ = tokio::task::spawn_blocking(
                predictive::container_boot::ensure_pbs_runtime_dir_persistence,
            ).await;
        });

        // WolfStack Pools orchestrator — drives in-flight pools
        // (`provisioning` → `leader_up` → `live`) by polling backend
        // VM IPs and joining followers to the leader's cluster.
        // 30 s tick. No state shared with the rest of the daemon —
        // it operates entirely off /etc/wolfstack/pools.json.
        // Manager-only: pool provisioning is orchestration an agent
        // never drives (agent-mode memory reduction).
        if !agent_mode {
            tokio::spawn(crate::pools::orchestrator::run_loop());
        }

        // HTTP-proxy edge reconciler — keeps DNS records (Cloudflare
        // and friends) in sync with peer-health observations. Runs
        // every 30s; only the elected leader actually pushes to
        // provider APIs (others compute their view of "should I be
        // leader" and short-circuit). See `edge::reconcile::run_pass`.
        let cluster_for_edge = app_state.cluster.clone();
        let router_for_edge = app_state.router.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            // Skip the first immediate fire — startup is busy enough
            // without hammering Cloudflare in the boot path.
            tick.tick().await;
            loop {
                tick.tick().await;
                let snapshot = crate::edge::reconcile::ClusterSnapshot::from_cluster_state(&cluster_for_edge);
                let am_leader = crate::edge::reconcile::am_i_leader(&snapshot);
                if !am_leader { continue; }
                let proxies = router_for_edge.config.read().unwrap().http_proxies.clone();
                if proxies.iter().all(|p| !p.edge.manages_dns()) { continue; }
                let providers = crate::edge::CloudProviderStore::load();
                let dns_providers = crate::dns_providers::DnsProviderStore::load();
                let reports = crate::edge::reconcile::run_pass(
                    &proxies, &snapshot, &providers, &dns_providers, true,
                ).await;
                for r in &reports {
                    if r.errors.is_empty() && (r.added > 0 || r.removed > 0) {
                        tracing::info!(
                            "edge reconcile: {} → {:?} (added {} removed {} kept {})",
                            r.proxy_id, r.after, r.added, r.removed, r.unchanged
                        );
                    }
                    for e in &r.errors {
                        tracing::warn!("edge reconcile {}: {}", r.proxy_id, e);
                    }
                }
            }
        });

        // Start the WolfRouter safe-mode watcher — auto-reverts firewall
        // changes if the user doesn't confirm within the safe-mode window.
        crate::networking::router::spawn_rollback_watcher(app_state.router.clone());

        // WolfNet route push — event-driven announcement of our local
        // container routes to every cluster peer. Wakes on the
        // `WOLFNET_ROUTES_CHANGED` Notify (signalled by
        // `flush_routes_to_disk` when the route map really changes),
        // plus a 5-minute heartbeat as a safety net for peers that
        // came online during a quiet period or missed an earlier push
        // due to transient network. No polling cost during steady-
        // state — if nothing changes and all peers heard the last
        // heartbeat, the next push is 5 minutes away.
        //
        // Symmetric to the pull-based `poll_remote_nodes` path: both
        // populate the same WOLFNET_ROUTES table on the receiver, and
        // either path failing on its own doesn't take down cross-node
        // container reachability.
        //
        // Why both: the pull path can silently fail in ways the
        // receiver can't recover from on its own (TLS-trust mismatch
        // on the peer's API, cluster state missing the peer entirely,
        // a peer's /api/agent/status returning non-StatusReport JSON).
        // dreamer 2026-05-26: routes.json on dreamer correctly
        // contained `10.10.10.100→10.10.10.171` but mouse's
        // routes.json had ZERO dreamer entries, so mouse couldn't
        // reply to container traffic from regions9 — the host-to-host
        // wolfnet tunnel was fine but mouse had no `find_route` hit
        // for the container's IP. Push closes the gap from the SOURCE
        // side, so the sender doesn't need the receiver's poll path
        // to be healthy.
        // Re-load the cluster secret from disk on every push instead of
        // capturing the boot-time value — see the equivalent comment on
        // the poll loop above. A cluster_secret rotation should take
        // effect without a wolfstack restart.

        // Seed WOLFNET_ROUTES with local container routes before the first
        // push fires (T+5), so we never announce an empty set that makes every
        // peer drop the routes it holds for us. seed_local_routes_if_empty is
        // a no-op when routes.json already populated the cache, and the
        // announce loop repeats the check before every push — this call just
        // gets it done before the first one.
        containers::seed_local_routes_if_empty();

        let cluster_for_push = app_state.cluster.clone();
        tokio::spawn(async move {

            // Initial push so peers learn our routes on boot without
            // waiting for the heartbeat or for a route change.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            crate::api::announce_wolfnet_routes_to_peers(
                cluster_for_push.clone(),
                auth::load_cluster_secret(),
            ).await;
            // Minimum quiet period between announces. The loop is woken by
            // WOLFNET_ROUTES_CHANGED on every local route-map change; with no
            // floor, a sustained change source — e.g. a route set that never
            // converges between two nodes (the active-only pull vs. used-set
            // push disagree on a stopped container's IP), or the cross-node
            // announce→flush→notify→announce ping-pong — drives back-to-back
            // announces with zero delay. Each announce opens a fresh
            // connection to every peer (and to the port+1 overlay URL that
            // CA-signed peers no longer bind), so on a multi-node mesh this
            // exhausts file descriptors (EMFILE) within minutes and pegs every
            // node's CPU in the accept/reconnect path. AstroMandoSponsor
            // 2026-07-01: 6-node cluster, ~100 leaked sockets/s → 65k FD
            // ceiling in ~10 min → cluster-wide 1500%+ CPU storm.
            //
            // The floor is applied AFTER each announce, so the FIRST change
            // after a quiet period still propagates immediately (route
            // latency unchanged in the common case). notify_one() coalesces,
            // so any changes arriving during the sleep collapse into a single
            // pending permit that fires exactly one more announce when the
            // sleep ends — a burst, or an unconverging ping-pong, can never
            // spin faster than one announce per interval.
            const ANNOUNCE_MIN_INTERVAL: std::time::Duration =
                std::time::Duration::from_secs(10);
            loop {
                tokio::select! {
                    _ = crate::containers::WOLFNET_ROUTES_CHANGED.notified() => {}
                    _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {}
                }
                crate::api::announce_wolfnet_routes_to_peers(
                    cluster_for_push.clone(),
                    auth::load_cluster_secret(),
                ).await;
                tokio::time::sleep(ANNOUNCE_MIN_INTERVAL).await;
            }
        });

        // WolfNet config.toml peer route sync — pull container routes
        // from peers listed in /etc/wolfnet/config.toml. This is the
        // ground-truth pull mechanism: config.toml defines exactly which
        // nodes share this WolfNet mesh, so it doesn't depend on the
        // cluster_name matching in poll_remote_nodes.
        tokio::spawn(async {
            // Wait for wolfnet to be up and initial push to fire
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            containers::sync_wolfnet_peer_routes().await;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            tick.tick().await; // skip immediate
            loop {
                tick.tick().await;
                containers::sync_wolfnet_peer_routes().await;
            }
        });

        // Background: auto-poll registered tenants (SP → customer-cluster
        // federation). Keeps the tenant health cache that `tenants_list` serves
        // fresh without the operator pressing "Refresh all". 60s cadence; a
        // no-op when no tenants are registered, and each tenant is probed
        // lock-free so one slow/unreachable customer can't stall the rest. A
        // short initial delay lets startup settle before the first sweep.
        tokio::spawn(async move {
            // Manager-only: tenants are registered and browsed via the
            // manager UI, so an agent's registry is always empty and the
            // sweep is pure overhead (agent-mode reduction).
            if agent_mode { return; }
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            // If a sweep ever runs long (many unreachable tenants), skip the
            // missed ticks rather than firing back-to-back sweeps on catch-up.
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                crate::api::poll_all_tenants_once().await;
            }
        });

        // LXC bridge self-heal — re-affirm lxcbr0 + its iptables rules
        // every 60s. External events (Docker daemon restart, NetworkManager
        // reload, package upgrade, admin `iptables -F`, unattended-upgrades
        // restarting lxc-net) routinely wipe the bridge and our FORWARD /
        // MASQUERADE rules. Without this tick the next recovery is the
        // next `lxc-start` going through wolfstack — which may be hours
        // away while every container is unreachable. The function is
        // idempotent (early `ip addr show` skip when the bridge is
        // healthy) and shells out to `ip` / `iptables`, so it runs on
        // the blocking pool. Mirrors the router's subnet-route
        // reconciler at `networking::router::mod.rs:2281`.
        tokio::spawn(async {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.tick().await; // skip the immediate fire — startup just did it
            loop {
                tick.tick().await;
                let _ = tokio::task::spawn_blocking(containers::ensure_lxc_bridge).await;
            }
        });

        // One-shot at startup: adopt any native `lxc-create` LXC containers
        // the pre-fix App Store installer left orphaned into PVE, so the
        // containers WolfStack tracks match what Proxmox shows. The function
        // self-guards (no-op off Proxmox / when there are none) and is
        // idempotent; it tars + re-creates rootfs, so it runs on the blocking
        // pool rather than the async runtime.
        let _ = tokio::task::spawn_blocking(crate::appstore::reconcile_orphaned_lxc);

        // Antivirus scheduler — every 5 minutes, check whether the
        // configured schedule_hours interval has elapsed since the
        // last completed scan; if so, fire a background scan thread.
        // Per-node (each host scans its own filesystem), so no
        // leader election required.
        let av_state = app_state.antivirus.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
            // Skip the very first immediate fire — boot is busy enough.
            tick.tick().await;
            loop {
                tick.tick().await;
                crate::antivirus::maybe_run_scheduled_scan(av_state.clone());
            }
        });

        // Daily config auto-backup — snapshot all WolfStack config (cluster
        // nodes, AI/storage/PBS/IP-mapping settings, backup schedules) once a
        // day to /etc/wolfstack/config-backups so a wiped or garbled config can
        // always be restored from Settings → Config Backup. This is the hole
        // the v24.29.x control-plane incident fell into — no on-box snapshot to
        // roll back to. Hourly tick + a "today already done?" guard makes it
        // at-most-once-per-day and restart-safe; the first tick fires
        // immediately so a fresh node gets a snapshot at boot. PVE creds are
        // stripped from the snapshot (build_config_bundle).
        tokio::spawn(async {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tick.tick().await;
                let _ = tokio::task::spawn_blocking(|| {
                    match crate::api::maybe_write_daily_config_backup() {
                        Ok(Some(name)) => tracing::info!("config: wrote daily backup {}", name),
                        Ok(None) => {}
                        Err(e) => tracing::warn!("config: daily backup failed: {}", e),
                    }
                }).await;
            }
        });

        // If on-access scanning was previously enabled, clamonacc keeps
        // running across a wolfstack restart (it's a systemd service)
        // but the log tailer thread doesn't (in-process). Re-attach
        // the tailer at startup so findings keep flowing to the UI.
        crate::antivirus::resume_on_access_tailer_if_enabled(app_state.antivirus.clone());

        // Self-heal: if /etc/logrotate.d/clamav-freshclam is installed but the
        // `clamav` user isn't, recreate the user so the daily logrotate run
        // stops failing, and clear any stale logrotate.service failed state.
        // v24.7.4 only healed post-apt-install; piranhaSponsor's nodes were
        // already in the broken state before upgrading WolfStack, so the
        // install-time hook never fired. Idempotent — no-op on healthy hosts.
        tokio::task::spawn_blocking(crate::antivirus::self_heal_clamav_logrotate);

        // ...and re-run it periodically. logrotate.timer fires daily and can
        // fail AFTER boot (e.g. a transient lock during freshclam's rotation
        // window); systemd then keeps logrotate.service red until its next
        // *successful* run, so the predictive inbox kept re-surfacing a stale
        // failure for operators whose clamav user was already fine (sponsor
        // report 2026-06-03, 4 nodes — "restarting logrotate fixes it but it
        // comes back"). The startup hook can't catch a failure that lands
        // between reboots, so re-run the idempotent heal every 30 min: it only
        // touches logrotate when the unit is actually in a failed state, and
        // clears it the moment a re-run succeeds — no operator action needed.
        tokio::spawn(async {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1800));
            tick.tick().await; // consume the immediate tick — startup hook covers t0
            loop {
                tick.tick().await;
                let _ = tokio::task::spawn_blocking(crate::antivirus::self_heal_clamav_logrotate).await;
            }
        });

        // Security scanner background loop — runs posture + active-attack
        // checks on a timer and fires alerts via Discord/Slack/Telegram/
        // email when a critical-severity finding appears (SSH brute-force,
        // crypto miner, world-readable cluster_secret, etc). Cooldown keeps
        // the same finding from spamming channels.
        //
        // Interval is operator-configurable via Settings → Alerting
        // (`security_scan_interval_secs`, default 4 h). Each scan does
        // journalctl/lsof/port-probe work that costs CPU + (when AI
        // assistance is on) tokens — at 15 min that adds up across a
        // cluster. 4 h still catches attackers within the hour at worst
        // and operators can run on-demand scans via /api/system-check.
        // Clamped to a 60-second floor so misconfiguration can't turn
        // it into a busy-loop.
        tokio::spawn(async move {
            // Startup delay so the first scan happens after cluster discovery
            // settles — avoids noisy "scanner errored" at boot.
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            let mut recent_alerts: std::collections::HashMap<String, std::time::Instant> =
                std::collections::HashMap::new();
            let cooldown = std::time::Duration::from_secs(60 * 60);
            loop {
                // Run the synchronous scan off the async executor.
                let findings = tokio::task::spawn_blocking(
                    crate::security::run_security_checks
                ).await.unwrap_or_default();

                // Load alert config fresh each iteration so toggle changes
                // take effect without a restart.
                let cfg = crate::alerting::AlertConfig::load();
                if cfg.enabled {
                    for f in &findings {
                        // Only `Missing` (which we use as "critical" severity)
                        // goes to alerts — warnings live in the System Check
                        // UI, don't page operators at 3am.
                        if !matches!(f.status, crate::systemcheck::DepStatus::Missing) {
                            continue;
                        }
                        // Dedup key: strip everything after an opening
                        // parenthesis so dynamic counts ("3 IPs, 47
                        // attempts") don't create a new key every
                        // iteration and defeat the cooldown. Stable
                        // prefix == same-attack dedup, while a NEW kind
                        // of finding gets its own bucket.
                        let key = f.name
                            .split('(')
                            .next().unwrap_or(&f.name)
                            .trim()
                            .to_string();
                        let now = std::time::Instant::now();
                        if let Some(prev) = recent_alerts.get(&key)
                            && now.duration_since(*prev) < cooldown { continue; }
                        recent_alerts.insert(key.clone(), now);

                        let title = format!("🚨 WolfStack Security — {}", f.name);
                        let mut msg = f.detail.clone();
                        if let Some(fix) = &f.install_hint {
                            msg.push_str("\n\nSuggested fix:\n");
                            msg.push_str(fix);
                        }
                        // Map each finding to an AlertCategory by stable
                        // name prefix. Only Compromise fires under Simple
                        // mode; the rest are Verbose-only "you have a
                        // recommendation" or "we blocked a scanner" noise
                        // that floods operator inboxes on any public box.
                        let category = match key.as_str() {
                            // ── Compromise indicators — fire in Simple AND Verbose ──
                            // Crypto miner running on this host.
                            n if n.starts_with("Crypto-miner") => crate::alerting::AlertCategory::Compromise,
                            // Freshly-dropped executable in /tmp or /dev/shm.
                            // `scan_tmp_binaries` was promoted from warn → critical
                            // so this path is reachable.
                            n if n.starts_with("Suspicious binary")
                                || n.starts_with("Recent executable file") =>
                                crate::alerting::AlertCategory::Compromise,
                            // ── Brute-force noise — Verbose only ──
                            n if n.starts_with("SSH brute-force") =>
                                crate::alerting::AlertCategory::BruteForce,
                            // ── Everything else from the security scanner is
                            // posture/config (PermitRootLogin, world-readable
                            // secrets, duplicate IPs, fail2ban missing, etc.)
                            _ => crate::alerting::AlertCategory::Posture,
                        };
                        // send_local_alert prepends `[<cluster> / <host>]` and
                        // a Cluster/Host/When body header so operators on
                        // multi-cluster setups know which node fired the alert.
                        crate::alerting::send_local_alert(category, &title, &msg).await;
                    }
                }

                // Prune cooldown map entries older than 2× cooldown — stops
                // it growing unbounded over weeks of uptime.
                let prune_cutoff = std::time::Duration::from_secs(60 * 60 * 2);
                let now = std::time::Instant::now();
                recent_alerts.retain(|_, t| now.duration_since(*t) < prune_cutoff);

                // Re-read interval every iteration so a settings change
                // applies on the next sleep without needing a restart.
                // 60-second floor stops accidental zero/tiny values from
                // turning the scanner into a busy loop.
                let interval = crate::alerting::AlertConfig::load()
                    .security_scan_interval_secs
                    .max(60);
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            }
        });

        // Re-apply the persisted router config (WAN, LAN DHCP/DNS,
        // firewall) on startup. Before this existed, every reboot of a
        // WolfStack-as-router host dropped its WAN link, LAN DHCP, and
        // firewall rules until a human clicked Apply in the UI — while
        // Docker and Proxmox happily auto-started their containers/VMs
        // into a network with no path to the internet. Spawn-blocking
        // so iptables/dnsmasq/pppd subprocess work doesn't hold up the
        // async runtime, with a small delay so sysinfo metrics and
        // cluster discovery initialize first.
        {
            let router_state = app_state.router.clone();
            let nid = node_id.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                tokio::task::spawn_blocking(move || {
                    // Restore threat-intel ipsets BEFORE the router applies its
                    // ruleset. Without this, a host reboot would leave the
                    // ipsets empty/missing and `iptables-restore --test` would
                    // reject the rule that references them, leaving the user
                    // un-protected until they re-enable from the UI.
                    crate::threat_intel::startup();
                    crate::networking::router::apply_on_startup(router_state, &nid);
                }).await.ok();
            });
        }

        // Background dnsmasq watchdog. Re-applies any LAN whose dnsmasq
        // crashed / was killed / never bound :53 to router_ip. Per-LAN
        // circuit breaker stops loops on permanently broken configs.
        // First tick is ~90s after spawn so the startup apply above has
        // settled.
        crate::networking::router::spawn_dnsmasq_watchdog(
            app_state.router.clone(),
            node_id.clone(),
        );

        // WolfAgents: one-shot migration for pre-v18.6.1 agents that
        // were created with an empty allowed_tools list. Runs before
        // the API starts serving so the first agent chat after upgrade
        // already has its tools available.
        wolfagents::migrate_empty_allowed_tools();

        // WolfUSB: init with cluster secret and restore assignments on startup
        wolfusb::init(&cluster_secret);
        {
            let nid = node_id.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                tokio::task::spawn_blocking(move || {
                    wolfusb::ensure_wolfusb_server();
                    wolfusb::restore_assignments(&nid);
                }).await.ok();
            });
        }

        // WolfUSB SOURCE-side restore (PapaSchlumpf/wabil 2026-06-17): when THIS
        // node is the USB *host* (the exporter with the device physically
        // plugged in) and it reboots, the device used to come back unexported
        // and the target couldn't reconnect until a manual remove + re-assign.
        // `restore_assignments` above only re-establishes the TARGET side — it
        // has no branch for assignments where this node is the SOURCE. Fill that
        // gap by re-driving each such assignment through the exact recovery the
        // manual "Re-attach" button runs (`POST /api/wolfusb/reattach/{busid}`):
        // for a remote target we poke the target node (it calls back here for
        // prepare-for-export, then re-installs its mount unit + re-passes the
        // device through); a same-node assignment recovers locally.
        {
            let nid = node_id.clone();
            let secret = cluster_secret.clone();
            let cluster_usb = cluster.clone();
            tokio::spawn(async move {
                // Run after the target-side restore (5s) so a whole-cluster
                // reboot doesn't have both ends fighting over the mount unit.
                tokio::time::sleep(std::time::Duration::from_secs(12)).await;
                let config = wolfusb::WolfUsbConfig::load();
                if !config.enabled { return; }
                let mine: Vec<wolfusb::UsbAssignment> = config.assignments.iter()
                    .filter(|a| a.source_node_id == nid)
                    .cloned()
                    .collect();
                if mine.is_empty() || !wolfusb::is_wolfusb_available() { return; }
                info!("WolfUSB: re-driving {} source-side assignment(s) after startup", mine.len());
                for a in &mine {
                    if a.target_node_id == nid {
                        // Source and target are the same node — recover locally.
                        let busid = a.busid.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            wolfusb::reattach_local(&busid, None)
                        }).await;
                        continue;
                    }
                    // Remote target — trigger its full Re-attach recovery.
                    // Resolve by either id form (map-key or canonical self_id):
                    // the assignment usually stores the target's canonical ws-…
                    // self_id, but this node keys the peer under a node-… map key,
                    // so a raw n.id== scan would miss it and silently skip the
                    // restore (same class as the re-attach source-lookup bug).
                    let Some(target) = cluster_usb.get_node(&a.target_node_id) else {
                        warn!("WolfUSB: target node {} for {} not in cluster — skipping source-side restore",
                            a.target_node_id, a.busid);
                        continue;
                    };
                    let urls = api::build_node_urls(&target.address, target.port,
                        &format!("/api/wolfusb/reattach/{}", a.busid));
                    let client = &*api::API_HTTP_CLIENT;
                    let mut ok = false;
                    for url in &urls {
                        if let Ok(r) = client.post(url)
                            .timeout(std::time::Duration::from_secs(60))
                            .peer_auth(&secret)
                            .send().await
                            && r.status().is_success()
                        {
                            ok = true;
                            break;
                        }
                    }
                    if ok {
                        info!("WolfUSB: re-attach triggered on {} for {}", target.hostname, a.busid);
                    } else {
                        warn!("WolfUSB: could not trigger re-attach on {} for {} (target offline?) — \
                               its own mount unit will keep retrying", target.hostname, a.busid);
                    }
                }
            });
        }

        // Background: periodic self-monitoring update
        let state_clone = app_state.clone();
        let cluster_clone = cluster.clone();
        // Clone public_ip for the background task
        // Deadman-switch tick — every second, check pending dangerous
        // ops and auto-rollback any whose TTL has expired. See
        // src/danger.rs for the design. Cheap (HashMap scan + Instant
        // elapsed check); runs unconditionally so every node enforces
        // its own rollback window even if the orchestrator's dead.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                tokio::task::spawn_blocking(danger::tick).await.ok();
            }
        });

        // Threat-intel scheduler: every minute, refresh feeds when the
        // configured interval has elapsed. No-op when disabled (~1µs config
        // file read). Lives separate from the WolfRouter apply path —
        // refresh_all updates the cache + ipset, build_ruleset's hook
        // picks the result up on the next firewall apply.
        {
            let cluster_for_ti = cluster.clone();
            tokio::spawn(async move {
                threat_intel::scheduler_loop(cluster_for_ti).await;
            });
        }

        // Hook A for WolfNet endpoint self-healing — one-shot startup
        // pass 30s after launch. By then the first cluster gossip cycle
        // has run and we have public_ip for any peer that's online;
        // offline peers stay roaming-only until they come back and hit
        // Hook B (the gossip-arrival check in agent::mod).
        //
        // The pass is BATCHED in a single function call: one config
        // read, all changes applied in-memory, one config write, one
        // reload/restart. This is a critical behaviour change from
        // 22.14.8 — that version called the per-peer reconciler in a
        // loop, and each call independently restarted wolfnet via
        // systemctl, which on klasSponsor's cluster (3+ NAT'd peers)
        // immediately hit systemd's default `StartLimitBurst=5/10s`
        // and left wolfnet permanently dead. Batching collapses N
        // restarts to 1.
        //
        // The batched call also scans for ORPHAN peers — wolfnet
        // config entries that aren't wolfstack cluster members but
        // have loop-inducing endpoints (klasSponsor's unifios case,
        // a UniFi router with a stale `10.100.10.1:9634` endpoint).
        //
        // Runs 30s after launch (first gossip cycle done) and then every
        // 5 minutes, so it also self-heals drift that appears at runtime —
        // notably a stale/wrong peer `allowed_ip` in config.toml (klasSponsor
        // 2026-06-04: a VPS that showed peers as 10.10.20.x instead of
        // 10.100.10.x). The batch no-ops (one config read, no write, no
        // reload) when nothing has drifted, so the periodic cadence is cheap.
        {
            let cluster_for_wnfix = cluster.clone();
            tokio::spawn(async move {
                // Initial settle delay so the first cluster poll has
                // populated peer WolfNet IPs before we self-heal the config.
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
                loop {
                    tick.tick().await; // first tick fires immediately
                    let self_addr = cluster_for_wnfix.self_address.clone();
                    // Cluster-scope the targets. The WolfNet IP self-heal writes
                    // to /etc/wolfnet/config.toml, so it must only ever trust
                    // peers in THIS cluster — feeding another cluster's nodes in
                    // (a hostname collision on a shared /24 would slip past the
                    // subnet guard) is exactly the cross-cluster poisoning class
                    // that bit klasSponsor before (v24.3.6). Same membership test
                    // the subnet-route path uses in agent::poll.
                    let self_cluster = cluster_for_wnfix.get_self_cluster_name();
                    let targets: Vec<crate::networking::ReconcileTarget> = cluster_for_wnfix
                        .get_all_nodes()
                        .into_iter()
                        .filter(|n| !n.is_self
                            && n.node_type == "wolfstack"
                            && n.cluster_name.as_deref().unwrap_or("WolfStack") == self_cluster)
                        .map(|n| {
                            // Authoritative WolfNet IP = the peer's own live
                            // wolfnet0 address, recorded from gossip. Borrow
                            // n.address before it's moved into lan_address.
                            let wolfnet_ip = crate::api::lookup_node_wolfnet_ip(&n.address);
                            crate::networking::ReconcileTarget {
                                hostname: n.hostname,
                                lan_address: Some(n.address),
                                public_ip: n.public_ip,
                                wolfnet_ip,
                            }
                        })
                        .collect();
                    tokio::task::spawn_blocking(move || {
                        match crate::networking::reconcile_wolfnet_peers_batch(&self_addr, &targets) {
                            Ok(0) => {}
                            Ok(n) => tracing::info!(
                                "WolfNet reconcile: {} peer entr{} updated",
                                n, if n == 1 { "y" } else { "ies" }
                            ),
                            Err(e) => tracing::warn!("WolfNet reconcile failed: {}", e),
                        }
                    }).await.ok();
                }
            });
        }

        // Daily certbot renewal. Runs certbot's own `renew --quiet`
        // which is a no-op for any cert with >30 days left, so it's
        // cheap to fire every 24h. Skipped by config flag and when
        // certbot isn't installed — both checked inside renew_due.
        // First run after 60s so we don't race the service into a
        // fresh LE hit at every restart.
        let cluster_renew = app_state.cluster.clone();
        let secret_renew = app_state.cluster_secret.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            loop {
                tokio::task::spawn_blocking(|| {
                    let _ = certbot::renew_due();
                }).await.ok();
                // certbot may have just rotated a key. Push the new
                // material now instead of leaving every replica stale
                // until the next periodic reconcile.
                api::reconcile_cert_replication(cluster_renew.clone(), secret_renew.clone()).await;
                tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
            }
        });

        // Periodic certificate-replication reconcile.
        //
        // This is the leg that catches renewals WolfStack did NOT perform
        // itself — the distro's own certbot systemd timer, or an operator
        // running certbot by hand — neither of which tells us anything.
        // Comparing digests rather than listening for an event is what
        // makes those paths safe, and it self-heals a rebuilt peer too.
        //
        // 15 minutes is far tighter than strictly needed (certs renew 30
        // days before expiry, so staleness is never dangerous) and a
        // steady-state pass is one small GET per peer that moves no key
        // material. First run at 90s so cluster state is populated.
        let cluster_certrep = app_state.cluster.clone();
        let secret_certrep = app_state.cluster_secret.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(90)).await;
            loop {
                api::reconcile_cert_replication(cluster_certrep.clone(), secret_certrep.clone()).await;
                tokio::time::sleep(Duration::from_secs(15 * 60)).await;
            }
        });

        let public_ip = public_ip.clone();
        let cached_status_bg = cached_status.clone();
        // Agent nodes: relax the self-monitor cadence 2s→5s. This is the
        // most frequent loop (collects sysinfo + docker/lxc/vm counts every
        // tick), and the MANAGER only polls the agent every 10s, so 5s is
        // still fresher than the consumer — cutting this loop's allocation
        // rate ~2.5× on RAM-constrained agents (agent-mode reduction).
        let self_monitor_secs = if agent_mode { 5 } else { 2 };
        tokio::spawn(async move {
            loop {
                // Collect IMMEDIATELY on the first pass — the sleep is at the
                // BOTTOM of this loop deliberately.
                //
                // Sleeping first left `cached_status` as None for the first
                // couple of seconds after every start. `agent_status` serves
                // peers from that cache, and on a cluster with real traffic
                // every poll arriving in that window used to fall through to
                // its own full collection: a blocking thread each, all
                // contending on `monitor`. The pool capped at 512, tokio's
                // blocking queue is unbounded, and THIS task's own
                // spawn_blocking then queued behind the stampede it caused —
                // so the cache could never be populated and the node never
                // recovered. Requests stopped returning, actix could not
                // close their sockets, and inbound CLOSE-WAIT grew without
                // limit until the descriptor table was gone.
                //
                // Populating before serving closes the window; `agent_status`
                // no longer collects on a miss, which removes the stampede
                // even if the window is somehow hit.
                // Run all blocking sysinfo/subprocess work off the async runtime.
                let sc = state_clone.clone();
                let (metrics, components, docker_count, lxc_count, vm_count, compose_count, has_docker, has_lxc, has_kvm, wn_active, wn_reserved) =
                    tokio::task::spawn_blocking(move || {
                        let mut monitor = sc.monitor.lock().unwrap();
                        let m = monitor.collect();
                        drop(monitor);  // release mutex before spawning subprocesses
                        let c = installer::get_all_status_cached();
                        let dc = containers::docker_count();
                        let lc = containers::lxc_count();
                        let vc = sc.vms.lock().unwrap().list_vms().len() as u32;
                        // Compose count is a cheap dir scan, but it's still
                        // blocking I/O — keep it inside spawn_blocking with the
                        // other counts (v25.0.0 offloaded exactly this).
                        let cmc = crate::api::compose_stack_count();
                        let hd = containers::has_docker_cached();
                        let hl = containers::has_lxc_cached();
                        let hk = containers::has_kvm_cached();
                        // Both WolfNet scans shell out (ip, docker, lxc-info,
                        // VM json) — they belong here, not on the executor.
                        let wa = containers::wolfnet_active_ips_cached();
                        let wr = containers::wolfnet_used_ips_cached();
                        (m, c, dc, lc, vc, cmc, hd, hl, hk, wa, wr)
                    }).await.unwrap();
                // Record historical snapshot
                {
                    let mut history = state_clone.metrics_history.lock().unwrap();
                    history.push(&metrics);
                }

                // Cache the agent status report for instant polling responses
                let self_id = cluster_clone.self_id.clone();
                let hostname = metrics.hostname.clone();
                let known_nodes = cluster_clone.get_all_nodes();
                let deleted_ids = cluster_clone.get_deleted_ids();
                let msg = agent::AgentMessage::StatusReport {
                    node_id: self_id,
                    hostname,
                    metrics: metrics.clone(),
                    components: components.clone(),
                    docker_count,
                    lxc_count,
                    vm_count,
                    compose_count,
                    public_ip: public_ip.read().await.clone(),
                    known_nodes,
                    deleted_ids,
                    wolfnet_ips: wn_active,
                    wolfnet_reserved_ips: wn_reserved,
                    has_docker,
                    has_lxc,
                    has_kvm,
                    workload_subnets: networking::collect_workload_subnets(),
                    // Self's declared site tag — gossiped to peers so
                    // their cluster-sync can choose LAN-dial vs public-dial.
                    site: cluster_clone.get_node(&cluster_clone.self_id).and_then(|n| n.site),
                    // Self's operator-set display name — gossiped so peers
                    // show the chosen name, not the OS hostname.
                    display_name: cluster_clone.get_node(&cluster_clone.self_id).and_then(|n| n.display_name),
                    // Self's assigned tier roles — gossiped so peers know the
                    // DNS / mail / ingress / host tier membership.
                    roles: cluster_clone.get_node(&cluster_clone.self_id).map(|n| n.roles).unwrap_or_default(),
                    // Propagate license to cluster nodes
                    license_key: if crate::compat::platform_ready() {
                        std::fs::read_to_string(crate::compat::dm_path()).ok().map(|s| s.trim().to_string())
                    } else { None },
                    pubkey: node_identity::self_pubkey(),
                };
                if let Ok(json) = serde_json::to_value(&msg)
                    && let Ok(mut cache) = cached_status_bg.write() {
                        *cache = Some(json);
                    }

                cluster_clone.update_self(metrics, components, docker_count, lxc_count, vm_count, compose_count, public_ip.read().await.clone(), has_docker, has_lxc, has_kvm, tls_enabled);

                // Sleep at the BOTTOM so the first collection happens at
                // startup rather than `self_monitor_secs` after it. See the
                // note at the top of this loop.
                tokio::time::sleep(Duration::from_secs(self_monitor_secs)).await;
            }
        });

        // Background: poll remote nodes.
        //
        // Re-load the cluster secret from disk on every iteration. The
        // pre-fix version held a boot-time `cluster_secret.clone()` for
        // the lifetime of the process, which meant a secret rotation
        // (Settings -> Security, or fleet rotation API) only took
        // effect on the SENDER side after a full wolfstack restart —
        // even though receivers already re-read disk on every auth call
        // (`validate_inter_node_secret`). That asymmetry quietly broke
        // route propagation across an entire fleet: the poll kept
        // sending the pre-rotation secret, every peer's receiver
        // returned 403, mouse never learned dreamer's container routes,
        // dreamer never learned mouse's. Every inter-node sender now
        // re-reads the secret per iteration — this poll included.
        let cluster_poll = cluster.clone();
        let ai_agent_poll = ai_agent.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let secret = auth::load_cluster_secret();
                agent::poll_remote_nodes(cluster_poll.clone(), secret, Some(ai_agent_poll.clone())).await;
            }
        });

        // WolfHA: boot-time takeover check for HA primaries (their
        // lxc.start.auto is stripped, so lxc-autostart never races this),
        // then the periodic replication scheduler and the auto-failover
        // monitor. Delayed 30s so the cluster poll above has populated
        // peer reachability first.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            wolfha::boot_guard().await;
        });
        tokio::spawn(wolfha::scheduler_forever());
        let wolfha_cluster = cluster.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(45)).await;
            wolfha::failover_monitor_forever(wolfha_cluster).await;
        });

        // The retroactive cluster-name sweep that used to run here was
        // removed in v25.5.5 — see the tombstone in agent/mod.rs above the
        // identity-intent queue. It re-asserted a MIRRORED value as a
        // command every 30 minutes and undid operator corrections. Cluster
        // and display identity now propagate solely via the identity-intent
        // sweep spawned below, which carries a recorded operator intent and
        // clears once the owning node confirms it.

        // Background: identity-intent reconcile sweep. Re-pushes operator
        // renames (display_name) and moves (cluster_name) to each owning node
        // until its self-report confirms the value, then clears the intent.
        // This is what makes an edit to an offline/blipped node "apply on
        // reconnect" instead of silently reverting. 60s cadence; first run at
        // T+20s catches a node that was offline during the edit.
        let cluster_intents = cluster.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(20)).await;
            loop {
                let secret = auth::load_cluster_secret();
                agent::sweep_identity_intents(cluster_intents.clone(), secret).await;
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });

        // Background: control-plane replication sweep. Converges cluster
        // membership (so ANY node shows the whole fleet, not just the node the
        // cluster was built on) AND replicates WolfStack users + auth config
        // last-write-wins, so a user created on one node can log in on any
        // node. 30s cadence heals peers that were offline when a change's
        // immediate push fired. Secret re-read each tick (survives rotation).
        let cluster_repl = cluster.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(20)).await;
            loop {
                let secret = auth::load_cluster_secret();
                agent::sweep_replicate_control_plane(cluster_repl.clone(), secret).await;
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });

        // Background: clean up stale WolfNet kernel routes (every 60s)
        // Only runs if WolfNet is configured (cleanup fn returns early if not)
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                tokio::task::spawn_blocking(|| {
                    containers::cleanup_stale_wolfnet_routes();
                }).await.ok();
            }
        });

        // Background: clean up duplicate IPs on `br-pt-*` slaves (every
        // 60s). Bridge-creation flushes the slave's IP, but NetworkManager
        // / systemd-networkd / dhclient on the slave often re-add it
        // afterwards — leaving the same IP on both the slave and the
        // bridge, plus duplicate routes. PapaSchlumpf's `ens1` /
        // `br-pt-ens1` both had 10.10.10.1/24 with two routes for
        // 10.10.10.0/24 from this exact race. The reconciliation only
        // removes IPs from the slave that ALSO exist on the bridge —
        // never the slave's only address.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                tokio::task::spawn_blocking(|| {
                    networking::cleanup_passthrough_slave_ips();
                }).await.ok();
            }
        });

        // Background: reconcile IP mappings (DNAT rules) until every
        // enabled mapping has its iptables rules in place. The
        // synchronous startup pass at boot fails silently when wolfnet0
        // isn't ready yet — typical right after a reboot, before
        // WireGuard establishes the mesh and assigns the wolfnet0
        // address. Without this loop, a node that boots with WolfStack
        // starting before WolfNet has no DNAT rules and the operator
        // only sees a `warn!` line in journalctl that nobody reads
        // (PapaSchlumpf's Frigate / Home Assistant
        // mapped-but-unreachable symptom). The retry tick is 5s while
        // any mapping is still failing, 30s once everything's settled.
        // `apply_ip_mappings` is idempotent — `apply_mapping_rules`
        // calls `purge_mapping_rules` first — so re-running over a
        // healthy state is a safe ~2 iptables ops per mapping.
        tokio::spawn(async move {
            let mut interval_secs = 30u64;
            loop {
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
                let failed = tokio::task::spawn_blocking(networking::apply_ip_mappings)
                    .await
                    .unwrap_or(0);
                interval_secs = if failed > 0 { 5 } else { 30 };
            }
        });

        // Background: re-apply hardware VLAN offload disable on passthrough
        // NICs (every 30s). `ethtool -K` is session-local — when a NIC link
        // bounces (NM refresh, hostname-network restart, cable flap, driver
        // reload) the kernel resets offloads to driver defaults. Without
        // this, OPNsense + VLAN trunking gets a few good DHCP handshakes
        // then silently breaks once anything cycles the link.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                tokio::task::spawn_blocking(|| {
                    let m = vms::manager::VmManager::new();
                    m.reapply_passthrough_offloads();
                }).await.ok();
            }
        });

        // Discord bot supervisor — idle until the operator configures
        // a bot token in Settings → Alerting, then connects to the
        // Discord gateway and routes messages in agent-bound channels
        // to the right WolfAgent. Fails open: if the token is invalid
        // or Discord is unreachable, the supervisor retries every 30s
        // without affecting the rest of the server.
        // Clone the shared AppState into each surface-supervisor task
        // so Telegram / Discord-originated chats can run the full
        // tool-use loop — not just simple_chat. Without this, models
        // that follow the system-prompt tool directive (Gemini, some
        // Claude revisions) would get UNEXPECTED_TOOL_CALL errors
        // because the no-tools fallback couldn't honour the prompt.
        let discord_state = app_state.clone();
        tokio::spawn(async move {
            crate::discord_bot::supervise_forever(discord_state).await;
        });

        // Telegram receiver — same idea as Discord but simpler
        // (HTTP long-polling; no gateway, no heartbeat). Idle until
        // the operator turns on telegram_receiver_enabled AND a
        // telegram_bot_token is set.
        let telegram_state = app_state.clone();
        tokio::spawn(async move {
            crate::telegram_bot::supervise_forever(telegram_state).await;
        });

        // Background: re-broadcast this node's shares so peers that were
        // offline during a create/delete still converge. Delivery on
        // change is best-effort and skips offline peers, which is how a
        // deleted share could survive on some nodes indefinitely.
        let gateway_sync_state = app_state.clone();
        tokio::spawn(async move {
            crate::api::gateway_resync_loop(gateway_sync_state).await;
        });

        // Background: session + login rate limiter + reset token cleanup.
        // Also sweeps expired OIDC pending-flow state tokens — pre-v18.7.30
        // that map grew without bound because the TTL was only checked
        // on successful callback lookup, so an attacker (or a buggy IdP)
        // that initiated flows without ever completing them could
        // exhaust memory.
        let sessions_cleanup = sessions.clone();
        let login_limiter_cleanup = app_state.login_limiter.clone();
        let reset_tokens_cleanup = app_state.password_reset_tokens.clone();
        let oidc_flows_cleanup = app_state.oidc_pending_flows.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(300)).await;
                sessions_cleanup.cleanup();
                login_limiter_cleanup.cleanup();
                reset_tokens_cleanup.cleanup();
                // OIDC flows: 5 minute TTL. Walk the map and drop any
                // entry whose creation timestamp is older than that.
                {
                    let mut flows = oidc_flows_cleanup.write().unwrap();
                    let now = std::time::Instant::now();
                    flows.retain(|_state, flow| {
                        now.duration_since(flow.created_at).as_secs() < 300
                    });
                }
            }
        });

        // Background: backup schedule checker (every 60s).
        // check_schedules() is synchronous and ultimately runs
        // qemu-img convert / tar over multi-GB VM disks — call it via
        // spawn_blocking so a long backup can't starve the Tokio
        // worker threads (which would also block the actix workers
        // that share the same runtime).
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                if let Err(e) = tokio::task::spawn_blocking(backup::check_schedules).await {
                    // A panic inside check_schedules would surface here
                    // as a JoinError. Log it so we don't silently lose
                    // the scheduler loop (the spawn itself keeps the
                    // loop alive because each iteration spawns afresh).
                    tracing::error!("backup::check_schedules panicked: {}", e);
                }
            }
        });

        // Boot: re-apply persisted "interface UP" intents from the UI.
        // Retries every 10s for ~5 minutes because the motivating case is
        // a USB NIC (RutgerDiehard, 2026-08-18) — USB enumeration can land
        // well after this daemon starts, and a single early attempt would
        // miss it. Each attempt only touches recorded NICs that exist and
        // are down, so the loop is idle-cheap and fights no other manager.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            for attempt in 0..30 {
                let outstanding =
                    match tokio::task::spawn_blocking(networking::link_persist::apply_once).await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::error!("link_persist::apply_once panicked: {}", e);
                            break;
                        }
                    };
                if outstanding.is_empty() {
                    break;
                }
                if attempt == 29 {
                    tracing::warn!(
                        "boot link-up: gave up waiting for {:?} after 5 minutes — device never appeared",
                        outstanding
                    );
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        // Background: S3 remote endpoint health probes (every 60s tick; each
        // remote is actually probed every ~5min with per-remote jitter — see
        // storage::s3_health). run_due_probes builds its own current-thread
        // runtime for the S3 calls, so it must run via spawn_blocking, not
        // inline on the Tokio workers. Alert edges (outage after 3 misses,
        // recovery) come back as values and are dispatched here, where
        // awaiting send_local_alert is possible. First round waits 90s so a
        // booting node isn't declared an outage while the network settles.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(90)).await;
            loop {
                match tokio::task::spawn_blocking(storage::s3_health::run_due_probes).await {
                    Ok(alerts) => {
                        for alert in alerts {
                            // Outages at warn, recoveries at info — the
                            // journal tells the story even with no alert
                            // channels configured.
                            if alert.recovered {
                                tracing::info!("{}", alert.title);
                            } else {
                                tracing::warn!("{}", alert.title);
                            }
                            crate::alerting::send_local_alert(
                                crate::alerting::AlertCategory::Threshold,
                                &alert.title,
                                &alert.body,
                            )
                            .await;
                        }
                    }
                    Err(e) => {
                        // A panic inside run_due_probes surfaces as a
                        // JoinError — log it so the probe loop's death is
                        // visible, and keep looping (each round respawns).
                        tracing::error!("s3_health::run_due_probes panicked: {}", e);
                    }
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });

        // Background: S3 bucket-sync scheduler (every 60s). due_jobs_and_alerts
        // is a cheap config read + schedule arithmetic; each due job's rclone
        // pass runs on its own blocking thread (a pass can take hours — the
        // engine's in-process single-flight stops the next tick doubling it
        // up, and back-to-back schedules key off the previous pass's END).
        // Lag alerts ("job hasn't succeeded in 3× its cadence") dispatch here.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(120)).await;
            loop {
                let (due, alerts) = storage::s3_sync::due_jobs_and_alerts();
                for alert in alerts {
                    tracing::warn!("{}", alert.title);
                    crate::alerting::send_local_alert(
                        crate::alerting::AlertCategory::Threshold,
                        &alert.title,
                        &alert.body,
                    )
                    .await;
                }
                for job_id in due {
                    tokio::task::spawn_blocking(move || {
                        if let Err(e) = storage::s3_sync::run_job(&job_id) {
                            // "already running" lands here harmlessly if a
                            // manual run raced the tick; real failures are
                            // in the job's run record too.
                            tracing::warn!("s3-sync scheduled run: {}", e);
                        }
                    });
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });

        // Background: reclaim staging left by backups that died before they
        // could clean up (crash, OOM kill, restart mid-archive). Runs once
        // shortly after boot — which is when a node that filled its disk
        // overnight most needs the space back — then hourly. The sweep only
        // touches entries older than a day that no running backup owns, so it
        // is safe to run alongside an in-flight job.
        tokio::spawn(async move {
            // Containers stuck frozen under a hung lxc-freeze (left by a
            // pre-v25.20.x backup across an upgrade, or anything else) are
            // thawed IMMEDIATELY at boot — a frozen container is a live
            // outage (legolas, 2026-08-26), unlike stale staging files
            // which can wait the 120s below.
            if let Err(e) = tokio::task::spawn_blocking(backup::sweep_frozen_orphans).await {
                tracing::error!("backup::sweep_frozen_orphans panicked: {}", e);
            }
            // A container left holding a `backup`/`snapshot` lock by a task
            // that died is unoperable until the lock goes — same urgency as a
            // frozen one, so it is also cleared immediately at boot.
            if let Err(e) = tokio::task::spawn_blocking(containers::sweep_stale_lxc_locks).await {
                tracing::error!("containers::sweep_stale_lxc_locks panicked: {}", e);
            }
            tokio::time::sleep(Duration::from_secs(120)).await;
            loop {
                if let Err(e) = tokio::task::spawn_blocking(backup::sweep_staging_orphans).await {
                    tracing::error!("backup::sweep_staging_orphans panicked: {}", e);
                }
                if let Err(e) = tokio::task::spawn_blocking(backup::sweep_frozen_orphans).await {
                    tracing::error!("backup::sweep_frozen_orphans panicked: {}", e);
                }
                if let Err(e) = tokio::task::spawn_blocking(containers::sweep_stale_lxc_locks).await {
                    tracing::error!("containers::sweep_stale_lxc_locks panicked: {}", e);
                }
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });

        // Cluster service discovery — runs on demand only (triggered
        // by the Cluster Browser page on load). Restore the previous
        // sweep's cache from disk so the first API hit returns
        // something instead of an empty list.
        services_discovery::restore_cache();

        // Background: cluster browser session reconciliation (every 60s)
        // — prunes ghost sessions whose container died. Manager-only:
        // browser sessions are a manager-UI feature (agent-mode reduction).
        if !agent_mode {
            tokio::spawn(cluster_browser::run_reconcile_loop());
        }

        // Background: Internet Exposure — refresh each exposed workload's
        // upstream so its public URL keeps working after the workload
        // restarts or MOVES NODE. Uses the cached container list (no
        // shell-out) so the config lock is held only briefly; only
        // re-renders when an upstream actually changed — and then also
        // replicates the router config, because the hosting node is
        // usually NOT the ingress node that renders the route.
        {
            let exp_state = app_state.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
                loop {
                    tick.tick().await;
                    let router = exp_state.router.clone();
                    let cluster = exp_state.cluster.clone();
                    let changed = tokio::task::spawn_blocking(move || {
                        let self_id = crate::agent::self_node_id();
                        let changed = {
                            let mut cfg = router.config.write().unwrap();
                            let mut proxies = cfg.http_proxies.clone();
                            if crate::exposure::reconcile_upstreams(&mut proxies, &cluster) {
                                cfg.http_proxies = proxies.clone();
                                let _ = cfg.save();
                                Some(proxies)
                            } else {
                                None
                            }
                        };
                        if let Some(proxies) = &changed {
                            crate::networking::router::http_proxy::apply_for_node(proxies, &self_id);
                        }
                        changed.is_some()
                    })
                    .await
                    .unwrap_or(false);
                    if changed {
                        crate::networking::router::api::replicate_config_to_cluster(exp_state.clone());
                    }
                }
            });
        }

        // Background: WolfFlow scheduler (every 60s)
        {
            let wf_state = wolfflow_state.clone();
            let wf_cluster = cluster.clone();
            let wf_secret = cluster_secret.clone();
            let wf_ai = app_state.ai_agent.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    let due = wf_state.get_due_workflows();
                    for workflow in due {
                        let s = wf_state.clone();
                        let c = wf_cluster.clone();
                        let sec = wf_secret.clone();
                        let ai_cfg = wf_ai.config.lock().unwrap().clone();
                        tokio::spawn(async move {
                            wolfflow::execute_workflow(&s, &c, &sec, "wolfflow-scheduler", &workflow, "scheduled", Some(ai_cfg)).await;
                        });
                    }
                }
            });
        }

        // Background: Patreon membership sync (every 24h)
        let patreon_state = app_state.patreon.clone();
        tokio::spawn(async move {
            // Initial delay — let the server settle before first check
            tokio::time::sleep(Duration::from_secs(60)).await;
            loop {
                if patreon_state.config.read().map(|c| c.linked).unwrap_or(false) {
                    match patreon_state.sync_membership().await {
                        Ok(tier) => info!("Patreon tier synced: {:?}", tier),
                        Err(e) => warn!("Patreon sync failed: {}", e),
                    }
                }
                tokio::time::sleep(Duration::from_secs(86400)).await; // 24 hours
            }
        });

        // Background: Enterprise license heartbeat (once daily)
        // Reports server hostname, version, and cluster name to IntelligentWolf
        // for license compliance. Fire-and-forget — never blocks the server.
        {
            let hb_cluster = cluster.clone();
            tokio::spawn(async move {
                // Initial delay — first heartbeat 5 minutes after boot
                tokio::time::sleep(Duration::from_secs(300)).await;
                loop {
                    if crate::compat::platform_ready() {
                        crate::compat::report_license_heartbeat(&hb_cluster).await;
                    }
                    tokio::time::sleep(Duration::from_secs(86400)).await; // once per day
                }
            });
        }

        // Background: image watcher — periodic check + auto-apply for
        // Docker container image updates. The check populates a cache
        // that the UI reads; the auto-apply step is gated by:
        //   - Per-container `AutoUpdate` policy
        //   - Cluster-wide maintenance window (cron + duration); when
        //     no window is configured, applies fire immediately on
        //     detection.
        //   - `max_parallel_updates` (default 1) bound via a Semaphore
        //     so a host with 20 containers doesn't get crushed by 20
        //     concurrent docker pulls.
        // Each applied update is recorded as an `ImageUpdateEvent` in
        // `config.update_history` (capped at the most-recent 200) so
        // the operator has a full audit trail.
        {
            let iw_cache = app_state.image_watcher_cache.clone();
            let iw_wake = app_state.image_watcher_wake.clone();
            tokio::spawn(async move {
                use crate::containers::image_watcher as iw;
                tokio::time::sleep(Duration::from_secs(120)).await;
                loop {
                    let config = iw::ImageWatcherConfig::load();
                    if config.enabled {
                        // ── CHECK pass ──
                        // Honour per-container check frequency: pass the last
                        // results so containers still within their interval
                        // are carried forward, not re-queried.
                        let prev = { iw_cache.read().unwrap().clone() };
                        let (results, checked_now) = iw::check_due_containers(&config, &prev).await;
                        {
                            let mut cache = iw_cache.write().unwrap();
                            for r in &results {
                                cache.insert(r.container_name.clone(), r.clone());
                            }
                        }

                        // ── APPLY pass ──
                        // Only fires when a maintenance window is open
                        // (or no schedule is set). Returns the events
                        // produced so we can fold them into history.
                        let now = chrono::Utc::now().naive_utc();
                        if config.auto_apply_window_open(now) {
                            let pending: Vec<String> = results.iter()
                                .filter(|r| r.update_available && r.error.is_none())
                                .map(|r| r.container_name.clone())
                                // ONLY containers re-queried this pass — a
                                // carried-forward (stale) "update available"
                                // must never re-apply, or a failed auto-update
                                // would retry on every loop wake.
                                .filter(|name| checked_now.contains(name))
                                .filter(|name| config.policy_for(name).is_auto_apply())
                                .collect();
                            if !pending.is_empty() {
                                let max_parallel = config.max_parallel_updates.max(1);
                                tracing::info!(
                                    "image_watcher: auto-applying {} update(s) (max_parallel={})",
                                    pending.len(), max_parallel,
                                );
                                let sem = std::sync::Arc::new(
                                    tokio::sync::Semaphore::new(max_parallel),
                                );
                                let mut handles = Vec::new();
                                for name in pending {
                                    let sem = sem.clone();
                                    let cfg = config.clone();
                                    // Keep an outer-scope copy of the
                                    // container name so a worker-join
                                    // failure can be attributed in the
                                    // audit trail. Without this the
                                    // fallback event records "<unknown>"
                                    // and the operator can't tell which
                                    // update misbehaved.
                                    let fallback_name = name.clone();
                                    handles.push(tokio::spawn(async move {
                                        let _permit = sem.acquire_owned().await
                                            .expect("semaphore closed");
                                        tokio::task::spawn_blocking(move || {
                                            iw::perform_update_blocking(&name, &cfg)
                                        }).await.unwrap_or_else(|join_err| {
                                            let event = iw::ImageUpdateEvent {
                                                id: format!("evt-join-{}", chrono::Utc::now().timestamp()),
                                                container_name: fallback_name,
                                                image: String::new(),
                                                old_digest: String::new(),
                                                new_digest: String::new(),
                                                backup_id: None,
                                                status: iw::ImageUpdateStatus::Failed,
                                                timestamp: chrono::Utc::now().to_rfc3339(),
                                                error: Some(format!("worker join failed: {}", join_err)),
                                            };
                                            // The wrapper inside perform_update_blocking never
                                            // returned, so it fired nothing — a joined-failed
                                            // update is still an update failure.
                                            wolffunctions::fire_event_global(
                                                wolffunctions::TriggerEvent::ContainerUpdateFailed,
                                                serde_json::to_value(&event).unwrap_or_default(),
                                                true,
                                            );
                                            event
                                        })
                                    }));
                                }
                                let mut events: Vec<iw::ImageUpdateEvent> = Vec::with_capacity(handles.len());
                                for h in handles {
                                    if let Ok(ev) = h.await {
                                        events.push(ev);
                                    }
                                }
                                // A completed apply means the local image now
                                // matches remote — clear the cached "update
                                // available" flag. Otherwise a container whose
                                // next per-container check isn't due yet would
                                // be carried forward as still-needing-update
                                // and re-applied on every loop tick.
                                {
                                    let mut cache = iw_cache.write().unwrap();
                                    for ev in &events {
                                        if matches!(ev.status, iw::ImageUpdateStatus::Completed)
                                            && let Some(r) = cache.get_mut(&ev.container_name) {
                                                r.update_available = false;
                                                r.last_checked = chrono::Utc::now().to_rfc3339();
                                            }
                                    }
                                }
                                // Persist the audit trail. Reload the
                                // config fresh because the apply pass
                                // can take minutes and the operator
                                // may have edited settings mid-flight.
                                if !events.is_empty() {
                                    let mut latest = iw::ImageWatcherConfig::load();
                                    latest.update_history.extend(events);
                                    let overflow = latest.update_history.len().saturating_sub(200);
                                    if overflow > 0 {
                                        latest.update_history.drain(0..overflow);
                                    }
                                    if let Err(e) = latest.save() {
                                        tracing::warn!(
                                            "image_watcher: failed to persist update history: {}", e,
                                        );
                                    }
                                }
                            }
                        }
                    }
                    // Wake as often as the most-frequently-checked container
                    // needs (the shortest of the global + per-container
                    // intervals, floored at 6h). Containers not yet due are
                    // skipped cheaply inside check_due_containers.
                    //
                    // Phase-locked to this node's stagger slot rather than
                    // sleeping a flat interval from process start. Every node
                    // in a fleet boots within seconds of the others during an
                    // upgrade, so a flat sleep had them all pulling registry
                    // manifests and running `docker inspect` at the same
                    // instant, forever. The slot comes from the WolfNet
                    // address's last octet, so the fleet self-spreads with no
                    // coordination and each node keeps its slot across
                    // restarts.
                    let interval = config.min_effective_interval_secs();
                    let now_unix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let delay = crate::containers::image_watcher::secs_until_next_slot(
                        interval, now_unix,
                    );
                    // Sleep to the slot OR until something asks for a sweep now
                    // (settings enabled, "Check for updates now", a reconcile
                    // that adopted a newer cluster rev). Without the wake arm,
                    // enabling the watcher produced no results for up to six
                    // hours — the floor on the interval — and looked broken.
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
                        _ = iw_wake.notified() => {
                            tracing::info!("image_watcher: woken early — running a sweep now");
                        }
                    }
                }
            });
        }

        // Background: image-watcher cluster-settings reconcile (every 10
        // minutes). Save-time propagation only reaches peers online at that
        // instant; this pull-based pass is what lets a node that was offline,
        // rebuilt, or joined the cluster later converge on the fleet's watcher
        // settings (rev-gated — see image_watcher_reconcile_from_peers). One
        // tiny GET per same-cluster peer per pass; first pass 3 minutes after
        // boot so a freshly joined node starts checking within minutes, not
        // whenever an operator next edits settings.
        {
            let iw_rec_cluster = app_state.cluster.clone();
            let iw_rec_secret = app_state.cluster_secret.clone();
            let iw_rec_wake = app_state.image_watcher_wake.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(180)).await;
                loop {
                    api::image_watcher_reconcile_from_peers(
                        &iw_rec_cluster, &iw_rec_secret, &iw_rec_wake,
                    ).await;
                    tokio::time::sleep(Duration::from_secs(600)).await;
                }
            });
        }

        // Background: integration health checks (every 60 seconds)
        {
            let int_state = app_state.integrations.clone();
            tokio::spawn(async move {
                // Manager-only: integration health is a manager feature
                // (agent-mode reduction).
                if agent_mode { return; }
                tokio::time::sleep(Duration::from_secs(60)).await;
                loop {
                    int_state.check_all_health().await;
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            });
        }

        // Background: scheduled issues scan (configurable alerts + daily summary)
        let scan_state = app_state.clone();
        let scan_ai = ai_agent.clone();
        let scan_cluster = cluster.clone();
        let scan_secret = cluster_secret.clone();
        tokio::spawn(async move {
            // Manager-only: fleet-wide issue scan + daily email report is
            // pure aggregation the manager runs over every node (which it
            // scans on-demand via each node's /api/issues/scan). An agent
            // running it just re-polls the fleet redundantly — the single
            // biggest agent-mode memory saving (agent-mode reduction).
            if agent_mode { return; }
            // Wait 60 seconds after startup before first check
            tokio::time::sleep(Duration::from_secs(60)).await;
            let mut last_daily_date = String::new();
            let mut last_scan_time = std::time::Instant::now();
            // Run first scan immediately after startup delay
            let mut should_scan_now = true;
            let http_client = crate::api::ipv4_only_client_builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default();
            loop {
                // Re-read config each loop to pick up schedule changes
                let config = scan_ai.config.lock().unwrap().clone();
                let schedule = config.scan_schedule.as_str();

                // Determine scan interval from schedule
                let interval_secs: u64 = match schedule {
                    "hourly" => 3600,
                    "6h"     => 6 * 3600,
                    "12h"    => 12 * 3600,
                    "daily"  => 24 * 3600,
                    _        => 0, // "off" — no scanning
                };

                if interval_secs > 0 && config.email_enabled && !config.email_to.is_empty() {
                    // Check if enough time has passed
                    if should_scan_now || last_scan_time.elapsed().as_secs() >= interval_secs {
                        should_scan_now = false;
                        last_scan_time = std::time::Instant::now();

                        // Collect issues from ALL nodes (local + remote)
                        // Each entry: (cluster_name, hostname, issue)
                        let mut all_issues: Vec<(String, String, api::Issue)> = Vec::new();

                        // Local node — sample metrics AND collect issues on the
                        // blocking pool (collect_issues shells out and now probes
                        // SMART per physical disk, so it must not run on an async
                        // worker thread).
                        let ss = scan_state.clone();
                        let (metrics, local_issues) = tokio::task::spawn_blocking(move || {
                            let metrics = ss.monitor.lock().unwrap().collect();
                            let issues = api::collect_issues(&metrics);
                            (metrics, issues)
                        }).await.unwrap();
                        let local_hostname = metrics.hostname.clone();
                        let local_cluster = {
                            let nodes = scan_cluster.get_all_nodes();
                            nodes.iter().find(|n| n.is_self)
                                .and_then(|n| n.cluster_name.clone())
                                .unwrap_or_else(|| "Default".to_string())
                        };
                        for issue in local_issues {
                            all_issues.push((local_cluster.clone(), local_hostname.clone(), issue));
                        }

                        // All remote WolfStack nodes
                        let nodes = scan_cluster.get_all_nodes();
                        for node in nodes.iter().filter(|n| !n.is_self && n.online && n.node_type != "proxmox") {
                            let cluster = node.cluster_name.clone().unwrap_or_else(|| "Default".to_string());
                            let url = node_api_url(node, "/api/issues/scan");
                            match http_client.get(&url)
                                .peer_auth(scan_secret.as_str())
                                .timeout(std::time::Duration::from_secs(30))
                                .send().await
                            {
                                Ok(resp) => {
                                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                                        let node_host = data["hostname"].as_str().unwrap_or(&node.hostname).to_string();
                                        if let Some(issues_arr) = data["issues"].as_array() {
                                            for iv in issues_arr {
                                                if let (Some(sev), Some(cat), Some(title), Some(detail)) = (
                                                    iv["severity"].as_str(), iv["category"].as_str(),
                                                    iv["title"].as_str(), iv["detail"].as_str(),
                                                ) {
                                                    all_issues.push((cluster.clone(), node_host.clone(), api::Issue {
                                                        severity: sev.to_string(), category: cat.to_string(),
                                                        title: title.to_string(), detail: detail.to_string(),
                                                    }));
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("Scheduled scan: failed to reach {}: {}", node.hostname, e);
                                }
                            }
                        }

                        // Sort by cluster name, then hostname (alphabetical)
                        all_issues.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

                        // Write critical and warning issues to the alert log (surfaced in frontend Tasks window)
                        {
                            let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
                            let mut log = scan_state.alert_log.write().unwrap();
                            let mut next_id = log.last().map(|e| e.id + 1).unwrap_or(1);
                            for (cluster, host, issue) in &all_issues {
                                if issue.severity == "critical" || issue.severity == "warning" {
                                    log.push(api::AlertLogEntry {
                                        id: next_id,
                                        timestamp: now.clone(),
                                        severity: issue.severity.clone(),
                                        title: issue.title.clone(),
                                        detail: issue.detail.clone(),
                                        hostname: host.clone(),
                                        cluster: cluster.clone(),
                                    });
                                    next_id += 1;
                                }
                            }
                            // Keep only the last 200 entries
                            if log.len() > 200 {
                                let drain = log.len() - 200;
                                log.drain(..drain);
                            }
                        }

                        let critical_count = all_issues.iter().filter(|(_, _, i)| i.severity == "critical").count();
                        let warning_count = all_issues.iter().filter(|(_, _, i)| i.severity == "warning").count();
                        let info_count = all_issues.iter().filter(|(_, _, i)| i.severity == "info").count();
                        let total_nodes = {
                            let n = scan_cluster.get_all_nodes();
                            n.iter().filter(|nd| nd.node_type != "proxmox").count()
                        };

                        // Helper: format issues grouped by cluster → hostname
                        let format_grouped = |issues: &[(String, String, api::Issue)], filter_sev: Option<&str>| -> String {
                            let mut out = String::new();
                            let mut current_cluster = String::new();
                            let mut current_host = String::new();
                            for (cluster, host, issue) in issues {
                                if let Some(sev) = filter_sev
                                    && issue.severity != sev { continue; }
                                if *cluster != current_cluster {
                                    current_cluster = cluster.clone();
                                    current_host.clear();
                                    out.push_str(&format!("\n━━━ {} ━━━\n", cluster));
                                }
                                if *host != current_host {
                                    current_host = host.clone();
                                    out.push_str(&format!("\n  📍 {}\n", host));
                                }
                                let icon = match issue.severity.as_str() {
                                    "critical" => "❌",
                                    "warning" => "⚠️",
                                    _ => "ℹ️",
                                };
                                out.push_str(&format!("    {} {}\n      {}\n", icon, issue.title, issue.detail));
                            }
                            out
                        };

                        // Immediate alert if critical issues found
                        if critical_count > 0 {
                            let subject = format!(
                                "[WolfStack CRITICAL] {} critical issue(s) across {} node(s)",
                                critical_count, total_nodes
                            );
                            let mut body = format!(
                                "🚨 Critical Issues Detected\nTime: {}\nNodes scanned: {}\n",
                                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"), total_nodes
                            );
                            body.push_str(&format_grouped(&all_issues, Some("critical")));
                            if warning_count > 0 {
                                body.push_str(&format!("\n\n⚠️ Also {} warning(s) — see daily report for details.\n", warning_count));
                            }

                            // AI analysis of all critical issues
                            let critical_summary: String = all_issues.iter()
                                .filter(|(_, _, i)| i.severity == "critical")
                                .map(|(_, host, i)| format!("- {} on {}: {}", i.title, host, i.detail))
                                .collect::<Vec<_>>()
                                .join("\n");
                            let ai_suggestion = scan_ai.analyze_issue(
                                &format!(
                                    "These critical issues were detected across a WolfStack cluster. \
                                     For each issue, suggest what the admin should do to fix it:\n\n{}",
                                    critical_summary
                                )
                            ).await.unwrap_or_default();
                            if !ai_suggestion.is_empty() {
                                body.push_str(&format!("\n\n🤖 AI Recommendations:\n{}", ai_suggestion));
                            }

                            body.push_str(&format!("\nWolfStack v{}", env!("CARGO_PKG_VERSION")));
                            // Aggregated daily-issues mail — Posture category
                            // (mixed bag of config/posture findings). Verbose
                            // only; Simple operators see the inbox.
                            let alert_config = crate::alerting::AlertConfig::load();
                            let posture_allowed = crate::alerting::should_send(
                                &alert_config,
                                crate::alerting::AlertCategory::Posture,
                            );
                            // Stamp the subject + body with `[<cluster> / <host>]`
                            // and the Cluster/Host/When header so the email AND
                            // the webhook recipients see the same originator
                            // metadata.
                            let (subject, body) = crate::alerting::decorate_local(&subject, &body);
                            if posture_allowed {
                                crate::alerting::send_alert_email_if_selected(
                                    &alert_config, &subject, &body,
                                ).await;
                            }

                            // Also send to webhook channels
                            if alert_config.enabled && alert_config.has_channels() {
                                let s = subject.clone();
                                let b = body.clone();
                                tokio::spawn(async move {
                                    crate::alerting::send_alert(
                                        &alert_config,
                                        crate::alerting::AlertCategory::Posture,
                                        &s, &b,
                                    ).await;
                                });
                            }
                            let wn_title = subject.clone();
                            let wn_body = body.clone();
                            tokio::spawn(async move {
                                wolfnote::log_alert_to_wolfnote(&wn_title, &wn_body).await;
                            });
                        }

                        // Daily summary — send once per day (first check after midnight UTC)
                        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                        if today != last_daily_date {
                            last_daily_date = today.clone();

                            let subject = format!(
                                "[WolfStack Daily] {} issue(s) across {} node(s)",
                                all_issues.len(), total_nodes
                            );

                            // ─── Build HTML daily report ───
                            let fmt_bytes = |b: u64| -> String {
                                if b == 0 { return "0 B".to_string(); }
                                let units = ["B", "KB", "MB", "GB", "TB"];
                                let i = (b as f64).log(1024.0).floor() as usize;
                                let i = i.min(units.len() - 1);
                                format!("{:.1} {}", b as f64 / 1024f64.powi(i as i32), units[i])
                            };

                            let mut html = String::from(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8f9fa;color:#1a1a2e;margin:0;padding:20px;}
@media print{body{padding:0;background:#fff;}}
.container{max-width:900px;margin:0 auto;background:#ffffff;border-radius:12px;padding:24px;border:1px solid #e0e0e8;box-shadow:0 2px 8px rgba(0,0,0,0.06);}
h1{color:#1a1a2e;font-size:22px;margin-top:0;border-bottom:3px solid #dc2626;padding-bottom:8px;}
h2{color:#333;font-size:16px;margin:24px 0 12px;border-bottom:2px solid #e8e8ee;padding-bottom:8px;}
table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px;}
th{background:#f0f1f5;color:#444;text-align:left;padding:8px 12px;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;border-bottom:2px solid #ddd;}
td{padding:8px 12px;border-bottom:1px solid #eee;color:#333;}
tr:nth-child(even) td{background:#fafbfc;}
.badge{display:inline-block;padding:2px 8px;border-radius:8px;font-size:11px;font-weight:600;}
.online{background:#dcfce7;color:#166534;}
.offline{background:#fee2e2;color:#991b1b;}
.running{background:#dcfce7;color:#166534;}
.stopped{background:#f3f4f6;color:#6b7280;}
.paused{background:#fef9c3;color:#854d0e;}
.frozen{background:#dbeafe;color:#1e40af;}
.critical{background:#fee2e2;color:#991b1b;}
.warning{background:#fef3c7;color:#92400e;}
.info{background:#dbeafe;color:#1e40af;}
.bar{height:8px;border-radius:4px;overflow:hidden;background:#e5e7eb;min-width:60px;}
.bar-fill{height:100%;border-radius:4px;}
.meta{color:#666;font-size:11px;}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px;}
.summary-card{background:#f8f9fa;border:1px solid #e0e0e8;border-radius:8px;padding:12px;text-align:center;}
.summary-value{font-size:24px;font-weight:700;color:#1a1a2e;}
.summary-label{font-size:11px;color:#666;text-transform:uppercase;margin-top:4px;}
a{color:#dc2626;text-decoration:none;}a:hover{text-decoration:underline;}
.ai-box{background:#fffbeb;border:1px solid #f59e0b;border-radius:8px;padding:16px;margin-top:16px;white-space:pre-wrap;font-size:13px;line-height:1.6;color:#1a1a2e;}
.logo-bar{display:flex;align-items:center;gap:12px;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid #eee;}
.logo-bar img{height:28px;}
@media print{.container{box-shadow:none;border:none;} .bar-fill{-webkit-print-color-adjust:exact;print-color-adjust:exact;}}
</style></head><body><div class="container">"#);

                            // Header
                            html.push_str(&format!(
                                r#"<h1>WolfStack Daily Report</h1>
                                <p style="color:#666;margin-top:-8px;font-size:13px;">Date: {} &bull; WolfStack v{} &bull; {} node(s) scanned</p>"#,
                                today, env!("CARGO_PKG_VERSION"), total_nodes
                            ));

                            // Summary cards
                            html.push_str(&format!(
                                r#"<div class="summary-grid">
                                <div class="summary-card"><div class="summary-value">{}</div><div class="summary-label">Nodes</div></div>
                                <div class="summary-card"><div class="summary-value" style="color:{}">{}</div><div class="summary-label">Critical</div></div>
                                <div class="summary-card"><div class="summary-value" style="color:{}">{}</div><div class="summary-label">Warnings</div></div>
                                <div class="summary-card"><div class="summary-value" style="color:#3b82f6">{}</div><div class="summary-label">Info</div></div>
                                </div>"#,
                                total_nodes,
                                if critical_count > 0 { "#dc2626" } else { "#166534" }, critical_count,
                                if warning_count > 0 { "#92400e" } else { "#166534" }, warning_count,
                                info_count
                            ));

                            // ─── Node Inventory Table ───
                            let all_nodes = scan_cluster.get_all_nodes();
                            html.push_str(r#"<h2>Node Inventory</h2>
                            <table><thead><tr><th>Node</th><th>Status</th><th>CPU</th><th>Memory</th><th>Docker</th><th>LXC</th><th>VMs</th></tr></thead><tbody>"#);
                            for n in all_nodes.iter().filter(|n| n.node_type != "proxmox") {
                                let status_class = if n.online { "online" } else { "offline" };
                                let status_text = if n.online { "Online" } else { "Offline" };
                                let (cpu_str, mem_str) = if let Some(ref m) = n.metrics {
                                    let cpu = m.cpu_usage_percent;
                                    let mem_pct = if m.memory_total_bytes > 0 {
                                        (m.memory_used_bytes as f64 / m.memory_total_bytes as f64 * 100.0) as u64
                                    } else { 0 };
                                    let cpu_color = if cpu > 80.0 { "#dc2626" } else if cpu > 50.0 { "#d97706" } else { "#16a34a" };
                                    let mem_color = if mem_pct > 90 { "#dc2626" } else if mem_pct > 70 { "#d97706" } else { "#16a34a" };
                                    (
                                        format!(r#"<div class="bar"><div class="bar-fill" style="width:{}%;background:{}"></div></div><span class="meta">{:.0}%</span>"#, cpu.min(100.0), cpu_color, cpu),
                                        format!(r#"<div class="bar"><div class="bar-fill" style="width:{}%;background:{}"></div></div><span class="meta">{} / {}</span>"#, mem_pct.min(100), mem_color, fmt_bytes(m.memory_used_bytes), fmt_bytes(m.memory_total_bytes)),
                                    )
                                } else {
                                    ("—".to_string(), "—".to_string())
                                };
                                let display_name = if n.hostname.is_empty() { &n.address } else { &n.hostname };
                                html.push_str(&format!(
                                    r#"<tr><td><strong>{}</strong><br><span class="meta">{} &bull; port {}</span></td><td><span class="badge {}">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                                    display_name, n.address, n.port, status_class, status_text, cpu_str, mem_str,
                                    if n.has_docker { format!("{}", n.docker_count) } else { "—".to_string() },
                                    if n.has_lxc { format!("{}", n.lxc_count) } else { "—".to_string() },
                                    if n.has_kvm { format!("{}", n.vm_count) } else { "—".to_string() },
                                ));
                            }
                            // (Legacy Proxmox-API entries are no longer rendered — they're surfaced
                            // through the deprecation banner so the user can remove them.)
                            html.push_str("</tbody></table>");

                            // ─── Docker Containers Table ───
                            {
                                let local_docker = tokio::task::spawn_blocking(crate::containers::docker_list_all).await.unwrap_or_default();
                                // Also fetch from remote WolfStack nodes
                                let mut all_docker: Vec<(String, crate::containers::ContainerInfo)> = Vec::new();
                                let local_host = {
                                    let nodes = scan_cluster.get_all_nodes();
                                    nodes.iter().find(|n| n.is_self).map(|n| n.hostname.clone()).unwrap_or_else(|| "localhost".to_string())
                                };
                                for c in local_docker {
                                    all_docker.push((local_host.clone(), c));
                                }
                                // Fetch from remote nodes
                                for node in all_nodes.iter().filter(|n| !n.is_self && n.online && n.node_type != "proxmox" && n.has_docker) {
                                    let url = node_api_url(node, "/api/containers/docker");
                                    if let Ok(resp) = http_client.get(&url)
                                        .peer_auth(scan_secret.as_str())
                                        .timeout(std::time::Duration::from_secs(15))
                                        .send().await
                                        && let Ok(containers) = resp.json::<Vec<crate::containers::ContainerInfo>>().await {
                                            for c in containers {
                                                all_docker.push((node.hostname.clone(), c));
                                            }
                                        }
                                }

                                if !all_docker.is_empty() {
                                    html.push_str(r#"<h2>Docker Containers</h2>
                                    <table><thead><tr><th>Container</th><th>Node</th><th>Image</th><th>State</th><th>IP</th><th>Ports</th></tr></thead><tbody>"#);
                                    for (host, c) in &all_docker {
                                        let state_class = match c.state.as_str() { "running" => "running", "paused" => "paused", _ => "stopped" };
                                        let ports = if c.ports.is_empty() { "—".to_string() } else { c.ports.join(", ") };
                                        html.push_str(&format!(
                                            r#"<tr><td><strong>{}</strong></td><td class="meta">{}</td><td class="meta">{}</td><td><span class="badge {}">{}</span></td><td class="meta">{}</td><td class="meta" style="font-size:10px;">{}</td></tr>"#,
                                            c.name, host, c.image, state_class, c.state, if c.ip_address.is_empty() { "—" } else { &c.ip_address }, ports,
                                        ));
                                    }
                                    html.push_str("</tbody></table>");
                                }
                            }

                            // ─── LXC Containers Table ───
                            {
                                let local_lxc = tokio::task::spawn_blocking(crate::containers::lxc_list_all).await.unwrap_or_default();
                                let mut all_lxc: Vec<(String, crate::containers::ContainerInfo)> = Vec::new();
                                let local_host = {
                                    let nodes = scan_cluster.get_all_nodes();
                                    nodes.iter().find(|n| n.is_self).map(|n| n.hostname.clone()).unwrap_or_else(|| "localhost".to_string())
                                };
                                for c in local_lxc {
                                    all_lxc.push((local_host.clone(), c));
                                }
                                for node in all_nodes.iter().filter(|n| !n.is_self && n.online && n.node_type != "proxmox" && n.has_lxc) {
                                    let url = node_api_url(node, "/api/containers/lxc");
                                    if let Ok(resp) = http_client.get(&url)
                                        .peer_auth(scan_secret.as_str())
                                        .timeout(std::time::Duration::from_secs(15))
                                        .send().await
                                        && let Ok(containers) = resp.json::<Vec<crate::containers::ContainerInfo>>().await {
                                            for c in containers {
                                                all_lxc.push((node.hostname.clone(), c));
                                            }
                                        }
                                }

                                if !all_lxc.is_empty() {
                                    html.push_str(r#"<h2>LXC Containers</h2>
                                    <table><thead><tr><th>Container</th><th>Node</th><th>Version</th><th>State</th><th>IP</th><th>Autostart</th></tr></thead><tbody>"#);
                                    for (host, c) in &all_lxc {
                                        let state_class = match c.state.as_str() { "running" | "RUNNING" => "running", "frozen" | "FROZEN" => "frozen", _ => "stopped" };
                                        let display_name = if c.hostname.is_empty() { &c.name } else { &c.hostname };
                                        html.push_str(&format!(
                                            r#"<tr><td><strong>{}</strong>{}</td><td class="meta">{}</td><td class="meta">{}</td><td><span class="badge {}">{}</span></td><td class="meta">{}</td><td>{}</td></tr>"#,
                                            display_name,
                                            if !c.hostname.is_empty() && c.hostname != c.name { format!(r#"<br><span class="meta">CT {}</span>"#, c.name) } else { String::new() },
                                            host,
                                            c.version.as_deref().unwrap_or("—"),
                                            state_class, c.state,
                                            if c.ip_address.is_empty() { "—" } else { &c.ip_address },
                                            if c.autostart { "Yes" } else { "No" },
                                        ));
                                    }
                                    html.push_str("</tbody></table>");
                                }
                            }

                            // ─── VMs Table (all nodes) ───
                            {
                                let local_vms = scan_state.vms.lock().unwrap().list_vms();
                                let mut all_vms: Vec<(String, crate::vms::manager::VmConfig)> = Vec::new();
                                let local_host = {
                                    let nodes = scan_cluster.get_all_nodes();
                                    nodes.iter().find(|n| n.is_self).map(|n| n.hostname.clone()).unwrap_or_else(|| "localhost".to_string())
                                };
                                for vm in local_vms {
                                    all_vms.push((local_host.clone(), vm));
                                }
                                // Fetch from remote nodes that have KVM
                                for node in all_nodes.iter().filter(|n| !n.is_self && n.online && n.node_type != "proxmox" && n.has_kvm) {
                                    let url = node_api_url(node, "/api/vms");
                                    if let Ok(resp) = http_client.get(&url)
                                        .peer_auth(scan_secret.as_str())
                                        .timeout(std::time::Duration::from_secs(15))
                                        .send().await
                                        && let Ok(vms) = resp.json::<Vec<crate::vms::manager::VmConfig>>().await {
                                            for vm in vms {
                                                all_vms.push((node.hostname.clone(), vm));
                                            }
                                        }
                                }

                                if !all_vms.is_empty() {
                                    html.push_str(r#"<h2>Virtual Machines</h2>
                                    <table><thead><tr><th>VM</th><th>Node</th><th>State</th><th>CPUs</th><th>Memory</th><th>Disk</th><th>Autostart</th></tr></thead><tbody>"#);
                                    for (host, vm) in &all_vms {
                                        let state_class = if vm.running { "running" } else { "stopped" };
                                        let state_text = if vm.running { "Running" } else { "Stopped" };
                                        html.push_str(&format!(
                                            r#"<tr><td><strong>{}</strong></td><td class="meta">{}</td><td><span class="badge {}">{}</span></td><td>{}</td><td>{} MB</td><td>{} GB</td><td>{}</td></tr>"#,
                                            vm.name, host, state_class, state_text, vm.cpus, vm.memory_mb, vm.disk_size_gb,
                                            if vm.auto_start { "Yes" } else { "No" },
                                        ));
                                    }
                                    html.push_str("</tbody></table>");
                                }
                            }

                            // ─── Kubernetes Clusters Table ───
                            {
                                let k8s_clusters = crate::kubernetes::list_clusters();
                                if !k8s_clusters.is_empty() {
                                    html.push_str(r#"<h2>Kubernetes Clusters</h2>"#);
                                    for cluster in &k8s_clusters {
                                        let status = tokio::task::spawn_blocking({
                                            let kc = cluster.kubeconfig_path.clone();
                                            move || crate::kubernetes::get_cluster_status(&kc)
                                        }).await.unwrap_or(crate::kubernetes::K8sClusterStatus {
                                            healthy: false, nodes_ready: 0, nodes_total: 0,
                                            pods_running: 0, pods_total: 0, namespaces: 0,
                                            api_version: "unknown".to_string(),
                                        });

                                        let health_class = if status.healthy { "online" } else { "critical" };
                                        let health_text = if status.healthy { "Healthy" } else { "Unhealthy" };
                                        html.push_str(&format!(
                                            r#"<p style="margin:12px 0 6px;"><strong>{}</strong> <span class="badge info">{}</span> <span class="badge {}">{}</span> &bull; <span class="meta">{}/{} nodes, {}/{} pods, {} namespaces, API {}</span></p>"#,
                                            cluster.name, cluster.cluster_type, health_class, health_text,
                                            status.nodes_ready, status.nodes_total,
                                            status.pods_running, status.pods_total,
                                            status.namespaces, status.api_version,
                                        ));

                                        // Get pods for this cluster
                                        let pods = tokio::task::spawn_blocking({
                                            let kc = cluster.kubeconfig_path.clone();
                                            move || {
                                                let pods = crate::kubernetes::get_pods(&kc, None);
                                                if pods.is_empty() {
                                                    crate::kubernetes::get_pods_insecure_pub(&kc, None)
                                                } else {
                                                    pods
                                                }
                                            }
                                        }).await.unwrap_or_default();

                                        if !pods.is_empty() {
                                            html.push_str(r#"<table><thead><tr><th>Pod</th><th>Namespace</th><th>Status</th><th>Ready</th><th>Restarts</th><th>Node</th><th>Age</th></tr></thead><tbody>"#);
                                            for p in &pods {
                                                let state_class = match p.status.as_str() { "Running" => "running", "Failed" | "Unknown" => "critical", "Pending" => "warning", "Succeeded" => "info", _ => "stopped" };
                                                html.push_str(&format!(
                                                    r#"<tr><td><strong>{}</strong></td><td class="meta">{}</td><td><span class="badge {}">{}</span></td><td>{}</td><td>{}{}</td><td class="meta">{}</td><td class="meta">{}</td></tr>"#,
                                                    p.name, p.namespace, state_class, p.status,
                                                    p.ready, p.restarts,
                                                    if p.restarts >= 10 { " ⚠" } else { "" },
                                                    p.node, p.age,
                                                ));
                                            }
                                            html.push_str("</tbody></table>");
                                        }
                                    }
                                }
                            }


                            // ─── Issues Table ───
                            if all_issues.is_empty() {
                                html.push_str(r#"<h2>Issues</h2><p style="color:#22c55e;text-align:center;padding:20px;">All systems healthy — no issues detected.</p>"#);
                            } else {
                                html.push_str(r#"<h2>Issues</h2>
                                <table><thead><tr><th>Severity</th><th>Node</th><th>Issue</th><th>Detail</th></tr></thead><tbody>"#);
                                for (cluster, host, issue) in &all_issues {
                                    let sev_class = match issue.severity.as_str() { "critical" => "critical", "warning" => "warning", _ => "info" };
                                    html.push_str(&format!(
                                        r#"<tr><td><span class="badge {}">{}</span></td><td><strong>{}</strong><br><span class="meta">{}</span></td><td>{}</td><td class="meta">{}</td></tr>"#,
                                        sev_class, issue.severity, host, cluster, issue.title, issue.detail,
                                    ));
                                }
                                html.push_str("</tbody></table>");
                            }

                            // ─── AI Recommendations ───
                            if !all_issues.is_empty() {
                                let issues_summary: String = all_issues.iter()
                                    .map(|(_, host, i)| format!("- [{}] {} on {}: {}", i.severity, i.title, host, i.detail))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                let ai_recs = scan_ai.analyze_issue(
                                    &format!(
                                        "Here is today's WolfStack daily report with {} issue(s) across {} node(s). \
                                         Provide a brief prioritised summary of what the admin should address first, \
                                         with specific commands or steps for each issue. Servers may be running different \
                                         Linux distributions.\n\n{}",
                                        all_issues.len(), total_nodes, issues_summary
                                    )
                                ).await.unwrap_or_default();
                                if !ai_recs.is_empty() {
                                    // Escape HTML in AI output
                                    let escaped = ai_recs.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
                                    html.push_str(&format!(
                                        r#"<h2 style="color:#eab308;">🤖 AI Recommendations</h2><div class="ai-box">{}</div>"#,
                                        escaped
                                    ));
                                }
                            }

                            // Footer
                            html.push_str(&format!(
                                r#"<p style="color:#999;font-size:11px;text-align:center;margin-top:24px;border-top:1px solid #e0e0e8;padding-top:12px;">WolfStack v{} &bull; Generated {}</p>"#,
                                env!("CARGO_PKG_VERSION"), chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                            ));
                            html.push_str("</div></body></html>");

                            if let Err(e) = ai::send_html_email(&config, &subject, &html) {
                                tracing::warn!("Failed to send daily report email: {}", e);
                            }
                        }
                    }
                }

                // Check every 60 seconds for schedule changes / time elapsed
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });

        // Background: AI health check loop
        let ai_state = app_state.clone();
        let ai_agent_bg = ai_agent.clone();
        tokio::spawn(async move {
            // Manager-only: the periodic LLM health probe is a manager
            // feature (agent-mode reduction).
            if agent_mode { return; }
            // Wait 30 seconds after startup before first check
            tokio::time::sleep(Duration::from_secs(30)).await;
            loop {
                // `check_interval_minutes == 0` is the operator's "Off"
                // setting for health checks (KO4BSR ask): the chat agent
                // stays usable but the periodic LLM probe is skipped so
                // a free/quota'd backend doesn't burn budget on idle hosts.
                // We still loop on a 5-minute cadence so re-enabling the
                // interval (or flipping agent_enabled back on) takes
                // effect within one cycle rather than at next process
                // restart.
                let (run_check, interval) = {
                    let config = ai_agent_bg.config.lock().unwrap();
                    let configured = config.is_configured();
                    let mins = config.check_interval_minutes;
                    let secs = if configured && mins > 0 {
                        mins as u64 * 60
                    } else {
                        300u64
                    };
                    (configured && mins > 0, secs)
                };

                if run_check {
                    // Collect local metrics (sync — release mutex before any .await)
                    let ai_sc = ai_state.clone();
                    let (hostname, cpu_pct, mem_used_gb, mem_total_gb, disk_used_gb, disk_total_gb,
                         docker_count, lxc_count, vm_count, uptime_secs) =
                        tokio::task::spawn_blocking(move || {
                            let mut monitor = ai_sc.monitor.lock().unwrap();
                            let m = monitor.collect();
                            drop(monitor);
                            let docker_count = containers::docker_count();
                            let lxc_count = containers::lxc_count();
                            let vm_count = ai_sc.vms.lock().unwrap().list_vms().len() as u32;

                            let mem_used = m.memory_used_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                            let mem_total = m.memory_total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                            let root_disk = m.disks.iter().find(|d| d.mount_point == "/").or_else(|| m.disks.first());
                            let disk_used = root_disk.map(|d| d.used_bytes as f64 / (1024.0 * 1024.0 * 1024.0)).unwrap_or(0.0);
                            let disk_total = root_disk.map(|d| d.total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)).unwrap_or(0.0);

                            (m.hostname.clone(), m.cpu_usage_percent, mem_used, mem_total,
                             disk_used, disk_total, docker_count, lxc_count, vm_count, m.uptime_secs)
                        }).await.unwrap();

                    // Legacy Proxmox-API guests no longer feed AI metrics — those entries are
                    // surfaced via the deprecation banner and not polled.
                    let guest_stats_refs: Vec<(&str, &str, u64, &str, f32)> = Vec::new();

                    // Gather Kubernetes cluster health (blocking kubectl calls)
                    let k8s_health = tokio::task::spawn_blocking(|| {
                        crate::kubernetes::health_summary()
                    }).await.unwrap_or(None);

                    let summary = ai::build_metrics_summary(
                        &hostname,
                        cpu_pct,
                        mem_used_gb, mem_total_gb,
                        disk_used_gb, disk_total_gb,
                        docker_count, lxc_count, vm_count,
                        uptime_secs,
                        if guest_stats_refs.is_empty() { None } else { Some(&guest_stats_refs) },
                        k8s_health.as_deref(),
                    );
                    let sample = ai::baseline::Sample {
                        ts: chrono::Utc::now().timestamp(),
                        cpu_pct,
                        mem_used_gb, mem_total_gb,
                        disk_used_gb, disk_total_gb,
                        docker_count, lxc_count, vm_count,
                    };
                    let outcome = ai_agent_bg.health_check(sample, &summary).await;
                    // AI output goes to private channels only (email +
                    // Discord/Telegram/Slack). It is NEVER posted to the
                    // public status page — host internals must not leak
                    // to anonymous viewers. On the alert→OK transition
                    // we fire a "cleared" notification so operators see
                    // the full cycle (self-gated — no-op if this host
                    // wasn't previously alerting, so every healthy ALL_OK
                    // stays silent).
                    if matches!(outcome, ai::HealthOutcome::Ok) {
                        ai_agent_bg.notify_resolved(&hostname).await;
                    }
                }

                tokio::time::sleep(Duration::from_secs(interval)).await;
            }
        });

        // Background: alerting threshold monitor (CPU, memory, disk) for ALL nodes
        let alert_cluster = cluster.clone();
        let alert_secret = cluster_secret.clone();
        let alert_ai = ai_agent.clone();
        let alert_http = crate::api::ipv4_only_client_builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();
        tokio::spawn(async move {
            // Manager-only: the threshold monitor iterates ALL cluster
            // nodes and alerts; the manager runs its own copy, so an agent
            // doing it too is redundant (and would double-alert). Gate off
            // in agent mode (agent-mode reduction).
            if agent_mode { return; }
            // Wait 90 seconds after startup before first check (let metrics stabilise)
            tokio::time::sleep(Duration::from_secs(90)).await;

            let mut cooldowns: std::collections::HashMap<String, std::time::Instant> = std::collections::HashMap::new();
            loop {
                let config = alerting::AlertConfig::load();


                // `has_delivery`: this loop's dispatch (send_local_alert) also
                // mails the operator, so an email-only setup must not be gated out.
                if config.enabled && config.has_delivery() {
                    let all_nodes = alert_cluster.get_all_nodes();

                    for node in &all_nodes {
                        if !node.online { continue; }
                        let metrics = match &node.metrics {
                            Some(m) => m,
                            None => continue,
                        };

                            let cpu_pct = metrics.cpu_usage_percent;
                            let mem_pct = metrics.memory_percent;
                            let disk_pct = metrics.disks.iter()
                                .filter(|d| {
                                    // Skip /boot entirely — the predictive
                                    // `boot_partition` analyzer owns it, with a
                                    // free-space floor sized from the kernels on
                                    // the partition (the old ">99% only" rule
                                    // here alerted after /boot was already full
                                    // and dpkg broken — wolf1 2026-08-01). Note
                                    // this whole loop's alert dispatch is retired
                                    // (`triggered` below is always empty); the
                                    // filter is kept aligned so nobody reads a
                                    // stale rule out of dead code.
                                    if d.mount_point.starts_with("/boot") { return false; }
                                    // /etc/pve (pmxcfs) only counts at >99%.
                                    if d.mount_point == "/etc/pve" { return d.usage_percent > 99.0; }
                                    true
                                })
                                .map(|d| d.usage_percent)
                                .fold(0.0_f32, f32::max);




                            let display_name = if node.hostname.is_empty() { &node.address } else { &node.hostname };

                            // Check thresholds.
                            //
                            // Convergence B (the predictive ops pipeline) now owns
                            // first-appearance threshold dispatch via
                            // `predictive::notify::find_first_appearance_alerts` +
                            // `dispatch_alerts`, fired from each tick of
                            // `predictive::orchestrator`. That layer:
                            //   • Has a unified Severity tier with snooze/dismiss/ack
                            //     semantics instead of the old cooldown HashMap
                            //   • Auto-resolves on `ConditionCleared` so the recovery
                            //     branch below isn't needed for thresholds it covers
                            //   • Surfaces in the Predictive Inbox alongside trend-based
                            //     findings (disk-fill ETA, container restart-loops, etc.)
                            //
                            // We keep this `triggered` binding *only* so the recovery-
                            // notification branch downstream still executes on legacy
                            // signals — it's harmless when `triggered` is empty. The
                            // primary alert-fire loop below sees zero entries and
                            // becomes a no-op.
                            //
                            // Per-node remote-peer dispatch: each cluster node runs its
                            // own predictive orchestrator; remote peers' findings are
                            // surfaced via `/api/proposals/cluster` aggregation in the
                            // Inbox UI.
                            let _ = (cpu_pct, mem_pct, disk_pct, &config);  // signal: kept for the recovery branch
                            let triggered: Vec<alerting::ThresholdAlert> = Vec::new();

                            for alert in &triggered {
                                if !alerting::is_in_cooldown_secs(&cooldowns, &node.id, &alert.alert_type, config.cooldown_secs) {
                                    let type_label = match alert.alert_type.as_str() {
                                        "cpu" => "CPU",
                                        "memory" => "Memory",
                                        "disk" => "Disk",
                                        _ => &alert.alert_type,
                                    };

                                    // AI analysis of the issue
                                    let ai_suggestion = alert_ai.analyze_issue(
                                        &format!(
                                            "{} usage on '{}' is at {:.1}% (threshold: {:.0}%). \
                                             What are the most likely causes and how can the admin fix this?",
                                            type_label, display_name, alert.current, alert.threshold
                                        )
                                    ).await.unwrap_or_default();

                                    let title = format!(
                                        "[WolfStack ALERT] {} {} at {:.1}% on {}",
                                        type_label, "threshold exceeded", alert.current, display_name
                                    );
                                    let mut body = format!(
                                        "⚠️ {} Threshold Alert\n\n\
                                         Hostname: {}\n\
                                         Metric: {} usage\n\
                                         Current: {:.1}%\n\
                                         Threshold: {:.0}%\n\
                                         Time: {}\n\n\
                                         This alert will not repeat for 15 minutes.",
                                        type_label, display_name, type_label,
                                        alert.current, alert.threshold,
                                        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                                    );
                                    if !ai_suggestion.is_empty() {
                                        body.push_str(&format!(
                                            "\n\n🤖 AI Recommendations:\n{}", ai_suggestion
                                        ));
                                    }

                                    let t = title.clone();
                                    let b = body.clone();
                                    tokio::spawn(async move {
                                        // CPU/mem/disk threshold — visible on
                                        // dashboard, Simple suppresses push.
                                        // send_local_alert adds the cluster + host
                                        // labels so multi-cluster operators see
                                        // which node fired this in Discord/email.
                                        alerting::send_local_alert(
                                            alerting::AlertCategory::Threshold,
                                            &t, &b,
                                        ).await;
                                    });
                                    let wn_title = title.clone();
                                    let wn_body = body.clone();
                                    tokio::spawn(async move {
                                        wolfnote::log_alert_to_wolfnote(&wn_title, &wn_body).await;
                                    });
                                    alerting::record_alert(&mut cooldowns, &node.id, &alert.alert_type);
                                }
                            }

                            // Recovery notifications: if previously alerted but now below threshold
                            let triggered_types: Vec<&str> = triggered.iter().map(|a| a.alert_type.as_str()).collect();
                            for check_type in &["cpu", "memory", "disk"] {
                                if !triggered_types.contains(check_type)
                                    && alerting::was_alerted(&cooldowns, &node.id, check_type)
                                {
                                    let type_label = match *check_type {
                                        "cpu" => "CPU",
                                        "memory" => "Memory",
                                        "disk" => "Disk",
                                        _ => check_type,
                                    };
                                    let current_val = match *check_type {
                                        "cpu" => cpu_pct,
                                        "memory" => mem_pct,
                                        "disk" => disk_pct,
                                        _ => 0.0,
                                    };
                                    let title = format!(
                                        "[WolfStack OK] {} recovered on {}",
                                        type_label, display_name
                                    );
                                    let body = format!(
                                        "✅ {} Recovered\n\n\
                                         Hostname: {}\n\
                                         Metric: {} usage\n\
                                         Current: {:.1}%\n\
                                         Time: {}\n\n\
                                         {} usage has dropped below the threshold.",
                                        type_label, display_name, type_label,
                                        current_val,
                                        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
                                        type_label,
                                    );

                                    let t = title.clone();
                                    let b = body.clone();
                                    tokio::spawn(async move {
                                        // Threshold recovery — pair with the
                                        // matching breach, same category.
                                        alerting::send_local_alert(
                                            alerting::AlertCategory::Threshold,
                                            &t, &b,
                                        ).await;
                                    });
                                    let wn_title = title.clone();
                                    let wn_body = body.clone();
                                    tokio::spawn(async move {
                                        wolfnote::log_alert_to_wolfnote(&wn_title, &wn_body).await;
                                    });
                                    alerting::clear_cooldown(&mut cooldowns, &node.id, check_type);
                                }
                            }
                            // ── Reboot detection ──
                            // If uptime is under 10 minutes, the node recently rebooted
                            if metrics.uptime_secs < 600 {
                                let reboot_key = format!("{}:reboot", node.id);
                                if let std::collections::hash_map::Entry::Vacant(e) = cooldowns.entry(reboot_key) {
                                    let uptime_mins = metrics.uptime_secs / 60;

                                    // Gather reboot reason diagnostics
                                    let diag = if node.is_self {
                                        gather_reboot_reason_local()
                                    } else {
                                        gather_reboot_reason_remote(
                                            &alert_http, &node.address, node.port, node.tls, &alert_secret
                                        ).await
                                    };

                                    // If AI is configured, analyze the diagnostics
                                    let ai_analysis = alert_ai.analyze_reboot(display_name, &diag).await
                                        .unwrap_or_default();

                                    let title = format!(
                                        "[WolfStack ALERT] {} rebooted — uptime {}m",
                                        display_name, uptime_mins
                                    );
                                    let mut body = format!(
                                        "🔄 Server Reboot Detected\n\n\
                                         Hostname: {}\n\
                                         Current Uptime: {} minutes\n\
                                         Time: {}\n\n\
                                         Reboot Diagnostics:\n{}",
                                        display_name, uptime_mins,
                                        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
                                        diag
                                    );
                                    if !ai_analysis.is_empty() {
                                        body.push_str(&format!(
                                            "\n\n🤖 AI Analysis & Recommendations:\n{}",
                                            ai_analysis
                                        ));
                                    }

                                    let t = title.clone();
                                    let b = body.clone();
                                    tokio::spawn(async move {
                                        // Reboot detected — Lifecycle.
                                        alerting::send_local_alert(
                                            alerting::AlertCategory::Lifecycle,
                                            &t, &b,
                                        ).await;
                                    });
                                    let wn_title = title.clone();
                                    let wn_body = body.clone();
                                    tokio::spawn(async move {
                                        wolfnote::log_alert_to_wolfnote(&wn_title, &wn_body).await;
                                    });
                                    // Use a long cooldown (1 hour) so we don't re-alert for the same reboot
                                    e.insert(std::time::Instant::now());
                                }
                            }
                    }

                    // Container memory monitoring lived here and was removed in
                    // v25.12.8. It collected `docker_stats()` + `lxc_stats()` on
                    // every tick of this loop — five `docker` subprocesses plus a
                    // full LXC enumeration, every 30-60s on every install, since
                    // `alert_containers` defaults to true.
                    //
                    // All of it fed code that could not execute. When the
                    // threshold dispatch moved to `predictive::container_memory`,
                    // the `docker_alerts`/`lxc_alerts` vectors were left hardcoded
                    // empty, so the alert loop never ran; and the recovery branch
                    // below it asked `was_alerted("container:<name>:memory")`, a
                    // key written ONLY inside that dead loop, so it was always
                    // false too. Net effect: the most expensive Docker calls in
                    // the daemon ran forever to produce nothing, and on a host
                    // with a slow dockerd they outlived their own interval and
                    // piled up (klas, 2026-08-13: hundreds of concurrent
                    // `docker inspect` processes, node unreachable).
                    //
                    // `predictive::container_memory` is the live path: it honours
                    // the same `alert_containers` toggle, reads
                    // `docker_stats_cached()`, and routes findings through the
                    // Inbox with ack/suppress/dedup. Do not reinstate this block —
                    // add to the predictive item instead.
                }

                // Use the configured interval (re-read each loop in case user changed it)
                let interval = config.check_interval_secs.max(30);
                tokio::time::sleep(Duration::from_secs(interval)).await;
            }
        });

        // Background: WolfRun reconciliation loop (every 15s)
        let wolfrun_cluster = cluster.clone();
        let wolfrun_secret = cluster_secret.clone();
        let wolfrun_bg = wolfrun_state.clone();
        tokio::spawn(async move {
            // Wait 30 seconds after startup before first reconciliation
            tokio::time::sleep(Duration::from_secs(30)).await;
            info!("WolfRun reconciliation loop started");
            loop {
                // Only the cluster leader runs reconciliation to prevent
                // duplicate container creation and IP address conflicts
                if wolfrun::is_leader(&wolfrun_cluster) {
                    wolfrun::reconcile(&wolfrun_bg, &wolfrun_cluster, &wolfrun_secret).await;
                    // Check failover — promote standby containers for offline nodes
                    wolfrun::check_failover(&wolfrun_bg, &wolfrun_cluster, &wolfrun_secret).await;
                    // Create standby containers for failover-enabled services
                    wolfrun::manage_standby(&wolfrun_bg, &wolfrun_cluster, &wolfrun_secret).await;
                    // Broadcast updated instance status to cluster peers
                    wolfrun::broadcast_to_cluster(&wolfrun_bg, &wolfrun_cluster, &wolfrun_secret).await;
                }
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        });

        // Background: UPS staged-shutdown engine. Polls `upsc` at the
        // operator-configured interval; a disabled/unconfigured engine
        // costs one small config read per tick. Runs on EVERY node —
        // each host winds down its own workloads on ITS battery.
        let ups_bg = ups_state.clone();
        let ups_app = app_state.clone().into_inner();
        tokio::spawn(async move {
            loop {
                ups::engine_tick(&ups_bg, &ups_app).await;
                let poll = ups::UpsConfig::load().poll_secs.clamp(5, 300);
                tokio::time::sleep(Duration::from_secs(poll)).await;
            }
        });

        // Background: WolfFunctions reconciliation loop (every 15s).
        // EVERY node runs local_reconcile (each node owns its own warm
        // sandboxes); only the leader computes placements, fires schedules,
        // detects node online/offline transitions, and broadcasts config.
        let wolffn_cluster = cluster.clone();
        let wolffn_secret = cluster_secret.clone();
        let wolffn_bg = wolffunctions_state.clone();
        tokio::spawn(async move {
            // Reap sandboxes orphaned by a PREVIOUS run FIRST — before the
            // API can accept an invoke that would create a live sandbox this
            // reap must not touch (it skips the live registry, but running
            // early avoids the race entirely). No pre-sleep here.
            wolffunctions::runtime::cleanup_orphans(&wolffn_bg).await;
            // Adopt config from peers if this node has none (fresh join).
            wolffunctions::pull_from_peers(&wolffn_bg, &wolffn_cluster, &wolffn_secret).await;
            // Pre-warm the runtime (single-flighted runsc download) so the
            // first invocation on a fresh node doesn't pay the ~20s fetch
            // inside its own timeout budget.
            wolffunctions::runtime::probe_eligibility(&wolffn_bg).await;
            info!("WolfFunctions reconciliation loop started");
            let mut prev_online: Option<std::collections::HashSet<String>> = None;
            let mut last_broadcast = std::time::Instant::now();
            loop {
                let mut broadcast_now = false;
                if wolfrun::is_leader(&wolffn_cluster) {
                    if wolffunctions::runtime::leader_place(&wolffn_bg, &wolffn_cluster) {
                        broadcast_now = true;
                    }
                    if wolffunctions::runtime::schedule_tick(
                        &wolffn_bg, &wolffn_cluster, &wolffn_secret).await
                    {
                        broadcast_now = true;
                    }
                    // Node online/offline transition events for subscribed
                    // functions. First tick only seeds the baseline.
                    let self_cluster = wolffunctions::self_cluster_name(&wolffn_cluster);
                    let current: std::collections::HashSet<String> = wolffn_cluster
                        .get_all_nodes().iter()
                        .filter(|n| n.online
                            && n.cluster_name.as_deref().unwrap_or("WolfStack") == self_cluster)
                        .map(|n| n.id.clone())
                        .collect();
                    if let Some(prev) = &prev_online {
                        for gone in prev.difference(&current) {
                            wolffunctions::fire_event(
                                &wolffn_bg, &wolffn_cluster, &wolffn_secret,
                                wolffunctions::TriggerEvent::NodeOffline,
                                serde_json::json!({ "node_id": gone }), false).await;
                        }
                        for back in current.difference(prev) {
                            wolffunctions::fire_event(
                                &wolffn_bg, &wolffn_cluster, &wolffn_secret,
                                wolffunctions::TriggerEvent::NodeOnline,
                                serde_json::json!({ "node_id": back }), false).await;
                        }
                    }
                    prev_online = Some(current);
                }
                wolffunctions::runtime::local_reconcile(&wolffn_bg, &wolffn_cluster).await;
                // Config broadcast: immediately after placement/schedule
                // changes, and at least every 60s (carries last_fired so a
                // leader change never double-fires schedules).
                let has_functions = !wolffn_bg.config.read().unwrap().functions.is_empty();
                if has_functions && (broadcast_now || last_broadcast.elapsed().as_secs() >= 60) {
                    wolffunctions::broadcast_to_cluster(
                        &wolffn_bg, &wolffn_cluster, &wolffn_secret).await;
                    last_broadcast = std::time::Instant::now();
                }
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        });

        // Background: Status page health check runner (every 30s)
        let sp_state = statuspage_state.clone();
        let sp_cluster = app_state.cluster.clone();
        let sp_secret = app_state.cluster_secret.clone();
        tokio::spawn(async move {
            // Short delay after startup, then run first check immediately
            tokio::time::sleep(Duration::from_secs(5)).await;
            loop {
                statuspage::run_checks(&sp_state, &sp_cluster, &sp_secret).await;
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });

        // Background: periodically pull status page config from peers if we have none
        let sp_sync = statuspage_state.clone();
        let sp_sync_cluster = cluster.clone();
        let sp_sync_secret = cluster_secret.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(15)).await;
            loop {
                // Only sync if status pages are configured
                if sp_sync.has_any_pages() {
                    statuspage::pull_from_peers(&sp_sync, &sp_sync_cluster, &sp_sync_secret).await;
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });

        // Background: WolfNet auto-restart watchdog (check every 60s, restart at most once/hour)
        let wolfnet_ai = ai_agent.clone();
        tokio::spawn(async move {
            // Wait for system to stabilise before first check
            tokio::time::sleep(Duration::from_secs(60)).await;
            let mut last_restart_attempt: Option<std::time::Instant> = None;
            let mut restart_failed = false;
            loop {
                let status = networking::get_wolfnet_status();
                // Only act if WolfNet is installed but not running
                if status.installed && !status.running {
                    let should_attempt = match last_restart_attempt {
                        None => true,
                        Some(t) => t.elapsed().as_secs() >= 3600, // once per hour
                    };

                    if should_attempt {
                        info!("WolfNet is down — attempting automatic restart");
                        match networking::wolfnet_service_action("restart") {
                            Ok(_) => {
                                // Verify it actually came up
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                let check = networking::get_wolfnet_status();
                                if check.running {
                                    info!("WolfNet auto-restart succeeded");
                                    restart_failed = false;
                                    // Send recovery alert if we previously reported failure
                                    let config = alerting::AlertConfig::load();
                                    if config.enabled && config.has_delivery() {
                                        let title = "[WolfStack OK] WolfNet auto-recovered".to_string();
                                        let body = format!(
                                            "✅ WolfNet Auto-Recovery\n\n\
                                             WolfNet was detected as down and has been automatically restarted.\n\
                                             Time: {}",
                                            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                                        );
                                        tokio::spawn(async move {
                                            // WolfNet auto-recovered — Lifecycle.
                                            alerting::send_local_alert(
                                                alerting::AlertCategory::Lifecycle,
                                                &title, &body,
                                            ).await;
                                        });
                                    }
                                } else {
                                    warn!("WolfNet auto-restart failed — service did not come up");
                                    if !restart_failed {
                                        restart_failed = true;
                                        let ai_suggestion = wolfnet_ai.analyze_issue(
                                            "WolfNet overlay network service is down and an automatic restart failed. \
                                             The service did not come up after a WolfNet service restart. \
                                             What should the admin check and how can they fix this?"
                                        ).await.unwrap_or_default();
                                        let config = alerting::AlertConfig::load();
                                        if config.enabled && config.has_delivery() {
                                            let title = "[WolfStack ALERT] WolfNet down — auto-restart failed".to_string();
                                            let mut body = format!(
                                                "⚠️ WolfNet Down\n\n\
                                                 WolfNet was detected as down and an automatic restart was attempted but failed.\n\
                                                 Manual intervention may be required.\n\
                                                 Time: {}\n\n\
                                                 Next restart attempt in 1 hour.",
                                                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                                            );
                                            if !ai_suggestion.is_empty() {
                                                body.push_str(&format!(
                                                    "\n\n🤖 AI Recommendations:\n{}", ai_suggestion
                                                ));
                                            }
                                            tokio::spawn(async move {
                                                // WolfNet restart failed — Lifecycle.
                                                alerting::send_local_alert(
                                                    alerting::AlertCategory::Lifecycle,
                                                    &title, &body,
                                                ).await;
                                            });
                                        }
                                    }
                                }
                                last_restart_attempt = Some(std::time::Instant::now());
                            }
                            Err(e) => {
                                warn!("WolfNet auto-restart command failed: {}", e);
                                if !restart_failed {
                                    restart_failed = true;
                                    let ai_suggestion = wolfnet_ai.analyze_issue(
                                        &format!(
                                            "WolfNet overlay network service is down. The WolfNet service restart \
                                             failed with error: {}. What should the admin check?", e
                                        )
                                    ).await.unwrap_or_default();
                                    let config = alerting::AlertConfig::load();
                                    if config.enabled && config.has_delivery() {
                                        let title = "[WolfStack ALERT] WolfNet down — auto-restart failed".to_string();
                                        let mut body = format!(
                                            "⚠️ WolfNet Down\n\n\
                                             WolfNet was detected as down and an automatic restart was attempted but failed.\n\
                                             Error: {}\n\
                                             Manual intervention may be required.\n\
                                             Time: {}\n\n\
                                             Next restart attempt in 1 hour.",
                                            e, chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                                        );
                                        if !ai_suggestion.is_empty() {
                                            body.push_str(&format!(
                                                "\n\n🤖 AI Recommendations:\n{}", ai_suggestion
                                            ));
                                        }
                                        tokio::spawn(async move {
                                            // WolfNet restart-command error — Lifecycle.
                                            alerting::send_local_alert(
                                                alerting::AlertCategory::Lifecycle,
                                                &title, &body,
                                            ).await;
                                        });
                                    }
                                }
                                last_restart_attempt = Some(std::time::Instant::now());
                            }
                        }
                    }
                } else if status.installed && status.running && restart_failed {
                    // WolfNet came back (maybe manually restarted)
                    restart_failed = false;
                    info!("WolfNet is running again");
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });

        // Determine web directory
        let located_web_dir = locate_web_dir();
        let web_dir = located_web_dir.clone().unwrap_or_else(|| WEB_DIR_CANDIDATES[0].to_string());
        // `agent_mode` already bound above (near the background-task gates).
        if agent_mode {
            info!("  ⚙ Agent-only mode — management SPA disabled, cluster API only");
            info!("    Manage this node from the master server's UI (Add Node).");
        } else if located_web_dir.is_some() {
            info!("  Serving web UI from: {}", web_dir);
        } else {
            // A daemon that answers every API call while every UI page 500s
            // is a confusing pair of signals (Colt 2026-09-06: binary + unit
            // copied to a standby host without the web tree). Say exactly
            // what is missing and where it was looked for.
            tracing::error!(
                "  ✗ Web UI directory not found — looked for index.html in {} — the API \
                 works but every UI page will fail. Re-run setup.sh, or copy the web/ \
                 tree from an installed node to /opt/wolfstack/web and restart.",
                WEB_DIR_CANDIDATES.join(", ")
            );
        }
        info!("");

        // Resolve TLS certificate paths
        let tls_paths = if cli.no_tls {
            None
        } else if let (Some(cert), Some(key)) = (&cli.tls_cert, &cli.tls_key) {
            Some((cert.clone(), key.clone()))
        } else {
            installer::find_tls_certificate(cli.tls_domain.as_deref())
        };

        // WolfHost subsystem: build its state, then start the customer
        // portal as its own bound server + background tasks. The admin API
        // is registered on the main app(s) below via configure_admin. The
        // portal serves untrusted public customers, so it stays a separate
        // server rather than sharing this process's main port.
        let wolfhost_cfg = wolfhost::config::WolfHostConfig::load();
        let wolfhost_portal_port = wolfhost_cfg.portal_port;
        // Portal static assets ship with WolfStack (web/wolfhost-portal),
        // not the old plugin path.
        let wolfhost_portal_dir = format!("{}/wolfhost-portal", web_dir);
        let wolfhost_state = wolfhost::build_state(wolfhost_cfg).await;
        let wolfhost_data = web::Data::new(wolfhost_state.clone());
        let wolfhost_data2 = wolfhost_data.clone();
        // The portal is manager-only: agent nodes have no web assets and
        // must not bind a public customer-facing port (klas 2026-07-16:
        // Unraid agent logged "Specified path is not a directory:
        // web/wolfhost-portal" and grabbed 0.0.0.0:8443). Same gating
        // rationale as the v25.2.66 agent-mode background-loop reduction.
        if agent_mode {
            info!("  ⚙ Agent mode — WolfHost customer portal not started (manager-only)");
        } else {
            wolfhost::spawn_portal(wolfhost_state.clone(), wolfhost_portal_port, wolfhost_portal_dir).await;
        }

        // HTTP worker count. Agents serve only the manager's 10s poll plus
        // occasional on-demand proxied calls, but some handlers still run
        // sync work on the worker thread (the sync-in-async sweep is
        // ongoing), so keep 4 workers of headroom rather than the bare
        // minimum — enough that a couple of concurrent blocking calls
        // can't stall the manager's poll. The default is one worker PER
        // CPU THREAD per listener (actix-server 2.6.0 builder.rs:61:
        // available_parallelism().map_or(2, get)), which on a 16-thread
        // host is 48 idle threads across three listeners — each an OS
        // thread + malloc arena an OOM-squeezed Unraid agent can't spare
        // (agent-mode reduction). min() so a small box never gets MORE
        // workers than the upstream default gave it; managers keep the
        // exact upstream default via the same formula.
        let default_workers = std::thread::available_parallelism()
            .map_or(2, std::num::NonZeroUsize::get);
        let http_workers: usize = if agent_mode {
            default_workers.min(4)
        } else {
            default_workers
        };

        // mTLS client-certificate gate — OFF by default. Loaded once; when
        // enabled with a valid CA it is applied to the admin HTTPS acceptor
        // below so only the operator's cert-bearing devices can use the port.
        let mtls_ca = crate::mtls::MtlsConfig::load().active_ca();

        // Try to load TLS config using OpenSSL — fall back to HTTP if anything goes wrong
        let ssl_builder = tls_paths.as_ref().and_then(|(cert_path, key_path)| {
            use openssl::ssl::{SslAcceptor, SslMethod, SslFiletype};

            let mut builder = match SslAcceptor::mozilla_intermediate(SslMethod::tls()) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("Failed to create SSL acceptor: {} — falling back to HTTP", e);
                    return None;
                }
            };

            if let Err(e) = builder.set_certificate_chain_file(cert_path) {
                tracing::warn!("Cannot load TLS cert '{}': {} — falling back to HTTP", cert_path, e);
                return None;
            }

            if let Err(e) = builder.set_private_key_file(key_path, SslFiletype::PEM) {
                tracing::warn!("Cannot load TLS key '{}': {} — falling back to HTTP", key_path, e);
                return None;
            }

            // Apply the client-certificate gate when configured. On any load
            // failure, log and continue WITHOUT it — a CA typo must never
            // brick admin access (recovery would need console, which many
            // installs lack). MTLS_ACTIVE is only set when it truly activates.
            if let Some(ca) = &mtls_ca {
                match crate::mtls::apply_client_ca(&mut builder, ca) {
                    Ok(()) => {
                        crate::mtls::MTLS_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);
                        info!("  🔐 mTLS: admin port requires a client certificate (CA: {})", ca);
                    }
                    Err(e) => tracing::error!(
                        "mTLS: could not enable client-cert gate: {} — admin port running WITHOUT it", e
                    ),
                }
            }

            Some(builder)
        });

        if let Some(ssl_builder) = ssl_builder {
            let (cert_path, key_path) = tls_paths.as_ref().unwrap();
            // v23.12: only bind the secondary plain-HTTP listener if the
            // loaded cert is self-signed. CA-signed-cert operators get
            // HTTPS-only and never collide with Frigate/MediaMTX/go2rtc/
            // GStreamer RTSP server etc. on 8554. The self-signed branch
            // also gets the auto-fallback scan (8554..=8599) so even
            // those operators can run alongside the same applications.
            // See src/installer/self_signed.rs:cert_appears_self_signed.
            let cert_is_self_signed = installer::self_signed::cert_appears_self_signed(cert_path);
            let inter_node_port: Option<u16> = if cert_is_self_signed {
                Some(ports::reserve_inter_node_port(
                    &cli.bind,
                    inter_node_pref,
                    8554..=8599,
                    &[api_port, status_port],
                    may_persist_ports,
                ))
            } else {
                None
            };

            info!("  🔒 TLS enabled");
            info!("     Cert: {} ({})", cert_path,
                if cert_is_self_signed { "self-signed" } else { "CA-signed" });
            info!("     Key:  {}", key_path);
            info!("     HTTPS: https://{}", netaddr::host_port(&cli.bind, api_port));
            match inter_node_port {
                Some(p) => info!("     HTTP (inter-node legacy + cluster-home): http://{}", netaddr::host_port(&cli.bind, p)),
                None => info!("     HTTP (inter-node): not bound — CA-signed cert means peers use HTTPS"),
            }
            info!("     Status pages: http://{}", netaddr::host_port(&cli.bind, status_port));
            info!("");

            // Clone web_dir for status-page closure (always needed) + the
            // optional second listener closure (only constructed when bound).
            let web_dir2 = web_dir.clone();
            let app_state2 = app_state.clone();
            let app_state3 = app_state.clone();

            let https_bind = netaddr::host_port(&cli.bind, api_port);
            let https_server = HttpServer::new(move || {
                let app = App::new()
                    // Compress responses (gzip/brotli/zstd, negotiated via
                    // Accept-Encoding). web/js/app.js is ~3.9 MB uncompressed —
                    // without this every page load shipped the whole thing in
                    // the clear, which is what got reset (ERR_CONNECTION_RESET)
                    // on slow/proxied links and broke the entire UI
                    // ("toggleLayoutDropdown is not defined" = app.js never
                    // finished loading, so none of its functions existed).
                    // Compressed it's ~10x smaller and far less reset-prone.
                    .wrap(actix_web::middleware::Compress::default())
                    .wrap(actix_web::middleware::from_fn(mtls_gate))
                    .app_data(app_state.clone())
                    .app_data(wolfhost_data.clone())
                    .app_data(actix_multipart::form::MultipartFormConfig::default().total_limit(2 * 1024 * 1024 * 1024))
                    .app_data(actix_web::web::PayloadConfig::new(2 * 1024 * 1024 * 1024))
                    // Cache-Control: no-cache on every response that doesn't set
                    // its own (DefaultHeaders never overwrites an explicit one).
                    // actix_files sends ETag/Last-Modified but NO Cache-Control,
                    // so browsers heuristically cached app.js/index.html for
                    // hours-days and operators ran a STALE UI after every
                    // upgrade (Gary KO4BSR 2026-06-10: phantom "connection
                    // lost" banner from a cached pre-fix heartbeat). no-cache
                    // means revalidate-always: unchanged files are still cheap
                    // 304s via ETag; changed files arrive immediately.
                    .wrap(actix_web::middleware::DefaultHeaders::new().add(("Cache-Control", "no-cache")))
                    .configure(api::configure)
                    .configure(wolfhost::configure_admin);
                if agent_mode {
                    app.default_service(web::to(agent_index_handler))
                } else {
                    app.configure(|cfg| configure_web_ui(cfg, &web_dir))
                }
            })
            // Tighten the lifecycle so peers churning connections (cluster
            // polling, wolfrun/statuspage broadcasts from older peers)
            // don't accumulate in CLOSE_WAIT on our side. Defaults are
            // 5s / 5s / 1s — halving them drops fd residence time ~80%
            // under peer-initiated-close workloads. Reported by Bel:
            // 26k CLOSE_WAIT on :8553 → fd exhaustion.
            .keep_alive(std::time::Duration::from_secs(2))
            .client_request_timeout(std::time::Duration::from_secs(3))
            .client_disconnect_timeout(std::time::Duration::from_millis(500))
            // The keep-alive knobs above CANNOT reclaim a socket whose
            // request is still in flight. actix-http's dispatcher only
            // starts shutdown on a client FIN when the half-closure is
            // disallowed *or* request processing has finished:
            //
            //   if READ_DISCONNECT && (!config.h1_allow_half_closed() || state_is_none)
            //       -> start shutdown                (h1/dispatcher.rs:1228)
            //
            // h1_allow_half_closed defaults to TRUE (config.rs:103), so a
            // client that gives up mid-request left us holding the fd for
            // the entire remaining handler duration — CLOSE_WAIT residence
            // became "however long the slowest handler takes". klas
            // (hemulen) and klnet-12gb both showed 75-80k CLOSE_WAIT on the
            // inter-node listener with CPU pegged at 80-100%.
            //
            // A client that has closed its writer-side cannot send another
            // request on this connection, so there is nothing to preserve:
            // abort as soon as we see EOF and give the fd straight back.
            .h1_allow_half_closed(false)
            .workers(http_workers)
            .on_connect(mtls_on_connect)
            .bind_openssl(&https_bind, ssl_builder)
            .map_err(|e| {
                tracing::error!("❌ Failed to bind HTTPS on {}: {}", https_bind, e);
                e
            })?
            .run();

            // Secondary plain-HTTP listener — only on self-signed installs.
            // Construct the Option<server> upfront so the tokio::join!
            // arities stay static (join! macro can't accept a runtime
            // optional future cleanly).
            let http_server_opt = match inter_node_port {
                Some(p) => {
                    let http_bind = netaddr::host_port(&cli.bind, p);
                    let srv = HttpServer::new(move || {
                        let app = App::new()
                            // Compress responses — see the main server above
                            // (app.js is ~3.9 MB uncompressed otherwise).
                            .wrap(actix_web::middleware::Compress::default())
                    .wrap(actix_web::middleware::from_fn(mtls_gate))
                            .app_data(app_state2.clone())
                            .app_data(wolfhost_data2.clone())
                            .app_data(actix_multipart::form::MultipartFormConfig::default().total_limit(2 * 1024 * 1024 * 1024))
                            .app_data(actix_web::web::PayloadConfig::new(2 * 1024 * 1024 * 1024))
                            // Same stale-UI guard as the primary listeners — see
                            // the comment there (Gary KO4BSR 2026-06-10).
                            .wrap(actix_web::middleware::DefaultHeaders::new().add(("Cache-Control", "no-cache")))
                            .configure(api::configure)
                            .configure(wolfhost::configure_admin);
                        if agent_mode {
                            app.default_service(web::to(agent_index_handler))
                        } else {
                            app.configure(|cfg| configure_web_ui(cfg, &web_dir2))
                        }
                    })
                    .keep_alive(std::time::Duration::from_secs(2))
                    .client_request_timeout(std::time::Duration::from_secs(3))
                    .client_disconnect_timeout(std::time::Duration::from_millis(500))
                    // See the HTTPS listener above. This is the listener that
                    // actually drowned: klnet-12gb showed 75,084 CLOSE_WAIT
                    // here against 4,394 on :8553, because every peer's
                    // route-announce falls back to http://{peer}:8554 and the
                    // half-closure default pinned each fd for the whole
                    // handler.
                    .h1_allow_half_closed(false)
                    .workers(http_workers)
                    .bind(&http_bind)
                    .map_err(|e| {
                        tracing::error!("❌ Failed to bind HTTP on {}: {}", http_bind, e);
                        e
                    })?
                    .run();
                    Some(srv)
                }
                None => None,
            };

            // Dedicated status page listener — plain HTTP on the configured status port
            let sp_bind = netaddr::host_port(&cli.bind, status_port);
            let sp_server = HttpServer::new(move || {
                App::new()
                    .app_data(app_state3.clone())
                    .configure(api::configure_statuspage_only)
            })
            // The status listener is the one surface we publish to the open
            // internet, and until now it was the only HttpServer with NO
            // lifecycle limits at all — actix defaults of 5s keep-alive, 5s
            // request timeout, 0s disconnect timeout and half-closures
            // allowed. Give it the same budget protection as the admin
            // listeners; an anonymous client must not be able to park fds
            // here.
            .keep_alive(std::time::Duration::from_secs(2))
            .client_request_timeout(std::time::Duration::from_secs(3))
            .client_disconnect_timeout(std::time::Duration::from_millis(500))
            .h1_allow_half_closed(false)
            .workers(http_workers)
            .bind(&sp_bind)
            .map_err(|e| {
                tracing::warn!("⚠️  Failed to bind status page listener on {}: {}", sp_bind, e);
                e
            });

            // Run the active set of listeners. Combinatorial: HTTPS is
            // always present; HTTP and SP each may or may not be. Four
            // branches; explicit so tokio::join!'s arity is fixed in
            // each.
            match (http_server_opt, sp_server) {
                (Some(http), Ok(sp)) => {
                    let (r1, r2, r3) = tokio::join!(https_server, http, sp.run());
                    r1?; r2?; r3?;
                }
                (Some(http), Err(_)) => {
                    let (r1, r2) = tokio::join!(https_server, http);
                    r1?; r2?;
                }
                (None, Ok(sp)) => {
                    let (r1, r2) = tokio::join!(https_server, sp.run());
                    r1?; r2?;
                }
                (None, Err(_)) => {
                    https_server.await?;
                }
            }
            Ok(())
        } else {
            if cli.no_tls {
                info!("  ⚡ HTTP mode (TLS disabled via --no-tls)");
            } else if tls_paths.is_some() {
                info!("  ⚠️  TLS certificates found but failed to load — running HTTP only");
            } else {
                info!("  ⚡ HTTP mode (no TLS certificates found)");
            }
            info!("     Dashboard: http://{}", netaddr::host_port(&cli.bind, api_port));
            info!("     Status pages: http://{}", netaddr::host_port(&cli.bind, status_port));
            info!("     Tip: Use the Certificates page to request a Let's Encrypt certificate");
            info!("");

            let app_state2 = app_state.clone();

            // Start HTTP server (same as before — no breaking changes)
            let main_server = HttpServer::new(move || {
                let app = App::new()
                    // Compress responses (gzip/brotli/zstd, negotiated via
                    // Accept-Encoding). web/js/app.js is ~3.9 MB uncompressed —
                    // without this every page load shipped the whole thing in
                    // the clear, which is what got reset (ERR_CONNECTION_RESET)
                    // on slow/proxied links and broke the entire UI
                    // ("toggleLayoutDropdown is not defined" = app.js never
                    // finished loading, so none of its functions existed).
                    // Compressed it's ~10x smaller and far less reset-prone.
                    .wrap(actix_web::middleware::Compress::default())
                    .wrap(actix_web::middleware::from_fn(mtls_gate))
                    .app_data(app_state.clone())
                    .app_data(wolfhost_data.clone())
                    .app_data(actix_multipart::form::MultipartFormConfig::default().total_limit(2 * 1024 * 1024 * 1024))
                    .app_data(actix_web::web::PayloadConfig::new(2 * 1024 * 1024 * 1024))
                    // Cache-Control: no-cache on every response that doesn't set
                    // its own (DefaultHeaders never overwrites an explicit one).
                    // actix_files sends ETag/Last-Modified but NO Cache-Control,
                    // so browsers heuristically cached app.js/index.html for
                    // hours-days and operators ran a STALE UI after every
                    // upgrade (Gary KO4BSR 2026-06-10: phantom "connection
                    // lost" banner from a cached pre-fix heartbeat). no-cache
                    // means revalidate-always: unchanged files are still cheap
                    // 304s via ETag; changed files arrive immediately.
                    .wrap(actix_web::middleware::DefaultHeaders::new().add(("Cache-Control", "no-cache")))
                    .configure(api::configure)
                    .configure(wolfhost::configure_admin);
                if agent_mode {
                    app.default_service(web::to(agent_index_handler))
                } else {
                    app.configure(|cfg| configure_web_ui(cfg, &web_dir))
                }
            })
            // See matching block above on the TLS path for why these
            // lifecycle knobs matter. Keep-alive / disconnect tuning
            // caps CLOSE_WAIT residence time to protect fd budget, and
            // disallowing half-closures is what lets a client FIN reclaim
            // the fd mid-request instead of at handler completion.
            .keep_alive(std::time::Duration::from_secs(2))
            .client_request_timeout(std::time::Duration::from_secs(3))
            .client_disconnect_timeout(std::time::Duration::from_millis(500))
            .h1_allow_half_closed(false)
            .workers(http_workers)
            .bind(netaddr::host_port(&cli.bind, api_port))?
            .run();

            // Dedicated status page listener — plain HTTP on the configured status port
            let sp_bind = netaddr::host_port(&cli.bind, status_port);
            let sp_server = HttpServer::new(move || {
                App::new()
                    .app_data(app_state2.clone())
                    .configure(api::configure_statuspage_only)
            })
            // The status listener is the one surface we publish to the open
            // internet, and until now it was the only HttpServer with NO
            // lifecycle limits at all — actix defaults of 5s keep-alive, 5s
            // request timeout, 0s disconnect timeout and half-closures
            // allowed. Give it the same budget protection as the admin
            // listeners; an anonymous client must not be able to park fds
            // here.
            .keep_alive(std::time::Duration::from_secs(2))
            .client_request_timeout(std::time::Duration::from_secs(3))
            .client_disconnect_timeout(std::time::Duration::from_millis(500))
            .h1_allow_half_closed(false)
            .workers(http_workers)
            .bind(&sp_bind)
            .map_err(|e| {
                tracing::warn!("⚠️  Failed to bind status page listener on {}: {}", sp_bind, e);
                e
            });

            match sp_server {
                Ok(sp) => {
                    let (r1, r2) = tokio::join!(main_server, sp.run());
                    r1?; r2?;
                }
                Err(_) => {
                    main_server.await?;
                }
            }
            Ok(())
        }
    }
}

/// Build the preferred inter-node URL for a given node and API path.
///
/// v23.12: returns HTTPS for TLS-enabled peers (with the surrounding HTTP
/// clients using `danger_accept_invalid_certs(true)` so self-signed certs
/// are accepted), plain HTTP for legacy `--no-tls` peers. The pre-v23.12
/// behaviour returned `http://addr:port+1` for TLS peers, which broke
/// against CA-signed-cert nodes that no longer bind the second listener.
fn node_api_url(node: &crate::agent::Node, path: &str) -> String {
    let host = netaddr::bracket_host(&node.address);
    if node.tls {
        format!("https://{}:{}{}", host, node.port, path)
    } else {
        format!("http://{}:{}{}", host, node.port, path)
    }
}

/// Self-heal the systemd unit. Two directives, both add-only (Golden Rule:
/// nothing else about the unit changes), both idempotent:
///
/// * `KillMode=process` — WolfStack daemonizes native QEMU VMs
///   (`qemu -daemonize`) and spawns other long-lived children; units created
///   before mid-2026 carry no `KillMode=` line and inherit systemd's
///   `control-group` default, so `systemctl restart wolfstack` (every in-app
///   upgrade ends in one) SIGTERMed those guests too — PapaSchlumpf 2026-06: a
///   Home Assistant VM killed by an upgrade on a raw/native host.
/// * A missing working directory must not stop the daemon. The unit sets
///   `WorkingDirectory=/opt/wolfstack`; on a host where that directory does not
///   exist (binary + unit copied to a standby without running setup.sh)
///   systemd fails the service with `200/CHDIR` before WolfStack runs a single
///   line, and the visible symptom is a `wolfstack-mounts-wait` timeout that
///   reads like a storage fault (Colt 2026-09-06). The `-` prefix makes a
///   missing directory non-fatal (systemd.exec(5), WorkingDirectory=) and an
///   `ExecStartPre=/bin/mkdir -p` creates it, so ExecStart then chdirs into a
///   real directory.
///
/// setup.sh writes both on fresh installs; this covers binary-swap upgrades
/// and copied units that never re-run setup.sh. Best-effort — any failure is
/// logged and swallowed; it must never block startup.
fn ensure_unit_self_heal() {
    let unit = std::path::Path::new("/etc/systemd/system/wolfstack.service");
    let content = match std::fs::read_to_string(unit) {
        Ok(c) => c,
        // No unit (container/dev run, or a non-systemd install) → nothing to heal.
        Err(_) => return,
    };
    let Some((out, applied)) = heal_unit_content(&content) else { return };
    if let Err(e) = std::fs::write(unit, out) {
        tracing::warn!(
            "startup: could not update wolfstack.service ({}): {}",
            applied.join(", "), e
        );
        return;
    }
    // The file is patched, but systemd still has the OLD unit loaded until
    // daemon-reload. Only claim success if the reload actually applied —
    // otherwise the directives take effect on the next boot.
    match std::process::Command::new("systemctl")
        .arg("daemon-reload")
        .output()
    {
        Ok(o) if o.status.success() => tracing::info!(
            "startup: updated wolfstack.service ({})", applied.join(", ")
        ),
        _ => tracing::warn!(
            "startup: wrote {} to wolfstack.service but `systemctl daemon-reload` \
             did not succeed; it takes effect on the next reload/boot",
            applied.join(", ")
        ),
    }
}

/// Pure unit-file transform behind `ensure_unit_self_heal`. Returns the new
/// content and a description of each directive applied, or `None` when the
/// unit already has everything (steady state) or has no `[Service]` section we
/// recognise (don't guess — leave it untouched).
fn heal_unit_content(content: &str) -> Option<(String, Vec<&'static str>)> {
    let has_killmode = content
        .lines()
        .any(|l| l.trim_start().starts_with("KillMode="));
    // WorkingDirectory= value, if the unit sets one without the "-" prefix.
    let workdir: Option<String> = content
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("WorkingDirectory="))
        .map(str::trim)
        .find(|v| !v.is_empty() && !v.starts_with('-') && v.starts_with('/'))
        .map(|v| v.to_string());
    let has_mkdir_pre = |dir: &str| content
        .lines()
        .map(str::trim_start)
        .any(|l| l.starts_with("ExecStartPre=") && l.contains("mkdir") && l.contains(dir));

    let mut applied: Vec<&'static str> = Vec::new();
    let mut out = String::with_capacity(content.len() + 96);
    let mut in_service = false;
    for line in content.lines() {
        let t = line.trim();
        // Rewrite `WorkingDirectory=/x` → `WorkingDirectory=-/x` in place.
        if let Some(dir) = &workdir
            && in_service
            && t.strip_prefix("WorkingDirectory=").map(str::trim) == Some(dir.as_str())
        {
            out.push_str(&format!("WorkingDirectory=-{}\n", dir));
            if !has_mkdir_pre(dir) {
                out.push_str(&format!("ExecStartPre=/bin/mkdir -p {}\n", dir));
                applied.push("ExecStartPre mkdir for the working directory");
            }
            applied.push("WorkingDirectory tolerates a missing directory");
            continue;
        }
        out.push_str(line);
        out.push('\n');
        if t == "[Service]" {
            in_service = true;
            if !has_killmode {
                out.push_str("KillMode=process\n");
                applied.push("KillMode=process");
            }
        } else if t.starts_with('[') {
            in_service = false;
        }
    }
    if applied.is_empty() { None } else { Some((out, applied)) }
}

/// Gather reboot reason diagnostics from the local machine
fn gather_reboot_reason_local() -> String {
    let commands = [
        ("Last shutdown/reboot entries", "last -x reboot shutdown -n 5 2>/dev/null || last reboot -n 5 2>/dev/null"),
        ("Previous boot final logs", "journalctl -b -1 -n 30 --no-pager -p warning 2>/dev/null"),
        ("Kernel panic check", "journalctl -b -1 --no-pager -k 2>/dev/null | grep -i -E 'panic|oom|killed|segfault|error|watchdog' | tail -10"),
        ("Unattended upgrades", "tail -20 /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null || echo '(no unattended-upgrades log)'"),
    ];

    let mut result = String::new();
    for (label, cmd) in &commands {
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(cmd)
            .output();
        let text = match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let trimmed = stdout.trim().to_string();
                if trimmed.is_empty() { "(no output)".to_string() } else { trimmed }
            }
            Err(e) => format!("(failed: {})", e),
        };
        result.push_str(&format!("\n--- {} ---\n{}\n", label, text));
    }

    // Truncate if too long for notification
    if result.len() > 3000 {
        result.truncate(3000);
        result.push_str("\n[truncated]");
    }
    result
}

/// Gather reboot reason diagnostics from a remote node via /api/ai/exec
async fn gather_reboot_reason_remote(
    client: &reqwest::Client,
    address: &str,
    port: u16,
    tls: bool,
    secret: &str,
) -> String {
    let commands = [
        ("Last shutdown/reboot entries", "last -x reboot shutdown -n 5 2>/dev/null || last reboot -n 5 2>/dev/null"),
        ("Previous boot final logs", "journalctl -b -1 -n 30 --no-pager -p warning 2>/dev/null"),
        ("Kernel panic check", "journalctl -b -1 --no-pager -k 2>/dev/null | grep -i -E 'panic|oom|killed|segfault|error|watchdog' | tail -10"),
    ];

    // HTTPS-first for TLS peers (client must accept self-signed); plain
    // HTTP on the main port for legacy `--no-tls` peers.
    let urls: Vec<String> = if tls {
        vec![format!("https://{}:{}/api/ai/exec", netaddr::bracket_host(address), port)]
    } else {
        vec![format!("http://{}:{}/api/ai/exec", netaddr::bracket_host(address), port)]
    };

    let mut result = String::new();
    for (label, cmd) in &commands {
        let mut output = "(could not reach node)".to_string();
        for url in &urls {
            let resp = client
                .post(url)
                .peer_auth(secret)
                .json(&serde_json::json!({ "command": *cmd }))
                .send()
                .await;
            match resp {
                Ok(r) => {
                    let text = r.text().await.unwrap_or_default();
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(err) = json["error"].as_str() {
                            output = format!("(error: {})", err);
                        } else {
                            output = json["output"].as_str().unwrap_or("(no output)").to_string();
                        }
                    } else {
                        output = "(invalid response)".to_string();
                    }
                    break;
                }
                Err(_) => continue,
            }
        }
        result.push_str(&format!("\n--- {} ---\n{}\n", label, output));
    }

    if result.len() > 3000 {
        result.truncate(3000);
        result.push_str("\n[truncated]");
    }
    result
}

/// `on_connect` hook for the admin HTTPS listener: record whether the peer
/// presented a CA-verified client certificate, for the mTLS gate to read via
/// `conn_data`. With SSL_VERIFY_PEER (no fail-if-absent), an invalid cert
/// already aborts the handshake, so a present cert here is a valid one.
fn mtls_on_connect(conn: &dyn std::any::Any, ext: &mut actix_web::dev::Extensions) {
    if !crate::mtls::is_active() {
        return;
    }
    if let Some(tls) = conn.downcast_ref::<
        actix_tls::accept::openssl::TlsStream<actix_web::rt::net::TcpStream>
    >() {
        let present = tls.ssl().peer_certificate().is_some();
        ext.insert(crate::mtls::ClientCertPresented(present));
    }
}

/// mTLS enforcement middleware for the admin API. A no-op unless mTLS is active
/// (a single atomic load when disabled). When active, a request must EITHER authenticate
/// as an inter-node peer (valid cluster secret — machine-to-machine, no cert)
/// OR arrive on a connection that presented a valid client certificate.
/// Anything else is refused before any handler runs.
async fn mtls_gate(
    req: actix_web::dev::ServiceRequest,
    next: actix_web::middleware::Next<impl actix_web::body::MessageBody + 'static>,
) -> Result<actix_web::dev::ServiceResponse<actix_web::body::BoxBody>, actix_web::Error> {
    if crate::mtls::is_active() {
        // Inter-node (cluster-secret) requests bypass the client-cert rule:
        // peers hold no client cert and authenticate with the shared secret.
        let secret_ok = req
            .headers()
            .get("X-WolfStack-Secret")
            .and_then(|v| v.to_str().ok())
            .map(|s| {
                // ServiceRequest exposes the same transport peer as
                // HttpRequest::peer_addr — never a forwarded header.
                let peer = req.peer_addr().map(|a| a.ip());
                req.app_data::<actix_web::web::Data<crate::api::AppState>>()
                    .map(|st| crate::auth::validate_inter_node_secret_from(
                        s, &st.cluster_secret, peer))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if !secret_ok {
            let has_cert = req
                .conn_data::<crate::mtls::ClientCertPresented>()
                .map(|c| c.0)
                .unwrap_or(false);
            if !has_cert {
                return Ok(req
                    .into_response(actix_web::HttpResponse::Forbidden().json(serde_json::json!({
                        "error": "A client certificate is required to access this server."
                    })))
                    .map_into_boxed_body());
            }
        }
    }
    Ok(next.call(req).await?.map_into_boxed_body())
}

/// Where the web UI may live, in lookup order: the development checkout,
/// then the two install locations.
const WEB_DIR_CANDIDATES: [&str; 3] = ["web", "/opt/wolfstack/web", "/usr/share/wolfstack/web"];

/// Find the web directory — the first candidate holding an index.html.
/// `None` when no candidate qualifies; callers that need a path anyway fall
/// back to the development default and the startup log says so loudly.
fn locate_web_dir() -> Option<String> {
    WEB_DIR_CANDIDATES.iter()
        .find(|dir| std::path::Path::new(dir).join("index.html").exists())
        .map(|d| d.to_string())
}

fn find_web_dir() -> String {
    locate_web_dir().unwrap_or_else(|| WEB_DIR_CANDIDATES[0].to_string())
}

#[cfg(test)]
mod unit_self_heal_tests {
    use super::heal_unit_content;

    // The unit setup.sh wrote before 2026-06 (no KillMode) with the plain
    // WorkingDirectory that fails 200/CHDIR when /opt/wolfstack is absent.
    const LEGACY: &str = "\
[Unit]
Description=WolfStack - Server Management Platform
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wolfstack --bind 0.0.0.0
WorkingDirectory=/opt/wolfstack
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
";

    #[test]
    fn legacy_unit_gets_all_three_directives() {
        let (out, applied) = heal_unit_content(LEGACY).expect("legacy unit needs healing");
        assert!(out.contains("[Service]\nKillMode=process\n"), "{out}");
        assert!(out.contains("WorkingDirectory=-/opt/wolfstack\nExecStartPre=/bin/mkdir -p /opt/wolfstack\n"), "{out}");
        assert!(!out.contains("WorkingDirectory=/opt/wolfstack\n"), "plain form must be rewritten: {out}");
        assert_eq!(applied.len(), 3);
        // Everything else is untouched, line for line.
        for line in LEGACY.lines().filter(|l| !l.starts_with("WorkingDirectory=")) {
            assert!(out.lines().any(|o| o == line), "lost line {line:?}");
        }
        // Healing is idempotent: the healed unit needs nothing more.
        assert!(heal_unit_content(&out).is_none());
    }

    #[test]
    fn already_healed_unit_is_left_alone() {
        let healed = LEGACY
            .replace("[Service]\n", "[Service]\nKillMode=process\n")
            .replace("WorkingDirectory=/opt/wolfstack\n",
                     "WorkingDirectory=-/opt/wolfstack\nExecStartPre=/bin/mkdir -p /opt/wolfstack\n");
        assert!(heal_unit_content(&healed).is_none());
    }

    #[test]
    fn operator_killmode_is_respected() {
        // An explicit KillMode=mixed stays; only the workdir pair is added.
        let unit = LEGACY.replace("Type=simple\n", "Type=simple\nKillMode=mixed\n");
        let (out, applied) = heal_unit_content(&unit).unwrap();
        assert!(out.contains("KillMode=mixed"));
        assert!(!out.contains("KillMode=process"));
        assert_eq!(applied.len(), 2);
    }

    #[test]
    fn existing_mkdir_pre_is_not_duplicated() {
        let unit = LEGACY.replace("WorkingDirectory=/opt/wolfstack\n",
            "ExecStartPre=/bin/mkdir -p /opt/wolfstack\nWorkingDirectory=/opt/wolfstack\n");
        let (out, _) = heal_unit_content(&unit).unwrap();
        assert_eq!(out.matches("ExecStartPre=/bin/mkdir -p /opt/wolfstack").count(), 1);
        assert!(out.contains("WorkingDirectory=-/opt/wolfstack"));
    }

    #[test]
    fn unit_without_service_section_is_untouched() {
        assert!(heal_unit_content("[Unit]\nDescription=x\n").is_none());
    }
}

#[cfg(test)]
mod service_context_tests {
    use super::systemd_service_context;

    // Real /proc/self/cgroup contents, captured from the machines described.
    const SERVICE: &str = "0::/system.slice/wolfstack.service";
    const SSH_SESSION: &str = "0::/user.slice/user-0.slice/session-3228.scope";
    const DESKTOP_TERMINAL: &str = "0::/user.slice/user-1000.slice/user@1000.service\
                                    /app.slice/app-org.kde.konsole-21731.scope/tab(1062235).scope";

    #[test]
    fn real_service_is_a_service() {
        assert!(systemd_service_context(true, Some(SERVICE)));
    }

    #[test]
    fn desktop_terminal_is_not_a_service_despite_inheriting_invocation_id() {
        // The hole this function exists to close: a terminal emulator running
        // as an app.scope under user@N.service inherits INVOCATION_ID, so the
        // environment check alone would wave a manual launch straight through.
        assert!(!systemd_service_context(true, Some(DESKTOP_TERMINAL)));
    }

    #[test]
    fn ssh_session_is_not_a_service() {
        // Belt and braces — an SSH login has no INVOCATION_ID to begin with,
        // but the cgroup says user.slice too.
        assert!(!systemd_service_context(false, Some(SSH_SESSION)));
        assert!(!systemd_service_context(true, Some(SSH_SESSION)));
    }

    #[test]
    fn no_invocation_id_is_never_a_service() {
        assert!(!systemd_service_context(false, Some(SERVICE)));
        assert!(!systemd_service_context(false, None));
    }

    #[test]
    fn unreadable_cgroup_falls_back_to_the_env_var() {
        // Fail toward starting. Refusing to boot a genuine service because
        // /proc/self/cgroup was unreadable would be far worse than letting a
        // manual launch through on an exotic host.
        assert!(systemd_service_context(true, None));
    }
}

#[cfg(test)]
mod shell_launch_tests {
    use super::should_refuse_shell_launch;

    #[test]
    fn bare_shell_launch_is_refused() {
        // The case worth stopping: `wolfstack` typed at a prompt to see whether
        // the service is up. No systemd, no flag, no arguments.
        assert!(should_refuse_shell_launch(false, false, false));
    }

    #[test]
    fn systemd_service_always_starts() {
        assert!(!should_refuse_shell_launch(true, false, false));
        assert!(!should_refuse_shell_launch(true, true, true));
    }

    #[test]
    fn explicit_foreground_is_honoured() {
        assert!(!should_refuse_shell_launch(false, true, true));
    }

    #[test]
    fn a_non_systemd_supervisor_passing_agent_must_start() {
        // REGRESSION. Unraid has no systemd: a bash supervisor runs
        // `wolfstack --agent`, so INVOCATION_ID is unset and --foreground is
        // not passed. The original guard refused, printed help, and exited 1
        // every 60s — the node never came up (customer, 25.10.14, 2026-08-07).
        // Any argument at all means the launch was deliberate.
        assert!(!should_refuse_shell_launch(false, false, true));
    }

    #[test]
    fn any_argument_counts_as_deliberate() {
        // --port, --bind, --agent, --no-tls … all of them. The refusal is for
        // the zero-argument case only, so no supervisor anywhere is blocked.
        {
            let has_args = true;
            assert!(!should_refuse_shell_launch(false, false, has_args));
        }
    }
}
