// WolfHost — managed web-hosting subsystem.
//
// Formerly a separate plugin (its own binary + dual HTTP servers), now
// merged into WolfStack core. Two integration points:
//   * `configure_admin()` registers the admin API routes into WolfStack's
//     main app (mounted under `/api/wolfhost`). The caller also registers
//     the WolfHost `AppState` as app_data.
//   * `spawn_portal()` runs the customer-facing portal as its OWN bound
//     server (own port) plus the background tasks. The portal serves
//     untrusted public customers, so it stays a separate server rather
//     than sharing the root core process's main port.

pub mod config;
pub mod models;
pub mod store;
pub mod api;
pub mod portal;
pub mod provisioning;

use actix_web::{web, App, HttpServer};
use std::path::Path;
use std::sync::Arc;

use config::{WolfHostConfig, ConfigStore};
use store::JsonStore;
use store::json_store::DataStore;

pub struct AppState {
    pub store: JsonStore,
    pub config: ConfigStore,
    pub db_pool: Option<Arc<sqlx::mysql::MySqlPool>>,
    pub provision_logger: provisioning::log_stream::ProvisionLogger,
    pub customers: DataStore<models::customer::Customer>,
    pub plans: DataStore<models::plan::Plan>,
    pub services: DataStore<models::service::HostingService>,
    pub invoices: DataStore<models::invoice::Invoice>,
    pub tickets: DataStore<models::ticket::Ticket>,
    pub domains: DataStore<models::domain::Domain>,
    pub ftp_accounts: DataStore<models::ftp::FtpAccount>,
    pub certificates: DataStore<models::certificate::Certificate>,
    pub databases: DataStore<models::database::CustomerDatabase>,
    pub email_accounts: DataStore<models::email::EmailAccount>,
    pub da_instances: DataStore<models::directadmin::DirectAdminInstance>,
    pub migrations: DataStore<models::migration::Migration>,
    pub portal_sessions: portal::auth::PortalSessionManager,
}

// ID extractor functions for each model
fn customer_id(c: &models::customer::Customer) -> String { c.id.clone() }
fn plan_id(p: &models::plan::Plan) -> String { p.id.clone() }
fn service_id(s: &models::service::HostingService) -> String { s.id.clone() }
fn invoice_id(i: &models::invoice::Invoice) -> String { i.id.clone() }
fn ticket_id(t: &models::ticket::Ticket) -> String { t.id.clone() }
fn domain_id(d: &models::domain::Domain) -> String { d.id.clone() }
fn ftp_id(f: &models::ftp::FtpAccount) -> String { f.id.clone() }
fn cert_id(c: &models::certificate::Certificate) -> String { c.id.clone() }
fn db_id(d: &models::database::CustomerDatabase) -> String { d.id.clone() }
fn email_id(e: &models::email::EmailAccount) -> String { e.id.clone() }
fn da_id(d: &models::directadmin::DirectAdminInstance) -> String { d.id.clone() }
fn migration_id(m: &models::migration::Migration) -> String { m.id.clone() }

/// Build the WolfHost state: MySQL-backed when a database is configured
/// and reachable, otherwise JSON file storage (the default). Falls back
/// to JSON on any DB connection/migration error so a misconfigured DB
/// never stops WolfHost from starting.
pub async fn build_state(cfg: WolfHostConfig) -> Arc<AppState> {
    let json_store = JsonStore::new(Path::new(&cfg.data_dir));

    if cfg.database.enabled {
        log::info!(
            "WolfHost: database storage enabled — connecting to {}:{}/{}",
            cfg.database.host, cfg.database.port, cfg.database.database
        );
        match store::mysql_store::connect(&cfg.database.connection_url()).await {
            Ok(pool) => {
                let pool = Arc::new(pool);
                match store::mysql_store::run_migrations(&pool).await {
                    Ok(_) => {
                        log::info!("WolfHost: database tables ready");
                        let p = pool.clone();
                        return Arc::new(AppState {
                            customers: DataStore::mysql(p.clone(), "customers", "customers", customer_id).await,
                            plans: DataStore::mysql(p.clone(), "plans", "plans", plan_id).await,
                            services: DataStore::mysql(p.clone(), "services", "services", service_id).await,
                            invoices: DataStore::mysql(p.clone(), "invoices", "invoices", invoice_id).await,
                            tickets: DataStore::mysql(p.clone(), "tickets", "tickets", ticket_id).await,
                            domains: DataStore::mysql(p.clone(), "domains", "domains", domain_id).await,
                            ftp_accounts: DataStore::mysql(p.clone(), "ftp_accounts", "ftp_accounts", ftp_id).await,
                            certificates: DataStore::mysql(p.clone(), "certificates", "certificates", cert_id).await,
                            databases: DataStore::mysql(p.clone(), "databases", "customer_databases", db_id).await,
                            email_accounts: DataStore::mysql(p.clone(), "email_accounts", "email_accounts", email_id).await,
                            da_instances: DataStore::mysql(p.clone(), "da_instances", "da_instances", da_id).await,
                            migrations: DataStore::mysql(p.clone(), "migrations", "migrations", migration_id).await,
                            portal_sessions: portal::auth::PortalSessionManager::new(),
                            provision_logger: provisioning::log_stream::ProvisionLogger::new(),
                            db_pool: Some(pool),
                            store: json_store,
                            config: ConfigStore::new(cfg),
                        });
                    }
                    Err(e) => log::error!("WolfHost: DB migration failed: {} — falling back to JSON storage", e),
                }
            }
            Err(e) => log::error!("WolfHost: DB connection failed: {} — falling back to JSON storage", e),
        }
    }

    log::info!("WolfHost: using JSON file storage in {}", cfg.data_dir);
    Arc::new(AppState {
        customers: DataStore::json(json_store.clone(), "customers", customer_id),
        plans: DataStore::json(json_store.clone(), "plans", plan_id),
        services: DataStore::json(json_store.clone(), "services", service_id),
        invoices: DataStore::json(json_store.clone(), "invoices", invoice_id),
        tickets: DataStore::json(json_store.clone(), "tickets", ticket_id),
        domains: DataStore::json(json_store.clone(), "domains", domain_id),
        ftp_accounts: DataStore::json(json_store.clone(), "ftp_accounts", ftp_id),
        certificates: DataStore::json(json_store.clone(), "certificates", cert_id),
        databases: DataStore::json(json_store.clone(), "databases", db_id),
        email_accounts: DataStore::json(json_store.clone(), "email_accounts", email_id),
        da_instances: DataStore::json(json_store.clone(), "da_instances", da_id),
        migrations: DataStore::json(json_store.clone(), "migrations", migration_id),
        portal_sessions: portal::auth::PortalSessionManager::new(),
        provision_logger: provisioning::log_stream::ProvisionLogger::new(),
        db_pool: None,
        store: json_store,
        config: ConfigStore::new(cfg),
    })
}

/// Scope-level auth guard for the WolfHost admin API.
///
/// Every `/api/wolfhost/*` route is an administrative operation (customer
/// records + PII, container provisioning across the cluster, DNS, DirectAdmin
/// control). The rest of the main-app API enforces auth per-handler via
/// `require_auth`, but the WolfHost handlers were written behind an older
/// plugin/portal boundary and never adopted that convention — so when the
/// subsystem was folded onto the main port the whole subtree was reachable
/// with no credential. This guard closes that in ONE place by applying the
/// exact same check every other admin endpoint uses (`crate::api::require_auth`
/// — session cookie, API key, or inter-node secret). The admin UI (which sends
/// the `wolfstack_session` cookie) and inter-node callers keep working
/// unchanged; an unauthenticated request is rejected before reaching any
/// handler. Using the shared helper means this can never drift from the
/// acceptance rules the rest of the API applies.
async fn require_admin_auth(
    req: actix_web::dev::ServiceRequest,
    next: actix_web::middleware::Next<impl actix_web::body::MessageBody + 'static>,
) -> Result<actix_web::dev::ServiceResponse<actix_web::body::BoxBody>, actix_web::Error> {
    // Keep require_auth's OWN response rather than collapsing every failure
    // to a generic 401: a read-only (viewer) session is refused with a 403
    // that carries X-WolfStack-Role, which the dashboard turns into a
    // visible explanation; an expired session carries the header the
    // dashboard bounces to the login page on.
    let verdict = match req.app_data::<web::Data<crate::api::AppState>>() {
        Some(state) => crate::api::require_auth(req.request(), state).map(|_| ()),
        None => Err(actix_web::HttpResponse::Unauthorized()
            .json(serde_json::json!({ "error": "Not authenticated" }))),
    };
    match verdict {
        Ok(()) => Ok(next.call(req).await?.map_into_boxed_body()),
        Err(resp) => Ok(req.into_response(resp).map_into_boxed_body()),
    }
}

/// Register the WolfHost admin API routes into WolfStack's main app,
/// mounted under `/api/wolfhost`. The caller must also register the
/// WolfHost `AppState` via `.app_data(web::Data::new(state))`. The whole
/// scope is gated by `require_admin_auth` so no handler is reachable without
/// the same authentication the rest of the admin API requires.
pub fn configure_admin(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/wolfhost")
            .wrap(actix_web::middleware::from_fn(require_admin_auth))
            .configure(api::configure),
    );
}

/// Spawn the customer-facing portal as its own bound server, plus the
/// portal-session-cleanup and DirectAdmin-sync background tasks. A bind
/// failure is logged and skipped rather than propagated — the portal
/// failing to start must never take WolfStack down.
pub async fn spawn_portal(state: Arc<AppState>, portal_port: u16, portal_web_dir: String) {
    let portal_state = state.clone();
    // Only mount the static-asset service when the directory actually
    // exists. actix_files::Files::new on a missing path logs an ERROR
    // per server worker ("Specified path is not a directory") and then
    // 404s everything anyway — one clear warning here is strictly
    // better, and the portal API routes keep working either way.
    let portal_static_dir = if Path::new(&portal_web_dir).is_dir() {
        Some(portal_web_dir)
    } else {
        log::warn!(
            "WolfHost portal: static assets dir '{}' not found — portal UI disabled, API routes still served",
            portal_web_dir
        );
        None
    };
    let portal_factory = move || {
        let app = App::new()
            .app_data(web::Data::new(portal_state.clone()))
            .configure(portal::configure);
        match &portal_static_dir {
            Some(dir) => app.service(
                actix_files::Files::new("/", dir).index_file("index.html"),
            ),
            None => app,
        }
    };

    // Reuse WolfStack's TLS material for the portal when available:
    // /etc/wolfstack/cert.pem first, then any Let's Encrypt live cert.
    let (cert_path, key_path, has_tls) = {
        let ws_cert = "/etc/wolfstack/cert.pem";
        let ws_key = "/etc/wolfstack/key.pem";
        if Path::new(ws_cert).exists() && Path::new(ws_key).exists() {
            (ws_cert.to_string(), ws_key.to_string(), true)
        } else {
            let mut found = (String::new(), String::new(), false);
            if let Ok(entries) = std::fs::read_dir("/etc/letsencrypt/live") {
                for entry in entries.flatten() {
                    let p = entry.path();
                    let cert = p.join("fullchain.pem");
                    let key = p.join("privkey.pem");
                    if cert.exists() && key.exists() {
                        found = (cert.to_string_lossy().to_string(), key.to_string_lossy().to_string(), true);
                        break;
                    }
                }
            }
            found
        }
    };

    let bind_addr = format!("0.0.0.0:{}", portal_port);
    let portal_server = if has_tls {
        match openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls()) {
            Ok(mut builder) => {
                if let Err(e) = builder.set_certificate_chain_file(&cert_path) {
                    log::error!("WolfHost portal: TLS cert load failed: {}", e);
                    return;
                }
                if let Err(e) = builder.set_private_key_file(&key_path, openssl::ssl::SslFiletype::PEM) {
                    log::error!("WolfHost portal: TLS key load failed: {}", e);
                    return;
                }
                match HttpServer::new(portal_factory).bind_openssl(&bind_addr, builder) {
                    Ok(s) => s.run(),
                    Err(e) => { log::error!("WolfHost portal: bind {} failed: {}", bind_addr, e); return; }
                }
            }
            Err(e) => { log::error!("WolfHost portal: TLS acceptor failed: {}", e); return; }
        }
    } else {
        match HttpServer::new(portal_factory).bind(&bind_addr) {
            Ok(s) => s.run(),
            Err(e) => { log::error!("WolfHost portal: bind {} failed: {}", bind_addr, e); return; }
        }
    };

    log::info!("WolfHost customer portal listening on {} (TLS: {})", bind_addr, has_tls);
    tokio::spawn(async move {
        if let Err(e) = portal_server.await {
            log::error!("WolfHost portal server exited: {}", e);
        }
    });

    // Portal session cleanup (every 10 minutes).
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
            cleanup_state.portal_sessions.cleanup_expired().await;
        }
    });

    // DirectAdmin instance auto-sync (every 5 minutes).
    let da_sync_state = state.clone();
    tokio::spawn(async move {
        use crate::wolfhost::provisioning::directadmin::{DaClient, deobfuscate_password};
        use crate::wolfhost::models::directadmin::DirectAdminStatus;

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            let instances = da_sync_state.da_instances.list().await;
            if instances.is_empty() {
                continue;
            }
            for inst in &instances {
                let pass = deobfuscate_password(&inst.admin_password_enc);
                let da = DaClient::new(&inst.url, &inst.admin_user, &pass);
                let id = inst.id.clone();
                match da.list_users().await {
                    Ok(users) => {
                        let user_count = users.len() as u32;
                        let now = chrono::Utc::now().to_rfc3339();
                        let _ = da_sync_state.da_instances.update_with(move |items| {
                            if let Some(i) = items.iter_mut().find(|i| i.id == id) {
                                i.user_count = user_count;
                                i.last_sync = now;
                                i.status = DirectAdminStatus::Online;
                            }
                        }).await;
                    }
                    Err(e) => {
                        log::warn!("WolfHost DA sync: instance '{}' offline: {}", inst.name, e);
                        let _ = da_sync_state.da_instances.update_with(move |items| {
                            if let Some(i) = items.iter_mut().find(|i| i.id == id) {
                                i.status = DirectAdminStatus::Offline;
                            }
                        }).await;
                    }
                }
            }
        }
    });
}
